//! Adversary tests (#62 round 1) for the recordings routes, through the public `router` only.
//! In-memory and synthetic segment ports; no real roots or volumes.
#![expect(clippy::unwrap_used, reason = "test code")]
#![expect(
    clippy::arithmetic_side_effects,
    reason = "test oracles on small, bounded values"
)]

use std::collections::HashMap;
use std::future::Future;
use std::io::{self, Read, Seek, SeekFrom};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};

use axum::Router;
use axum::body::Body;
use axum::http::{Method, Request, Response, StatusCode, header};
use http_body_util::BodyExt as _;
use tower::ServiceExt as _;
mod common;

use wardenlens_api::router;
use wardenlens_api::token::Token;
use wardenlens_core::camera::{
    Camera, CameraDirectory, CameraId, CameraStatus, DirectoryError, LinkStatus,
};
use wardenlens_core::storage::{
    MemorySegmentFiles, OpenedSegment, SegmentCursor, SegmentFiles, SegmentId, SegmentListError,
    SegmentLister, SegmentOpenError, SegmentPage, StorageSnapshot, StorageStatus,
    StorageStatusError, Tier,
};
use wardenlens_core::time::Timestamp;
use wardenlens_core::token_store::{TokenId, TokenRecord, TokenStore, TokenStoreError};

/// The router's download cap (`MAX_DOWNLOADS`, documented as 8).
const CAP: usize = 8;

#[derive(Default)]
struct Store(Mutex<HashMap<String, TokenRecord>>);

impl TokenStore for Store {
    fn find(
        &self,
        id: &TokenId,
    ) -> impl Future<Output = Result<Option<TokenRecord>, TokenStoreError>> + Send {
        let out = self
            .0
            .lock()
            .map(|m| m.get(id.as_str()).cloned())
            .map_err(|_| TokenStoreError);
        std::future::ready(out)
    }
}

struct Dir;

impl CameraDirectory for Dir {
    fn list(&self) -> impl Future<Output = Result<Vec<Camera>, DirectoryError>> + Send {
        std::future::ready(Ok(Vec::new()))
    }
    fn get(
        &self,
        _id: &CameraId,
    ) -> impl Future<Output = Result<Option<Camera>, DirectoryError>> + Send {
        std::future::ready(Ok(None))
    }
}

struct St;

impl CameraStatus for St {
    fn status(&self, _id: &CameraId) -> impl Future<Output = Option<LinkStatus>> + Send {
        std::future::ready(None)
    }
}

struct NoStorage;

impl StorageStatus for NoStorage {
    fn snapshot(&self) -> impl Future<Output = Result<StorageSnapshot, StorageStatusError>> + Send {
        std::future::ready(Err(StorageStatusError))
    }
}

type Call = (i64, i64, usize, Option<String>);

/// Records every call's `(from, to, limit, cursor)`.
#[derive(Clone, Default)]
struct Recording(Arc<Mutex<Vec<Call>>>);

impl SegmentLister for Recording {
    fn list(
        &self,
        _camera: &CameraId,
        from: Timestamp,
        to: Timestamp,
        limit: usize,
        cursor: Option<&SegmentCursor>,
    ) -> impl Future<Output = Result<SegmentPage, SegmentListError>> + Send {
        self.0.lock().unwrap().push((
            from.as_unix_millis(),
            to.as_unix_millis(),
            limit,
            cursor.map(|c| c.as_token().to_owned()),
        ));
        std::future::ready(Ok(SegmentPage::new(Vec::new(), None)))
    }
}

fn token() -> (Store, String) {
    let store = Store::default();
    let t = Token::generate().unwrap();
    store.0.lock().unwrap().insert(
        t.id().to_string(),
        TokenRecord {
            digest: t.secret().digest(),
            revoked: false,
        },
    );
    (store, format!("Bearer {}", t.expose()))
}

fn app_with<L, F>(lister: L, files: F) -> (Router, String)
where
    L: SegmentLister + Send + Sync + 'static,
    F: SegmentFiles + Send + Sync + 'static,
    F::Handle: 'static,
{
    let (store, auth) = token();
    (
        router(Arc::new(store), Dir, St, NoStorage, lister, files),
        auth,
    )
}

async fn req(
    app: &Router,
    auth: &str,
    method: Method,
    uri: &str,
    headers: &[(&str, &str)],
) -> Response<Body> {
    let mut b = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::AUTHORIZATION, auth);
    for (k, v) in headers {
        b = b.header(*k, *v);
    }
    app.clone()
        .oneshot(b.body(Body::empty()).unwrap())
        .await
        .unwrap()
}

/// Collects the body; `Err(prefix)` when the stream ends in an error.
async fn body(resp: Response<Body>) -> Result<Vec<u8>, Vec<u8>> {
    let mut b = resp.into_body();
    let mut got = Vec::new();
    while let Some(frame) = b.frame().await {
        match frame {
            Ok(f) => {
                if let Ok(d) = f.into_data() {
                    got.extend_from_slice(&d);
                }
            }
            Err(_) => return Err(got),
        }
    }
    Ok(got)
}

fn pattern(n: usize) -> Vec<u8> {
    (0..n)
        .map(|i| u8::try_from((i * 7 + i / 251) % 256).unwrap())
        .collect()
}

fn hdr(resp: &Response<Body>, name: header::HeaderName) -> Option<&str> {
    resp.headers().get(name).map(|v| v.to_str().unwrap())
}

// ---- Range: oracle at chunk boundaries -------------------------------------------------------

/// What a naive RFC 9110 single-range oracle expects.
enum Want {
    Full,
    Unsatisfiable,
    Slice(u64, u64),
}

fn oracle(spec: &str, len: u64) -> Want {
    let Some((a, b)) = spec.split_once('-') else {
        return Want::Full;
    };
    if a.is_empty() {
        let Ok(n) = b.parse::<u64>() else {
            return Want::Full;
        };
        if n == 0 || len == 0 {
            return Want::Unsatisfiable;
        }
        return Want::Slice(len.saturating_sub(n), len - 1);
    }
    let Ok(start) = a.parse::<u64>() else {
        return Want::Full;
    };
    // A last-pos past u64 is still a valid (clamped) range.
    let end: Option<u64> = if b.is_empty() {
        None
    } else if b.bytes().all(|c| c.is_ascii_digit()) {
        Some(b.parse().unwrap_or(u64::MAX))
    } else {
        return Want::Full;
    };
    if end.is_some_and(|e| e < start) {
        return Want::Full;
    }
    if start >= len {
        return Want::Unsatisfiable;
    }
    Want::Slice(start, end.map_or(len - 1, |e| e.min(len - 1)))
}

#[tokio::test]
async fn ranges_at_chunk_boundaries_match_a_naive_oracle() {
    const C: u64 = 64 * 1024;
    let len = 3 * C + 17;
    let data = pattern(usize::try_from(len).unwrap());
    let files = MemorySegmentFiles::new();
    files.insert(SegmentId::new(7), Tier::Hot, &data);
    let (app, auth) = app_with(common::NoLister, files);
    let specs = [
        "0-0".to_owned(),
        format!("{}-{}", C - 1, C),
        format!("{C}-"),
        format!("{}-", C - 1),
        format!("{}-{}", C + 1, 2 * C + 1),
        format!("-{}", C + 1),
        format!("-{C}"),
        format!("-{len}"),
        format!("-{}", len + 1),
        format!("{}-", len - 1),
        format!("{len}-"),
        format!("0-{}", len - 1),
        format!("0-{len}"),
        format!("{}-{}", 2 * C, 2 * C),
        "00-01".to_owned(),
        "-18446744073709551615".to_owned(),
        "0-18446744073709551616".to_owned(),
    ];
    for spec in specs {
        let resp = req(
            &app,
            &auth,
            Method::GET,
            "/api/v1/recordings/7/file",
            &[("range", &format!("bytes={spec}"))],
        )
        .await;
        let status = resp.status();
        let cl = hdr(&resp, header::CONTENT_LENGTH).map(str::to_owned);
        let cr = hdr(&resp, header::CONTENT_RANGE).map(str::to_owned);
        match oracle(&spec, len) {
            Want::Full => {
                assert_eq!(status, StatusCode::OK, "{spec}");
                assert_eq!(body(resp).await.unwrap(), data, "{spec}");
            }
            Want::Unsatisfiable => {
                assert_eq!(status, StatusCode::RANGE_NOT_SATISFIABLE, "{spec}");
                assert_eq!(cr.as_deref(), Some(format!("bytes */{len}").as_str()));
            }
            Want::Slice(s, e) => {
                assert_eq!(status, StatusCode::PARTIAL_CONTENT, "{spec}");
                assert_eq!(cr, Some(format!("bytes {s}-{e}/{len}")), "{spec}");
                assert_eq!(cl, Some((e - s + 1).to_string()), "{spec}");
                let got = body(resp).await.unwrap();
                let want = data
                    .get(usize::try_from(s).unwrap()..=usize::try_from(e).unwrap())
                    .unwrap();
                assert_eq!(got, want, "{spec}");
            }
        }
    }
}

#[tokio::test]
async fn unsatisfiable_range_keeps_content_range_and_a_bare_json_body() {
    let files = MemorySegmentFiles::new();
    files.insert(SegmentId::new(1), Tier::Hot, &pattern(10));
    let (app, auth) = app_with(common::NoLister, files);
    let resp = req(
        &app,
        &auth,
        Method::GET,
        "/api/v1/recordings/1/file",
        &[("range", "bytes=10-")],
    )
    .await;
    assert_eq!(resp.status(), StatusCode::RANGE_NOT_SATISFIABLE);
    assert_eq!(hdr(&resp, header::CONTENT_RANGE), Some("bytes */10"));
    assert_eq!(
        body(resp).await.unwrap(),
        br#"{"error":"range_not_satisfiable"}"#
    );
}

#[tokio::test]
async fn head_reports_the_full_length_without_a_body() {
    let data = pattern(200_000);
    let files = MemorySegmentFiles::new();
    files.insert(SegmentId::new(1), Tier::Hot, &data);
    let (app, auth) = app_with(common::NoLister, files);
    let resp = req(&app, &auth, Method::HEAD, "/api/v1/recordings/1/file", &[]).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(hdr(&resp, header::CONTENT_LENGTH), Some("200000"));
    assert_eq!(hdr(&resp, header::CONTENT_TYPE), Some("video/mp4"));
    assert_eq!(body(resp).await.unwrap(), b"");
}

/// RFC 9110 section 13.1.5: a server MUST ignore `Range` when the `If-Range` validator does not
/// match its current one. This server issues no validator (no `ETag`, no `Last-Modified`), so no
/// `If-Range` can match and the answer must be the full `200`.
#[tokio::test]
async fn if_range_that_cannot_match_gets_the_full_file() {
    let data = pattern(100);
    let files = MemorySegmentFiles::new();
    files.insert(SegmentId::new(1), Tier::Hot, &data);
    let (app, auth) = app_with(common::NoLister, files);
    let resp = req(
        &app,
        &auth,
        Method::GET,
        "/api/v1/recordings/1/file",
        &[
            ("range", "bytes=10-19"),
            ("if-range", "\"some-other-etag\""),
        ],
    )
    .await;
    assert!(resp.headers().get(header::ETAG).is_none());
    assert!(resp.headers().get(header::LAST_MODIFIED).is_none());
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body(resp).await.unwrap(), data);
}

// ---- slot release on every exit path ----------------------------------------------------------

/// Opens that fail in every way the port can, including a panic.
struct Faulty {
    inner: MemorySegmentFiles,
}

impl SegmentFiles for Faulty {
    type Handle = <MemorySegmentFiles as SegmentFiles>::Handle;
    fn open_segment(&self, id: SegmentId) -> Result<OpenedSegment<Self::Handle>, SegmentOpenError> {
        assert!(id.as_u64() != 66, "open panicked");
        self.inner.open_segment(id)
    }
}

type Case = (
    &'static str,
    &'static [(&'static str, &'static str)],
    StatusCode,
);

#[tokio::test]
async fn error_paths_never_leak_download_slots() {
    let inner = MemorySegmentFiles::new();
    inner.insert(SegmentId::new(1), Tier::Hot, &pattern(70_000));
    inner.insert(SegmentId::new(2), Tier::Archive, &pattern(10));
    inner.insert(SegmentId::new(3), Tier::Hot, &[]);
    inner.fail_with(SegmentId::new(4), io::ErrorKind::PermissionDenied);
    inner.set_archive_available(false);
    let (app, auth) = app_with(common::NoLister, Faulty { inner });
    let cases: [Case; 7] = [
        ("/api/v1/recordings/9/file", &[], StatusCode::NOT_FOUND),
        (
            "/api/v1/recordings/2/file",
            &[],
            StatusCode::SERVICE_UNAVAILABLE,
        ),
        ("/api/v1/recordings/3/file", &[], StatusCode::OK),
        (
            "/api/v1/recordings/3/file",
            &[("range", "bytes=0-")],
            StatusCode::RANGE_NOT_SATISFIABLE,
        ),
        (
            "/api/v1/recordings/4/file",
            &[],
            StatusCode::INTERNAL_SERVER_ERROR,
        ),
        (
            "/api/v1/recordings/66/file",
            &[],
            StatusCode::INTERNAL_SERVER_ERROR,
        ),
        (
            "/api/v1/recordings/1/file",
            &[("range", "bytes=99999-")],
            StatusCode::RANGE_NOT_SATISFIABLE,
        ),
    ];
    for _ in 0..3 * CAP {
        for (uri, h, want) in cases {
            let resp = req(&app, &auth, Method::GET, uri, h).await;
            assert_eq!(resp.status(), want, "{uri} {h:?}");
            let b = body(resp).await.unwrap();
            let text = String::from_utf8_lossy(&b);
            assert!(!text.contains("panick"), "{text}");
            assert!(!text.contains("ermission"), "{text}");
        }
    }
    // Sequential full downloads after all of that: every one gets a slot.
    for i in 0..3 * CAP {
        let resp = req(&app, &auth, Method::GET, "/api/v1/recordings/1/file", &[]).await;
        assert_eq!(resp.status(), StatusCode::OK, "download {i}");
        assert_eq!(body(resp).await.unwrap().len(), 70_000);
    }
}

/// A handle whose behaviour after open is hostile: it lies about its length (seek to the end
/// reports more than it yields), panics on a read, or fails a seek.
#[derive(Clone, Copy)]
enum Mode {
    Shrunk,
    PanicOnRead,
    BadSeek,
}

struct Hostile {
    mode: Mode,
    data: io::Cursor<Vec<u8>>,
    claimed: u64,
}

impl Read for Hostile {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        assert!(
            !(matches!(self.mode, Mode::PanicOnRead) && self.data.position() > 0),
            "read panicked"
        );
        self.data.read(buf)
    }
}

impl Seek for Hostile {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        match pos {
            SeekFrom::End(0) => Ok(self.claimed),
            SeekFrom::Start(0) => self.data.seek(pos),
            _ if matches!(self.mode, Mode::BadSeek) => Err(io::Error::other("seek failed")),
            _ => self.data.seek(pos),
        }
    }
}

struct HostileFiles(Mode);

impl SegmentFiles for HostileFiles {
    type Handle = Hostile;
    fn open_segment(&self, _id: SegmentId) -> Result<OpenedSegment<Hostile>, SegmentOpenError> {
        let real = pattern(200_000);
        let claimed = match self.0 {
            Mode::Shrunk => 300_000,
            _ => 200_000,
        };
        OpenedSegment::from_handle(
            Hostile {
                mode: self.0,
                data: io::Cursor::new(real),
                claimed,
            },
            Tier::Hot,
        )
    }
}

#[tokio::test]
async fn hostile_handles_end_the_body_in_an_error_and_free_their_slot() {
    for (mode, range) in [
        (Mode::Shrunk, None),
        (Mode::Shrunk, Some("bytes=150000-")),
        (Mode::PanicOnRead, None),
        (Mode::BadSeek, Some("bytes=1000-")),
    ] {
        let (app, auth) = app_with(common::NoLister, HostileFiles(mode));
        let h: Vec<(&str, &str)> = range.map(|r| ("range", r)).into_iter().collect();
        for i in 0..2 * CAP {
            let resp = req(&app, &auth, Method::GET, "/api/v1/recordings/1/file", &h).await;
            assert!(resp.status().is_success(), "{range:?} round {i}");
            let declared: usize = hdr(&resp, header::CONTENT_LENGTH).unwrap().parse().unwrap();
            let got = body(resp).await;
            let prefix = got.expect_err("a short body must end in an error, not a clean end");
            assert!(prefix.len() < declared);
            if matches!(mode, Mode::BadSeek) {
                assert!(prefix.is_empty(), "no bytes from the wrong offset");
            }
        }
    }
}

// ---- the cap bounds work in flight, not only responses -----------------------------------------

/// `(released, peak blocked at once, opens entered)`.
type GateState = (bool, usize, usize);

/// An open that blocks until the test releases it, and counts how many are blocked at once.
#[derive(Clone, Default)]
struct Gate {
    state: Arc<(Mutex<GateState>, Condvar)>,
}

impl Gate {
    fn release(&self) {
        let (m, c) = &*self.state;
        m.lock().unwrap().0 = true;
        c.notify_all();
    }
    /// Waits (on a blocking thread) until `n` opens have entered.
    async fn wait_entered(&self, count: usize) {
        let gate = self.clone();
        tokio::task::spawn_blocking(move || {
            let (lock, cvar) = &*gate.state;
            let mut st = lock.lock().unwrap();
            while st.2 < count && !st.0 {
                st = cvar.wait(st).unwrap();
            }
        })
        .await
        .unwrap();
    }
    fn max_concurrent(&self) -> usize {
        self.state.0.lock().unwrap().1
    }
}

struct BlockingFiles {
    gate: Gate,
    blocked_now: AtomicUsize,
}

impl SegmentFiles for BlockingFiles {
    type Handle = <MemorySegmentFiles as SegmentFiles>::Handle;
    fn open_segment(
        &self,
        _id: SegmentId,
    ) -> Result<OpenedSegment<Self::Handle>, SegmentOpenError> {
        let now = self.blocked_now.fetch_add(1, Ordering::SeqCst) + 1;
        let (m, c) = &*self.gate.state;
        let mut s = m.lock().unwrap();
        s.1 = s.1.max(now);
        s.2 += 1;
        c.notify_all();
        while !s.0 {
            s = c.wait(s).unwrap();
        }
        drop(s);
        self.blocked_now.fetch_sub(1, Ordering::SeqCst);
        Err(SegmentOpenError::NotFound)
    }
}

/// A client that sends the request and goes away (the server drops the handler future) while
/// the open is still running on the blocking pool. The download cap exists to bound file work;
/// it must still count that open, or a client that repeatedly connects and hangs up can pile up
/// any number of opens stuck in the kernel (a hung archive) and exhaust the blocking pool.
#[tokio::test]
async fn abandoned_requests_cannot_push_blocked_opens_past_the_download_cap() {
    let gate = Gate::default();
    let files = BlockingFiles {
        gate: gate.clone(),
        blocked_now: AtomicUsize::new(0),
    };
    let (app, auth) = app_with(common::NoLister, files);
    let rounds = 3 * CAP;
    let mut accepted_opens = 0;
    for _ in 0..rounds {
        let app2 = app.clone();
        let auth2 = auth.clone();
        let mut task = tokio::spawn(async move {
            req(&app2, &auth2, Method::GET, "/api/v1/recordings/1/file", &[])
                .await
                .status()
        });
        // Either the open starts (and blocks), or the request is refused at the cap.
        let entered = gate.wait_entered(accepted_opens + 1);
        tokio::select! {
            () = entered => {
                accepted_opens += 1;
                task.abort(); // the client hangs up
                let _ = task.await;
            }
            status = &mut task => {
                assert_eq!(status.unwrap(), StatusCode::SERVICE_UNAVAILABLE);
                break;
            }
        }
    }
    let peak = gate.max_concurrent();
    gate.release();
    assert!(
        peak <= CAP,
        "{peak} opens were blocked at once, above the download cap of {CAP}"
    );
}

// ---- listing ---------------------------------------------------------------------------------

#[tokio::test]
async fn list_converts_every_offset_form_to_utc_millis() {
    let lister = Recording::default();
    let calls = lister.clone();
    let (app, auth) = app_with(lister, MemorySegmentFiles::new());
    let base = 1_704_067_200_000_i64; // 2024-01-01T00:00:00Z
    let rows = [
        ("2024-01-01T05:30:00%2B05:30", base),
        ("2023-12-31T18:30:00-05:30", base),
        ("2024-01-01T00:00:00-00:00", base),
        ("2024-01-01t00:00:00z", base),
        ("2024-01-01T00:00:00.999999999Z", base + 999),
        ("2024-01-01T23:59:00%2B23:59", base),
        ("1970-01-01T00:00:00.001Z", 1),
        ("1969-12-31T23:59:59.999Z", -1),
    ];
    for (text, want) in rows {
        let resp = req(
            &app,
            &auth,
            Method::GET,
            &format!("/api/v1/recordings?camera=cam-1&from={text}"),
            &[],
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK, "{text}");
        let (from, to, limit, cursor) = calls.0.lock().unwrap().pop().unwrap();
        assert_eq!(from, want, "{text}");
        assert_eq!(to, i64::MAX, "an absent `to` is an open end");
        assert_eq!(limit, 100);
        assert_eq!(cursor, None);
    }
}

#[tokio::test]
async fn list_refuses_hostile_query_bytes_before_the_port() {
    let lister = Recording::default();
    let calls = lister.clone();
    let (app, auth) = app_with(lister, MemorySegmentFiles::new());
    for q in [
        "camera=cam-1&from=2024-01-01T00:00:00+02:00", // bare `+` is a space
        "camera=cam-1&from=2024-01-01T00:00:00%00Z",
        "camera=cam-1&from=%FF",
        "camera=cam-1&from=2024-01-01T00:00:00Z&from=2024-01-01T00:00:00Z",
        "camera=cam-1&to=2024-01-01T00:00:00.1234567890Z",
        "camera=cam-1&to=10000-01-01T00:00:00Z",
        "camera=cam-1&limit=1e3",
        "camera=cam-1&limit=%201",
        "camera=%FF",
        "camera=cam-1%00",
        "camera=cam-1&cursor=x&cursor=y",
    ] {
        let resp = req(
            &app,
            &auth,
            Method::GET,
            &format!("/api/v1/recordings?{q}"),
            &[],
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{q}");
        assert_eq!(
            body(resp).await.unwrap(),
            br#"{"error":"bad_request"}"#,
            "{q}"
        );
    }
    assert!(calls.0.lock().unwrap().is_empty());
}

#[tokio::test]
async fn unauthenticated_requests_never_open_a_segment() {
    struct Never;
    impl SegmentFiles for Never {
        type Handle = <MemorySegmentFiles as SegmentFiles>::Handle;
        fn open_segment(
            &self,
            _id: SegmentId,
        ) -> Result<OpenedSegment<Self::Handle>, SegmentOpenError> {
            panic!("opened without a token");
        }
    }
    let (app, _auth) = app_with(common::NoLister, Never);
    for auth in ["", "Bearer ", "Bearer x", "Basic abc"] {
        for uri in [
            "/api/v1/recordings/1/file",
            "/api/v1/recordings/%31/file",
            "/api/v1/recordings?camera=cam-1",
        ] {
            let resp = req(&app, auth, Method::GET, uri, &[("range", "bytes=0-")]).await;
            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "{auth:?} {uri}");
        }
    }
}
