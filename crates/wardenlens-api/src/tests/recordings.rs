//! Recordings route tests: a fake lister and a fake `SegmentFiles` over temporary files.

use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::http::{HeaderMap, HeaderValue, Request, Response, StatusCode, header};
use http_body_util::BodyExt as _;
use tempfile::TempDir;
use tower::ServiceExt as _;
use wardenlens_core::camera::CameraId;
use wardenlens_core::recording::SegmentRecord;
use wardenlens_core::storage::{
    IndexedSegment, OpenedSegment, SegmentCursor, SegmentFiles, SegmentId, SegmentListError,
    SegmentLister, SegmentOpenError, SegmentPage, Tier,
};
use wardenlens_core::time::{Timestamp, UnixMs};

use super::{FakeDirectory, FakeLister, FakeStatus, FakeStorage, FakeStore, body_string};
use crate::recordings::{RangeChoice, choose_range};
use crate::token::Token;
use crate::{LIMITS, Limits, build};

const IDLE: Duration = Duration::from_secs(5);
const JUST_UNDER_IDLE: Duration = Duration::from_millis(4_999);

/// A handle that counts itself as open until dropped.
struct CountedFile {
    file: File,
    open: Arc<AtomicUsize>,
}

impl Drop for CountedFile {
    fn drop(&mut self) {
        self.open.fetch_sub(1, Ordering::SeqCst);
    }
}

impl Read for CountedFile {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.file.read(buf)
    }
}

impl Seek for CountedFile {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.file.seek(pos)
    }
}

/// Segment files in two temporary directories, one per tier. It reads its own table of rows, as
/// the storage implementation reads the index: the row's tier first, the other tier once on
/// `ENOENT` (the real implementation re-reads the row; here the table is the row).
struct DirFiles {
    dir: TempDir,
    rows: Mutex<HashMap<u64, Tier>>,
    failing: Mutex<HashSet<u64>>,
    archive_up: AtomicBool,
    open: Arc<AtomicUsize>,
}

impl DirFiles {
    fn new() -> Self {
        let dir = TempDir::new().unwrap();
        fs::create_dir(dir.path().join("hot")).unwrap();
        fs::create_dir(dir.path().join("archive")).unwrap();
        Self {
            dir,
            rows: Mutex::default(),
            failing: Mutex::default(),
            archive_up: AtomicBool::new(true),
            open: Arc::default(),
        }
    }

    fn path(&self, tier: Tier, id: u64) -> PathBuf {
        let d = if tier == Tier::Hot { "hot" } else { "archive" };
        self.dir.path().join(d).join(id.to_string())
    }

    fn put(&self, id: u64, tier: Tier, bytes: &[u8]) {
        fs::write(self.path(tier, id), bytes).unwrap();
        self.rows.lock().unwrap().insert(id, tier);
    }

    /// Moves the file as the mover does: the file is on the other tier, the row follows.
    fn move_to(&self, id: u64, to: Tier) {
        let from = if to == Tier::Hot {
            Tier::Archive
        } else {
            Tier::Hot
        };
        fs::rename(self.path(from, id), self.path(to, id)).unwrap();
        self.rows.lock().unwrap().insert(id, to);
    }

    fn open_handles(&self) -> usize {
        self.open.load(Ordering::SeqCst)
    }
}

struct SharedFiles(Arc<DirFiles>);

impl SegmentFiles for SharedFiles {
    type Handle = CountedFile;

    fn open_segment(&self, id: SegmentId) -> Result<OpenedSegment<CountedFile>, SegmentOpenError> {
        let f = &self.0;
        let raw = id.as_u64();
        if f.failing.lock().unwrap().contains(&raw) {
            return Err(SegmentOpenError::Io {
                kind: io::ErrorKind::PermissionDenied,
            });
        }
        let Some(tier) = f.rows.lock().unwrap().get(&raw).copied() else {
            return Err(SegmentOpenError::NotFound);
        };
        if tier == Tier::Archive && !f.archive_up.load(Ordering::SeqCst) {
            return Err(SegmentOpenError::ArchiveUnavailable);
        }
        let file = File::open(f.path(tier, raw)).map_err(|e| SegmentOpenError::io(&e))?;
        f.open.fetch_add(1, Ordering::SeqCst);
        OpenedSegment::from_handle(
            CountedFile {
                file,
                open: Arc::clone(&f.open),
            },
            tier,
        )
    }
}

struct SharedLister(Arc<FakeLister>);

impl SegmentLister for SharedLister {
    fn list(
        &self,
        camera: &CameraId,
        from: Timestamp,
        to: Timestamp,
        limit: usize,
        cursor: Option<&SegmentCursor>,
    ) -> impl Future<Output = Result<SegmentPage, SegmentListError>> + Send {
        self.0.list(camera, from, to, limit, cursor)
    }
}

struct Env {
    app: Router,
    auth: String,
    files: Arc<DirFiles>,
    lister: Arc<FakeLister>,
}

fn env_with(lister: FakeLister, limits: Limits) -> Env {
    let store = FakeStore::default();
    let token = Token::generate().unwrap();
    store.add(&token, false);
    let files = Arc::new(DirFiles::new());
    let lister = Arc::new(lister);
    let app = build(
        Arc::new(store),
        FakeDirectory::default(),
        FakeStatus::default(),
        FakeStorage::default(),
        SharedLister(Arc::clone(&lister)),
        SharedFiles(Arc::clone(&files)),
        limits,
    );
    Env {
        app,
        auth: format!("Bearer {}", token.expose()),
        files,
        lister,
    }
}

fn env() -> Env {
    env_with(
        FakeLister::default(),
        Limits {
            download_idle: IDLE,
            ..LIMITS
        },
    )
}

impl Env {
    async fn get(&self, uri: &str, range: Option<&str>) -> Response<Body> {
        let mut b = Request::builder()
            .uri(uri)
            .header(header::AUTHORIZATION, &self.auth);
        if let Some(r) = range {
            b = b.header(header::RANGE, r);
        }
        self.app
            .clone()
            .oneshot(b.body(Body::empty()).unwrap())
            .await
            .unwrap()
    }

    async fn file(&self, id: u64, range: Option<&str>) -> Response<Body> {
        self.get(&format!("/api/v1/recordings/{id}/file"), range)
            .await
    }
}

async fn bytes_of(resp: Response<Body>) -> Vec<u8> {
    resp.into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes()
        .to_vec()
}

fn pattern(n: usize) -> Vec<u8> {
    (0..n).map(|i| u8::try_from(i % 251).unwrap()).collect()
}

fn header_str(h: &HeaderMap, name: header::HeaderName) -> Option<&str> {
    h.get(name).and_then(|v| v.to_str().ok())
}

// ---- authentication --------------------------------------------------------------------------

#[tokio::test]
async fn both_routes_need_a_token() {
    let e = env();
    e.files.put(1, Tier::Hot, b"x");
    for uri in [
        "/api/v1/recordings?camera=cam-1",
        "/api/v1/recordings/1/file",
    ] {
        let resp = e
            .app
            .clone()
            .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "{uri}");
        assert_eq!(body_string(resp).await, super::UNAUTHORIZED_BODY);
    }
    assert!(e.lister.calls.lock().unwrap().is_empty());
    assert_eq!(e.files.open_handles(), 0, "nothing was opened");
}

// ---- listing ---------------------------------------------------------------------------------

/// Any instant the index accepts.
const T0: i64 = 1_700_000_000_000;

fn seg(id: u64, tier: Tier, start: i64, dur: u64, bytes: u64) -> IndexedSegment {
    IndexedSegment::new(
        SegmentId::new(id),
        tier,
        SegmentRecord::new(
            CameraId::new("cam-1").unwrap(),
            UnixMs::new(start).unwrap(),
            dur,
            bytes,
            30,
        ),
    )
}

fn lister_with(page: SegmentPage) -> FakeLister {
    FakeLister {
        result: Some(Ok(page)),
        ..FakeLister::default()
    }
}

#[tokio::test]
async fn list_returns_every_field_and_the_cursor() {
    let page = SegmentPage::new(
        vec![
            seg(7, Tier::Archive, T0, 2_000, 500),
            seg(9, Tier::Hot, T0 + 2_000, 1, 42),
        ],
        Some(SegmentCursor::from_token("abcd".to_owned())),
    );
    let e = env_with(lister_with(page), LIMITS);
    let resp = e.get("/api/v1/recordings?camera=cam-1", None).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        header_str(resp.headers(), header::CONTENT_TYPE),
        Some("application/json")
    );
    let doc: serde_json::Value = serde_json::from_str(&body_string(resp).await).unwrap();
    assert_eq!(
        doc,
        serde_json::json!({
            "segments": [
                {"id": 7, "camera": "cam-1", "started_at": T0, "ended_at": T0 + 2000,
                 "duration": 2000, "bytes": 500, "tier": "archive"},
                {"id": 9, "camera": "cam-1", "started_at": T0 + 2000, "ended_at": T0 + 2001,
                 "duration": 1, "bytes": 42, "tier": "hot"}
            ],
            "next_cursor": "abcd"
        })
    );
    // Defaults reach the port: an open range and 100 rows.
    assert_eq!(
        e.lister.calls.lock().unwrap().as_slice(),
        [("cam-1".to_owned(), i64::MIN, i64::MAX, 100, None)]
    );
}

#[tokio::test]
async fn list_passes_parameters_through() {
    let e = env();
    let resp = e
        .get(
            "/api/v1/recordings?camera=cam-1&from=2024-01-01T02:00:00%2B02:00&to=2024-01-01T00:00:01.5Z&limit=1000&cursor=beef",
            None,
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        body_string(resp).await,
        r#"{"segments":[],"next_cursor":null}"#
    );
    assert_eq!(
        e.lister.calls.lock().unwrap().as_slice(),
        [(
            "cam-1".to_owned(),
            1_704_067_200_000,
            1_704_067_201_500,
            1000,
            Some("beef".to_owned())
        )]
    );
}

/// TEST-9: every query form, one row each. A 400 row must never reach the port.
#[tokio::test]
async fn list_query_table() {
    let long_cursor = "a".repeat(257);
    let max_cursor = "a".repeat(256);
    let long_camera = "a".repeat(33);
    let rows: Vec<(String, u16)> = [
        ("camera=cam-1", 200),
        ("", 400),
        ("camera=", 400),
        ("camera=CAM", 400),
        ("camera=a/b", 400),
        ("camera=1abc", 400),
        ("camera=cam-1&camera=cam-2", 400),
        ("camera=cam-1&limit=0", 400),
        ("camera=cam-1&limit=1", 200),
        ("camera=cam-1&limit=1000", 200),
        ("camera=cam-1&limit=1001", 400),
        ("camera=cam-1&limit=-1", 400),
        ("camera=cam-1&limit=%2B5", 400),
        ("camera=cam-1&limit=abc", 400),
        ("camera=cam-1&limit=", 400),
        ("camera=cam-1&limit=100000000000000000000", 400),
        ("camera=cam-1&limit=1&limit=2", 400),
        ("camera=cam-1&from=yesterday", 400),
        ("camera=cam-1&from=2024-01-01", 400),
        ("camera=cam-1&from=2024-01-01T00:00:00", 400),
        ("camera=cam-1&from=2024-01-01T00:00:00+02:00", 400),
        ("camera=cam-1&from=2024-02-30T00:00:00Z", 400),
        ("camera=cam-1&to=nope", 400),
        ("camera=cam-1&to=2024-01-01T00:00:00Z", 200),
        ("camera=cam-1&to=%C3%A9", 400),
        (
            "camera=cam-1&from=2024-01-01T00:00:01Z&to=2024-01-01T00:00:00Z",
            400,
        ),
        (
            "camera=cam-1&from=2024-01-01T00:00:00Z&to=2024-01-01T00:00:00Z",
            200,
        ),
        (
            "camera=cam-1&from=2024-01-01T00:00:00Z&to=2024-01-01T00:00:00.001Z",
            200,
        ),
        ("camera=cam-1&cursor=", 400),
        ("camera=cam-1&cursor=%C3%A9", 200),
        ("unknown=1&camera=cam-1", 200),
    ]
    .iter()
    .map(|(q, s)| ((*q).to_owned(), *s))
    .chain([
        (format!("camera=cam-1&cursor={long_cursor}"), 400),
        (format!("camera=cam-1&cursor={max_cursor}"), 200),
        (format!("camera={long_camera}"), 400),
    ])
    .collect();
    for (query, want) in rows {
        let e = env();
        let resp = e.get(&format!("/api/v1/recordings?{query}"), None).await;
        assert_eq!(resp.status().as_u16(), want, "{query}");
        let called = !e.lister.calls.lock().unwrap().is_empty();
        assert_eq!(called, want == 200, "port reached iff accepted: {query}");
        if want == 400 {
            assert_eq!(body_string(resp).await, r#"{"error":"bad_request"}"#);
        }
    }
}

#[tokio::test]
async fn list_maps_port_errors() {
    for (err, status, body) in [
        (
            SegmentListError::InvalidCursor,
            StatusCode::BAD_REQUEST,
            r#"{"error":"bad_request"}"#,
        ),
        (
            SegmentListError::Failed,
            StatusCode::INTERNAL_SERVER_ERROR,
            r#"{"error":"internal_error"}"#,
        ),
    ] {
        let e = env_with(
            FakeLister {
                result: Some(Err(err)),
                ..FakeLister::default()
            },
            LIMITS,
        );
        let resp = e
            .get("/api/v1/recordings?camera=cam-1&cursor=ab", None)
            .await;
        assert_eq!(resp.status(), status);
        assert_eq!(body_string(resp).await, body);
    }
}

// ---- download: ids and errors ----------------------------------------------------------------

#[tokio::test]
async fn download_streams_the_whole_file() {
    let e = env();
    // Several chunks, and not a multiple of the chunk size.
    let data = pattern(200_003);
    e.files.put(5, Tier::Hot, &data);
    let resp = e.file(5, None).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let h = resp.headers();
    assert_eq!(header_str(h, header::CONTENT_TYPE), Some("video/mp4"));
    assert_eq!(header_str(h, header::CONTENT_LENGTH), Some("200003"));
    assert_eq!(header_str(h, header::ACCEPT_RANGES), Some("bytes"));
    assert_eq!(header_str(h, header::CONTENT_RANGE), None);
    assert_eq!(bytes_of(resp).await, data);
    wait_closed(&e.files).await;
}

async fn wait_closed(files: &DirFiles) {
    for _ in 0..10_000 {
        if files.open_handles() == 0 {
            return;
        }
        tokio::task::spawn_blocking(|| ()).await.unwrap();
        tokio::task::yield_now().await;
    }
    panic!("a handle stayed open");
}

#[tokio::test]
async fn download_id_table() {
    let e = env();
    e.files.put(1, Tier::Hot, b"x");
    for (id, want) in [
        ("1", 200),
        ("0", 404),
        ("2", 404),
        ("9223372036854775807", 404),
        ("9223372036854775808", 400),
        ("18446744073709551615", 400),
        ("18446744073709551616", 400),
        ("99999999999999999999999999", 400),
        ("01", 400),
        ("00", 400),
        ("-1", 400),
        ("%2B1", 400),
        ("1.0", 400),
        ("1e3", 400),
        ("abc", 400),
        ("0x1", 400),
        ("%20", 400),
        ("%EF%BC%91", 400),
        ("1%00", 400),
        ("..", 400),
        ("%2E%2E", 400),
        ("1%2F..%2F2", 400),
    ] {
        let resp = e.get(&format!("/api/v1/recordings/{id}/file"), None).await;
        assert_eq!(resp.status().as_u16(), want, "{id}");
    }
}

#[tokio::test]
async fn open_errors_map_to_bare_json() {
    let e = env();
    e.files.put(2, Tier::Archive, b"a");
    e.files.archive_up.store(false, Ordering::SeqCst);
    e.files.put(3, Tier::Hot, b"h");
    e.files.failing.lock().unwrap().insert(3);
    for (id, status, body) in [
        (1, StatusCode::NOT_FOUND, r#"{"error":"not_found"}"#),
        (
            2,
            StatusCode::SERVICE_UNAVAILABLE,
            r#"{"error":"unavailable"}"#,
        ),
        (
            3,
            StatusCode::INTERNAL_SERVER_ERROR,
            r#"{"error":"internal_error"}"#,
        ),
    ] {
        let resp = e.file(id, None).await;
        assert_eq!(resp.status(), status, "{id}");
        assert_eq!(
            header_str(resp.headers(), header::CONTENT_TYPE),
            Some("application/json")
        );
        let text = body_string(resp).await;
        assert_eq!(text, body);
        assert!(!text.contains("hot") && !text.contains("archive") && !text.contains('/'));
    }
    assert_eq!(e.files.open_handles(), 0);
    // The archive coming back makes the same row servable.
    e.files.archive_up.store(true, Ordering::SeqCst);
    assert_eq!(e.file(2, None).await.status(), StatusCode::OK);
}

// ---- download: ranges ------------------------------------------------------------------------

/// Expected results are computed from the data, not from the code under test.
#[tokio::test]
#[expect(clippy::too_many_lines, reason = "one table, one row per range form")]
async fn range_table_on_ten_bytes() {
    let e = env();
    let data = b"0123456789";
    e.files.put(1, Tier::Hot, data);
    // (header, status, content-range, expected body)
    let rows: &[(&str, u16, Option<&str>, &[u8])] = &[
        ("bytes=0-0", 206, Some("bytes 0-0/10"), b"0"),
        ("bytes=9-9", 206, Some("bytes 9-9/10"), b"9"),
        ("bytes=0-", 206, Some("bytes 0-9/10"), data),
        ("bytes=5-", 206, Some("bytes 5-9/10"), b"56789"),
        ("bytes=2-4", 206, Some("bytes 2-4/10"), b"234"),
        ("bytes=9-100", 206, Some("bytes 9-9/10"), b"9"),
        ("bytes=0-9", 206, Some("bytes 0-9/10"), data),
        ("bytes=-3", 206, Some("bytes 7-9/10"), b"789"),
        ("bytes=-1", 206, Some("bytes 9-9/10"), b"9"),
        ("bytes=-10", 206, Some("bytes 0-9/10"), data),
        ("bytes=-11", 206, Some("bytes 0-9/10"), data),
        (
            "bytes=-99999999999999999999999",
            206,
            Some("bytes 0-9/10"),
            data,
        ),
        (
            "bytes=0-99999999999999999999999",
            206,
            Some("bytes 0-9/10"),
            data,
        ),
        ("BYTES=1-2", 206, Some("bytes 1-2/10"), b"12"),
        ("bytes=10-", 416, Some("bytes */10"), b""),
        ("bytes=10-10", 416, Some("bytes */10"), b""),
        ("bytes=11-20", 416, Some("bytes */10"), b""),
        ("bytes=-0", 416, Some("bytes */10"), b""),
        (
            "bytes=99999999999999999999999-",
            416,
            Some("bytes */10"),
            b"",
        ),
        ("bytes=18446744073709551615-", 416, Some("bytes */10"), b""),
        ("bytes=18446744073709551616-", 416, Some("bytes */10"), b""),
        // Ignored: the whole file with 200.
        ("bytes=5-3", 200, None, data),
        ("bytes=0-1,3-4", 200, None, data),
        ("bytes=0-1, 3-4", 200, None, data),
        ("bytes=-", 200, None, data),
        ("bytes=", 200, None, data),
        ("bytes", 200, None, data),
        ("bytes=a-b", 200, None, data),
        ("bytes=1-b", 200, None, data),
        ("bytes=a-1", 200, None, data),
        ("bytes=+1-2", 200, None, data),
        ("bytes= 1-2", 200, None, data),
        ("bytes=1 -2", 200, None, data),
        ("bytes=1-2-3", 200, None, data),
        ("bytes=--1", 200, None, data),
        ("bytes=0x1-2", 200, None, data),
        ("items=0-1", 200, None, data),
        ("", 200, None, data),
        ("byte=0-1", 200, None, data),
    ];
    for (range, status, content_range, body) in rows {
        let resp = e.file(1, Some(range)).await;
        assert_eq!(resp.status().as_u16(), *status, "{range:?}");
        assert_eq!(
            header_str(resp.headers(), header::CONTENT_RANGE),
            *content_range,
            "{range:?}"
        );
        if *status == 416 {
            assert_eq!(
                body_string(resp).await,
                r#"{"error":"range_not_satisfiable"}"#
            );
        } else {
            let len = body.len().to_string();
            assert_eq!(
                header_str(resp.headers(), header::CONTENT_LENGTH),
                Some(len.as_str()),
                "{range:?}"
            );
            assert_eq!(bytes_of(resp).await, *body, "{range:?}");
        }
    }
    wait_closed(&e.files).await;
}

#[tokio::test]
async fn range_with_non_text_value_and_repeated_headers_is_ignored() {
    let e = env();
    e.files.put(1, Tier::Hot, b"0123456789");
    let send = |headers: Vec<HeaderValue>| {
        let mut b = Request::builder()
            .uri("/api/v1/recordings/1/file")
            .header(header::AUTHORIZATION, &e.auth);
        for v in headers {
            b = b.header(header::RANGE, v);
        }
        e.app.clone().oneshot(b.body(Body::empty()).unwrap())
    };
    for headers in [
        vec![HeaderValue::from_bytes(b"bytes=0-\xff").unwrap()],
        vec![
            HeaderValue::from_static("bytes=0-1"),
            HeaderValue::from_static("bytes=2-3"),
        ],
    ] {
        let resp = send(headers).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(bytes_of(resp).await, b"0123456789");
    }
}

#[tokio::test]
async fn ranges_on_an_empty_file() {
    let e = env();
    e.files.put(1, Tier::Hot, b"");
    let resp = e.file(1, None).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        header_str(resp.headers(), header::CONTENT_LENGTH),
        Some("0")
    );
    assert_eq!(bytes_of(resp).await, b"");
    for range in ["bytes=0-0", "bytes=0-", "bytes=-1", "bytes=-0", "bytes=5-9"] {
        let resp = e.file(1, Some(range)).await;
        assert_eq!(resp.status(), StatusCode::RANGE_NOT_SATISFIABLE, "{range}");
        assert_eq!(
            header_str(resp.headers(), header::CONTENT_RANGE),
            Some("bytes */0")
        );
    }
}

/// Ranges across chunk boundaries equal the slice of the data.
#[tokio::test]
async fn ranges_across_chunks_match_the_data() {
    let e = env();
    let data = pattern(200_003);
    e.files.put(1, Tier::Hot, &data);
    let last = data.len() - 1;
    let cases = [
        (0, 0),
        (last, last),
        (65_535, 65_536),
        (65_536, 131_071),
        (1, 131_072),
        (100_000, last),
        (0, last),
    ];
    for (a, b) in cases {
        let resp = e.file(1, Some(&format!("bytes={a}-{b}"))).await;
        assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT, "{a}-{b}");
        let want = data.get(a..=b).unwrap();
        assert_eq!(
            header_str(resp.headers(), header::CONTENT_LENGTH),
            Some(want.len().to_string().as_str())
        );
        assert_eq!(
            header_str(resp.headers(), header::CONTENT_RANGE),
            Some(format!("bytes {a}-{b}/{}", data.len()).as_str())
        );
        assert_eq!(bytes_of(resp).await, want, "{a}-{b}");
    }
    let resp = e.file(1, Some("bytes=-70000")).await;
    assert_eq!(
        bytes_of(resp).await,
        data.get(data.len() - 70_000..).unwrap()
    );
    let resp = e.file(1, Some("bytes=199999-")).await;
    assert_eq!(bytes_of(resp).await, data.get(199_999..).unwrap());
}

#[test]
fn choose_range_never_panics_and_stays_inside_the_file() {
    let values = [
        "",
        "bytes=",
        "bytes=-",
        "bytes=0-0",
        "bytes=-0",
        "bytes=9-5",
        "bytes=18446744073709551615-",
        "bytes=-18446744073709551615",
        "bytes=0-18446744073709551615",
        "bytes=\u{e9}-1",
        "bytes=1-\u{e9}",
        "\u{e9}\u{e9}\u{e9}\u{e9}",
        "byt\u{e9}s=1-2",
    ];
    for len in [0u64, 1, 2, 10, u64::MAX] {
        for v in values {
            let mut h = HeaderMap::new();
            if let Ok(value) = HeaderValue::from_str(v) {
                h.insert(header::RANGE, value);
            }
            match choose_range(&h, len) {
                RangeChoice::Slice { start, end } => {
                    assert!(start <= end && end < len, "{v:?} {len}");
                }
                RangeChoice::Full | RangeChoice::Unsatisfiable => {}
            }
        }
    }
}

// ---- download: tiers, limits, timeouts --------------------------------------------------------

#[tokio::test]
async fn a_segment_that_moves_tiers_mid_download_completes() {
    let e = env();
    let data = pattern(300_000);
    e.files.put(1, Tier::Hot, &data);
    let mut resp = e.file(1, None).await;
    assert_eq!(resp.status(), StatusCode::OK);
    // Take the first frame, then the mover finishes: the file leaves the hot tier.
    let first = resp
        .body_mut()
        .frame()
        .await
        .unwrap()
        .unwrap()
        .into_data()
        .unwrap();
    e.files.move_to(1, Tier::Archive);
    assert!(!e.files.path(Tier::Hot, 1).exists());
    let mut got = first.to_vec();
    got.extend(bytes_of(resp).await);
    assert_eq!(got, data);
    // Deleted outright (eviction) while streaming: the open handle still reads.
    e.files.put(2, Tier::Hot, &data);
    let resp = e.file(2, None).await;
    fs::remove_file(e.files.path(Tier::Hot, 2)).unwrap();
    assert_eq!(bytes_of(resp).await, data);
    // A new request follows the row to its new tier.
    let resp = e.file(1, None).await;
    assert_eq!(bytes_of(resp).await, data);
}

#[tokio::test]
async fn a_client_that_goes_away_releases_the_file() {
    let e = env();
    e.files.put(1, Tier::Hot, &pattern(500_000));
    let mut resp = e.file(1, None).await;
    let _ = resp.body_mut().frame().await.unwrap().unwrap();
    assert_eq!(e.files.open_handles(), 1);
    drop(resp);
    wait_closed(&e.files).await;
}

/// Advances the paused clock in `step`s until `done` holds. A step that lands before the pump is
/// waiting for the client changes nothing, so this converges whatever the thread timing; a
/// download that is never cut exhausts the bound and fails.
async fn advance_until(step: Duration, mut done: impl FnMut() -> bool) {
    for _ in 0..10_000 {
        if done() {
            return;
        }
        tokio::time::advance(step).await;
        tokio::task::spawn_blocking(|| ()).await.unwrap();
        tokio::task::yield_now().await;
    }
    panic!("the condition never held");
}

#[tokio::test(start_paused = true)]
async fn a_stalled_client_is_cut_after_the_idle_timeout() {
    let e = env();
    let data = pattern(500_000);
    e.files.put(1, Tier::Hot, &data);
    let mut resp = e.file(1, None).await;
    assert_eq!(e.files.open_handles(), 1);
    // Never poll the body. The pump holds one chunk in the channel and one waiting to be sent.
    advance_until(IDLE, || e.files.open_handles() == 0).await;
    // The client now sees the delivered prefix, then an error: never a clean end.
    let mut got = Vec::new();
    let mut failed = false;
    while let Some(frame) = resp.body_mut().frame().await {
        match frame {
            Ok(f) => got.extend(f.into_data().unwrap()),
            Err(_) => failed = true,
        }
    }
    assert!(failed, "a cut download ends in an error");
    assert!(got.len() < data.len());
    assert_eq!(
        got,
        data.get(..got.len()).unwrap(),
        "what arrived is a true prefix"
    );
}

#[tokio::test(start_paused = true)]
async fn a_slow_but_steady_client_is_not_cut() {
    let e = env();
    let data = pattern(500_000);
    e.files.put(1, Tier::Hot, &data);
    let mut resp = e.file(1, None).await;
    let started = tokio::time::Instant::now();
    let mut got = Vec::new();
    while let Some(frame) = resp.body_mut().frame().await {
        got.extend(frame.unwrap().into_data().unwrap());
        // Each pause is below the idle timeout; together they are far above it.
        tokio::time::advance(JUST_UNDER_IDLE).await;
    }
    assert!(started.elapsed() > IDLE * 3);
    assert_eq!(got, data);
}

#[tokio::test(start_paused = true)]
async fn downloads_are_capped_and_a_cut_one_frees_its_slot() {
    let e = env_with(
        FakeLister::default(),
        Limits {
            download_idle: IDLE,
            max_downloads: 2,
            ..LIMITS
        },
    );
    e.files.put(1, Tier::Hot, &pattern(500_000));
    let a = e.file(1, None).await;
    let b = e.file(1, None).await;
    assert_eq!((a.status(), b.status()), (StatusCode::OK, StatusCode::OK));
    let c = e.file(1, None).await;
    assert_eq!(c.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(header_str(c.headers(), header::RETRY_AFTER), Some("1"));
    assert_eq!(body_string(c).await, r#"{"error":"unavailable"}"#);
    assert_eq!(
        e.files.open_handles(),
        2,
        "the refused request opened nothing"
    );
    // Both stalled downloads are cut by the idle timeout; then a slot is free again.
    let mut served = None;
    for _ in 0..10_000 {
        let resp = e.file(1, Some("bytes=0-0")).await;
        if resp.status() == StatusCode::PARTIAL_CONTENT {
            served = Some(resp);
            break;
        }
        tokio::time::advance(IDLE).await;
        tokio::task::spawn_blocking(|| ()).await.unwrap();
        tokio::task::yield_now().await;
    }
    assert_eq!(bytes_of(served.expect("a slot was freed")).await.len(), 1);
    drop((a, b));
}

#[tokio::test]
async fn a_finished_download_frees_its_slot() {
    let e = env_with(
        FakeLister::default(),
        Limits {
            download_idle: IDLE,
            max_downloads: 1,
            ..LIMITS
        },
    );
    e.files.put(1, Tier::Hot, &pattern(70_000));
    for _ in 0..3 {
        let resp = e.file(1, None).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(bytes_of(resp).await.len(), 70_000);
        // The permit goes with the pump, a moment after the last byte.
        let mut freed = false;
        for _ in 0..10_000 {
            let probe = e.file(1, Some("bytes=0-0")).await;
            if probe.status() == StatusCode::PARTIAL_CONTENT {
                let _ = bytes_of(probe).await;
                freed = true;
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(freed);
    }
}

// ---- documentation and structure --------------------------------------------------------------

#[tokio::test]
async fn openapi_documents_both_routes() {
    let e = env();
    let resp = e.get("/api/v1/openapi.json", None).await;
    let doc: serde_json::Value = serde_json::from_str(&body_string(resp).await).unwrap();
    let list = &doc["paths"]["/api/v1/recordings"]["get"];
    assert!(list["responses"]["200"].is_object());
    assert!(list["responses"]["400"].is_object());
    let names: Vec<&str> = list["parameters"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["camera", "from", "to", "limit", "cursor"]);
    let file = &doc["paths"]["/api/v1/recordings/{id}/file"]["get"];
    for status in ["200", "206", "400", "401", "404", "416", "500", "503"] {
        assert!(file["responses"][status].is_object(), "{status}");
    }
    assert!(file["responses"]["206"]["content"]["video/mp4"].is_object());
}

/// ADR 0005 section 7: the API holds no path, root or `openat2`. A structural guard on the module.
#[test]
fn the_recordings_module_touches_no_file_system_api() {
    let src: String = include_str!("../recordings.rs")
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    for banned in [
        "std::fs",
        "std::path",
        "PathBuf",
        "canonicalize",
        "openat",
        "tokio::fs",
        "File::open",
    ] {
        assert!(!src.contains(banned), "{banned}");
    }
}
