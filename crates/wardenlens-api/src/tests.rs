//! In-process router tests: `oneshot`, no sockets, an in-memory fake `TokenStore`.

use std::collections::HashMap;
use std::io;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::extract::State;
use axum::http::{Request, Response, StatusCode, header};
use axum::routing::get;
use http_body_util::BodyExt as _;
use tokio::sync::Semaphore;
use tower::ServiceExt as _;
use wardenlens_core::camera::{
    Camera, CameraDirectory, CameraId, CameraStatus, Credential, DirectoryError, LinkStatus,
};
use wardenlens_core::storage::{
    SegmentCursor, SegmentListError, SegmentLister, SegmentPage, StorageSnapshot, StorageStatus,
    StorageStatusError,
};
use wardenlens_core::time::Timestamp;
use wardenlens_core::token_store::{TokenId, TokenRecord, TokenStore, TokenStoreError};

use super::{LIMITS, Limits, build, with_layers};
use crate::token::Token;

#[derive(Default)]
struct FakeStore {
    records: Mutex<HashMap<String, TokenRecord>>,
    fail: bool,
}

impl FakeStore {
    fn add(&self, token: &Token, revoked: bool) {
        let rec = TokenRecord {
            digest: token.secret().digest(),
            revoked,
        };
        if let Ok(mut m) = self.records.lock() {
            m.insert(token.id().to_string(), rec);
        }
    }
}

impl TokenStore for FakeStore {
    fn find(
        &self,
        id: &TokenId,
    ) -> impl Future<Output = Result<Option<TokenRecord>, TokenStoreError>> + Send {
        let out = if self.fail {
            Err(TokenStoreError)
        } else {
            self.records
                .lock()
                .map(|m| m.get(id.as_str()).cloned())
                .map_err(|_| TokenStoreError)
        };
        std::future::ready(out)
    }
}

/// Synthetic camera directory: a fixed list, or a failure.
#[derive(Default)]
struct FakeDirectory {
    cameras: Vec<Camera>,
    fail: bool,
    /// What a real directory's vault would hold for each camera. Never served.
    credentials: HashMap<String, Credential>,
}

impl CameraDirectory for FakeDirectory {
    fn list(&self) -> impl Future<Output = Result<Vec<Camera>, DirectoryError>> + Send {
        std::future::ready(if self.fail {
            Err(DirectoryError)
        } else {
            Ok(self.cameras.clone())
        })
    }

    fn get(
        &self,
        id: &CameraId,
    ) -> impl Future<Output = Result<Option<Camera>, DirectoryError>> + Send {
        std::future::ready(if self.fail {
            Err(DirectoryError)
        } else {
            Ok(self.cameras.iter().find(|c| c.id() == id).cloned())
        })
    }
}

/// Synthetic live status by camera id.
#[derive(Default)]
struct FakeStatus(HashMap<String, LinkStatus>);

impl CameraStatus for FakeStatus {
    fn status(&self, id: &CameraId) -> impl Future<Output = Option<LinkStatus>> + Send {
        std::future::ready(self.0.get(id.as_str()).copied())
    }
}

/// Synthetic storage status: a fixed snapshot, or a failure.
struct FakeStorage {
    snapshot: StorageSnapshot,
    fail: bool,
}

impl Default for FakeStorage {
    fn default() -> Self {
        Self {
            snapshot: StorageSnapshot::initial(),
            fail: false,
        }
    }
}

impl StorageStatus for FakeStorage {
    fn snapshot(&self) -> impl Future<Output = Result<StorageSnapshot, StorageStatusError>> + Send {
        std::future::ready(if self.fail {
            Err(StorageStatusError)
        } else {
            Ok(self.snapshot)
        })
    }
}

/// Synthetic segment listing: a fixed result, or a failure.
#[derive(Default)]
struct FakeLister {
    result: Option<Result<SegmentPage, SegmentListError>>,
    /// The arguments of every call, for assertions.
    calls: Mutex<Vec<ListCall>>,
}

type ListCall = (String, i64, i64, usize, Option<String>);

impl SegmentLister for FakeLister {
    fn list(
        &self,
        camera: &CameraId,
        from: Timestamp,
        to: Timestamp,
        limit: usize,
        cursor: Option<&SegmentCursor>,
    ) -> impl Future<Output = Result<SegmentPage, SegmentListError>> + Send {
        if let Ok(mut c) = self.calls.lock() {
            c.push((
                camera.as_str().to_owned(),
                from.as_unix_millis(),
                to.as_unix_millis(),
                limit,
                cursor.map(|c| c.as_token().to_owned()),
            ));
        }
        std::future::ready(
            self.result
                .clone()
                .unwrap_or_else(|| Ok(SegmentPage::new(Vec::new(), None))),
        )
    }
}

fn app_with(store: FakeStore) -> (Router, Token) {
    let token = Token::generate().unwrap();
    store.add(&token, false);
    (
        build(
            Arc::new(store),
            FakeDirectory::default(),
            FakeStatus::default(),
            FakeStorage::default(),
            FakeLister::default(),
            wardenlens_core::storage::MemorySegmentFiles::new(),
            LIMITS,
        ),
        token,
    )
}

fn app() -> (Router, Token) {
    app_with(FakeStore::default())
}

fn get_req(path: &str, auth: Option<&str>) -> Request<Body> {
    let mut b = Request::builder().uri(path);
    if let Some(a) = auth {
        b = b.header(header::AUTHORIZATION, a);
    }
    b.body(Body::empty()).unwrap()
}

async fn body_string(resp: Response<Body>) -> String {
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    String::from_utf8(bytes.to_vec()).unwrap()
}

const UNAUTHORIZED_BODY: &str = r#"{"error":"unauthorized"}"#;

#[tokio::test]
async fn health_is_open_and_has_no_version() {
    let (app, _) = app();
    let resp = app.oneshot(get_req("/api/v1/health", None)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_string(resp).await, r#"{"status":"ok"}"#);
}

#[tokio::test]
async fn openapi_requires_token_and_serves_with_one() {
    let (app, token) = app();
    let resp = app
        .clone()
        .oneshot(get_req("/api/v1/openapi.json", None))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let auth = format!("Bearer {}", token.expose());
    let resp = app
        .oneshot(get_req("/api/v1/openapi.json", Some(&auth)))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn openapi_lists_every_route_and_declares_bearer_scheme() {
    let (app, token) = app();
    let auth = format!("Bearer {}", token.expose());
    let resp = app
        .oneshot(get_req("/api/v1/openapi.json", Some(&auth)))
        .await
        .unwrap();
    let doc: serde_json::Value = serde_json::from_str(&body_string(resp).await).unwrap();
    let mut paths: Vec<&str> = doc["paths"]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    paths.sort_unstable();
    // Add every new route here; a route missing from the document fails this test.
    assert_eq!(
        paths,
        [
            "/api/v1/cameras",
            "/api/v1/cameras/{id}",
            "/api/v1/health",
            "/api/v1/openapi.json",
            "/api/v1/recordings",
            "/api/v1/recordings/{id}/file",
            "/api/v1/storage"
        ]
    );
    let scheme = &doc["components"]["securitySchemes"]["bearer"];
    assert_eq!(scheme["type"], "http");
    assert_eq!(scheme["scheme"], "bearer");
    assert_eq!(doc["security"][0]["bearer"], serde_json::json!([]));
}

#[tokio::test]
async fn all_authentication_failures_look_identical() {
    let store = FakeStore::default();
    let revoked = Token::generate().unwrap();
    store.add(&revoked, true);
    let known = Token::generate().unwrap();
    store.add(&known, false);
    let app = build(
        Arc::new(store),
        FakeDirectory::default(),
        FakeStatus::default(),
        FakeStorage::default(),
        FakeLister::default(),
        wardenlens_core::storage::MemorySegmentFiles::new(),
        LIMITS,
    );
    let unknown = Token::generate().unwrap();
    let wrong_secret = {
        let other = Token::generate().unwrap();
        format!("wl_{}_{}", known.id(), &other.expose()[12..])
    };
    let attempts: Vec<Option<String>> = vec![
        None,
        Some(String::new()),
        Some("Bearer".into()),
        Some("Bearer ".into()),
        Some("Bearer garbage".into()),
        Some(format!("Basic {}", known.expose())),
        Some(known.expose()),
        Some(format!("Bearer {}", unknown.expose())),
        Some(format!("Bearer {}", revoked.expose())),
        Some(format!("Bearer {wrong_secret}")),
        Some(format!("Bearer {}", "a".repeat(300))),
    ];
    for a in attempts {
        let resp = app
            .clone()
            .oneshot(get_req("/api/v1/openapi.json", a.as_deref()))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "{a:?}");
        assert_eq!(resp.headers()[header::WWW_AUTHENTICATE], "Bearer");
        assert_eq!(body_string(resp).await, UNAUTHORIZED_BODY, "{a:?}");
    }
}

#[tokio::test]
async fn two_authorization_headers_are_rejected() {
    let (app, token) = app();
    let good = format!("Bearer {}", token.expose());
    let req = Request::builder()
        .uri("/api/v1/openapi.json")
        .header(header::AUTHORIZATION, &good)
        .header(header::AUTHORIZATION, &good)
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        app.oneshot(req).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn bearer_scheme_is_case_insensitive() {
    let (app, token) = app();
    for scheme in ["bearer", "BEARER", "BeArEr", "Bearer"] {
        let auth = format!("{scheme} {}", token.expose());
        let resp = app
            .clone()
            .oneshot(get_req("/api/v1/openapi.json", Some(&auth)))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "{scheme}");
    }
}

#[tokio::test]
async fn token_in_query_string_is_rejected() {
    let (app, token) = app();
    for q in ["access_token", "token", "authorization"] {
        let uri = format!("/api/v1/openapi.json?{q}={}", token.expose());
        let resp = app.clone().oneshot(get_req(&uri, None)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "{q}");
    }
}

#[tokio::test]
async fn unknown_path_needs_token_then_is_json_404() {
    let (app, token) = app();
    let resp = app
        .clone()
        .oneshot(get_req("/api/v1/nope", None))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let auth = format!("Bearer {}", token.expose());
    let resp = app
        .oneshot(get_req("/api/v1/nope", Some(&auth)))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    assert_eq!(body_string(resp).await, r#"{"error":"not_found"}"#);
}

#[tokio::test]
async fn wrong_method_is_json_405() {
    let (app, _) = app();
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/health")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(body_string(resp).await, r#"{"error":"method_not_allowed"}"#);
}

#[tokio::test]
async fn store_failure_is_500_without_detail() {
    let store = FakeStore {
        fail: true,
        ..FakeStore::default()
    };
    let (app, token) = app_with(store);
    let auth = format!("Bearer {}", token.expose());
    let resp = app
        .oneshot(get_req("/api/v1/openapi.json", Some(&auth)))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(body_string(resp).await, r#"{"error":"internal_error"}"#);
}

fn req_with_length(len: usize) -> Request<Body> {
    Request::builder()
        .uri("/api/v1/health")
        .header(header::CONTENT_LENGTH, len)
        .body(Body::from(vec![b'x'; len]))
        .unwrap()
}

#[tokio::test]
async fn body_over_64_kib_is_rejected_with_json_413() {
    let (app, _) = app();
    let resp = app.oneshot(req_with_length(64 * 1024 + 1)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(body_string(resp).await, r#"{"error":"payload_too_large"}"#);
}

#[tokio::test]
async fn body_of_exactly_64_kib_is_accepted() {
    let (app, _) = app();
    let resp = app.oneshot(req_with_length(64 * 1024)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test(start_paused = true)]
async fn slow_handler_gets_json_408() {
    let slow = Router::new().route(
        "/slow",
        get(|| async {
            tokio::time::sleep(Duration::from_secs(3600)).await;
            "late"
        }),
    );
    let limits = Limits {
        timeout: Duration::from_secs(5),
        ..LIMITS
    };
    let resp = with_layers(slow, limits)
        .oneshot(get_req("/slow", None))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::REQUEST_TIMEOUT);
    assert_eq!(body_string(resp).await, r#"{"error":"request_timeout"}"#);
}

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl io::Write for Capture {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if let Ok(mut v) = self.0.lock() {
            v.extend_from_slice(buf);
        }
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Capture {
    type Writer = Capture;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// Installs (once) a process-wide capturing subscriber and returns its buffer. A
/// thread-local one loses to callsite interest cached as "disabled" by tests running in
/// parallel. Tests share the buffer, so each filters on a unique marker.
fn capture() -> &'static Capture {
    static CAPTURE: OnceLock<Capture> = OnceLock::new();
    CAPTURE.get_or_init(|| {
        let capture = Capture::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(capture.clone())
            .with_max_level(tracing::Level::TRACE)
            .finish();
        // Ignoring the error is fine: it only fails if a global subscriber exists already.
        let _ = tracing::subscriber::set_global_default(subscriber);
        capture
    })
}

fn captured() -> String {
    String::from_utf8(capture().0.lock().unwrap().clone()).unwrap()
}

#[tokio::test]
async fn token_is_absent_from_trace_output() {
    capture();
    let (app, token) = app();
    let secret = token.expose();
    let auth = format!("Bearer {secret}");
    let req = Request::builder()
        .uri("/api/v1/openapi.json")
        .header(header::AUTHORIZATION, &auth)
        .header(header::COOKIE, format!("session={secret}"))
        .header(header::PROXY_AUTHORIZATION, format!("Bearer {secret}"))
        .header("x-control", "visible-marker")
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        app.clone().oneshot(req).await.unwrap().status(),
        StatusCode::OK
    );
    // A token in the query string is not accepted, and must not be traced either.
    let query = format!("/api/v1/openapi.json?access_token={secret}");
    assert_eq!(
        app.oneshot(get_req(&query, None)).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
    let out = captured();
    // Positive control: headers are traced, so the absence below is meaningful.
    assert!(out.contains("visible-marker"), "headers not traced: {out}");
    assert!(!out.contains(&secret), "token leaked into trace output");
    assert!(
        !out.contains(&secret[12..]),
        "secret leaked into trace output"
    );
}

/// Lines of `out` that mention `marker` and `message`.
fn count_lines(out: &str, marker: &str, message: &str) -> usize {
    out.lines()
        .filter(|l| l.contains(marker) && l.contains(message))
        .count()
}

#[tokio::test]
async fn auth_failures_are_sampled_and_log_only_the_token_id() {
    capture();
    let (app, _) = app();
    let unknown = Token::generate().unwrap();
    let auth = format!("Bearer {}", unknown.expose());
    let marker = "/api/v1/sampling-auth-marker";
    let n = 200usize;
    for _ in 0..n {
        let resp = app
            .clone()
            .oneshot(get_req(marker, Some(&auth)))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }
    let out = captured();
    assert_eq!(
        count_lines(&out, marker, "authentication failed"),
        n.div_ceil(64)
    );
    for line in out
        .lines()
        .filter(|l| l.contains("authentication failed") && l.contains(marker))
    {
        assert!(
            line.contains(&format!("token_id=Some(\"{}\")", unknown.id())),
            "{line}"
        );
        assert!(!line.contains(&unknown.expose()), "{line}");
        assert!(!line.contains(&unknown.expose()[12..]), "{line}");
        assert!(!line.contains("token store unavailable"), "{line}");
    }
    assert_eq!(count_lines(&out, marker, "token store unavailable"), 0);
}

#[tokio::test]
async fn store_failures_are_sampled_separately_and_log_no_token() {
    capture();
    let store = FakeStore {
        fail: true,
        ..FakeStore::default()
    };
    let (app, token) = app_with(store);
    let auth = format!("Bearer {}", token.expose());
    let marker = "/api/v1/sampling-store-marker";
    let n = 130usize;
    for _ in 0..n {
        let resp = app
            .clone()
            .oneshot(get_req(marker, Some(&auth)))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }
    // Interleave auth failures: they must not advance the store counter.
    for _ in 0..3 {
        let resp = app.clone().oneshot(get_req(marker, None)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }
    let out = captured();
    assert_eq!(
        count_lines(&out, marker, "token store unavailable"),
        n.div_ceil(64)
    );
    // The auth counter saw only the 3 header-less failures: one warn line.
    assert_eq!(count_lines(&out, marker, "authentication failed"), 1);
    for line in out
        .lines()
        .filter(|l| l.contains("token store unavailable") && l.contains(marker))
    {
        assert!(line.contains("ERROR"), "{line}");
        assert!(!line.contains(token.id().as_str()), "{line}");
        assert!(!line.contains("wl_"), "{line}");
    }
}

#[tokio::test(start_paused = true)]
async fn request_queued_for_a_slot_past_the_timeout_still_succeeds() {
    async fn hold() -> &'static str {
        tokio::time::sleep(Duration::from_secs(8)).await;
        "held"
    }
    let router = Router::new()
        .route("/hold", get(hold))
        .route("/fast", get(|| async { "fast" }));
    let app = with_layers(
        router,
        Limits {
            max_in_flight: 1,
            timeout: Duration::from_secs(10),
            ..LIMITS
        },
    );
    let start = tokio::time::Instant::now();
    let spawn = |path: &'static str| {
        let app = app.clone();
        tokio::spawn(async move { app.oneshot(get_req(path, None)).await })
    };
    let first = spawn("/hold");
    for _ in 0..50 {
        tokio::task::yield_now().await;
    }
    let second = spawn("/hold");
    for _ in 0..50 {
        tokio::task::yield_now().await;
    }
    let queued = spawn("/fast");
    for h in [first, second, queued] {
        assert_eq!(h.await.unwrap().unwrap().status(), StatusCode::OK);
    }
    // The last request waited 16 s for its slot: longer than the 10 s deadline. The permit
    // is taken in `poll_ready` and the timer starts at `call`, so this holds for either
    // order of the two layers; it does not pin that order.
    assert!(start.elapsed() >= Duration::from_secs(16));
}

#[tokio::test(start_paused = true)]
async fn waiting_inside_the_handler_does_consume_the_request_deadline() {
    // Counterpart of the test above: waiting that starts after `call` (here, on a lock the
    // handler takes) is charged to the 5 s deadline. Without this, the test above could
    // not fail for any reason about when the timer starts.
    async fn gated(State(gate): State<Arc<Semaphore>>) -> &'static str {
        let _permit = gate.acquire().await;
        tokio::time::sleep(Duration::from_secs(8)).await;
        "done"
    }
    let router = Router::new()
        .route("/gated", get(gated))
        .with_state(Arc::new(Semaphore::new(1)));
    let app = with_layers(
        router,
        Limits {
            max_in_flight: 2,
            timeout: Duration::from_secs(5),
            ..LIMITS
        },
    );
    let start = tokio::time::Instant::now();
    let spawn = || {
        let app = app.clone();
        tokio::spawn(async move { app.oneshot(get_req("/gated", None)).await })
    };
    let first = spawn();
    for _ in 0..50 {
        tokio::task::yield_now().await;
    }
    let second = spawn();
    for h in [first, second] {
        assert_eq!(
            h.await.unwrap().unwrap().status(),
            StatusCode::REQUEST_TIMEOUT
        );
    }
    // Both ended at the 5 s deadline; the second never got the handler's lock in time.
    assert!(start.elapsed() < Duration::from_secs(8));
}

#[tokio::test]
async fn health_declares_no_security_requirement() {
    let (app, token) = app();
    let auth = format!("Bearer {}", token.expose());
    let resp = app
        .oneshot(get_req("/api/v1/openapi.json", Some(&auth)))
        .await
        .unwrap();
    let doc: serde_json::Value = serde_json::from_str(&body_string(resp).await).unwrap();
    assert_eq!(
        doc["paths"]["/api/v1/health"]["get"]["security"],
        serde_json::json!([{}])
    );
}

#[tokio::test]
async fn undocumented_path_is_never_served() {
    let (app, token) = app();
    let auth = format!("Bearer {}", token.expose());
    for (a, want) in [
        (None, StatusCode::UNAUTHORIZED),
        (Some(auth.as_str()), StatusCode::NOT_FOUND),
    ] {
        let resp = app
            .clone()
            .oneshot(get_req("/api/v1/undocumented", a))
            .await
            .unwrap();
        assert_eq!(resp.status(), want);
    }
}

mod adversary;
mod adversary_r2;
mod cameras;
mod recordings;
mod storage;
