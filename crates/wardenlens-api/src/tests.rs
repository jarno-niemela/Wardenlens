//! In-process router tests: `oneshot`, no sockets, an in-memory fake `TokenStore`.

use std::collections::HashMap;
use std::io;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, Response, StatusCode, header};
use axum::routing::get;
use http_body_util::BodyExt as _;
use tower::ServiceExt as _;
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

fn app_with(store: FakeStore) -> (Router, Token) {
    let token = Token::generate().unwrap();
    store.add(&token, false);
    (build(Arc::new(store), LIMITS), token)
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
    assert_eq!(paths, ["/api/v1/health", "/api/v1/openapi.json"]);
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
    let app = build(Arc::new(store), LIMITS);
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

#[tokio::test]
async fn token_is_absent_from_trace_output() {
    // A process-wide subscriber: a thread-local one loses to callsite interest cached
    // as "disabled" by tests running in parallel. Other tests' output lands in the same
    // buffer, which only makes the absence check stricter.
    static CAPTURE: OnceLock<Capture> = OnceLock::new();
    let capture = CAPTURE.get_or_init(|| {
        let capture = Capture::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(capture.clone())
            .with_max_level(tracing::Level::TRACE)
            .finish();
        // Ignoring the error is fine: it only fails if a global subscriber exists already.
        let _ = tracing::subscriber::set_global_default(subscriber);
        capture
    });
    let (app, token) = app();
    let secret = token.expose();
    let auth = format!("Bearer {secret}");
    let req = Request::builder()
        .uri("/api/v1/openapi.json")
        .header(header::AUTHORIZATION, &auth)
        .header("x-control", "visible-marker")
        .body(Body::empty())
        .unwrap();
    assert_eq!(app.oneshot(req).await.unwrap().status(), StatusCode::OK);
    let out = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
    // Positive control: headers are traced, so the absence below is meaningful.
    assert!(out.contains("visible-marker"), "headers not traced: {out}");
    assert!(!out.contains(&secret), "token leaked into trace output");
    assert!(
        !out.contains(&secret[12..]),
        "secret leaked into trace output"
    );
}
