//! Round-2 adversarial tests for #60: the global cap through the real `build`, slot
//! release on timeout, store hangs, and redaction of repeated sensitive headers.

use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use axum::routing::get;
use tower::ServiceExt as _;
use wardenlens_core::token_store::{TokenId, TokenRecord, TokenStore, TokenStoreError};

use super::{
    FakeDirectory, FakeLister, FakeStatus, FakeStorage, body_string, capture, captured, get_req,
};
use crate::token::Token;
use crate::{LIMITS, Limits, build, with_layers};

/// A store whose lookups never finish.
struct HangingStore;

impl TokenStore for HangingStore {
    fn find(
        &self,
        _id: &TokenId,
    ) -> impl Future<Output = Result<Option<TokenRecord>, TokenStoreError>> + Send {
        std::future::pending()
    }
}

fn hanging_app(limits: Limits) -> Router {
    build(
        Arc::new(HangingStore),
        FakeDirectory::default(),
        FakeStatus::default(),
        FakeStorage::default(),
        FakeLister::default(),
        wardenlens_core::storage::MemorySegmentFiles::new(),
        limits,
    )
}

fn req(method: &str, path: &str, auth: Option<&str>) -> Request<Body> {
    let mut b = Request::builder().method(method).uri(path);
    if let Some(a) = auth {
        b = b.header(header::AUTHORIZATION, a);
    }
    b.body(Body::empty()).unwrap()
}

/// With a cap of 1, holds the only slot with an authenticated request stuck in the
/// store, then reports whether `method path` completes within one virtual second.
async fn completes_while_slot_held(method: &str, path: &str, auth: Option<&str>) -> bool {
    let app = hanging_app(Limits {
        max_in_flight: 1,
        timeout: Duration::from_secs(100_000),
        ..LIMITS
    });
    let holder_tok = Token::generate().unwrap();
    let holder_auth = format!("Bearer {}", holder_tok.expose());
    let holder = app.clone();
    let held = tokio::spawn(async move {
        holder
            .oneshot(req("GET", "/api/v1/openapi.json", Some(&holder_auth)))
            .await
    });
    for _ in 0..50 {
        tokio::task::yield_now().await;
    }
    let done = tokio::time::timeout(Duration::from_secs(1), app.oneshot(req(method, path, auth)))
        .await
        .is_ok();
    held.abort();
    done
}

#[tokio::test(start_paused = true)]
async fn real_router_cap_is_global_for_open_health() {
    assert!(!completes_while_slot_held("GET", "/api/v1/health", None).await);
}

#[tokio::test(start_paused = true)]
async fn real_router_cap_is_global_for_405_on_health() {
    assert!(!completes_while_slot_held("POST", "/api/v1/health", None).await);
}

#[tokio::test(start_paused = true)]
async fn real_router_cap_is_global_for_unknown_path_without_token() {
    assert!(!completes_while_slot_held("GET", "/nope", None).await);
}

#[tokio::test(start_paused = true)]
async fn real_router_cap_is_global_for_protected_401() {
    assert!(!completes_while_slot_held("GET", "/api/v1/openapi.json", None).await);
}

#[tokio::test(start_paused = true)]
async fn real_router_cap_control_without_holder_completes() {
    // Control: the same request completes when nothing holds the slot.
    let app = hanging_app(Limits {
        max_in_flight: 1,
        ..LIMITS
    });
    let done = tokio::time::timeout(
        Duration::from_secs(1),
        app.oneshot(req("GET", "/api/v1/health", None)),
    )
    .await;
    assert_eq!(done.unwrap().unwrap().status(), StatusCode::OK);
}

#[tokio::test(start_paused = true)]
async fn hanging_store_gives_json_408_not_hang() {
    let app = hanging_app(Limits {
        timeout: Duration::from_secs(5),
        ..LIMITS
    });
    let t = Token::generate().unwrap();
    let auth = format!("Bearer {}", t.expose());
    let resp = app
        .oneshot(req("GET", "/api/v1/openapi.json", Some(&auth)))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::REQUEST_TIMEOUT);
    assert_eq!(body_string(resp).await, r#"{"error":"request_timeout"}"#);
}

#[tokio::test(start_paused = true)]
async fn timed_out_request_releases_its_slot() {
    let r = Router::new()
        .route(
            "/slow",
            get(|| async {
                tokio::time::sleep(Duration::from_secs(3600)).await;
                "late"
            }),
        )
        .route("/fast", get(|| async { "fast" }));
    let app = with_layers(
        r,
        Limits {
            max_in_flight: 1,
            timeout: Duration::from_secs(5),
            ..LIMITS
        },
    );
    for _ in 0..3 {
        let resp = app.clone().oneshot(get_req("/slow", None)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::REQUEST_TIMEOUT);
    }
    let done =
        tokio::time::timeout(Duration::from_secs(1), app.oneshot(get_req("/fast", None))).await;
    assert_eq!(done.unwrap().unwrap().status(), StatusCode::OK);
}

#[tokio::test(start_paused = true)]
async fn many_concurrent_requests_all_complete_under_cap() {
    // No lost permits: 20 requests through a cap of 2 all finish.
    let r = Router::new().route(
        "/w",
        get(|| async {
            tokio::time::sleep(Duration::from_secs(1)).await;
            "ok"
        }),
    );
    let app = with_layers(
        r,
        Limits {
            max_in_flight: 2,
            timeout: Duration::from_secs(5),
            ..LIMITS
        },
    );
    let start = tokio::time::Instant::now();
    let hs: Vec<_> = (0..20)
        .map(|_| {
            let a = app.clone();
            tokio::spawn(async move { a.oneshot(get_req("/w", None)).await })
        })
        .collect();
    for h in hs {
        assert_eq!(h.await.unwrap().unwrap().status(), StatusCode::OK);
    }
    // 20 requests, 2 at a time, 1 s each: at least 10 s.
    assert!(start.elapsed() >= Duration::from_secs(10));
}

#[tokio::test]
async fn repeated_sensitive_headers_are_all_redacted_in_trace() {
    capture();
    let (app, token) = super::app();
    let secret = token.expose();
    let other = Token::generate().unwrap().expose();
    let mut r = req("GET", "/api/v1/r2-redact-marker", None);
    let h = r.headers_mut();
    h.append(
        header::AUTHORIZATION,
        format!("Bearer {secret}").parse().unwrap(),
    );
    h.append(
        header::AUTHORIZATION,
        format!("Bearer {other}").parse().unwrap(),
    );
    h.append(header::COOKIE, format!("a={secret}").parse().unwrap());
    h.append(header::COOKIE, format!("b={other}").parse().unwrap());
    h.append(
        header::PROXY_AUTHORIZATION,
        format!("Bearer {other}").parse().unwrap(),
    );
    h.append("x-control", "r2-visible-marker".parse().unwrap());
    let resp = app.oneshot(r).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let out = captured();
    assert!(out.contains("r2-visible-marker"));
    assert!(!out.contains(&secret[12..]), "first secret leaked");
    assert!(!out.contains(&other[12..]), "second secret leaked");
}

#[tokio::test]
async fn health_head_and_options_do_not_need_token_or_leak_cors() {
    let (app, _) = super::app();
    let resp = app
        .oneshot(req("OPTIONS", "/api/v1/health", None))
        .await
        .unwrap();
    assert!(
        resp.headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .is_none()
    );
    assert!(resp.status().is_client_error());
    let ct = resp.headers().get(header::CONTENT_TYPE).cloned();
    assert_eq!(ct.unwrap(), "application/json");
}

#[tokio::test]
async fn oversized_body_on_protected_route_is_413_json_and_no_store_call() {
    let app = hanging_app(LIMITS);
    let r = Request::builder()
        .method("POST")
        .uri("/api/v1/openapi.json")
        .header(header::CONTENT_LENGTH, 64 * 1024 + 1)
        .body(Body::from(vec![0u8; 64 * 1024 + 1]))
        .unwrap();
    let resp = tokio::time::timeout(Duration::from_secs(5), app.oneshot(r))
        .await
        .unwrap()
        .unwrap();
    // Either 401 (auth first) or 413 is acceptable; it must be JSON and not hang.
    assert!(
        resp.status() == StatusCode::UNAUTHORIZED || resp.status() == StatusCode::PAYLOAD_TOO_LARGE
    );
    assert!(body_string(resp).await.starts_with("{\"error\":"));
}

/// A router whose `/boom` route answers `500`, behind the real layers.
fn failing_app() -> Router {
    let r = Router::new().route(
        "/boom/{*rest}",
        get(|| async { StatusCode::INTERNAL_SERVER_ERROR }),
    );
    with_layers(r, LIMITS)
}

#[tokio::test]
async fn a_5xx_logs_one_bounded_line_without_header_values_or_path_tokens() {
    capture();
    let token = Token::generate().unwrap().expose();
    let marker = "r118-five-xx-marker";
    let path = format!("/boom/{marker}/{token}");
    let mut r = req("GET", &path, None);
    let h = r.headers_mut();
    h.append(
        header::AUTHORIZATION,
        format!("Bearer {token}").parse().unwrap(),
    );
    h.append("x-control", "r118-header-value".parse().unwrap());
    h.append(header::COOKIE, "r118-cookie-value".parse().unwrap());
    let resp = failing_app().oneshot(r).await.unwrap();
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let out = captured();
    let lines: Vec<&str> = out.lines().filter(|l| l.contains(marker)).collect();
    // Control: the request event still shows the (non-sensitive) headers.
    assert!(
        lines.iter().any(|l| l.contains("r118-header-value")),
        "{out}"
    );
    let failures: Vec<&&str> = lines
        .iter()
        .filter(|l| l.contains("response failed"))
        .collect();
    assert_eq!(failures.len(), 1, "{lines:?}");
    for line in &lines {
        assert!(!line.contains(&token[3..]), "token segment leaked: {line}");
        assert!(!line.contains("r118-cookie-value"), "{line}");
        assert!(line.len() < 1024, "unbounded line: {line}");
    }
    for line in lines.iter().filter(|l| !l.contains("started processing")) {
        assert!(!line.contains("r118-header-value"), "{line}");
        assert!(!line.contains("authorization"), "{line}");
    }
}

#[tokio::test]
async fn a_hostile_header_map_is_capped_in_the_trace() {
    capture();
    let marker = "r118-cap-marker";
    let mut r = req("GET", &format!("/boom/{marker}"), None);
    for i in 0..500 {
        r.headers_mut().append(
            axum::http::HeaderName::from_bytes(format!("x-flood-{i}").as_bytes()).unwrap(),
            "z".repeat(5000).parse().unwrap(),
        );
    }
    let resp = failing_app().oneshot(r).await.unwrap();
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let out = captured();
    for line in out.lines().filter(|l| l.contains(marker)) {
        assert!(line.len() < 8192, "{} bytes", line.len());
    }
    assert!(!out.contains("x-flood-499"));
}
