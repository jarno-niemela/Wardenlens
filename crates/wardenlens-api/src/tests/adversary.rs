//! Adversarial tests for the API router (verification of #60).

use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use axum::response::IntoResponse;
use axum::routing::get;
use tower::ServiceExt as _;

use super::{UNAUTHORIZED_BODY, app, body_string, get_req};
use crate::{LIMITS, Limits, with_layers};

async fn sleepy() -> &'static str {
    tokio::time::sleep(Duration::from_secs(3600)).await;
    "late"
}

async fn quick() -> &'static str {
    "ok"
}

fn capped_router() -> Router {
    let r = Router::new()
        .route("/slow", get(sleepy))
        .route("/fast", get(quick))
        .route("/fast2", get(quick).post(quick));
    with_layers(
        r,
        Limits {
            max_in_flight: 1,
            timeout: Duration::from_secs(100_000),
            ..LIMITS
        },
    )
}

/// Holds one in-flight request on `/slow`, then reports whether a request to `path`
/// completes within one (virtual) second.
async fn second_request_completes(method: &str, path: &str) -> bool {
    let app = capped_router();
    let holder = app.clone();
    let held = tokio::spawn(async move { holder.oneshot(get_req("/slow", None)).await });
    for _ in 0..50 {
        tokio::task::yield_now().await;
    }
    let req = Request::builder()
        .method(method)
        .uri(path)
        .body(Body::empty())
        .unwrap();
    let done = tokio::time::timeout(Duration::from_secs(1), app.oneshot(req))
        .await
        .is_ok();
    held.abort();
    done
}

#[tokio::test(start_paused = true)]
async fn concurrency_cap_blocks_second_request_on_same_route() {
    // Control: with a cap of 1, a second request to the same route waits.
    assert!(!second_request_completes("GET", "/slow").await);
}

#[tokio::test(start_paused = true)]
async fn concurrency_cap_is_global_across_routes() {
    // ADR 0004: ConcurrencyLimit caps concurrent requests (to the router), not per route.
    assert!(
        !second_request_completes("GET", "/fast").await,
        "a different route bypassed the in-flight cap of 1"
    );
}

#[tokio::test(start_paused = true)]
async fn concurrency_cap_is_global_across_unknown_paths() {
    assert!(
        !second_request_completes("GET", "/does-not-exist").await,
        "the fallback bypassed the in-flight cap of 1"
    );
}

#[tokio::test(start_paused = true)]
async fn concurrency_cap_is_global_across_methods() {
    assert!(
        !second_request_completes("POST", "/fast2").await,
        "another method bypassed the in-flight cap of 1"
    );
}

#[tokio::test]
async fn protected_route_wrong_method_without_token_is_401() {
    let (app, _) = app();
    for m in ["POST", "PUT", "DELETE", "OPTIONS", "HEAD", "PATCH"] {
        let req = Request::builder()
            .method(m)
            .uri("/api/v1/openapi.json")
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "{m}");
        assert!(
            resp.headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .is_none(),
            "{m}: CORS header"
        );
    }
}

#[tokio::test]
async fn protected_route_wrong_method_with_token_is_json_405_with_allow() {
    let (app, token) = app();
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/openapi.json")
        .header(header::AUTHORIZATION, format!("Bearer {}", token.expose()))
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert!(resp.headers().get(header::ALLOW).is_some());
    assert_eq!(body_string(resp).await, r#"{"error":"method_not_allowed"}"#);
}

#[tokio::test]
async fn path_variants_of_health_need_token() {
    let (app, _) = app();
    for p in [
        "/api/v1/health/",
        "/api/v1//health",
        "/API/V1/HEALTH",
        "/api/v1/health%2f",
        "/api/v1/./health/../openapi.json",
        "/",
        "/api/v2/health",
    ] {
        let resp = app.clone().oneshot(get_req(p, None)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "{p}");
        assert_eq!(body_string(resp).await, UNAUTHORIZED_BODY, "{p}");
    }
}

#[tokio::test]
async fn health_with_query_and_head_is_open() {
    let (app, _) = app();
    let resp = app
        .clone()
        .oneshot(get_req("/api/v1/health?verbose=1", None))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let req = Request::builder()
        .method("HEAD")
        .uri("/api/v1/health")
        .body(Body::empty())
        .unwrap();
    assert_eq!(app.oneshot(req).await.unwrap().status(), StatusCode::OK);
}

#[tokio::test]
async fn bearer_with_multiple_spaces_is_accepted() {
    // RFC 7235: credentials = auth-scheme [ 1*SP ( token68 / ... ) ].
    let (app, token) = app();
    let auth = format!("Bearer  {}", token.expose());
    let resp = app
        .oneshot(get_req("/api/v1/openapi.json", Some(&auth)))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn auth_header_mutations_all_401() {
    let (app, token) = app();
    let t = token.expose();
    let mut chars: Vec<char> = t.chars().collect();
    let last = chars.len() - 1;
    chars[last] = if chars[last] == 'A' { 'B' } else { 'A' };
    let flipped: String = chars.into_iter().collect();
    let cases = vec![
        format!("Bearer\t{t}"),
        format!("Bearer {t} "),
        format!("Bearer {t}x"),
        format!("Bearer {}", &t[..t.len() - 1]),
        format!("Bearer {}", t.to_uppercase()),
        format!("Bearer {flipped}"),
        format!("Bearerx {t}"),
        format!("Bearer {t},Bearer {t}"),
    ];
    for a in &cases {
        let resp = app
            .clone()
            .oneshot(get_req("/api/v1/openapi.json", Some(a)))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "{a:?}");
    }
}

#[tokio::test]
async fn non_utf8_authorization_header_is_401_not_panic() {
    let (app, _) = app();
    let v = axum::http::HeaderValue::from_bytes(b"Bearer wl_\xff\xfe").unwrap();
    let req = Request::builder()
        .uri("/api/v1/openapi.json")
        .header(header::AUTHORIZATION, v)
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        app.oneshot(req).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn json_error_rewrite_keeps_multi_valued_headers() {
    let r = Router::new().route(
        "/err",
        get(|| async {
            // `[(k, v), (k, v)]` header parts use `insert` in axum and would collapse the
            // two values before the middleware sees them, so append them explicitly.
            let mut resp =
                (StatusCode::BAD_REQUEST, "internal detail: /etc/secret path").into_response();
            resp.headers_mut()
                .append("x-multi", axum::http::HeaderValue::from_static("a"));
            resp.headers_mut()
                .append("x-multi", axum::http::HeaderValue::from_static("b"));
            resp
        }),
    );
    let resp = with_layers(r, LIMITS)
        .oneshot(get_req("/err", None))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let vals: Vec<_> = resp.headers().get_all("x-multi").iter().collect();
    assert_eq!(vals.len(), 2, "multi-valued header collapsed: {vals:?}");
    assert_eq!(body_string(resp).await, r#"{"error":"bad_request"}"#);
}

#[tokio::test]
async fn non_json_5xx_from_handler_is_masked() {
    let r = Router::new().route(
        "/boom",
        get(|| async { (StatusCode::BAD_GATEWAY, "upstream 10.0.0.5 refused").into_response() }),
    );
    let resp = with_layers(r, LIMITS)
        .oneshot(get_req("/boom", None))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    assert_eq!(body_string(resp).await, r#"{"error":"internal_error"}"#);
}
