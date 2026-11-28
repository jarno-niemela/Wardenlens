//! Adversarial tests for #118 (PR #236): the bounded, redacted request trace.

use axum::Router;
use axum::body::Body;
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, Request, StatusCode, header};
use axum::routing::get;
use tower::ServiceExt as _;

use super::{app, capture, captured};
use crate::token::Token;
use crate::trace::{HeaderSummary, redact_path};
use crate::{LIMITS, with_layers};

fn ok_app() -> Router {
    let r = Router::new().route("/ok/{*rest}", get(|| async { "ok" }));
    with_layers(r, LIMITS)
}

// ---- redact_path: encodings and boundaries (expected to pass) ----

#[test]
fn every_percent_encoding_of_the_prefix_is_redacted() {
    let secret = "SECRETSECRETSECRET";
    for prefix in [
        "wl_",
        "Wl_",
        "wL_",
        "WL_",
        "%77l_",
        "w%6c_",
        "w%6C_",
        "wl%5f",
        "wl%5F",
        "%77%6c%5f",
        "%57%4C%5F",
    ] {
        let path = format!("/api/v1/{prefix}abcdefgh_{secret}");
        let out = redact_path(&path);
        assert!(!out.contains(secret), "{path} -> {out}");
    }
}

#[test]
fn token_straddling_the_length_cap_is_not_partly_written() {
    let secret = "SECRETSECRETSECRET";
    for pad in 230..270 {
        let path = format!("/{}/wl_abcdefgh_{secret}", "a".repeat(pad));
        let out = redact_path(&path);
        assert!(out.len() <= 256, "{pad}: {}", out.len());
        for k in 4..secret.len() {
            assert!(!out.contains(&secret[..k]), "{pad}: {out}");
        }
        assert!(!out.contains("abcdefgh"), "{pad}: {out}");
    }
}

#[test]
fn a_token_after_a_huge_segment_or_inside_one_is_redacted() {
    let secret = "SECRETSECRETSECRET";
    let inside = format!("/{}wl_abcdefgh_{secret}", "x".repeat(300));
    assert!(!redact_path(&inside).contains("SECRET"));
    let matrix = format!("/a;k=wl_abcdefgh_{secret};z");
    assert!(!redact_path(&matrix).contains("SECRET"));
    let query_like = format!("/a%3Ftoken%3Dwl_abcdefgh_{secret}");
    assert!(!redact_path(&query_like).contains("SECRET"));
}

#[test]
fn redact_path_degenerate_inputs() {
    assert_eq!(redact_path(""), "");
    assert_eq!(redact_path("/"), "/");
    assert_eq!(redact_path("//"), "//");
    assert_eq!(redact_path("%"), "%");
    assert_eq!(redact_path("/%zz/%4"), "/%zz/%4");
    assert_eq!(redact_path("/wl"), "/wl");
    assert_eq!(redact_path("/w%"), "/w%");
    // Non-ASCII near the cap must not panic and must stay on a char boundary.
    for pad in 250..260 {
        let p = format!("/{}{}", "a".repeat(pad), "é".repeat(10));
        let out = redact_path(&p);
        assert!(out.len() <= 256);
    }
}

// ---- HeaderSummary bounds ----

/// Length of the `Debug` output of a single-entry summary, minus the braces.
fn one_entry_len(name: &str, value: &HeaderValue) -> usize {
    let mut h = HeaderMap::new();
    h.insert(
        HeaderName::from_bytes(name.as_bytes()).unwrap(),
        value.clone(),
    );
    format!("{:?}", HeaderSummary(&h)).len()
}

#[test]
fn header_value_of_invalid_utf8_stays_within_the_value_cap() {
    // 128 bytes of obs-text: each byte becomes U+FFFD (3 bytes) after the lossy decode.
    let value = HeaderValue::from_bytes(&[0x80; 128]).unwrap();
    let len = one_entry_len("x-a", &value);
    // name (3) + quotes + ": " + value (<= 128 + "...") + braces: well under 160.
    assert!(len <= 160, "one 128-byte value rendered as {len} bytes");
}

#[test]
fn header_value_of_quotes_stays_within_the_value_cap() {
    let value = HeaderValue::from_bytes(&[b'"'; 128]).unwrap();
    let len = one_entry_len("x-a", &value);
    assert!(len <= 160, "one 128-byte value rendered as {len} bytes");
}

#[test]
fn sensitive_header_past_the_entry_cap_is_not_shown() {
    let mut h = HeaderMap::new();
    for i in 0..40 {
        h.append(
            HeaderName::from_bytes(format!("x-{i}").as_bytes()).unwrap(),
            HeaderValue::from_static("v"),
        );
    }
    let mut v = HeaderValue::from_static("Bearer wl_abcdefgh_SECRETSECRET");
    v.set_sensitive(true);
    h.append(header::AUTHORIZATION, v);
    let out = format!("{:?}", HeaderSummary(&h));
    assert!(!out.contains("SECRET"), "{out}");
}

// ---- Through the layers ----

#[tokio::test]
async fn a_token_in_a_non_standard_header_is_not_traced() {
    capture();
    let secret = Token::generate().unwrap().expose();
    let marker = "r118adv-xapikey-marker";
    let mut r = Request::builder()
        .uri(format!("/ok/{marker}"))
        .body(Body::empty())
        .unwrap();
    r.headers_mut().insert("x-api-key", secret.parse().unwrap());
    r.headers_mut()
        .insert("x-auth-token", format!("Bearer {secret}").parse().unwrap());
    assert_eq!(ok_app().oneshot(r).await.unwrap().status(), StatusCode::OK);
    let out = captured();
    let lines: Vec<&str> = out.lines().filter(|l| l.contains(marker)).collect();
    assert!(!lines.is_empty(), "control: no trace lines");
    for l in lines {
        assert!(!l.contains(&secret[3..]), "token in a header leaked: {l}");
    }
}

#[tokio::test]
async fn a_token_in_the_referer_query_string_is_not_traced() {
    capture();
    let secret = Token::generate().unwrap().expose();
    let marker = "r118adv-referer-marker";
    let mut r = Request::builder()
        .uri(format!("/ok/{marker}"))
        .body(Body::empty())
        .unwrap();
    r.headers_mut().insert(
        header::REFERER,
        format!("https://nvr.local/ui?access_token={secret}")
            .parse()
            .unwrap(),
    );
    assert_eq!(ok_app().oneshot(r).await.unwrap().status(), StatusCode::OK);
    let out = captured();
    let lines: Vec<&str> = out.lines().filter(|l| l.contains(marker)).collect();
    assert!(!lines.is_empty(), "control: no trace lines");
    for l in lines {
        assert!(
            !l.contains(&secret[3..]),
            "token in the Referer query leaked: {l}"
        );
    }
}

fn long_method(marker: &str) -> Method {
    let name = format!("{}{}", marker.to_ascii_uppercase(), "M".repeat(20_000));
    Method::from_bytes(name.as_bytes()).unwrap()
}

#[tokio::test]
async fn a_5xx_line_is_fixed_size_whatever_the_method() {
    capture();
    let marker = "R118ADV-METHOD-5XX";
    let r = Request::builder()
        .method(long_method(marker))
        // The marker is also in the path: the method is logged as `OTHER` now.
        .uri(format!("/boom/{marker}"))
        .body(Body::empty())
        .unwrap();
    // Any method on a GET-only route: 405 from the router, so use the fallback instead.
    let app = with_layers(
        Router::new().fallback(|| async { StatusCode::INTERNAL_SERVER_ERROR }),
        LIMITS,
    );
    assert_eq!(
        app.oneshot(r).await.unwrap().status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
    let out = captured();
    let failures: Vec<&str> = out
        .lines()
        .filter(|l| l.contains(marker) && l.contains("response failed"))
        .collect();
    assert_eq!(failures.len(), 1, "control: one failure line");
    assert!(
        failures[0].len() < 1024,
        "5xx line is {} bytes",
        failures[0].len()
    );
}

#[tokio::test]
async fn auth_failure_warning_is_bounded_whatever_the_method() {
    capture();
    let marker = "R118ADV-METHOD-AUTH";
    // A fresh app: its sampling counter is at 0, so this first failure is logged.
    let (app, _token) = app();
    let r = Request::builder()
        .method(long_method(marker))
        .uri(format!("/api/v1/cameras/{marker}"))
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        app.oneshot(r).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
    let out = captured();
    let warns: Vec<&str> = out
        .lines()
        .filter(|l| l.contains(marker) && l.contains("authentication failed"))
        .collect();
    assert_eq!(warns.len(), 1, "control: one sampled warning");
    assert!(
        warns[0].len() < 1024,
        "auth warning is {} bytes",
        warns[0].len()
    );
}
