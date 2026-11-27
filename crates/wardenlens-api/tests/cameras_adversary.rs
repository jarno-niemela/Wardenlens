//! Adversary tests for the read-only camera routes, through the public `router` only.
//! Synthetic data: documentation address ranges and made-up names.
#![expect(clippy::unwrap_used, reason = "test code")]

use std::collections::HashMap;
use std::future::Future;
use std::num::NonZeroU16;
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use http_body_util::BodyExt as _;
use tower::ServiceExt as _;
mod common;

use wardenlens_api::router;
use wardenlens_api::token::Token;
use wardenlens_core::camera::{
    Camera, CameraDirectory, CameraId, CameraStatus, DirectoryError, DisplayName, Host, LinkState,
    LinkStatus, ModelRef, RtspPath, StreamSet,
};
use wardenlens_core::connection::FailureKind;
use wardenlens_core::storage::{StorageSnapshot, StorageStatus, StorageStatusError};
use wardenlens_core::time::Timestamp;
use wardenlens_core::token_store::{TokenId, TokenRecord, TokenStore, TokenStoreError};

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

#[derive(Default, Clone)]
struct Dir(Vec<Camera>);

impl CameraDirectory for Dir {
    fn list(&self) -> impl Future<Output = Result<Vec<Camera>, DirectoryError>> + Send {
        std::future::ready(Ok(self.0.clone()))
    }
    fn get(
        &self,
        id: &CameraId,
    ) -> impl Future<Output = Result<Option<Camera>, DirectoryError>> + Send {
        std::future::ready(Ok(self.0.iter().find(|c| c.id() == id).cloned()))
    }
}

/// The storage port is not under test here.
struct NoStorage;

impl StorageStatus for NoStorage {
    fn snapshot(&self) -> impl Future<Output = Result<StorageSnapshot, StorageStatusError>> + Send {
        std::future::ready(Ok(StorageSnapshot::initial()))
    }
}

#[derive(Default)]
struct St(HashMap<String, LinkStatus>);

impl CameraStatus for St {
    fn status(&self, id: &CameraId) -> impl Future<Output = Option<LinkStatus>> + Send {
        std::future::ready(self.0.get(id.as_str()).copied())
    }
}

fn cam(id: &str, main: RtspPath) -> Camera {
    Camera::new(
        CameraId::new(id).unwrap(),
        DisplayName::new("Synthetic Cam").unwrap(),
        ModelRef::new("acme", "model-1").unwrap(),
        Host::new("192.0.2.10").unwrap(),
        NonZeroU16::new(554).unwrap(),
        StreamSet::new(main, None),
    )
}

fn app(dir: Dir, st: St) -> (Router, String) {
    let store = Store::default();
    let token = Token::generate().unwrap();
    store.0.lock().unwrap().insert(
        token.id().to_string(),
        TokenRecord {
            digest: token.secret().digest(),
            revoked: false,
        },
    );
    (
        router(
            Arc::new(store),
            dir,
            st,
            NoStorage,
            common::NoLister,
            wardenlens_core::storage::MemorySegmentFiles::new(),
        ),
        format!("Bearer {}", token.expose()),
    )
}

async fn send(
    app: &Router,
    method: Method,
    path: &str,
    auth: Option<&str>,
) -> (StatusCode, String) {
    let mut b = Request::builder().method(method).uri(path);
    if let Some(a) = auth {
        b = b.header(header::AUTHORIZATION, a);
    }
    let resp = app
        .clone()
        .oneshot(b.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let code = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (code, String::from_utf8(bytes.to_vec()).unwrap())
}

const SECRET: &str = "synthsecret77";

/// The ticket: "Never expose credentials". `RtspPath`'s own docs say its credential-name
/// denylist "can never be complete". The API therefore serves only
/// `RtspPath::redacted_for_display`, never `as_str`, so a spelling the list misses is still
/// hidden. Each row is a credential carried in a path `RtspPath` accepts.
#[tokio::test]
async fn stream_paths_never_carry_a_credential_value_to_clients() {
    let forms = [
        format!("/live?uid=synthadmin&pin={SECRET}"),
        format!("/live?passkey={SECRET}"),
        format!("/live?pwd2={SECRET}"),
        format!("/live?password1={SECRET}"),
        format!("/live?userpwd={SECRET}"),
        format!("/live?loginpwd={SECRET}"),
        format!("/live?mdp={SECRET}"),
        format!("/live?contrasena={SECRET}"),
        format!("/live?pass.word={SECRET}"),
        format!("/live?sessionkey={SECRET}"),
    ];
    let mut accepted = Vec::new();
    for f in &forms {
        if let Ok(p) = RtspPath::new(f) {
            accepted.push((f.clone(), p));
        }
    }
    assert!(
        !accepted.is_empty(),
        "self-check: at least one credential-bearing form must pass RtspPath"
    );
    let mut leaked = Vec::new();
    for (form, path) in accepted {
        let (app, auth) = app(Dir(vec![cam("cam-a", path)]), St::default());
        for route in ["/api/v1/cameras", "/api/v1/cameras/cam-a"] {
            let (code, body) = send(&app, Method::GET, route, Some(&auth)).await;
            assert_eq!(code, StatusCode::OK);
            if body.contains(SECRET) {
                leaked.push(format!("{route} <- {form}"));
            }
        }
    }
    assert!(leaked.is_empty(), "credential values served: {leaked:#?}");
}

/// `error_kind` is documented as "the most recent failure while degraded". Round 2: the port
/// type now carries the kind inside `LinkState::Degraded`, so the contradiction (a kind next to
/// another state) cannot be built; the test keeps the non-degraded expectation and adds the
/// degraded one.
#[tokio::test]
async fn error_kind_appears_only_while_degraded() {
    for state in [
        LinkState::Streaming,
        LinkState::Connecting,
        LinkState::Backoff,
    ] {
        let st = St(HashMap::from([(
            "cam-a".to_owned(),
            LinkStatus {
                state,
                since: Timestamp::from_unix_millis(1),
            },
        )]));
        let (app, auth) = app(Dir(vec![cam("cam-a", RtspPath::new("/main").unwrap())]), st);
        let (_, body) = send(&app, Method::GET, "/api/v1/cameras/cam-a", Some(&auth)).await;
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert!(
            v["connection"].get("error_kind").is_none(),
            "{state:?}: {body}"
        );
    }
    let st = St(HashMap::from([(
        "cam-a".to_owned(),
        LinkStatus {
            state: LinkState::Degraded(FailureKind::Auth),
            since: Timestamp::from_unix_millis(1),
        },
    )]));
    let (app, auth) = app(Dir(vec![cam("cam-a", RtspPath::new("/main").unwrap())]), st);
    let (_, body) = send(&app, Method::GET, "/api/v1/cameras/cam-a", Some(&auth)).await;
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["connection"]["error_kind"], "auth", "{body}");
}

#[tokio::test]
async fn mutating_methods_are_refused_and_auth_comes_first() {
    let (app, auth) = app(
        Dir(vec![cam("cam-a", RtspPath::new("/main").unwrap())]),
        St::default(),
    );
    for path in [
        "/api/v1/cameras",
        "/api/v1/cameras/cam-a",
        "/api/v1/cameras/BAD",
    ] {
        for m in [Method::POST, Method::PUT, Method::PATCH, Method::DELETE] {
            let (code, body) = send(&app, m.clone(), path, None).await;
            assert_eq!(code, StatusCode::UNAUTHORIZED, "{m} {path}");
            assert_eq!(body, r#"{"error":"unauthorized"}"#);
            let (code, body) = send(&app, m.clone(), path, Some(&auth)).await;
            assert_eq!(code, StatusCode::METHOD_NOT_ALLOWED, "{m} {path}");
            assert_eq!(body, r#"{"error":"method_not_allowed"}"#);
        }
        let (code, _) = send(&app, Method::HEAD, path, None).await;
        assert_eq!(code, StatusCode::UNAUTHORIZED, "HEAD {path}");
    }
}

#[tokio::test]
async fn odd_paths_give_json_errors_without_echo() {
    let (app, auth) = app(
        Dir(vec![cam("cam-a", RtspPath::new("/main").unwrap())]),
        St::default(),
    );
    let long = "a".repeat(10_000);
    let rows: [(&str, StatusCode); 9] = [
        ("/api/v1/cameras/%FF", StatusCode::BAD_REQUEST),
        ("/api/v1/cameras/%C3", StatusCode::BAD_REQUEST),
        ("/api/v1/cameras/%E2%80%AE", StatusCode::BAD_REQUEST),
        ("/api/v1/cameras/cam%2Da%00", StatusCode::BAD_REQUEST),
        ("/api/v1/cameras/", StatusCode::NOT_FOUND),
        ("/api/v1/cameras/cam-a/", StatusCode::NOT_FOUND),
        ("/api/v1/cameras/cam-a/x", StatusCode::NOT_FOUND),
        ("/api/v1/cameras//cam-a", StatusCode::NOT_FOUND),
        ("/api/v1/Cameras", StatusCode::NOT_FOUND),
    ];
    for (path, want) in rows {
        let (code, body) = send(&app, Method::GET, path, Some(&auth)).await;
        assert_eq!(code, want, "{path}");
        assert!(body.starts_with(r#"{"error":""#), "{path}: {body}");
        let (code, _) = send(&app, Method::GET, path, None).await;
        assert_eq!(code, StatusCode::UNAUTHORIZED, "{path}");
    }
    let (code, body) = send(
        &app,
        Method::GET,
        &format!("/api/v1/cameras/{long}"),
        Some(&auth),
    )
    .await;
    assert_eq!(code, StatusCode::BAD_REQUEST);
    assert_eq!(body, r#"{"error":"bad_request"}"#);
    // Percent-encoded spelling of a valid id resolves to the same camera.
    let (code, body) = send(&app, Method::GET, "/api/v1/cameras/%63am-a", Some(&auth)).await;
    assert_eq!(code, StatusCode::OK);
    assert!(body.contains(r#""id":"cam-a""#));
    // A query string never changes the routed id.
    let (code, _) = send(
        &app,
        Method::GET,
        "/api/v1/cameras/nosuch?id=cam-a",
        Some(&auth),
    )
    .await;
    assert_eq!(code, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn since_round_trips_extremes() {
    for ms in [i64::MIN, -1, 0, i64::MAX] {
        let st = St(HashMap::from([(
            "cam-a".to_owned(),
            LinkStatus {
                state: LinkState::Backoff,
                since: Timestamp::from_unix_millis(ms),
            },
        )]));
        let (app, auth) = app(Dir(vec![cam("cam-a", RtspPath::new("/main").unwrap())]), st);
        let (code, body) = send(&app, Method::GET, "/api/v1/cameras", Some(&auth)).await;
        assert_eq!(code, StatusCode::OK);
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["cameras"][0]["connection"]["since"].as_i64(), Some(ms));
    }
}

#[tokio::test]
async fn openapi_schema_marks_optional_fields_and_has_no_port_or_credential() {
    let (app, auth) = app(Dir::default(), St::default());
    let (_, body) = send(&app, Method::GET, "/api/v1/openapi.json", Some(&auth)).await;
    let doc: serde_json::Value = serde_json::from_str(&body).unwrap();
    let s = &doc["components"]["schemas"];
    let required = |name: &str| -> Vec<String> {
        s[name]["required"].as_array().map_or_else(Vec::new, |a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect()
        })
    };
    assert!(!required("ConnectionDto").contains(&"error_kind".to_owned()));
    assert!(!required("StreamsDto").contains(&"sub".to_owned()));
    let all = serde_json::to_string(s).unwrap().to_ascii_lowercase();
    for word in ["password", "\"user\"", "username", "credential\""] {
        assert!(!all.contains(word), "{word}");
    }
}
