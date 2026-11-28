//! Adversary tests (#61 round 2) for the camera routes, through the public `router` only.
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
fn cam_with_sub(id: &str, main: RtspPath, sub: RtspPath) -> Camera {
    Camera::new(
        CameraId::new(id).unwrap(),
        DisplayName::new("Synthetic Cam").unwrap(),
        ModelRef::new("acme", "model-1").unwrap(),
        Host::new("192.0.2.10").unwrap(),
        NonZeroU16::new(554).unwrap(),
        StreamSet::new(main, Some(sub)),
    )
}

const SECRET_A: &str = "synthsecreta";
const SECRET_B: &str = "synthsecretb";

/// ADR 0004 (#61): every `name=value` value in a served stream path is `***`. In a query a
/// value may contain `/`, `?` and `;` (RFC 3986 section 3.4; base64 tokens contain `/`), so
/// the part after such a character is still the value and must not be served.
#[tokio::test]
async fn served_stream_paths_hide_query_values_containing_slash_question_or_semicolon() {
    let forms = [
        format!("/live?sig2={SECRET_A}/{SECRET_B}"),
        format!("/live?sig2={SECRET_A}?{SECRET_B}"),
        format!("/live?sig2={SECRET_A};{SECRET_B}"),
        format!("/live?channel=1&sig2={SECRET_A}/{SECRET_B}=="),
    ];
    let mut leaked = Vec::new();
    for f in &forms {
        let main = RtspPath::new(f).unwrap();
        let sub = RtspPath::new(f).unwrap();
        let (app, auth) = app(Dir(vec![cam_with_sub("cam-a", main, sub)]), St::default());
        for route in ["/api/v1/cameras", "/api/v1/cameras/cam-a"] {
            let (code, body) = send(&app, Method::GET, route, Some(&auth)).await;
            assert_eq!(code, StatusCode::OK);
            assert!(!body.contains(SECRET_A), "{route} <- {f}: {body}");
            if body.contains(SECRET_B) {
                leaked.push(format!("{route} <- {f}: {body}"));
            }
        }
    }
    assert!(leaked.is_empty(), "value bytes served: {leaked:#?}");
}

/// The sub stream goes through the same redaction as the main one.
#[tokio::test]
async fn sub_stream_values_are_redacted_too() {
    let main = RtspPath::new("/main").unwrap();
    let sub = RtspPath::new(&format!("/sub?pin2={SECRET_A}&x=")).unwrap();
    let (app, auth) = app(Dir(vec![cam_with_sub("cam-a", main, sub)]), St::default());
    let (_, body) = send(&app, Method::GET, "/api/v1/cameras/cam-a", Some(&auth)).await;
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["streams"]["main"], "/main");
    assert_eq!(v["streams"]["sub"], "/sub?pin2=***&x=***");
}

/// Every failure kind maps to its own lowercase code, and degraded always carries one.
#[tokio::test]
async fn every_failure_kind_is_served_as_its_code() {
    for (kind, code) in [
        (FailureKind::Timeout, "timeout"),
        (FailureKind::Refused, "refused"),
        (FailureKind::Auth, "auth"),
        (FailureKind::Protocol, "protocol"),
    ] {
        let st = St(HashMap::from([(
            "cam-a".to_owned(),
            LinkStatus {
                state: LinkState::Degraded(kind),
                since: Timestamp::from_unix_millis(5),
                last_failure: None,
                attempts: 0,
            },
        )]));
        let (app, auth) = app(Dir(vec![cam("cam-a", RtspPath::new("/m").unwrap())]), st);
        let (_, body) = send(&app, Method::GET, "/api/v1/cameras", Some(&auth)).await;
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        let c = &v["cameras"][0]["connection"];
        assert_eq!(c["state"], "degraded", "{body}");
        assert_eq!(c["error_kind"], code, "{body}");
        assert_eq!(c["since"], 5, "{body}");
    }
}

/// The `OpenAPI` document carries no example or default holding a path value, and lists the
/// failure kinds as an enum.
#[tokio::test]
async fn openapi_lists_failure_kinds_and_has_no_examples() {
    let (app, auth) = app(Dir::default(), St::default());
    let (_, body) = send(&app, Method::GET, "/api/v1/openapi.json", Some(&auth)).await;
    let doc: serde_json::Value = serde_json::from_str(&body).unwrap();
    let kinds = &doc["components"]["schemas"]["FailureKindDto"]["enum"];
    let mut got: Vec<&str> = kinds
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|k| k.as_str())
        .collect();
    got.sort_unstable();
    assert_eq!(got, ["auth", "other", "protocol", "refused", "timeout"]);
    assert!(!body.contains("\"example\""), "{body}");
}
