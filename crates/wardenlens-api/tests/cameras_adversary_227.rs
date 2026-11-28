//! Adversary tests (#227) for `connection.last_failure` and `connection.attempts`, through the
//! public `router` only. Synthetic data: documentation address ranges and made-up names.
#![expect(clippy::unwrap_used, reason = "test code")]
#![expect(
    clippy::indexing_slicing,
    clippy::panic,
    reason = "test helpers outside #[test] fns; a panic fails the test"
)]

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
    Camera, CameraDirectory, CameraId, CameraStatus, DirectoryError, DisplayName, Host,
    LastFailure, LinkState, LinkStatus, ModelRef, RtspPath, StreamSet,
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

fn one(status: LinkStatus) -> (Router, String) {
    let st = St(HashMap::from([("cam-a".to_owned(), status)]));
    app(Dir(vec![cam("cam-a", RtspPath::new("/main").unwrap())]), st)
}

async fn connection(status: LinkStatus) -> (serde_json::Value, serde_json::Value) {
    let (app, auth) = one(status);
    let (code, body) = send(&app, Method::GET, "/api/v1/cameras/cam-a", Some(&auth)).await;
    assert_eq!(code, StatusCode::OK, "{body}");
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    let (code, body) = send(&app, Method::GET, "/api/v1/cameras", Some(&auth)).await;
    assert_eq!(code, StatusCode::OK, "{body}");
    let list: serde_json::Value = serde_json::from_str(&body).unwrap();
    let listed = list["cameras"]
        .as_array()
        .and_then(|a| a.first())
        .map_or_else(|| panic!("{list}"), |c| c["connection"].clone());
    (v["connection"].clone(), listed)
}

#[tokio::test]
async fn attempts_and_last_failure_extremes_round_trip_on_both_routes() {
    for (attempts, at) in [
        (0_u32, i64::MIN),
        (1, 0),
        (u32::MAX, i64::MAX),
        (u32::MAX - 1, -1),
    ] {
        let s = LinkStatus {
            state: LinkState::Streaming,
            since: Timestamp::from_unix_millis(3),
            last_failure: Some(LastFailure {
                kind: FailureKind::Timeout,
                at: Timestamp::from_unix_millis(at),
            }),
            attempts,
        };
        let (one, listed) = connection(s).await;
        assert_eq!(one, listed, "both routes serve the same connection");
        assert_eq!(one["attempts"].as_u64(), Some(u64::from(attempts)), "{one}");
        // A failure is kept after recovery: served while streaming.
        assert_eq!(one["state"], "streaming");
        assert_eq!(one["last_failure"]["kind"], "timeout");
        assert_eq!(
            one["last_failure"]["at"].as_i64(),
            Some(Timestamp::from_unix_millis(at).as_unix_millis()),
            "{one}"
        );
        assert!(one.get("error_kind").is_none(), "{one}");
    }
}

#[tokio::test]
async fn degraded_serves_both_error_kind_and_last_failure_without_other_keys() {
    let s = LinkStatus {
        state: LinkState::Degraded(FailureKind::Auth),
        since: Timestamp::from_unix_millis(5),
        last_failure: Some(LastFailure {
            kind: FailureKind::Refused,
            at: Timestamp::from_unix_millis(9),
        }),
        attempts: 40,
    };
    let (one, _) = connection(s).await;
    let mut keys: Vec<&str> = one
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        ["attempts", "error_kind", "last_failure", "since", "state"],
        "{one}"
    );
    assert_eq!(one["error_kind"], "auth");
    assert_eq!(one["last_failure"]["kind"], "refused");
    for secret in ["192.0.2.10", "/main", "Synthetic", "acme"] {
        assert!(!one.to_string().contains(secret), "{one}");
    }
}

fn refs(v: &serde_json::Value, out: &mut Vec<String>) {
    match v {
        serde_json::Value::Object(m) => {
            if let Some(serde_json::Value::String(r)) = m.get("$ref") {
                out.push(r.clone());
            }
            m.values().for_each(|x| refs(x, out));
        }
        serde_json::Value::Array(a) => a.iter().for_each(|x| refs(x, out)),
        _ => {}
    }
}

/// Every `$ref` in the document resolves, and the new fields are documented with their types:
/// `attempts` a required non-negative integer, `last_failure` optional with required `kind`/`at`.
#[tokio::test]
async fn openapi_documents_attempts_and_last_failure_and_every_ref_resolves() {
    let (app, auth) = one(LinkStatus {
        state: LinkState::Connecting,
        since: Timestamp::from_unix_millis(1),
        last_failure: None,
        attempts: 0,
    });
    let (code, body) = send(&app, Method::GET, "/api/v1/openapi.json", Some(&auth)).await;
    assert_eq!(code, StatusCode::OK);
    let doc: serde_json::Value = serde_json::from_str(&body).unwrap();
    let schemas = doc["components"]["schemas"].as_object().unwrap();
    let mut all = Vec::new();
    refs(&doc, &mut all);
    for r in &all {
        let name = r
            .strip_prefix("#/components/schemas/")
            .unwrap_or_else(|| panic!("{r}"));
        assert!(schemas.contains_key(name), "dangling {r}");
    }
    let conn = &schemas["ConnectionDto"];
    let required: Vec<&str> = conn["required"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|x| x.as_str())
        .collect();
    assert!(required.contains(&"attempts"), "{conn}");
    assert!(!required.contains(&"last_failure"), "{conn}");
    let attempts = &conn["properties"]["attempts"];
    assert_eq!(attempts["type"], "integer", "{attempts}");
    assert_eq!(attempts["minimum"], 0, "{attempts}");
    assert!(conn["properties"]["last_failure"].is_object(), "{conn}");
    let lf = &schemas["LastFailureDto"];
    let mut req: Vec<&str> = lf["required"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|x| x.as_str())
        .collect();
    req.sort_unstable();
    assert_eq!(req, ["at", "kind"], "{lf}");
    assert_eq!(lf["properties"].as_object().unwrap().len(), 2, "{lf}");
}
