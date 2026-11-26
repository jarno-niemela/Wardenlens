//! Adversary tests (#61 round 3) for the camera routes, through the public `router` only.
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

/// Independent scanner of the round-3 ruling (query value to the next `&`; path segment
/// rest after its first `=`).
fn oracle(text: &str) -> String {
    let (mut out, mut in_query, mut skipping) = (String::new(), false, false);
    for c in text.chars() {
        if !in_query && c == '?' {
            in_query = true;
            skipping = false;
            out.push(c);
        } else if (in_query && c == '&') || (!in_query && c == '/') {
            skipping = false;
            out.push(c);
        } else if skipping {
        } else if c == '=' {
            skipping = true;
            out.push_str("=***");
        } else {
            out.push(c);
        }
    }
    out
}

/// Every served path, on both routes and both streams, is exactly the ruling's redaction and
/// never the raw text when the path holds an `=`.
#[tokio::test]
async fn served_paths_equal_the_ruling_on_every_route_and_stream() {
    let forms = [
        "/a=QQQ?b=WWW/EEE?RRR;TTT&c",
        "/a&b=QQQ;c=WWW/d?e",
        "/a?=QQQ&=WWW",
        "/a?b?c=QQQ?WWW",
        "/a=?b=QQQ,WWW:EEE",
        "/x/y;z=QQQ/w",
        "/a?b,c=QQQ&d;e=WWW",
        "/plain/path",
    ];
    let cams: Vec<Camera> = forms
        .iter()
        .enumerate()
        .map(|(i, f)| {
            cam_with_sub(
                &format!("cam-{i}"),
                RtspPath::new(f).unwrap(),
                RtspPath::new(f).unwrap(),
            )
        })
        .collect();
    let (app, auth) = app(Dir(cams), St::default());
    let (code, body) = send(&app, Method::GET, "/api/v1/cameras", Some(&auth)).await;
    assert_eq!(code, StatusCode::OK);
    for bad in ["QQQ", "WWW", "EEE", "RRR", "TTT"] {
        assert!(!body.contains(bad), "{bad} served: {body}");
    }
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    for (i, f) in forms.iter().enumerate() {
        let want = oracle(f);
        let c = &v["cameras"][i];
        assert_eq!(c["streams"]["main"], want.as_str(), "{f}");
        assert_eq!(c["streams"]["sub"], want.as_str(), "{f}");
        let (_, one) = send(
            &app,
            Method::GET,
            &format!("/api/v1/cameras/cam-{i}"),
            Some(&auth),
        )
        .await;
        let o: serde_json::Value = serde_json::from_str(&one).unwrap();
        assert_eq!(o["streams"]["main"], want.as_str(), "{f}");
        assert_eq!(o["streams"]["sub"], want.as_str(), "{f}");
        if f.contains('=') {
            assert!(!one.contains(f), "raw path served: {one}");
        }
    }
}

/// `same_coarse` is an equivalence over the coarse state: reflexive, symmetric, and every
/// failure-kind pair inside `Degraded` compares equal.
#[test]
fn same_coarse_is_an_equivalence_over_every_kind() {
    let kinds = [
        FailureKind::Timeout,
        FailureKind::Refused,
        FailureKind::Auth,
        FailureKind::Protocol,
    ];
    let mut all = vec![
        LinkState::Streaming,
        LinkState::Connecting,
        LinkState::Backoff,
    ];
    all.extend(kinds.iter().map(|k| LinkState::Degraded(*k)));
    for a in &all {
        for b in &all {
            let both_degraded =
                matches!(a, LinkState::Degraded(_)) && matches!(b, LinkState::Degraded(_));
            assert_eq!(a.same_coarse(b), a == b || both_degraded, "{a:?} {b:?}");
            assert_eq!(a.same_coarse(b), b.same_coarse(a));
        }
    }
}
