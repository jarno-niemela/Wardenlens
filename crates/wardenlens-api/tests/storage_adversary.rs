//! Adversary tests (#63 round 1) for `GET /api/v1/storage`, through the public `router` only.
//! Synthetic snapshots; no real roots.
#![expect(clippy::unwrap_used, reason = "test code")]

use std::collections::HashMap;
use std::future::Future;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use http_body_util::BodyExt as _;
use tower::ServiceExt as _;
use wardenlens_api::router;
use wardenlens_api::token::Token;
use wardenlens_core::camera::{
    Camera, CameraDirectory, CameraId, CameraStatus, DirectoryError, LinkStatus,
};
use wardenlens_core::storage::{
    ArchiveCondition, ArchiveUnavailableCause, MinFreePercent, StorageSnapshot, StorageStatus,
    StorageStatusError, TickErrorKind, TierStatus, VolumeSpace, VolumeStatus,
};
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

struct Dir;

impl CameraDirectory for Dir {
    fn list(&self) -> impl Future<Output = Result<Vec<Camera>, DirectoryError>> + Send {
        std::future::ready(Ok(Vec::new()))
    }
    fn get(
        &self,
        _id: &CameraId,
    ) -> impl Future<Output = Result<Option<Camera>, DirectoryError>> + Send {
        std::future::ready(Ok(None))
    }
}

struct St;

impl CameraStatus for St {
    fn status(&self, _id: &CameraId) -> impl Future<Output = Option<LinkStatus>> + Send {
        std::future::ready(None)
    }
}

/// Counts reads, so a test can prove the handler never ran.
#[derive(Clone)]
struct Counting {
    snap: StorageSnapshot,
    calls: Arc<AtomicUsize>,
}

impl StorageStatus for Counting {
    fn snapshot(&self) -> impl Future<Output = Result<StorageSnapshot, StorageStatusError>> + Send {
        self.calls.fetch_add(1, Ordering::SeqCst);
        std::future::ready(Ok(self.snap))
    }
}

fn app(snap: StorageSnapshot) -> (Router, String, String, Arc<AtomicUsize>) {
    let store = Store::default();
    let good = Token::generate().unwrap();
    let revoked = Token::generate().unwrap();
    for (t, r) in [(&good, false), (&revoked, true)] {
        store.0.lock().unwrap().insert(
            t.id().to_string(),
            TokenRecord {
                digest: t.secret().digest(),
                revoked: r,
            },
        );
    }
    let calls = Arc::new(AtomicUsize::new(0));
    let storage = Counting {
        snap,
        calls: Arc::clone(&calls),
    };
    (
        router(Arc::new(store), Dir, St, storage),
        format!("Bearer {}", good.expose()),
        format!("Bearer {}", revoked.expose()),
        calls,
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
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    (code, String::from_utf8(body.to_vec()).unwrap())
}

fn vol(cap: u64, free: u64, floor: u8) -> VolumeStatus {
    VolumeStatus::new(
        VolumeSpace {
            capacity_bytes: cap,
            free_bytes: free,
        },
        MinFreePercent::new(floor).unwrap(),
    )
}

/// Every method and spelling of the storage path, without a valid token, is refused before the
/// handler reads the port.
#[tokio::test]
async fn no_form_of_the_storage_route_reaches_the_port_without_a_valid_token() {
    let (app, _, revoked, calls) = app(StorageSnapshot::initial());
    let paths = [
        "/api/v1/storage",
        "/api/v1/storage/",
        "/api/v1/storage?x=1",
        "/api/v1//storage",
        "/api/v1/storage/../storage",
        "/API/V1/STORAGE",
        "/api/v1/storage%2F",
        "/api/v1/./storage",
    ];
    let methods = [
        Method::GET,
        Method::HEAD,
        Method::POST,
        Method::PUT,
        Method::DELETE,
        Method::OPTIONS,
    ];
    let auths: [Option<&str>; 5] = [
        None,
        Some(revoked.as_str()),
        Some("Bearer "),
        Some("Basic dXNlcjpwYXNz"),
        Some("bearer wl_garbage"),
    ];
    for p in paths {
        for m in &methods {
            for a in auths {
                let (code, _) = send(&app, m.clone(), p, a).await;
                assert_eq!(code, StatusCode::UNAUTHORIZED, "{m} {p} {a:?}");
            }
        }
    }
    assert_eq!(calls.load(Ordering::SeqCst), 0, "the port was read");
}

/// Extreme values serialise exactly (no float rounding, no wrap), and the cause is present
/// exactly when the state is `unavailable`.
#[tokio::test]
async fn extreme_values_are_exact_and_the_cause_follows_the_state() {
    // The snapshot types are `non_exhaustive`: build from `initial()` and set the fields.
    let pct = |p| MinFreePercent::new(p).unwrap();
    let mut extreme = StorageSnapshot::initial();
    extreme.hot = TierStatus::new(
        pct(90),
        Some(vol(u64::MAX, u64::MAX, 90)),
        u64::MAX,
        Some(Timestamp::from_unix_millis(i64::MIN)),
        Some(Timestamp::from_unix_millis(i64::MAX)),
    );
    extreme.archive = TierStatus::new(pct(0), Some(vol(u64::MAX, 0, 0)), 0, None, None);
    extreme.archive_condition = ArchiveCondition::Full;
    extreme.unverified_total = u64::MAX;
    extreme.quarantined_total = u64::MAX;
    extreme.last_tick = Some(Timestamp::from_unix_millis(-1));
    extreme.last_error = Some(TickErrorKind::Plan);
    extreme.floor_breaches_total = u64::MAX;
    let (router1, good, _, _) = app(extreme);
    let (code, body) = send(&router1, Method::GET, "/api/v1/storage", Some(&good)).await;
    assert_eq!(code, StatusCode::OK);
    let max = u64::MAX.to_string();
    for needle in [
        format!("\"total_bytes\":{max}"),
        format!("\"segments\":{max}"),
        format!("\"floor_breaches_total\":{max}"),
        format!("\"oldest_segment\":{}", i64::MIN),
        format!("\"newest_segment\":{}", i64::MAX),
        "\"last_tick\":-1".to_owned(),
        "\"free_percent\":100".to_owned(),
        "\"state\":\"full\"".to_owned(),
        "\"unavailable_cause\":null".to_owned(),
        "\"last_error\":\"plan\"".to_owned(),
    ] {
        assert!(body.contains(&needle), "{needle} not in {body}");
    }
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["archive"]["below_floor"], false, "a zero floor");
    assert_eq!(v["archive"]["free_percent"], 0);
    assert_eq!(v["hot"]["below_floor"], false);

    for (cond, state, cause) in [
        (ArchiveCondition::Available, "available", None),
        (ArchiveCondition::Full, "full", None),
        (
            ArchiveCondition::Unavailable(ArchiveUnavailableCause::MoveFailures),
            "unavailable",
            Some("move_failures"),
        ),
        (
            ArchiveCondition::Unavailable(ArchiveUnavailableCause::SameFilesystem),
            "unavailable",
            Some("same_filesystem"),
        ),
    ] {
        let mut s = StorageSnapshot::initial();
        s.archive_condition = cond;
        let (r2, good, _, _) = app(s);
        let (_, body) = send(&r2, Method::GET, "/api/v1/storage", Some(&good)).await;
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["archive"]["state"], state);
        assert_eq!(v["archive"]["unavailable_cause"].as_str(), cause, "{body}");
    }
}

/// The initial snapshot (before the first tick) is all nulls and zeros: nothing measured is
/// invented, and a never-ticked loop is not reported as a failure.
#[tokio::test]
async fn before_the_first_tick_every_measurement_is_null() {
    let (app, good, _, calls) = app(StorageSnapshot::initial());
    let (code, body) = send(&app, Method::GET, "/api/v1/storage", Some(&good)).await;
    assert_eq!(code, StatusCode::OK);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    for tier in ["hot", "archive"] {
        for k in [
            "total_bytes",
            "free_bytes",
            "free_percent",
            "min_free_percent",
            "below_floor",
            "oldest_segment",
            "newest_segment",
        ] {
            assert!(v[tier][k].is_null(), "{tier}.{k} in {body}");
        }
        assert_eq!(v[tier]["segments"], 0);
    }
    assert!(v["last_tick"].is_null() && v["last_error"].is_null());
    assert_eq!(v["floor_breaches_total"], 0);
}

/// The `OpenAPI` document describes the flattened archive object: its tier fields appear in the
/// archive schema (directly or through a composition), so a client generated from it can read
/// `archive.free_bytes`.
#[tokio::test]
async fn the_openapi_archive_schema_carries_the_tier_fields() {
    let (app, good, _, _) = app(StorageSnapshot::initial());
    let (code, body) = send(&app, Method::GET, "/api/v1/openapi.json", Some(&good)).await;
    assert_eq!(code, StatusCode::OK);
    let doc: serde_json::Value = serde_json::from_str(&body).unwrap();
    let archive = doc["components"]["schemas"]["ArchiveDto"].to_string();
    let resolved =
        archive.contains("free_bytes") || archive.contains("#/components/schemas/TierDto");
    assert!(resolved, "{archive}");
    let storage = doc["components"]["schemas"]["StorageDto"].to_string();
    for k in [
        "hot",
        "archive",
        "floor_breaches_total",
        "last_tick",
        "last_error",
    ] {
        assert!(storage.contains(k), "{k} not in {storage}");
    }
}
