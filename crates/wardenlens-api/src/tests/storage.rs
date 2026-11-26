//! Storage route tests with synthetic snapshots (no real roots, no site values).

use std::sync::Arc;

use axum::Router;
use axum::http::StatusCode;
use tower::ServiceExt as _;
use wardenlens_core::storage::{
    ArchiveCondition, ArchiveUnavailableCause, MinFreePercent, StorageSnapshot, TickErrorKind,
    TierStatus, VolumeSpace, VolumeStatus,
};
use wardenlens_core::time::Timestamp;

use super::{FakeDirectory, FakeStatus, FakeStorage, FakeStore, body_string, get_req};
use crate::token::Token;
use crate::{LIMITS, build};

fn app_of(storage: FakeStorage) -> (Router, String) {
    let store = FakeStore::default();
    let token = Token::generate().unwrap();
    store.add(&token, false);
    let auth = format!("Bearer {}", token.expose());
    (
        build(
            Arc::new(store),
            FakeDirectory::default(),
            FakeStatus::default(),
            storage,
            LIMITS,
        ),
        auth,
    )
}

async fn fetch(app: &Router, auth: Option<&str>) -> (StatusCode, String) {
    let resp = app
        .clone()
        .oneshot(get_req("/api/v1/storage", auth))
        .await
        .unwrap();
    (resp.status(), body_string(resp).await)
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

fn snapshot() -> StorageSnapshot {
    StorageSnapshot {
        hot: TierStatus {
            volume: Some(vol(1000, 200, 25)),
            segments: 7,
            oldest: Some(Timestamp::from_unix_millis(1_000)),
            newest: Some(Timestamp::from_unix_millis(9_000)),
        },
        archive: TierStatus::default(),
        archive_condition: ArchiveCondition::Unavailable(ArchiveUnavailableCause::NoMarker),
        unverified_total: 3,
        quarantined_total: 2,
        last_tick: Some(Timestamp::from_unix_millis(12_345)),
        last_error: Some(TickErrorKind::Index),
        floor_breaches_total: 4,
    }
}

#[tokio::test]
async fn storage_needs_a_token() {
    let (app, _) = app_of(FakeStorage::default());
    let (code, body) = fetch(&app, None).await;
    assert_eq!(code, StatusCode::UNAUTHORIZED);
    assert_eq!(body, r#"{"error":"unauthorized"}"#);
    let (code, _) = fetch(&app, Some("Bearer wrong")).await;
    assert_eq!(code, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn storage_reports_the_snapshot_field_by_field() {
    let (app, auth) = app_of(FakeStorage {
        snapshot: snapshot(),
        fail: false,
    });
    let (code, body) = fetch(&app, Some(&auth)).await;
    assert_eq!(code, StatusCode::OK);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    let hot = &v["hot"];
    assert_eq!(hot["total_bytes"], 1000);
    assert_eq!(hot["free_bytes"], 200);
    assert_eq!(hot["free_percent"], 20);
    assert_eq!(hot["min_free_percent"], 25);
    assert_eq!(hot["below_floor"], true);
    assert_eq!(hot["segments"], 7);
    assert_eq!(hot["oldest_segment"], 1_000);
    assert_eq!(hot["newest_segment"], 9_000);
    let arch = &v["archive"];
    assert_eq!(arch["state"], "unavailable");
    assert_eq!(arch["unavailable_cause"], "no_marker");
    assert!(arch["total_bytes"].is_null(), "an absent volume is null");
    assert!(arch["below_floor"].is_null());
    assert_eq!(arch["segments"], 0);
    assert!(arch["oldest_segment"].is_null());
    assert_eq!(v["unverified_total"], 3);
    assert_eq!(v["quarantined_total"], 2);
    assert_eq!(v["last_tick"], 12_345);
    assert_eq!(v["last_error"], "index");
    assert_eq!(v["floor_breaches_total"], 4);
}

#[tokio::test]
async fn archive_states_and_every_cause_have_a_name() {
    use ArchiveUnavailableCause as C;
    let cases = [
        (ArchiveCondition::Available, "available", None),
        (ArchiveCondition::Full, "full", None),
        (
            ArchiveCondition::Unavailable(C::Missing),
            "unavailable",
            Some("missing"),
        ),
        (
            ArchiveCondition::Unavailable(C::SameFilesystem),
            "unavailable",
            Some("same_filesystem"),
        ),
        (
            ArchiveCondition::Unavailable(C::ReadOnly),
            "unavailable",
            Some("read_only"),
        ),
        (
            ArchiveCondition::Unavailable(C::NoMarker),
            "unavailable",
            Some("no_marker"),
        ),
        (
            ArchiveCondition::Unavailable(C::MoveFailures),
            "unavailable",
            Some("move_failures"),
        ),
        (
            ArchiveCondition::Unavailable(C::Unusable),
            "unavailable",
            Some("unusable"),
        ),
        (
            ArchiveCondition::Unavailable(C::ProbeFailed),
            "unavailable",
            Some("probe_failed"),
        ),
        (
            ArchiveCondition::Unavailable(C::Other),
            "unavailable",
            Some("other"),
        ),
    ];
    for (cond, state, cause) in cases {
        let mut s = snapshot();
        s.archive_condition = cond;
        let (app, auth) = app_of(FakeStorage {
            snapshot: s,
            fail: false,
        });
        let (_, body) = fetch(&app, Some(&auth)).await;
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["archive"]["state"], state, "{cond:?}");
        match cause {
            Some(c) => assert_eq!(v["archive"]["unavailable_cause"], c, "{cond:?}"),
            None => assert!(v["archive"]["unavailable_cause"].is_null(), "{cond:?}"),
        }
    }
}

#[tokio::test]
async fn every_error_kind_has_a_name_and_none_is_null() {
    for (k, want) in [
        (TickErrorKind::HotVolume, "hot_volume"),
        (TickErrorKind::Index, "index"),
        (TickErrorKind::Plan, "plan"),
        (TickErrorKind::Other, "other"),
    ] {
        let mut s = snapshot();
        s.last_error = Some(k);
        let (app, auth) = app_of(FakeStorage {
            snapshot: s,
            fail: false,
        });
        let (_, body) = fetch(&app, Some(&auth)).await;
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["last_error"], want);
    }
    let mut s = snapshot();
    s.last_error = None;
    s.last_tick = None;
    let (app, auth) = app_of(FakeStorage {
        snapshot: s,
        fail: false,
    });
    let (_, body) = fetch(&app, Some(&auth)).await;
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert!(v["last_error"].is_null() && v["last_tick"].is_null());
}

#[tokio::test]
async fn a_snapshot_error_is_a_bare_500() {
    let (app, auth) = app_of(FakeStorage {
        snapshot: snapshot(),
        fail: true,
    });
    let (code, body) = fetch(&app, Some(&auth)).await;
    assert_eq!(code, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(body, r#"{"error":"internal_error"}"#);
}

#[tokio::test]
async fn storage_is_read_only() {
    let (app, auth) = app_of(FakeStorage::default());
    for method in ["POST", "PUT", "DELETE", "PATCH"] {
        let req = axum::http::Request::builder()
            .method(method)
            .uri("/api/v1/storage")
            .header(axum::http::header::AUTHORIZATION, &auth)
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED, "{method}");
    }
}

#[tokio::test]
async fn the_route_is_in_openapi_with_a_schema_and_no_path_field() {
    let (app, auth) = app_of(FakeStorage::default());
    let resp = app
        .clone()
        .oneshot(get_req("/api/v1/openapi.json", Some(&auth)))
        .await
        .unwrap();
    let doc: serde_json::Value = serde_json::from_str(&body_string(resp).await).unwrap();
    let op = &doc["paths"]["/api/v1/storage"]["get"];
    assert!(op.is_object(), "{doc}");
    for code in ["200", "401", "500"] {
        assert!(op["responses"][code].is_object(), "{code}");
    }
    let schemas = &doc["components"]["schemas"];
    let text = [
        op,
        &schemas["StorageDto"],
        &schemas["TierDto"],
        &schemas["ArchiveDto"],
        &schemas["ArchiveStateDto"],
        &schemas["UnavailableCauseDto"],
        &schemas["TickErrorDto"],
    ]
    .iter()
    .map(ToString::to_string)
    .collect::<String>();
    assert!(text.contains("floor_breaches_total") && text.contains("no_marker"));
    for forbidden in ["mount", "device", "\"path\"", "root", "errno", "message"] {
        assert!(
            !text.contains(forbidden),
            "{forbidden} in the storage OpenAPI schema"
        );
    }
    assert!(doc["components"]["schemas"]["StorageDto"].is_object());
}

fn walk(v: &serde_json::Value, out: &mut Vec<String>) {
    match v {
        serde_json::Value::String(s) => out.push(s.clone()),
        serde_json::Value::Array(a) => a.iter().for_each(|x| walk(x, out)),
        serde_json::Value::Object(o) => o.values().for_each(|x| walk(x, out)),
        _ => {}
    }
}

#[tokio::test]
async fn the_response_has_exactly_the_documented_keys_and_no_free_text() {
    let (app, auth) = app_of(FakeStorage {
        snapshot: snapshot(),
        fail: false,
    });
    let (_, body) = fetch(&app, Some(&auth)).await;
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    let keys = |o: &serde_json::Value| {
        let mut k: Vec<String> = o.as_object().unwrap().keys().cloned().collect();
        k.sort();
        k
    };
    assert_eq!(
        keys(&v),
        [
            "archive",
            "floor_breaches_total",
            "hot",
            "last_error",
            "last_tick",
            "quarantined_total",
            "unverified_total"
        ]
    );
    let tier = [
        "below_floor",
        "free_bytes",
        "free_percent",
        "min_free_percent",
        "newest_segment",
        "oldest_segment",
        "segments",
        "total_bytes",
    ];
    assert_eq!(keys(&v["hot"]), tier);
    let mut archive: Vec<&str> = tier.to_vec();
    archive.extend(["state", "unavailable_cause"]);
    archive.sort_unstable();
    assert_eq!(keys(&v["archive"]), archive);
    // The only strings are closed-enum names.
    let mut strings = Vec::new();
    walk(&v, &mut strings);
    strings.sort();
    assert_eq!(strings, ["index", "no_marker", "unavailable"]);
}
