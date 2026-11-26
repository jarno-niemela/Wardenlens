//! Camera route tests with synthetic cameras (documentation address ranges only).

use std::collections::HashMap;
use std::num::NonZeroU16;
use std::sync::Arc;

use axum::Router;
use axum::http::StatusCode;
use tower::ServiceExt as _;
use wardenlens_core::camera::{
    Camera, CameraId, Credential, DisplayName, Host, LinkState, LinkStatus, ModelRef, RtspPath,
    StreamSet,
};
use wardenlens_core::connection::FailureKind;
use wardenlens_core::time::Timestamp;

use super::{FakeDirectory, FakeStatus, FakeStore, body_string, get_req};
use crate::token::Token;
use crate::{LIMITS, build};

const USER: &str = "synthuser-4417";
const PASSWORD: &str = "synthpass-9031";

fn camera(id: &str, host: &str, sub: Option<&str>) -> Camera {
    Camera::new(
        CameraId::new(id).unwrap(),
        DisplayName::new("Synthetic Cam").unwrap(),
        ModelRef::new("acme", "model-1").unwrap(),
        Host::new(host).unwrap(),
        NonZeroU16::new(554).unwrap(),
        StreamSet::new(
            RtspPath::new("/main").unwrap(),
            sub.map(|s| RtspPath::new(s).unwrap()),
        ),
    )
}

fn status(state: LinkState, since: i64, kind: Option<FailureKind>) -> LinkStatus {
    LinkStatus {
        state,
        since: Timestamp::from_unix_millis(since),
        error_kind: kind,
    }
}

fn app_of(dir: FakeDirectory, st: FakeStatus) -> (Router, String) {
    let store = FakeStore::default();
    let token = Token::generate().unwrap();
    store.add(&token, false);
    let auth = format!("Bearer {}", token.expose());
    (build(Arc::new(store), dir, st, LIMITS), auth)
}

async fn fetch(app: &Router, path: &str, auth: Option<&str>) -> (StatusCode, String) {
    let resp = app.clone().oneshot(get_req(path, auth)).await.unwrap();
    (resp.status(), body_string(resp).await)
}

fn two_cameras() -> (Router, String) {
    let dir = FakeDirectory {
        cameras: vec![
            camera("cam-a", "192.0.2.10", Some("/sub")),
            camera("cam-b", "2001:db8::1", None),
        ],
        fail: false,
        ..FakeDirectory::default()
    };
    let st = FakeStatus(HashMap::from([(
        "cam-a".to_owned(),
        status(LinkState::Streaming, 1_700_000_000_000, None),
    )]));
    app_of(dir, st)
}

#[tokio::test]
async fn list_returns_cameras_with_state() {
    let (app, auth) = two_cameras();
    let (code, body) = fetch(&app, "/api/v1/cameras", Some(&auth)).await;
    assert_eq!(code, StatusCode::OK);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    let a = &v["cameras"][0];
    assert_eq!(a["id"], "cam-a");
    assert_eq!(a["display_name"], "Synthetic Cam");
    assert_eq!(a["model"]["vendor"], "acme");
    assert_eq!(a["model"]["model"], "model-1");
    assert_eq!(a["host"], "192.0.2.10");
    assert_eq!(a["streams"]["main"], "/main");
    assert_eq!(a["streams"]["sub"], "/sub");
    assert_eq!(a["connection"]["state"], "streaming");
    assert_eq!(a["connection"]["since"], 1_700_000_000_000_i64);
    let b = &v["cameras"][1];
    assert_eq!(b["id"], "cam-b");
    assert!(b["streams"].get("sub").is_none());
    assert!(b["connection"].is_null());
}

#[tokio::test]
async fn empty_list_is_ok() {
    let (app, auth) = app_of(FakeDirectory::default(), FakeStatus::default());
    let (code, body) = fetch(&app, "/api/v1/cameras", Some(&auth)).await;
    assert_eq!(code, StatusCode::OK);
    assert_eq!(body, r#"{"cameras":[]}"#);
}

#[tokio::test]
async fn get_returns_one_camera() {
    let (app, auth) = two_cameras();
    let (code, body) = fetch(&app, "/api/v1/cameras/cam-a", Some(&auth)).await;
    assert_eq!(code, StatusCode::OK);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["id"], "cam-a");
    assert_eq!(v["connection"]["state"], "streaming");
}

#[tokio::test]
async fn every_state_maps_to_its_wire_name() {
    let cases = [
        (LinkState::Streaming, "streaming", None, None),
        (LinkState::Connecting, "connecting", None, None),
        (LinkState::Backoff, "backoff", None, None),
        (
            LinkState::Degraded,
            "degraded",
            Some(FailureKind::Auth),
            Some("auth"),
        ),
        (
            LinkState::Degraded,
            "degraded",
            Some(FailureKind::Timeout),
            Some("timeout"),
        ),
        (
            LinkState::Degraded,
            "degraded",
            Some(FailureKind::Refused),
            Some("refused"),
        ),
        (
            LinkState::Degraded,
            "degraded",
            Some(FailureKind::Protocol),
            Some("protocol"),
        ),
        (
            LinkState::Degraded,
            "degraded",
            Some(FailureKind::Other),
            Some("other"),
        ),
    ];
    for (state, name, kind, kind_name) in cases {
        let dir = FakeDirectory {
            cameras: vec![camera("cam-a", "192.0.2.10", None)],
            ..FakeDirectory::default()
        };
        let st = FakeStatus(HashMap::from([(
            "cam-a".to_owned(),
            status(state, 5, kind),
        )]));
        let (app, auth) = app_of(dir, st);
        let (_, body) = fetch(&app, "/api/v1/cameras/cam-a", Some(&auth)).await;
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["connection"]["state"], name);
        assert_eq!(v["connection"]["since"], 5);
        match kind_name {
            Some(k) => assert_eq!(v["connection"]["error_kind"], k),
            None => assert!(v["connection"].get("error_kind").is_none()),
        }
    }
}

#[tokio::test]
async fn invalid_id_is_400_and_unknown_is_404() {
    let (app, auth) = two_cameras();
    // Valid slugs that are unknown, and every kind of malformed id.
    let (code, body) = fetch(&app, "/api/v1/cameras/nosuch", Some(&auth)).await;
    assert_eq!(code, StatusCode::NOT_FOUND);
    assert_eq!(body, r#"{"error":"not_found"}"#);
    for bad in [
        "Cam-A",
        "1cam",
        "-a",
        "a_b",
        "%2e%2e",
        "..",
        "a%2Fb",
        "cam%00",
        "caf%C3%A9",
        "%20",
        &"a".repeat(33),
    ] {
        let (code, body) = fetch(&app, &format!("/api/v1/cameras/{bad}"), Some(&auth)).await;
        assert_eq!(code, StatusCode::BAD_REQUEST, "{bad}");
        assert_eq!(body, r#"{"error":"bad_request"}"#, "{bad}");
    }
}

#[tokio::test]
async fn directory_failure_is_a_bare_500() {
    let dir = FakeDirectory {
        cameras: Vec::new(),
        fail: true,
        ..FakeDirectory::default()
    };
    let (app, auth) = app_of(dir, FakeStatus::default());
    for path in ["/api/v1/cameras", "/api/v1/cameras/cam-a"] {
        let (code, body) = fetch(&app, path, Some(&auth)).await;
        assert_eq!(code, StatusCode::INTERNAL_SERVER_ERROR, "{path}");
        assert_eq!(body, r#"{"error":"internal_error"}"#, "{path}");
    }
}

#[tokio::test]
async fn camera_routes_require_a_token() {
    let (app, _) = two_cameras();
    for path in [
        "/api/v1/cameras",
        "/api/v1/cameras/cam-a",
        "/api/v1/cameras/nosuch",
        "/api/v1/cameras/BAD",
    ] {
        let (code, body) = fetch(&app, path, None).await;
        assert_eq!(code, StatusCode::UNAUTHORIZED, "{path}");
        assert_eq!(body, super::UNAUTHORIZED_BODY, "{path}");
    }
}

/// The credential of a camera is held next to it (as the vault would), yet no byte of it
/// may appear in any response.
#[tokio::test]
async fn responses_never_contain_credentials() {
    use secrecy::{ExposeSecret, SecretString};
    let cred = Credential::new(USER, SecretString::from(PASSWORD));
    let dir = FakeDirectory {
        cameras: vec![camera("cam-a", "192.0.2.10", Some("/sub"))],
        credentials: HashMap::from([("cam-a".to_owned(), cred)]),
        ..FakeDirectory::default()
    };
    // Self-check: the fake really holds the secrets the assertions below look for.
    let held = &dir.credentials["cam-a"];
    assert_eq!(held.user, USER);
    assert_eq!(held.password.expose_secret(), PASSWORD);
    let (app, auth) = app_of(dir, FakeStatus::default());
    for path in ["/api/v1/cameras", "/api/v1/cameras/cam-a"] {
        let (_, body) = fetch(&app, path, Some(&auth)).await;
        assert!(!body.contains(USER), "{path}");
        assert!(!body.contains(PASSWORD), "{path}");
        let lower = body.to_ascii_lowercase();
        for word in ["password", "credential", "secret", "user", "token"] {
            assert!(!lower.contains(word), "{path}: {word}");
        }
    }
}

#[tokio::test]
async fn openapi_documents_both_routes_with_schemas() {
    let (app, auth) = two_cameras();
    let (_, body) = fetch(&app, "/api/v1/openapi.json", Some(&auth)).await;
    let doc: serde_json::Value = serde_json::from_str(&body).unwrap();
    let list = &doc["paths"]["/api/v1/cameras"]["get"]["responses"]["200"];
    assert_eq!(
        list["content"]["application/json"]["schema"]["$ref"],
        "#/components/schemas/CameraList"
    );
    let one = &doc["paths"]["/api/v1/cameras/{id}"]["get"];
    assert_eq!(
        one["responses"]["200"]["content"]["application/json"]["schema"]["$ref"],
        "#/components/schemas/CameraDto"
    );
    assert!(one["responses"]["400"].is_object());
    assert!(one["responses"]["404"].is_object());
    let schemas = doc["components"]["schemas"].as_object().unwrap();
    for name in [
        "CameraDto",
        "CameraList",
        "ConnectionDto",
        "ConnectionStateDto",
    ] {
        assert!(schemas.contains_key(name), "{name}");
    }
    // No schema property may name a credential (descriptions may say "no credential").
    let mut names = Vec::new();
    for schema in schemas.values() {
        if let Some(props) = schema["properties"].as_object() {
            names.extend(props.keys().map(|k| k.to_ascii_lowercase()));
        }
    }
    assert!(names.contains(&"display_name".to_owned()));
    for name in &names {
        for word in ["password", "credential", "secret", "user", "token", "pass"] {
            assert!(!name.contains(word), "{name}");
        }
    }
}
