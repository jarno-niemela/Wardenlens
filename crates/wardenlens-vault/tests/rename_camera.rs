//! `Vault::rename_camera` (#188): all `cam:<from>:*` entries move to `cam:<to>:*` in one
//! transaction, values intact. Synthetic values only.

#![expect(
    clippy::unwrap_used,
    reason = "integration-test helpers outside #[test] fns; clippy.toml in-tests allowances do not reach them"
)]

use std::os::unix::fs::PermissionsExt;

use secrecy::{ExposeSecret, SecretString};
use tempfile::TempDir;
use wardenlens_core::camera::CameraId;
use wardenlens_core::entry::{EntryId, EntryKind};
use wardenlens_secrets::{Credentials, KeyFile};
use wardenlens_vault::{Scan, Value, Vault, VaultError};

fn fresh() -> (TempDir, Vault) {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let key = KeyFile::generate(&tmp.path().join("k")).unwrap();
    let v = Vault::create(&tmp.path().join("v.db"), key).unwrap();
    (tmp, v)
}

fn cam(s: &str) -> CameraId {
    CameraId::new(s).unwrap()
}

fn id(s: &str) -> EntryId {
    EntryId::new(s).unwrap()
}

fn put(v: &mut Vault, entry: &str, kind: EntryKind, value: &str) {
    let value = if kind == EntryKind::Credential {
        Value::Credential(Credentials::new("svc-reader", value))
    } else {
        Value::Text(SecretString::from(value.to_owned()))
    };
    v.set(&id(entry), kind, &value, Scan::Normal).unwrap();
}

fn ids(v: &Vault) -> Vec<String> {
    v.list()
        .unwrap()
        .iter()
        .map(|e| e.id.as_str().to_owned())
        .collect()
}

fn text(v: &Vault, entry: &str) -> String {
    match v.get(&id(entry)).unwrap().unwrap().value {
        Value::Text(t) => t.expose_secret().to_owned(),
        _ => String::from("<not text>"),
    }
}

fn seed(v: &mut Vault, camera: &str) {
    put(
        v,
        &format!("cam:{camera}:host"),
        EntryKind::Host,
        "192.0.2.10",
    );
    put(
        v,
        &format!("cam:{camera}:credential"),
        EntryKind::Credential,
        "pw-synthetic-9",
    );
    put(
        v,
        &format!("cam:{camera}:name"),
        EntryKind::DisplayName,
        "Door Cam",
    );
    put(
        v,
        &format!("cam:{camera}:mac"),
        EntryKind::Mac,
        "02:00:00:00:00:01",
    );
}

#[test]
fn moves_every_entry_with_its_value_and_kind() {
    let (_t, mut v) = fresh();
    seed(&mut v, "import-json-1");
    put(&mut v, "cam:other:host", EntryKind::Host, "192.0.2.77");
    let moved = v
        .rename_camera(&cam("import-json-1"), &cam("reolink-1"))
        .unwrap();
    assert_eq!(moved.len(), 4);
    assert_eq!(
        ids(&v),
        [
            "cam:other:host",
            "cam:reolink-1:credential",
            "cam:reolink-1:host",
            "cam:reolink-1:mac",
            "cam:reolink-1:name"
        ]
    );
    assert_eq!(text(&v, "cam:reolink-1:host"), "192.0.2.10");
    assert_eq!(text(&v, "cam:reolink-1:mac"), "02:00:00:00:00:01");
    let Value::Credential(c) = v
        .get(&id("cam:reolink-1:credential"))
        .unwrap()
        .unwrap()
        .value
    else {
        panic!("shape")
    };
    assert_eq!(c.password.expose_secret(), "pw-synthetic-9");
    assert_eq!(text(&v, "cam:other:host"), "192.0.2.77");
}

#[test]
fn keeps_the_unscannable_flag() {
    let (_t, mut v) = fresh();
    put(&mut v, "cam:a:credential", EntryKind::Credential, "pw");
    assert!(v.list().unwrap()[0].unscannable);
    v.rename_camera(&cam("a"), &cam("b")).unwrap();
    assert!(v.list().unwrap()[0].unscannable);
}

#[test]
fn survives_a_reopen_and_authenticates_under_the_new_id() {
    let (t, mut v) = fresh();
    seed(&mut v, "a");
    v.rename_camera(&cam("a"), &cam("b")).unwrap();
    drop(v);
    let v = Vault::open(
        &t.path().join("v.db"),
        KeyFile::load(&t.path().join("k")).unwrap(),
    )
    .unwrap();
    assert_eq!(text(&v, "cam:b:name"), "Door Cam");
}

#[test]
fn a_missing_source_is_refused() {
    let (_t, mut v) = fresh();
    put(&mut v, "cam:other:host", EntryKind::Host, "192.0.2.77");
    let err = v.rename_camera(&cam("a"), &cam("b")).unwrap_err();
    assert!(matches!(err, VaultError::NothingToRename), "{err:?}");
}

#[test]
fn any_existing_target_entry_refuses_and_changes_nothing() {
    let (_t, mut v) = fresh();
    seed(&mut v, "a");
    put(&mut v, "cam:b:name", EntryKind::DisplayName, "Other Door");
    let before = ids(&v);
    let err = v.rename_camera(&cam("a"), &cam("b")).unwrap_err();
    assert!(
        matches!(&err, VaultError::RenameTargetExists { id } if id == "cam:b:name"),
        "{err:?}"
    );
    assert_eq!(ids(&v), before);
    assert_eq!(text(&v, "cam:b:name"), "Other Door");
    assert_eq!(text(&v, "cam:a:host"), "192.0.2.10");
}

#[test]
fn renaming_a_camera_onto_itself_is_refused() {
    let (_t, mut v) = fresh();
    seed(&mut v, "a");
    let err = v.rename_camera(&cam("a"), &cam("a")).unwrap_err();
    assert!(matches!(err, VaultError::RenameSame), "{err:?}");
    assert_eq!(ids(&v).len(), 4);
}

/// A longer target id can push a deep entry id over the id length cap: nothing moves.
#[test]
fn a_failure_part_way_rolls_back_every_entry() {
    let (_t, mut v) = fresh();
    seed(&mut v, "a");
    // `cam:a:` + 100 characters fits the 128-byte cap; the same suffix after the 32-char id does not.
    let long = format!("cam:a:{}", "x".repeat(100));
    put(&mut v, &long, EntryKind::Other, "synthetic-note");
    let before = ids(&v);
    let err = v
        .rename_camera(&cam("a"), &cam(&"b".repeat(32)))
        .unwrap_err();
    assert!(matches!(err, VaultError::InvalidId(_)), "{err:?}");
    assert_eq!(ids(&v), before);
    assert_eq!(text(&v, "cam:a:host"), "192.0.2.10");
}

/// An id that merely starts with the source id is not part of the camera.
#[test]
fn a_camera_whose_id_extends_the_source_is_untouched() {
    let (_t, mut v) = fresh();
    seed(&mut v, "a");
    put(&mut v, "cam:a-1:host", EntryKind::Host, "192.0.2.50");
    put(&mut v, "cam:a:b:extra", EntryKind::Other, "synthetic-note");
    v.rename_camera(&cam("a"), &cam("z")).unwrap();
    let got = ids(&v);
    assert!(got.contains(&"cam:a-1:host".to_owned()), "{got:?}");
    assert!(got.contains(&"cam:z:b:extra".to_owned()), "{got:?}");
    assert!(!got.iter().any(|i| i.starts_with("cam:a:")), "{got:?}");
}
