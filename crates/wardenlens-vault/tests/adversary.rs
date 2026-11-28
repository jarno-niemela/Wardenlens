//! Adversarial tests for the vault library (synthetic values only).

#![expect(
    clippy::unwrap_used,
    reason = "integration-test helpers outside #[test] fns; clippy.toml in-tests allowances do not reach them"
)]

use std::collections::{BTreeMap, BTreeSet};
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::PathBuf;

use secrecy::{ExposeSecret, SecretString};
use tempfile::TempDir;
use wardenlens_core::entry::{EntryId, EntryKind};
use wardenlens_secrets::{Credentials, KeyFile};
use wardenlens_vault::legacy::{map_inventory_toml, map_secret_json};
use wardenlens_vault::{Scan, Value, Vault, VaultError};

fn dir() -> TempDir {
    let d = tempfile::tempdir().unwrap();
    std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    d
}

fn id(s: &str) -> EntryId {
    EntryId::new(s).unwrap()
}

fn text(s: &str) -> Value {
    Value::Text(SecretString::from(s.to_owned()))
}

fn fresh() -> (TempDir, PathBuf, Vault) {
    let d = dir();
    let key = KeyFile::generate(&d.path().join("k")).unwrap();
    let p = d.path().join("v.db");
    let v = Vault::create(&p, key).unwrap();
    (d, p, v)
}

fn ids_of(i: &wardenlens_vault::legacy::LegacyImport) -> Vec<String> {
    i.entries.iter().map(|e| e.id.to_string()).collect()
}

// ---- legacy mapping: id collisions ----------------------------------------------------------

/// Two different cameras in one inventory must never share an entry id: a section literally
/// named `import-1` and an earlier section whose name is not a valid id (ordinal fallback 1).
#[test]
fn toml_ordinal_fallback_never_collides_with_a_real_section_id() {
    let t: toml::Table = toml::from_str(
        "[cameras.\"Front Gate\"]\nhost = \"192.0.2.10\"\n\n[cameras.import-1]\nhost = \"192.0.2.11\"\n",
    )
    .unwrap();
    let i = map_inventory_toml(&t).unwrap();
    let ids = ids_of(&i);
    let unique: BTreeSet<&String> = ids.iter().collect();
    assert_eq!(unique.len(), ids.len(), "duplicate ids: {ids:?}");
}

/// Same within the JSON file: a camera mapped to inventory id `import-2` and an unmapped
/// second camera (ordinal fallback `import-2`).
#[test]
fn json_ordinal_fallback_never_collides_with_a_mapped_id() {
    let m = BTreeMap::from([("Front Gate".to_owned(), "import-2".to_owned())]);
    let v: serde_json::Value = serde_json::from_str(
        r#"[{"name":"Front Gate","login":"u1","password":"pw-one-1"},
            {"name":"Garage","login":"u2","password":"pw-two-2"}]"#,
    )
    .unwrap();
    let i = map_secret_json(&v, &m).unwrap();
    let ids = ids_of(&i);
    let unique: BTreeSet<&String> = ids.iter().collect();
    assert_eq!(unique.len(), ids.len(), "duplicate ids: {ids:?}");
}

/// The two legacy files are imported into the same vault. An unmapped JSON camera and an
/// inventory section with an unusable name are different cameras; they must not be merged
/// into the same `cam:import-1:*` entries (the JSON name would overwrite the TOML name and the
/// JSON credential would be paired with the TOML host).
#[test]
fn ordinal_ids_from_the_two_legacy_files_do_not_merge_different_cameras() {
    let j: serde_json::Value =
        serde_json::from_str(r#"[{"name":"Garage","login":"u","password":"pw-garage-1"}]"#)
            .unwrap();
    let t: toml::Table =
        toml::from_str("[cameras.\"Front Gate\"]\nhost = \"192.0.2.10\"\nname = \"Front Gate\"\n")
            .unwrap();
    let a = map_secret_json(&j, &BTreeMap::new()).unwrap();
    let b = map_inventory_toml(&t).unwrap();
    let a_ids: BTreeSet<String> = ids_of(&a).into_iter().collect();
    let b_ids: BTreeSet<String> = ids_of(&b).into_iter().collect();
    let shared: Vec<&String> = a_ids.intersection(&b_ids).collect();
    assert!(shared.is_empty(), "shared ids: {shared:?}");
}

/// `name` and `display_name` in one section map to the same id: one value silently overwrites
/// the other. The second must be reported or refused, not dropped.
#[test]
fn toml_name_and_display_name_together_do_not_yield_duplicate_ids() {
    let t: toml::Table = toml::from_str(
        "[cameras.cam-2]\nname = \"Back Door North\"\ndisplay_name = \"Back Door South\"\n",
    )
    .unwrap();
    let i = map_inventory_toml(&t).unwrap();
    let ids = ids_of(&i);
    let unique: BTreeSet<&String> = ids.iter().collect();
    assert_eq!(unique.len(), ids.len(), "duplicate ids: {ids:?}");
}

// ---- legacy mapping: nothing silently dropped ----------------------------------------------

/// A password without a login is neither imported nor reported: after the owner deletes the
/// legacy file (#76) it is gone. It must at least be listed by key name.
#[test]
fn json_password_without_login_is_reported_not_silently_dropped() {
    let v: serde_json::Value =
        serde_json::from_str(r#"[{"name":"Garage","password":"orphan-pw-1"}]"#).unwrap();
    let m = BTreeMap::from([("Garage".to_owned(), "cam-5".to_owned())]);
    let i = map_secret_json(&v, &m).unwrap();
    let imported_cred = i.entries.iter().any(|e| e.kind == EntryKind::Credential);
    let reported = i.unknown_keys.iter().any(|k| k.ends_with(".password"));
    assert!(
        imported_cred || reported,
        "password neither imported nor reported: {:?}",
        i.unknown_keys
    );
}

/// `login` wins over `username`; a differing `username` is silently dropped.
#[test]
fn json_username_shadowed_by_login_is_reported() {
    let v: serde_json::Value = serde_json::from_str(
        r#"[{"name":"Garage","login":"svc-reader","username":"svc-admin","password":"pw-x-1234"}]"#,
    )
    .unwrap();
    let m = BTreeMap::from([("Garage".to_owned(), "cam-5".to_owned())]);
    let i = map_secret_json(&v, &m).unwrap();
    assert!(
        i.unknown_keys.iter().any(|k| k.ends_with(".username")),
        "username dropped silently: {:?}",
        i.unknown_keys
    );
}

/// Top-level keys of the inventory outside `[cameras]` (for example a `[site]` table holding
/// an address) are neither imported nor listed.
#[test]
fn toml_top_level_unknown_keys_are_listed() {
    let t: toml::Table = toml::from_str(
        "[site]\naddress = \"12 Example Lane\"\n\n[cameras.cam-2]\nhost = \"192.0.2.10\"\n",
    )
    .unwrap();
    let i = map_inventory_toml(&t).unwrap();
    assert!(
        i.unknown_keys.iter().any(|k| k.contains("site")),
        "top-level key not reported: {:?}",
        i.unknown_keys
    );
    assert!(!format!("{:?}", i.unknown_keys).contains("Example Lane"));
}

/// A long but valid inventory id passes the `host`-length probe in `inventory_id` but makes
/// `cam:<id>:credential` exceed 128 bytes: the credential is silently dropped.
#[test]
fn json_long_inventory_id_does_not_silently_drop_the_credential() {
    let inv = "a".repeat(118); // cam:<118>:host = 127 bytes; cam:<118>:credential = 133
    let m = BTreeMap::from([("Garage".to_owned(), inv)]);
    let v: serde_json::Value =
        serde_json::from_str(r#"[{"name":"Garage","login":"u","password":"pw-long-1"}]"#).unwrap();
    let i = map_secret_json(&v, &m).unwrap();
    assert!(
        i.entries.iter().any(|e| e.kind == EntryKind::Credential),
        "credential dropped: {:?}",
        ids_of(&i)
    );
}

#[test]
fn toml_long_section_id_does_not_silently_drop_the_serial() {
    let sec = "a".repeat(118);
    let t: toml::Table =
        toml::from_str(&format!("[cameras.{sec}]\nserial = \"SN-0042-ZQ\"\n")).unwrap();
    let i = map_inventory_toml(&t).unwrap();
    assert!(
        i.entries.iter().any(|e| e.kind == EntryKind::Serial),
        "serial dropped: {:?}",
        ids_of(&i)
    );
}

/// Unknown key names are reported; a key carrying terminal escapes or newlines is passed
/// through verbatim to whoever prints the list.
#[test]
fn unknown_key_names_carry_no_control_characters() {
    let v: serde_json::Value =
        serde_json::from_str("[{\"name\":\"Garage\",\"x\\u001b[2J\\ny\":1}]").unwrap();
    let m = BTreeMap::from([("Garage".to_owned(), "cam-5".to_owned())]);
    let i = map_secret_json(&v, &m).unwrap();
    for k in &i.unknown_keys {
        assert!(!k.chars().any(char::is_control), "{k:?}");
    }
}

/// Values never appear in the Debug output of a mapping result.
#[test]
fn legacy_import_debug_redacts_values() {
    let v: serde_json::Value = serde_json::from_str(
        r#"[{"name":"Back Door North","login":"svc-reader","password":"Tr0ub4dor-x9"}]"#,
    )
    .unwrap();
    let i = map_secret_json(&v, &BTreeMap::new()).unwrap();
    let dbg = format!("{i:?}");
    for s in ["Back Door North", "svc-reader", "Tr0ub4dor-x9"] {
        assert!(!dbg.contains(s), "{s} in {dbg}");
    }
}

// ---- store ---------------------------------------------------------------------------------

#[test]
fn entry_debug_redacts_credential_fields() {
    let (_d, _p, mut v) = fresh();
    let c = Value::Credential(Credentials::new("svc-reader", "Tr0ub4dor-x9"));
    v.set(
        &id("cam:a:credential"),
        EntryKind::Credential,
        &c,
        Scan::Normal,
    )
    .unwrap();
    let e = v.get(&id("cam:a:credential")).unwrap().unwrap();
    let dbg = format!("{e:?} {v:?}");
    assert!(
        !dbg.contains("svc-reader") && !dbg.contains("Tr0ub4dor-x9"),
        "{dbg}"
    );
}

#[test]
fn refuses_a_vault_reached_through_a_symlinked_parent_into_a_work_tree() {
    let d = dir();
    let repo = d.path().join("repo");
    std::fs::create_dir(&repo).unwrap();
    std::fs::set_permissions(&repo, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::create_dir(repo.join(".git")).unwrap();
    let sub = repo.join("sub");
    std::fs::create_dir(&sub).unwrap();
    std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o700)).unwrap();
    let link = d.path().join("link");
    symlink(&sub, &link).unwrap();
    let key = KeyFile::generate(&d.path().join("k")).unwrap();
    let r = Vault::create(&link.join("v.db"), key);
    assert!(matches!(r, Err(VaultError::InWorkTree)), "{r:?}");
    assert!(!sub.join("v.db").exists(), "file created inside work tree");
}

#[test]
fn refuses_a_work_tree_marked_by_a_git_file() {
    let d = dir();
    std::fs::write(d.path().join(".git"), "gitdir: /nonexistent\n").unwrap();
    let key = KeyFile::generate(&d.path().join("k"));
    // KeyFile may itself refuse the work tree; either way the vault must not be created.
    if let Ok(key) = key {
        let r = Vault::create(&d.path().join("v.db"), key);
        assert!(matches!(r, Err(VaultError::InWorkTree)), "{r:?}");
    }
    assert!(!d.path().join("v.db").exists());
}

#[test]
fn credential_row_moved_into_a_host_row_is_corrupt() {
    let (_d, p, mut v) = fresh();
    let c = Value::Credential(Credentials::new("svc-reader", "Tr0ub4dor-x9"));
    v.set(&id("cam:a:x"), EntryKind::Credential, &c, Scan::Normal)
        .unwrap();
    v.set(
        &id("cam:b:x"),
        EntryKind::Host,
        &text("192.0.2.10"),
        Scan::Normal,
    )
    .unwrap();
    let raw = rusqlite::Connection::open(&p).unwrap();
    // Same id, change only the kind column: credential record labelled as secret.
    raw.execute("UPDATE entries SET kind = 2 WHERE id = 'cam:a:x'", [])
        .unwrap();
    let r = v.get(&id("cam:a:x"));
    assert!(matches!(r, Err(VaultError::CorruptEntry { .. })), "{r:?}");
    // Kind column that is out of range, negative or text.
    for bad in ["0", "-1", "256", "1.5", "'host'"] {
        raw.execute(
            &format!("UPDATE entries SET kind = {bad} WHERE id = 'cam:b:x'"),
            [],
        )
        .unwrap();
        let r = v.get(&id("cam:b:x"));
        assert!(r.is_err(), "kind {bad} accepted");
        let r = v.list();
        assert!(r.is_err(), "list accepted kind {bad}");
    }
}

#[test]
fn rekey_rolls_back_on_a_bad_row_and_keeps_old_key_and_records() {
    let (tmp, path, mut vault) = fresh();
    vault
        .set(
            &id("cam:a:host"),
            EntryKind::Host,
            &text("192.0.2.10"),
            Scan::Normal,
        )
        .unwrap();
    vault
        .set(
            &id("cam:z:host"),
            EntryKind::Host,
            &text("192.0.2.11"),
            Scan::Normal,
        )
        .unwrap();
    let raw = rusqlite::Connection::open(&path).unwrap();
    raw.execute(
        "UPDATE entries SET record = X'01' WHERE id = 'cam:z:host'",
        [],
    )
    .unwrap();
    let new = KeyFile::generate(&tmp.path().join("k2")).unwrap();
    assert!(vault.rekey(new).is_err());
    drop(vault);
    let old = KeyFile::load(&tmp.path().join("k")).unwrap();
    let vault = Vault::open(&path, old).unwrap();
    let Some(entry) = vault.get(&id("cam:a:host")).unwrap() else {
        panic!("missing")
    };
    let Value::Text(shown) = entry.value else {
        panic!()
    };
    assert_eq!(shown.expose_secret(), "192.0.2.10");
    let new = KeyFile::load(&tmp.path().join("k2")).unwrap();
    drop(vault);
    assert!(matches!(Vault::open(&path, new), Err(VaultError::WrongKey)));
}

#[test]
fn rekey_round_trips_credentials_and_unscannable() {
    let (tmp, path, mut vault) = fresh();
    let c = Value::Credential(Credentials::new("svc-reader", "pw"));
    assert!(
        vault
            .set(
                &id("cam:a:credential"),
                EntryKind::Credential,
                &c,
                Scan::Normal
            )
            .unwrap()
            .is_unscannable()
    );
    vault
        .rekey(KeyFile::generate(&tmp.path().join("k2")).unwrap())
        .unwrap();
    drop(vault);
    let vault = Vault::open(&path, KeyFile::load(&tmp.path().join("k2")).unwrap()).unwrap();
    let entry = vault.get(&id("cam:a:credential")).unwrap().unwrap();
    assert!(entry.unscannable);
    let Value::Credential(pair) = entry.value else {
        panic!()
    };
    assert_eq!(pair.username, "svc-reader");
    assert_eq!(pair.password.expose_secret(), "pw");
}

#[test]
fn a_second_handle_sees_the_first_handles_writes() {
    // A second handle sees the first one's writes (no stale cached count).
    let (d, p, mut a) = fresh();
    let mut b = Vault::open(&p, KeyFile::load(&d.path().join("k")).unwrap()).unwrap();
    a.set(
        &id("x1"),
        EntryKind::Secret,
        &text("secret-one-1"),
        Scan::Normal,
    )
    .unwrap();
    b.set(
        &id("x2"),
        EntryKind::Secret,
        &text("secret-two-2"),
        Scan::Normal,
    )
    .unwrap();
    assert_eq!(a.list().unwrap().len(), 2);
}

#[test]
fn errors_for_invalid_values_never_echo_them() {
    let (_d, _p, mut v) = fresh();
    let cases: [(EntryKind, &str); 6] = [
        (EntryKind::Host, "192.0.2.999"),
        (EntryKind::Host, "zz:zz::pw-host-xyz"),
        (EntryKind::Host, "bad host name-xyz"),
        (EntryKind::Mac, "02:00:5e:00:53:zz-xyz"),
        (EntryKind::Serial, "SN-xyz\u{7}"),
        (EntryKind::Credential, "pw-shape-xyz"),
    ];
    for (k, s) in cases {
        let e = v
            .set(&id("cam:a:v"), k, &text(s), Scan::Normal)
            .unwrap_err();
        let msg = format!("{e} {e:?}");
        assert!(!msg.contains("xyz"), "{msg}");
    }
}

#[test]
fn host_validation_edges() {
    let (_d, _p, mut v) = fresh();
    for bad in [
        " 192.0.2.10",
        "192.0.2.10 ",
        "192.0.2.10\n",
        "192.0.2.10:554",
        "http://192.0.2.10",
        "1234567890",
        "..",
        "a..",
        "*.example.invalid",
    ] {
        assert!(
            v.set(&id("cam:a:host"), EntryKind::Host, &text(bad), Scan::Normal)
                .is_err(),
            "{bad:?} accepted"
        );
    }
}

#[test]
fn mac_with_any_separator_layout_is_accepted() {
    let (_d, _p, mut v) = fresh();
    v.set(
        &id("cam:a:mac"),
        EntryKind::Mac,
        &text("0:2:0:0:5:e:0:0:5:3:a:f"),
        Scan::Normal,
    )
    .unwrap();
    let e = v.get(&id("cam:a:mac")).unwrap().unwrap();
    let Value::Text(t) = e.value else {
        panic!("shape")
    };
    assert_eq!(t.expose_secret(), "02:00:5e:00:53:af");
}
