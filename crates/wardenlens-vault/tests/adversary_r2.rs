//! Round-2 adversarial tests for the vault library (synthetic values only).

#![expect(
    clippy::unwrap_used,
    reason = "integration-test helpers outside #[test] fns; clippy.toml in-tests allowances do not reach them"
)]

use std::collections::{BTreeMap, BTreeSet};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use secrecy::{ExposeSecret, SecretString};
use tempfile::TempDir;
use wardenlens_core::entry::{EntryId, EntryKind};
use wardenlens_secrets::{Credentials, KeyFile};
use wardenlens_vault::legacy::{map_inventory_toml, map_legacy, map_secret_json};
use wardenlens_vault::{Scan, Scannability, Value, Vault};

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

// ---- unscannable rule: fold and squeeze (ADR 0006 section 7) --------------------------------

/// Serial needles are matched in the fold; the compact form must reach 7 bytes *after* the
/// fold. Six KELVIN SIGNs (U+212A, 3 bytes each) fold to `kkkkkk` (6 bytes).
#[test]
fn serial_whose_folded_compact_form_is_short_is_unscannable() {
    let (_d, _p, mut v) = fresh();
    let s = v
        .set(
            &id("cam:a:serial"),
            EntryKind::Serial,
            &text(&"\u{212A}".repeat(6)),
            Scan::Normal,
        )
        .unwrap();
    assert_eq!(s, Scannability::Unscannable);
}

/// ADR 0006 section 7: "a value made only of zero-width characters squeezes to an empty
/// needle", so the entry is unscannable.
#[test]
#[ignore = "squeeze applied by #75, which recomputes the flag for all kinds"]
fn display_name_of_only_zero_width_characters_is_unscannable() {
    let (_d, _p, mut v) = fresh();
    let r = v.set(
        &id("cam:a:name"),
        EntryKind::DisplayName,
        &text(&"\u{200B}".repeat(7)),
        Scan::Normal,
    );
    assert_eq!(r.unwrap(), Scannability::Unscannable);
}

#[test]
#[ignore = "squeeze applied by #75, which recomputes the flag for all kinds"]
fn secret_of_only_soft_hyphens_is_unscannable() {
    let (_d, _p, mut v) = fresh();
    let r = v.set(
        &id("api:x:token"),
        EntryKind::Secret,
        &text(&"\u{00AD}".repeat(7)),
        Scan::Normal,
    );
    assert_eq!(r.unwrap(), Scannability::Unscannable);
}

/// The fold can shrink a value: KELVIN SIGN (3 bytes) folds to `k` (1 byte).
#[test]
fn other_kind_uses_the_fold_for_its_minimum() {
    let (_d, _p, mut v) = fresh();
    // KELVIN SIGN x3 + "ab" = 11 bytes raw, folds to "kkkab" (5 bytes).
    let r = v
        .set(
            &id("site:x:addr"),
            EntryKind::Other,
            &text("\u{212A}\u{212A}\u{212A}ab"),
            Scan::Normal,
        )
        .unwrap();
    assert_eq!(r, Scannability::Unscannable);
}

// ---- limits ---------------------------------------------------------------------------------

#[test]
fn credential_at_both_field_limits_round_trips() {
    let (_d, path, mut v) = fresh();
    let user = "u".repeat(4096);
    let pw = "p".repeat(4096);
    v.set(
        &id("cam:a:credential"),
        EntryKind::Credential,
        &Value::Credential(Credentials::new(&user, &pw)),
        Scan::Normal,
    )
    .unwrap();
    drop(v);
    let key = KeyFile::load(&path.parent().unwrap().join("k")).unwrap();
    let v = Vault::open(&path, key).unwrap();
    let got = v.get(&id("cam:a:credential")).unwrap().unwrap();
    let Value::Credential(cred) = got.value else {
        panic!("shape")
    };
    assert_eq!(cred.username, user);
    assert_eq!(cred.password.expose_secret(), pw);
}

#[test]
fn display_name_that_grows_under_the_fold_at_the_limit_is_stored() {
    let (_d, _p, mut v) = fresh();
    // 2048 x U+0130 = 4096 bytes; lowercased 6144 bytes (only used for the flag).
    let r = v.set(
        &id("cam:a:name"),
        EntryKind::DisplayName,
        &text(&"\u{130}".repeat(2048)),
        Scan::Normal,
    );
    assert_eq!(r.unwrap(), Scannability::Scannable);
}

// ---- legacy mapping -------------------------------------------------------------------------

/// The two mapping results are imported into one vault, whose `set` is an upsert. Their union
/// must not contain one id twice, or the second file silently overwrites the first.
#[test]
fn json_and_toml_results_never_share_an_entry_id() {
    let toml: toml::Table =
        toml::from_str("[cameras.import-json-1]\nname = \"Back Door North\"\n").unwrap();
    let json: serde_json::Value =
        serde_json::from_str(r#"[{"name":"Front Gate","login":"svc-reader","password":"x"}]"#)
            .unwrap();
    let both = map_legacy(Some(&json), &BTreeMap::new(), Some(&toml)).unwrap();
    let mut seen = BTreeSet::new();
    for e in &both.entries {
        assert!(seen.insert(e.id.to_string()), "duplicate id {}", e.id);
    }
}

/// A real inventory id on both sides: the inventory owns the display name, so the import
/// succeeds and the JSON name is reported by key.
#[test]
fn json_name_of_a_mapped_camera_yields_to_the_inventory_name() {
    let toml: toml::Table = toml::from_str("[cameras.tapo]\nname = \"Garage Side\"\n").unwrap();
    let json: serde_json::Value =
        serde_json::from_str(r#"[{"name":"Garage","login":"u","password":"p"}]"#).unwrap();
    let m = BTreeMap::from([("Garage".to_owned(), "tapo".to_owned())]);
    let i = map_legacy(Some(&json), &m, Some(&toml)).unwrap();
    assert!(i.unknown_keys.iter().any(|k| k == "tapo.name"));
    assert_eq!(
        i.entries
            .iter()
            .filter(|e| e.id.as_str() == "cam:tapo:name")
            .count(),
        1
    );
}

/// Every entry the mapper emits should be storable; otherwise one bad field aborts or skips
/// at `set` time instead of being reported by name.
#[test]
fn json_empty_name_is_reported_or_storable() {
    let json: serde_json::Value =
        serde_json::from_str(r#"[{"name":"","login":"svc-reader","password":"Tr0ub4dor-x9"}]"#)
            .unwrap();
    let j = map_secret_json(&json, &BTreeMap::new()).unwrap();
    let (_d, _p, mut v) = fresh();
    for e in &j.entries {
        assert!(
            v.set(&e.id, e.kind, &e.value, Scan::Normal).is_ok(),
            "mapped entry {} cannot be stored",
            e.id
        );
    }
}

#[test]
fn json_empty_login_with_a_username_is_reported_or_storable() {
    let json: serde_json::Value =
        serde_json::from_str(r#"[{"login":"","username":"svc-reader","password":"Tr0ub4dor-x9"}]"#)
            .unwrap();
    let j = map_secret_json(&json, &BTreeMap::new()).unwrap();
    let (_d, _p, mut v) = fresh();
    for e in &j.entries {
        assert!(
            v.set(&e.id, e.kind, &e.value, Scan::Normal).is_ok(),
            "mapped entry {} cannot be stored",
            e.id
        );
    }
}

#[test]
fn reported_key_names_escape_bidi_and_line_separators() {
    let json: serde_json::Value =
        serde_json::from_str("[{\"a\\u202eb\":1,\"c\\u2028d\":2,\"e\\u200bf\":3}]").unwrap();
    let j = map_secret_json(&json, &BTreeMap::new()).unwrap();
    for k in &j.unknown_keys {
        assert!(
            !k.chars()
                .any(|c| matches!(c, '\u{202E}' | '\u{2028}' | '\u{200B}')),
            "unescaped: {k:?}"
        );
    }
    assert_eq!(j.unknown_keys.len(), 3);
}

#[test]
fn toml_nested_table_inside_a_camera_is_reported() {
    let toml: toml::Table = toml::from_str(
        "[cameras.a]\nhost = \"192.0.2.10\"\n[cameras.a.auth]\npassword = \"Tr0ub4dor-x9\"\n",
    )
    .unwrap();
    let t = map_inventory_toml(&toml).unwrap();
    assert_eq!(t.unknown_keys, ["a.auth"]);
    assert!(!format!("{t:?}").contains("Tr0ub4dor"));
}

#[test]
fn json_null_fields_import_nothing_and_report_nothing() {
    let json: serde_json::Value =
        serde_json::from_str(r#"[{"name":null,"login":null,"password":null}]"#).unwrap();
    let j = map_secret_json(&json, &BTreeMap::new()).unwrap();
    assert!(j.entries.is_empty());
    assert_eq!(j.unknown_keys.len(), 0);
}

#[test]
fn mapped_inventory_id_with_reserved_looking_prefix_stays_under_cam() {
    let json: serde_json::Value =
        serde_json::from_str(r#"[{"name":"G","login":"u","password":"p"}]"#).unwrap();
    let m = BTreeMap::from([("G".to_owned(), "meta".to_owned())]);
    let j = map_secret_json(&json, &m).unwrap();
    assert!(j.entries.iter().all(|e| e.id.as_str().starts_with("cam:")));
}

// ---- open sequence --------------------------------------------------------------------------

#[test]
fn create_refuses_a_path_ending_in_dotdot() {
    // A path whose final component is `..` is never a vault file.
    let d = dir();
    let key = KeyFile::generate(&d.path().join("k")).unwrap();
    let sub = d.path().join("s");
    std::fs::create_dir(&sub).unwrap();
    std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(Vault::create(&sub.join(".."), key).is_err());
}

#[test]
fn create_after_a_failed_create_on_an_empty_file_works_and_open_needs_meta() {
    let d = dir();
    let p = d.path().join("v.db");
    std::fs::File::create(&p).unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
    let key = KeyFile::generate(&d.path().join("k")).unwrap();
    let k2 = KeyFile::load(&d.path().join("k")).unwrap();
    assert!(Vault::open(&p, k2).is_err());
    let mut v = Vault::create(&p, key).unwrap();
    v.set(
        &id("cam:a:host"),
        EntryKind::Host,
        &text("192.0.2.10"),
        Scan::Normal,
    )
    .unwrap();
}
