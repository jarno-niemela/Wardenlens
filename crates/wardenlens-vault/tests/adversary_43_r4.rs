//! Adversary tests for #43 round 4: one invisible predicate (I2), decoded views that keep every
//! form (I3) and legacy name mapping without silent collisions (I1). Synthetic values only.

#![expect(
    clippy::unwrap_used,
    reason = "integration-test helpers outside #[test] fns; clippy.toml in-tests allowances do not reach them"
)]

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::os::unix::fs::PermissionsExt;

use secrecy::SecretString;
use tempfile::TempDir;
use wardenlens_core::entry::{EntryId, EntryKind};
use wardenlens_core::text::is_dropped_invisible;
use wardenlens_secrets::KeyFile;
use wardenlens_vault::legacy::{LegacyError, map_legacy};
use wardenlens_vault::{Matcher, Scan, Value, Vault, scan};

fn fresh() -> (TempDir, Vault) {
    let d = tempfile::tempdir().unwrap();
    std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let key = KeyFile::generate(&d.path().join("k")).unwrap();
    let v = Vault::create(&d.path().join("v.db"), key).unwrap();
    (d, v)
}

fn text(s: &str) -> Value {
    Value::Text(SecretString::from(s.to_owned()))
}

fn with_name(name: &str) -> (TempDir, Vault) {
    let (d, mut v) = fresh();
    v.set(
        &EntryId::new("cam:a:name").unwrap(),
        EntryKind::DisplayName,
        &text(name),
        Scan::Normal,
    )
    .unwrap();
    (d, v)
}

fn hits(m: &Matcher, body: &str) -> usize {
    scan(m, body.as_bytes()).unwrap().hits.len()
}

/// I2, the legacy file itself: a JSON secret file whose camera name is written with a JSON
/// short escape for white space (`\t`, `\f`) is imported as `Porte Nord Est` (the vault
/// normalises the tab), but the scanner's JSON view does not decode `\t` or `\f` (only `\u`,
/// `\"`, `\\`, `\/`), so the very file the name came from is not found. `\u0009` is decoded,
/// and `%09` is too, so only the short escape spelling is lost.
#[test]
fn name_imported_from_a_json_short_escape_is_found_in_that_json_file() {
    let source = r#"[{"name":"Porte\tNord\tEst"}]"#;
    let doc: serde_json::Value = serde_json::from_str(source).unwrap();
    let out = map_legacy(Some(&doc), &BTreeMap::new(), None).unwrap();
    let (_d, mut v) = fresh();
    for e in &out.entries {
        v.set(&e.id, e.kind, &e.value, Scan::Normal).unwrap();
    }
    let m = Matcher::from_vault(&v).unwrap();
    let mut missed = Vec::new();
    for body in [
        source.to_owned(),
        r#"{"label":"Porte\fNord\fEst"}"#.to_owned(),
        r#"{"label":"Porte\tNord Est"}"#.to_owned(),
    ] {
        if hits(&m, &body) == 0 {
            missed.push(body);
        }
    }
    // Control: the long escape and percent-encoded forms are found.
    assert_eq!(hits(&m, r#"{"label":"Porte\u0009Nord\u0009Est"}"#), 1);
    assert_eq!(hits(&m, "label=Porte%09Nord%09Est"), 1);
    assert!(missed.is_empty(), "missed: {missed:?}");
}

/// I3: a literal invisible character before a percent-encoded value. The plain form
/// `x<ZWSP>Porte Nord Est` is found in the raw view, and the round-3 fix finds the fully
/// escaped `x%E2%80%8BPorte%20Nord%20Est`. But the decoded views are built from the squeezed
/// input, so the literal ZWSP is deleted before decoding, the value is glued to `x` and the
/// boundary fails: the mixed spelling is lost while both neighbouring spellings are found.
#[test]
fn literal_invisible_before_a_percent_encoded_value_keeps_its_boundary() {
    let (_d, v) = with_name("Porte Nord Est");
    let m = Matcher::from_vault(&v).unwrap();
    assert_eq!(hits(&m, "label=x\u{200B}Porte Nord Est\n"), 1);
    assert_eq!(hits(&m, "label=x%E2%80%8BPorte%20Nord%20Est\n"), 1);
    let mut missed = Vec::new();
    for body in [
        "label=x\u{200B}Porte%20Nord%20Est\n",
        "label=x\u{FE0F}Porte%20Nord%20Est\n",
        "{\"label\":\"x\u{200B}Porte\\u0020Nord\\u0020Est\"}\n",
    ] {
        if hits(&m, body) == 0 {
            missed.push(body);
        }
    }
    assert!(missed.is_empty(), "missed: {missed:?}");
}

/// I2 exhaustively: for every scalar value `c`, the source spelling `Porte<c>Nord Est` is found
/// exactly when the vault would store that spelling as one of the two stored names (white space
/// gives `Porte Nord Est`, a dropped invisible gives `PorteNord Est`).
#[test]
fn every_dropped_or_whitespace_character_inside_a_stored_name_is_found() {
    let (_d, mut v) = with_name("Porte Nord Est");
    v.set(
        &EntryId::new("cam:b:name").unwrap(),
        EntryKind::DisplayName,
        &text("PorteNord Est"),
        Scan::Normal,
    )
    .unwrap();
    let m = Matcher::from_vault(&v).unwrap();
    let mut missed = Vec::new();
    for n in 0..=0x0010_FFFF_u32 {
        let Some(c) = char::from_u32(n) else { continue };
        if !(c.is_whitespace() || is_dropped_invisible(c)) {
            continue;
        }
        if hits(&m, &format!("label=Porte{c}Nord Est\n")) == 0 {
            missed.push(format!("U+{n:04X}"));
        }
    }
    assert!(missed.is_empty(), "missed: {missed:?}");
}

/// I2, escaped spellings: every dropped invisible character, JSON-escaped (with surrogate
/// pairs above the BMP) and percent-encoded, inside the stored name is found.
#[test]
fn escaped_dropped_invisible_inside_a_stored_name_is_found() {
    let (_d, v) = with_name("PorteNord Est");
    let m = Matcher::from_vault(&v).unwrap();
    let mut missed = Vec::new();
    for n in 0..=0x0010_FFFF_u32 {
        let Some(c) = char::from_u32(n) else { continue };
        if !is_dropped_invisible(c) {
            continue;
        }
        let mut units = [0u16; 2];
        let mut json = String::new();
        for u in c.encode_utf16(&mut units).iter() {
            write!(json, "\\u{u:04x}").unwrap();
        }
        let mut buf = [0u8; 4];
        let mut pct = String::new();
        for b in c.encode_utf8(&mut buf).bytes() {
            write!(pct, "%{b:02X}").unwrap();
        }
        for body in [
            format!("{{\"label\":\"Porte{json}Nord Est\"}}\n"),
            format!("label=Porte{pct}Nord%20Est\n"),
        ] {
            if hits(&m, &body) == 0 {
                missed.push(body);
            }
        }
    }
    assert!(missed.is_empty(), "missed: {missed:?}");
}

/// I1: two JSON cameras whose names the vault refuses to store but which map to one inventory
/// camera are a typed error, never a silent overwrite or a credential on another camera.
#[test]
fn two_unstorable_json_names_mapping_to_one_inventory_camera_are_refused() {
    let names = BTreeMap::from([("\u{2605}".to_owned(), "garage".to_owned())]);
    for second in [
        "\u{2605}",
        "\u{2605}\u{FE0F}",
        " \u{2605} ",
        "\u{200B}\u{2605}",
    ] {
        let doc = serde_json::json!([
            {"name": "\u{2605}", "login": "u1", "password": "Tr0ub4dor-1"},
            {"name": second, "login": "u2", "password": "Tr0ub4dor-2"},
        ]);
        let r = map_legacy(Some(&doc), &names, None);
        assert!(
            matches!(
                r,
                Err(LegacyError::DuplicateId(_) | LegacyError::DuplicateName)
            ),
            "{second:?}: {r:?}"
        );
    }
}

/// I1: every credential lands on the inventory id of the camera whose name matches in stored
/// form, for each spelling of the JSON name, and only there.
#[test]
fn credential_lands_on_the_matching_inventory_camera_for_every_spelling() {
    let names = BTreeMap::from([
        ("Porte Nord".to_owned(), "nord".to_owned()),
        ("Porte Sud".to_owned(), "sud".to_owned()),
        ("PorteNord".to_owned(), "glued".to_owned()),
    ]);
    for (spelling, want) in [
        ("Porte\u{a0}Nord", "nord"),
        ("Porte\u{2028}Nord", "nord"),
        ("Porte\tNord ", "nord"),
        ("Porte\u{200B}Nord", "glued"),
        ("Porte\u{FE0F}Nord", "glued"),
        ("Porte\u{3000}Sud", "sud"),
    ] {
        let doc = serde_json::json!([{"name": spelling, "login": "u1", "password": "Tr0ub4dor-1"}]);
        let out = map_legacy(Some(&doc), &names, None).unwrap();
        let creds: Vec<&str> = out
            .entries
            .iter()
            .filter(|e| e.kind == EntryKind::Credential)
            .map(|e| e.id.as_str())
            .collect();
        assert_eq!(creds, [format!("cam:{want}:credential")], "{spelling:?}");
    }
}
