//! Adversary tests for #43 round 3: display names are normalised before core's `DisplayName`,
//! legacy import maps names in that normalised form, and the decoded scan views are squeezed and
//! joined. Synthetic values only.

#![expect(
    clippy::unwrap_used,
    reason = "integration-test helpers outside #[test] fns; clippy.toml in-tests allowances do not reach them"
)]

use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt;

use secrecy::SecretString;
use tempfile::TempDir;
use wardenlens_core::entry::{EntryId, EntryKind};
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

fn json(s: &str) -> serde_json::Value {
    serde_json::from_str(s).unwrap()
}

fn credential_ids(out: &wardenlens_vault::legacy::LegacyImport) -> Vec<String> {
    out.entries
        .iter()
        .filter(|e| e.kind == EntryKind::Credential)
        .map(|e| e.id.as_str().to_owned())
        .collect()
}

/// P1: two inventory cameras whose names differ only in whitespace (a doubled space, a trailing
/// space, an NBSP) normalise to the same stored form. The CLI refuses two inventory cameras that
/// share a name exactly; the library now silently keeps the first of the normalised pair, so the
/// JSON credential written for one camera is imported under the other camera's id. Expected:
/// either the exact-name camera gets it, or the import is refused with a typed error.
#[test]
fn legacy_credential_is_never_attached_to_a_different_camera_after_name_normalisation() {
    for (exact, other) in [
        ("Porte Nord", "Porte  Nord"),
        ("Porte Nord", "Porte Nord "),
        ("Porte Nord", "Porte\u{a0}Nord"),
        ("Porte\u{a0}Nord", "Porte Nord"),
        ("PorteNord", "Porte\u{200b}Nord"),
    ] {
        let names = BTreeMap::from([
            (exact.to_owned(), "cam-exact".to_owned()),
            (other.to_owned(), "cam-other".to_owned()),
        ]);
        let doc = json(&format!(
            r#"[{{"name":{},"login":"u1","password":"Tr0ub4dor-1"}}]"#,
            serde_json::to_string(exact).unwrap()
        ));
        match map_legacy(Some(&doc), &names, None) {
            Err(_) => {}
            Ok(out) => assert_eq!(
                credential_ids(&out),
                ["cam:cam-exact:credential"],
                "{exact:?} vs {other:?}"
            ),
        }
    }
}

/// Round 3 refuses names with no alphanumeric character. An emoji-only camera name renders
/// visibly and was accepted in round 2; now the JSON credential of an inventory camera with that
/// name is imported under an ordinal id instead of the inventory id (the round-2 major, again):
/// the name only needs to be *looked up*, not stored, for a mapped camera.
#[test]
fn legacy_credential_of_an_inventory_camera_with_a_refused_name_keeps_the_inventory_id() {
    for name in [
        "\u{1F3E0}",
        "\u{1F6AA}\u{1F6AA}",
        "---",
        "\u{2605} \u{2605}",
    ] {
        let names = BTreeMap::from([(name.to_owned(), "garage".to_owned())]);
        let doc = json(&format!(
            r#"[{{"name":{},"login":"u1","password":"Tr0ub4dor-1"}}]"#,
            serde_json::to_string(name).unwrap()
        ));
        let out = map_legacy(Some(&doc), &names, None).unwrap();
        assert_eq!(
            credential_ids(&out),
            ["cam:garage:credential"],
            "{name:?} {:?}",
            out.unknown_keys
        );
    }
}

/// Two JSON cameras whose names normalise to one stored name are refused with the typed
/// duplicate error, never merged or overwritten.
#[test]
fn legacy_json_names_equal_after_normalisation_are_a_duplicate() {
    let doc = json(
        r#"[{"name":"Porte Nord","login":"u1","password":"Tr0ub4dor-1"},
            {"name":"Porte  Nord","login":"u2","password":"Tr0ub4dor-2"}]"#,
    );
    assert!(matches!(
        map_legacy(Some(&doc), &BTreeMap::new(), None),
        Err(LegacyError::DuplicateName)
    ));
}

/// Every emitted display name is accepted by the vault and stored unchanged (the mapper emits
/// the stored form).
#[test]
fn legacy_emitted_names_are_stored_verbatim() {
    let (_d, mut v) = fresh();
    let bs = "\\";
    let doc = json(&format!(
        r#"[{{"name":"{bs}u2066Cour{bs}u2003{bs}u2003Est{bs}u2069 ","login":"u3","password":"Tr0ub4dor-3"}}]"#
    ));
    let out = map_legacy(Some(&doc), &BTreeMap::new(), None).unwrap();
    for e in &out.entries {
        v.set(&e.id, e.kind, &e.value, Scan::Normal).unwrap();
        if e.kind == EntryKind::DisplayName {
            let Value::Text(sent) = &e.value else {
                panic!("shape")
            };
            let Value::Text(got) = v.get(&e.id).unwrap().unwrap().value else {
                panic!("shape")
            };
            assert_eq!(
                secrecy::ExposeSecret::expose_secret(&got),
                secrecy::ExposeSecret::expose_secret(sent)
            );
            assert_eq!(secrecy::ExposeSecret::expose_secret(sent), "Cour Est");
        }
    }
}

/// Normalisation is idempotent: setting the stored form again stores the same text.
#[test]
fn display_name_normalisation_is_idempotent() {
    let (_d, mut v) = fresh();
    let id = EntryId::new("cam:a:name").unwrap();
    for raw in [
        "\u{a0}a\u{200b} \u{2028}b\u{3000}",
        "a\u{85}b",
        "\u{1680}Porte\u{205f}Nord",
        "a \u{200b} b",
    ] {
        v.set(&id, EntryKind::DisplayName, &text(raw), Scan::Normal)
            .unwrap();
        let Value::Text(once) = v.get(&id).unwrap().unwrap().value else {
            panic!("shape")
        };
        let once = secrecy::ExposeSecret::expose_secret(&once).to_owned();
        assert!(!once.contains("  "), "{raw:?} -> {once:?}");
        v.set(&id, EntryKind::DisplayName, &text(&once), Scan::Normal)
            .unwrap();
        let Value::Text(twice) = v.get(&id).unwrap().unwrap().value else {
            panic!("shape")
        };
        assert_eq!(secrecy::ExposeSecret::expose_secret(&twice), once);
    }
}

fn hits(v: &Vault, body: &str) -> usize {
    let m = Matcher::from_vault(v).unwrap();
    scan(&m, body.as_bytes()).unwrap().hits.len()
}

/// Loss check: before round 3 the decoded views were not squeezed, so a value glued behind an
/// escaped invisible character (`x%E2%80%8B<value>`, `x​<value>`) passed the alphanumeric
/// boundary in the decoded view and was found. Squeezing the decoded view deletes the invisible
/// character, glues the value to `x` and the boundary now fails.
#[test]
fn values_behind_an_escaped_invisible_character_are_still_found() {
    let (_d, mut v) = fresh();
    v.set(
        &EntryId::new("cam:a:name").unwrap(),
        EntryKind::DisplayName,
        &text("Porte Nord Est"),
        Scan::Normal,
    )
    .unwrap();
    v.set(
        &EntryId::new("cam:a:host").unwrap(),
        EntryKind::Host,
        &text("nvr-1.example.invalid"),
        Scan::Normal,
    )
    .unwrap();
    let bs = "\\";
    let mut missed = Vec::new();
    for body in [
        "label=x%E2%80%8BPorte%20Nord%20Est\n".to_owned(),
        format!("{{\"label\":\"x{bs}u200bPorte Nord Est\"}}\n"),
        "url=x%E2%80%8Bnvr-1.example.invalid\n".to_owned(),
        format!("{{\"url\":\"x{bs}u200bnvr-1.example.invalid\"}}\n"),
    ] {
        if hits(&v, &body) == 0 {
            missed.push(body);
        }
    }
    assert!(missed.is_empty(), "missed: {missed:?}");
}

/// False-positive check: the joined view over decoded text must not join two halves of a
/// display name split by an encoded line break, nor match across a `%0A` that is not decoded.
#[test]
fn decoded_joined_view_reports_on_the_right_line() {
    let (_d, mut v) = fresh();
    v.set(
        &EntryId::new("cam:a:name").unwrap(),
        EntryKind::DisplayName,
        &text("Porte Nord Est"),
        Scan::Normal,
    )
    .unwrap();
    let m = Matcher::from_vault(&v).unwrap();
    let r = scan(&m, b"a\nb\nPorte%09Nord%20%20Est\n").unwrap();
    assert_eq!(r.hits.len(), 1);
    assert_eq!(r.hits[0].line, 3);
}

/// I2: a display name typed with any character the vault drops (emoji variation selector, CGJ,
/// Mongolian vowel separator, Hangul filler, a variation selector) is found once the vault stores
/// the plain form: the scanner squeezes exactly what the vault normalises away.
#[test]
fn stored_plain_name_is_found_when_the_file_has_any_dropped_invisible_character() {
    let (_d, mut v) = fresh();
    v.set(
        &EntryId::new("cam:a:name").unwrap(),
        EntryKind::DisplayName,
        &text("Porte Nord Est"),
        Scan::Normal,
    )
    .unwrap();
    for c in [
        '\u{FE0F}',
        '\u{034F}',
        '\u{180E}',
        '\u{3164}',
        '\u{FE00}',
        '\u{E0100}',
        '\u{2065}',
    ] {
        let body = format!("label=Porte{c} Nord{c} Est\n");
        assert_eq!(hits(&v, &body), 1, "U+{:04X}", u32::from(c));
    }
}

/// I3: a decoded view is searched both as decoded and squeezed.
#[test]
fn decoded_views_keep_both_forms() {
    let (_d, mut v) = fresh();
    v.set(
        &EntryId::new("cam:a:name").unwrap(),
        EntryKind::DisplayName,
        &text("Porte Nord Est"),
        Scan::Normal,
    )
    .unwrap();
    assert_eq!(hits(&v, "x%E2%80%8BPorte%20Nord%20Est\n"), 1);
    assert_eq!(hits(&v, "Po%EF%B8%8Frte%20Nord%20Est\n"), 1);
}
