//! Adversary tests for #43 round 2: the vault normalises a display name (whitespace to U+0020,
//! invisible characters dropped) and then applies core's `DisplayName`; the stored form is found
//! in every spelling a file can use. Synthetic values only.

#![expect(
    clippy::unwrap_used,
    reason = "integration-test helpers outside #[test] fns; clippy.toml in-tests allowances do not reach them"
)]

use std::os::unix::fs::PermissionsExt;

use secrecy::SecretString;
use tempfile::TempDir;
use wardenlens_core::entry::{EntryId, EntryKind};
use wardenlens_secrets::KeyFile;
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

/// `\u` built at run time so no tool turns the escape into the character.
fn json_esc(hex: &str) -> String {
    format!("\\u{hex}")
}

/// The spellings of `Porte<ws>Nord Est` in a file that a French name typed with a (narrow)
/// no-break space takes: verbatim, JSON-escaped (Python `json.dumps` default) and URL-encoded.
fn spellings() -> Vec<(&'static str, String)> {
    vec![
        ("raw U+202F", "Porte\u{202F}Nord Est".to_owned()),
        ("raw U+00A0", "Porte\u{A0}Nord Est".to_owned()),
        ("json \\u202f", format!("Porte{}Nord Est", json_esc("202f"))),
        ("json \\u00a0", format!("Porte{}Nord Est", json_esc("00a0"))),
        ("percent %E2%80%AF", "Porte%E2%80%AFNord%20Est".to_owned()),
        ("percent %C2%A0", "Porte%C2%A0Nord%20Est".to_owned()),
    ]
}

fn misses(v: &Vault) -> Vec<&'static str> {
    let m = Matcher::from_vault(v).unwrap();
    assert_eq!(m.unscannable().len(), 0);
    spellings()
        .into_iter()
        .filter(|(_, s)| {
            let body = format!("x\n{{\"name\":\"{s}\"}}\n");
            scan(&m, body.as_bytes()).unwrap().hits.len() != 1
        })
        .map(|(label, _)| label)
        .collect()
}

/// The vault normalises `Porte\u{202F}Nord Est` to the plain-space `Porte Nord Est`, the only
/// spelling it keeps. Every spelling of the same name in a file must still be found, though the
/// verbatim spelling is no longer stored for the unsqueezed needles to match (ADR 0006 section 7).
#[test]
fn a_plain_space_display_name_is_found_in_every_no_break_space_spelling() {
    let (_d, mut v) = fresh();
    let id = EntryId::new("cam:a:name").unwrap();
    // Round 3: the NNBSP spelling is normalised to the plain-space form on `set`.
    v.set(
        &id,
        EntryKind::DisplayName,
        &text("Porte\u{202F}Nord Est"),
        Scan::Normal,
    )
    .unwrap();
    let stored = v.get(&id).unwrap().unwrap();
    let Value::Text(t) = stored.value else {
        panic!("not text")
    };
    assert_eq!(secrecy::ExposeSecret::expose_secret(&t), "Porte Nord Est");
    let missed = misses(&v);
    assert!(missed.is_empty(), "display name missed in: {missed:?}");
}

/// Control: an `other` value keeps the no-break space it is stored with, and its escaped
/// spellings are found through the unsqueezed needles.
#[test]
fn an_other_value_stored_with_the_no_break_space_is_found_in_its_escaped_spellings() {
    let (_d, mut v) = fresh();
    v.set(
        &EntryId::new("cam:a:other").unwrap(),
        EntryKind::Other,
        &text("Porte\u{202F}Nord Est"),
        Scan::Normal,
    )
    .unwrap();
    let m = Matcher::from_vault(&v).unwrap();
    for s in [
        "Porte\u{202F}Nord Est".to_owned(),
        format!("Porte{}Nord Est", json_esc("202f")),
        "Porte%E2%80%AFNord%20Est".to_owned(),
    ] {
        let body = format!("x\n{{\"name\":\"{s}\"}}\n");
        assert_eq!(scan(&m, body.as_bytes()).unwrap().hits.len(), 1, "{s}");
    }
}

/// Round 3: whitespace and invisible characters in a display name are normalised before core's
/// rule (the stored form is plain-space); what is still refused is never stored in another form.
#[test]
fn display_names_are_normalised_and_the_rest_refused_without_a_stored_value() {
    let (_d, mut v) = fresh();
    let id = EntryId::new("cam:a:name").unwrap();
    for bad in [&"n".repeat(129), "a\u{1}b", "\u{2800}", "\u{200B}"] {
        let e = v
            .set(&id, EntryKind::DisplayName, &text(bad), Scan::Normal)
            .unwrap_err();
        assert!(
            matches!(e, wardenlens_vault::VaultError::InvalidValue { .. }),
            "{e}"
        );
        assert!(v.get(&id).unwrap().is_none());
    }
    for (raw, want) in [
        ("Porte\u{A0}Nord", "Porte Nord"),
        ("Porte\u{202F}Nord", "Porte Nord"),
        ("a\u{200B}b", "ab"),
        ("\u{2066}Porte\u{2069}", "Porte"),
        ("\u{A0}\u{3000}Porte Nord\u{2003}", "Porte Nord"),
    ] {
        v.set(&id, EntryKind::DisplayName, &text(raw), Scan::Normal)
            .unwrap();
        let Value::Text(t) = v.get(&id).unwrap().unwrap().value else {
            panic!("not text")
        };
        assert_eq!(secrecy::ExposeSecret::expose_secret(&t), want, "{raw:?}");
    }
}

/// The vault's host rule is core's `Host::new` behind lower-casing, one trailing dot removed and
/// brackets refused; the stored text is core's canonical form and builds a `Host` (ADR 0006
/// section 1). Oracle: that composition applied by hand.
#[test]
fn vault_host_rule_agrees_with_core_host() {
    use proptest::prelude::*;
    use secrecy::ExposeSecret;
    use wardenlens_core::camera::Host;

    let (_d, v) = fresh();
    let v = std::cell::RefCell::new(v);
    let id = EntryId::new("cam:a:host").unwrap();
    let accepted = std::cell::Cell::new(0_u32);
    let mut runner = proptest::test_runner::TestRunner::default();
    runner
        .run(
            &prop_oneof![
                "[A-Za-z0-9._:\\[\\]-]{0,20}",
                "(::ffff:)?[0-9]{1,3}(\\.[0-9]{1,3}){0,4}\\.?",
                "[a-z_]{1,8}(\\.[a-z0-9_-]{1,8}){0,3}\\.{0,2}",
            ],
            |raw| {
                let lower = raw.to_ascii_lowercase();
                let name = lower.strip_suffix('.').unwrap_or(&lower);
                let oracle = if name.contains(['[', ']']) {
                    None
                } else {
                    Host::new(name).ok()
                };
                let got = v
                    .borrow_mut()
                    .set(&id, EntryKind::Host, &text(&raw), Scan::Normal);
                prop_assert_eq!(got.is_ok(), oracle.is_some(), "{:?}", raw);
                if let Some(h) = oracle {
                    accepted.set(accepted.get() + 1);
                    let e = v.borrow().get(&id).unwrap().unwrap();
                    let Value::Text(t) = e.value else {
                        panic!("not text")
                    };
                    let want = h.expose();
                    prop_assert_eq!(t.expose_secret(), want.as_str());
                    prop_assert_eq!(Host::new(t.expose_secret()).unwrap(), h);
                }
                Ok(())
            },
        )
        .unwrap();
    assert!(accepted.get() > 0);
}

/// A legacy name that the display-name rule still refuses (over 128 bytes) is reported by key,
/// never dropped silently, and its credential is still imported (P1).
#[test]
fn legacy_names_refused_by_the_new_rule_are_reported() {
    use std::collections::BTreeMap;
    use wardenlens_vault::legacy::map_legacy;
    let long = "n".repeat(200);
    let j: serde_json::Value = serde_json::from_str(&format!(
        r#"[{{"name":"Porte Nord","login":"u1","password":"Tr0ub4dor-1"}},
            {{"name":"{long}","login":"u2","password":"Tr0ub4dor-2"}}]"#
    ))
    .unwrap();
    let out = map_legacy(Some(&j), &BTreeMap::new(), None).unwrap();
    let names = out
        .entries
        .iter()
        .filter(|e| e.kind == EntryKind::DisplayName)
        .count();
    let creds = out
        .entries
        .iter()
        .filter(|e| e.kind == EntryKind::Credential)
        .count();
    // The plain-space name is stored; the 200-byte one is not.
    assert_eq!((names, creds), (1, 2), "{:?}", out.unknown_keys);
    assert_eq!(
        out.unknown_keys
            .iter()
            .filter(|k| k.rsplit('.').next() == Some("name"))
            .count(),
        1,
        "{:?}",
        out.unknown_keys
    );
}
