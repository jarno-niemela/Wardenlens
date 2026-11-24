//! Adversary tests for the exact-match scan (#75, ADR 0006 sections 7 and 8). Synthetic values
//! only: TEST-NET addresses, `*.invalid` names and made-up secrets.

#![expect(
    clippy::unwrap_used,
    reason = "integration-test helpers outside #[test] fns; clippy.toml in-tests allowances do not reach them"
)]

use secrecy::SecretString;
use wardenlens_core::entry::{EntryId, EntryKind};
use wardenlens_vault::{Matcher, ScanEntry, scan};

fn entry(name: &str, kind: EntryKind, value: &str) -> ScanEntry {
    ScanEntry {
        id: EntryId::new(name).unwrap(),
        kind,
        value: SecretString::from(value.to_owned()),
        unscannable: false,
    }
}

fn found(kind: EntryKind, value: &str, text: &str) -> Vec<(usize, String)> {
    let m = Matcher::new(&[entry("e:one", kind, value)]).unwrap();
    assert!(m.unscannable().is_empty(), "entry unexpectedly unscannable");
    scan(&m, text.as_bytes())
        .unwrap()
        .hits
        .iter()
        .map(|h| (h.line, h.id.as_str().to_owned()))
        .collect()
}

/// The stored value itself, byte for byte, in a text must be a hit. Display names and `other`
/// values are accepted by the store with any Unicode whitespace (display names refuse only
/// control characters), and the needle is whitespace-collapsed, but the joined view only
/// collapses spaces, tabs and line breaks. A stored value with U+202F (narrow no-break space,
/// common in French typography), U+205F, U+1680, U+2028 or U+2029 is then not found verbatim.
#[test]
fn a_display_name_with_unicode_whitespace_is_found_verbatim() {
    let missed: Vec<String> = ['\u{202F}', '\u{205F}', '\u{1680}', '\u{2028}', '\u{2029}']
        .into_iter()
        .filter(|&ws| {
            let stored = format!("Porte{ws}Nord Est");
            let text = format!("camera name: {stored}\n");
            found(EntryKind::DisplayName, &stored, &text) != vec![(1, "e:one".to_owned())]
        })
        .map(|ws| format!("U+{:04X}", u32::from(ws)))
        .collect();
    assert!(
        missed.is_empty(),
        "display names not found verbatim with {missed:?}"
    );
}

#[test]
fn an_other_value_with_unicode_whitespace_is_found_verbatim() {
    let mut missed = Vec::new();
    for ws in [
        '\u{000B}', '\u{000C}', '\u{0085}', '\u{202F}', '\u{205F}', '\u{2028}',
    ] {
        let stored = format!("Unit 4{ws}Harbour Road");
        let text = format!("note: {stored}\n");
        if found(EntryKind::Other, &stored, &text) != vec![(1, "e:one".to_owned())] {
            missed.push(format!("U+{:04X}", u32::from(ws)));
        }
    }
    assert!(
        missed.is_empty(),
        "other values not found verbatim with {missed:?}"
    );
}

/// ADR 0006 section 7 gives the joined view (line wrapping collapsed) to `display-name` and
/// `other` only. A serial must match only "the value as entered and the compact form".
#[test]
fn a_serial_is_not_matched_across_a_line_break() {
    let hits = found(EntryKind::Serial, "SN 0042 ZQ", "serial SN\n    0042 ZQ\n");
    assert!(
        hits.is_empty(),
        "serial matched in the joined view: {hits:?}"
    );
}

// ---- attacks that survived (kept as coverage) ----

#[test]
fn a_mac_with_a_multibyte_or_invalid_byte_separator_is_found() {
    let m = Matcher::new(&[entry("e:mac", EntryKind::Mac, "02:00:5e:00:53:af")]).unwrap();
    for text in [
        "02\u{00B7}00\u{00B7}5e\u{00B7}00\u{00B7}53\u{00B7}af"
            .as_bytes()
            .to_vec(),
        b"02\xFF00\xFF5e\xFF00\xFF53\xFFaf".to_vec(),
        "02\u{FF1A}00\u{FF1A}5E\u{FF1A}00\u{FF1A}53\u{FF1A}AF"
            .as_bytes()
            .to_vec(),
    ] {
        assert_eq!(scan(&m, &text).unwrap().hits.len(), 1, "{text:?}");
    }
}

#[test]
fn an_ipv6_with_a_percent_encoded_zone_or_in_brackets_is_found() {
    for text in [
        "http://[2001:db8::1%25eth0]/",
        "2001%3Adb8%3A%3A1",
        "a=2001:DB8:0000::0001;",
        "2001:db8::1...",
    ] {
        assert_eq!(
            found(EntryKind::Host, "2001:db8::1", text).len(),
            1,
            "{text}"
        );
    }
}

#[test]
fn ipv6_near_misses_are_not_found() {
    for text in ["2001:db8::1:0", "2001:db8::11", "2001:db8:0:1::"] {
        assert!(
            found(EntryKind::Host, "2001:db8::1", text).is_empty(),
            "{text}"
        );
    }
}

#[test]
fn every_owner_of_one_needle_is_reported_across_kinds() {
    let m = Matcher::new(&[
        entry("a:secret", EntryKind::Secret, "Back Door North"),
        entry("b:name", EntryKind::DisplayName, "Back Door North"),
        entry("c:other", EntryKind::Other, "back door north"),
        entry("d:secret", EntryKind::Secret, "Back Door North"),
    ])
    .unwrap();
    let ids: Vec<String> = scan(&m, b"x Back Door North y")
        .unwrap()
        .hits
        .iter()
        .map(|h| h.id.as_str().to_owned())
        .collect();
    assert_eq!(ids, ["a:secret", "b:name", "c:other", "d:secret"]);
}

#[test]
fn encoded_line_breaks_never_shift_a_hit_line() {
    let pw = "correct-horse-9";
    let text = format!("a%0Ab%0d%E2%80%A8%C2%85\\u000a\\u2028\\n\nline two {pw}\n");
    assert_eq!(
        found(EntryKind::Secret, pw, &text),
        vec![(2, "e:one".to_owned())]
    );
    // The percent and JSON forms of the secret on line 3, after encoded breaks on line 1.
    let text = "x%0A%0a\\u000A\\u0085\n\ncorrect%2Dhorse%2D9 \\u0063orrect-horse-9\n";
    assert_eq!(
        found(EntryKind::Secret, pw, text),
        vec![(3, "e:one".to_owned())]
    );
}

#[test]
fn ipv4_shapes_that_are_not_the_value_are_not_found() {
    // A longer chain is windowed (ADR 0006 section 7), so this one is found.
    assert_eq!(
        found(EntryKind::Host, "192.0.2.10", "192.0.2.10.0.0").len(),
        1
    );
    for text in [
        "192..0.2.10",
        "192.0..2.10",
        "192:0:2:10",
        "1920.2.10",
        "c000020a0",
        "0xc000020a1",
        "32212259940",
        "192 . 0 . 2 . 10",
    ] {
        assert!(
            found(EntryKind::Host, "192.0.2.10", text).is_empty(),
            "{text}"
        );
    }
}

/// The display name with U+202F is accepted by the store, so the verbatim miss is reachable
/// through `vault set` and `Matcher::from_vault`.
#[test]
fn a_stored_display_name_with_a_narrow_no_break_space_is_found_verbatim_through_the_vault() {
    use std::os::unix::fs::PermissionsExt;
    use wardenlens_secrets::KeyFile;
    use wardenlens_vault::{Scan, Value, Vault};

    let d = tempfile::tempdir().unwrap();
    std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let key = KeyFile::generate(&d.path().join("k")).unwrap();
    let mut v = Vault::create(&d.path().join("v.db"), key).unwrap();
    let stored = "Porte\u{202F}Nord Est";
    v.set(
        &EntryId::new("cam:a:name").unwrap(),
        EntryKind::DisplayName,
        &Value::Text(SecretString::from(stored.to_owned())),
        Scan::Normal,
    )
    .unwrap();
    let m = Matcher::from_vault(&v).unwrap();
    assert_eq!(m.unscannable().len(), 0);
    let text = format!("name = {stored}\n");
    assert_eq!(scan(&m, text.as_bytes()).unwrap().hits.len(), 1);
}
