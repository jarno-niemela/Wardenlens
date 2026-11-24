//! A stored display-name or `other` value, byte for byte in a text, is always found, whatever
//! Unicode whitespace it holds (#75 round 2). Synthetic values only.

#![expect(
    clippy::unwrap_used,
    reason = "integration-test helpers outside #[test] fns; clippy.toml in-tests allowances do not reach them"
)]

use proptest::prelude::*;
use proptest::strategy::ValueTree;
use secrecy::SecretString;
use wardenlens_core::entry::{EntryId, EntryKind};
use wardenlens_vault::{Matcher, ScanEntry, scan};

/// Every Unicode `White_Space` character, so the generator reaches the collapse branch.
const WHITESPACE: [char; 25] = [
    '\t', '\n', '\u{B}', '\u{C}', '\r', ' ', '\u{85}', '\u{A0}', '\u{1680}', '\u{2000}',
    '\u{2001}', '\u{2002}', '\u{2003}', '\u{2004}', '\u{2005}', '\u{2006}', '\u{2007}', '\u{2008}',
    '\u{2009}', '\u{200A}', '\u{2028}', '\u{2029}', '\u{202F}', '\u{205F}', '\u{3000}',
];

fn piece() -> impl Strategy<Value = String> {
    prop_oneof![
        3 => proptest::sample::select(WHITESPACE.to_vec()).prop_map(String::from),
        4 => "[A-Za-z0-9]{1,5}",
        2 => any::<char>().prop_filter("not a control", |c| !c.is_control()).prop_map(String::from),
    ]
}

fn value() -> impl Strategy<Value = String> {
    proptest::collection::vec(piece(), 1..12).prop_map(|p| p.concat())
}

fn hits(kind: EntryKind, value: &str, text: &str) -> Option<usize> {
    let m = Matcher::new(&[ScanEntry {
        id: EntryId::new("e:one").unwrap(),
        kind,
        value: SecretString::from(value.to_owned()),
        unscannable: false,
    }])
    .unwrap();
    if !m.unscannable().is_empty() {
        return None;
    }
    Some(scan(&m, text.as_bytes()).unwrap().hits.len())
}

proptest! {
    #[test]
    fn a_stored_value_embedded_verbatim_is_found(
        v in value(),
        other in any::<bool>(),
        before in prop_oneof![Just(String::new()), Just("note: ".to_owned()), Just("x\n".to_owned())],
        after in prop_oneof![Just(String::new()), Just(" end".to_owned()), Just("\nend".to_owned())],
    ) {
        let kind = if other { EntryKind::Other } else { EntryKind::DisplayName };
        let text = format!("{before}{v}{after}");
        if let Some(n) = hits(kind, &v, &text) {
            // More than one line can be reported when the value itself holds a line break.
            prop_assert!(n >= 1, "value not found verbatim");
        }
    }
}

/// The generator must reach scannable values that hold whitespace, or the property is vacuous.
#[test]
fn the_generator_reaches_scannable_values_with_whitespace() {
    let mut runner = proptest::test_runner::TestRunner::deterministic();
    let mut reached = 0;
    for _ in 0..200 {
        let v = value().new_tree(&mut runner).unwrap().current();
        if v.chars().any(|c| WHITESPACE.contains(&c)) && hits(EntryKind::Other, &v, &v).is_some() {
            reached += 1;
        }
    }
    assert!(reached > 20, "only {reached} usable values");
}
