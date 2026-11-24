//! Adversary tests of #75 round 2 (ADR 0006 section 7): the shared `White_Space` set of the joined
//! view, the verbatim needle, the joined view only for display-name and `other`, and line
//! numbers. Synthetic values only.

#![expect(
    clippy::unwrap_used,
    reason = "integration-test helpers outside #[test] fns; clippy.toml in-tests allowances do not reach them"
)]

use secrecy::SecretString;
use wardenlens_core::entry::{EntryId, EntryKind};
use wardenlens_vault::{Matcher, ScanEntry, scan};

fn matcher(kind: EntryKind, value: &str) -> Matcher {
    let m = Matcher::new(&[ScanEntry {
        id: EntryId::new("e:one").unwrap(),
        kind,
        value: SecretString::from(value.to_owned()),
        unscannable: false,
    }])
    .unwrap();
    assert!(m.unscannable().is_empty(), "{value:?} is unscannable");
    m
}

/// The lines reported for `text`.
fn lines(kind: EntryKind, value: &str, text: &str) -> Vec<usize> {
    let m = matcher(kind, value);
    scan(&m, text.as_bytes())
        .unwrap()
        .hits
        .iter()
        .map(|h| h.line)
        .collect()
}

const ALL_WS: [char; 25] = [
    '\t', '\n', '\u{B}', '\u{C}', '\r', ' ', '\u{85}', '\u{A0}', '\u{1680}', '\u{2000}',
    '\u{2001}', '\u{2002}', '\u{2003}', '\u{2004}', '\u{2005}', '\u{2006}', '\u{2007}', '\u{2008}',
    '\u{2009}', '\u{200A}', '\u{2028}', '\u{2029}', '\u{202F}', '\u{205F}', '\u{3000}',
];

/// Stored `Back Door North` (ASCII spaces): every `White_Space` character between the words in
/// the text is found (joined view), and the hit is on the line where it starts; `Door North`
/// alone is never found (ADR example).
#[test]
fn every_whitespace_separator_is_found_on_the_starting_line() {
    for c in ALL_WS {
        let text = format!("first\nsay Back{c}Door{c}{c}North now\n");
        assert_eq!(
            lines(EntryKind::DisplayName, "Back Door North", &text),
            vec![2],
            "U+{:04X}",
            u32::from(c)
        );
        let partial = format!("first\nsay Door{c}North now\n");
        assert_eq!(
            lines(EntryKind::DisplayName, "Back Door North", &partial),
            Vec::<usize>::new(),
            "U+{:04X}",
            u32::from(c)
        );
    }
}

/// A stored value with an unusual whitespace character is found in every rendering the ADR
/// lists: verbatim, with ASCII spaces, percent-encoded and JSON-escaped (unsqueezed needles in
/// the decoded and JSON views).
#[test]
fn a_value_with_a_narrow_no_break_space_is_found_in_every_view() {
    let v = "Back\u{202F}Door North";
    for text in [
        "x Back\u{202F}Door North y",
        "x back door north y",
        "x BACK   DOOR\n   NORTH y",
        "x Back%E2%80%AFDoor%20North y",
        "x Back\\u202fDoor North y",
        "x Back\\u202FDoor\\u0020North y",
    ] {
        assert_eq!(lines(EntryKind::DisplayName, v, text), vec![1], "{text:?}");
        assert_eq!(lines(EntryKind::Other, v, text), vec![1], "{text:?}");
    }
}

/// A line break inside the run before the match moves the hit to the line where the match
/// starts; U+2028, U+2029, U+0085 and a lone CR never count as line breaks.
#[test]
fn only_lf_counts_as_a_line_break_in_the_joined_view() {
    let v = "Back Door North";
    assert_eq!(
        lines(
            EntryKind::DisplayName,
            v,
            "a\u{2028}b\u{2029}c\u{85}d\re\nBack Door North"
        ),
        vec![2]
    );
    assert_eq!(
        lines(
            EntryKind::DisplayName,
            v,
            "a \n\n \u{2028}\n Back\n\u{85}\nDoor North"
        ),
        vec![4]
    );
}

/// The verbatim needle keeps the boundary rule: a letter or digit touching the value is no hit
/// (not `A` on either side), in every view.
#[test]
fn the_verbatim_needle_keeps_the_alnum_boundary() {
    let v = "Back\u{202F}Door North";
    for text in [
        "xBack\u{202F}Door North",
        "Back\u{202F}Door Northx",
        "1Back%E2%80%AFDoor%20North",
        "Back\\u202fDoor North9",
    ] {
        assert_eq!(
            lines(EntryKind::Other, v, text),
            Vec::<usize>::new(),
            "{text:?}"
        );
    }
}

/// A serial has no joined view (ADR 0006 section 7): `SN 0042 ZQ` regrouped is not found, and a
/// stored serial holding a space is not found with the space doubled or wrapped across lines.
#[test]
fn a_serial_gets_no_joined_view() {
    assert_eq!(
        lines(EntryKind::Serial, "SN-0042-ZQ", "x SN 0042 ZQ y"),
        Vec::<usize>::new()
    );
    let v = "SN 0042 ZQ";
    assert_eq!(lines(EntryKind::Serial, v, "x SN 0042 ZQ y"), vec![1]);
    assert_eq!(lines(EntryKind::Serial, v, "x SN0042ZQ y"), vec![1]);
    for text in [
        "x SN  0042 ZQ y",
        "x SN\n0042 ZQ y",
        "x SN\u{2028}0042 ZQ y",
    ] {
        assert_eq!(
            lines(EntryKind::Serial, v, text),
            Vec::<usize>::new(),
            "{text:?}"
        );
    }
}

/// Two entries with the same display name, one written with NNBSP: both are reported for the
/// same line (dedup keeps every owner).
#[test]
fn every_owner_of_a_shared_needle_is_reported() {
    let m = Matcher::new(&[
        ScanEntry {
            id: EntryId::new("e:a").unwrap(),
            kind: EntryKind::DisplayName,
            value: SecretString::from("Back Door North".to_owned()),
            unscannable: false,
        },
        ScanEntry {
            id: EntryId::new("e:b").unwrap(),
            kind: EntryKind::Other,
            value: SecretString::from("Back\u{202F}Door North".to_owned()),
            unscannable: false,
        },
    ])
    .unwrap();
    for text in [
        "back door north",
        "Back\u{202F}Door North",
        "Back\n  Door North",
    ] {
        let r = scan(&m, text.as_bytes()).unwrap();
        let ids: Vec<String> = r.hits.iter().map(|h| h.id.to_string()).collect();
        assert_eq!(ids, ["e:a", "e:b"], "{text:?}");
    }
}

/// The JSON and decoded views never gain a line break, so a hit after an escaped separator is
/// on the line of the text, not one further.
#[test]
fn escaped_separators_never_move_the_line() {
    let v = "zq-synthetic-mark-7781";
    for text in [
        "a\\u2028b\\u2029c\\u0085d\\u000Ae zq-synthetic-mark-7781",
        "a%E2%80%A8b%e2%80%a9c%C2%85d%0Ae%0d zq-synthetic-mark-7781",
    ] {
        assert_eq!(lines(EntryKind::Secret, v, text), vec![1], "{text:?}");
    }
}
