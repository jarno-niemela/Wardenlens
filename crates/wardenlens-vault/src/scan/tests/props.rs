//! Property tests. Positive properties build well-formed text with the value embedded at a
//! random position between arbitrary surroundings (multibyte, invalid UTF-8, control bytes) and
//! assert the value is found on the expected line. Negative properties assert the control
//! (the value itself) is found in the same text, so a pass is never vacuous.

use std::fmt::Write as _;
use std::net::{Ipv4Addr, Ipv6Addr};

use proptest::prelude::*;
use wardenlens_core::entry::EntryKind::{DisplayName, Host, Mac, Other, Secret};

use super::{entry, matcher};
use crate::scan::scan;

/// Arbitrary bytes, either raw (so often invalid UTF-8) or the bytes of arbitrary text.
fn surround() -> impl Strategy<Value = Vec<u8>> {
    prop_oneof![
        proptest::collection::vec(any::<u8>(), 0..48),
        "\\PC{0,24}".prop_map(String::into_bytes),
        "[\\n\\r \\t\u{e9}\u{65e5}\u{1F642}%\\\\\"]{0,16}".prop_map(String::into_bytes),
    ]
}

fn newlines(b: &[u8]) -> usize {
    b.split(|&c| c == b'\n').count().saturating_sub(1)
}

/// `pre`, one space, the rendering, one space, `post`.
fn embed(pre: &[u8], middle: &str, post: &[u8]) -> Vec<u8> {
    let mut v = pre.to_vec();
    v.push(b' ');
    v.extend_from_slice(middle.as_bytes());
    v.push(b' ');
    v.extend_from_slice(post);
    v
}

fn found_lines(kind: wardenlens_core::entry::EntryKind, value: &str, text: &[u8]) -> Vec<usize> {
    let m = matcher(&[entry("e:one", kind, value)]);
    scan(&m, text)
        .unwrap()
        .hits
        .iter()
        .map(|h| h.line)
        .collect()
}

fn ipv4_style(a: Ipv4Addr, style: u8) -> String {
    let o = a.octets();
    let n = u32::from(a);
    match style % 7 {
        0 => a.to_string(),
        1 => format!("{}-{}-{}-{}", o[0], o[1], o[2], o[3]),
        2 => format!("{}_{}_{}_{}", o[0], o[1], o[2], o[3]),
        3 => format!("{}[.]{}[.]{}[.]{}", o[0], o[1], o[2], o[3]),
        4 => format!("{:03}.{:03}.{:03}.{:03}", o[0], o[1], o[2], o[3]),
        5 if n >= 10_000_000 => n.to_string(),
        5 => format!("0x{n:08X}"),
        _ => format!("{n:08x}"),
    }
}

fn mac_text(bytes: [u8; 6], shape: u8, seps: &[u8], upper: bool, drop_zero: bool) -> String {
    let sep = |i: usize| {
        char::from(
            *b":-._ /x"
                .get(usize::from(seps[i % seps.len()]) % 7)
                .unwrap(),
        )
    };
    let hex: Vec<String> = bytes
        .iter()
        .map(|b| {
            if drop_zero && *b < 16 {
                format!("{b:x}")
            } else {
                format!("{b:02x}")
            }
        })
        .collect();
    let flat = bytes.iter().fold(String::new(), |mut s, b| {
        write!(s, "{b:02x}").unwrap();
        s
    });
    let groups: Vec<String> = match shape % 4 {
        0 => hex,
        1 => flat
            .as_bytes()
            .chunks(4)
            .map(|c| String::from_utf8_lossy(c).into_owned())
            .collect(),
        2 => flat
            .as_bytes()
            .chunks(6)
            .map(|c| String::from_utf8_lossy(c).into_owned())
            .collect(),
        _ => vec![flat],
    };
    let mut out = String::new();
    for (i, g) in groups.iter().enumerate() {
        if i > 0 {
            out.push(sep(i));
        }
        out.push_str(g);
    }
    if upper { out.to_uppercase() } else { out }
}

proptest! {
    #[test]
    fn secret_is_found_between_arbitrary_bytes(
        value in "[A-Za-z0-9]{7,24}",
        pre in surround(),
        post in surround(),
        glue in prop::bool::ANY,
    ) {
        // `glue` puts the value directly against the surroundings: a secret has no boundary.
        let mut text = pre.clone();
        if !glue { text.push(b' '); }
        text.extend_from_slice(value.as_bytes());
        if !glue { text.push(b' '); }
        text.extend_from_slice(&post);
        let lines = found_lines(Secret, &value, &text);
        prop_assert!(lines.contains(&(1 + newlines(&pre))), "{lines:?}");
    }

    #[test]
    fn secret_is_not_found_in_text_that_lacks_it(
        value in "[a-z0-9]{7,16}",
        text in "[A-Z ,;:\u{e9}\u{65e5}\u{1F642}\\n]{0,200}",
    ) {
        prop_assert!(found_lines(Secret, &value, text.as_bytes()).is_empty());
        let control = format!("{text}\n{value}");
        prop_assert_eq!(
            found_lines(Secret, &value, control.as_bytes()),
            vec![text.matches('\n').count() + 2]
        );
    }

    #[test]
    fn ipv4_is_found_in_every_rendering(
        n in any::<u32>(),
        style in any::<u8>(),
        pre in surround(),
        post in surround(),
    ) {
        let a = Ipv4Addr::from(n);
        let text = embed(&pre, &ipv4_style(a, style), &post);
        let lines = found_lines(Host, &a.to_string(), &text);
        prop_assert!(lines.contains(&(1 + newlines(&pre))), "{lines:?}");
    }

    #[test]
    fn a_different_ipv4_is_not_found(a in any::<u32>(), b in any::<u32>(), style in 0u8..5) {
        prop_assume!(a != b);
        let (a, b) = (Ipv4Addr::from(a), Ipv4Addr::from(b));
        let other = ipv4_style(b, style);
        let none = found_lines(Host, &a.to_string(), other.as_bytes());
        prop_assert!(none.is_empty(), "{none:?}");
        let control = format!("{other}\n{}", ipv4_style(a, style));
        prop_assert_eq!(found_lines(Host, &a.to_string(), control.as_bytes()), vec![2]);
    }

    #[test]
    fn ipv6_is_found_compressed_expanded_and_next_to_punctuation(
        n in any::<u128>(),
        upper in prop::bool::ANY,
        glue in 0u8..4,
        pre in surround(),
        post in surround(),
    ) {
        let a = Ipv6Addr::from(n);
        let short = a.to_string();
        let full = a.segments().iter().map(|s| format!("{s:x}")).collect::<Vec<_>>().join(":");
        let mut rendering = if glue == 3 { full } else { short.clone() };
        if upper { rendering = rendering.to_uppercase(); }
        match glue {
            // A word glued on in front is found (suffix sub-runs) unless the address starts
            // with `::`, where the colon cannot separate it.
            1 if !rendering.starts_with(':') => rendering = format!("Source:{rendering}"),
            2 => rendering.push('.'),
            _ => {}
        }
        let text = embed(&pre, &rendering, &post);
        let lines = found_lines(Host, &short, &text);
        prop_assert!(lines.contains(&(1 + newlines(&pre))), "{rendering:?} {lines:?}");
    }

    #[test]
    fn mac_is_found_in_every_shape_and_separator(
        bytes in any::<[u8; 6]>(),
        shape in any::<u8>(),
        seps in proptest::collection::vec(any::<u8>(), 1..6),
        upper in prop::bool::ANY,
        drop_zero in prop::bool::ANY,
        pre in surround(),
        post in surround(),
    ) {
        let stored = bytes.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(":");
        let rendering = mac_text(bytes, shape, &seps, upper, drop_zero && shape % 4 == 0);
        let text = embed(&pre, &rendering, &post);
        let lines = found_lines(Mac, &stored, &text);
        prop_assert!(lines.contains(&(1 + newlines(&pre))), "{rendering:?} {lines:?}");
    }

    #[test]
    fn names_are_found_in_case_and_slug_variants(
        words in proptest::collection::vec("[a-z]{4,8}", 2..5),
        variant in 0u8..6,
        kind_is_display in prop::bool::ANY,
        pre in surround(),
        post in surround(),
    ) {
        let stored = words.join(" ");
        let kind = if kind_is_display { DisplayName } else { Other };
        let rendering = match (variant, kind_is_display) {
            (1, _) => stored.to_uppercase(),
            (2, true) => words.join("-"),
            (3, true) => words.join("_"),
            (4, true) => words.concat(),
            (5, _) => words.join("  \n   "),
            _ => stored.clone(),
        };
        let text = embed(&pre, &rendering, &post);
        let lines = found_lines(kind, &stored, &text);
        prop_assert!(lines.contains(&(1 + newlines(&pre))), "{rendering:?} {lines:?}");
    }

    #[test]
    fn a_different_name_is_not_found(
        a in proptest::collection::vec("[a-m]{4,8}", 2..4),
        b in proptest::collection::vec("[n-z]{4,8}", 2..4),
    ) {
        let (stored, other) = (a.join(" "), b.join(" "));
        prop_assert!(found_lines(DisplayName, &stored, other.as_bytes()).is_empty());
        let control = format!("{other}\n{stored}");
        prop_assert_eq!(found_lines(DisplayName, &stored, control.as_bytes()), vec![2]);
    }

    #[test]
    fn scanning_arbitrary_bytes_never_panics_and_hits_stay_in_range(
        text in proptest::collection::vec(any::<u8>(), 0..512),
    ) {
        let m = rich_matcher();
        let r = scan(&m, &text).unwrap();
        let lines = 1 + newlines(&text);
        prop_assert!(r.hits.iter().all(|h| (1..=lines).contains(&h.line)));
    }
}

fn rich_matcher() -> crate::scan::Matcher {
    matcher(&[
        entry("a:ip4", Host, "192.0.2.10"),
        entry("a:ip6", Host, "2001:db8::1"),
        entry("a:mac", Mac, "02:00:5e:00:53:af"),
        entry("a:dns", Host, "nvr-1.example.invalid"),
        entry("a:name", DisplayName, "Garage \u{2013} Side"),
        entry("a:sec", Secret, "pa\"ss\u{2013}word"),
    ])
}

#[test]
fn every_prefix_of_a_hostile_input_scans_without_panicking() {
    let text = "x\u{FF11}\u{FF19}\u{FF12}.0.2.10 %E2%80%93 \\u2013 2001:db8::1. \u{200B}\u{FFFD}\n\u{1F642}Garage%20-%20Side 02:00:5e:00:53:af nvr-1.example.invalid"
        .as_bytes()
        .to_vec();
    let m = rich_matcher();
    let mut found = 0;
    for end in 0..=text.len() {
        found += scan(&m, &text[..end]).unwrap().hits.len();
    }
    assert!(found > 20, "the sweep reached the matching paths: {found}");
    // And every suffix, which starts inside multibyte sequences.
    for start in 0..text.len() {
        scan(&m, &text[start..]).unwrap();
    }
}
