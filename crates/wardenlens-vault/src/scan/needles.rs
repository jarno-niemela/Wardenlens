//! Needle expansion per kind (ADR 0006 section 7, "the normaliser").
//!
//! A stored value becomes literal needles (matched by the Aho-Corasick automata) and numbers
//! for the IPv4, IPv6 and MAC tokenisers. Every literal needle exists twice when the squeeze
//! table changes it: the unsqueezed form (for the raw view) and the squeezed form (for the text
//! views). If any needle is shorter than 7 bytes the whole entry is `Unscannable`; an entry is
//! never partly scanned.

use std::fmt::Write as _;
use std::net::{Ipv4Addr, Ipv6Addr};

use base64::Engine;
use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, percent_encode};
use wardenlens_core::entry::EntryKind;

use super::squeeze::{fold, is_collapsible, squeeze};
use crate::validate::MIN_SCANNABLE_LEN;

/// Single-label hosts shorter than this are `unscannable` (ADR 0006 section 4).
const MIN_SINGLE_LABEL_HOST_LEN: usize = 8;

/// The views a needle applies to.
pub(super) mod view {
    pub(in crate::scan) const RAW: u8 = 1;
    pub(in crate::scan) const SQUEEZED: u8 = 2;
    pub(in crate::scan) const DECODED: u8 = 4;
    pub(in crate::scan) const JSON: u8 = 8;
    pub(in crate::scan) const JOINED: u8 = 16;
    /// The raw view and the views built from the squeezed text with decoding.
    pub(in crate::scan) const UNSQUEEZED: u8 = RAW | DECODED | JSON;
    /// The squeezed, decoded, JSON and joined views.
    pub(in crate::scan) const SQUEEZED_SET: u8 = SQUEEZED | DECODED | JSON | JOINED;
    /// The squeezed, decoded and JSON views: every squeezed view except the joined one.
    pub(in crate::scan) const SQUEEZED_PLAIN: u8 = SQUEEZED | DECODED | JSON;
}

/// What may touch a match (`A` is an ASCII letter or digit).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) enum Boundary {
    /// Nothing is checked: a substring hit on a password is a leak.
    None,
    /// Not `A` on either side.
    Alnum,
    /// Not `A`, `-` or `_` on either side (a DNS name).
    Dns,
}

/// One literal needle and where it applies.
pub(super) struct Literal {
    pub(super) text: String,
    pub(super) boundary: Boundary,
    /// Matched in the lowercased views.
    pub(super) folded: bool,
    pub(super) views: u8,
}

/// A number for a tokeniser.
pub(super) enum Net {
    V4(u32),
    V6(u128),
    Mac(u64),
}

/// The result of expanding one entry.
pub(super) enum Expansion {
    /// A needle is shorter than 7 bytes (or the value is unusable): never scanned, always warned.
    Unscannable,
    Scannable {
        literals: Vec<Literal>,
        net: Vec<Net>,
    },
}

struct Spec {
    fold: bool,
    boundary: Boundary,
    /// Whitespace is collapsed (also after the squeeze), because the joined view collapses it.
    collapse: bool,
    min_len: usize,
}

/// The needle collapse: every run of [`is_collapsible`] characters becomes one space, and the
/// ends are trimmed. The joined view uses the same definition.
pub(super) fn collapse(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut pending = false;
    for c in text.chars() {
        if is_collapsible(c) {
            pending = !out.is_empty();
        } else {
            if pending {
                out.push(' ');
                pending = false;
            }
            out.push(c);
        }
    }
    out
}

fn literals(bases: Vec<String>, spec: &Spec) -> Expansion {
    let mut out = Vec::new();
    for base in bases {
        let mut sq = squeeze(&base);
        if spec.collapse {
            sq = collapse(&sq);
        }
        let (unsq, sq) = if spec.fold {
            (fold(&base), fold(&sq))
        } else {
            (base, sq)
        };
        if unsq.len() < spec.min_len || sq.len() < spec.min_len {
            return Expansion::Unscannable;
        }
        let mut push = |text: String, views: u8| {
            out.push(Literal {
                text,
                boundary: spec.boundary,
                folded: spec.fold,
                views,
            });
        };
        // Only a kind with a joined view (`collapse`) gets that view (ADR 0006 section 7).
        let squeezed_views = if spec.collapse {
            view::SQUEEZED_SET
        } else {
            view::SQUEEZED_PLAIN
        };
        if unsq == sq {
            push(unsq, view::UNSQUEEZED | squeezed_views);
        } else {
            push(unsq, view::UNSQUEEZED);
            push(sq, squeezed_views);
        }
    }
    Expansion::Scannable {
        literals: out,
        net: Vec::new(),
    }
}

/// Adds the stored value itself, folded but not collapsed, as a needle of the views in which
/// the verbatim text can match: the joined view collapses whitespace and is covered by the
/// collapsed needle, every other view keeps the text as it is.
fn with_verbatim(expansion: Expansion, value: &str) -> Expansion {
    let Expansion::Scannable { mut literals, net } = expansion else {
        return expansion;
    };
    let raw = fold(value);
    let squeezed = fold(&squeeze(value));
    for (text, views) in [(raw, view::UNSQUEEZED), (squeezed, view::SQUEEZED_PLAIN)] {
        literals.push(Literal {
            text,
            boundary: Boundary::Alnum,
            folded: true,
            views,
        });
    }
    Expansion::Scannable { literals, net }
}

fn only_net(net: Net) -> Expansion {
    Expansion::Scannable {
        literals: Vec::new(),
        net: vec![net],
    }
}

/// Expands one stored value. `value` is the password for a credential (usernames are not
/// scanned).
pub(super) fn expand(kind: EntryKind, value: &str) -> Expansion {
    let text = Spec {
        fold: true,
        boundary: Boundary::Alnum,
        collapse: true,
        min_len: MIN_SCANNABLE_LEN,
    };
    match kind {
        EntryKind::Host => host(value),
        EntryKind::Mac => mac(value),
        EntryKind::Serial => {
            let trimmed = value.trim();
            let compact = trimmed
                .chars()
                .filter(|c| !matches!(c, '-' | '_' | '.' | ' '))
                .collect();
            let spec = Spec {
                collapse: false,
                ..text
            };
            literals(vec![trimmed.to_owned(), compact], &spec)
        }
        EntryKind::DisplayName => {
            let base = collapse(value);
            let bases = vec![
                base.replace(' ', "-"),
                base.replace(' ', "_"),
                base.replace(' ', ""),
                base,
            ];
            with_verbatim(literals(bases, &text), value)
        }
        EntryKind::Other => with_verbatim(literals(vec![collapse(value)], &text), value),
        EntryKind::Credential | EntryKind::Secret => {
            let spec = Spec {
                fold: false,
                boundary: Boundary::None,
                collapse: false,
                min_len: MIN_SCANNABLE_LEN,
            };
            literals(secret_bases(value), &spec)
        }
        // A kind added later is reported as unscannable until it gets its own rules.
        _ => Expansion::Unscannable,
    }
}

fn host(value: &str) -> Expansion {
    let name = value.trim().trim_end_matches('.').to_ascii_lowercase();
    if let Ok(a) = name.parse::<Ipv4Addr>() {
        return only_net(Net::V4(u32::from(a)));
    }
    if let Ok(a) = name.parse::<Ipv6Addr>() {
        let mut net = vec![Net::V6(u128::from(a))];
        if let Some(mapped) = a.to_ipv4_mapped() {
            // A stored IPv4-mapped address is also its IPv4 form.
            net.push(Net::V4(u32::from(mapped)));
        }
        return Expansion::Scannable {
            literals: Vec::new(),
            net,
        };
    }
    let spec = Spec {
        fold: true,
        boundary: Boundary::Dns,
        collapse: false,
        min_len: if name.contains('.') {
            MIN_SCANNABLE_LEN
        } else {
            MIN_SINGLE_LABEL_HOST_LEN
        },
    };
    literals(vec![name], &spec)
}

fn mac(value: &str) -> Expansion {
    let digits: Vec<u8> = value.bytes().filter(u8::is_ascii_hexdigit).collect();
    if digits.len() != 12 {
        return Expansion::Unscannable;
    }
    let n = digits.iter().fold(0u64, |a, &d| {
        let nib = char::from(d).to_digit(16).unwrap_or(0);
        a.wrapping_shl(4) | u64::from(nib)
    });
    only_net(Net::Mac(n))
}

/// Everything except the unreserved characters is percent-encoded.
pub(super) const UNRESERVED: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

fn percent_lower(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for chunk in percent_encode(value.as_bytes(), UNRESERVED) {
        // A chunk is either a run of unreserved bytes or one `%XX`.
        if chunk.starts_with('%') {
            out.push_str(&chunk.to_ascii_lowercase());
        } else {
            out.push_str(chunk);
        }
    }
    out
}

fn every_byte(value: &str, upper: bool) -> String {
    let mut out = String::with_capacity(value.len().saturating_mul(3));
    for b in value.bytes() {
        // Writing to a String cannot fail.
        let _ = if upper {
            write!(out, "%{b:02X}")
        } else {
            write!(out, "%{b:02x}")
        };
    }
    out
}

/// Base64 without padding at the three alignments: with `k` filler bytes in front, only the
/// characters fully determined by the value are kept (character `ceil(8k / 6)` up to, not
/// including, `floor(8(k + n) / 6)`). With a 7-byte minimum the shortest needle is 8 characters.
fn base64_needles(value: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    for k in 0..3usize {
        let mut buf = vec![0u8; k];
        buf.extend_from_slice(value);
        let from = k.saturating_mul(8).div_ceil(6);
        let to = k.saturating_add(value.len()).saturating_mul(8) / 6;
        for enc in [STANDARD_NO_PAD.encode(&buf), URL_SAFE_NO_PAD.encode(&buf)] {
            out.push(enc.get(from..to).unwrap_or_default().to_owned());
        }
    }
    out
}

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// The raw value, percent forms (upper, lower, every-byte, form-encoded), base64 (both
/// alphabets, three alignments), hex (both cases) and the XML escape.
fn secret_bases(value: &str) -> Vec<String> {
    let upper = percent_encode(value.as_bytes(), UNRESERVED).to_string();
    let lower = percent_lower(value);
    let mut out = vec![
        value.to_owned(),
        upper.replace("%20", "+"),
        lower.replace("%20", "+"),
        upper,
        lower,
        every_byte(value, true),
        every_byte(value, false),
    ];
    out.extend(base64_needles(value.as_bytes()));
    let hex: String = value.bytes().fold(String::new(), |mut s, b| {
        // Writing to a String cannot fail.
        let _ = write!(s, "{b:02x}");
        s
    });
    out.push(hex.to_ascii_uppercase());
    out.push(hex);
    let xml = xml_escape(value);
    if xml != value {
        out.push(xml);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn texts(e: Expansion) -> Vec<String> {
        match e {
            Expansion::Scannable { literals, .. } => literals.into_iter().map(|l| l.text).collect(),
            Expansion::Unscannable => Vec::new(),
        }
    }

    #[test]
    fn base64_alignments_match_the_adr_worked_example() {
        let n = base64_needles(b"correct-horse-9");
        // (standard, url-safe) for k = 0, 1, 2
        assert_eq!(n.first().map(String::as_str), Some("Y29ycmVjdC1ob3JzZS05"));
        assert_eq!(n.get(2).map(String::as_str), Some("NvcnJlY3QtaG9yc2UtO"));
        assert_eq!(n.get(4).map(String::as_str), Some("jb3JyZWN0LWhvcnNlLT"));
    }

    #[test]
    fn seven_byte_secret_keeps_every_alignment_with_at_least_eight_characters() {
        for n in base64_needles(b"abcdefg") {
            assert!(n.len() >= 8, "{n}");
        }
    }

    #[test]
    fn percent_forms_cover_case_every_byte_and_form_encoding() {
        let t = texts(expand(EntryKind::Secret, "pa ss/word"));
        for want in [
            "pa%20ss%2Fword",
            "pa%20ss%2fword",
            "pa+ss%2Fword",
            "%70%61%20%73%73%2F%77%6F%72%64",
            "%70%61%20%73%73%2f%77%6f%72%64",
            "70612073732f776f7264",
        ] {
            assert!(t.iter().any(|x| x == want), "missing {want}");
        }
    }

    #[test]
    fn xml_and_hex_forms_exist() {
        let t = texts(expand(EntryKind::Secret, "a<b&c'dd"));
        assert!(t.iter().any(|x| x == "a&lt;b&amp;c&apos;dd"));
        assert!(t.iter().any(|x| x == "613c622663276464"));
    }

    #[test]
    fn short_values_and_short_squeezed_needles_are_unscannable() {
        assert!(matches!(
            expand(EntryKind::Secret, "123456"),
            Expansion::Unscannable
        ));
        assert!(!matches!(
            expand(EntryKind::Secret, "1234567"),
            Expansion::Unscannable
        ));
        // Seven bytes, but the zero-width characters squeeze away.
        assert!(matches!(
            expand(EntryKind::Secret, "a\u{200B}b\u{200B}c"),
            Expansion::Unscannable
        ));
        assert!(matches!(
            expand(
                EntryKind::Secret,
                "\u{200B}\u{200B}\u{200B}\u{200B}\u{200B}\u{200B}\u{200B}"
            ),
            Expansion::Unscannable
        ));
    }
}
