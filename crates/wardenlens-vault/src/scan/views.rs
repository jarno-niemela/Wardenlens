//! The views of a text (ADR 0006 section 7): raw, squeezed, decoded, JSON-unescaped and joined.
//!
//! A [`View`] knows the line number of every byte offset. Lines are split on `\n` only (the
//! convention of `grep` and `git`), and no view ever gains or loses a `\n`.

use std::borrow::Cow;

use super::squeeze::is_collapsible;

/// Bytes of one view and the offsets at which the line number increases.
pub(super) struct View<'a> {
    pub(super) bytes: Cow<'a, [u8]>,
    /// Offsets of line breaks, ascending. A joined view may hold one offset several times.
    marks: Vec<u32>,
}

fn offset(i: usize) -> u32 {
    // Views are bounded by the input cap (8 MiB, at most 3 times that after lossy decoding).
    u32::try_from(i).unwrap_or(u32::MAX)
}

impl<'a> View<'a> {
    /// A view over `bytes`; each `\n` is a line break.
    pub(super) fn new(bytes: Cow<'a, [u8]>) -> Self {
        let marks = bytes
            .iter()
            .enumerate()
            .filter(|&(_, &b)| b == b'\n')
            .map(|(i, _)| offset(i))
            .collect();
        Self { bytes, marks }
    }

    /// The 1-based line of the byte at `at`.
    pub(super) fn line_at(&self, at: usize) -> u32 {
        let before = self
            .marks
            .partition_point(|&m| usize::try_from(m).is_ok_and(|m| m < at));
        offset(before).saturating_add(1)
    }
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => b.checked_sub(b'0'),
        b'a'..=b'f' => b.checked_sub(b'a').map(|v| v.saturating_add(10)),
        b'A'..=b'F' => b.checked_sub(b'A').map(|v| v.saturating_add(10)),
        _ => None,
    }
}

fn hex_pair(bytes: &[u8], at: usize) -> Option<u8> {
    let hi = hex_val(*bytes.get(at)?)?;
    let lo = hex_val(*bytes.get(at.checked_add(1)?)?)?;
    Some(hi.wrapping_mul(16).wrapping_add(lo))
}

/// The length of the escape text at `at` if it spells U+0085, U+2028 or U+2029 in UTF-8
/// (`%C2%85`, `%E2%80%A8`, `%E2%80%A9`, any case): those are never decoded.
fn escaped_line_break(b: &[u8], at: usize) -> Option<usize> {
    let byte = |k: usize| hex_pair(b, at.saturating_add(k.saturating_mul(3)).saturating_add(1));
    let pct = |k: usize| b.get(at.saturating_add(k.saturating_mul(3))) == Some(&b'%');
    if pct(0) && pct(1) && byte(0) == Some(0xC2) && byte(1) == Some(0x85) {
        return Some(6);
    }
    (pct(0)
        && pct(1)
        && pct(2)
        && byte(0) == Some(0xE2)
        && byte(1) == Some(0x80)
        && matches!(byte(2), Some(0xA8 | 0xA9)))
    .then_some(9)
}

/// `%XX` decoded once; the decoded bytes are re-decoded as UTF-8, lossy. Invalid sequences are
/// left as they are. Nothing that would add a line break is decoded: `%0A` and `%0D` (any
/// case) and the escapes of U+0085, U+2028 and U+2029 stay as text.
pub(super) fn percent_decoded(squeezed: &str) -> String {
    let b = squeezed.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while let Some(&c) = b.get(i) {
        if c == b'%'
            && let Some(len) = escaped_line_break(b, i)
        {
            let end = i.saturating_add(len);
            out.extend_from_slice(b.get(i..end).unwrap_or_default());
            i = end;
        } else if c == b'%'
            && let Some(v) = hex_pair(b, i.saturating_add(1))
            && v != b'\n'
            && v != b'\r'
        {
            out.push(v);
            i = i.saturating_add(3);
        } else {
            out.push(c);
            i = i.saturating_add(1);
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// A `\uXXXX` escape at `at` (pointing at the backslash): its code unit.
fn unicode_escape(b: &[u8], at: usize) -> Option<u32> {
    if b.get(at) != Some(&b'\\') || b.get(at.saturating_add(1)) != Some(&b'u') {
        return None;
    }
    let mut v = 0u32;
    for k in 2..6 {
        let d = hex_val(*b.get(at.saturating_add(k))?)?;
        v = v.wrapping_mul(16).wrapping_add(u32::from(d));
    }
    Some(v)
}

/// Escapes that would add a line break are never decoded.
fn is_line_break(code: u32) -> bool {
    matches!(code, 0x0A | 0x0D | 0x85 | 0x2028 | 0x2029)
}

/// The decoded character and the length of the escape text it came from, if the escape at
/// `at` is decoded. A lone surrogate and the line-break escapes are left alone.
fn decode_escape(b: &[u8], at: usize) -> Option<(char, usize)> {
    match *b.get(at.saturating_add(1))? {
        b'"' => Some(('"', 2)),
        b'\\' => Some(('\\', 2)),
        b'/' => Some(('/', 2)),
        // White space and a control character: none adds a line break.
        b't' => Some(('\t', 2)),
        b'f' => Some(('\u{000C}', 2)),
        b'b' => Some(('\u{0008}', 2)),
        b'u' => {
            let code = unicode_escape(b, at)?;
            if is_line_break(code) {
                return None;
            }
            if (0xD800..0xDC00).contains(&code) {
                let low = unicode_escape(b, at.saturating_add(6))?;
                if !(0xDC00..0xE000).contains(&low) {
                    return None;
                }
                let high_part = code.saturating_sub(0xD800) << 10;
                let c = 0x10000u32
                    .saturating_add(high_part)
                    .saturating_add(low.saturating_sub(0xDC00));
                return char::from_u32(c).map(|c| (c, 12));
            }
            char::from_u32(code).map(|c| (c, 6))
        }
        _ => None,
    }
}

/// JSON string escapes decoded once: `\uXXXX` (with surrogate pairs), `\"`, `\\`, `\/`, `\t`, `\f` and `\b`. `\n` and `\r`
/// stay as text, like the other line-break escapes (they would move line numbers).
pub(super) fn json_unescaped(squeezed: &str) -> String {
    let b = squeezed.as_bytes();
    let mut out = String::with_capacity(b.len());
    let mut start = 0;
    let mut i = 0;
    while let Some(&c) = b.get(i) {
        if c == b'\\'
            && let Some((decoded, len)) = decode_escape(b, i)
        {
            out.push_str(squeezed.get(start..i).unwrap_or_default());
            out.push(decoded);
            i = i.saturating_add(len);
            start = i;
        } else {
            i = i.saturating_add(1);
        }
    }
    out.push_str(squeezed.get(start..).unwrap_or_default());
    out
}

/// The joined view, already folded: every run of whitespace (`is_collapsible`, the set the needle
/// collapse uses) becomes one space and the text is lowercased. A name wrapped across lines or indented is found; a hit is
/// reported at the line where it starts.
pub(super) fn joined_folded(squeezed: &str) -> View<'static> {
    let mut out = String::with_capacity(squeezed.len());
    let mut marks = Vec::new();
    let mut in_run = false;
    for c in squeezed.chars() {
        if is_collapsible(c) {
            if !in_run {
                in_run = true;
                out.push(' ');
            }
            if c == '\n' {
                // The space just written sits at the end of `out` minus its one byte.
                marks.push(offset(out.len().saturating_sub(1)));
            }
        } else {
            in_run = false;
            out.extend(c.to_lowercase());
        }
    }
    View {
        bytes: Cow::Owned(out.into_bytes()),
        marks,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percent_decoding_skips_line_breaks_and_bad_sequences() {
        assert_eq!(percent_decoded("a%20b%2Fc"), "a b/c");
        assert_eq!(percent_decoded("a%0Ab%0db%0a"), "a%0Ab%0db%0a");
        assert_eq!(percent_decoded("%zz%2"), "%zz%2");
        assert_eq!(percent_decoded("%E2%80%93"), "\u{2013}");
        assert_eq!(percent_decoded("%FF"), "\u{FFFD}");
        assert_eq!(
            percent_decoded("a%C2%85b%e2%80%a8c%E2%80%A9d%C2%A0"),
            "a%C2%85b%e2%80%a8c%E2%80%A9d\u{A0}"
        );
        // decoded once only
        assert_eq!(percent_decoded("%2541"), "%41");
    }

    /// A JSON `\\uXXXX` escape as literal text (built here so no editor or tool turns it into
    /// the character it spells).
    macro_rules! esc {
        ($hex:literal) => {
            concat!("\\u", $hex)
        };
    }

    #[test]
    fn json_unescaping_decodes_once_and_never_adds_a_break() {
        assert_eq!(json_unescaped(r#"pa\"ss\\w\/d"#), r#"pa"ss\w/d"#);
        assert_eq!(
            json_unescaped(concat!(esc!("0026"), esc!("0027"), esc!("2013"))),
            "&'\u{2013}"
        );
        assert_eq!(
            json_unescaped(concat!(esc!("D83D"), esc!("DE00"))),
            "\u{1F600}"
        );
        let lone = concat!(esc!("D83D"), " x");
        assert_eq!(json_unescaped(lone), lone);
        assert_eq!(
            json_unescaped(concat!(esc!("D83D"), esc!("0041"))),
            concat!(esc!("D83D"), "A")
        );
        for kept in [
            esc!("000a"),
            esc!("000A"),
            esc!("000d"),
            esc!("0085"),
            esc!("2028"),
            esc!("2029"),
            "\\n",
            "\\r",
        ] {
            assert_eq!(json_unescaped(kept), kept);
        }
        assert_eq!(json_unescaped(r"a\tb\fc\bd"), "a\tb\u{C}c\u{8}d");
        assert_eq!(
            json_unescaped(concat!("\\", esc!("0041"))),
            concat!("\\", "u0041")
        );
        assert_eq!(json_unescaped(concat!("\\u", "00")), concat!("\\u", "00"));
    }

    #[test]
    fn joined_view_collapses_wrapping_and_tracks_lines() {
        let v = joined_folded("Back Door\n    North\nx");
        assert_eq!(v.bytes.as_ref(), b"back door north x");
        assert_eq!(v.line_at(0), 1);
        assert_eq!(v.line_at(10), 2);
        assert_eq!(v.line_at(16), 3);
    }

    /// The needle collapse and the joined view collapse exactly the same characters, for every
    /// scalar value, and neither adds a line break (only `\n` is one).
    #[test]
    fn needle_collapse_and_joined_view_use_one_whitespace_set() {
        use super::super::needles::collapse;
        for n in 0..=0x0010_FFFFu32 {
            let Some(c) = char::from_u32(n) else { continue };
            let text = format!("a{c}b");
            let joined = joined_folded(&text);
            let by_view = joined.bytes.as_ref() == b"a b";
            let by_needle = collapse(&text).as_str() == "a b";
            assert_eq!(by_view, by_needle, "U+{n:04X}");
            assert_eq!(by_view, is_collapsible(c), "U+{n:04X}");
            if c != '\n' {
                assert_eq!(joined.line_at(usize::MAX), 1, "U+{n:04X} adds a line break");
            }
        }
        assert_eq!(collapse("  a \u{2028}\u{202F}b\n c  ").as_str(), "a b c");
    }

    #[test]
    fn line_numbers_count_newlines_before_the_offset() {
        let v = View::new(Cow::Borrowed(b"a\nbb\n\nc"));
        assert_eq!(v.line_at(0), 1);
        assert_eq!(v.line_at(1), 1);
        assert_eq!(v.line_at(2), 2);
        assert_eq!(v.line_at(5), 3);
        assert_eq!(v.line_at(6), 4);
    }
}
