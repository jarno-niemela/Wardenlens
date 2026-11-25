//! The ADR 0006 section 7 squeeze and the fold (full lowercase mapping). What the squeeze deletes
//! is `wardenlens_core::text::is_dropped_invisible`, the predicate the vault's display-name
//! normalisation uses too (one definition).
//!
//! Line breaks are never touched, so line numbers stay valid.

use std::borrow::Cow;

/// Appends `c` to `out` after the squeeze: invisible characters are deleted, the
/// fullwidth ASCII block and the listed lookalikes of `.`, `-` and space are mapped.
fn squeeze_char(c: char, out: &mut String) {
    if is_dropped_invisible(c) {
        return;
    }
    match u32::from(c) {
        // U+FF01..=U+FF5E is U+0021..=U+007E plus 0xFEE0.
        n @ 0xFF01..=0xFF5E => out.extend(char::from_u32(n.saturating_sub(0xFEE0))),
        0x3002 | 0xFF61 | 0x2024 => out.push('.'),
        0x2010..=0x2015 | 0x2212 => out.push('-'),
        0x00A0 | 0x2000..=0x200A | 0x3000 => out.push(' '),
        _ => out.push(c),
    }
}

use wardenlens_core::text::is_dropped_invisible;
pub use wardenlens_core::text::is_invisible;

/// True for a character that the joined view and the needle collapse both turn into a space
/// (a run of them is one space): Unicode `White_Space`. This is the one definition both use, so
/// a stored value and the same text in a file collapse alike. A line break among them is no
/// extra line break: lines are counted on `\n` only.
pub(super) fn is_collapsible(c: char) -> bool {
    c.is_whitespace()
}

/// The squeezed form of `text`.
pub(super) fn squeeze(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        squeeze_char(c, &mut out);
    }
    out
}

/// Decodes `bytes` as UTF-8 (each invalid sequence becomes U+FFFD), then squeezes. Never slices.
pub(super) fn squeeze_lossy(bytes: &[u8]) -> String {
    squeeze(&String::from_utf8_lossy(bytes))
}

/// The view lowercased with the full lowercase mapping (`char::to_lowercase`; a string can
/// change length). This is not Unicode case folding.
pub(super) fn fold(text: &str) -> String {
    text.chars().flat_map(char::to_lowercase).collect()
}

/// Lossy UTF-8 decoding of raw input, borrowed when it is already valid.
pub(super) fn lossy(bytes: &[u8]) -> Cow<'_, str> {
    String::from_utf8_lossy(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deletes_invisible_and_maps_lookalikes() {
        assert_eq!(squeeze("a\u{200B}b\u{00AD}c\u{FEFF}d"), "abcd");
        assert_eq!(squeeze("\u{FF11}\u{FF19}\u{FF12}\u{FF0E}x"), "192.x");
        assert_eq!(squeeze("a\u{3002}b\u{FF61}c\u{2024}d"), "a.b.c.d");
        assert_eq!(
            squeeze("a\u{2010}b\u{2013}c\u{2015}d\u{2212}e"),
            "a-b-c-d-e"
        );
        assert_eq!(squeeze("a\u{00A0}b\u{2003}c\u{3000}d"), "a b c d");
        assert_eq!(squeeze("a\nb\r\nc"), "a\nb\r\nc");
    }

    #[test]
    fn table_boundaries_are_exact() {
        // First and last of each range, and the neighbours just outside it.
        for (c, kept) in [
            ('\u{200A}', false),
            ('\u{200B}', false),
            ('\u{200F}', false),
            ('\u{2010}', false),
            ('\u{202A}', false),
            ('\u{202E}', false),
            ('\u{202F}', true),
            ('\u{2060}', false),
            ('\u{2064}', false),
            ('\u{2065}', false),
            ('\u{2066}', false),
            ('\u{2069}', false),
            ('\u{206A}', false),
            ('\u{2070}', true),
            // Not deleted: white space collapses instead.
            ('\u{2028}', true),
            ('\u{2029}', true),
        ] {
            let squeezed = squeeze(&c.to_string());
            assert_eq!(squeezed == c.to_string(), kept, "U+{:04X}", u32::from(c));
        }
        assert_eq!(squeeze("\u{FF01}"), "!");
        assert_eq!(squeeze("\u{FF5E}"), "~");
        assert_eq!(squeeze("\u{FF00}"), "\u{FF00}");
        assert_eq!(squeeze("\u{FF5F}"), "\u{FF5F}");
    }

    #[test]
    fn squeeze_deletes_exactly_the_dropped_invisible_characters() {
        for n in 0..=0x0010_FFFF_u32 {
            let Some(c) = char::from_u32(n) else { continue };
            assert_eq!(
                squeeze(&c.to_string()).is_empty(),
                is_dropped_invisible(c),
                "U+{n:04X}"
            );
        }
        for c in [
            '\u{FE0F}',
            '\u{034F}',
            '\u{180E}',
            '\u{3164}',
            '\u{FE00}',
            '\u{E0100}',
        ] {
            assert_eq!(squeeze(&format!("a{c}b")), "ab", "U+{:04X}", u32::from(c));
        }
    }

    #[test]
    fn everything_the_squeeze_table_deletes_is_invisible() {
        for n in 0..=0x0010_FFFF_u32 {
            let Some(c) = char::from_u32(n) else { continue };
            if squeeze(&c.to_string()).is_empty() {
                assert!(is_invisible(c), "U+{n:04X}");
            }
        }
    }

    #[test]
    fn lossy_never_slices_invalid_bytes() {
        assert_eq!(squeeze_lossy(b"a\xFFb"), "a\u{FFFD}b");
        assert_eq!(squeeze_lossy(b"\xE2\x80"), "\u{FFFD}");
    }

    #[test]
    fn fold_uses_the_full_lowercase_mapping() {
        assert_eq!(fold("GARAGE"), "garage");
        // U+0130 lowercases to two characters.
        assert_eq!(fold("\u{0130}"), "i\u{0307}");
    }
}
