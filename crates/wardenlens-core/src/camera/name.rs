//! [`DisplayName`]: the human label of a camera, with redacting `Debug` and `Display` (ADR 0006).
//!
//! | input | result |
//! |---|---|
//! | 1 to 128 bytes of printable text, Unicode letters allowed, inner U+0020 allowed | accepted |
//! | empty, or over 128 bytes | `NameLength` |
//! | leading or trailing space | `NameCharset` |
//! | control chars (NUL, tab, newline, DEL, C1) | `NameCharset` |
//! | whitespace other than U+0020 (NBSP, U+2003, U+3000, U+2028) | `NameCharset` |
//! | any Unicode `Cf` char, bidi control (incl. U+061C), soft hyphen, variation selector or invisible filler (`crate::text::is_invisible`, the vault scanner's predicate) | `NameCharset` |
//! | no alphanumeric character, a leading combining mark (in the blocks `is_combining_mark` lists, not every Unicode combining mark), no alphanumeric character other than combining marks, a private-use or noncharacter code point, U+2800 or U+FFFC (renders blank or as a box) | `NameCharset` |
//!
//! This is the one display-name validator: the vault normalises whitespace and invisible
//! characters and then calls [`DisplayName::new`] for its `display_name` entries, so a name set
//! by this version always builds a camera (ADR 0006 section 1). A value stored by an older
//! version may not; the future camera loader must report such a value by its id, not build it.
use std::fmt;
use std::str::FromStr;

use super::CameraError;
use crate::text::is_invisible;

/// Longest display name in bytes.
pub const MAX_NAME_LEN: usize = 128;

/// The text printed by `Debug` and `Display`.
pub(crate) const REDACTED_NAME: &str = "<redacted-name>";

/// A validated camera display name. `Debug` and `Display` print `<redacted-name>`; use
/// [`DisplayName::expose`] at the last moment.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct DisplayName(String);

/// Code points that render as nothing or as a placeholder box: private use, noncharacters,
/// U+2800 (braille blank) and U+FFFC (object replacement).
fn is_blank_glyph(c: char) -> bool {
    let n = u32::from(c);
    matches!(n, 0x2800 | 0xFFFC | 0xE000..=0xF8FF | 0xF0000..=0xFFFFD | 0x0010_0000..=0x0010_FFFD | 0xFDD0..=0xFDEF)
        || (n & 0xFFFE) == 0xFFFE
}

/// Combining marks (`Mn`, `Mc`, `Me`) in the blocks listed here: Combining Diacritical Marks,
/// Cyrillic, Hebrew, Arabic, Syriac, Thaana, `NKo`, Samaritan, Mandaic, Devanagari and the Indic
/// blocks, Thai, Lao, Tibetan, Myanmar, Khmer, the extended and supplement diacritics, symbols,
/// CJK and half marks. Not every Unicode combining mark is covered, only the marks in these
/// blocks. The ranges leave out the letters (`Lm`, `Lo`) that sit between marks in those blocks
/// (U+081A, U+0824, U+0828, U+093D, U+09BD, U+0ABD, U+0B3D), so such a letter is an ordinary
/// character. A code point inside a range that Unicode 16 has not assigned is treated as a mark.
const COMBINING_RANGES: [(u32, u32); 99] = [
    (0x0300, 0x036F),
    (0x0483, 0x0489),
    (0x0591, 0x05BD),
    (0x05BF, 0x05BF),
    (0x05C1, 0x05C2),
    (0x05C4, 0x05C5),
    (0x05C7, 0x05C7),
    (0x0610, 0x061A),
    (0x064B, 0x065F),
    (0x0670, 0x0670),
    (0x06D6, 0x06DC),
    (0x06DF, 0x06E4),
    (0x06E7, 0x06E8),
    (0x06EA, 0x06ED),
    (0x0711, 0x0711),
    (0x0730, 0x074A),
    (0x07A6, 0x07B0),
    (0x07EB, 0x07F3),
    (0x0816, 0x0819),
    (0x081B, 0x0823),
    (0x0825, 0x0827),
    (0x0829, 0x082D),
    (0x0859, 0x085B),
    (0x08D3, 0x08E1),
    (0x08E3, 0x0903),
    (0x093A, 0x093C),
    (0x093E, 0x094F),
    (0x0951, 0x0957),
    (0x0962, 0x0963),
    (0x0981, 0x0983),
    (0x09BC, 0x09BC),
    (0x09BE, 0x09CD),
    (0x09D7, 0x09D7),
    (0x09E2, 0x09E3),
    (0x0A01, 0x0A03),
    (0x0A3C, 0x0A51),
    (0x0A70, 0x0A71),
    (0x0A75, 0x0A75),
    (0x0A81, 0x0A83),
    (0x0ABC, 0x0ABC),
    (0x0ABE, 0x0ACD),
    (0x0AE2, 0x0AE3),
    (0x0B01, 0x0B03),
    (0x0B3C, 0x0B3C),
    (0x0B3E, 0x0B57),
    (0x0B62, 0x0B63),
    (0x0B82, 0x0B82),
    (0x0BBE, 0x0BCD),
    (0x0BD7, 0x0BD7),
    (0x0C00, 0x0C04),
    (0x0C3E, 0x0C56),
    (0x0C62, 0x0C63),
    (0x0C81, 0x0C83),
    (0x0CBC, 0x0CBC),
    (0x0CBE, 0x0CD6),
    (0x0CE2, 0x0CE3),
    (0x0D00, 0x0D03),
    (0x0D3B, 0x0D3C),
    (0x0D3E, 0x0D4D),
    (0x0D57, 0x0D57),
    (0x0D62, 0x0D63),
    (0x0D81, 0x0D83),
    (0x0DCA, 0x0DDF),
    (0x0DF2, 0x0DF3),
    (0x0E31, 0x0E31),
    (0x0E34, 0x0E3A),
    (0x0E47, 0x0E4E),
    (0x0EB1, 0x0EB1),
    (0x0EB4, 0x0EBC),
    (0x0EC8, 0x0ECE),
    (0x0F18, 0x0F19),
    (0x0F35, 0x0F35),
    (0x0F37, 0x0F37),
    (0x0F39, 0x0F39),
    (0x0F3E, 0x0F3F),
    (0x0F71, 0x0F84),
    (0x0F86, 0x0F87),
    (0x0F8D, 0x0FBC),
    (0x102B, 0x103E),
    (0x1056, 0x1059),
    (0x105E, 0x1060),
    (0x1062, 0x1064),
    (0x1067, 0x106D),
    (0x1071, 0x1074),
    (0x1082, 0x108D),
    (0x108F, 0x108F),
    (0x109A, 0x109D),
    (0x135D, 0x135F),
    (0x1712, 0x1715),
    (0x17B6, 0x17D3),
    (0x17DD, 0x17DD),
    (0x180B, 0x180D),
    (0x1AB0, 0x1AFF),
    (0x1DC0, 0x1DFF),
    (0x20D0, 0x20FF),
    (0x302A, 0x302F),
    (0x3099, 0x309A),
    (0xFB1E, 0xFB1E),
    (0xFE20, 0xFE2F),
];

/// True for a combining mark in the blocks of `COMBINING_RANGES` (not every Unicode mark).
#[must_use]
pub fn is_combining_mark(c: char) -> bool {
    let n = u32::from(c);
    COMBINING_RANGES
        .iter()
        .any(|&(lo, hi)| (lo..=hi).contains(&n))
}

impl DisplayName {
    /// Validates `text` as a display name.
    ///
    /// # Errors
    /// [`CameraError`] naming the failed rule, never echoing `text`.
    pub fn new(text: &str) -> Result<Self, CameraError> {
        if text.is_empty() || text.len() > MAX_NAME_LEN {
            return Err(CameraError::NameLength);
        }
        let bad = text.chars().any(|c| {
            c.is_control()
                || is_invisible(c)
                || (c.is_whitespace() && c != ' ')
                || is_blank_glyph(c)
        });
        let leading_mark = text.chars().next().is_some_and(is_combining_mark);
        if bad
            || leading_mark
            || !text
                .chars()
                .any(|c| c.is_alphanumeric() && !is_combining_mark(c))
            || text.starts_with(' ')
            || text.ends_with(' ')
        {
            return Err(CameraError::NameCharset);
        }
        Ok(Self(text.to_owned()))
    }

    /// The name text. Sensitive: call at the last moment.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for DisplayName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED_NAME)
    }
}

impl fmt::Display for DisplayName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED_NAME)
    }
}

impl FromStr for DisplayName {
    type Err = CameraError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_ordinary_names() {
        for n in [
            "Back Door North",
            "a",
            "Garage \u{2013} Side",
            "\u{4e2d}\u{6587}",
            "caf\u{e9}",
            &"a".repeat(128),
        ] {
            assert_eq!(DisplayName::new(n).unwrap().expose(), n);
        }
    }

    #[test]
    fn rejects_names_that_render_blank() {
        for n in [
            "\u{2800}",
            "\u{2800}\u{2800}",
            "\u{301}",
            "\u{301}abc",
            "\u{FFFC}",
            "\u{E000}",
            "a\u{E000}b",
            "\u{FFFF}",
            "\u{1FFFE}",
            "\u{FDD0}",
            "---",
            "(?)",
            "\u{F0000}x",
        ] {
            assert_eq!(DisplayName::new(n), Err(CameraError::NameCharset), "{n:?}");
        }
        for n in ["a\u{301}", "1", "\u{4e2d}", "Cam #1", "\u{e9}-"] {
            assert!(DisplayName::new(n).is_ok(), "{n:?}");
        }
    }

    /// The letters (`Lm`, `Lo`) that sit between marks in the listed blocks are accepted, alone,
    /// first and as the only content; their neighbouring marks still are not.
    #[test]
    fn letters_between_marks_are_ordinary_characters() {
        for c in [
            '\u{081A}', '\u{0824}', '\u{0828}', '\u{093D}', '\u{09BD}', '\u{0ABD}', '\u{0B3D}',
        ] {
            assert!(c.is_alphanumeric(), "U+{:04X}", u32::from(c));
            assert!(!is_combining_mark(c), "U+{:04X}", u32::from(c));
            assert!(
                DisplayName::new(&c.to_string()).is_ok(),
                "U+{:04X}",
                u32::from(c)
            );
            assert!(
                DisplayName::new(&format!("{c}x")).is_ok(),
                "U+{:04X}",
                u32::from(c)
            );
        }
        for c in [
            '\u{0819}', '\u{081B}', '\u{093C}', '\u{093E}', '\u{09BC}', '\u{09BE}',
        ] {
            assert!(is_combining_mark(c), "U+{:04X}", u32::from(c));
        }
    }

    #[test]
    fn combining_marks_in_the_listed_blocks_are_not_alphanumeric_content() {
        for n in [
            "\u{0E31}",
            "\u{05C1}",
            "\u{0670}",
            "\u{0E31} \u{0981}",
            "\u{0F71}abc",
        ] {
            assert_eq!(DisplayName::new(n), Err(CameraError::NameCharset), "{n:?}");
        }
        assert!(DisplayName::new("\u{0E01}\u{0E31}").is_ok());
    }

    #[test]
    fn rejects_length() {
        assert_eq!(DisplayName::new(""), Err(CameraError::NameLength));
        assert_eq!(
            DisplayName::new(&"a".repeat(129)),
            Err(CameraError::NameLength)
        );
    }

    #[test]
    fn rejects_bad_characters() {
        for n in [
            " a",
            "a ",
            " ",
            "a\tb",
            "a\nb",
            "a\rb",
            "a\0b",
            "a\x7fb",
            "a\u{85}b",
            "a\u{a0}b",
            "a\u{2003}b",
            "a\u{3000}b",
            "a\u{2028}b",
            "a\u{ad}b",
            "a\u{200b}b",
            "a\u{200e}b",
            "a\u{202e}b",
            "a\u{2060}b",
            "a\u{2066}b",
            "a\u{feff}b",
            "a\u{61c}b",
            "a\u{2067}b",
            "a\u{2068}b",
            "a\u{34f}b",
            "a\u{115f}b",
            "a\u{3164}b",
            "a\u{ffa0}b",
            "a\u{fe0f}b",
            "a\u{e0020}b",
            "a\u{600}b",
        ] {
            assert_eq!(DisplayName::new(n), Err(CameraError::NameCharset), "{n:?}");
        }
    }

    #[test]
    fn debug_and_display_are_redacted_everywhere() {
        let n = DisplayName::new("Back Door North").unwrap();
        for shown in [
            format!("{n}"),
            format!("{n:?}"),
            format!("{n:#?}"),
            format!("{:?}", Some(&n)),
        ] {
            assert!(
                !shown.contains("Back") && !shown.contains("Door"),
                "{shown}"
            );
            assert!(shown.contains("redacted"));
        }
        let msg = DisplayName::new(" Back Door").unwrap_err().to_string();
        assert!(!msg.contains("Back"));
    }

    proptest::proptest! {
        #[test]
        fn never_panics_and_accepted_is_clean(s in "\\PC{0,140}") {
            if let Ok(n) = DisplayName::new(&s) {
                proptest::prop_assert!(n.expose().len() <= 128 && !n.expose().is_empty());
                proptest::prop_assert!(!n.expose().chars().any(|c| c.is_control() || is_invisible(c)));
                proptest::prop_assert!(!n.expose().starts_with(' ') && !n.expose().ends_with(' '));
            }
        }
    }
}
