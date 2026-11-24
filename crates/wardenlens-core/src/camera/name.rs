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
//! | no alphanumeric character, a leading combining mark, a private-use or noncharacter code point, U+2800 or U+FFFC (renders blank or as a box) | `NameCharset` |
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

/// Combining marks (`Mn`, `Mc`, `Me`), by the main blocks: a name may not start with one.
fn is_combining_mark(c: char) -> bool {
    matches!(
        u32::from(c),
        0x0300..=0x036F
            | 0x0483..=0x0489
            | 0x0591..=0x05BD
            | 0x0610..=0x061A
            | 0x064B..=0x065F
            | 0x0900..=0x0903
            | 0x093A..=0x094F
            | 0x1AB0..=0x1AFF
            | 0x1DC0..=0x1DFF
            | 0x20D0..=0x20FF
            | 0x302A..=0x302F
            | 0x3099..=0x309A
            | 0xFE20..=0xFE2F
    )
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
            || !text.chars().any(char::is_alphanumeric)
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
