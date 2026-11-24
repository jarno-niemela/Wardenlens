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
//!
//! This is the one display-name validator: the vault calls [`DisplayName::new`] for its
//! `display_name` entries, so a stored name always builds a camera (ADR 0006 section 1).
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

impl DisplayName {
    /// Validates `text` as a display name.
    ///
    /// # Errors
    /// [`CameraError`] naming the failed rule, never echoing `text`.
    pub fn new(text: &str) -> Result<Self, CameraError> {
        if text.is_empty() || text.len() > MAX_NAME_LEN {
            return Err(CameraError::NameLength);
        }
        let bad = text
            .chars()
            .any(|c| c.is_control() || is_invisible(c) || (c.is_whitespace() && c != ' '));
        if bad || text.starts_with(' ') || text.ends_with(' ') {
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
