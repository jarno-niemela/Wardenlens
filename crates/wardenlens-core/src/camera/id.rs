//! [`CameraId`]: the validated slug that names a camera and is a path component (ADR 0005, SEC-4).
//!
//! Accepted: `[a-z][a-z0-9-]{0,31}`.
//!
//! | input | result |
//! |---|---|
//! | `a`, `cam1`, `reolink-1`, 32 chars | accepted |
//! | `a-`, `a--b`, `a-1-` | accepted (the ADR charset allows `-` anywhere after the first char) |
//! | empty | `IdEmpty` |
//! | 33 or more bytes | `IdTooLong` |
//! | starts with a digit or `-` (also `_quarantine`-like names) | `IdCharset` |
//! | uppercase, `.`, `..`, `/`, `\`, `:`, `_`, NUL, any control char | `IdCharset` |
//! | space, tab, newline, Unicode spaces, anywhere | `IdCharset` |
//! | any non-ASCII char (Cyrillic look-alikes, fullwidth digits, combining marks) | `IdCharset` |
//!
//! Because the first byte is a lowercase letter and `.`/`/` are never allowed, no value is `.` or `..`
//! and none contains a separator.

use std::fmt;
use std::str::FromStr;

use super::CameraError;
use crate::entry::{EntryId, EntryKind};

/// Longest camera id in bytes.
pub const MAX_CAMERA_ID_LEN: usize = 32;

/// A validated camera id. Not sensitive: it appears in logs, paths and vault entry ids.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CameraId(String);

impl CameraId {
    /// Validates `text` as a camera id.
    ///
    /// # Errors
    /// [`CameraError`] naming the failed rule, never echoing `text`.
    pub fn new(text: &str) -> Result<Self, CameraError> {
        let bytes = text.as_bytes();
        let Some(first) = bytes.first() else {
            return Err(CameraError::IdEmpty);
        };
        if bytes.len() > MAX_CAMERA_ID_LEN {
            return Err(CameraError::IdTooLong);
        }
        if !first.is_ascii_lowercase()
            || !bytes
                .iter()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
        {
            return Err(CameraError::IdCharset);
        }
        Ok(Self(text.to_owned()))
    }

    /// The id text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The vault entry id for this camera's `kind` (`cam:<id>:host`, `cam:<id>:credential`,
    /// `cam:<id>:name`).
    ///
    /// # Errors
    /// [`CameraError::EntryKindNotOwned`] for a kind a camera does not own;
    /// [`CameraError::EntryId`] if the vault refuses the built id (it cannot today: at most
    /// `cam:` + 32 + `:credential` = 47 bytes of `[a-z0-9:-]`, and a test pins that).
    pub fn entry_id(&self, kind: EntryKind) -> Result<EntryId, CameraError> {
        let suffix = match kind {
            EntryKind::Credential => "credential",
            EntryKind::Host => "host",
            EntryKind::DisplayName => "name",
            _ => return Err(CameraError::EntryKindNotOwned),
        };
        EntryId::new(&format!("cam:{}:{suffix}", self.0)).map_err(|_| CameraError::EntryId)
    }
}

impl fmt::Display for CameraId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for CameraId {
    type Err = CameraError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_slugs() {
        for id in [
            "a",
            "cam1",
            "reolink-1",
            "a-",
            "a--b",
            "a-1-",
            &"a".repeat(32),
        ] {
            assert_eq!(CameraId::new(id).unwrap().as_str(), id);
        }
    }

    #[test]
    fn rejects_empty_and_long() {
        assert_eq!(CameraId::new(""), Err(CameraError::IdEmpty));
        assert_eq!(CameraId::new(&"a".repeat(33)), Err(CameraError::IdTooLong));
        assert_eq!(CameraId::new(&"a".repeat(200)), Err(CameraError::IdTooLong));
    }

    #[test]
    fn rejects_every_bad_form() {
        let bad = [
            "1a",
            "-a",
            "_a",
            "_quarantine",
            ".",
            "..",
            "a.b",
            "a/b",
            "/a",
            "a\\b",
            "a:b",
            "a_b",
            "A",
            "aB",
            "a\0",
            "\0",
            "a\n",
            "a\r",
            "a\t",
            "a\x1b",
            "a\x7f",
            "a\u{85}",
            " a",
            "a ",
            "a b",
            "a\u{a0}b",
            "a\u{2003}",
            "a\u{3000}",
            "a\u{200b}",
            "\u{430}bc",
            "a\u{ff11}",
            "\u{ff41}",
            "a\u{e9}",
            "a\u{301}",
            "a\u{202e}",
            "a\u{feff}",
            "a%2f",
            "a;",
            "a+",
            "a\u{1f600}",
        ];
        for id in bad {
            assert_eq!(CameraId::new(id), Err(CameraError::IdCharset), "{id:?}");
        }
    }

    #[test]
    fn error_never_echoes_input() {
        let msg = CameraId::new("Secret/Name").unwrap_err().to_string();
        assert!(!msg.contains("Secret") && !msg.contains("Name"));
    }

    #[test]
    fn entry_ids_follow_the_adr_naming() {
        let id = CameraId::new("reolink-1").unwrap();
        let name = |k| id.entry_id(k).map(|e| e.as_str().to_owned()).ok();
        assert_eq!(name(EntryKind::Host).as_deref(), Some("cam:reolink-1:host"));
        assert_eq!(
            name(EntryKind::Credential).as_deref(),
            Some("cam:reolink-1:credential")
        );
        assert_eq!(
            name(EntryKind::DisplayName).as_deref(),
            Some("cam:reolink-1:name")
        );
        assert_eq!(name(EntryKind::Mac), None);
        assert_eq!(
            id.entry_id(EntryKind::Mac),
            Err(CameraError::EntryKindNotOwned)
        );
    }

    #[test]
    fn entry_id_never_fails_for_an_owned_kind_at_the_longest_id() {
        let id = CameraId::new(&format!("a{}", "9".repeat(31))).unwrap();
        for k in [
            EntryKind::Credential,
            EntryKind::Host,
            EntryKind::DisplayName,
        ] {
            assert!(id.entry_id(k).is_ok(), "{k:?}");
        }
    }

    proptest::proptest! {
        #[test]
        fn round_trips(s in "[a-z][a-z0-9-]{0,31}") {
            let id: CameraId = s.parse().unwrap();
            proptest::prop_assert_eq!(id.to_string().parse::<CameraId>().unwrap(), id);
        }

        #[test]
        fn accepts_exactly_the_charset(s in "\\PC{0,40}") {
            let b = s.as_bytes();
            let expected = !b.is_empty()
                && b.len() <= 32
                && b[0].is_ascii_lowercase()
                && b.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-');
            let got = CameraId::new(&s);
            proptest::prop_assert_eq!(got.is_ok(), expected);
            if let Ok(id) = got {
                proptest::prop_assert!(id.as_str() != "." && id.as_str() != "..");
                proptest::prop_assert!(!id.as_str().contains(['/', '\\', '\0']));
            }
        }

        #[test]
        fn arbitrary_bytes_never_panic(s in ".*") {
            let _ = CameraId::new(&s);
        }
    }
}
