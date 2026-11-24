//! Vault entry identity and kind (ADR 0006 section 1). Pure types: no crypto, no I/O.

use std::fmt;
use std::str::FromStr;

/// Longest entry id in bytes.
pub const MAX_ENTRY_ID_LEN: usize = 128;

/// The id prefix reserved for the store's own entries (`meta:keycheck`).
pub const RESERVED_ID_PREFIX: &str = "meta:";

/// Why an id or a kind name was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum EntryError {
    /// The id is empty.
    #[error("entry id is empty")]
    EmptyId,
    /// The id is longer than 128 bytes.
    #[error("entry id is longer than {MAX_ENTRY_ID_LEN} bytes")]
    IdTooLong,
    /// The id does not match `[a-z0-9][a-z0-9:_.-]*`.
    #[error("entry id has a character outside [a-z0-9:_.-] or does not start with [a-z0-9]")]
    IdCharset,
    /// The id uses the reserved `meta:` prefix.
    #[error("entry id uses the reserved prefix")]
    ReservedId,
    /// The kind name is not one of the seven kinds.
    #[error("unknown entry kind")]
    UnknownKind,
}

/// An opaque, non-sensitive entry reference such as `cam:reolink-1:host`.
///
/// Matches `[a-z0-9][a-z0-9:_.-]{0,127}` and never starts with `meta:`. An id must never be
/// derived from a value.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct EntryId(String);

impl EntryId {
    /// Validates `text` as an entry id.
    ///
    /// # Errors
    /// [`EntryError`] naming the rule that failed (never echoing `text`).
    pub fn new(text: &str) -> Result<Self, EntryError> {
        let bytes = text.as_bytes();
        let Some(first) = bytes.first() else {
            return Err(EntryError::EmptyId);
        };
        if bytes.len() > MAX_ENTRY_ID_LEN {
            return Err(EntryError::IdTooLong);
        }
        let first_ok = first.is_ascii_lowercase() || first.is_ascii_digit();
        let rest_ok = bytes.iter().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b':' | b'_' | b'.' | b'-')
        });
        if !first_ok || !rest_ok {
            return Err(EntryError::IdCharset);
        }
        if text.starts_with(RESERVED_ID_PREFIX) {
            return Err(EntryError::ReservedId);
        }
        Ok(Self(text.to_owned()))
    }

    /// The id text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for EntryId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for EntryId {
    type Err = EntryError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

/// What an entry holds. Codes are stable on disk and bound into the ciphertext; a new kind
/// takes a new code, never a reused one. Code 0 is reserved for the keycheck record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum EntryKind {
    /// A username and password pair (code 1).
    Credential,
    /// One opaque secret (code 2).
    Secret,
    /// A LAN address or hostname (code 3).
    Host,
    /// A MAC address (code 4).
    Mac,
    /// A device serial number (code 5).
    Serial,
    /// A camera or site display name (code 6).
    DisplayName,
    /// Any other sensitive text (code 7).
    Other,
}

impl EntryKind {
    /// Every kind, in code order.
    pub const ALL: [Self; 7] = [
        Self::Credential,
        Self::Secret,
        Self::Host,
        Self::Mac,
        Self::Serial,
        Self::DisplayName,
        Self::Other,
    ];

    /// The stable on-disk code (1 to 7).
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Credential => 1,
            Self::Secret => 2,
            Self::Host => 3,
            Self::Mac => 4,
            Self::Serial => 5,
            Self::DisplayName => 6,
            Self::Other => 7,
        }
    }

    /// The kind for a stored code; `None` for 0 (reserved) and unassigned codes.
    #[must_use]
    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::Credential),
            2 => Some(Self::Secret),
            3 => Some(Self::Host),
            4 => Some(Self::Mac),
            5 => Some(Self::Serial),
            6 => Some(Self::DisplayName),
            7 => Some(Self::Other),
            _ => None,
        }
    }

    /// The CLI name (`credential`, `display-name`, ...).
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Credential => "credential",
            Self::Secret => "secret",
            Self::Host => "host",
            Self::Mac => "mac",
            Self::Serial => "serial",
            Self::DisplayName => "display-name",
            Self::Other => "other",
        }
    }
}

impl fmt::Display for EntryKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl FromStr for EntryKind {
    type Err = EntryError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|k| k.name() == s)
            .ok_or(EntryError::UnknownKind)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_inventory_style_ids() {
        for id in [
            "cam:reolink-1:host",
            "0",
            "a",
            "cam:import-3:credential",
            "a.b_c-d:e",
        ] {
            assert_eq!(EntryId::new(id).unwrap().as_str(), id);
        }
    }

    #[test]
    fn rejects_empty_and_bad_first_char() {
        assert_eq!(EntryId::new(""), Err(EntryError::EmptyId));
        for id in [":a", "-a", ".a", "_a", "A", "Cam"] {
            assert_eq!(EntryId::new(id), Err(EntryError::IdCharset), "{id}");
        }
    }

    #[test]
    fn rejects_bad_characters() {
        for id in ["a b", "a/b", "a\n", "a\u{e9}", "a;b", "a\0"] {
            assert_eq!(EntryId::new(id), Err(EntryError::IdCharset), "{id:?}");
        }
    }

    #[test]
    fn id_length_limit_is_128() {
        assert!(EntryId::new(&"a".repeat(128)).is_ok());
        assert_eq!(EntryId::new(&"a".repeat(129)), Err(EntryError::IdTooLong));
    }

    #[test]
    fn reserved_prefix_is_refused() {
        assert_eq!(EntryId::new("meta:keycheck"), Err(EntryError::ReservedId));
        assert_eq!(EntryId::new("meta:"), Err(EntryError::ReservedId));
        assert!(EntryId::new("metadata:x").is_ok());
        assert!(EntryId::new("cam:meta:x").is_ok());
    }

    #[test]
    fn kind_codes_are_stable() {
        let codes: Vec<u8> = EntryKind::ALL.iter().map(|k| k.code()).collect();
        assert_eq!(codes, [1, 2, 3, 4, 5, 6, 7]);
        assert_eq!(EntryKind::from_code(0), None);
        assert_eq!(EntryKind::from_code(8), None);
        for k in EntryKind::ALL {
            assert_eq!(EntryKind::from_code(k.code()), Some(k));
        }
    }

    #[test]
    fn kind_names_round_trip() {
        for k in EntryKind::ALL {
            assert_eq!(k.name().parse::<EntryKind>(), Ok(k));
        }
        assert_eq!("Host".parse::<EntryKind>(), Err(EntryError::UnknownKind));
        assert_eq!(
            "display_name".parse::<EntryKind>(),
            Err(EntryError::UnknownKind)
        );
    }

    proptest::proptest! {
        #[test]
        fn entry_id_accepts_exactly_the_charset(s in "\\PC{0,140}") {
            let allowed = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b':' | b'_' | b'.' | b'-');
            let expected = !s.is_empty()
                && s.len() <= 128
                && (s.as_bytes()[0].is_ascii_lowercase() || s.as_bytes()[0].is_ascii_digit())
                && s.bytes().all(allowed)
                && !s.starts_with("meta:");
            proptest::prop_assert_eq!(EntryId::new(&s).is_ok(), expected);
        }

        #[test]
        fn entry_id_accepts_every_charset_string(s in "[a-z0-9][a-z0-9:_.-]{0,127}") {
            proptest::prop_assume!(!s.starts_with("meta:"));
            proptest::prop_assert!(EntryId::new(&s).is_ok());
        }
    }
}
