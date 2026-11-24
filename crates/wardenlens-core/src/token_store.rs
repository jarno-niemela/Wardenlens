//! Port for API-token storage: plain data access, no hashing.
//!
//! The format, hashing and verification of tokens live in `wardenlens-api::token`
//! (ADR 0004 section 9). Implementations of [`TokenStore`] only look rows up.

use std::fmt;
use std::future::Future;

/// Number of characters in a [`TokenId`].
pub const TOKEN_ID_LEN: usize = 8;

/// Public, random identifier of an API token (8 characters of `a-z2-7`).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct TokenId([u8; TOKEN_ID_LEN]);

/// A string was not a valid [`TokenId`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidTokenId;

impl fmt::Display for InvalidTokenId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("token id must be 8 characters of a-z2-7")
    }
}

impl std::error::Error for InvalidTokenId {}

impl TokenId {
    /// Parses an id, accepting exactly [`TOKEN_ID_LEN`] characters from `a-z2-7`.
    ///
    /// # Errors
    /// Returns [`InvalidTokenId`] for any other length or character.
    pub fn parse(s: &str) -> Result<Self, InvalidTokenId> {
        let bytes: [u8; TOKEN_ID_LEN] = s.as_bytes().try_into().map_err(|_| InvalidTokenId)?;
        if bytes.iter().all(|b| matches!(b, b'a'..=b'z' | b'2'..=b'7')) {
            Ok(Self(bytes))
        } else {
            Err(InvalidTokenId)
        }
    }

    /// Builds an id from random bytes; cannot fail. The low 5 bits of each byte pick a
    /// character of `a-z2-7`; 32 divides 256, so a uniform byte gives a uniform character.
    #[must_use]
    pub fn from_random(bytes: [u8; TOKEN_ID_LEN]) -> Self {
        const ALPHABET: [u8; 32] = *b"abcdefghijklmnopqrstuvwxyz234567";
        // `b & 31` is below 32, so the lookup is always in range; the fallback is unreachable.
        Self(bytes.map(|b| ALPHABET.get(usize::from(b & 31)).copied().unwrap_or(b'a')))
    }

    /// The id as a string slice (always ASCII).
    #[must_use]
    pub fn as_str(&self) -> &str {
        // Invariant: `parse` only admits ASCII bytes, so this cannot fail; the
        // fallback keeps the function total without a panic path.
        std::str::from_utf8(&self.0).unwrap_or_default()
    }
}

impl fmt::Display for TokenId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl fmt::Debug for TokenId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TokenId({})", self.as_str())
    }
}

/// What the store knows about one token. The digest is `sha256(secret bytes)`.
#[derive(Clone, PartialEq, Eq)]
pub struct TokenRecord {
    /// SHA-256 of the decoded token secret.
    pub digest: [u8; 32],
    /// Whether the token was revoked.
    pub revoked: bool,
}

impl fmt::Debug for TokenRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenRecord")
            .field("digest", &"<redacted>")
            .field("revoked", &self.revoked)
            .finish()
    }
}

/// The store failed; the cause is deliberately not carried to callers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TokenStoreError;

impl fmt::Display for TokenStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("token store unavailable")
    }
}

impl std::error::Error for TokenStoreError {}

/// Read access to stored tokens.
pub trait TokenStore {
    /// Looks a token up by id; `Ok(None)` when the id is unknown.
    ///
    /// # Errors
    /// Returns [`TokenStoreError`] when the backing store fails.
    fn find(
        &self,
        id: &TokenId,
    ) -> impl Future<Output = Result<Option<TokenRecord>, TokenStoreError>> + Send;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_valid_id() {
        assert_eq!(
            TokenId::parse("abcdefgh").map(|i| i.to_string()),
            Ok("abcdefgh".to_owned())
        );
        assert!(TokenId::parse("a2b7z3y6").is_ok());
    }

    #[test]
    fn rejects_wrong_length_and_alphabet() {
        for bad in [
            "",
            "abcdefg",
            "abcdefghi",
            "ABCDEFGH",
            "abcdefg1",
            "abcdefg8",
            "abcdef_h",
            "abcdéfg",
        ] {
            assert_eq!(TokenId::parse(bad), Err(InvalidTokenId), "{bad}");
        }
    }

    #[test]
    fn from_random_maps_every_byte_to_a_valid_id() {
        for b in 0..=255u8 {
            let id = TokenId::from_random([b; TOKEN_ID_LEN]);
            assert_eq!(TokenId::parse(id.as_str()), Ok(id), "byte {b}");
        }
        let id = TokenId::from_random([0, 1, 25, 26, 31, 32, 33, 255]);
        assert_eq!(id.as_str(), "abz27ab7");
    }

    #[test]
    fn record_debug_redacts_digest() {
        let r = TokenRecord {
            digest: [7; 32],
            revoked: false,
        };
        assert!(!format!("{r:?}").contains('7'));
    }
}
