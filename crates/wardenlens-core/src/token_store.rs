//! Port for API-token storage: plain data access, no hashing.
//!
//! The format, hashing and verification of tokens live in `wardenlens-api::token`
//! (ADR 0004 section 9). Implementations of [`TokenStore`] only look rows up.

use std::fmt;
use std::future::Future;

use crate::text::is_invisible;
use crate::time::UnixMs;

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

/// The most bytes in a [`TokenName`] (the schema's `CHECK`, ADR 0005 section 5).
pub const MAX_TOKEN_NAME_LEN: usize = 64;

/// The most token rows a store holds (rows are never deleted, so this bounds the table and a
/// listing, SEC-2).
pub const MAX_TOKENS: usize = 10_000;

/// A token name was not 1 to [`MAX_TOKEN_NAME_LEN`] bytes of visible text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvalidTokenName {
    /// Empty, or only white space.
    Empty,
    /// More than [`MAX_TOKEN_NAME_LEN`] bytes.
    TooLong,
    /// A control or invisible character (it could forge a line in a listing).
    ForbiddenCharacter,
}

impl fmt::Display for InvalidTokenName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("token name is empty"),
            Self::TooLong => write!(f, "token name is longer than {MAX_TOKEN_NAME_LEN} bytes"),
            Self::ForbiddenCharacter => {
                f.write_str("token name contains a control or invisible character")
            }
        }
    }
}

impl std::error::Error for InvalidTokenName {}

/// A human label for a token: 1 to [`MAX_TOKEN_NAME_LEN`] bytes, not only white space, no control
/// or invisible character. Not a secret and not unique.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenName(String);

impl TokenName {
    /// Validates `s`.
    ///
    /// # Errors
    /// [`InvalidTokenName`] with the rule that failed.
    pub fn new(s: &str) -> Result<Self, InvalidTokenName> {
        if s.len() > MAX_TOKEN_NAME_LEN {
            return Err(InvalidTokenName::TooLong);
        }
        if s.chars().any(|c| c.is_control() || is_invisible(c)) {
            return Err(InvalidTokenName::ForbiddenCharacter);
        }
        if s.trim().is_empty() {
            return Err(InvalidTokenName::Empty);
        }
        Ok(Self(s.to_owned()))
    }

    /// The name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A token to store: only what the store keeps (never the secret).
#[derive(Clone, PartialEq, Eq)]
pub struct NewToken {
    /// The public id; unique over the life of the store, revoked ids included.
    pub id: TokenId,
    /// SHA-256 of the decoded secret.
    pub digest: [u8; 32],
    /// The label.
    pub name: TokenName,
    /// When the token was created.
    pub created_at: UnixMs,
}

impl fmt::Debug for NewToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NewToken")
            .field("id", &self.id)
            .field("digest", &"<redacted>")
            .field("name", &self.name)
            .field("created_at", &self.created_at)
            .finish()
    }
}

/// What a listing shows of one token. No digest, no secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenSummary {
    /// The public id.
    pub id: TokenId,
    /// The label.
    pub name: TokenName,
    /// When the token was created.
    pub created_at: UnixMs,
    /// When it last authenticated (written at most once a minute), or `None` if never.
    pub last_used_at: Option<UnixMs>,
    /// Whether the token was revoked.
    pub revoked: bool,
}

/// Why [`TokenStore::insert`] failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InsertError {
    /// A row with this id exists (revoked or not); nothing was written. The caller generates
    /// another token.
    IdTaken,
    /// The store holds [`MAX_TOKENS`] rows; nothing was written.
    Full,
    /// The store failed.
    Store(TokenStoreError),
}

impl fmt::Display for InsertError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IdTaken => f.write_str("a token with this id already exists"),
            Self::Full => write!(f, "the token store holds {MAX_TOKENS} tokens"),
            Self::Store(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for InsertError {}

/// What [`TokenStore::revoke`] found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevokeOutcome {
    /// The token was active and is now revoked.
    Revoked,
    /// The token was already revoked; nothing changed.
    AlreadyRevoked,
    /// No token has this id; nothing changed.
    NotFound,
}

/// Verification lookup: plain data access to stored tokens, no hashing and no comparison (that
/// is `wardenlens-api::token`). This is all the API's authentication needs; token management and
/// bookkeeping are [`TokenAdmin`].
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

/// Token management and bookkeeping (the CLI, and the API's `last_used` update): plain data
/// access, no hashing. Rows are never deleted. Split from [`TokenStore`] so the verifier depends
/// on lookup only (interface segregation); an index implements both.
pub trait TokenAdmin {
    /// Stores a new token, active, never used.
    ///
    /// # Errors
    /// [`InsertError::IdTaken`] if the id exists (revoked ids are never reused),
    /// [`InsertError::Full`], [`InsertError::Store`].
    fn insert(&self, token: &NewToken) -> impl Future<Output = Result<(), InsertError>> + Send;

    /// Every token, oldest first (at most [`MAX_TOKENS`]).
    ///
    /// # Errors
    /// Returns [`TokenStoreError`] when the backing store fails.
    fn list(&self) -> impl Future<Output = Result<Vec<TokenSummary>, TokenStoreError>> + Send;

    /// Marks the token revoked. The row stays.
    ///
    /// # Errors
    /// Returns [`TokenStoreError`] when the backing store fails.
    fn revoke(
        &self,
        id: &TokenId,
    ) -> impl Future<Output = Result<RevokeOutcome, TokenStoreError>> + Send;

    /// Records that the token was used at `now`, at most once a minute per token: the store
    /// writes only when the stored value is empty or at least a minute older than `now`.
    /// Returns whether it wrote. An unknown id writes nothing.
    ///
    /// # Errors
    /// Returns [`TokenStoreError`] when the backing store fails.
    fn touch_last_used(
        &self,
        id: &TokenId,
        now: UnixMs,
    ) -> impl Future<Output = Result<bool, TokenStoreError>> + Send;
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
    fn token_name_accepts_and_refuses_by_rule() {
        let long_ok = "a".repeat(MAX_TOKEN_NAME_LEN);
        let long_bad = "a".repeat(MAX_TOKEN_NAME_LEN + 1);
        // 21 three-byte characters are 63 bytes; 22 are 66: the limit is bytes, not characters.
        let wide_ok = "\u{20AC}".repeat(21);
        let wide_bad = "\u{20AC}".repeat(22);
        for (name, want) in [
            ("grafana", Ok(())),
            ("a", Ok(())),
            (long_ok.as_str(), Ok(())),
            (wide_ok.as_str(), Ok(())),
            ("", Err(InvalidTokenName::Empty)),
            ("   ", Err(InvalidTokenName::Empty)),
            ("\u{a0}", Err(InvalidTokenName::Empty)),
            (long_bad.as_str(), Err(InvalidTokenName::TooLong)),
            (wide_bad.as_str(), Err(InvalidTokenName::TooLong)),
            ("a\nb", Err(InvalidTokenName::ForbiddenCharacter)),
            ("a\tb", Err(InvalidTokenName::ForbiddenCharacter)),
            ("a\u{1b}[0m", Err(InvalidTokenName::ForbiddenCharacter)),
            ("a\u{7f}", Err(InvalidTokenName::ForbiddenCharacter)),
            ("a\u{202e}b", Err(InvalidTokenName::ForbiddenCharacter)),
            ("a\u{2028}b", Err(InvalidTokenName::ForbiddenCharacter)),
        ] {
            assert_eq!(TokenName::new(name).map(|_| ()), want, "{name:?}");
        }
    }

    #[test]
    fn new_token_debug_redacts_digest() {
        let t = NewToken {
            id: TokenId::from_random([1; TOKEN_ID_LEN]),
            digest: [211; 32],
            name: TokenName::new("x").unwrap(),
            created_at: UnixMs::new(1_700_000_000_000).unwrap(),
        };
        let dbg = format!("{t:?}");
        assert!(dbg.contains("redacted") && !dbg.contains("211"));
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
