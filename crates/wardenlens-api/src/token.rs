//! The single token codec: generate, encode, parse, hash and verify (ADR 0004 section 9).
//!
//! A token is `wl_<id>_<secret>`: `<id>` is 8 characters of `a-z2-7` (public, see
//! [`TokenId`]) and `<secret>` is 32 CSPRNG bytes as 43 characters of canonical unpadded
//! base64url. The store keeps `sha256(secret bytes)`, never the secret.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;
use wardenlens_core::token_store::{TOKEN_ID_LEN, TokenId, TokenRecord};

/// Token prefix, so secret scanners and humans recognise it.
const PREFIX: &str = "wl";
/// Number of secret bytes (256 bits).
const SECRET_LEN: usize = 32;
/// Characters of the encoded secret: 32 bytes as unpadded base64url.
const ENCODED_SECRET_LEN: usize = 43;
/// Longest token (and so header value) the server will look at, in bytes (SEC-2).
pub const MAX_TOKEN_LEN: usize = 128;

/// Digest compared against when the id is unknown or revoked, so timing does not
/// reveal which ids exist. Never equals a real digest (a SHA-256 preimage is needed).
const DUMMY_DIGEST: [u8; 32] = [0xA5; 32];

/// A token string was not of the exact shape `wl_<id>_<secret>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("malformed token")]
pub struct MalformedToken;

/// Generating a token failed because the operating system CSPRNG was unavailable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("system random number generator unavailable")]
pub struct RandomUnavailable;

/// The 32 secret bytes of a token. `Debug` is redacted (SEC-6).
#[derive(Clone)]
pub struct Secret([u8; SECRET_LEN]);

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

impl Secret {
    /// `sha256(secret bytes)`, the value the token store keeps.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        Sha256::digest(self.0).into()
    }
}

/// A token split into its public id and its secret. Obtained from [`Token::parse`] or
/// [`Token::generate`]; `Debug` never shows the secret.
#[derive(Debug, Clone)]
pub struct Token {
    id: TokenId,
    secret: Secret,
}

impl Token {
    /// Creates a new token with a random id and secret from the OS CSPRNG.
    ///
    /// # Errors
    /// Returns [`RandomUnavailable`] if the OS random source fails.
    pub fn generate() -> Result<Self, RandomUnavailable> {
        let mut id_bytes = [0u8; TOKEN_ID_LEN];
        let mut secret = [0u8; SECRET_LEN];
        getrandom::fill(&mut id_bytes).map_err(|_| RandomUnavailable)?;
        getrandom::fill(&mut secret).map_err(|_| RandomUnavailable)?;
        let id = TokenId::from_random(id_bytes);
        Ok(Self {
            id,
            secret: Secret(secret),
        })
    }

    /// Parses `wl_<id>_<secret>`; anything not exactly that shape is rejected.
    ///
    /// # Errors
    /// Returns [`MalformedToken`] for a wrong prefix, id, secret length or alphabet,
    /// non-canonical base64, trailing data or an over-long input.
    pub fn parse(s: &str) -> Result<Self, MalformedToken> {
        if s.len() > MAX_TOKEN_LEN {
            return Err(MalformedToken);
        }
        // The base64url alphabet contains `_`, so split into exactly three parts.
        let mut parts = s.splitn(3, '_');
        let (Some(prefix), Some(id), Some(rest)) = (parts.next(), parts.next(), parts.next())
        else {
            return Err(MalformedToken);
        };
        if prefix != PREFIX || rest.len() != ENCODED_SECRET_LEN {
            return Err(MalformedToken);
        }
        let id = TokenId::parse(id).map_err(|_| MalformedToken)?;
        let decoded = URL_SAFE_NO_PAD.decode(rest).map_err(|_| MalformedToken)?;
        let secret: [u8; SECRET_LEN] = decoded.try_into().map_err(|_| MalformedToken)?;
        Ok(Self {
            id,
            secret: Secret(secret),
        })
    }

    /// The public id.
    #[must_use]
    pub fn id(&self) -> &TokenId {
        &self.id
    }

    /// The secret part.
    #[must_use]
    pub fn secret(&self) -> &Secret {
        &self.secret
    }

    /// The full `wl_<id>_<secret>` string. Show it to the operator once, never log it.
    #[must_use]
    pub fn expose(&self) -> String {
        format!(
            "{PREFIX}_{}_{}",
            self.id,
            URL_SAFE_NO_PAD.encode(self.secret.0)
        )
    }

    /// Checks this token against what the store returned for its id.
    ///
    /// The SHA-256 and the constant-time comparison run on every path: for an unknown
    /// id or a revoked token the digest is compared against a fixed dummy and the
    /// result is discarded, so response time does not reveal which ids exist.
    #[must_use]
    pub fn verify(&self, record: Option<&TokenRecord>) -> bool {
        let presented = self.secret.digest();
        let (stored, usable) = match record {
            Some(r) if !r.revoked => (r.digest, true),
            _ => (DUMMY_DIGEST, false),
        };
        let equal: bool = presented.ct_eq(&stored).into();
        equal & usable
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET_43: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    fn tok(id: &str, rest: &str) -> String {
        format!("wl_{id}_{rest}")
    }

    #[test]
    fn generated_token_round_trips() {
        let t = Token::generate().unwrap();
        let s = t.expose();
        assert_eq!(s.len(), 3 + 8 + 1 + 43);
        let back = Token::parse(&s).unwrap();
        assert_eq!(back.id(), t.id());
        assert_eq!(back.secret().digest(), t.secret().digest());
    }

    #[test]
    fn generated_tokens_differ() {
        let a = Token::generate().unwrap();
        let b = Token::generate().unwrap();
        assert_ne!(a.expose(), b.expose());
    }

    #[test]
    fn parses_secret_containing_underscores() {
        // 0xFF.. encodes to '_' characters in base64url.
        let t = Token::parse(&tok("abcdefgh", &URL_SAFE_NO_PAD.encode([0xFFu8; 32]))).unwrap();
        assert_eq!(t.secret().digest(), Sha256::digest([0xFFu8; 32]).as_slice());
    }

    #[test]
    fn rejects_malformed_tokens() {
        let long_rest = format!("{SECRET_43}A");
        let padded = format!("{}=", &SECRET_43[..42]);
        // Last char 'B' sets non-zero trailing bits: not canonical.
        let non_canonical = format!("{}B", &SECRET_43[..42]);
        let cases = [
            String::new(),
            "wl".to_owned(),
            "wl_abcdefgh".to_owned(),
            "wl_abcdefgh_".to_owned(),
            tok("abcdefgh", &SECRET_43[..42]),
            tok("abcdefgh", &long_rest),
            tok("abcdefgh", &padded),
            tok("abcdefgh", &non_canonical),
            tok("abcdefg", SECRET_43),
            tok("abcdefghi", SECRET_43),
            tok("ABCDEFGH", SECRET_43),
            tok("abcdef_h", SECRET_43),
            format!("xx_abcdefgh_{SECRET_43}"),
            format!("WL_abcdefgh_{SECRET_43}"),
            format!("wl_abcdefgh_{SECRET_43}_x"),
            format!("wl_abcdefgh_{}+", &SECRET_43[..42]),
            format!("wl_abcdefgh_{}é", &SECRET_43[..41]),
            "x".repeat(MAX_TOKEN_LEN + 1),
        ];
        for c in &cases {
            assert!(Token::parse(c).is_err(), "accepted {c:?}");
        }
        assert!(Token::parse(&tok("abcdefgh", SECRET_43)).is_ok());
    }

    #[test]
    fn debug_never_shows_secret() {
        let t = Token::generate().unwrap();
        let dbg = format!("{t:?}");
        assert!(dbg.contains("redacted"));
        assert!(!dbg.contains(&t.expose()));
    }

    #[test]
    fn verify_accepts_matching_digest_only() {
        let t = Token::generate().unwrap();
        let rec = TokenRecord {
            digest: t.secret().digest(),
            revoked: false,
        };
        assert!(t.verify(Some(&rec)));
        let other = TokenRecord {
            digest: [1; 32],
            revoked: false,
        };
        assert!(!t.verify(Some(&other)));
    }

    #[test]
    fn verify_rejects_revoked_and_unknown() {
        let t = Token::generate().unwrap();
        let rec = TokenRecord {
            digest: t.secret().digest(),
            revoked: true,
        };
        assert!(!t.verify(Some(&rec)));
        assert!(!t.verify(None));
    }
}
