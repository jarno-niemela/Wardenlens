//! The versioned record format (ADR 0006 section 3).
//!
//! ```text
//! record = version (0x01) || nonce (24) || ciphertext || tag (16)
//! AAD    = version (1) || kind code (1) || entry id (UTF-8, the rest)
//! ```

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

use crate::credentials::Credentials;
use crate::error::SecretsError;
use crate::key::KeyFile;

const VERSION: u8 = 0x01;
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;

/// Longest entry id in bytes.
pub const MAX_ID_LEN: usize = 128;
/// Longest single value (username, password or plain value) in bytes.
pub const MAX_VALUE_LEN: usize = 4096;
/// Shortest possible record: version, nonce and tag.
pub const MIN_RECORD_LEN: usize = 1 + NONCE_LEN + TAG_LEN;
/// Longest accepted plaintext (a credential: length prefix plus two maximal values).
const MAX_PLAINTEXT_LEN: usize = 2 + 2 * MAX_VALUE_LEN;
/// Longest accepted record.
pub const MAX_RECORD_LEN: usize = MIN_RECORD_LEN + MAX_PLAINTEXT_LEN;

/// The entry kind, bound into the ciphertext. Codes are stable on disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RecordKind {
    /// Reserved for the vault's own `meta:keycheck` entry; never an entry kind.
    Keycheck,
    /// A username and password pair.
    Credential,
    /// One opaque secret.
    Secret,
    /// A LAN address or hostname.
    Host,
    /// A MAC address.
    Mac,
    /// A device serial number.
    Serial,
    /// A camera or site display name.
    DisplayName,
    /// Any other sensitive text.
    Other,
}

impl RecordKind {
    /// The stable on-disk code.
    pub const fn code(self) -> u8 {
        match self {
            Self::Keycheck => 0,
            Self::Credential => 1,
            Self::Secret => 2,
            Self::Host => 3,
            Self::Mac => 4,
            Self::Serial => 5,
            Self::DisplayName => 6,
            Self::Other => 7,
        }
    }
}

fn check_id(id: &str) -> Result<(), SecretsError> {
    let bytes = id.as_bytes();
    let first_ok = bytes
        .first()
        .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit());
    let rest_ok = bytes.iter().all(|b| {
        b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b':' | b'_' | b'.' | b'-')
    });
    if bytes.len() > MAX_ID_LEN || !first_ok || !rest_ok {
        return Err(SecretsError::InvalidId);
    }
    Ok(())
}

fn aad(kind: RecordKind, id: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(id.len().saturating_add(2));
    out.push(VERSION);
    out.push(kind.code());
    out.extend_from_slice(id.as_bytes());
    out
}

/// Encrypts `plaintext` for entry `entry_id` of `kind` under a fresh random nonce.
///
/// # Errors
/// [`SecretsError::InvalidId`], [`SecretsError::TooLarge`] or [`SecretsError::Random`].
pub fn seal(
    key: &KeyFile,
    kind: RecordKind,
    entry_id: &str,
    plaintext: &[u8],
) -> Result<Vec<u8>, SecretsError> {
    check_id(entry_id)?;
    if plaintext.len() > MAX_PLAINTEXT_LEN {
        return Err(SecretsError::TooLarge);
    }
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce).map_err(|_| SecretsError::Random)?;
    let cipher = XChaCha20Poly1305::new(key.as_array().into());
    let aad = aad(kind, entry_id);
    let sealed = cipher
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| SecretsError::Authentication)?;
    let mut out = Vec::with_capacity(MIN_RECORD_LEN.saturating_add(sealed.len()));
    out.push(VERSION);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&sealed);
    Ok(out)
}

/// Decrypts a record produced by [`seal`] with the same key, kind and entry id.
///
/// # Errors
/// [`SecretsError::Truncated`], [`SecretsError::UnsupportedVersion`],
/// [`SecretsError::Authentication`], [`SecretsError::InvalidId`] or [`SecretsError::TooLarge`].
pub fn open(
    key: &KeyFile,
    kind: RecordKind,
    entry_id: &str,
    record: &[u8],
) -> Result<Zeroizing<Vec<u8>>, SecretsError> {
    check_id(entry_id)?;
    if record.len() > MAX_RECORD_LEN {
        return Err(SecretsError::TooLarge);
    }
    if record.len() < MIN_RECORD_LEN {
        return Err(SecretsError::Truncated);
    }
    let (version, rest) = record.split_first().ok_or(SecretsError::Truncated)?;
    if *version != VERSION {
        return Err(SecretsError::UnsupportedVersion(*version));
    }
    let (nonce, ciphertext) = rest
        .split_first_chunk::<NONCE_LEN>()
        .ok_or(SecretsError::Truncated)?;
    let cipher = XChaCha20Poly1305::new(key.as_array().into());
    let aad = aad(kind, entry_id);
    cipher
        .decrypt(
            &XNonce::from(*nonce),
            Payload {
                msg: ciphertext,
                aad: &aad,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| SecretsError::Authentication)
}

/// Seals a [`Credentials`] pair as a [`RecordKind::Credential`] record.
///
/// # Errors
/// As [`seal`].
pub fn seal_credentials(
    key: &KeyFile,
    entry_id: &str,
    credentials: &Credentials,
) -> Result<Vec<u8>, SecretsError> {
    let plaintext = credentials.encode()?;
    seal(key, RecordKind::Credential, entry_id, &plaintext)
}

/// Opens a [`RecordKind::Credential`] record.
///
/// # Errors
/// As [`open`], plus [`SecretsError::MalformedPlaintext`].
pub fn open_credentials(
    key: &KeyFile,
    entry_id: &str,
    record: &[u8],
) -> Result<Credentials, SecretsError> {
    let plaintext = open(key, RecordKind::Credential, entry_id, record)?;
    Credentials::decode(&plaintext)
}
