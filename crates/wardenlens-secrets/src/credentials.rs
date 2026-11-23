//! The credential pair and its plaintext layout.

use std::fmt;

use secrecy::{ExposeSecret, SecretString};
use zeroize::Zeroizing;

use crate::error::SecretsError;
use crate::record::{MAX_VALUE_LEN, RecordKind};

/// A username and password. `Debug` redacts both fields.
pub struct Credentials {
    /// The account name.
    pub username: String,
    /// The password, zeroised on drop.
    pub password: SecretString,
}

impl fmt::Debug for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credentials")
            .field("username", &format_args!("[redacted]"))
            .field("password", &format_args!("[redacted]"))
            .finish()
    }
}

impl Credentials {
    /// Builds credentials from plain parts.
    pub fn new(username: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            username: username.into(),
            password: SecretString::from(password.into()),
        }
    }

    /// `username_len (u16 big endian) || username || password` (ADR 0006 section 3).
    pub(crate) fn encode(&self) -> Result<Zeroizing<Vec<u8>>, SecretsError> {
        let password = self.password.expose_secret().as_bytes();
        let username = self.username.as_bytes();
        if username.len() > MAX_VALUE_LEN || password.len() > MAX_VALUE_LEN {
            return Err(SecretsError::TooLarge);
        }
        let len = u16::try_from(username.len()).map_err(|_| SecretsError::TooLarge)?;
        let mut out = Zeroizing::new(Vec::with_capacity(
            2usize
                .saturating_add(username.len())
                .saturating_add(password.len()),
        ));
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(username);
        out.extend_from_slice(password);
        Ok(out)
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, SecretsError> {
        let malformed = || SecretsError::MalformedPlaintext(RecordKind::Credential);
        let (len_bytes, rest) = bytes.split_first_chunk::<2>().ok_or_else(malformed)?;
        let len = usize::from(u16::from_be_bytes(*len_bytes));
        if len > MAX_VALUE_LEN || rest.len() < len {
            return Err(malformed());
        }
        let (user, pass) = rest.split_at(len);
        if pass.len() > MAX_VALUE_LEN {
            return Err(malformed());
        }
        let username = std::str::from_utf8(user)
            .map_err(|_| malformed())?
            .to_owned();
        let password = std::str::from_utf8(pass)
            .map_err(|_| malformed())?
            .to_owned();
        Ok(Self {
            username,
            password: SecretString::from(password),
        })
    }
}
