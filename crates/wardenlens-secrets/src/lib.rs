//! Cipher primitives for the Wardenlens sensitive-data vault (ADR 0006).
//!
//! This crate is deliberately small: a key file with strict permission rules, the versioned
//! XChaCha20-Poly1305 record format with its associated-data binding, and a redacting
//! [`Credentials`] type. It has no SQLite and no scanner; those live in the vault crate.
//!
//! Errors never contain key, plaintext or ciphertext bytes.

mod credentials;
mod error;
mod key;
mod record;

pub use credentials::Credentials;
pub use error::SecretsError;
pub use key::{KEY_LEN, KeyFile};
pub use record::{
    MAX_ID_LEN, MAX_RECORD_LEN, MAX_VALUE_LEN, MIN_RECORD_LEN, RecordKind, open, open_credentials,
    seal, seal_credentials,
};

#[cfg(test)]
mod tests;
