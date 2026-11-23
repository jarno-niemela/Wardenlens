//! The Wardenlens sensitive-data vault (ADR 0006 sections 1, 3 to 5).
//!
//! A [`Vault`] is one SQLite file of sealed entries `(id, kind, value)`. Values are encrypted
//! with `wardenlens-secrets` records bound to their id and kind. The file is opened only
//! through the checked sequence in `store` (own `O_NOFOLLOW` descriptor, `SQLITE_OPEN_NOFOLLOW`,
//! device and inode comparison, private parent directory).
//!
//! Values never appear in errors, `Debug` output or logs.

mod error;
pub mod legacy;
mod store;
mod validate;

pub use error::VaultError;
pub use store::{BUSY_TIMEOUT, Entry, EntryInfo, MAX_ENTRIES, MAX_VALUE_LEN, Value, Vault};
pub use validate::MIN_SCANNABLE_LEN;

#[cfg(test)]
mod tests;
