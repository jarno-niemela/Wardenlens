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
mod scan;
mod store;
mod validate;

pub use error::VaultError;
pub use scan::{
    BINARY_PROBE_LEN, Content, Hit, MAX_FILE_LEN, MAX_HITS, MAX_INPUT_LEN, MAX_NEEDLE_BYTES,
    Matcher, ScanEntry, ScanError, ScanReport, Unscannable, classify, scan,
};
pub use store::{
    BUSY_TIMEOUT, Entry, EntryInfo, MAX_ENTRIES, MAX_VALUE_LEN, Scan, Scannability, Value, Vault,
};
pub use validate::MIN_SCANNABLE_LEN;

#[cfg(test)]
mod tests;
