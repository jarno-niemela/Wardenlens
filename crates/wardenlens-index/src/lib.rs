//! The SQLite index of recorded segments (ADR 0005 section 5; ticket #49).
//!
//! [`Index`] is one SQLite file in WAL mode with `synchronous = FULL`, opened only through the
//! checked sequence in `open`: a private parent directory, our own `O_NOFOLLOW` descriptor, every
//! sidecar checked for kind, owner and mode, and the identity of the file and of its `-wal` proven
//! read-only (header, an immutable open, or a read-only connection when a `-wal` is present) before any read-write connection exists,
//! then `SQLITE_OPEN_NOFOLLOW` and a device and inode comparison. The schema is versioned with
//! `PRAGMA user_version`; an older file is migrated step by step, a newer one is refused and left
//! untouched. [`Index`] implements the core port [`wardenlens_core::storage::SegmentIndex`].
//!
//! The API is synchronous. Async callers wrap it in `spawn_blocking`. One process owns the file
//! (ADR 0005 section 7: an exclusive lock held by the cli).
//!
//! Every SQL statement is a `&'static str` in `sql`; values travel only as bound parameters.
//! Errors carry no path and no row data (SEC-6).

mod cursor;
mod error;
mod migrate;
mod open;
mod ops;
mod rows;
mod sql;

use std::fmt;
use std::path::Path;

use rusqlite::Connection;
use wardenlens_fsutil::PrivateFile;

pub use error::{CursorFault, IndexError};
pub use open::BUSY_TIMEOUT;

/// An open index. Holds the connection and, until it is dropped, the descriptor whose identity
/// was checked at open (so the inode cannot be recycled under the comparison).
pub struct Index {
    conn: Connection,
    _file: PrivateFile,
}

impl fmt::Debug for Index {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Index { .. }")
    }
}

/// The directory that holds `path` (`.` for a bare file name).
pub(crate) fn parent_of(path: &Path) -> &Path {
    match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    }
}

impl Index {
    /// Opens the index at `path`, creating it (mode `0600`) when the file is missing or empty,
    /// and migrates it to the schema of this build.
    ///
    /// # Errors
    /// - [`IndexError::Fs`]: a symlink, a directory, a FIFO, a wrong owner or mode, a missing
    ///   parent directory, or a path that changed while it was opened.
    /// - [`IndexError::NotAnIndex`], [`IndexError::WrongApplicationId`],
    ///   [`IndexError::BadSidecar`], [`IndexError::StraySidecar`], [`IndexError::PendingJournal`]:
    ///   the file is not an index of ours; it was not modified.
    /// - [`IndexError::SchemaTooNew`] and [`IndexError::InvalidSchemaVersion`]: the stored
    ///   version; the file was not modified.
    /// - [`IndexError::Migration`], [`IndexError::MigrationDidNotAdvance`]: a step failed and was
    ///   rolled back; earlier steps stay committed and the file keeps working at that version.
    /// - [`IndexError::PragmaRefused`], [`IndexError::Busy`], [`IndexError::Sqlite`],
    ///   [`IndexError::Io`].
    pub fn open(path: &Path) -> Result<Self, IndexError> {
        Self::open_with(path, migrate::MIGRATIONS, || {})
    }

    pub(crate) fn open_with(
        path: &Path,
        migrations: &[migrate::Migration],
        between: impl FnOnce(),
    ) -> Result<Self, IndexError> {
        let opened = open::open(path, migrations, between)?;
        Ok(Self {
            conn: opened.conn,
            _file: opened.file,
        })
    }
}

#[cfg(test)]
#[expect(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::too_many_lines,
    reason = "tests: small bounded synthetic values, and one long table per invariant (TEST-9)"
)]
mod tests;
