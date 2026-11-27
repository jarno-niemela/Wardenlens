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

mod cameras;
mod cursor;
mod error;
mod migrate;
mod open;
mod ops;
mod registry;
mod rows;
mod sql;
mod tokens;

use std::fmt;
use std::path::Path;

use crate::registry::Held;
use crate::sql::Db;
use wardenlens_fsutil::FileLock;

pub use cameras::{CameraRecord, MAX_CAMERAS, StoredCamera};
pub use error::{CursorFault, IndexError};
pub use open::BUSY_TIMEOUT;
pub use tokens::{TOUCH_INTERVAL_MS, TokenIndex};

/// An open index. Holds the connection and, until it is dropped, the descriptor whose identity
/// was checked at open (so the inode cannot be recycled under the comparison).
pub struct Index {
    // Field order is the drop order: the connection closes first, then the descriptors. Closing
    // any descriptor of the main file drops the process's POSIX locks on it, including SQLite's
    // WAL shared lock, so none of them may close while the connection is live.
    conn: Db,
    _lock: FileLock,
    // Last: the registry entry goes after the descriptor closes.
    _held: Held,
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
    /// Concurrent openers are serialised by an exclusive `flock` on the verified file descriptor
    /// (waiting up to [`BUSY_TIMEOUT`]); every process must open through this function, or hold the
    /// service's process lock around it (ADR 0005 section 5, #68).
    ///
    /// # Errors
    /// Every variant of [`IndexError`] that `open` can return:
    /// - [`IndexError::Fs`]: a symlink, a directory, a FIFO, a wrong owner or mode, a parent
    ///   directory that is not ours or is group- or world-writable, a missing parent, or a path
    ///   that changed while it was opened.
    /// - [`IndexError::Io`]: a file-system call on the file or a sidecar failed.
    /// - [`IndexError::NotAnIndex`], [`IndexError::WrongApplicationId`]: the file is not an index.
    /// - [`IndexError::BadSidecar`], [`IndexError::InsecureSidecar`], [`IndexError::StraySidecar`],
    ///   [`IndexError::PendingJournal`], [`IndexError::InvalidWal`], [`IndexError::ForeignWal`]:
    ///   a sidecar does not belong to the file.
    /// - [`IndexError::UnexpectedSchema`], [`IndexError::Damaged`]: the schema differs from its
    ///   version, or the integrity check failed.
    /// - [`IndexError::SchemaTooNew`], [`IndexError::InvalidSchemaVersion`]: the stored version.
    /// - [`IndexError::Migration`], [`IndexError::MigrationDidNotAdvance`]: a step failed and was
    ///   rolled back; earlier steps stay committed.
    /// - [`IndexError::PragmaRefused`]: a pragma did not take its value.
    /// - [`IndexError::SidecarsChanging`]: the sidecars kept changing (a process was closing the
    ///   index) for every one of the bounded attempts; nothing was modified, try again.
    /// - [`IndexError::AlreadyOpenInProcess`]: this process already has that file open (by any
    ///   name); the first handle is untouched.
    /// - [`IndexError::Busy`]: another opener or writer held the file past the timeout.
    /// - [`IndexError::Sqlite`]: any other SQLite failure.
    ///
    /// Every refusal in the first six groups leaves the main file and the `-wal` unmodified (a
    /// `-shm` that did not exist is not left behind); each message names a lossless remedy.
    pub fn open(path: &Path) -> Result<Self, IndexError> {
        Self::open_with(path, migrate::MIGRATIONS, || {})
    }

    pub(crate) fn open_with(
        path: &Path,
        migrations: &[migrate::Migration],
        between: impl FnOnce(),
    ) -> Result<Self, IndexError> {
        Self::open_with_lock_wait(path, migrations, between, BUSY_TIMEOUT)
    }

    pub(crate) fn open_with_lock_wait(
        path: &Path,
        migrations: &[migrate::Migration],
        between: impl FnOnce(),
        lock_wait: std::time::Duration,
    ) -> Result<Self, IndexError> {
        Self::open_with_hooks(path, migrations, between, lock_wait, &mut |_| {})
    }

    pub(crate) fn open_with_hooks(
        path: &Path,
        migrations: &[migrate::Migration],
        between: impl FnOnce(),
        lock_wait: std::time::Duration,
        hook: &mut dyn FnMut(open::Stage),
    ) -> Result<Self, IndexError> {
        let opened = open::open(path, migrations, between, lock_wait, hook)?;
        Ok(Self {
            conn: opened.conn,
            _lock: opened.lock,
            _held: opened.held,
        })
    }
}

/// Test only: the parts of an [`Index`] with its registry entry released, standing in for
/// another process that has the file open (the registry refuses a second handle in this one).
#[cfg(test)]
pub(crate) struct Foreign {
    _conn: Db,
    _lock: FileLock,
    _file: wardenlens_fsutil::PrivateFile,
}

#[cfg(test)]
impl Index {
    pub(crate) fn into_foreign(self) -> Foreign {
        let Self {
            conn,
            _lock: lock,
            _held: held,
        } = self;
        Foreign {
            _conn: conn,
            _lock: lock,
            _file: held.into_file(),
        }
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
