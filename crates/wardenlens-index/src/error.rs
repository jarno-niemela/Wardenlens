//! The crate error type (SEC-6). No variant carries a path, a camera id, a timestamp or any
//! other row data; segment ids and schema versions are the only values that appear.

use rusqlite::ErrorCode;
use wardenlens_fsutil::FsError;

/// Why a cursor was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CursorFault {
    /// Longer than any cursor this crate issues.
    TooLong,
    /// Not a cursor in the canonical form: bad hex, version, number or camera field.
    Malformed,
    /// Issued for another camera than the one being listed.
    WrongCamera,
}

/// Every failure of the index.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum IndexError {
    /// The secure file open failed (symlink, wrong owner or mode, not a regular file, missing
    /// directory, identity changed after SQLite opened the path).
    #[error("index file check failed: {0}")]
    Fs(#[from] FsError),
    /// A file-system call on the index file or a sidecar failed.
    #[error("{op} failed: {kind}")]
    Io {
        /// What was being done.
        op: &'static str,
        /// The error kind.
        kind: std::io::ErrorKind,
    },
    /// The file is not empty and is not an SQLite database.
    #[error("file is not an sqlite database")]
    NotAnIndex,
    /// An SQLite database that is not an index (its `application_id` differs). Never modified.
    #[error("database is not a wardenlens index (application id {found:#x})")]
    WrongApplicationId {
        /// The `application_id` found.
        found: u32,
    },
    /// A `-wal`, `-shm` or `-journal` sidecar is a symlink or not a regular file.
    #[error("sidecar {suffix} is not a regular file")]
    BadSidecar {
        /// The sidecar suffix.
        suffix: &'static str,
    },
    /// A sidecar sits next to an empty database file: it belongs to something else and SQLite
    /// would delete or replay it on first open. Nothing was modified.
    #[error("sidecar {suffix} exists next to an empty database")]
    StraySidecar {
        /// The sidecar suffix.
        suffix: &'static str,
    },
    /// The database is in rollback-journal mode and has a non-empty `-journal`: a write was
    /// interrupted (the only such window is the first creation of the file) or the file is
    /// somebody else's. Nothing was modified. Do not delete the journal on a guess: it may hold
    /// the data needed to roll a database back. The index can be rebuilt from the recordings
    /// (ADR 0005 section 9), so when no other process runs, the owner may remove `index.db*`.
    #[error("database has an unfinished rollback journal; nothing was modified")]
    PendingJournal,
    /// The file was written by a newer build.
    #[error("index schema version {found} is newer than the supported {supported}")]
    SchemaTooNew {
        /// The `user_version` found.
        found: i64,
        /// The newest version this build knows.
        supported: i64,
    },
    /// A negative `user_version`.
    #[error("index schema version {found} is invalid")]
    InvalidSchemaVersion {
        /// The `user_version` found.
        found: i64,
    },
    /// A migration script failed; its transaction was rolled back.
    #[error("migration {version} failed: {code:?}")]
    Migration {
        /// The migration number.
        version: i64,
        /// The SQLite result code, if any.
        code: Option<ErrorCode>,
    },
    /// A migration script ran but did not set `user_version` to its own number; rolled back.
    #[error("migration {version} did not set the schema version")]
    MigrationDidNotAdvance {
        /// The migration number.
        version: i64,
    },
    /// A pragma did not take the value required.
    #[error("pragma {pragma} did not take the required value")]
    PragmaRefused {
        /// The pragma name.
        pragma: &'static str,
    },
    /// The database is locked by another connection past the busy timeout. Transient.
    #[error("{op}: database is busy")]
    Busy {
        /// What was being done.
        op: &'static str,
    },
    /// An SQLite failure that is not one of the cases above.
    #[error("{op} failed: {code:?}")]
    Sqlite {
        /// What was being done.
        op: &'static str,
        /// The SQLite result code, if any.
        code: Option<ErrorCode>,
    },
    /// A segment with the same camera and start time exists.
    #[error("a segment with this camera and start time already exists")]
    Duplicate,
    /// A schema constraint (a `CHECK`) refused the write.
    #[error("{op}: constraint violated")]
    Constraint {
        /// What was being done.
        op: &'static str,
    },
    /// The record to insert is outside the schema's bounds.
    #[error("invalid record: {field}")]
    InvalidRecord {
        /// The field name.
        field: &'static str,
    },
    /// No segment with this id.
    #[error("segment {0} not found")]
    NotFound(u64),
    /// `set_tier` to the tier the segment is already on.
    #[error("segment {0} is already on that tier")]
    AlreadyOnTier(u64),
    /// A limit outside `1..=max`.
    #[error("limit {limit} is outside 1..={max}")]
    InvalidLimit {
        /// The limit given.
        limit: usize,
        /// The largest accepted.
        max: usize,
    },
    /// A cursor that is not valid for this listing.
    #[error("invalid cursor: {0:?}")]
    InvalidCursor(CursorFault),
    /// A stored row violates the schema's bounds (a file edited outside SQLite).
    #[error("stored row {id} is invalid: {field}")]
    CorruptRow {
        /// The raw row id, or 0 when the row has no readable id.
        id: i64,
        /// The offending column.
        field: &'static str,
    },
}

impl IndexError {
    /// Maps a failed SQLite call, keeping only the result code (the message can name files).
    pub(crate) fn sqlite(op: &'static str) -> impl FnOnce(rusqlite::Error) -> Self {
        move |e| match e.sqlite_error_code() {
            Some(ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked) => Self::Busy { op },
            code => Self::Sqlite { op, code },
        }
    }

    pub(crate) fn io(op: &'static str) -> impl FnOnce(std::io::Error) -> Self {
        move |e| Self::Io { op, kind: e.kind() }
    }

    /// True for a failure that may succeed when retried: the database was busy, or an I/O error
    /// occurred. A constraint, a duplicate or a bad argument never is.
    #[must_use]
    pub fn is_transient(&self) -> bool {
        match self {
            Self::Busy { .. } => true,
            Self::Sqlite { code, .. } => matches!(
                code,
                Some(ErrorCode::SystemIoFailure | ErrorCode::DiskFull | ErrorCode::OutOfMemory)
            ),
            _ => false,
        }
    }
}
