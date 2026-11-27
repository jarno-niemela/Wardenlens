//! The crate error type (SEC-6). No variant carries a path, a camera id, a timestamp or any
//! other row data; segment ids and schema versions are the only values that appear.

use rusqlite::ErrorCode;
use wardenlens_core::camera::CameraError;
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
    #[error(
        "file is not an sqlite database; nothing was modified; move it out of the way and keep it until you know what it is"
    )]
    NotAnIndex,
    /// An SQLite database that is not an index (its `application_id` differs). Never modified.
    #[error(
        "database is not a wardenlens index (application id {found:#x}); nothing was modified; move it out of the way and keep it until you know whose it is"
    )]
    WrongApplicationId {
        /// The `application_id` found.
        found: u32,
    },
    /// A `-wal`, `-shm` or `-journal` sidecar is a symlink or not a regular file.
    #[error(
        "sidecar {suffix} is not a regular file; nothing was modified; move it out of the directory and keep it"
    )]
    BadSidecar {
        /// The sidecar suffix.
        suffix: &'static str,
    },
    /// A sidecar is owned by another user, grants group or other access, or has more than one
    /// hard link (SQLite rewrites a `-shm` and a `-wal` in place, which would clobber the file
    /// that has the other name). SQLite would replay or roll back whatever it holds into the
    /// index, so it is never trusted. Nothing was modified.
    #[error(
        "sidecar {suffix} is not owned by the current user, is accessible to others or has more than one hard link; nothing was modified; move it out of the directory and keep it (or fix its owner, mode or links if it is yours)"
    )]
    InsecureSidecar {
        /// The sidecar suffix.
        suffix: &'static str,
    },
    /// The index file itself has more than one hard link. Two names of one index get two
    /// separate `-wal`/`-shm` pairs, so two processes would not see each other's locks and would
    /// overwrite each other's committed rows. Nothing was modified.
    #[error(
        "index file has more than one hard link; nothing was modified; remove the extra name (keep one) and start again"
    )]
    HardLinkedIndex,
    /// This process already has the index file open (under this or another name). A second
    /// handle would drop the first one's POSIX locks when it closed its descriptor, so it is
    /// refused (#148, ADR 0005 section 5). Share the one `Index` instead.
    #[error(
        "this process already has the index file open; nothing was modified; share the one open Index (a second open would drop the first one's locks)"
    )]
    AlreadyOpenInProcess,
    /// A sidecar exists that cannot belong to this database in its state: any sidecar next to an
    /// empty file, a `-wal` or `-shm` next to a rollback-mode file, or an empty `-journal`.
    /// Nothing was modified. Move it out of the directory (and delete it later when you know
    /// it is not another program's).
    #[error(
        "sidecar {suffix} does not belong to this database; nothing was modified; move it out of the directory (keep it until you know whose it is)"
    )]
    StraySidecar {
        /// The sidecar suffix.
        suffix: &'static str,
    },
    /// A non-empty `-journal` next to the index. An index in WAL mode never writes a rollback
    /// journal, so this is either left by an interrupted creation (the file is in rollback mode
    /// only before the first row exists) or not ours. Nothing was modified and nothing was
    /// replayed. Decision (ADR 0005 section 5): no private-copy identification of a creation
    /// window; moving the `-journal` out is lossless, because an index holding recordings data
    /// never has one, and the empty file that is left is adopted again.
    #[error(
        "unfinished -journal next to the index; nothing was modified; move the -journal file out of the directory and keep it (an index with data never has one, so nothing is lost)"
    )]
    PendingJournal,
    /// The `-wal` next to the index has no valid header (wrong magic or header checksum) and is
    /// not a torn one (only a file that
    /// is entirely zero, or a short prefix of a valid header, is treated as empty): SQLite did not
    /// write it. Nothing was modified. It holds no committed data of this index; move it out of
    /// the directory and keep it.
    #[error(
        "the -wal file has no valid header; it holds no data of this index; nothing was modified; move it out of the directory and keep it"
    )]
    InvalidWal,
    /// The `-wal` next to the index is not this index's: a wrong header, another page size, or
    /// replaying it onto the index gives a database that is not an index of ours. Nothing was
    /// modified. Move it and its `-shm` out of the directory and keep them until you know whose they
    /// are; nothing is lost.
    #[error(
        "the -wal file does not belong to this index, or replaying it gives a damaged database; nothing was modified; move it and its -shm out of the directory and keep them until you know whose they are"
    )]
    ForeignWal,
    /// The sidecars of the index kept appearing or disappearing while it was judged, for every
    /// one of the bounded attempts: a process holding the index open was closing it as we looked.
    /// Nothing was modified.
    #[error(
        "the index's -wal and -shm kept changing while it was opened (another process was closing it); nothing was modified; try again"
    )]
    SidecarsChanging,
    /// The schema (every `sqlite_master` row) is not the one of its `user_version`.
    #[error(
        "index schema differs from its version; nothing was modified; keep the file and restore a backup, or move it aside (the index can be rebuilt from the recordings)"
    )]
    UnexpectedSchema,
    /// The database failed an integrity check or SQLite reports it corrupt. Nothing was modified.
    #[error(
        "index file is damaged; nothing was modified; keep the file and restore a backup, or move it aside (the index can be rebuilt from the recordings)"
    )]
    Damaged,
    /// The file was written by a newer build.
    #[error(
        "index schema version {found} is newer than the supported {supported}; nothing was modified; run a newer build, or restore a backup of an older index; do not delete the file"
    )]
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
    /// A read path was given a statement that is not read-only (a programming error, never
    /// caused by data): the read wrappers refuse it so it cannot skip the generation bump.
    #[error("{op}: refused a statement that is not read-only")]
    NotReadOnly {
        /// What was being done.
        op: &'static str,
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
    /// A camera path (or its query) was refused by the path rules: it has an `@`, a credential
    /// parameter, a bad character or a bad shape. Nothing was written; on a read, the row is bad.
    #[error("camera {field} refused: {source}")]
    CameraPathInvalid {
        /// `main_path` or `sub_path`.
        field: &'static str,
        /// The rule that failed (never the text).
        source: CameraError,
    },
    /// A camera path has a query string the catalogue does not allow for the camera's model.
    #[error("camera {field} has a query string the catalogue does not allow for this model")]
    CameraQueryNotAllowed {
        /// `main_path` or `sub_path`.
        field: &'static str,
    },
    /// A stored camera row violates the schema's bounds (a file edited outside SQLite). It names
    /// the column only, never the camera (SEC-6).
    #[error("stored camera row is invalid: {field}")]
    CorruptCameraRow {
        /// The offending column.
        field: &'static str,
    },
    /// The registry holds the most cameras it accepts.
    #[error("the camera registry is full ({max} cameras)")]
    TooManyCameras {
        /// The limit.
        max: usize,
    },
    /// A token with this id exists (active or revoked); nothing was written. Ids are never reused.
    #[error("a token with this id already exists")]
    TokenIdTaken,
    /// The token table holds the most rows it accepts.
    #[error("the token table is full ({max} tokens)")]
    TooManyTokens {
        /// The limit.
        max: usize,
    },
    /// A stored token row violates the schema's bounds (a file edited outside SQLite). It names
    /// the column only, never the token (SEC-6).
    #[error("stored token row is invalid: {field}")]
    CorruptTokenRow {
        /// The offending column.
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
            _ if matches!(e, rusqlite::Error::InvalidQuery) => Self::NotReadOnly { op },
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

impl wardenlens_core::storage::TransientFault for IndexError {
    fn is_transient(&self) -> bool {
        IndexError::is_transient(self)
    }
}
