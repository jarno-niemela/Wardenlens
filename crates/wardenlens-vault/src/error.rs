//! The crate error type. Messages name the rule that failed; they never carry a value, a key or
//! ciphertext. Entry ids and kinds are non-sensitive and may appear.

use wardenlens_core::entry::{EntryError, EntryKind};
use wardenlens_fsutil::FsError;
use wardenlens_secrets::SecretsError;

/// Every failure the vault can report.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum VaultError {
    /// The vault path lies inside a git work tree.
    #[error("vault path is inside a git work tree")]
    InWorkTree,
    /// The vault path has no parent directory.
    #[error("vault path has no parent directory")]
    NoParent,
    /// The parent directory is owned by another user.
    #[error("vault directory is not owned by the current user")]
    ParentWrongOwner,
    /// The parent directory is writable by group or others.
    #[error("vault directory is writable by group or others")]
    ParentWritable,
    /// The vault file does not exist.
    #[error("vault file does not exist")]
    NotFound,
    /// The file exists but holds no vault: no `meta` table, not exactly the vault schema, or no
    /// keycheck record. A corrupt database or an unfinished transaction is never reported as
    /// this (see [`VaultError::PendingJournal`]).
    #[error("file is not an initialised vault")]
    NotInitialized,
    /// The vault has a non-empty `-journal` that did not go away within the busy timeout and the
    /// state could not be judged. Causes: `create` met a vault with an unfinished transaction; a
    /// copy of the vault with its journal rolled back in a private scratch directory is still
    /// corrupt; a read that raced a writer after the busy timeout found the file corrupt; the retry
    /// cap was exhausted (the journal or the change counter kept moving); the copy was over the
    /// 256 MiB cap; the journal is not a regular file; or the journal ends in a super-journal
    /// pointer (a vault never writes one, and following it is unsafe). Nothing was modified. The
    /// owner can wait for a running writer to finish and retry; if no writer is running, restore
    /// the vault from a backup. Do not delete the `-journal` file: it holds the data needed to roll
    /// the vault back. A wrong key, a foreign database or an unknown schema in that state is
    /// reported as [`VaultError::WrongKey`], [`VaultError::NotInitialized`] or
    /// [`VaultError::UnsupportedSchema`] instead.
    ///
    /// A process killed in the middle of `create` leaves a file with a hot journal and no vault:
    /// `create` then reports [`VaultError::NotEmpty`] (when the rolled-back copy holds no vault)
    /// and `open` reports [`VaultError::NotInitialized`]. The library cannot recover this state
    /// (the file holds nothing of value); the owner removes both files and runs `create` again.
    #[error(
        "vault has an unfinished transaction (another process is writing, or a previous write was interrupted); do not delete the -journal file"
    )]
    PendingJournal,
    /// `create` found a file that is not empty and holds no vault.
    #[error("file exists and is not empty")]
    NotEmpty,
    /// `create` found a vault that already exists.
    #[error("vault already initialised")]
    AlreadyInitialized,
    /// The schema version is not one this build knows.
    #[error("unsupported vault schema version")]
    UnsupportedSchema,
    /// The key does not open `meta:keycheck`.
    #[error("wrong key: the vault keycheck record did not authenticate")]
    WrongKey,
    /// A stored entry is malformed or does not authenticate under the key.
    #[error("entry {id} is corrupt")]
    CorruptEntry {
        /// The id of the damaged entry (ids are not sensitive).
        id: String,
    },
    /// The id is invalid.
    #[error("invalid entry id: {0}")]
    InvalidId(#[from] EntryError),
    /// The value breaks a per-kind rule.
    #[error("invalid value for kind {kind}: {rule}")]
    InvalidValue {
        /// The kind that was being stored.
        kind: EntryKind,
        /// Which rule failed.
        rule: &'static str,
    },
    /// The value is longer than 4096 bytes.
    #[error("value for kind {kind} exceeds 4096 bytes")]
    ValueTooLarge {
        /// The kind that was being stored.
        kind: EntryKind,
    },
    /// The value shape does not fit the kind (credential vs text).
    #[error("value shape does not match kind {kind}")]
    ValueKindMismatch {
        /// The kind that was being stored.
        kind: EntryKind,
    },
    /// `Scan::PublicOccurrence` was used with a kind other than credential or secret.
    #[error("a public occurrence applies only to credential and secret entries, not {kind}")]
    PublicOccurrenceKind {
        /// The kind that was being stored.
        kind: EntryKind,
    },
    /// `rename_camera` found no entry of the source camera.
    #[error("no entries to move: the source camera has none")]
    NothingToRename,
    /// `rename_camera` found the target camera already holding this entry (ids are not sensitive).
    #[error("entry {id} already exists; nothing was moved")]
    RenameTargetExists {
        /// The id of the existing target entry.
        id: String,
    },
    /// `rename_camera` was asked to move a camera onto itself.
    #[error("source and target camera are the same")]
    RenameSame,
    /// The store would exceed 10,000 entries.
    #[error("vault holds the maximum number of entries")]
    TooManyEntries,
    /// A SQLite call failed.
    #[error("sqlite {op} failed: {source}")]
    Sqlite {
        /// The step that failed.
        op: &'static str,
        /// The underlying error.
        #[source]
        source: rusqlite::Error,
    },
    /// A file-system trust check or call failed.
    #[error("vault file check failed: {0}")]
    Fs(#[from] FsError),
    /// A filesystem call failed.
    #[error("vault i/o failed during {op}: {source}")]
    Io {
        /// The step that failed.
        op: &'static str,
        /// The underlying error.
        #[source]
        source: std::io::Error,
    },
    /// The cipher layer failed.
    #[error("cipher failure: {0}")]
    Secrets(#[from] SecretsError),
}

impl VaultError {
    pub(crate) fn sqlite(op: &'static str) -> impl FnOnce(rusqlite::Error) -> Self {
        move |source| Self::Sqlite { op, source }
    }

    pub(crate) fn io(op: &'static str) -> impl FnOnce(std::io::Error) -> Self {
        move |source| Self::Io { op, source }
    }

    pub(crate) fn corrupt(id: &str) -> Self {
        Self::CorruptEntry { id: id.to_owned() }
    }
}
