//! Filesystem trust-boundary helpers (ADR 0005 section 11, ADR 0006 section 4).
//!
//! * [`open_private_file`]: the secure open of a SQLite file (create `0600`, `O_NOFOLLOW`,
//!   owner and mode checks, device and inode comparison after SQLite opened the path).
//! * [`RootDir`]: a directory handle; everything beneath it is opened with `openat2`
//!   (`RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS`) and mutated one path component at a time.
//! * [`check_parent`], [`sidecar_len`], [`Scratch`], [`copy_bounded`], [`immutable_uri`]: the shared
//!   pieces of the read-only identity probes of SQLite files (vault and index).
//! * [`open_regular_nofollow`]: read-open of an untrusted path (no symlink, regular files only).
//! * [`quarantine`]: `RENAME_NOREPLACE` into `<root>/_quarantine/<same relative path>`.
//!
//! Safe Rust only; no SQLite and no async. Errors never contain a path.

mod error;
mod private_file;
mod probe;
mod quarantine;
mod regular_file;
mod root;

pub use error::FsError;
pub use private_file::{FileIdentity, FileLock, PrivateFile, open_private_file, path_identity};
pub use probe::{
    MAX_COPY_LEN, Scratch, check_parent, copy_bounded, immutable_uri, open_sidecar, sidecar_len,
};
pub use quarantine::{
    MAX_QUARANTINE_SUFFIX, QUARANTINE_DIR, QuarantineOutcome, quarantine, quarantine_with_bound,
};
pub use regular_file::{is_symlink_refusal, open_regular_nofollow};
pub use root::{FileKind, FileStat, ReadFile, RootDir, VolumeStat};
