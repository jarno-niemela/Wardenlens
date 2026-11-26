//! The storage executor (ADR 0005 sections 6 to 8; ticket #58): the volume probe and the archive
//! state, the crash-safe tier move M1-M9, delete, quarantine eviction, and the bounded
//! [`StorageLoop::tick`] that runs the pure core plan against real volumes.
//!
//! The hot copy of a segment stays authoritative until the index says archive and is unlinked
//! last, so no failure at any step loses the only copy. Every path is opened below a root handle
//! with `openat2` (`RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS`) and every directory operation takes a
//! single path component on an opened parent descriptor (through `wardenlens-fsutil`; this crate
//! contains no raw descriptor code). The archive handle of the latest successful probe is the
//! only archive handle that the mover and [`StorageFiles`] use.
//!
//! Errors and reports carry counts and states only: never a path, a camera id or a time (SEC-6).
//!
//! Not here: the reconciliation after a crash and the "archive returned" pass of section 9
//! (ticket #59); [`TickReport::archive_returned`] says when that pass is due.

mod config;
mod error;
mod evict;
mod files;
mod fs;
mod index;
mod mover;
mod probe;
mod storage_loop;

#[cfg(test)]
#[expect(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::too_many_lines,
    reason = "tests: small bounded synthetic values, and one long table per invariant (TEST-9)"
)]
mod tests;

pub use config::StorageConfig;
pub use error::{ProbeError, StorageError, TickError};
pub use evict::MAX_QUARANTINE_ENTRIES;
pub use files::{ReadSeekSource, StorageFiles};
pub use fs::{Fs, Opened, PartFile, RealFs, SourceFile};
#[cfg(test)]
pub(crate) use mover::{COPY_CHUNK, Dropped, Outcome, Skip, Stage};
pub use probe::{
    ARCHIVE_MARKER, ArchiveProbe, MAX_MOVE_FAILURES, PROBE_FILE, StatvfsUsage, UnavailableCause,
    VolumeUsage, space_from_stat,
};
pub use storage_loop::{
    Built, INDEX_ERROR_TICKS, MAX_REPLANS, MAX_SEGMENTS, Observer, Storage, StorageLoop, TickReport,
};
