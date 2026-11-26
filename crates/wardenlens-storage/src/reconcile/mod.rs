//! Reconciliation of the index and the segment files (ADR 0005 section 9; ticket #59).
//!
//! Two entry points share one engine:
//!
//! * the **start-up pass** ([`StorageLoop::reconcile_startup`](crate::StorageLoop::reconcile_startup)):
//!   run after the volume probe and before the recorders start. It walks both roots, deletes
//!   `.part` files (the archive's only when the archive is available), and applies the per-key
//!   decision table of section 9 to every key `(camera, started_at)`: 27 cells with the archive
//!   available, 9 without.
//! * the **"archive returned" pass** ([`StorageLoop::tick`](crate::StorageLoop::tick) runs it on
//!   the tick that sees the archive change from unavailable to available, serialised with the
//!   mover). The recorders are running, so its scope is strictly limited: only keys with an
//!   archive file, a `tier = archive` row or a `tier = hot` row whose hot file is missing; only
//!   the archive `.part` rule; a hot `.part` is never touched, a hot-only key is never adopted
//!   and, for a key without a row, the hot file is never touched (it may be in the recorder's
//!   rename-to-insert window).
//!
//! **What an observation means.** A copy is *none* only when the open failed with `ENOENT` and
//! nothing else; any other error leaves the key `unverified` (nothing is concluded, row and files
//! stay). A non-regular object (FIFO, directory, symlink) at a segment name is `unknown_left`
//! and the key is skipped. A copy is *valid* when it is a regular file whose size equals the row's
//! `bytes`, or, without a row, when it passes the adoption parser (untrusted input, see
//! [`adopt`]). An invalid file is **never deleted**: it is quarantined with `RENAME_NOREPLACE`
//! and a numeric suffix. Only a valid duplicate and a `.part` file are deleted.
//!
//! **Order and durability.** Every roll-forward, roll-back, adoption and "the file is the truth"
//! cell fsyncs the surviving file and its directory before the index write that makes it the
//! only copy and before any twin is deleted. An id is never reassigned while a row exists: the
//! pass only inserts rows for keys without one, changes `tier`, or deletes.
//!
//! **Bounds.** The walk is `<root>/<camera>/<day>/<file>`: a directory below a day directory is
//! not entered, a symlink is never followed, and the entries visited are capped
//! (`StorageConfig::walk_max_entries`, default 5,000,000). One `(camera, day)` directory and its
//! rows are held in memory at a time. Past the cap the walk stops, the report says `unverified`
//! for the tiers and carries a health error, and nothing is concluded from the part not seen.
//!
//! **Reports** hold counts and flags only: never a camera, a path or a time.

mod adopt;
mod cells;
mod walk;

use std::collections::{BTreeMap, HashSet};

use wardenlens_core::camera::CameraId;
use wardenlens_core::storage::SegmentIndex;
use wardenlens_core::time::UnixMs;

use crate::fs::Fs;
use crate::index::SharedIndex;

/// Which pass is running.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Mode {
    /// Before the recorders start: the whole decision table.
    Startup,
    /// With the recorders running, after the archive came back: the limited scope.
    Returned,
}

/// What a reconciliation pass did. Counts and flags only (SEC-6): no file name, camera or time.
///
/// Every category a pass can produce:
///
/// * `part_deleted`: `.part` files deleted (a hot `.part` only at start-up; an archive `.part`
///   only when the archive is available).
/// * `rolled_forward`: a row set to `archive` because the archive copy is the truth.
/// * `rolled_back`: a row set to `hot` because the hot copy is the truth.
/// * `missing`: a row dropped because no file of it exists (ENOENT on both tiers).
/// * `adopted`: a file without a row got one.
/// * `quarantined`: a file moved into `_quarantine` (invalid, or an adoption that failed).
/// * `size_mismatch`: a regular file of a key that has a row whose size is not the row's.
/// * `duplicates_deleted`: a valid twin deleted.
/// * `unverified`: no conclusion was drawn (an error that is not `ENOENT`, a non-regular object,
///   an archive that is not observable, an exhausted quarantine bound, a failed index call, or a
///   part of the walk that was not seen).
/// * `unknown_left`: an object that is not ours (or not a regular file at a segment name), left
///   where it is.
/// * `index_errors`: index calls that failed (each also left its key `unverified`).
/// * `archive_unavailable`: the archive could not be observed (start-up pass only).
/// * `walk_cap_exceeded`: the entry cap stopped the walk (a health error).
/// * `hot_unverified` / `archive_unverified`: the tier was not (fully) observed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
#[expect(
    clippy::struct_excessive_bools,
    reason = "a flat report of independent facts; callers read each flag on its own"
)]
pub struct ReconcileReport {
    /// `.part` files deleted.
    pub part_deleted: u32,
    /// Rows set to `archive` (the archive copy is the truth).
    pub rolled_forward: u32,
    /// Rows set to `hot` (the hot copy is the truth).
    pub rolled_back: u32,
    /// Rows dropped because no file of them exists.
    pub missing: u32,
    /// Files without a row that got one.
    pub adopted: u32,
    /// Files moved into `_quarantine`.
    pub quarantined: u32,
    /// Regular files of a key with a row whose size differs from the row's.
    pub size_mismatch: u32,
    /// Valid twins deleted.
    pub duplicates_deleted: u32,
    /// Keys, directories or rows from which no conclusion was drawn.
    pub unverified: u32,
    /// Objects that are not ours, left in place.
    pub unknown_left: u32,
    /// Failed index calls.
    pub index_errors: u32,
    /// The archive could not be observed: no archive row was concluded from an absent file.
    pub archive_unavailable: bool,
    /// The entry cap stopped the walk (a health error; the service still starts).
    pub walk_cap_exceeded: bool,
    /// The hot tier was not fully observed.
    pub hot_unverified: bool,
    /// The archive tier was not fully observed.
    pub archive_unverified: bool,
}

impl ReconcileReport {
    /// A health error: the pass could not see everything it should (the entry cap), or the index
    /// failed.
    #[must_use]
    pub const fn health_error(&self) -> bool {
        self.walk_cap_exceeded || self.index_errors > 0
    }
}

pub(crate) fn bump(c: &mut u32) {
    *c = c.saturating_add(1);
}

/// The newest key (the largest `started_at`) the start-up walk saw per camera, in either root's
/// segment files and in the quarantine. The recorder seeds its "previous start" from it next to
/// the index's `MAX(started_at_ms)`, so a clock that stepped back across a restart cannot pick the
/// name of an orphan that is not in the index (ADR 0005 section 2).
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Newest(BTreeMap<String, UnixMs>);

impl std::fmt::Debug for Newest {
    /// The count only: camera ids are names, and a logged `{:?}` must not carry them (SEC-6).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Newest({} cameras)", self.0.len())
    }
}

impl Newest {
    /// The newest key seen for `camera`.
    #[must_use]
    pub fn get(&self, camera: &CameraId) -> Option<UnixMs> {
        self.0.get(camera.as_str()).copied()
    }

    pub(crate) fn note(&mut self, camera: &str, key: UnixMs) {
        let e = self.0.entry(camera.to_owned()).or_insert(key);
        if key > *e {
            *e = key;
        }
    }
}

/// The result of the start-up pass.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Reconciled {
    /// The counts.
    pub report: ReconcileReport,
    /// The newest key seen per camera.
    pub newest: Newest,
}

/// The engine. One per pass.
pub(crate) struct Reconciler<'a, F, I> {
    pub(crate) fs: &'a F,
    pub(crate) index: &'a SharedIndex<I>,
    pub(crate) mode: Mode,
    /// The archive can be observed (a fresh handle from the latest probe is in the slot).
    pub(crate) archive: bool,
    /// Entries the walk may still visit.
    pub(crate) budget: usize,
    pub(crate) capped: bool,
    pub(crate) report: ReconcileReport,
    pub(crate) newest: Newest,
    /// The `(camera, day)` directories the walk processed.
    pub(crate) visited: HashSet<(String, String)>,
    /// Rows handled through their directory (so the orphan-row phase can account for the rest).
    pub(crate) rows_seen: u64,
}

impl<'a, F: Fs, I: SegmentIndex> Reconciler<'a, F, I> {
    pub(crate) fn new(
        fs: &'a F,
        index: &'a SharedIndex<I>,
        mode: Mode,
        archive: bool,
        max_entries: usize,
    ) -> Self {
        let report = ReconcileReport {
            archive_unavailable: !archive,
            archive_unverified: !archive,
            ..ReconcileReport::default()
        };
        Self {
            fs,
            index,
            mode,
            archive,
            budget: max_entries,
            capped: false,
            report,
            newest: Newest::default(),
            visited: HashSet::new(),
            rows_seen: 0,
        }
    }

    /// Run the pass.
    pub(crate) fn run(mut self) -> Reconciled {
        if self.walk().is_err() {
            self.capped = true;
        }
        if self.capped {
            self.report.walk_cap_exceeded = true;
            self.report.hot_unverified = true;
            self.report.archive_unverified = true;
            self.count_unseen_rows();
        } else {
            self.rows_without_a_directory();
        }
        if self.mode == Mode::Startup {
            self.note_quarantined_keys();
        }
        Reconciled {
            report: self.report,
            newest: self.newest,
        }
    }
}
