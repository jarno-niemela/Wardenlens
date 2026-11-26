//! `StorageLoop::tick`: probe, plan, execute, re-probe after each action, at most N actions.

use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use wardenlens_core::storage::{
    Action, ArchiveState, ArchiveStatus, HotState, MAX_OLDEST, MinFreePercent, PlanInput, Policy,
    SegmentId, SegmentIndex, StorageSnapshot, StoredSegment, TickErrorKind, Tier, VolumeSpace,
    plan,
};
use wardenlens_core::time::Timestamp;
use wardenlens_fsutil::RootDir;

use crate::config::StorageConfig;
use crate::error::{StorageError, TickError};
use crate::evict::{self, Candidate};
use crate::files::StorageFiles;
use crate::fs::{ArchiveSlot, Fs, RealFs};
use crate::index::SharedIndex;
use crate::mover::{Mover, Outcome, Skip};
use crate::probe::{ArchiveProbe, Probe, ProbeResult, VolumeUsage};
use crate::reconcile::{Mode, ReconcileReport, Reconciled, Reconciler};
use crate::status::{self, TierRows};

/// The cap on segment rows (SEC-2; ADR 0005 section 6). It bounds the memory of one plan (about
/// 40 MB per tier) and is enforced as a retention bound, after the plan's actions and with its
/// own per-tick bound. With the archive available, rows of both tiers together above it are
/// evicted oldest first (archive first, then hot); with the archive unavailable only the hot
/// tier's own excess is (hot video is never deleted because of archive rows). In normal
/// operation no tier then exceeds it and the plan never sees a truncated prefix. If a tier still does (rows
/// added from outside, faster than evicted), the plan is made from the oldest-first prefix, the
/// unseen archive rows are accounted for by their true total, and the report says so.
pub const MAX_SEGMENTS: usize = 1_000_000;
/// Ticks, per failed cap tick of the cycle, after which the row cap's cursors go back to the
/// oldest rows so that rows that could not be deleted are tried again.
const CAP_RETRY_TICKS: u32 = 16;
/// Consecutive ticks with an index error after which the report carries a health error.
pub const INDEX_ERROR_TICKS: u32 = 3;
/// Unfinished "archive returned" passes in a row after which the pass is backed off.
pub const RETURNED_PASS_TRIES: u32 = 3;
/// Idle ticks between two attempts of a backed-off "archive returned" pass (it reruns after 16
/// idle ticks).
pub const RETURNED_PASS_BACKOFF_TICKS: u32 = 16;
/// Most times one tick re-plans because the archive state changed under it.
pub const MAX_REPLANS: u32 = 2;

/// Told before quarantined files are evicted (the files are evidence of a corruption: an
/// operator should hear about it first).
pub trait Observer: Send {
    /// `files` quarantined files of `tier` are about to be deleted, oldest first.
    fn quarantine_eviction(&self, tier: Tier, files: usize);
}

struct NoObserver;
impl Observer for NoObserver {
    fn quarantine_eviction(&self, _tier: Tier, _files: usize) {}
}

/// What one tick did. Counts only: never a path, a camera or a time.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[expect(
    clippy::struct_excessive_bools,
    reason = "a flat report of independent facts; callers read each flag on its own"
)]
pub struct TickReport {
    /// The archive state of the last probe of the tick.
    pub archive: ArchiveProbe,
    /// The archive is available but cannot absorb the moves even after evicting everything
    /// (`archive_full`); it behaves like unavailable.
    pub archive_full: bool,
    /// The planner's state of the hot volume.
    pub hot: Option<HotState>,
    /// Moves completed (M1-M9).
    pub moved: u32,
    /// Moves whose row committed but whose hot file could not be unlinked.
    pub hot_unlink_left: u32,
    /// Bad hot files resolved to an archive copy (the M1 cell).
    pub rolled_forward: u32,
    /// Rows dropped by the M1 cells (`missing`, `size_mismatch`).
    pub rows_dropped: u32,
    /// Hot segments quarantined after a read error.
    pub source_quarantined: u32,
    /// Segments left alone because nothing could be concluded.
    pub unverified: u32,
    /// Archive-side move failures this tick.
    pub archive_failures: u32,
    /// Index failures this tick (a segment skipped).
    pub index_errors: u32,
    /// Segments deleted.
    pub deleted: u32,
    /// Deletes that left a non-regular twin (a symlink, FIFO, ...) on the other tier alone: it is
    /// not a segment, so the row went anyway; counted so it is never silent.
    pub twins_left: u32,
    /// Deletes that could not unlink or fsync.
    pub delete_failed: u32,
    /// Quarantined files deleted first.
    pub quarantine_evicted: u32,
    /// Actions skipped for a stale plan or an unavailable archive.
    pub skipped: u32,
    /// The plan held more actions than the per-tick bound; the rest waits for the next tick.
    pub truncated: bool,
    /// Times the plan was recomputed because the archive state changed mid-tick.
    pub replans: u32,
    /// The "archive returned" pass of section 9 (ticket #59) is pending: some probe (this tick's
    /// or an earlier tick's, including one whose tick failed) saw the archive change from
    /// unavailable to available and no tick has completed `Ok` since. This tick planned no move.
    /// It is a pending flag, not an edge: it is reported once, by the first tick that completes.
    pub archive_returned: bool,
    /// The index failed (an error on a segment, or a failed read) on [`INDEX_ERROR_TICKS`]
    /// consecutive ticks. A tick that returns [`TickError::Index`] has no report: read
    /// [`StorageLoop::index_health_error`] then.
    pub index_health_error: bool,
    /// A quarantine listing hit the entry bound or failed: some quarantined files were not seen
    /// (health flag; what was seen was still evicted in order).
    pub quarantine_incomplete: bool,
    /// The plan was made from a truncated prefix of the index, so its rolling-buffer deletes of
    /// hot video were refused (the budget would be computed from an understated total).
    pub rolling_deletes_refused: bool,
    /// A tier (either) holds more segments than the loop plans from: the plan used the oldest-first
    /// prefix (health warning; moves and floor deletes still run).
    pub segments_truncated: bool,
    /// A row-cap delete failed this tick (`DeleteFailed`): a row that cannot be deleted (health
    /// warning). The cap continues past it with its paging cursor and retries it when the
    /// cursor wraps. A row skipped because the archive went away is not a failure.
    pub cap_delete_failed: bool,
    /// The row cap ran out of its own per-tick bound with rows still over the cap.
    pub cap_truncated: bool,
    /// Segments evicted (oldest first) because the rows of both tiers exceeded [`MAX_SEGMENTS`].
    /// They are counted in `deleted` too.
    pub rows_evicted_over_cap: u32,
    /// The hot volume could not be probed after an action; the tick stopped.
    pub hot_probe_failed: bool,
    /// The "archive returned" pass has been unfinished [`RETURNED_PASS_TRIES`] times in a row and
    /// is backed off (a persistent health error until a pass finishes).
    pub returned_pass_unfinished: bool,
    /// The "archive returned" pass of section 9 ran at the end of this tick (it is due on the
    /// tick that reports `archive_returned`, and clears the hold on moves). Its scope is strictly
    /// limited because the recorders are running: only keys with an archive file, a
    /// `tier = archive` row or a `tier = hot` row whose hot file is missing; only the archive
    /// `.part` rule; never a hot `.part`, never a hot-only key, and for a key without a row never
    /// the hot file. `None` on every other
    /// tick, and on the returning tick when the archive was away again at its end (the hold
    /// stays until a tick that can run the pass).
    pub returned: Option<ReconcileReport>,
}

/// Probes, plans and executes. One per process, on one task; it is the only writer of `tier`.
pub struct StorageLoop<I, F, U> {
    cfg: StorageConfig,
    index: SharedIndex<I>,
    fs: F,
    usage: U,
    probe: Probe,
    failures: u32,
    rolling_budget: Option<u64>,
    hot_after_last_tick: Option<u64>,
    index_error_ticks: u32,
    archive_was_available: Option<bool>,
    returned_pending: bool,
    /// Consecutive "archive returned" passes that could not finish (walk cap or index error).
    returned_unfinished: u32,
    /// Ticks since the last unfinished pass, while the pass is backed off.
    returned_wait: u32,
    max_segments: usize,
    max_rows: usize,
    /// Per tier the key of the last row the row cap attempted: the next pass
    /// resumes after it, so stuck rows cannot hold the cap back.
    cap_after: CapCursors,
    /// Ticks, and ticks with a failed cap delete, since the cursors were last cleared.
    cap_cycle_ticks: u32,
    cap_cycle_failures: u32,
    observer: Box<dyn Observer>,
    /// What the API reads (ticket #63): rebuilt after every tick.
    snapshot: StorageSnapshot,
    /// The rows of both tiers as last read; kept when the index cannot be read.
    rows: (TierRows, TierRows),
}

/// How one plan treats the archive.
#[derive(Debug, Clone, Copy, Default)]
struct PlanMode {
    /// The archive counts as unavailable (its true total is unknown).
    archive_unknown: bool,
    /// The "archive returned" hold has outlived an unfinished pass: plan the hot side as if the
    /// archive were unavailable, the emergency reserve acting as a floor.
    held: bool,
    /// Plan with the hot video out of sight (only the archive's own floor).
    archive_only: bool,
}

/// Which tiers were cut to their oldest-first prefix by the segment cap.
#[derive(Debug, Clone, Copy, Default)]
struct Truncated {
    hot: bool,
    archive: bool,
}

impl Truncated {
    const fn any(self) -> bool {
        self.hot || self.archive
    }
}

/// The loop and the `SegmentFiles` implementation that share one index and one archive handle.
pub type Built<I, F, U> = (StorageLoop<I, F, U>, StorageFiles<I>);

/// Builds the loop and the `SegmentFiles` implementation.
pub struct Storage;

impl Storage {
    /// Open the hot root (refusing to start when it is unusable) and build the loop on the real
    /// file system.
    ///
    /// # Errors
    /// [`StorageError::HotRoot`], [`StorageError::NoActions`].
    pub fn open<I, U>(
        cfg: StorageConfig,
        index: I,
        usage: U,
    ) -> Result<Built<I, RealFs, U>, StorageError>
    where
        I: SegmentIndex,
        U: VolumeUsage,
    {
        Self::open_with(cfg, index, usage, |fs| fs)
    }

    /// As [`open`](Self::open), with `wrap` applied to the real file system (tests wrap it in a
    /// fault injector).
    ///
    /// # Errors
    /// As [`open`](Self::open).
    pub fn open_with<I, U, F>(
        cfg: StorageConfig,
        index: I,
        usage: U,
        wrap: impl FnOnce(RealFs) -> F,
    ) -> Result<Built<I, F, U>, StorageError>
    where
        I: SegmentIndex,
        U: VolumeUsage,
        F: Fs,
    {
        if cfg.max_actions_per_tick == 0 {
            return Err(StorageError::NoActions);
        }
        let hot = Arc::new(RootDir::open(&cfg.hot_root).map_err(StorageError::HotRoot)?);
        let slot = Arc::new(ArchiveSlot::default());
        let index = SharedIndex::new(index);
        let files = StorageFiles::new(index.clone(), Arc::clone(&hot), Arc::clone(&slot));
        let probe = Probe::new(
            Arc::clone(&hot),
            &cfg.archive_root,
            Arc::clone(&slot),
            allow_same(&cfg),
        );
        let fs = wrap(RealFs::new(hot, slot));
        let looper = StorageLoop {
            cfg,
            index,
            fs,
            usage,
            probe,
            failures: 0,
            rolling_budget: None,
            hot_after_last_tick: None,
            index_error_ticks: 0,
            archive_was_available: None,
            returned_pending: false,
            returned_unfinished: 0,
            returned_wait: 0,
            max_segments: MAX_SEGMENTS,
            max_rows: MAX_SEGMENTS,
            cap_after: CapCursors::default(),
            cap_cycle_ticks: 0,
            cap_cycle_failures: 0,
            observer: Box::new(NoObserver),
            snapshot: StorageSnapshot::initial(),
            rows: (TierRows::default(), TierRows::default()),
        };
        Ok((looper, files))
    }
}

#[cfg(feature = "test-support")]
const fn allow_same(cfg: &StorageConfig) -> bool {
    cfg.allow_same_filesystem
}

#[cfg(not(feature = "test-support"))]
const fn allow_same(_cfg: &StorageConfig) -> bool {
    false
}

fn archive_state(p: &ArchiveProbe) -> ArchiveState {
    match p {
        ArchiveProbe::Available(space) => ArchiveState::Available(*space),
        _ => ArchiveState::Unavailable,
    }
}

impl<I: SegmentIndex, F: Fs, U: VolumeUsage> StorageLoop<I, F, U> {
    /// Install the observer told before quarantined files are evicted.
    pub fn set_observer(&mut self, observer: Box<dyn Observer>) {
        self.observer = observer;
    }

    /// Consecutive archive-side move failures (three make the archive unavailable).
    #[must_use]
    pub const fn move_failures(&self) -> u32 {
        self.failures
    }

    /// Seed the "was the archive available" state from the start-up probe (ADR 0005 section 9:
    /// start-up probe, then reconciliation, then the loop). Without it the first probe of the
    /// loop is never a return; with `false` the first available probe is, and the "archive
    /// returned" pass is due before any move.
    pub const fn set_initial_archive_state(&mut self, available: bool) {
        self.archive_was_available = Some(available);
    }

    /// Probe, plan and execute at most `max_actions_per_tick` actions, probing again after each.
    /// Quarantine evictions count toward that bound. After the plan the row cap (retention, see
    /// [`MAX_SEGMENTS`]) runs, each of its two tier passes on a bound of its own (the same
    /// `max_actions_per_tick` again), so a tick executes at most three times the bound and the cap
    /// never takes the plan's actions. A segment whose action did not succeed is never retried within the tick and the rest of
    /// the plan still runs.
    ///
    /// **Archive returned.** When any probe sees the archive change from unavailable to
    /// available, [`TickReport::archive_returned`] is reported and no move runs until the
    /// "archive returned" pass (section 9) has run: the loop keeps a *pending* flag that survives
    /// `Err` ticks. A tick that completes `Ok` with the archive available runs the pass itself,
    /// after its plan (the result is [`TickReport::returned`]), and clears the flag unless the
    /// pass hit the walk cap or an index error, in which case it runs again next tick. After
    /// [`RETURNED_PASS_TRIES`] unfinished passes in a row it runs only after
    /// [`RETURNED_PASS_BACKOFF_TICKS`] idle ticks and [`TickReport::returned_pass_unfinished`]
    /// is raised. While the flag is pending a tick plans no moves and evicts no archive video
    /// on behalf of one; once a pass has been unfinished, the hot side is also planned as if the
    /// archive were unavailable (the floor and the emergency reserve deletes run).
    ///
    /// # Errors
    /// [`TickError`]: the hot volume or the index cannot be read, or the planner refused its
    /// input. The next tick starts afresh.
    pub fn tick(&mut self, now: Timestamp) -> Result<TickReport, TickError> {
        // Only the first probe of a tick may clear the move failures.
        let first = self.probe_now(true);
        self.count_breaches(&first);
        if let Err(e) = first.hot {
            let e = TickError::HotVolume(e);
            self.record_tick(now, &first, None, Some(status::error_kind(&e)));
            return Err(e);
        }
        let mut report = TickReport {
            archive: first.archive,
            archive_full: false,
            hot: None,
            moved: 0,
            hot_unlink_left: 0,
            rolled_forward: 0,
            rows_dropped: 0,
            source_quarantined: 0,
            unverified: 0,
            archive_failures: 0,
            index_errors: 0,
            deleted: 0,
            delete_failed: 0,
            twins_left: 0,
            quarantine_evicted: 0,
            skipped: 0,
            truncated: false,
            replans: 0,
            archive_returned: false,
            index_health_error: false,
            segments_truncated: false,
            rows_evicted_over_cap: 0,
            cap_delete_failed: false,
            cap_truncated: false,
            quarantine_incomplete: false,
            rolling_deletes_refused: false,
            hot_probe_failed: false,
            returned: None,
            returned_pass_unfinished: false,
        };
        let mut executed = 0_usize;
        let mut current = first;

        // Quarantined files go first, when their volume is below its floor.
        self.evict_quarantine(&mut current, &mut executed, &mut report);

        let result = self.run_plan(now, &mut current, &mut executed, &mut report);
        report.archive = current.archive;
        // The hold survives an `Err` tick; it ends only when the pass has run to completion.
        report.archive_returned = self.returned_pending;
        // The pass runs on this task, after the plan's actions, so no move is in flight. With the
        // archive away again it cannot run, and the next tick that sees it available runs it. A
        // pass that hit the walk cap or an index error did not finish its work: the hold stays
        // and the pass runs again, but after [`RETURNED_PASS_TRIES`] unfinished passes in a row
        // only after [`RETURNED_PASS_BACKOFF_TICKS`] idle ticks (the walk is not repeated every
        // tick), with a persistent health error until one finishes. A new return runs the pass at
        // once but does not clear that unfinished state; only a finished pass does.
        let mut pass_index_errors = false;
        if result.is_ok() && self.returned_pending && current.archive.is_available() {
            let due = self.returned_unfinished < RETURNED_PASS_TRIES
                || self.returned_wait >= RETURNED_PASS_BACKOFF_TICKS;
            if due {
                let pass = self.run_returned_pass();
                pass_index_errors = pass.index_errors > 0;
                if pass.health_error() || pass.walk_cap_exceeded {
                    self.returned_unfinished = self.returned_unfinished.saturating_add(1);
                    self.returned_wait = 0;
                } else {
                    self.returned_pending = false;
                    self.returned_unfinished = 0;
                    self.returned_wait = 0;
                }
                report.returned = Some(pass);
            } else {
                self.returned_wait = self.returned_wait.saturating_add(1);
            }
        }
        report.returned_pass_unfinished = self.returned_pass_unfinished();
        // Only index failures count toward the index health (not a planner or probe error), the
        // returned pass's included.
        let index_failed =
            report.index_errors > 0 || pass_index_errors || matches!(result, Err(TickError::Index));
        self.index_error_ticks = if index_failed {
            self.index_error_ticks.saturating_add(1)
        } else {
            0
        };
        report.index_health_error = self.index_health_error();
        let kind = result.as_ref().err().map(status::error_kind);
        self.record_tick(now, &current, Some(&report), kind);
        result.map(|()| report)
    }

    /// The snapshot of the latest tick (or of the start, before the first): the volumes of its last
    /// probe, the rows, the archive condition, the counts since start and the floor breaches.
    /// Publish it after every tick.
    #[must_use]
    pub const fn snapshot(&self) -> StorageSnapshot {
        self.snapshot
    }

    /// One more breach per volume the first probe of a tick found under its floor (saturating).
    fn count_breaches(&mut self, first: &ProbeResult) {
        let n = status::breaches(
            first.hot.ok(),
            self.cfg.policy.hot_min_free,
            &first.archive,
            self.cfg.policy.archive_min_free,
        );
        self.snapshot.floor_breaches_total = self.snapshot.floor_breaches_total.saturating_add(n);
    }

    /// Rebuild the snapshot after a tick. `report` is `None` when the tick failed before it had
    /// one. The index is read again here; when that fails the rows of the last good read stay and
    /// the error kind is `index` unless the tick had its own.
    fn record_tick(
        &mut self,
        now: Timestamp,
        probe: &ProbeResult,
        report: Option<&TickReport>,
        error: Option<TickErrorKind>,
    ) {
        let mut error = error;
        match status::read_rows(&self.index) {
            Some(rows) => self.rows = rows,
            None => error = error.or(Some(TickErrorKind::Index)),
        }
        let policy = self.cfg.policy;
        let full = report.is_some_and(|r| r.archive_full);
        let archive_space = match probe.archive {
            ArchiveProbe::Available(space) => Some(space),
            _ => None,
        };
        if let Some(r) = report {
            let unverified = r
                .unverified
                .saturating_add(r.returned.as_ref().map_or(0, |p| p.unverified));
            let quarantined = r
                .source_quarantined
                .saturating_add(r.returned.as_ref().map_or(0, |p| p.quarantined));
            self.add_counts(unverified, quarantined);
        }
        let s = &mut self.snapshot;
        s.hot = status::tier_status(probe.hot.ok(), policy.hot_min_free, &self.rows.0);
        s.archive = status::tier_status(archive_space, policy.archive_min_free, &self.rows.1);
        s.archive_condition = status::archive_condition(&probe.archive, full);
        s.last_tick = Some(now);
        s.last_error = error;
    }

    fn add_counts(&mut self, unverified: u32, quarantined: u32) {
        let s = &mut self.snapshot;
        s.unverified_total = s.unverified_total.saturating_add(u64::from(unverified));
        s.quarantined_total = s.quarantined_total.saturating_add(u64::from(quarantined));
    }

    /// The "archive returned" pass of section 9 (see [`crate::reconcile`]): only keys with an
    /// archive file, a `tier = archive` row or a `tier = hot` row whose hot file is missing;
    /// only the archive `.part` rule; never a hot `.part`, never a hot-only key, and for a key
    /// without a row never the hot file.
    fn run_returned_pass(&self) -> ReconcileReport {
        Reconciler::new(
            &self.fs,
            &self.index,
            Mode::Returned,
            true,
            self.cfg.walk_max_entries,
            self.cfg.walk_max_dir_rows,
        )
        .run()
        .report
    }

    /// The start-up reconciliation of section 9: probe both volumes, then walk the roots and
    /// apply the per-key decision table. Run it once, after the index is open and before the
    /// recorders and [`tick`](Self::tick) start. With the archive unavailable it concludes nothing
    /// from an absent archive file: every archive row and file stays, and the report says so
    /// (the "archive returned" pass resolves them when the archive comes back; this call seeds the
    /// loop so that the first available probe counts as that return).
    ///
    /// The result holds counts (never a name) and the newest key seen per camera, for the
    /// recorder's seed. An entry cap that was exceeded is reported (`walk_cap_exceeded`), not an
    /// error: the service starts anyway.
    ///
    /// # Errors
    /// [`TickError::HotVolume`] when the hot volume cannot be probed.
    pub fn reconcile_startup(&mut self) -> Result<Reconciled, TickError> {
        let p = self.probe_now(true);
        p.hot.map_err(TickError::HotVolume)?;
        let done = Reconciler::new(
            &self.fs,
            &self.index,
            Mode::Startup,
            p.archive.is_available(),
            self.cfg.walk_max_entries,
            self.cfg.walk_max_dir_rows,
        )
        .run();
        self.add_counts(done.report.unverified, done.report.quarantined);
        Ok(done)
    }

    /// The "archive returned" pass could not finish [`RETURNED_PASS_TRIES`] times in a row (the
    /// walk cap or the index): it is backed off, the hold on moves stays, and the hot tier is
    /// planned as if the archive were unavailable. A health error until a pass finishes.
    #[must_use]
    pub const fn returned_pass_unfinished(&self) -> bool {
        self.returned_pending && self.returned_unfinished >= RETURNED_PASS_TRIES
    }

    /// The index failed on [`INDEX_ERROR_TICKS`] consecutive ticks (a health error: the index is
    /// the problem, not the archive).
    #[must_use]
    pub const fn index_health_error(&self) -> bool {
        self.index_error_ticks >= INDEX_ERROR_TICKS
    }

    /// Set the most segments per tier one plan is made from.
    #[cfg(test)]
    pub(crate) const fn set_max_segments(&mut self, n: usize) {
        self.max_segments = n;
    }

    /// Test hook: how many tiers have a row-cap paging cursor set (0 to 2).
    #[cfg(test)]
    pub(crate) fn cap_cursor_count(&self) -> usize {
        [self.cap_after.archive, self.cap_after.hot]
            .iter()
            .flatten()
            .count()
    }

    /// Set the most rows (both tiers together) kept before the oldest are evicted.
    #[cfg(test)]
    pub(crate) const fn set_max_rows(&mut self, n: usize) {
        self.max_rows = n;
    }

    #[cfg(test)]
    pub(crate) fn load_for_test(
        &self,
        page: usize,
        cap: usize,
    ) -> Result<(Vec<StoredSegment>, bool), TickError> {
        self.load_segments_with(page, cap)
            .map(|(v, t)| (v, t.any()))
    }

    /// Test hook: start the breach counter at `n`.
    #[cfg(test)]
    pub(crate) const fn set_breaches_for_test(&mut self, n: u64) {
        self.snapshot.floor_breaches_total = n;
    }

    /// Test hook: hot video bytes left after the last tick's actions.
    #[cfg(test)]
    pub(crate) const fn hot_after_last_tick(&self) -> Option<u64> {
        self.hot_after_last_tick
    }

    /// Test hook: the rolling budget carried to the next tick.
    #[cfg(test)]
    pub(crate) const fn rolling_budget(&self) -> Option<u64> {
        self.rolling_budget
    }

    /// Test hook: one move, bypassing the plan.
    #[cfg(test)]
    pub(crate) fn move_now(&self, id: SegmentId, archive_available: bool) -> Outcome {
        let _ = self.probe.run(&self.usage, self.failures, false);
        Mover {
            fs: &self.fs,
            index: &self.index,
        }
        .move_segment(id, archive_available)
    }

    /// Test hook: one delete, bypassing the plan.
    #[cfg(test)]
    pub(crate) fn delete_now(&self, id: SegmentId, archive_available: bool) -> Outcome {
        let _ = self.probe.run(&self.usage, self.failures, false);
        Mover {
            fs: &self.fs,
            index: &self.index,
        }
        .delete_segment(id, archive_available)
    }

    /// Probe both volumes and record what the probe saw, whichever probe it is (the first of the
    /// tick or one after an action): the failure count and every unavailable to available
    /// transition, which makes the "archive returned" pass (ticket #59) due.
    fn probe_now(&mut self, may_clear: bool) -> ProbeResult {
        let p = self.probe.run(&self.usage, self.failures, may_clear);
        if p.failures_cleared {
            self.failures = 0;
        }
        let available = p.archive.is_available();
        if self.archive_was_available == Some(false) && available {
            self.returned_pending = true;
            // A new return runs the pass at once: only the wait is reset (made due). The count of
            // unfinished passes is sticky (it drives the health error and the degraded hot plan)
            // and only a finished pass clears it.
            self.returned_wait = RETURNED_PASS_BACKOFF_TICKS;
        }
        self.archive_was_available = Some(available);
        p
    }

    fn make_plan(
        &self,
        current: &ProbeResult,
        segments: &[StoredSegment],
        now: Timestamp,
        hot_total: u64,
        mode: PlanMode,
    ) -> Result<wardenlens_core::storage::Plan, TickError> {
        let PlanMode {
            archive_unknown,
            held,
            archive_only,
        } = mode;
        let hot_space = current.hot.map_err(TickError::HotVolume)?;
        let ingested = self
            .hot_after_last_tick
            .map_or(0, |after| hot_total.saturating_sub(after));
        // `archive_only` plans with the hot video out of sight: the planner then plans no move and
        // no eviction on behalf of one, only what the archive's own floor needs.
        let visible: Vec<StoredSegment>;
        let used: &[StoredSegment] = if archive_only {
            visible = segments
                .iter()
                .filter(|s| s.tier != Tier::Hot)
                .copied()
                .collect();
            &visible
        } else {
            segments
        };
        let mut policy = self.cfg.policy;
        if held {
            // While the archive cannot relieve the hot tier, the emergency reserve is a floor
            // too: the recorder keeps writing, and a reserve that only a rolling buffer keeps
            // would let the volume run down to the plain floor and below between ticks.
            // Unreachable goals fall to the planner's own rules (nothing is deleted for them).
            if let Some(p) = reserve_percent(hot_space.capacity_bytes, policy) {
                policy.hot_min_free = policy.hot_min_free.max(p);
            }
        }
        plan(&PlanInput {
            hot: hot_space,
            archive: if archive_unknown || held {
                ArchiveState::Unavailable
            } else {
                archive_state(&current.archive)
            },
            segments: used,
            now,
            policy,
            ingested_bytes: ingested,
            rolling_budget: self.rolling_budget,
        })
        .map_err(TickError::Plan)
    }

    /// Bytes of each tier's video that `actions` delete.
    fn delete_bytes(segments: &[StoredSegment], actions: &[Action]) -> (u64, u64) {
        let by_id: HashMap<SegmentId, &StoredSegment> =
            segments.iter().map(|s| (s.id, s)).collect();
        let (mut hot, mut arch) = (0_u64, 0_u64);
        for a in actions {
            if let Action::Delete(id) = a
                && let Some(s) = by_id.get(id)
            {
                match s.tier {
                    Tier::Hot => hot = hot.saturating_add(s.bytes),
                    _ => arch = arch.saturating_add(s.bytes),
                }
            }
        }
        (hot, arch)
    }

    /// The plan and its actions, then the row cap (retention, never a safety action: it runs
    /// last and has a bound of its own, so it cannot consume the plan's actions).
    fn run_plan(
        &mut self,
        now: Timestamp,
        current: &mut ProbeResult,
        executed: &mut usize,
        report: &mut TickReport,
    ) -> Result<(), TickError> {
        self.plan_and_execute(now, current, executed, report)?;
        if !report.hot_probe_failed {
            self.enforce_row_cap(current, report);
        }
        Ok(())
    }

    #[expect(
        clippy::too_many_lines,
        reason = "one loop: plan, quarantine first, execute, re-probe, replan"
    )]
    fn plan_and_execute(
        &mut self,
        now: Timestamp,
        current: &mut ProbeResult,
        executed: &mut usize,
        report: &mut TickReport,
    ) -> Result<(), TickError> {
        // An action that did not succeed is never retried within the tick. A failed move does not
        // forbid the delete that the floor then demands (a different action).
        let mut failed: HashSet<(SegmentId, bool)> = HashSet::new();
        let mut replans = 0_u32;
        // Quarantine is evicted for a tier's planned deletes once per tier and tick.
        let (mut hot_quarantine_done, mut archive_quarantine_done) = (false, false);
        loop {
            current.hot.map_err(TickError::HotVolume)?;
            let (segments, truncated) = self.load_segments()?;
            report.segments_truncated |= truncated.any();
            let hot_total = segments
                .iter()
                .filter(|s| s.tier == Tier::Hot)
                .try_fold(0_u64, |a, s| a.checked_add(s.bytes))
                .unwrap_or(u64::MAX);
            let planned_available = current.archive.is_available();
            // An archive cut to its prefix would understate its total, and with it the room the
            // planner computes (free plus archive video): see `with_unseen_archive`.
            // If the true total cannot be read, the archive counts as unavailable for this tick's
            // archive-driven decisions (no moves, no archive evictions).
            let (plan_segments, standin, degraded): (Cow<'_, [StoredSegment]>, _, _) =
                if truncated.archive && planned_available {
                    if let Ok((all, id)) = self.with_unseen_archive(&segments) {
                        (Cow::Owned(all), id, false)
                    } else {
                        report.index_errors = report.index_errors.saturating_add(1);
                        (Cow::Borrowed(&segments[..]), None, true)
                    }
                } else {
                    (Cow::Borrowed(&segments[..]), None, false)
                };
            // The loaded rows and their tiers: every executed id must be one of them (the
            // `with_unseen_archive` stand-in, or any unloaded id, is never executed).
            let by_id: HashMap<SegmentId, Tier> = segments.iter().map(|s| (s.id, s.tier)).collect();
            // While the "archive returned" pass is pending no move runs and no archive video is
            // evicted on behalf of one (only the archive's own floor evictions stay). The hot side
            // keeps its plain plan until a pass has been unfinished; then it is planned as if the
            // archive were unavailable (below), so a pass that never finishes cannot starve the
            // hot volume (never ENOSPC).
            let hold = self.returned_pending && planned_available;
            // A hold that has outlived a pass that could not finish no longer waits: the hot side
            // is planned as if the archive were unavailable (the floor and reserve deletes run, so
            // the recorder cannot fill the volume), still with no move. The first held tick of a
            // healthy return keeps the plain hold: its pass finishes that very tick.
            let hold_degraded = hold && self.returned_unfinished > 0;
            let planned = self.make_plan(
                current,
                &plan_segments,
                now,
                hot_total,
                PlanMode {
                    archive_unknown: degraded,
                    held: hold_degraded,
                    archive_only: false,
                },
            )?;
            // The archive's own-floor evictions stay while held (they are not on behalf of a
            // move): the same plan with the hot video out of sight and the archive trusted as the
            // probe saw it.
            let own_floor: Vec<Action> = if hold {
                self.make_plan(
                    current,
                    &plan_segments,
                    now,
                    hot_total,
                    PlanMode {
                        archive_unknown: degraded,
                        held: false,
                        archive_only: true,
                    },
                )?
                .actions
                .iter()
                // Exactly like the plan's actions: a loaded row of the archive, never the
                // stand-in for the unseen rows or any other unloaded id.
                .filter(|a| {
                    matches!(a, Action::Delete(id) if by_id.get(id).is_some_and(|t| *t != Tier::Hot))
                })
                .copied()
                .collect()
            } else {
                Vec::new()
            };
            // The stand-in is never executed: the room it would free is not there, so the moves
            // sized on it wait for the next tick (the visible evictions still run).
            let standin_evicted =
                standin.is_some_and(|id| planned.actions.contains(&Action::Delete(id)));
            // From a truncated hot prefix the rolling buffer's budget is understated: refuse its
            // hot deletes (and say so) rather than delete video on a wrong number. An archive-only
            // truncation does not touch the hot numbers.
            // Degraded (the archive's true total unknown): the plan treated the archive as
            // unavailable, so its floor and reserve hot deletes run (ENOSPC safety outranks a
            // possible move); they are not refused.
            let refuse_hot = truncated.hot && planned.hot == HotState::RollingBuffer;
            let held_plan: Vec<Action> = planned
                .actions
                .iter()
                .copied()
                .filter(|a| match a {
                    Action::MoveToArchive(id) => {
                        !hold && !standin_evicted && by_id.contains_key(id)
                    }
                    Action::Delete(id) => match by_id.get(id) {
                        Some(Tier::Hot) => !refuse_hot,
                        // The stand-in for the unseen rows is never executed.
                        None => false,
                        // The plan's archive deletes are for the moves it holds back.
                        _ => !hold,
                    },
                    _ => true,
                })
                .collect();
            // The archive's own-floor evictions come first (the plan's own archive deletes are
            // dropped while held).
            let actions: Vec<Action> = own_floor.iter().copied().chain(held_plan).collect();
            report.rolling_deletes_refused |= refuse_hot;
            // Quarantine first, whenever the plan deletes a tier's video (any planner state): evict
            // that tier's quarantine, sized to the bytes the plan would delete, then plan again.
            // This plan is discarded when anything was evicted: nothing of it (budget, state)
            // is kept, and the replan sees the freed space through the re-probe.
            let (hot_del, arch_del) = Self::delete_bytes(&segments, &actions);
            let mut evicted_any = false;
            if hot_del > 0 && !hot_quarantine_done {
                hot_quarantine_done = true;
                evicted_any |=
                    self.evict_for_deletes(Tier::Hot, hot_del, current, executed, report);
            }
            if arch_del > 0 && !archive_quarantine_done {
                archive_quarantine_done = true;
                evicted_any |=
                    self.evict_for_deletes(Tier::Archive, arch_del, current, executed, report);
            }
            if evicted_any {
                continue;
            }
            // The plan that is executed: only now are its rolling budget and states kept.
            // Only the budget is withheld when the hot deletes were refused (it was computed from
            // an understated total); the states are always reported.
            if !refuse_hot {
                self.rolling_budget = planned.rolling_budget;
            }
            report.hot = Some(planned.hot);
            report.archive_full = planned.archive == ArchiveStatus::Full;
            let mut hot_left = hot_total;
            let mut replan = false;
            for action in &actions {
                if *executed >= self.cfg.max_actions_per_tick {
                    report.truncated = true;
                    break;
                }
                let (id, is_move) = match *action {
                    Action::MoveToArchive(id) => (id, true),
                    Action::Delete(id) => (id, false),
                    _ => continue,
                };
                if failed.contains(&(id, is_move)) {
                    continue;
                }
                if is_move && self.returned_pending {
                    // The archive just came back: the pass of section 9 runs before any move.
                    continue;
                }
                let tier_bytes = segments
                    .iter()
                    .find(|s| s.id == id)
                    .map(|s| (s.tier, s.bytes));
                let outcome = self.execute(id, is_move, current.archive.is_available());
                *executed = executed.saturating_add(1);
                self.account(outcome, report);
                if !outcome.succeeded() {
                    failed.insert((id, is_move));
                }
                if let Some((Tier::Hot, bytes)) = tier_bytes
                    && outcome.removed_hot_copy()
                {
                    hot_left = hot_left.saturating_sub(bytes);
                }
                // Re-probe after every action.
                *current = self.probe_now(false);
                if current.hot.is_err() {
                    report.hot_probe_failed = true;
                    self.hot_after_last_tick = Some(hot_left);
                    return Ok(());
                }
                if current.archive.is_available() != planned_available && replans < MAX_REPLANS {
                    replans = replans.saturating_add(1);
                    report.replans = replans;
                    replan = true;
                    break;
                }
            }
            self.hot_after_last_tick = Some(hot_left);
            if !replan {
                return Ok(());
            }
        }
    }

    fn execute(&self, id: SegmentId, is_move: bool, archive_available: bool) -> Outcome {
        let mover = Mover {
            fs: &self.fs,
            index: &self.index,
        };
        if is_move {
            mover.move_segment(id, archive_available)
        } else {
            mover.delete_segment(id, archive_available)
        }
    }

    fn account(&mut self, outcome: Outcome, report: &mut TickReport) {
        let bump = |c: &mut u32| *c = c.saturating_add(1);
        match outcome {
            Outcome::Moved => {
                bump(&mut report.moved);
                self.failures = 0;
            }
            Outcome::MovedHotLeft => {
                bump(&mut report.moved);
                bump(&mut report.hot_unlink_left);
                self.failures = 0;
            }
            Outcome::RolledForward => bump(&mut report.rolled_forward),
            Outcome::RowDropped(_) => bump(&mut report.rows_dropped),
            Outcome::SourceQuarantined => bump(&mut report.source_quarantined),
            Outcome::Unverified => bump(&mut report.unverified),
            Outcome::ArchiveFailure(_) => {
                bump(&mut report.archive_failures);
                self.failures = self.failures.saturating_add(1);
            }
            Outcome::IndexError => bump(&mut report.index_errors),
            Outcome::Deleted => bump(&mut report.deleted),
            Outcome::DeletedTwinLeft => {
                bump(&mut report.deleted);
                bump(&mut report.twins_left);
            }
            Outcome::DeleteFailed => bump(&mut report.delete_failed),
            Outcome::Skipped(_) => bump(&mut report.skipped),
        }
    }

    /// `segments` plus one stand-in archive segment that carries the bytes of the archive rows the
    /// cap cut off (the true archive total from the index, minus the loaded bytes), so the plan's
    /// archive `room` is computed from the true total. The stand-in is newer than every loaded
    /// row, so the planner takes it last, and it is never executed (its id is in no row). Hot
    /// deletes are decided from the hot rows only, so a truncated archive no longer deletes hot
    /// video the archive could take, and the archive's floor is restored from the visible oldest
    /// rows tick after tick.
    ///
    /// Chosen over refusing hot deletes while truncated: that would leave the archive below its
    /// floor for good (no eviction would ever be planned from a wrong `room`).
    fn with_unseen_archive(
        &self,
        segments: &[StoredSegment],
    ) -> Result<(Vec<StoredSegment>, Option<SegmentId>), TickError> {
        let totals = self.index.totals().map_err(|_| TickError::Index)?;
        let mut visible = 0_u64;
        let mut newest = None;
        let mut max_id = 0_u64;
        for s in segments {
            max_id = max_id.max(s.id.as_u64());
            if s.tier == Tier::Archive {
                visible = visible.saturating_add(s.bytes);
                newest = newest.max(Some(s.ended_at));
            }
        }
        let mut all = segments.to_vec();
        let mut standin = None;
        let unseen = totals.archive.bytes.saturating_sub(visible);
        if let (true, Some(ended_at), Some(id)) = (unseen > 0, newest, max_id.checked_add(1)) {
            standin = Some(SegmentId::new(id));
            all.push(StoredSegment {
                id: SegmentId::new(id),
                tier: Tier::Archive,
                bytes: unseen,
                ended_at,
            });
        }
        Ok((all, standin))
    }

    /// The retention bound on rows, run after the plan's actions with a bound of its own (the
    /// same `max_actions_per_tick`).
    ///
    /// With the archive available the rows of both tiers together may not exceed `max_rows`: the
    /// oldest deletable archive rows go first, and the hot tier gives only what is left above the
    /// archive's row count (`excess - archive_rows`). With the archive unavailable only the hot
    /// tier's own excess goes. Archive rows that cannot be deleted never cost hot video: the
    /// shortfall stays over the cap and is reported (`cap_delete_failed`, `cap_truncated`).
    /// Deletes use the normal protocol.
    ///
    /// Each tier pass has a bound of its own and a paging cursor carried across ticks (see
    /// `evict_oldest`). The cursors are cleared when the cap has nothing to do, when a pass wraps
    /// at the end of a tier, and, so that stuck rows are retried while new rows keep arriving
    /// behind the cursor, after `CAP_RETRY_TICKS` ticks for each failure of the cycle (a rare
    /// retry, so the stuck rows never take the bound from the deletable rows for long).
    fn enforce_row_cap(&mut self, current: &mut ProbeResult, report: &mut TickReport) {
        self.row_cap_passes(current, report);
        self.cap_cycle_ticks = self.cap_cycle_ticks.saturating_add(1);
        if report.cap_delete_failed {
            self.cap_cycle_failures = self.cap_cycle_failures.saturating_add(1);
        }
        let due =
            self.cap_cycle_ticks >= CAP_RETRY_TICKS.saturating_mul(self.cap_cycle_failures.max(1));
        if due || self.cap_after.is_clear() {
            self.cap_after = CapCursors::default();
            self.cap_cycle_ticks = 0;
            self.cap_cycle_failures = 0;
        }
    }

    fn row_cap_passes(&mut self, current: &mut ProbeResult, report: &mut TickReport) {
        let Ok(totals) = self.index.totals() else {
            report.index_errors = report.index_errors.saturating_add(1);
            return;
        };
        let rows = |n: u64| usize::try_from(n).unwrap_or(usize::MAX);
        let (hot_rows, archive_rows) = (rows(totals.hot.segments), rows(totals.archive.segments));
        let (from_archive, from_hot) = if current.archive.is_available() {
            let excess = hot_rows
                .saturating_add(archive_rows)
                .saturating_sub(self.max_rows);
            let a = excess.min(archive_rows);
            (a, excess.saturating_sub(a))
        } else {
            (0, hot_rows.saturating_sub(self.max_rows))
        };
        if from_archive > 0
            && self
                .evict_oldest(Tier::Archive, from_archive, current, report)
                .is_none()
        {
            return;
        }
        if from_hot > 0 {
            self.evict_oldest(Tier::Hot, from_hot, current, report);
        }
    }

    /// Delete up to `count` of `tier`'s oldest rows, attempting each row at most once per cycle.
    ///
    /// The tier has a paging cursor (`cap_after`) carried across ticks: the pass starts after the
    /// last row attempted, attempts rows oldest first until it has evicted `count` or spent the
    /// pass's own bound, and wraps to the oldest row at the end of the tier (once, up to where it
    /// started). A row whose delete fails (`DeleteFailed`) is skipped and counted, so any number
    /// of stuck rows cannot hold the cap back. Rows keyed behind the cursor (older than the last
    /// attempt) are not looked at again until the cursor wraps or is cleared (see
    /// `enforce_row_cap`), so the cap may evict newer rows before an older stuck one. Other
    /// outcomes (a stale row, an index error) are skipped without a flag; an archive that went
    /// away stops the archive pass without moving the cursor past the row.
    ///
    /// Returns the rows evicted, or `None` when the cap must stop for the tick: a failed read,
    /// the archive gone or a failed hot probe.
    fn evict_oldest(
        &mut self,
        tier: Tier,
        count: usize,
        current: &mut ProbeResult,
        report: &mut TickReport,
    ) -> Option<usize> {
        let mut used = 0_usize;
        let start = self.cap_after.get(tier);
        let mut after = start;
        let mut wrapped = false;
        let mut left = count;
        while left > 0 {
            let want = left.min(MAX_OLDEST);
            let Ok(page) = self.index.oldest(tier, after, want) else {
                report.index_errors = report.index_errors.saturating_add(1);
                return None;
            };
            let short = page.len() < want;
            for seg in &page {
                let key = (seg.ended_at, seg.id);
                if wrapped && start.is_some_and(|s| key > s) {
                    // A full cycle: everything up to where this pass started was attempted.
                    self.cap_after.set(tier, None);
                    return Some(count.saturating_sub(left));
                }
                if used >= self.cfg.max_actions_per_tick {
                    // Out of bound: what is left waits (the caller still takes the rest from the
                    // hot tier, which has its own bound).
                    report.cap_truncated = true;
                    return Some(count.saturating_sub(left));
                }
                used = used.saturating_add(1);
                let outcome = self.execute(seg.id, false, current.archive.is_available());
                self.account(outcome, report);
                if outcome == Outcome::Skipped(Skip::ArchiveUnavailable) {
                    // Not a failure and not attempted: the cursor stays before this row.
                    return None;
                }
                self.cap_after.set(tier, Some(key));
                after = Some(key);
                if outcome == Outcome::DeleteFailed {
                    report.cap_delete_failed = true;
                }
                if !outcome.succeeded() {
                    continue;
                }
                report.rows_evicted_over_cap = report.rows_evicted_over_cap.saturating_add(1);
                if tier == Tier::Hot {
                    self.hot_after_last_tick = self
                        .hot_after_last_tick
                        .map(|h| h.saturating_sub(seg.bytes));
                }
                *current = self.probe_now(false);
                if current.hot.is_err() {
                    report.hot_probe_failed = true;
                    return None;
                }
                left = left.saturating_sub(1);
                if left == 0 {
                    break;
                }
            }
            if left > 0 && short {
                // The end of the tier: the next pass starts at the oldest row.
                self.cap_after.set(tier, None);
                if wrapped || start.is_none() {
                    break;
                }
                wrapped = true;
                after = None;
            }
        }
        Some(count.saturating_sub(left))
    }

    /// Page through both tiers (`oldest` is bounded per call, SEC-2). A tier above the cap
    /// yields its oldest `cap` segments and `true`: the planner consumes oldest first anyway.
    fn load_segments(&self) -> Result<(Vec<StoredSegment>, Truncated), TickError> {
        self.load_segments_with(MAX_OLDEST, self.max_segments)
    }

    fn load_segments_with(
        &self,
        page: usize,
        cap: usize,
    ) -> Result<(Vec<StoredSegment>, Truncated), TickError> {
        let mut all = Vec::new();
        let mut truncated = Truncated::default();
        for tier in [Tier::Hot, Tier::Archive] {
            let start = all.len();
            let mut after = None;
            loop {
                let rows = self
                    .index
                    .oldest(tier, after, page)
                    .map_err(|_| TickError::Index)?;
                let full = rows.len() == page;
                after = rows.last().map(|s| (s.ended_at, s.id));
                all.extend(rows);
                if all.len().saturating_sub(start) > cap {
                    all.truncate(start.saturating_add(cap));
                    match tier {
                        Tier::Hot => truncated.hot = true,
                        _ => truncated.archive = true,
                    }
                    break;
                }
                if !full {
                    break;
                }
            }
        }
        Ok((all, truncated))
    }

    /// Before the plan: delete quarantined files of a volume below its floor, oldest first, when
    /// reaching the floor is possible at all (section 6 eviction order; the plan may then need to
    /// delete less video, or none). Counts toward the per-tick bound, failed attempts included.
    fn evict_quarantine(
        &mut self,
        current: &mut ProbeResult,
        executed: &mut usize,
        report: &mut TickReport,
    ) {
        let Ok(totals) = self.index.totals() else {
            // Without the true totals the reachability cannot be judged: skip, and count the
            // index error.
            report.index_errors = report.index_errors.saturating_add(1);
            return;
        };
        for tier in [Tier::Hot, Tier::Archive] {
            let (space, floor, deletable) = match tier {
                Tier::Hot => (
                    current.hot.ok(),
                    self.cfg.policy.hot_min_free.get(),
                    totals.hot.bytes,
                ),
                _ => match current.archive {
                    ArchiveProbe::Available(s) => (
                        Some(s),
                        self.cfg.policy.archive_min_free.get(),
                        totals.archive.bytes,
                    ),
                    _ => (None, 0, 0),
                },
            };
            let Some(space) = space else { continue };
            if !evict::below_floor(&space, floor) {
                continue;
            }
            let Some(sel) = evict::select(
                &self.fs,
                tier,
                &space,
                floor,
                deletable,
                &mut report.quarantine_incomplete,
            ) else {
                continue;
            };
            self.evict_files(tier, &sel.files, Some(sel.goal), current, executed, report);
        }
    }

    /// After a plan that deletes `need` bytes of `tier`'s video: delete that tier's quarantine
    /// first, oldest first, up to `need` bytes (all of it when that is less). No reachability
    /// gate: the plan deletes video anyway, so the evidence goes first. Returns whether anything
    /// was deleted (the caller plans again).
    fn evict_for_deletes(
        &mut self,
        tier: Tier,
        need: u64,
        current: &mut ProbeResult,
        executed: &mut usize,
        report: &mut TickReport,
    ) -> bool {
        let sized = evict::scan_sized(&self.fs, tier);
        report.quarantine_incomplete |= sized.incomplete;
        let files = evict::prefix(&sized.files, need);
        self.evict_files(tier, &files, None, current, executed, report) > 0
    }

    /// Delete `files` oldest first, stopping early at `goal` free bytes. The observer is told
    /// before the first deletion, with the number that can actually be attempted within the
    /// per-tick bound.
    fn evict_files(
        &mut self,
        tier: Tier,
        files: &[Candidate],
        goal: Option<u64>,
        current: &mut ProbeResult,
        executed: &mut usize,
        report: &mut TickReport,
    ) -> usize {
        if files.is_empty() {
            return 0;
        }
        let room = self.cfg.max_actions_per_tick.saturating_sub(*executed);
        if room == 0 {
            report.truncated = true;
            return 0;
        }
        self.observer
            .quarantine_eviction(tier, files.len().min(room));
        let mut evicted = 0_usize;
        for c in files {
            if *executed >= self.cfg.max_actions_per_tick {
                report.truncated = true;
                break;
            }
            *executed = executed.saturating_add(1);
            if !self.evict_one(tier, c) {
                continue;
            }
            evicted = evicted.saturating_add(1);
            report.quarantine_evicted = report.quarantine_evicted.saturating_add(1);
            *current = self.probe_now(false);
            if let Some(goal) = goal {
                match tier_space(current, tier) {
                    Some(s) if s.free_bytes < goal => {}
                    _ => break,
                }
            }
        }
        evicted
    }

    fn evict_one(&self, tier: Tier, c: &Candidate) -> bool {
        let dir = c.dir();
        self.fs.unlink(tier, &dir, &c.name).is_ok() && {
            let _ = self.fs.sync_dir(tier, &dir);
            true
        }
    }
}

/// The row cap's paging cursor per tier: the key of the last row attempted.
#[derive(Debug, Clone, Copy, Default)]
struct CapCursors {
    archive: Option<(Timestamp, SegmentId)>,
    hot: Option<(Timestamp, SegmentId)>,
}

impl CapCursors {
    const fn is_clear(&self) -> bool {
        self.archive.is_none() && self.hot.is_none()
    }

    const fn get(&self, tier: Tier) -> Option<(Timestamp, SegmentId)> {
        match tier {
            Tier::Hot => self.hot,
            _ => self.archive,
        }
    }

    const fn set(&mut self, tier: Tier, key: Option<(Timestamp, SegmentId)>) {
        match tier {
            Tier::Hot => self.hot = key,
            _ => self.archive = key,
        }
    }
}

fn tier_space(p: &ProbeResult, tier: Tier) -> Option<VolumeSpace> {
    match tier {
        Tier::Hot => p.hot.ok(),
        _ => match p.archive {
            ArchiveProbe::Available(s) => Some(s),
            _ => None,
        },
    }
}

/// The reserve as a whole percent of the hot capacity, rounded up (capped at the largest
/// accepted floor), or `None` for no reserve.
fn reserve_percent(
    capacity: u64,
    policy: Policy,
) -> Option<wardenlens_core::storage::MinFreePercent> {
    let reserve = policy.emergency_reserve_bytes;
    if reserve == 0 || capacity == 0 {
        return None;
    }
    let pct = u128::from(reserve)
        .checked_mul(100)?
        .div_ceil(u128::from(capacity));
    let pct = u8::try_from(pct.min(u128::from(MinFreePercent::MAX))).ok()?;
    MinFreePercent::new(pct).ok()
}

#[cfg(test)]
mod reserve_tests {
    use super::*;

    fn pol(reserve: u64) -> Policy {
        Policy {
            emergency_reserve_bytes: reserve,
            ..Policy::default()
        }
    }
    fn pct(capacity: u64, reserve: u64) -> Option<u8> {
        reserve_percent(capacity, pol(reserve)).map(MinFreePercent::get)
    }

    #[test]
    fn reserve_percent_covers_zero_rounding_and_the_cap() {
        assert_eq!(pct(1000, 0), None, "no reserve");
        assert_eq!(pct(0, 100), None, "zero capacity");
        assert_eq!(pct(1000, 100), Some(10), "a whole percent");
        assert_eq!(pct(1000, 101), Some(11), "rounds up");
        assert_eq!(pct(1000, 1), Some(1), "a tiny reserve is one percent");
        assert_eq!(pct(1000, 900), Some(90), "the cap exactly");
        assert_eq!(pct(1000, 901), Some(90), "capped at the largest floor");
        assert_eq!(pct(1000, u64::MAX), Some(90), "no overflow");
    }
}
