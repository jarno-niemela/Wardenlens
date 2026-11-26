//! `StorageLoop::tick`: probe, plan, execute, re-probe after each action, at most N actions.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use wardenlens_core::storage::{
    Action, ArchiveState, ArchiveStatus, HotState, MAX_OLDEST, PlanInput, SegmentId, SegmentIndex,
    StoredSegment, Tier, VolumeSpace, plan,
};
use wardenlens_core::time::Timestamp;
use wardenlens_fsutil::RootDir;

use crate::config::StorageConfig;
use crate::error::{StorageError, TickError};
use crate::evict::{self, Candidate};
use crate::files::StorageFiles;
use crate::fs::{ArchiveSlot, Fs, RealFs};
use crate::index::SharedIndex;
use crate::mover::{Mover, Outcome};
use crate::probe::{ArchiveProbe, Probe, ProbeResult, VolumeUsage};

/// The cap on segment rows (SEC-2; ADR 0005 section 6). It bounds the memory of one plan (about
/// 40 MB per tier) and is enforced as a retention bound, after the plan's actions and with its
/// own per-tick bound. With the archive available, rows of both tiers together above it are
/// evicted oldest first (archive first, then hot); with the archive unavailable only the hot
/// tier's own excess is (hot video is never deleted because of archive rows). In normal
/// operation no tier then exceeds it and the plan never sees a truncated prefix. If a tier still does (rows
/// added from outside, faster than evicted), the plan is made from the oldest-first prefix, the
/// unseen archive rows are accounted for by their true total, and the report says so.
pub const MAX_SEGMENTS: usize = 1_000_000;
/// Consecutive ticks with an index error after which the report carries a health error.
pub const INDEX_ERROR_TICKS: u32 = 3;
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
    /// Segments evicted (oldest first) because the rows of both tiers exceeded [`MAX_SEGMENTS`].
    /// They are counted in `deleted` too.
    pub rows_evicted_over_cap: u32,
    /// The hot volume could not be probed after an action; the tick stopped.
    pub hot_probe_failed: bool,
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
    max_segments: usize,
    max_rows: usize,
    observer: Box<dyn Observer>,
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
            max_segments: MAX_SEGMENTS,
            max_rows: MAX_SEGMENTS,
            observer: Box::new(NoObserver),
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
    /// A segment whose action did not succeed is never retried within the tick and the rest of
    /// the plan still runs.
    ///
    /// **Archive returned.** When any probe sees the archive change from unavailable to
    /// available, [`TickReport::archive_returned`] is reported and no move runs until the pass of
    /// ticket #59 had its tick: the loop keeps a *pending* flag that survives `Err` ticks and is
    /// cleared only by a tick that completes `Ok` (and reports it). While it is pending a tick
    /// plans no moves and evicts no archive video on behalf of one. The caller runs the pass on
    /// the tick that reports it, before the next tick.
    ///
    /// # Errors
    /// [`TickError`]: the hot volume or the index cannot be read, or the planner refused its
    /// input. The next tick starts afresh.
    pub fn tick(&mut self, now: Timestamp) -> Result<TickReport, TickError> {
        // Only the first probe of a tick may clear the move failures.
        let first = self.probe_now(true);
        first.hot.map_err(TickError::HotVolume)?;
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
            quarantine_incomplete: false,
            rolling_deletes_refused: false,
            hot_probe_failed: false,
        };
        let mut executed = 0_usize;
        let mut current = first;

        // Quarantined files go first, when their volume is below its floor.
        self.evict_quarantine(&mut current, &mut executed, &mut report);

        let result = self.run_plan(now, &mut current, &mut executed, &mut report);
        // Only index failures count toward the index health (not a planner or probe error).
        let index_failed = report.index_errors > 0 || matches!(result, Err(TickError::Index));
        self.index_error_ticks = if index_failed {
            self.index_error_ticks.saturating_add(1)
        } else {
            0
        };
        report.index_health_error = self.index_health_error();
        report.archive = current.archive;
        // The flag survives an `Err` tick: it is cleared only by a tick that completes `Ok` and
        // reports it.
        report.archive_returned = self.returned_pending;
        result.map(|()| {
            self.returned_pending = false;
            report
        })
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
        archive_only: bool,
        archive_unknown: bool,
    ) -> Result<wardenlens_core::storage::Plan, TickError> {
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
        plan(&PlanInput {
            hot: hot_space,
            archive: if archive_unknown {
                ArchiveState::Unavailable
            } else {
                archive_state(&current.archive)
            },
            segments: used,
            now,
            policy: self.cfg.policy,
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
            let (plan_segments, standin, degraded) = if truncated.archive && planned_available {
                if let Ok((all, id)) = self.with_unseen_archive(&segments) {
                    (all, id, false)
                } else {
                    report.index_errors = report.index_errors.saturating_add(1);
                    (segments.clone(), None, true)
                }
            } else {
                (segments.clone(), None, false)
            };
            let planned =
                self.make_plan(current, &plan_segments, now, hot_total, false, degraded)?;
            // The stand-in is never executed: the room it would free is not there, so the moves
            // sized on it wait for the next tick (the visible evictions still run).
            let standin_evicted =
                standin.is_some_and(|id| planned.actions.contains(&Action::Delete(id)));
            // From a truncated hot prefix the rolling buffer's budget is understated: refuse its
            // hot deletes (and say so) rather than delete video on a wrong number. An archive-only
            // truncation does not touch the hot numbers.
            // Degraded (the archive's true total unknown): only the rolling buffer's and reserve's
            // hot deletes run; a floor delete the archive might have absorbed waits.
            let rolling = planned.hot == HotState::RollingBuffer;
            let refuse_hot = (truncated.hot && rolling) || (degraded && !rolling);
            let by_id: HashMap<SegmentId, Tier> = segments.iter().map(|s| (s.id, s.tier)).collect();
            // While the "archive returned" pass is pending no move runs, and no archive video is
            // evicted on behalf of one: only the evictions the archive's own floor needs stay.
            // Hot deletes stay (the rolling buffer must not be halved by a flapping archive).
            let hold = self.returned_pending && planned_available;
            let own_floor: HashSet<SegmentId> = if hold {
                self.make_plan(current, &plan_segments, now, hot_total, true, degraded)?
                    .actions
                    .iter()
                    .filter_map(|a| match a {
                        Action::Delete(id) => Some(*id),
                        _ => None,
                    })
                    .collect()
            } else {
                HashSet::new()
            };
            let actions: Vec<Action> = planned
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
                        _ => !hold || own_floor.contains(id),
                    },
                    _ => true,
                })
                .collect();
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
    /// same `max_actions_per_tick`). With the archive available the rows of both tiers together
    /// may not exceed `max_rows`: the oldest archive rows go first, then the oldest hot rows
    /// (in the same tick) once none are left. With the archive unavailable only the hot tier's
    /// own excess goes: archive rows are never a reason to delete the only copy of hot video.
    /// Deletes use the normal protocol. The first failed delete ends the cap for the tick.
    fn enforce_row_cap(&mut self, current: &mut ProbeResult, report: &mut TickReport) {
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
        let mut used = 0_usize;
        for (tier, count) in [(Tier::Archive, from_archive), (Tier::Hot, from_hot)] {
            if count > 0 && !self.evict_oldest(tier, count, &mut used, current, report) {
                return;
            }
        }
    }

    /// Delete the `count` oldest rows of `tier`. `false` when the cap must stop for the tick: a
    /// failed delete or read, a failed hot probe, or the bound.
    fn evict_oldest(
        &mut self,
        tier: Tier,
        count: usize,
        used: &mut usize,
        current: &mut ProbeResult,
        report: &mut TickReport,
    ) -> bool {
        let mut left = count;
        let mut after = None;
        while left > 0 {
            let want = left.min(MAX_OLDEST);
            let Ok(page) = self.index.oldest(tier, after, want) else {
                report.index_errors = report.index_errors.saturating_add(1);
                return false;
            };
            after = page.last().map(|s| (s.ended_at, s.id));
            let short = page.len() < want;
            for seg in page {
                if *used >= self.cfg.max_actions_per_tick {
                    report.truncated = true;
                    return false;
                }
                *used = used.saturating_add(1);
                let outcome = self.execute(seg.id, false, current.archive.is_available());
                self.account(outcome, report);
                if !outcome.succeeded() {
                    return false;
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
                    return false;
                }
                left = left.saturating_sub(1);
            }
            if short {
                break;
            }
        }
        true
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

fn tier_space(p: &ProbeResult, tier: Tier) -> Option<VolumeSpace> {
    match tier {
        Tier::Hot => p.hot.ok(),
        _ => match p.archive {
            ArchiveProbe::Available(s) => Some(s),
            _ => None,
        },
    }
}
