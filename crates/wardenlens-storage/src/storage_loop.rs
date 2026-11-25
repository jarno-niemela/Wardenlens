//! `StorageLoop::tick`: probe, plan, execute, re-probe after each action, at most N actions.

use std::collections::HashSet;
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

/// Most segments the loop holds in memory for one plan (SEC-2): about 40 MB.
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
    /// The archive changed from unavailable to available on this tick's first probe: the
    /// "archive returned" pass of section 9 (ticket #59) is due before any move is planned.
    pub archive_returned: bool,
    /// The index failed on [`INDEX_ERROR_TICKS`] consecutive ticks.
    pub index_health_error: bool,
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
    archive_was_available: bool,
    observer: Box<dyn Observer>,
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
            cfg.allow_same_filesystem,
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
            archive_was_available: false,
            observer: Box::new(NoObserver),
        };
        Ok((looper, files))
    }
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

    /// Probe, plan and execute at most `max_actions_per_tick` actions, probing again after each.
    /// A segment whose action did not succeed is never retried within the tick and the rest of
    /// the plan still runs.
    ///
    /// # Errors
    /// [`TickError`]: the hot volume or the index cannot be read, or the planner refused its
    /// input. The next tick starts afresh.
    pub fn tick(&mut self, now: Timestamp) -> Result<TickReport, TickError> {
        let first = self.probe.run(&self.usage, self.failures);
        first.hot.map_err(TickError::HotVolume)?;
        self.note_probe(&first);
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
            quarantine_evicted: 0,
            skipped: 0,
            truncated: false,
            replans: 0,
            archive_returned: first.archive.is_available() && !self.archive_was_available,
            index_health_error: false,
            hot_probe_failed: false,
        };
        self.archive_was_available = first.archive.is_available();
        let mut executed = 0_usize;
        let mut current = first;

        // Quarantined files go first, when their volume is below its floor.
        self.evict_quarantine(&mut current, &mut executed, &mut report);

        let result = self.run_plan(now, &mut current, &mut executed, &mut report);
        self.index_error_ticks = if report.index_errors > 0 || result.is_err() {
            self.index_error_ticks.saturating_add(1)
        } else {
            0
        };
        report.index_health_error = self.index_error_ticks >= INDEX_ERROR_TICKS;
        report.archive = current.archive;
        result.map(|()| report)
    }

    #[cfg(test)]
    pub(crate) fn load_for_test(
        &self,
        page: usize,
        cap: usize,
    ) -> Result<Vec<StoredSegment>, TickError> {
        self.load_segments_with(page, cap)
    }

    /// Test hook: the rolling budget carried to the next tick.
    #[cfg(test)]
    pub(crate) const fn rolling_budget(&self) -> Option<u64> {
        self.rolling_budget
    }

    /// Test hook: one move, bypassing the plan.
    #[cfg(test)]
    pub(crate) fn move_now(&self, id: SegmentId, archive_available: bool) -> Outcome {
        let _ = self.probe.run(&self.usage, self.failures);
        Mover {
            fs: &self.fs,
            index: &self.index,
        }
        .move_segment(id, archive_available)
    }

    /// Test hook: one delete, bypassing the plan.
    #[cfg(test)]
    pub(crate) fn delete_now(&self, id: SegmentId, archive_available: bool) -> Outcome {
        let _ = self.probe.run(&self.usage, self.failures);
        Mover {
            fs: &self.fs,
            index: &self.index,
        }
        .delete_segment(id, archive_available)
    }

    fn note_probe(&mut self, p: &ProbeResult) {
        if p.failures_cleared {
            self.failures = 0;
        }
    }

    fn run_plan(
        &mut self,
        now: Timestamp,
        current: &mut ProbeResult,
        executed: &mut usize,
        report: &mut TickReport,
    ) -> Result<(), TickError> {
        let mut failed: HashSet<SegmentId> = HashSet::new();
        let mut replans = 0_u32;
        loop {
            let hot_space = current.hot.map_err(TickError::HotVolume)?;
            let segments = self.load_segments()?;
            let hot_total = segments
                .iter()
                .filter(|s| s.tier == Tier::Hot)
                .try_fold(0_u64, |a, s| a.checked_add(s.bytes))
                .unwrap_or(u64::MAX);
            let ingested = self
                .hot_after_last_tick
                .map_or(0, |after| hot_total.saturating_sub(after));
            let planned_available = current.archive.is_available();
            let planned = plan(&PlanInput {
                hot: hot_space,
                archive: archive_state(&current.archive),
                segments: &segments,
                now,
                policy: self.cfg.policy,
                ingested_bytes: ingested,
                rolling_budget: self.rolling_budget,
            })
            .map_err(TickError::Plan)?;
            self.rolling_budget = planned.rolling_budget;
            report.hot = Some(planned.hot);
            report.archive_full = planned.archive == ArchiveStatus::Full;
            let mut hot_left = hot_total;
            let mut replan = false;
            for action in &planned.actions {
                if *executed >= self.cfg.max_actions_per_tick {
                    report.truncated = true;
                    break;
                }
                let (id, is_move) = match *action {
                    Action::MoveToArchive(id) => (id, true),
                    Action::Delete(id) => (id, false),
                    _ => continue,
                };
                if failed.contains(&id) {
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
                    failed.insert(id);
                }
                if let Some((Tier::Hot, bytes)) = tier_bytes
                    && outcome.removed_hot_copy()
                {
                    hot_left = hot_left.saturating_sub(bytes);
                }
                // Re-probe after every action.
                let again = self.probe.run(&self.usage, self.failures);
                self.note_probe(&again);
                *current = again;
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
            Outcome::DeleteFailed => bump(&mut report.delete_failed),
            Outcome::Skipped(_) => bump(&mut report.skipped),
        }
    }

    /// Page through both tiers (`oldest` is bounded per call, SEC-2) and cap the total.
    fn load_segments(&self) -> Result<Vec<StoredSegment>, TickError> {
        self.load_segments_with(MAX_OLDEST, MAX_SEGMENTS)
    }

    fn load_segments_with(&self, page: usize, cap: usize) -> Result<Vec<StoredSegment>, TickError> {
        let mut all = Vec::new();
        for tier in [Tier::Hot, Tier::Archive] {
            let mut after = None;
            loop {
                let rows = self
                    .index
                    .oldest(tier, after, page)
                    .map_err(|_| TickError::Index)?;
                let full = rows.len() == page;
                after = rows.last().map(|s| (s.ended_at, s.id));
                all.extend(rows);
                if all.len() > cap {
                    return Err(TickError::TooManySegments);
                }
                if !full {
                    break;
                }
            }
        }
        Ok(all)
    }

    /// Delete quarantined files of a volume that is below its floor, oldest first, until the
    /// volume is back at floor plus headroom. Counts toward the per-tick bound.
    fn evict_quarantine(
        &mut self,
        current: &mut ProbeResult,
        executed: &mut usize,
        report: &mut TickReport,
    ) {
        for tier in [Tier::Hot, Tier::Archive] {
            let (space, floor) = match tier {
                Tier::Hot => (current.hot.ok(), self.cfg.policy.hot_min_free.get()),
                _ => match current.archive {
                    ArchiveProbe::Available(s) => (Some(s), self.cfg.policy.archive_min_free.get()),
                    _ => (None, 0),
                },
            };
            let Some(space) = space else { continue };
            if !evict::below_floor(&space, floor) {
                continue;
            }
            let Some(sel) = evict::select(&self.fs, tier, &space, floor) else {
                continue;
            };
            self.observer.quarantine_eviction(tier, sel.files.len());
            for c in &sel.files {
                if *executed >= self.cfg.max_actions_per_tick {
                    report.truncated = true;
                    return;
                }
                if !self.evict_one(tier, c) {
                    continue;
                }
                *executed = executed.saturating_add(1);
                report.quarantine_evicted = report.quarantine_evicted.saturating_add(1);
                *current = self.probe.run(&self.usage, self.failures);
                self.note_probe(current);
                match tier_space(current, tier) {
                    Some(s) if s.free_bytes < sel.goal => {}
                    _ => break,
                }
            }
        }
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
