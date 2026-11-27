//! The bounded walk: `<root>/<camera>/<day>/<file>`, one `(camera, day)` directory at a time.
//!
//! Depth is fixed: a directory below a day directory is never entered (the deepest thing the
//! service writes is `_quarantine/<camera>/<day>/<file>`, depth 4, and the quarantine is read
//! only for the keys it holds). Symlinks are never followed (`openat2` with
//! `RESOLVE_NO_SYMLINKS` under the `Fs` trait; the listing's kind is only a hint). The entry cap
//! is shared by both roots.

use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;

use rustix::io::Errno;
use wardenlens_core::camera::CameraId;
use wardenlens_core::recording::RelPath;
use wardenlens_core::storage::{IndexedSegment, MAX_OLDEST, SegmentId, SegmentIndex, Tier};
use wardenlens_core::time::UnixMs;
use wardenlens_fsutil::{DirEntry, FileKind, FsError, QUARANTINE_DIR};

use super::{Mode, Reconciler, bump};
use crate::evict;
use crate::fs::Fs;
use crate::index::Rel;
use crate::probe::{ARCHIVE_MARKER, HOT_LOCK_FILE, PROBE_FILE};

/// Most entries one directory may hold (SEC-2): a day directory holds about 1,440 files per
/// camera, so this is far above anything legitimate and bounds the memory of one listing.
pub(crate) const MAX_DIR_ENTRIES: usize = 200_000;

const MS_PER_DAY: i64 = 86_400_000;

/// The entry cap (or the per-directory bound) was exceeded: the walk stops.
#[derive(Debug, Clone, Copy)]
pub(super) struct Capped;

enum Listed {
    Entries(Vec<DirEntry>),
    /// `ENOENT`: there is no such directory (on this tier).
    Gone,
    /// `ENOTDIR` or `ELOOP`: a non-directory (or a symlink) where a directory should be.
    NotDir,
    /// Any other error: no conclusion about this directory.
    Failed,
}

/// What a name in a day directory is.
enum Name {
    /// A canonical `<HHMMSS>-<mmm>.mp4`.
    Segment(UnixMs),
    /// A canonical `<HHMMSS>-<mmm>.mp4.part`.
    Part,
    /// Anything else, including a name that matches the pattern but is not canonical.
    Foreign,
}

fn classify(camera: &str, day: &str, name: &str) -> Name {
    let (stem, part) = name
        .strip_suffix(".part")
        .map_or((name, false), |s| (s, true));
    // The strict parse round-trips the name, so `996099-000.mp4` (minute 60) or `240000-000.mp4`
    // (hour 24) is `Foreign`, never adopted or deleted.
    match RelPath::from_str(&format!("{camera}/{day}/{stem}")) {
        Ok(_) if part => Name::Part,
        Ok(p) => Name::Segment(p.started_at()),
        Err(_) => Name::Foreign,
    }
}

/// The start of the day `day` of `camera`, in Unix milliseconds, when `day` is a real date.
fn day_start(camera: &str, day: &str) -> Option<i64> {
    RelPath::from_str(&format!("{camera}/{day}/000000-000.mp4"))
        .ok()
        .map(|p| p.started_at().as_i64())
}

#[derive(Default)]
struct Slot {
    row: Option<IndexedSegment>,
    /// An archive file of this key was listed.
    arch: bool,
}

impl<F: Fs, I: SegmentIndex> Reconciler<'_, F, I> {
    fn list(&mut self, tier: Tier, dir: &[&str]) -> Result<Listed, Capped> {
        let max = self.budget.min(MAX_DIR_ENTRIES);
        match self.fs.list_dir(tier, dir, max) {
            Ok(v) => {
                // Names that cannot be returned (not UTF-8) were seen: they are charged to the
                // budget and are not ours, so they are `unknown_left`.
                self.budget = self
                    .budget
                    .saturating_sub(v.entries.len().saturating_add(v.dropped));
                for _ in 0..v.dropped {
                    bump(&mut self.report.unknown_left);
                }
                Ok(Listed::Entries(v.entries))
            }
            Err(FsError::TooManyEntries) => Err(Capped),
            Err(e) if e.is_not_found() => Ok(Listed::Gone),
            Err(e) if matches!(e.errno(), Some(Errno::NOTDIR | Errno::LOOP)) => Ok(Listed::NotDir),
            Err(_) => Ok(Listed::Failed),
        }
    }

    fn mark_unverified(&mut self, tier: Tier) {
        bump(&mut self.report.unverified);
        match tier {
            Tier::Hot => self.report.hot_unverified = true,
            _ => self.report.archive_unverified = true,
        }
    }

    /// The directories of one level that are ours: `accept` says whether a name is (anything
    /// else is `unknown_left`), and a non-directory is `unknown_left` too.
    fn dirs_of(
        &mut self,
        tier: Tier,
        dir: &[&str],
        accept: impl Fn(&str) -> bool,
        skip: impl Fn(&str) -> bool,
    ) -> Result<BTreeSet<String>, Capped> {
        let mut out = BTreeSet::new();
        match self.list(tier, dir)? {
            Listed::Entries(v) => {
                for e in v {
                    if skip(&e.name) {
                        continue;
                    }
                    if accept(&e.name) && matches!(e.kind, FileKind::Directory | FileKind::Other) {
                        out.insert(e.name);
                    } else {
                        bump(&mut self.report.unknown_left);
                    }
                }
            }
            Listed::Gone => {}
            Listed::NotDir => bump(&mut self.report.unknown_left),
            Listed::Failed => self.mark_unverified(tier),
        }
        Ok(out)
    }

    fn camera_dirs(&mut self, tier: Tier) -> Result<BTreeSet<String>, Capped> {
        self.dirs_of(
            tier,
            &[],
            |n| CameraId::new(n).is_ok(),
            |n| {
                // Ours, but not a camera: the quarantine, the hot root's lock file, the archive's marker and probe file.
                n == QUARANTINE_DIR
                    || (tier == Tier::Hot && n == HOT_LOCK_FILE)
                    || (tier == Tier::Archive && (n == ARCHIVE_MARKER || n == PROBE_FILE))
            },
        )
    }

    fn day_dirs(&mut self, tier: Tier, camera: &str) -> Result<BTreeSet<String>, Capped> {
        self.dirs_of(
            tier,
            &[camera],
            |n| day_start(camera, n).is_some(),
            |_| false,
        )
    }

    /// Walk the roots and apply the cells to every key of every `(camera, day)` directory.
    pub(super) fn walk(&mut self) -> Result<(), Capped> {
        let scan_hot = self.mode == Mode::Startup;
        let hot = if scan_hot {
            self.camera_dirs(Tier::Hot)?
        } else {
            BTreeSet::new()
        };
        let arch = if self.archive {
            self.camera_dirs(Tier::Archive)?
        } else {
            BTreeSet::new()
        };
        let cameras: BTreeSet<&String> = hot.iter().chain(arch.iter()).collect();
        for cam in cameras {
            let Ok(camera) = CameraId::new(cam) else {
                continue;
            };
            let hot_days = if hot.contains(cam) {
                self.day_dirs(Tier::Hot, cam)?
            } else {
                BTreeSet::new()
            };
            let arch_days = if arch.contains(cam) {
                self.day_dirs(Tier::Archive, cam)?
            } else {
                BTreeSet::new()
            };
            let days: BTreeSet<&String> = hot_days.iter().chain(arch_days.iter()).collect();
            for day in days {
                let (in_hot, in_arch) = (hot_days.contains(day), arch_days.contains(day));
                self.unit(cam, &camera, day, in_hot, in_arch)?;
            }
        }
        Ok(())
    }

    /// One `(camera, day)` directory: its files on both tiers and its rows.
    fn unit(
        &mut self,
        cam: &str,
        camera: &CameraId,
        day: &str,
        in_hot: bool,
        in_arch: bool,
    ) -> Result<(), Capped> {
        self.visited.insert((cam.to_owned(), day.to_owned()));
        let Some(day_ms) = day_start(cam, day) else {
            return Ok(());
        };
        let mut keys: BTreeMap<UnixMs, Slot> = BTreeMap::new();
        let mut hot_parts = Vec::new();
        let mut arch_parts = Vec::new();
        let mut failed = false;
        for (tier, present) in [(Tier::Hot, in_hot), (Tier::Archive, in_arch)] {
            if !present {
                continue;
            }
            match self.list(tier, &[cam, day])? {
                Listed::Entries(v) => {
                    for e in v {
                        match classify(cam, day, &e.name) {
                            Name::Segment(ms) => {
                                self.newest.note(cam, ms);
                                keys.entry(ms).or_default().arch |= tier == Tier::Archive;
                            }
                            Name::Part if tier == Tier::Hot => hot_parts.push(e.name),
                            Name::Part => arch_parts.push(e.name),
                            Name::Foreign => bump(&mut self.report.unknown_left),
                        }
                    }
                }
                Listed::Gone => {}
                Listed::NotDir => bump(&mut self.report.unknown_left),
                Listed::Failed => {
                    // Nothing is concluded from a directory that could not be listed.
                    self.mark_unverified(tier);
                    failed = true;
                }
            }
        }
        if failed {
            return Ok(());
        }
        let Some(day_end) = day_ms.checked_add(MS_PER_DAY) else {
            return Ok(());
        };
        let rows = match self
            .index
            .rows_started_in(camera, day_ms, day_end, self.max_dir_rows)
        {
            Ok((_, true)) => return Err(Capped),
            Ok((rows, false)) => rows,
            Err(_) => {
                self.index_failed();
                return Ok(());
            }
        };
        self.rows_seen = self
            .rows_seen
            .saturating_add(u64::try_from(rows.len()).unwrap_or(u64::MAX));
        for row in rows {
            self.seen_ids.insert(row.id);
            let started = row.record.started_at_ms;
            keys.entry(started).or_default().row = Some(row);
        }
        // `.part` files first: an interrupted segment (hot) or move (archive).
        if self.mode == Mode::Startup {
            self.delete_parts(Tier::Hot, cam, day, &hot_parts);
        }
        if self.archive {
            self.delete_parts(Tier::Archive, cam, day, &arch_parts);
        }
        let returned = self.mode == Mode::Returned;
        for (started, slot) in keys {
            // The returned pass looks only at keys with an archive file or a row.
            if returned && !slot.arch && slot.row.is_none() {
                continue;
            }
            let hot_gate =
                returned && !slot.arch && slot.row.as_ref().is_some_and(|r| r.tier == Tier::Hot);
            let Some(rel) = Rel::from_key(camera, started) else {
                bump(&mut self.report.unverified);
                continue;
            };
            self.key(&rel, slot.row.as_ref(), hot_gate);
        }
        Ok(())
    }

    /// Delete the `.part` files of one directory (regular files only; anything else is left).
    fn delete_parts(&mut self, tier: Tier, cam: &str, day: &str, names: &[String]) {
        let mut deleted = false;
        for name in names {
            match self.fs.open_read(tier, &[cam, day, name]) {
                Ok(file) => {
                    drop(file);
                    match self.fs.unlink(tier, &[cam, day], name) {
                        Ok(()) => {
                            bump(&mut self.report.part_deleted);
                            deleted = true;
                        }
                        Err(e) if e.is_not_found() => {}
                        Err(_) => bump(&mut self.report.unverified),
                    }
                }
                Err(e) if e.is_not_found() => {}
                Err(FsError::NotRegular) => bump(&mut self.report.unknown_left),
                Err(e) if e.errno() == Some(Errno::LOOP) => bump(&mut self.report.unknown_left),
                Err(_) => bump(&mut self.report.unverified),
            }
        }
        if deleted {
            // Best effort: a `.part` that comes back is deleted again.
            let _ = self.fs.sync_dir(tier, &[cam, day]);
        }
    }

    /// Rows whose `(camera, day)` directory the walk did not process (the directory is missing on
    /// every observed tier): evaluated by direct opens, so a row never survives only because its
    /// directory is gone. With the archive unobservable an archive row is kept and counted.
    pub(super) fn rows_without_a_directory(&mut self) {
        for tier in [Tier::Hot, Tier::Archive] {
            let mut after = None;
            loop {
                let Ok(page) = self.index.oldest(tier, after, MAX_OLDEST) else {
                    self.index_failed();
                    break;
                };
                for s in &page {
                    after = Some((s.ended_at, s.id));
                    self.row_without_a_directory(s.id);
                }
                if page.len() < MAX_OLDEST {
                    break;
                }
            }
        }
    }

    fn row_without_a_directory(&mut self, id: SegmentId) {
        // Handled through its directory already: no read needed.
        if self.seen_ids.contains(&id) {
            return;
        }
        let row = match self.index.get(id) {
            Ok(Some(row)) => row,
            Ok(None) => return,
            Err(_) => {
                self.index_failed();
                return;
            }
        };
        let Some(rel) = Rel::of(&row) else {
            bump(&mut self.report.unverified);
            return;
        };
        if self
            .visited
            .contains(&(rel.camera.clone(), rel.day.clone()))
        {
            return;
        }
        let hot_gate = self.mode == Mode::Returned && row.tier == Tier::Hot;
        self.key(&rel, Some(&row), hot_gate);
    }

    /// The walk stopped at the cap: every row not handled through a directory is `unverified`
    /// (nothing is concluded from the part that was not seen).
    pub(super) fn count_unseen_rows(&mut self) {
        match self.index.totals() {
            Ok(t) => {
                let all = t.hot.segments.saturating_add(t.archive.segments);
                let unseen = all.saturating_sub(self.rows_seen);
                self.report.unverified = self
                    .report
                    .unverified
                    .saturating_add(u32::try_from(unseen).unwrap_or(u32::MAX));
            }
            Err(_) => self.index_failed(),
        }
    }

    /// The keys of quarantined files, for the recorder's seed.
    pub(super) fn note_quarantined_keys(&mut self) {
        let tiers: &[Tier] = if self.archive {
            &[Tier::Hot, Tier::Archive]
        } else {
            &[Tier::Hot]
        };
        for &tier in tiers {
            let (found, _) = evict::scan(self.fs, tier);
            for c in found {
                if let Some((cam, key)) = c.key() {
                    self.newest.note(&cam, key);
                }
            }
        }
    }
}
