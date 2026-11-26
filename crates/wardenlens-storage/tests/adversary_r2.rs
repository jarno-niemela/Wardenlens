//! Adversarial tests for #58 round 2 (PR #156). Public API only, temporary directories only.
#![expect(
    clippy::unwrap_used,
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    reason = "test code: small bounded synthetic values"
)]

use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use wardenlens_core::camera::CameraId;
use wardenlens_core::recording::{RelPath, SegmentRecord};
use wardenlens_core::storage::{
    IndexedSegment, MinFreePercent, Policy, SegmentCursor, SegmentFiles, SegmentId, SegmentIndex,
    SegmentOpenError, SegmentPage, StoredSegment, Tier, TierTotals, VolumeSpace,
};
use wardenlens_core::time::{DurationMs, Timestamp, UnixMs};
use wardenlens_fsutil::RootDir;
use wardenlens_index::Index;
use wardenlens_storage::{
    ARCHIVE_MARKER, ProbeError, Storage, StorageConfig, TickError, VolumeUsage,
};

const T0: i64 = 1_700_000_000_000;
const SEG: usize = 100_000;

fn du(dir: &Path) -> u64 {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return 0;
    };
    rd.flatten()
        .map(|e| {
            let m = e.path().symlink_metadata().unwrap();
            if m.is_dir() { du(&e.path()) } else { m.len() }
        })
        .sum()
}

/// Measures two directories against pretend capacities; the hot probe can be made to fail.
struct Fake {
    hot: PathBuf,
    arch: PathBuf,
    hot_cap: u64,
    arch_cap: u64,
    fail_hot: Arc<AtomicBool>,
}

impl VolumeUsage for Fake {
    fn space(&self, tier: Tier, _root: &RootDir) -> Result<VolumeSpace, ProbeError> {
        let (dir, cap) = match tier {
            Tier::Hot => {
                if self.fail_hot.load(Ordering::SeqCst) {
                    return Err(ProbeError::Io(Some(rustix::io::Errno::IO)));
                }
                (&self.hot, self.hot_cap)
            }
            _ => (&self.arch, self.arch_cap),
        };
        Ok(VolumeSpace {
            capacity_bytes: cap,
            free_bytes: cap.saturating_sub(du(dir)),
        })
    }
}

/// The real index, whose `oldest` can be made to fail (a transient `SQLITE_BUSY`, say).
struct Flaky {
    inner: Index,
    fail_oldest: Arc<AtomicBool>,
}

#[derive(Debug)]
struct Busy;
impl std::fmt::Display for Busy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("busy")
    }
}
impl std::error::Error for Busy {}

fn wrap<T, E>(r: Result<T, E>) -> Result<T, Busy> {
    r.map_err(|_| Busy)
}

impl SegmentIndex for Flaky {
    type Error = Busy;
    fn insert(&mut self, record: &SegmentRecord, tier: Tier) -> Result<SegmentId, Busy> {
        wrap(self.inner.insert(record, tier))
    }
    fn get(&self, id: SegmentId) -> Result<Option<IndexedSegment>, Busy> {
        wrap(self.inner.get(id))
    }
    fn list(
        &self,
        camera: &CameraId,
        from: Timestamp,
        to: Timestamp,
        limit: usize,
        cursor: Option<&SegmentCursor>,
    ) -> Result<SegmentPage, Busy> {
        wrap(self.inner.list(camera, from, to, limit, cursor))
    }
    fn set_tier(&mut self, id: SegmentId, tier: Tier) -> Result<(), Busy> {
        wrap(self.inner.set_tier(id, tier))
    }
    fn delete(&mut self, id: SegmentId) -> Result<(), Busy> {
        wrap(self.inner.delete(id))
    }
    fn oldest(
        &self,
        tier: Tier,
        after: Option<(Timestamp, SegmentId)>,
        n: usize,
    ) -> Result<Vec<StoredSegment>, Busy> {
        if self.fail_oldest.load(Ordering::SeqCst) {
            return Err(Busy);
        }
        wrap(self.inner.oldest(tier, after, n))
    }
    fn bytes_by_tier(&self) -> Result<TierTotals, Busy> {
        wrap(self.inner.bytes_by_tier())
    }
    fn latest_started_at(&self, camera: &CameraId) -> Result<Option<UnixMs>, Busy> {
        wrap(self.inner.latest_started_at(camera))
    }
}

struct World {
    _tmp: tempfile::TempDir,
    hot: PathBuf,
    arch: PathBuf,
    index: Index,
}

fn mkdir(p: &Path) {
    std::fs::DirBuilder::new().mode(0o700).create(p).unwrap();
}

fn cam() -> CameraId {
    "cam-1".parse().unwrap()
}

fn rel(n: i64) -> String {
    RelPath::new(&cam(), UnixMs::new(T0 + n * 60_000).unwrap()).to_string()
}

impl World {
    fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let (hot, arch, idx) = (
            tmp.path().join("hot"),
            tmp.path().join("arch"),
            tmp.path().join("idx"),
        );
        for d in [&hot, &arch, &idx] {
            mkdir(d);
        }
        std::fs::write(arch.join(ARCHIVE_MARKER), b"").unwrap();
        let index = Index::open(&idx.join("index.db")).unwrap();
        Self {
            _tmp: tmp,
            hot,
            arch,
            index,
        }
    }

    fn add(&mut self, n: i64, tier: Tier) -> SegmentId {
        let start = UnixMs::new(T0 + n * 60_000).unwrap();
        let root = if tier == Tier::Hot {
            &self.hot
        } else {
            &self.arch
        };
        let p = root.join(rel(n));
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, vec![7_u8; SEG]).unwrap();
        let rec = SegmentRecord::new(cam(), start, 1000, SEG as u64, 30);
        self.index.insert(&rec, tier).unwrap()
    }

    fn cfg(&self) -> StorageConfig {
        StorageConfig::new(
            self.hot.clone(),
            self.arch.clone(),
            Policy {
                hot_min_free: MinFreePercent::new(25).unwrap(),
                archive_min_free: MinFreePercent::new(25).unwrap(),
                hot_max_age: DurationMs::from_secs(12 * 3600),
                emergency_reserve_bytes: 0,
            },
        )
        .with_allow_same_filesystem(true)
    }

    fn fake(&self, hot_cap: u64, arch_cap: u64) -> (Fake, Arc<AtomicBool>) {
        let fail = Arc::new(AtomicBool::new(false));
        (
            Fake {
                hot: self.hot.clone(),
                arch: self.arch.clone(),
                hot_cap,
                arch_cap,
                fail_hot: Arc::clone(&fail),
            },
            fail,
        )
    }

    fn marker(&self) -> PathBuf {
        self.arch.join(ARCHIVE_MARKER)
    }
}

/// Every segment is past `hot_max_age`: the planner moves all of them without pressure.
fn aged() -> Timestamp {
    Timestamp::from_unix_millis(T0 + 100 * 3_600_000)
}

fn tier_of(files: &impl SegmentFiles, id: SegmentId) -> Result<Tier, SegmentOpenError> {
    files.open_segment(id).map(|o| o.tier())
}

// ---------------------------------------------------------------------------------------------
// "archive returned" must not be lost when the returning tick fails.

#[test]
fn archive_returned_survives_a_returning_tick_that_fails_on_the_index() {
    // ADR 0005 section 8: "When the state changes from unavailable to available, the storage
    // loop first runs the 'archive returned' pass ... and only then plans moves."
    // The transition is consumed by the probe even when the tick then returns Err.
    let mut w = World::new();
    let id = w.add(0, Tier::Hot);
    std::fs::remove_file(w.marker()).unwrap();
    let fail = Arc::new(AtomicBool::new(false));
    let marker = w.marker();
    let (usage, _) = w.fake(100_000_000, 100_000_000);
    let cfg = w.cfg();
    let index = Flaky {
        inner: w.index,
        fail_oldest: Arc::clone(&fail),
    };
    let (mut lp, files) = Storage::open(cfg, index, usage).unwrap();

    let r = lp.tick(aged()).unwrap();
    assert!(!r.archive.is_available(), "{r:?}");
    assert_eq!(r.moved, 0);

    // The archive comes back on a tick whose index read is busy.
    std::fs::write(&marker, b"").unwrap();
    fail.store(true, Ordering::SeqCst);
    assert!(matches!(lp.tick(aged()), Err(TickError::Index)));
    fail.store(false, Ordering::SeqCst);

    // The next tick must still know the pass is due, and must not move before it.
    let r = lp.tick(aged()).unwrap();
    assert!(
        r.archive_returned || r.moved == 0,
        "the return was lost: moves ran with no 'archive returned' pass: {r:?}"
    );
    let _ = tier_of(&files, id);
}

#[test]
fn archive_returned_survives_a_returning_tick_whose_hot_probe_fails() {
    let mut w = World::new();
    w.add(0, Tier::Hot);
    std::fs::remove_file(w.marker()).unwrap();
    let marker = w.marker();
    let (usage, fail_hot) = w.fake(100_000_000, 100_000_000);
    let (mut lp, _files) = Storage::open(w.cfg(), w.index, usage).unwrap();

    let r = lp.tick(aged()).unwrap();
    assert!(!r.archive.is_available(), "{r:?}");

    std::fs::write(&marker, b"").unwrap();
    fail_hot.store(true, Ordering::SeqCst);
    assert!(matches!(lp.tick(aged()), Err(TickError::HotVolume(_))));
    fail_hot.store(false, Ordering::SeqCst);

    let r = lp.tick(aged()).unwrap();
    assert!(
        r.archive_returned || r.moved == 0,
        "the return was lost: moves ran with no 'archive returned' pass: {r:?}"
    );
}

// ---------------------------------------------------------------------------------------------
// Minimality: a returning tick holds every move back, so it must not evict archive video to
// make room for those moves.

#[test]
fn a_returning_tick_evicts_no_archive_video_for_moves_it_holds_back() {
    let mut w = World::new();
    // Archive: 3 x 100 kB of 500 kB, free 200 kB, floor 125 kB: above its floor. A 100 kB move
    // would leave 100 kB, below it, so the planner evicts archive video *for the move*.
    let archived: Vec<_> = (0..3).map(|n| w.add(n, Tier::Archive)).collect();
    let hot = w.add(10, Tier::Hot);
    std::fs::remove_file(w.marker()).unwrap();
    let marker = w.marker();
    let (usage, _) = w.fake(100_000_000, 500_000);
    let (mut lp, files) = Storage::open(w.cfg(), w.index, usage).unwrap();

    let r = lp.tick(aged()).unwrap();
    assert!(!r.archive.is_available(), "{r:?}");
    assert_eq!((r.moved, r.deleted), (0, 0), "{r:?}");

    std::fs::write(&marker, b"").unwrap();
    let r = lp.tick(aged()).unwrap();
    assert!(r.archive_returned, "{r:?}");
    assert_eq!(r.moved, 0, "no move in the returning tick: {r:?}");
    assert_eq!(
        r.deleted, 0,
        "archive video evicted to make room for a move that the same tick holds back: {r:?}"
    );
    assert_eq!(tier_of(&files, archived[0]), Ok(Tier::Archive));
    assert_eq!(tier_of(&files, hot), Ok(Tier::Hot));
}

#[test]
fn an_archive_below_its_own_floor_is_still_evicted_in_a_returning_tick() {
    // Control for the test above: eviction because the archive itself is below its floor is not
    // tied to a move and may run.
    let mut w = World::new();
    let archived: Vec<_> = (0..4).map(|n| w.add(n, Tier::Archive)).collect();
    std::fs::remove_file(w.marker()).unwrap();
    let marker = w.marker();
    // 400 kB of 500 kB: free 100 kB < floor 125 kB.
    let (usage, _) = w.fake(100_000_000, 500_000);
    let (mut lp, files) = Storage::open(w.cfg(), w.index, usage).unwrap();
    let _ = lp.tick(aged()).unwrap();
    std::fs::write(&marker, b"").unwrap();
    let r = lp.tick(aged()).unwrap();
    assert!(r.archive_returned);
    assert!(r.deleted >= 1, "{r:?}");
    assert_eq!(
        tier_of(&files, archived[0]).unwrap_err(),
        SegmentOpenError::NotFound,
        "oldest first"
    );
}

// ---------------------------------------------------------------------------------------------
// Failure accounting across ticks.

#[test]
fn a_healthy_tick_after_a_return_moves_everything_aged_and_keeps_rows_and_files_in_step() {
    let mut w = World::new();
    let ids: Vec<_> = (0..5).map(|n| w.add(n, Tier::Hot)).collect();
    std::fs::remove_file(w.marker()).unwrap();
    let marker = w.marker();
    let (hot_root, arch_root) = (w.hot.clone(), w.arch.clone());
    let (usage, _) = w.fake(100_000_000, 100_000_000);
    let (mut lp, files) = Storage::open(w.cfg(), w.index, usage).unwrap();
    let _ = lp.tick(aged()).unwrap();
    std::fs::write(&marker, b"").unwrap();
    let r = lp.tick(aged()).unwrap();
    assert_eq!(r.moved, 0);
    let r = lp.tick(aged()).unwrap();
    assert_eq!(r.moved, 5, "{r:?}");
    for (n, id) in (0_i64..).zip(ids.iter()) {
        assert_eq!(tier_of(&files, *id), Ok(Tier::Archive));
        assert!(!hot_root.join(rel(n)).exists(), "M9 unlinked the hot copy");
        assert!(arch_root.join(rel(n)).exists());
    }
    assert_eq!(lp.move_failures(), 0);
}
