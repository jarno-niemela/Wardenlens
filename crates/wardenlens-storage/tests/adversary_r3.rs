//! Adversarial tests for #58 round 3 (PR #156). Public API only, temporary directories only.
#![expect(
    clippy::unwrap_used,
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    reason = "test code: small bounded synthetic values"
)]

use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};

use wardenlens_core::camera::CameraId;
use wardenlens_core::recording::{RelPath, SegmentRecord};
use wardenlens_core::storage::{
    MinFreePercent, Policy, SegmentFiles, SegmentId, SegmentIndex, SegmentOpenError, Tier,
    VolumeSpace,
};
use wardenlens_core::time::{DurationMs, Timestamp, UnixMs};
use wardenlens_fsutil::RootDir;
use wardenlens_index::Index;
use wardenlens_storage::{ARCHIVE_MARKER, ProbeError, Storage, StorageConfig, VolumeUsage};

const T0: i64 = 1_700_000_000_000;

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

struct Fake {
    hot: PathBuf,
    arch: PathBuf,
    hot_cap: u64,
    arch_cap: u64,
}

impl VolumeUsage for Fake {
    fn space(&self, tier: Tier, _root: &RootDir) -> Result<VolumeSpace, ProbeError> {
        let (dir, cap) = match tier {
            Tier::Hot => (&self.hot, self.hot_cap),
            _ => (&self.arch, self.arch_cap),
        };
        Ok(VolumeSpace {
            capacity_bytes: cap,
            free_bytes: cap.saturating_sub(du(dir)),
        })
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

    fn add(&mut self, n: i64, tier: Tier, bytes: usize) -> SegmentId {
        let start = UnixMs::new(T0 + n * 60_000).unwrap();
        let root = if tier == Tier::Hot {
            &self.hot
        } else {
            &self.arch
        };
        let p = root.join(rel(n));
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, vec![7_u8; bytes]).unwrap();
        let rec = SegmentRecord::new(cam(), start, 1000, bytes as u64, 30);
        self.index.insert(&rec, tier).unwrap()
    }

    fn quarantine(root: &Path, name: &str, bytes: usize) -> PathBuf {
        let d = root.join("_quarantine/cam-1/2023-11-12");
        std::fs::create_dir_all(&d).unwrap();
        let p = d.join(name);
        std::fs::write(&p, vec![9_u8; bytes]).unwrap();
        p
    }

    fn cfg(&self, reserve: u64) -> StorageConfig {
        StorageConfig::new(
            self.hot.clone(),
            self.arch.clone(),
            Policy {
                hot_min_free: MinFreePercent::new(25).unwrap(),
                archive_min_free: MinFreePercent::new(25).unwrap(),
                hot_max_age: DurationMs::from_secs(12 * 3600),
                emergency_reserve_bytes: reserve,
            },
        )
        .with_allow_same_filesystem(true)
    }

    fn fake(&self, hot_cap: u64, arch_cap: u64) -> Fake {
        Fake {
            hot: self.hot.clone(),
            arch: self.arch.clone(),
            hot_cap,
            arch_cap,
        }
    }
}

/// Recent: nothing is past `hot_max_age`.
fn fresh() -> Timestamp {
    Timestamp::from_unix_millis(T0 + 10 * 60_000)
}

fn tier_of(files: &impl SegmentFiles, id: SegmentId) -> Result<Tier, SegmentOpenError> {
    files.open_segment(id).map(|o| o.tier())
}

/// Hot 1 MB, floor 25 % (250 kB). 760 kB foreign data, three 50 kB segments: the floor cannot be
/// reached even with every segment and the quarantine gone (rolling buffer, archive unavailable).
/// Emergency reserve 80 kB.
fn rolling_world(quarantine: bool) -> (World, Vec<SegmentId>, Option<PathBuf>) {
    let mut w = World::new();
    std::fs::remove_file(w.arch.join(ARCHIVE_MARKER)).unwrap();
    std::fs::write(w.hot.join("foreign"), vec![0_u8; 760_000]).unwrap();
    let ids: Vec<_> = (0..3).map(|n| w.add(n, Tier::Hot, 50_000)).collect();
    let q = quarantine.then(|| {
        let hot = w.hot.clone();
        World::quarantine(&hot, "000000-000.mp4", 30_000)
    });
    (w, ids, q)
}

#[test]
fn control_without_quarantine_a_met_reserve_deletes_nothing() {
    // free = 1000 - 760 - 150 = 90 kB >= 80 kB: no delete at all.
    let (w, ids, _) = rolling_world(false);
    let usage = w.fake(1_000_000, 100_000_000);
    let (mut lp, files) = Storage::open(w.cfg(80_000), w.index, usage).unwrap();
    let r = lp.tick(fresh()).unwrap();
    assert_eq!(r.deleted, 0, "{r:?}");
    for id in ids {
        assert_eq!(tier_of(&files, id), Ok(Tier::Hot));
    }
}

#[test]
fn a_quarantine_eviction_that_restores_the_reserve_deletes_no_hot_video() {
    // free = 1000 - 760 - 150 - 30 = 60 kB < reserve 80 kB. The first plan of the tick deletes
    // one 50 kB segment for the reserve and ratchets the rolling budget down to 100 kB. The
    // round-3 rule then evicts the 30 kB quarantine first and plans again: free is now 90 kB, the
    // reserve holds, and the tick began with no budget (hot video 150 kB) - so nothing should be
    // deleted. The ratcheted budget of the discarded first plan must not leak into the replan.
    let (w, ids, q) = rolling_world(true);
    let usage = w.fake(1_000_000, 100_000_000);
    let (mut lp, files) = Storage::open(w.cfg(80_000), w.index, usage).unwrap();
    let r = lp.tick(fresh()).unwrap();
    assert_eq!(r.quarantine_evicted, 1, "{r:?}");
    assert!(!q.unwrap().exists());
    assert_eq!(
        r.deleted, 0,
        "hot video deleted although the quarantine eviction alone restored the reserve: {r:?}"
    );
    for id in &ids {
        assert_eq!(tier_of(&files, *id), Ok(Tier::Hot));
    }
}

#[test]
fn a_quarantine_eviction_that_restores_the_reserve_does_not_lower_the_budget_for_later_ticks() {
    // Over several ticks with no ingest the hot video must stay where the reserve allows it.
    let (w, ids, _) = rolling_world(true);
    let usage = w.fake(1_000_000, 100_000_000);
    let (mut lp, files) = Storage::open(w.cfg(80_000), w.index, usage).unwrap();
    let mut deleted = 0;
    for _ in 0..4 {
        let r = lp.tick(fresh()).unwrap();
        deleted += r.deleted;
        assert_ne!(r.hot, None, "{r:?}");
    }
    let left = ids
        .iter()
        .filter(|id| tier_of(&files, **id) == Ok(Tier::Hot))
        .count();
    assert_eq!(
        (deleted, left),
        (0, 3),
        "video deleted for a reserve that the quarantine eviction already restored"
    );
}

#[test]
fn a_returning_tick_deletes_no_hot_video_and_the_next_tick_moves_instead_of_deleting() {
    // The rolling buffer was active while the archive was away; when it returns, the hot video
    // must go to the archive (after the held tick), never be deleted.
    let (w, ids, _) = rolling_world(false);
    let marker = w.arch.join(ARCHIVE_MARKER);
    let usage = w.fake(1_000_000, 100_000_000);
    // Reserve 100 kB: free 90 kB, so the unavailable tick deletes one segment.
    let (mut lp, files) = Storage::open(w.cfg(100_000), w.index, usage).unwrap();
    let r = lp.tick(fresh()).unwrap();
    assert!(!r.archive.is_available(), "{r:?}");
    assert_eq!(r.deleted, 1, "{r:?}");
    std::fs::write(&marker, b"").unwrap();
    let r = lp.tick(fresh()).unwrap();
    assert!(r.archive_returned, "{r:?}");
    assert_eq!((r.moved, r.deleted), (0, 0), "{r:?}");
    let r = lp.tick(fresh()).unwrap();
    assert!(!r.archive_returned, "{r:?}");
    assert_eq!(r.deleted, 0, "{r:?}");
    assert!(r.moved >= 1, "{r:?}");
    let surviving: Vec<_> = ids
        .iter()
        .filter_map(|id| tier_of(&files, *id).ok())
        .collect();
    assert_eq!(
        surviving.len(),
        2,
        "only the unavailable tick deleted video"
    );
}
