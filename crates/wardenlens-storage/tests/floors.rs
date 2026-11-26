//! Integration: two temporary directories and a fake `VolumeUsage` source. Only the public API.
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
const SEG: usize = 100_000;

fn du(dir: &Path) -> u64 {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return 0;
    };
    rd.flatten()
        .map(|e| {
            let m = e.metadata().unwrap();
            if m.is_dir() { du(&e.path()) } else { m.len() }
        })
        .sum()
}

/// A fake volume: a pretend capacity minus the bytes under the directory.
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
        let cam: CameraId = "cam-1".parse().unwrap();
        let start = UnixMs::new(T0 + n * 60_000).unwrap();
        let root = if tier == Tier::Hot {
            &self.hot
        } else {
            &self.arch
        };
        let p = root.join(RelPath::new(&cam, start).to_string());
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, vec![7_u8; SEG]).unwrap();
        let rec = SegmentRecord::new(cam, start, 1000, SEG as u64, 30);
        self.index.insert(&rec, tier).unwrap()
    }

    fn row_only(&mut self, n: i64, tier: Tier) -> SegmentId {
        let cam: CameraId = "cam-2".parse().unwrap();
        let start = UnixMs::new(T0 + n * 60_000).unwrap();
        let rec = SegmentRecord::new(cam, start, 1000, SEG as u64, 30);
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

    fn fake(&self) -> Fake {
        Fake {
            hot: self.hot.clone(),
            arch: self.arch.clone(),
            hot_cap: 1_000_000,
            arch_cap: 1_000_000,
        }
    }
}

fn now() -> Timestamp {
    Timestamp::from_unix_millis(T0 + 3_600_000)
}

fn tier_of(files: &impl SegmentFiles, id: SegmentId) -> Result<Tier, SegmentOpenError> {
    files.open_segment(id).map(|o| o.tier())
}

#[test]
fn both_floors_are_restored_by_evicting_then_moving() {
    let mut w = World::new();
    let archived: Vec<_> = (0..6).map(|n| w.add(n, Tier::Archive)).collect();
    let hot: Vec<_> = (100..109).map(|n| w.add(n, Tier::Hot)).collect();
    let (usage, cfg) = (w.fake(), w.cfg());
    let (mut lp, files) = Storage::open(cfg, w.index, usage).unwrap();
    // Hot free 100k, archive free 400k; both floors are 250k (target 260k).
    let mut moved = 0;
    for _ in 0..5 {
        let r = lp.tick(now()).unwrap();
        moved += r.moved;
        if r.moved == 0 && r.deleted == 0 {
            break;
        }
    }
    let fake = Fake {
        hot: w.hot.clone(),
        arch: w.arch.clone(),
        hot_cap: 1_000_000,
        arch_cap: 1_000_000,
    };
    let hot_free = fake.hot_cap - du(&fake.hot);
    let arch_free = fake.arch_cap - du(&fake.arch);
    assert!(hot_free >= 250_000, "hot floor restored: {hot_free}");
    assert!(arch_free >= 250_000, "archive floor restored: {arch_free}");
    assert_eq!(moved, 2, "exactly what the hot target needed");
    // The oldest hot video moved; the oldest archive video was evicted to make room.
    assert_eq!(tier_of(&files, hot[0]), Ok(Tier::Archive));
    assert_eq!(tier_of(&files, hot[1]), Ok(Tier::Archive));
    assert_eq!(tier_of(&files, hot[2]), Ok(Tier::Hot));
    assert_eq!(
        tier_of(&files, archived[0]).unwrap_err(),
        SegmentOpenError::NotFound
    );
    assert_eq!(tier_of(&files, archived[5]), Ok(Tier::Archive));
    // A tick with nothing to do does nothing.
    let r = lp.tick(now()).unwrap();
    assert_eq!((r.moved, r.deleted, r.archive_failures), (0, 0, 0));
}

#[test]
fn a_bounded_tick_leaves_the_rest_for_the_next_one() {
    let mut w = World::new();
    let hot: Vec<_> = (0..9).map(|n| w.add(n, Tier::Hot)).collect();
    let (usage, mut cfg) = (w.fake(), w.cfg());
    cfg.max_actions_per_tick = 1;
    let (mut lp, files) = Storage::open(cfg, w.index, usage).unwrap();
    let r = lp.tick(now()).unwrap();
    assert_eq!(r.moved, 1);
    assert!(r.truncated, "the plan wanted two moves");
    assert_eq!(tier_of(&files, hot[1]), Ok(Tier::Hot));
    let r = lp.tick(now()).unwrap();
    assert_eq!(r.moved, 1);
    assert_eq!(tier_of(&files, hot[1]), Ok(Tier::Archive));
    assert_eq!(lp.tick(now()).unwrap().moved, 0, "the floor holds");
}

#[test]
fn start_unmounted_mount_while_running_keeps_archive_rows_and_moves_land_on_the_new_directory() {
    let mut w = World::new();
    // "Unmounted": the mount point is an empty directory on the hot filesystem (no marker).
    std::fs::remove_file(w.arch.join(ARCHIVE_MARKER)).unwrap();
    let archived: Vec<_> = (0..4).map(|n| w.row_only(n, Tier::Archive)).collect();
    let hot: Vec<_> = (100..103).map(|n| w.add(n, Tier::Hot)).collect();
    let (usage, cfg) = (w.fake(), w.cfg());
    let (mut lp, files) = Storage::open(cfg, w.index, usage).unwrap();
    let aged = Timestamp::from_unix_millis(T0 + 100 * 3_600_000);
    let r = lp.tick(aged).unwrap();
    assert!(!r.archive.is_available() && r.moved == 0);
    assert!(std::fs::read_dir(&w.arch).unwrap().next().is_none());
    for id in &archived {
        // The row is still there: the port names the archive, which is unavailable.
        assert_eq!(
            files.open_segment(*id).unwrap_err(),
            SegmentOpenError::ArchiveUnavailable
        );
    }
    // Mount: another directory (new inode) with the marker covers the old one.
    let covered = w.arch.parent().unwrap().join("covered");
    std::fs::rename(&w.arch, &covered).unwrap();
    mkdir(&w.arch);
    std::fs::write(w.arch.join(ARCHIVE_MARKER), b"").unwrap();
    let r = lp.tick(aged).unwrap();
    assert!(r.archive.is_available() && r.archive_returned);
    assert_eq!(r.moved, 0, "no moves in the returning tick");
    assert_eq!(lp.tick(aged).unwrap().moved, 3);
    for id in &hot {
        assert_eq!(
            tier_of(&files, *id),
            Ok(Tier::Archive),
            "moves land on the new archive"
        );
    }
    assert!(
        std::fs::read_dir(&covered).unwrap().next().is_none(),
        "nothing on the covered one"
    );
    for id in &archived {
        // Still rows (their files are not on this disk yet: the pass of #59 decides), never dropped.
        assert_eq!(tier_of(&files, *id), Err(SegmentOpenError::NotFound));
    }
}
