//! Adversarial tests for #58 round 4 (PR #156). Public API only, temporary directories only.
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
    tmp: tempfile::TempDir,
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
            tmp,
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

/// Hot 1 MB at 800 kB used (free 200 kB < floor 250 kB: one 100 kB move is needed). Archive
/// 1 MB with 400 kB foreign and four 100 kB segments (free 200 kB < its own floor 250 kB).
/// The full plan evicts A0 and A1 (room for the move plus the target); the archive's own floor
/// needs only A0.
fn hold_world() -> (World, Vec<SegmentId>, Vec<SegmentId>) {
    let mut w = World::new();
    std::fs::write(w.hot.join("foreign"), vec![0_u8; 600_000]).unwrap();
    std::fs::write(w.arch.join("foreign"), vec![0_u8; 400_000]).unwrap();
    let arch: Vec<_> = (-10..-6)
        .map(|n| w.add(n, Tier::Archive, 100_000))
        .collect();
    let hot: Vec<_> = (0..2).map(|n| w.add(n, Tier::Hot, 100_000)).collect();
    (w, hot, arch)
}

fn gone(files: &impl SegmentFiles, ids: &[SegmentId]) -> usize {
    ids.iter()
        .filter(|id| matches!(tier_of(files, **id), Err(SegmentOpenError::NotFound)))
        .count()
}

#[test]
fn a_held_tick_evicts_only_what_the_archive_floor_needs_and_two_ticks_evict_no_more_than_one() {
    // Control: no hold.
    let (w, hot, arch) = hold_world();
    let usage = w.fake(1_000_000, 1_000_000);
    let (mut lp, files) = Storage::open(w.cfg(0), w.index, usage).unwrap();
    let r = lp.tick(fresh()).unwrap();
    assert!(!r.archive_returned, "{r:?}");
    assert_eq!(r.moved, 1, "{r:?}");
    let control_arch_gone = gone(&files, &arch);
    let control_hot_gone = gone(&files, &hot);
    assert_eq!((control_arch_gone, control_hot_gone), (2, 0));

    // Held: the archive just returned.
    let (w, hot, arch) = hold_world();
    let usage = w.fake(1_000_000, 1_000_000);
    let (mut lp, files) = Storage::open(w.cfg(0), w.index, usage).unwrap();
    lp.set_initial_archive_state(false);
    let r = lp.tick(fresh()).unwrap();
    assert!(r.archive_returned, "{r:?}");
    assert_eq!(r.moved, 0, "{r:?}");
    assert_eq!(
        (gone(&files, &arch), gone(&files, &hot)),
        (1, 0),
        "held tick must evict only A0 (own floor): {r:?}"
    );
    assert_eq!(
        tier_of(&files, arch[0]),
        Err(SegmentOpenError::NotFound),
        "oldest first"
    );
    let r = lp.tick(fresh()).unwrap();
    assert_eq!(r.moved, 1, "{r:?}");
    assert_eq!(
        (gone(&files, &arch), gone(&files, &hot)),
        (control_arch_gone, control_hot_gone),
        "hold plus the next tick evicted more than one unheld tick: {r:?}"
    );
}

#[test]
fn a_directory_twin_on_the_archive_never_pins_a_hot_delete_and_is_left() {
    // Archive available but too small for any segment (archive_full): the floor deletes hot video.
    let mut w = World::new();
    std::fs::write(w.hot.join("foreign"), vec![0_u8; 700_000]).unwrap();
    let ids: Vec<_> = (0..4).map(|n| w.add(n, Tier::Hot, 50_000)).collect();
    let twin = w.arch.join(rel(0));
    std::fs::create_dir_all(&twin).unwrap();
    let usage = w.fake(1_000_000, 60_000);
    let (mut lp, files) = Storage::open(w.cfg(0), w.index, usage).unwrap();
    let r = lp.tick(fresh()).unwrap();
    assert!(r.archive_full, "{r:?}");
    assert_eq!(
        tier_of(&files, ids[0]),
        Err(SegmentOpenError::NotFound),
        "{r:?}"
    );
    assert!(twin.is_dir(), "a non-regular twin is left in place");
    assert_eq!(r.delete_failed, 0, "{r:?}");
}

#[test]
fn a_flapping_archive_with_room_never_deletes_video_on_an_available_tick() {
    // Hot floor reachable; the archive has plenty of room. Over 40 ticks the archive marker
    // appears and disappears pseudo-randomly while the recorder adds segments. A tick that was
    // available at its start and end (held or not) must delete nothing: nothing needs deleting
    // when the archive can absorb everything.
    let mut x: u64 = 0x2545_F491_4F6C_DD1D;
    let mut rnd = |m: u64| {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x % m
    };
    let mut w = World::new();
    std::fs::write(w.hot.join("foreign"), vec![0_u8; 600_000]).unwrap();
    let marker = w.arch.join(ARCHIVE_MARKER);
    let mut n = 0_i64;
    for _ in 0..3 {
        w.add(n, Tier::Hot, 40_000);
        n += 1;
    }
    let hot = w.hot.clone();
    let usage = w.fake(1_000_000, 100_000_000);
    let cfg = w.cfg(10_000);
    let mut index = w.index;
    // The loop owns its own index handle; keep adding through a second one.
    let idx_path = w.tmp.path().join("idx/index.db");
    let (mut lp, files) = Storage::open(cfg, Index::open(&idx_path).unwrap(), usage).unwrap();
    let mut was = true;
    for tick in 0..40 {
        let avail = rnd(3) != 0;
        if avail && !marker.exists() {
            std::fs::write(&marker, b"").unwrap();
        } else if !avail && marker.exists() {
            std::fs::remove_file(&marker).unwrap();
        }
        for _ in 0..rnd(3) {
            let start = UnixMs::new(T0 + n * 60_000).unwrap();
            let p = hot.join(rel(n));
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(&p, vec![7_u8; 40_000]).unwrap();
            let rec = SegmentRecord::new(cam(), start, 1000, 40_000, 30);
            index.insert(&rec, Tier::Hot).unwrap();
            n += 1;
        }
        let r = lp
            .tick(Timestamp::from_unix_millis(T0 + (n + 1) * 60_000))
            .unwrap();
        if avail && was {
            assert_eq!(
                r.deleted, 0,
                "tick {tick}: video deleted on an available tick: {r:?}"
            );
        }
        was = avail;
        let _ = &files;
    }
}

fn du_alloc(dir: &Path) -> u64 {
    use std::os::unix::fs::MetadataExt;
    let Ok(rd) = std::fs::read_dir(dir) else {
        return 0;
    };
    rd.flatten()
        .map(|e| {
            let m = e.path().symlink_metadata().unwrap();
            if m.is_dir() {
                du_alloc(&e.path())
            } else {
                m.blocks() * 512
            }
        })
        .sum()
}

/// Space as the file system sees it: allocated blocks, not apparent lengths.
struct AllocFake {
    hot: PathBuf,
    cap: u64,
}

impl VolumeUsage for AllocFake {
    fn space(&self, tier: Tier, _root: &RootDir) -> Result<VolumeSpace, ProbeError> {
        assert_eq!(tier, Tier::Hot, "archive is unavailable in this test");
        Ok(VolumeSpace {
            capacity_bytes: self.cap,
            free_bytes: self.cap.saturating_sub(du_alloc(&self.hot)),
        })
    }
}

#[test]
fn small_quarantined_files_are_sized_by_what_deleting_them_frees() {
    // Rolling buffer (no archive, floor unreachable even with the whole quarantine gone),
    // reserve 60 kB, free about 17 kB. The plan deletes one 50 kB segment for the reserve, so the
    // quarantine is evicted first, sized to 50 kB. Fifteen 1000-byte quarantined files each free
    // a whole block when deleted: 13 of them free 50 kB; sizing them by their length instead
    // (1000 bytes) evicts all fifteen.
    let mut w = World::new();
    std::fs::remove_file(w.arch.join(ARCHIVE_MARKER)).unwrap();
    std::fs::write(w.hot.join("foreign"), vec![0_u8; 760_000]).unwrap();
    let ids: Vec<_> = (0..3).map(|n| w.add(n, Tier::Hot, 50_000)).collect();
    let hot = w.hot.clone();
    for i in 0..15 {
        World::quarantine(&hot, &format!("0000{i:02}-000.mp4"), 1000);
    }
    let block = std::fs::symlink_metadata(hot.join("_quarantine/cam-1/2023-11-12/000000-000.mp4"))
        .map(|m| std::os::unix::fs::MetadataExt::blocks(&m) * 512)
        .unwrap();
    assert!(block > 1000, "file system allocates whole blocks ({block})");
    let usage = AllocFake {
        hot: hot.clone(),
        cap: 1_000_000,
    };
    let free0 = 1_000_000 - du_alloc(&hot);
    assert!(free0 < 60_000, "{free0}");
    let (mut lp, files) = Storage::open(w.cfg(60_000), w.index, usage).unwrap();
    let r = lp.tick(fresh()).unwrap();
    assert_eq!(r.deleted, 0, "{r:?}");
    let needed = u32::try_from(50_000_u64.div_ceil(block)).unwrap();
    assert!(
        r.quarantine_evicted <= needed,
        "evicted {} quarantined files where {needed} free the 50 kB the plan needed: {r:?}",
        r.quarantine_evicted
    );
    for id in ids {
        assert_eq!(tier_of(&files, id), Ok(Tier::Hot));
    }
}
