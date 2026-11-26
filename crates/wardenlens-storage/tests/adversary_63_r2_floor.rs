//! Adversarial tests for #63 round 2 (PR #172): the snapshot in the ADR 0005 section 6 states
//! (unsatisfiable floor, archive full). Fixtures copied from `adversary_63.rs`.
#![expect(
    clippy::unwrap_used,
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    dead_code,
    reason = "test code: small bounded synthetic values"
)]

use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};

use wardenlens_core::camera::CameraId;
use wardenlens_core::recording::{RelPath, SegmentRecord};
use wardenlens_core::storage::{
    ArchiveCondition, IndexedSegment, MinFreePercent, Policy, SegmentCursor, SegmentId,
    SegmentIndex, SegmentPage, StoredSegment, Tier, TierTotals, VolumeSpace,
};
use wardenlens_core::time::{DurationMs, Timestamp, UnixMs};
use wardenlens_fsutil::RootDir;
use wardenlens_index::{Index, IndexError};
use wardenlens_storage::{
    ARCHIVE_MARKER, ProbeError, RealFs, Storage, StorageConfig, StorageLoop, VolumeUsage,
};

const T0: i64 = 1_700_000_000_000;
const FLOOR: u8 = 25;

#[derive(Clone)]
struct Shared(Arc<Mutex<Index>>);

impl Shared {
    fn with<R>(&self, f: impl FnOnce(&mut Index) -> R) -> R {
        let mut g = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        f(&mut g)
    }
}

impl SegmentIndex for Shared {
    type Error = IndexError;
    fn insert(&mut self, r: &SegmentRecord, t: Tier) -> Result<SegmentId, IndexError> {
        self.with(|i| i.insert(r, t))
    }
    fn get(&self, id: SegmentId) -> Result<Option<IndexedSegment>, IndexError> {
        self.with(|i| i.get(id))
    }
    fn list(
        &self,
        c: &CameraId,
        f: Timestamp,
        t: Timestamp,
        l: usize,
        cur: Option<&SegmentCursor>,
    ) -> Result<SegmentPage, IndexError> {
        self.with(|i| i.list(c, f, t, l, cur))
    }
    fn set_tier(&mut self, id: SegmentId, t: Tier) -> Result<(), IndexError> {
        self.with(|i| i.set_tier(id, t))
    }
    fn delete(&mut self, id: SegmentId) -> Result<(), IndexError> {
        self.with(|i| i.delete(id))
    }
    fn oldest(
        &self,
        t: Tier,
        a: Option<(Timestamp, SegmentId)>,
        n: usize,
    ) -> Result<Vec<StoredSegment>, IndexError> {
        self.with(|i| i.oldest(t, a, n))
    }
    fn newest(&self, t: Tier) -> Result<Option<StoredSegment>, IndexError> {
        self.with(|i| i.newest(t))
    }
    fn bytes_by_tier(&self) -> Result<TierTotals, IndexError> {
        self.with(|i| i.bytes_by_tier())
    }
    fn latest_started_at(&self, c: &CameraId) -> Result<Option<UnixMs>, IndexError> {
        self.with(|i| i.latest_started_at(c))
    }
}

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

/// What the fake handed out, so the test can compute the expected snapshot on its own.
#[derive(Default)]
struct Log {
    hot_cap: u64,
    arch_cap: u64,
    hot_foreign: u64,
    arch_foreign: u64,
    /// Hot `space` calls answered so far; calls at or after this many fail.
    hot_fail_from: Option<usize>,
    hot_calls: usize,
    /// Every answer, in order, since the last `mark`.
    answers: Vec<(Tier, Result<VolumeSpace, ()>)>,
}

#[derive(Clone)]
struct Usage {
    hot: PathBuf,
    arch: PathBuf,
    log: Arc<Mutex<Log>>,
}

impl VolumeUsage for Usage {
    fn space(&self, tier: Tier, _root: &RootDir) -> Result<VolumeSpace, ProbeError> {
        let mut l = self.log.lock().unwrap();
        let r = if tier == Tier::Hot {
            let n = l.hot_calls;
            l.hot_calls += 1;
            if l.hot_fail_from.is_some_and(|f| n >= f) {
                Err(())
            } else {
                Ok(VolumeSpace {
                    capacity_bytes: l.hot_cap,
                    free_bytes: l.hot_cap.saturating_sub(du(&self.hot) + l.hot_foreign),
                })
            }
        } else {
            Ok(VolumeSpace {
                capacity_bytes: l.arch_cap,
                free_bytes: l.arch_cap.saturating_sub(du(&self.arch) + l.arch_foreign),
            })
        };
        l.answers.push((tier, r));
        r.map_err(|()| ProbeError::Io(None))
    }
}

struct World {
    _tmp: tempfile::TempDir,
    hot: PathBuf,
    arch: PathBuf,
    index: Shared,
    log: Arc<Mutex<Log>>,
}

fn cam() -> CameraId {
    "cam-1".parse().unwrap()
}

fn key(n: i64) -> UnixMs {
    UnixMs::new(T0 + n * 60_000).unwrap()
}

impl World {
    fn new(hot_cap: u64, arch_cap: u64) -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let (hot, arch, idx) = (
            tmp.path().join("hot"),
            tmp.path().join("arch"),
            tmp.path().join("idx"),
        );
        for d in [&hot, &arch, &idx] {
            std::fs::DirBuilder::new().mode(0o700).create(d).unwrap();
        }
        std::fs::write(arch.join(ARCHIVE_MARKER), b"").unwrap();
        let index = Shared(Arc::new(Mutex::new(
            Index::open(&idx.join("index.db")).unwrap(),
        )));
        let log = Arc::new(Mutex::new(Log {
            hot_cap,
            arch_cap,
            ..Log::default()
        }));
        Self {
            _tmp: tmp,
            hot,
            arch,
            index,
            log,
        }
    }

    fn open(&self) -> StorageLoop<Shared, RealFs, Usage> {
        let cfg = StorageConfig::new(
            self.hot.clone(),
            self.arch.clone(),
            Policy {
                hot_min_free: MinFreePercent::new(FLOOR).unwrap(),
                archive_min_free: MinFreePercent::new(FLOOR).unwrap(),
                hot_max_age: DurationMs::from_secs(100 * 86_400),
                emergency_reserve_bytes: 0,
            },
        )
        .with_allow_same_filesystem(true);
        let usage = Usage {
            hot: self.hot.clone(),
            arch: self.arch.clone(),
            log: Arc::clone(&self.log),
        };
        let (lp, _files) = Storage::open(cfg, self.index.clone(), usage).unwrap();
        lp
    }

    /// A segment file and its row (junk bytes: the loop may move, quarantine or delete it).
    fn record(&self, n: i64, bytes: usize, tier: Tier) {
        let root = if tier == Tier::Hot {
            &self.hot
        } else {
            &self.arch
        };
        let p = root.join(RelPath::new(&cam(), key(n)).to_string());
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, vec![0_u8; bytes]).unwrap();
        let rec = SegmentRecord::new(cam(), key(n), 1000, bytes as u64, 3);
        self.index.clone().insert(&rec, tier).unwrap();
    }

    fn mark(&self) {
        self.log.lock().unwrap().answers.clear();
    }

    fn answers(&self) -> Vec<(Tier, Result<VolumeSpace, ()>)> {
        self.log.lock().unwrap().answers.clone()
    }
}

fn below(s: VolumeSpace) -> bool {
    // The planner's byte rule, computed here on its own: free < capacity * floor / 100.
    u128::from(s.free_bytes) < u128::from(s.capacity_bytes) * u128::from(FLOOR) / 100
}

fn pct(s: VolumeSpace) -> u8 {
    if s.capacity_bytes == 0 {
        return 0;
    }
    (u128::from(s.free_bytes) * 100 / u128::from(s.capacity_bytes)).min(100) as u8
}

/// The rows of `tier`, oldest first, read straight from the index.
fn all_rows(idx: &Shared, tier: Tier) -> Vec<StoredSegment> {
    let mut out: Vec<StoredSegment> = Vec::new();
    loop {
        let after = out.last().map(|s| (s.ended_at, s.id));
        let page = idx.oldest(tier, after, 100).unwrap();
        if page.is_empty() {
            return out;
        }
        out.extend(page);
    }
}

/// Small deterministic generator (no external crate).
struct Lcg(u64);
impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0 >> 33
    }
}

/// ADR 0005 section 6 case 4: foreign data holds the hot volume under its floor and deleting
/// every segment would not restore it. No video is deleted, every tick still counts the breach,
/// and the snapshot shows the volume under its floor (the endpoint reports `below_floor`).
#[test]
fn an_unsatisfiable_hot_floor_is_reported_and_counted_every_tick_and_deletes_nothing() {
    let w = World::new(1_000_000, 1_000_000);
    std::fs::remove_file(w.arch.join(ARCHIVE_MARKER)).unwrap();
    w.record(0, 10_000, Tier::Hot);
    w.log.lock().unwrap().hot_foreign = 900_000;
    let mut lp = w.open();
    for t in 1..=5_u64 {
        let at = Timestamp::from_unix_millis(T0 + 10_000 + i64::try_from(t).unwrap());
        let r = lp.tick(at);
        let s = lp.snapshot();
        assert_eq!(s.floor_breaches_total, t, "tick {t}: {r:?}");
        let hv = s.hot.volume.unwrap();
        assert!(hv.below_floor(), "tick {t}");
        assert_eq!(s.hot.segments, 1, "tick {t}: nothing deleted");
        assert_eq!(s.last_tick, Some(at));
        // The planner's refusal is a report state, not a tick error: `below_floor` says it.
        assert!(r.is_ok(), "tick {t}: {r:?}");
        assert_eq!(s.last_error, None);
    }
}

/// ADR 0005 section 6 case 3: the archive is available but cannot take one segment. The state is
/// `archive_full`, the hot floor is held by deletes, and the tick is not an error.
#[test]
fn an_archive_that_cannot_absorb_a_move_is_reported_full() {
    let w = World::new(1_000_000, 50_000);
    for n in 0..9 {
        w.record(n, 100_000, Tier::Hot);
    }
    let mut lp = w.open();
    let at = Timestamp::from_unix_millis(T0 + 10_000);
    let r = lp.tick(at).unwrap();
    let s = lp.snapshot();
    assert!(r.archive_full, "{r:?}");
    assert_eq!(s.archive_condition, ArchiveCondition::Full, "{s:?}");
    assert_eq!(s.last_error, None);
    assert!(s.archive.volume.is_some());
    assert_eq!(s.archive.min_free_percent, Some(FLOOR));
    assert_eq!(s.floor_breaches_total, 1, "the hot volume only");
}
