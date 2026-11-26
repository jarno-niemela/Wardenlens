//! Adversarial tests for #63 (PR #172): the storage snapshot the API reads, checked against an
//! independent oracle (the probe values the fake handed out, and the index itself) over many
//! ticks. Public API only, real SQLite index, temporary directories only.
#![expect(
    clippy::unwrap_used,
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::too_many_lines,
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

/// Over 80 ticks with a recorder writing every tick, foreign growth on both volumes and the
/// archive coming and going, every snapshot field is what an independent oracle computes: the
/// volumes of the tick's last probe, the rows the index holds, the tick time, and one breach per
/// volume whose first probe of the tick was under its floor.
#[test]
fn the_snapshot_matches_an_independent_oracle_over_many_ticks() {
    let w = World::new(2_000_000, 1_500_000);
    let mut lp = w.open();
    let mut rng = Lcg(0x6363);
    let mut want_breaches = 0_u64;
    let mut next = 0_i64;
    let mut breach_ticks = 0;
    let mut unavailable_ticks = 0;
    for tick in 0..80_i64 {
        // The recorder: one or two new segments of mixed size.
        for _ in 0..=(rng.next() % 2) {
            w.record(next, 40_000 + (rng.next() % 90_000) as usize, Tier::Hot);
            next += 1;
        }
        {
            let mut l = w.log.lock().unwrap();
            l.hot_foreign = rng.next() % 900_000;
            l.arch_foreign = rng.next() % 700_000;
        }
        // The archive goes away for a few ticks now and then.
        let away = (20..26).contains(&tick) || (50..53).contains(&tick);
        let marker = w.arch.join(ARCHIVE_MARKER);
        if away {
            let _ = std::fs::remove_file(&marker);
        } else {
            std::fs::write(&marker, b"").unwrap();
        }
        w.mark();
        let at = Timestamp::from_unix_millis(T0 + 10_000_000 + tick * 30_000);
        let r = lp.tick(at);
        let answers = w.answers();
        let s = lp.snapshot();

        // Breaches: the first hot and the first archive answer of the tick.
        let first_hot = answers.iter().find(|a| a.0 == Tier::Hot).unwrap().1;
        let first_arch = answers.iter().find(|a| a.0 == Tier::Archive).map(|a| a.1);
        let n = u64::from(first_hot.is_ok_and(below))
            + u64::from(first_arch.is_some_and(|a| a.is_ok_and(below)));
        if n > 0 {
            breach_ticks += 1;
        }
        want_breaches += n;
        assert_eq!(s.floor_breaches_total, want_breaches, "tick {tick}");

        assert_eq!(s.last_tick, Some(at), "tick {tick}");
        // Nothing in this fixture makes a tick fail: a healthy index and hot volume.
        assert!(r.is_ok(), "tick {tick}: {r:?}");
        assert_eq!(s.last_error, None, "tick {tick}");

        // The volumes: the last answer of the tick, by the formula of ADR 0005 section 6.
        let last_hot = answers.iter().rev().find(|a| a.0 == Tier::Hot).unwrap().1;
        let hv = s.hot.volume.unwrap();
        let lh = last_hot.unwrap();
        assert_eq!(
            (
                hv.total_bytes(),
                hv.free_bytes(),
                hv.free_percent(),
                hv.below_floor()
            ),
            (lh.capacity_bytes, lh.free_bytes, pct(lh), below(lh)),
            "tick {tick}"
        );
        assert_eq!(s.hot.min_free_percent, Some(FLOOR));
        if matches!(s.archive_condition, ArchiveCondition::Unavailable(_)) {
            unavailable_ticks += 1;
            assert!(away, "tick {tick}: unavailable while mounted");
            assert!(s.archive.volume.is_none(), "tick {tick}");
        } else {
            assert!(!away, "tick {tick}: available while unmarked");
            let la = answers
                .iter()
                .rev()
                .find(|a| a.0 == Tier::Archive)
                .unwrap()
                .1
                .unwrap();
            let av = s.archive.volume.unwrap();
            assert_eq!(
                (
                    av.total_bytes(),
                    av.free_bytes(),
                    av.free_percent(),
                    av.below_floor()
                ),
                (la.capacity_bytes, la.free_bytes, pct(la), below(la)),
                "tick {tick}"
            );
        }

        // The rows: straight from the index.
        for (tier, ts) in [(Tier::Hot, s.hot), (Tier::Archive, s.archive)] {
            let rows = all_rows(&w.index, tier);
            assert_eq!(ts.segments, rows.len() as u64, "tick {tick} {tier:?}");
            assert_eq!(ts.oldest, rows.first().map(|r| r.ended_at), "tick {tick}");
            assert_eq!(ts.newest, rows.last().map(|r| r.ended_at), "tick {tick}");
        }
    }
    // The generator reached the interesting branches.
    assert!(breach_ticks > 5, "breach ticks {breach_ticks}");
    assert!(
        unavailable_ticks > 3,
        "unavailable ticks {unavailable_ticks}"
    );
}

/// A tick whose re-probe of the hot volume fails after an action returns `Ok` (the report
/// raises `hot_probe_failed`), and the snapshot then has no hot volume. The gate must be able to
/// tell an unmeasured hot volume from a healthy one: either the volume is there or the snapshot
/// says why not.
#[test]
fn a_hot_probe_that_fails_mid_tick_is_not_reported_as_a_clean_tick() {
    let w = World::new(1_000_000, 1_000_000);
    // The archive is away, so the floor is held by deletes (an action, then a re-probe).
    std::fs::remove_file(w.arch.join(ARCHIVE_MARKER)).unwrap();
    for n in 0..9 {
        w.record(n, 100_000, Tier::Hot);
    }
    let mut lp = w.open();
    // The first hot probe of the tick answers, every later one fails.
    {
        let mut l = w.log.lock().unwrap();
        l.hot_fail_from = Some(l.hot_calls + 1);
    }
    let at = Timestamp::from_unix_millis(T0 + 99);
    let r = lp.tick(at).unwrap();
    assert!(
        r.hot_probe_failed,
        "the fixture reaches the mid-tick failure"
    );
    assert!(r.deleted >= 1);
    let s = lp.snapshot();
    assert_eq!(s.last_tick, Some(at));
    assert!(
        s.hot.volume.is_some() || s.last_error.is_some(),
        "hot volume unmeasured with no error kind: {s:?}"
    );
}

/// While the archive has just come back and its "archive returned" pass is still owed, no move
/// runs. Whatever the snapshot says then, it must agree with the probe (the archive is mounted
/// and measured) and never invent an error.
#[test]
fn an_archive_that_returns_is_measured_on_the_tick_it_returns() {
    let w = World::new(1_000_000, 1_000_000);
    w.record(0, 50_000, Tier::Hot);
    let mut lp = w.open();
    std::fs::remove_file(w.arch.join(ARCHIVE_MARKER)).unwrap();
    lp.tick(Timestamp::from_unix_millis(T0 + 1)).unwrap();
    assert!(matches!(
        lp.snapshot().archive_condition,
        ArchiveCondition::Unavailable(_)
    ));
    std::fs::write(w.arch.join(ARCHIVE_MARKER), b"").unwrap();
    lp.tick(Timestamp::from_unix_millis(T0 + 2)).unwrap();
    let s = lp.snapshot();
    assert_eq!(s.archive_condition, ArchiveCondition::Available);
    assert!(s.archive.volume.is_some());
    assert_eq!(s.last_error, None);
}

/// The breach counter is "since start": `Storage::open` and the start-up reconciliation do not
/// count, and a failed hot probe on the first probe counts the archive alone.
#[test]
fn a_failed_first_hot_probe_still_counts_an_archive_under_its_floor() {
    let w = World::new(1_000_000, 1_000_000);
    w.log.lock().unwrap().arch_foreign = 900_000; // 10 % free of a 25 % floor
    let mut lp = w.open();
    let _ = lp.reconcile_startup();
    assert_eq!(lp.snapshot().floor_breaches_total, 0);
    {
        let mut l = w.log.lock().unwrap();
        l.hot_fail_from = Some(l.hot_calls);
    }
    assert!(lp.tick(Timestamp::from_unix_millis(T0 + 5)).is_err());
    let s = lp.snapshot();
    assert_eq!(s.floor_breaches_total, 1);
    assert!(s.hot.volume.is_none());
    assert!(s.archive.volume.unwrap().below_floor());
}
