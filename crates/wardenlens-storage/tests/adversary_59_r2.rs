//! Adversarial tests for #59 round 2 (PR #165): the hold of the "archive returned" pass.
//! Public API only, real SQLite index, temporary directories only.
#![expect(
    clippy::unwrap_used,
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::cast_sign_loss,
    reason = "test code: small bounded synthetic values"
)]

use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};

use wardenlens_core::camera::CameraId;
use wardenlens_core::recording::{RelPath, SegmentRecord};
use wardenlens_core::storage::{
    IndexedSegment, MinFreePercent, Policy, SegmentCursor, SegmentId, SegmentIndex, SegmentPage,
    StoredSegment, Tier, TierTotals, VolumeSpace,
};
use wardenlens_core::time::{DurationMs, Timestamp, UnixMs};
use wardenlens_fsutil::RootDir;
use wardenlens_index::{Index, IndexError};
use wardenlens_storage::{
    ARCHIVE_MARKER, ProbeError, RealFs, Storage, StorageConfig, StorageLoop, VolumeUsage,
};

const T0: i64 = 1_700_000_000_000;
const CAM: &str = "cam-1";

// ---- fixtures -------------------------------------------------------------------------------------

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

struct Fake {
    hot: PathBuf,
    arch: PathBuf,
    hot_cap: u64,
}

impl VolumeUsage for Fake {
    fn space(&self, tier: Tier, _root: &RootDir) -> Result<VolumeSpace, ProbeError> {
        let cap = if tier == Tier::Hot {
            self.hot_cap
        } else {
            10_000_000_000_u64
        };
        let dir = if tier == Tier::Hot {
            &self.hot
        } else {
            &self.arch
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
    index: Shared,
}

fn cam() -> CameraId {
    CAM.parse().unwrap()
}

fn key(n: i64) -> UnixMs {
    UnixMs::new(T0 + n * 60_000).unwrap()
}

fn rel(n: i64) -> String {
    RelPath::new(&cam(), key(n)).to_string()
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
            std::fs::DirBuilder::new().mode(0o700).create(d).unwrap();
        }
        std::fs::write(arch.join(ARCHIVE_MARKER), b"").unwrap();
        let index = Shared(Arc::new(Mutex::new(
            Index::open(&idx.join("index.db")).unwrap(),
        )));
        Self {
            _tmp: tmp,
            hot,
            arch,
            index,
        }
    }

    fn cfg(&self, hot_max_age_min: u64) -> StorageConfig {
        StorageConfig::new(
            self.hot.clone(),
            self.arch.clone(),
            Policy {
                hot_min_free: MinFreePercent::new(5).unwrap(),
                archive_min_free: MinFreePercent::new(5).unwrap(),
                hot_max_age: DurationMs::from_secs(hot_max_age_min * 60),
                emergency_reserve_bytes: 0,
            },
        )
        .with_allow_same_filesystem(true)
    }

    fn open(&self, cfg: StorageConfig, hot_cap: u64) -> StorageLoop<Shared, RealFs, Fake> {
        let usage = Fake {
            hot: self.hot.clone(),
            arch: self.arch.clone(),
            hot_cap,
        };
        let (lp, _files) = Storage::open(cfg, self.index.clone(), usage).unwrap();
        lp
    }

    fn root(&self, tier: Tier) -> &Path {
        if tier == Tier::Hot {
            &self.hot
        } else {
            &self.arch
        }
    }

    fn put(&self, tier: Tier, n: i64, bytes: &[u8]) -> PathBuf {
        let p = self.root(tier).join(rel(n));
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, bytes).unwrap();
        p
    }

    fn row(&self, n: i64, tier: Tier, bytes: u64) -> SegmentId {
        let rec = SegmentRecord::new(cam(), key(n), 100, bytes, 3);
        self.index.clone().insert(&rec, tier).unwrap()
    }

    fn unmount(&self) {
        let _ = std::fs::remove_file(self.arch.join(ARCHIVE_MARKER));
    }

    fn mount(&self) {
        std::fs::write(self.arch.join(ARCHIVE_MARKER), b"").unwrap();
    }
}

fn bx(fourcc: [u8; 4], payload: &[u8]) -> Vec<u8> {
    let size = u32::try_from(payload.len() + 8).unwrap();
    let mut v = size.to_be_bytes().to_vec();
    v.extend_from_slice(&fourcc);
    v.extend_from_slice(payload);
    v
}

fn moov_with_padding(pad: Option<usize>) -> Vec<u8> {
    let mut mdhd = vec![0_u8; 12];
    mdhd.extend_from_slice(&90_000_u32.to_be_bytes());
    mdhd.extend_from_slice(&[0; 4]);
    let mut payload = bx(*b"trak", &bx(*b"mdia", &bx(*b"mdhd", &mdhd)));
    if let Some(total) = pad {
        // `total` is the wanted moov payload length.
        let free_payload = total - payload.len() - 8;
        payload.extend_from_slice(&bx(*b"free", &vec![0_u8; free_payload]));
    }
    bx(*b"moov", &payload)
}

fn fragment(durations: &[u32], mdat_len: usize) -> Vec<u8> {
    let mut trun = 0x0000_0701_u32.to_be_bytes().to_vec();
    trun.extend_from_slice(&u32::try_from(durations.len()).unwrap().to_be_bytes());
    trun.extend_from_slice(&0_i32.to_be_bytes());
    for d in durations {
        trun.extend_from_slice(&d.to_be_bytes());
        trun.extend_from_slice(&100_u32.to_be_bytes());
        trun.extend_from_slice(&0x0101_0000_u32.to_be_bytes());
    }
    let mut tfhd = 0_u32.to_be_bytes().to_vec();
    tfhd.extend_from_slice(&1_u32.to_be_bytes());
    let traf = bx(
        *b"traf",
        &[bx(*b"tfhd", &tfhd), bx(*b"trun", &trun)].concat(),
    );
    let mut out = bx(*b"moof", &[bx(*b"mfhd", &[0; 8]), traf].concat());
    out.extend_from_slice(&bx(*b"mdat", &vec![0xAB; mdat_len]));
    out
}

fn mp4_with(moov: &[u8], fragments: usize, per: &[u32], mdat_len: usize) -> Vec<u8> {
    let mut out = bx(*b"ftyp", b"isom\0\0\0\0isom");
    out.extend_from_slice(moov);
    let frag = fragment(per, mdat_len);
    for _ in 0..fragments {
        out.extend_from_slice(&frag);
    }
    out
}

/// A good segment; `mdat_len` changes its size without changing its validity.
fn good(mdat_len: usize) -> Vec<u8> {
    mp4_with(&moov_with_padding(None), 1, &[3000, 3000, 3000], mdat_len)
}

// ---- tests ----

/// A hot tier just below its floor with old segments that should move, and an archive whose
/// walk exceeds a small entry cap because of foreign files in its root.
fn crowded_world(segments: i64, junk: usize) -> (World, u64) {
    let w = World::new();
    let body = good(40_000);
    let len = body.len() as u64;
    for n in 0..segments {
        w.put(Tier::Hot, n, &body);
        w.row(n, Tier::Hot, len);
    }
    for j in 0..junk {
        std::fs::write(w.arch.join(format!("FOREIGN_{j}")), b"x").unwrap();
    }
    // Used is about `segments * len`: about 2 % free, below the 5 % floor.
    let hot_cap = (segments as u64 * len) * 102 / 100;
    (w, hot_cap)
}

fn hot_free_percent(w: &World, cap: u64) -> u64 {
    let mut used = 0;
    for e in walkdir(&w.hot) {
        used += e;
    }
    cap.saturating_sub(used) * 100 / cap
}

fn walkdir(d: &Path) -> Vec<u64> {
    let mut out = Vec::new();
    for e in std::fs::read_dir(d).unwrap().flatten() {
        let m = e.path().symlink_metadata().unwrap();
        if m.is_dir() {
            out.extend(walkdir(&e.path()));
        } else {
            out.push(m.len());
        }
    }
    out
}

const LATE: i64 = T0 + 3 * 86_400_000;

/// Control: the same archive present at start-up. The start-up walk hits the cap (a health
/// error, the service starts) and moves run as usual, restoring the hot floor.
#[test]
fn control_an_archive_over_the_walk_cap_at_start_up_still_receives_moves() {
    let (w, cap) = crowded_world(20, 40);
    let mut lp = w.open(w.cfg(30).with_walk_max_entries(30), cap);
    let s = lp.reconcile_startup().unwrap().report;
    assert!(s.walk_cap_exceeded, "{s:?}");
    let mut moved = 0;
    for t in 0..5 {
        let r = lp
            .tick(Timestamp::from_unix_millis(LATE + t * 60_000))
            .unwrap();
        moved += r.moved;
    }
    assert!(moved > 0, "moves run after a capped start-up");
    assert!(hot_free_percent(&w, cap) >= 5);
}

/// The archive returns at run time and its "archive returned" pass hits the same cap. The hold
/// must not outlive the safety of the hot tier: within a bounded number of ticks either moves run
/// again or hot video is deleted to hold the floor (ADR 0005 "never ENOSPC"). Observed: the pass
/// reruns every tick, the hold never ends, no move and no delete runs, and the hot tier stays
/// below its floor while the recorder keeps writing.
#[test]
fn a_returned_pass_that_always_hits_the_walk_cap_does_not_hold_the_hot_tier_below_its_floor() {
    let (w, cap) = crowded_world(20, 40);
    w.unmount();
    let mut lp = w.open(w.cfg(30).with_walk_max_entries(30), cap);
    let s = lp.reconcile_startup().unwrap().report;
    assert!(s.archive_unavailable && !s.walk_cap_exceeded, "{s:?}");
    w.mount();
    let (mut moved, mut deleted, mut held) = (0, 0, 0);
    for t in 0..30 {
        let r = lp
            .tick(Timestamp::from_unix_millis(LATE + t * 60_000))
            .unwrap();
        moved += r.moved;
        deleted += r.deleted;
        if r.archive_returned {
            held += 1;
        }
    }
    let free = hot_free_percent(&w, cap);
    assert!(
        moved + deleted > 0 && free >= 5,
        "30 ticks held: {held}, moved {moved}, deleted {deleted}, hot free {free} %"
    );
}

/// The same permanent hold with an emergency reserve configured and a recorder that keeps
/// writing one segment per tick: the reserve must still be held (the "never ENOSPC" invariant).
fn recorder_run(walk_cap: usize) -> (u32, u64, u64) {
    let (w, _) = crowded_world(20, 80);
    let body = good(40_000);
    let len = body.len() as u64;
    // Room for 30 segments; reserve of 3 segments.
    let cap = 30 * len;
    let mut cfg = w.cfg(30).with_walk_max_entries(walk_cap);
    cfg.policy.emergency_reserve_bytes = 3 * len;
    w.unmount();
    let mut lp = w.open(cfg, cap);
    let s = lp.reconcile_startup().unwrap().report;
    assert!(!s.walk_cap_exceeded, "{s:?}");
    w.mount();
    let mut min_free = u64::MAX;
    let mut held = 0;
    for t in 0..12_i64 {
        let r = lp
            .tick(Timestamp::from_unix_millis(LATE + t * 60_000))
            .unwrap();
        if r.archive_returned {
            held += 1;
        }
        let used: u64 = walkdir(&w.hot).iter().sum();
        min_free = min_free.min(cap.saturating_sub(used));
        // The recorder writes one more segment if there is room for it.
        if used + len <= cap {
            let n = 100 + t;
            w.put(Tier::Hot, n, &body);
            w.row(n, Tier::Hot, len);
        }
    }
    let used: u64 = walkdir(&w.hot).iter().sum();
    (held, cap.saturating_sub(used), len)
}

/// Control: the archive returns and its pass completes (no cap): the hold lasts one tick and the
/// moves keep the hot tier above its reserve while the recorder writes.
#[test]
fn control_a_returned_pass_that_completes_keeps_hot_room_while_the_recorder_writes() {
    let (held, free, len) = recorder_run(1_000_000);
    assert_eq!(held, 1);
    assert!(free >= 2 * len, "hot free {free} B");
}

/// The returned pass hits the walk cap on every tick: the hold never ends, nothing moves and
/// nothing is deleted, and the recorder fills the hot tier to 0 bytes free (ENOSPC).
#[test]
fn a_permanent_hold_still_keeps_the_emergency_reserve_while_the_recorder_writes() {
    let (held, free, len) = recorder_run(60);
    assert_eq!(held, 12, "the pass hits the cap on every tick");
    assert!(
        free >= 2 * len,
        "held {held} ticks; hot free {free} B, reserve {} B",
        3 * len
    );
}
