//! Adversarial tests for #58 (PR #156). Public API only, temporary directories only.
#![expect(
    clippy::unwrap_used,
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    reason = "test code: small bounded synthetic values"
)]

use std::os::unix::fs::{DirBuilderExt, symlink};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use wardenlens_core::camera::CameraId;
use wardenlens_core::recording::{RelPath, SegmentRecord};
use wardenlens_core::storage::{
    MinFreePercent, Policy, SegmentFiles, SegmentId, SegmentIndex, SegmentOpenError, Tier,
    VolumeSpace,
};
use wardenlens_core::time::{DurationMs, Timestamp, UnixMs};
use wardenlens_fsutil::{DirEntry, FsError, QuarantineOutcome, RootDir};
use wardenlens_index::Index;
use wardenlens_storage::{
    ARCHIVE_MARKER, ArchiveProbe, Fs, Opened, PartFile, ProbeError, RealFs, Storage, StorageConfig,
    UnavailableCause, VolumeUsage,
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

fn mkfifo(p: &Path) {
    let st = std::process::Command::new("mkfifo")
        .arg(p)
        .status()
        .unwrap();
    assert!(st.success());
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

    /// A row of `tier`, with a file of `SEG` bytes on that tier unless `file` is false.
    fn add(&mut self, n: i64, tier: Tier, file: bool) -> SegmentId {
        let start = UnixMs::new(T0 + n * 60_000).unwrap();
        if file {
            let root = if tier == Tier::Hot {
                &self.hot
            } else {
                &self.arch
            };
            let p = root.join(rel(n));
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(&p, vec![7_u8; SEG]).unwrap();
        }
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

    fn fake(&self, hot_cap: u64, arch_cap: u64) -> Fake {
        Fake {
            hot: self.hot.clone(),
            arch: self.arch.clone(),
            hot_cap,
            arch_cap,
        }
    }
}

/// Every segment is past `hot_max_age`: the planner moves all of them without pressure.
fn aged() -> Timestamp {
    Timestamp::from_unix_millis(T0 + 100 * 3_600_000)
}

fn now() -> Timestamp {
    Timestamp::from_unix_millis(T0 + 3_600_000)
}

fn tier_of(files: &impl SegmentFiles, id: SegmentId) -> Result<Tier, SegmentOpenError> {
    files.open_segment(id).map(|o| o.tier())
}

// ---------------------------------------------------------------------------------------------
// A recording / fault-injecting `Fs`.

#[derive(Default)]
struct SpyState {
    log: Vec<(String, bool)>,
    /// Fail the next `sync_dir(Archive, [])` (the archive root) once.
    fail_root_sync_once: bool,
}

struct Spy {
    inner: RealFs,
    state: Arc<Mutex<SpyState>>,
}

fn t(tier: Tier) -> &'static str {
    if tier == Tier::Hot { "hot" } else { "arch" }
}

impl Spy {
    fn rec<R>(&self, what: String, r: Result<R, FsError>) -> Result<R, FsError> {
        self.state.lock().unwrap().log.push((what, r.is_ok()));
        r
    }
}

impl Fs for Spy {
    fn open_read(&self, tier: Tier, comps: &[&str]) -> Result<Opened, FsError> {
        let r = self.inner.open_read(tier, comps);
        self.rec(format!("open {} {}", t(tier), comps.join("/")), r)
    }
    fn mkdir(&self, tier: Tier, parent: &[&str], name: &str) -> Result<(), FsError> {
        let r = self.inner.mkdir(tier, parent, name);
        self.rec(format!("mkdir {} {}|{name}", t(tier), parent.join("/")), r)
    }
    fn sync_dir(&self, tier: Tier, dir: &[&str]) -> Result<(), FsError> {
        let fail = {
            let mut s = self.state.lock().unwrap();
            tier == Tier::Archive && dir.is_empty() && std::mem::take(&mut s.fail_root_sync_once)
        };
        let r = if fail {
            Err(FsError::Io {
                op: "injected",
                source: rustix::io::Errno::IO,
            })
        } else {
            self.inner.sync_dir(tier, dir)
        };
        self.rec(format!("sync {} {}", t(tier), dir.join("/")), r)
    }
    fn unlink(&self, tier: Tier, dir: &[&str], name: &str) -> Result<(), FsError> {
        let r = self.inner.unlink(tier, dir, name);
        self.rec(format!("unlink {} {}|{name}", t(tier), dir.join("/")), r)
    }
    fn create_part(
        &self,
        tier: Tier,
        dir: &[&str],
        name: &str,
    ) -> Result<Box<dyn PartFile>, FsError> {
        let r = self.inner.create_part(tier, dir, name);
        self.rec(format!("create {} {}|{name}", t(tier), dir.join("/")), r)
    }
    fn rename_noreplace(
        &self,
        tier: Tier,
        dir: &[&str],
        from: &str,
        to: &str,
    ) -> Result<(), FsError> {
        let r = self.inner.rename_noreplace(tier, dir, from, to);
        self.rec(
            format!("rename {} {}|{from}->{to}", t(tier), dir.join("/")),
            r,
        )
    }
    fn quarantine(&self, tier: Tier, comps: &[&str]) -> Result<QuarantineOutcome, FsError> {
        let r = self.inner.quarantine(tier, comps);
        self.rec(format!("quarantine {} {}", t(tier), comps.join("/")), r)
    }
    fn list_dir(&self, tier: Tier, dir: &[&str], max: usize) -> Result<Vec<DirEntry>, FsError> {
        self.inner.list_dir(tier, dir, max)
    }
}

// ---------------------------------------------------------------------------------------------
// M6: EEXIST with an exhausted quarantine bound.

#[test]
fn eexist_at_m6_with_an_exhausted_quarantine_bound_is_unverified_and_never_blames_the_archive() {
    // ADR 0005 §7 / #58 amendment: an EEXIST at M6 never counts toward the three failures, and
    // when the 1,000 bound is used up the file is left in place and counted `unverified`.
    let mut w = World::new();
    let id = w.add(0, Tier::Hot, true);
    let r = rel(0);
    // A stale, wrong-size A/R.
    let a = w.arch.join(&r);
    std::fs::create_dir_all(a.parent().unwrap()).unwrap();
    std::fs::write(&a, b"stale").unwrap();
    // Its quarantine name and every suffix up to the bound are taken.
    let q = w.arch.join("_quarantine").join(&r);
    std::fs::create_dir_all(q.parent().unwrap()).unwrap();
    let name = q.file_name().unwrap().to_str().unwrap().to_owned();
    std::fs::write(&q, b"q").unwrap();
    for n in 1..=1000 {
        std::fs::write(q.parent().unwrap().join(format!("{name}.{n}")), b"q").unwrap();
    }
    let (usage, cfg) = (w.fake(1 << 40, 1 << 40), w.cfg());
    let (mut lp, files) = Storage::open(cfg, w.index, usage).unwrap();
    let rep = lp.tick(aged()).unwrap();
    // Safety first: nothing lost, nothing overwritten.
    assert_eq!(std::fs::read(&a).unwrap(), b"stale", "A/R left in place");
    assert_eq!(
        tier_of(&files, id),
        Ok(Tier::Hot),
        "hot stays authoritative"
    );
    assert_eq!(std::fs::metadata(w.hot.join(&r)).unwrap().len(), SEG as u64);
    // The accounting.
    assert_eq!(
        (rep.archive_failures, lp.move_failures()),
        (0, 0),
        "an EEXIST at M6 is not the archive's fault: {rep:?}"
    );
    assert_eq!(
        rep.unverified, 1,
        "an exhausted bound is `unverified`: {rep:?}"
    );
}

#[test]
fn eexist_at_m6_on_a_non_regular_archive_entry_is_unverified_and_touches_nothing() {
    let mut w = World::new();
    let id = w.add(0, Tier::Hot, true);
    let r = rel(0);
    let a = w.arch.join(&r);
    std::fs::create_dir_all(&a).unwrap(); // a directory where A/R would go
    std::fs::write(a.join("inner"), b"owner data").unwrap();
    let (usage, cfg) = (w.fake(1 << 40, 1 << 40), w.cfg());
    let (mut lp, files) = Storage::open(cfg, w.index, usage).unwrap();
    let rep = lp.tick(aged()).unwrap();
    assert_eq!(rep.archive_failures, 0, "{rep:?}");
    assert_eq!(rep.unverified, 1, "{rep:?}");
    assert_eq!(std::fs::read(a.join("inner")).unwrap(), b"owner data");
    assert_eq!(tier_of(&files, id), Ok(Tier::Hot));
    assert!(
        !w.arch.join(format!("{r}.part")).exists(),
        "no .part left behind"
    );
}

// ---------------------------------------------------------------------------------------------
// M2: directory chain durability.

#[test]
fn a_directory_whose_parent_fsync_failed_is_made_durable_before_the_move_commits() {
    // M2 fsyncs the parent of a directory it creates. If that fsync fails, the next attempt sees
    // EEXIST from mkdir: the camera directory's entry in the archive root has never been made
    // durable, yet the move commits (M8) and the hot copy is unlinked (M9). A power cut can then
    // drop the only copy's directory entry.
    let mut w = World::new();
    let id = w.add(0, Tier::Hot, true);
    let state = Arc::new(Mutex::new(SpyState {
        fail_root_sync_once: true,
        ..SpyState::default()
    }));
    let st = Arc::clone(&state);
    let (usage, cfg) = (w.fake(1 << 40, 1 << 40), w.cfg());
    let (mut lp, files) =
        Storage::open_with(cfg, w.index, usage, move |inner| Spy { inner, state: st }).unwrap();
    let r1 = lp.tick(aged()).unwrap();
    assert_eq!(r1.archive_failures, 1, "{r1:?}");
    let r2 = lp.tick(aged()).unwrap();
    assert_eq!(r2.moved, 1, "{r2:?}");
    assert_eq!(tier_of(&files, id), Ok(Tier::Archive));
    assert!(!w.hot.join(rel(0)).exists(), "the hot copy is gone");
    let log = &state.lock().unwrap().log;
    let created = log
        .iter()
        .position(|(op, ok)| *ok && op == "mkdir arch |cam-1")
        .unwrap();
    let durable = log
        .iter()
        .skip(created + 1)
        .any(|(op, ok)| *ok && op == "sync arch ");
    assert!(
        durable,
        "the archive root was never fsynced after cam-1 was created, but the hot copy is gone: {log:#?}"
    );
}

// ---------------------------------------------------------------------------------------------
// Quarantine-first eviction.

#[test]
fn quarantined_files_go_before_hot_video_when_the_archive_is_unavailable() {
    // ADR 0005 §6 eviction order: quarantined files of the volume first, segments after. With
    // the archive unavailable, the planner deletes hot video; quarantine files must go first.
    let mut w = World::new();
    std::fs::remove_file(w.arch.join(ARCHIVE_MARKER)).unwrap();
    let ids: Vec<_> = (100..109).map(|n| w.add(n, Tier::Hot, true)).collect();
    // One 50 kB quarantined file on the hot volume (older than every segment).
    let q = w.hot.join("_quarantine").join(rel(0));
    std::fs::create_dir_all(q.parent().unwrap()).unwrap();
    std::fs::write(&q, vec![1_u8; 50_000]).unwrap();
    // cap 1 MB: used 950 kB, free 50 kB; floor 250 kB, target 260 kB. The quarantine alone (50 kB)
    // cannot reach the floor, quarantine + 2 segments (300 kB) reach the target.
    let (usage, cfg) = (w.fake(1_000_000, 1 << 40), w.cfg());
    let (mut lp, files) = Storage::open(cfg, w.index, usage).unwrap();
    let rep = lp.tick(now()).unwrap();
    assert!(!rep.archive.is_available());
    let gone = ids
        .iter()
        .filter(|id| tier_of(&files, **id) == Err(SegmentOpenError::NotFound))
        .count();
    assert!(
        !q.exists(),
        "hot video ({gone} segments) was deleted while a quarantined file was kept: {rep:?}"
    );
    assert!(gone <= 2, "{gone} segments deleted; 2 were enough");
}

#[test]
fn quarantined_files_go_before_archive_video() {
    let mut w = World::new();
    let ids: Vec<_> = (100..109).map(|n| w.add(n, Tier::Archive, true)).collect();
    let q = w.arch.join("_quarantine").join(rel(0));
    std::fs::create_dir_all(q.parent().unwrap()).unwrap();
    std::fs::write(&q, vec![1_u8; 50_000]).unwrap();
    // Archive: used 950 kB of 1 MB, below its floor.
    let (usage, cfg) = (w.fake(1 << 40, 1_000_000), w.cfg());
    let (mut lp, files) = Storage::open(cfg, w.index, usage).unwrap();
    let rep = lp.tick(now()).unwrap();
    let gone = ids
        .iter()
        .filter(|id| tier_of(&files, **id) == Err(SegmentOpenError::NotFound))
        .count();
    // Whether the planner evicts the archive without a move is #44's business; if it deletes
    // archive video at all, the quarantine must have gone first.
    if gone > 0 {
        assert!(
            !q.exists(),
            "{gone} archive segments deleted while a quarantined file was kept: {rep:?}"
        );
    }
}

// ---------------------------------------------------------------------------------------------
// Paths: symlinks and FIFOs planted in either tree.

#[test]
fn a_symlinked_archive_camera_directory_is_never_followed() {
    let mut w = World::new();
    let id = w.add(0, Tier::Hot, true);
    let outside = w.tmp.path().join("outside");
    mkdir(&outside);
    symlink(&outside, w.arch.join("cam-1")).unwrap();
    let (usage, cfg) = (w.fake(1 << 40, 1 << 40), w.cfg());
    let (mut lp, files) = Storage::open(cfg, w.index, usage).unwrap();
    let rep = lp.tick(aged()).unwrap();
    assert_eq!(rep.moved, 0);
    assert!(
        std::fs::read_dir(&outside).unwrap().next().is_none(),
        "nothing written through the symlink"
    );
    assert_eq!(tier_of(&files, id), Ok(Tier::Hot));
    assert_eq!(
        std::fs::metadata(w.hot.join(rel(0))).unwrap().len(),
        SEG as u64
    );
}

#[test]
fn a_symlinked_hot_day_directory_is_never_followed_by_move_or_delete() {
    let mut w = World::new();
    let id = w.add(0, Tier::Hot, false);
    let r = rel(0);
    let day = w.hot.join(Path::new(&r).parent().unwrap());
    let outside = w.tmp.path().join("outside");
    mkdir(&outside);
    let fname = Path::new(&r).file_name().unwrap();
    std::fs::write(outside.join(fname), vec![7_u8; SEG]).unwrap();
    std::fs::create_dir_all(day.parent().unwrap()).unwrap();
    symlink(&outside, &day).unwrap();
    // Archive unavailable and hot over its floor: the planner deletes the hot row.
    std::fs::remove_file(w.arch.join(ARCHIVE_MARKER)).unwrap();
    let (usage, cfg) = (w.fake(SEG as u64 + 1, 1 << 40), w.cfg());
    let (mut lp, files) = Storage::open(cfg, w.index, usage).unwrap();
    let _ = lp.tick(aged());
    assert_eq!(
        std::fs::metadata(outside.join(fname)).unwrap().len(),
        SEG as u64,
        "the file outside the root is untouched"
    );
    let _ = files.open_segment(id);
}

#[test]
fn a_fifo_planted_as_the_hot_segment_never_hangs_and_keeps_the_row() {
    let mut w = World::new();
    let id = w.add(0, Tier::Hot, false);
    let p = w.hot.join(rel(0));
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    mkfifo(&p);
    let (usage, cfg) = (w.fake(1 << 40, 1 << 40), w.cfg());
    let (mut lp, files) = Storage::open(cfg, w.index, usage).unwrap();
    let rep = lp.tick(aged()).unwrap();
    assert_eq!((rep.unverified, rep.archive_failures), (1, 0), "{rep:?}");
    assert!(p.symlink_metadata().unwrap().file_type().is_fifo_like());
    assert!(matches!(
        files.open_segment(id),
        Err(SegmentOpenError::Io { .. })
    ));
}

trait FifoLike {
    fn is_fifo_like(&self) -> bool;
}
impl FifoLike for std::fs::FileType {
    fn is_fifo_like(&self) -> bool {
        use std::os::unix::fs::FileTypeExt;
        self.is_fifo()
    }
}

#[test]
fn a_missing_hot_file_and_a_fifo_archive_copy_is_unverified_and_keeps_the_row() {
    let mut w = World::new();
    let id = w.add(0, Tier::Hot, false);
    let a = w.arch.join(rel(0));
    std::fs::create_dir_all(a.parent().unwrap()).unwrap();
    mkfifo(&a);
    let (usage, cfg) = (w.fake(1 << 40, 1 << 40), w.cfg());
    let (mut lp, files) = Storage::open(cfg, w.index, usage).unwrap();
    let rep = lp.tick(aged()).unwrap();
    assert_eq!((rep.unverified, rep.rows_dropped), (1, 0), "{rep:?}");
    assert!(a.symlink_metadata().unwrap().file_type().is_fifo_like());
    assert_eq!(
        tier_of(&files, id).unwrap_err(),
        SegmentOpenError::NotFound,
        "the row is kept (hot file missing)"
    );
}

#[test]
fn an_archive_root_that_is_a_symlink_is_missing() {
    let w = World::new();
    let real = w.tmp.path().join("real-arch");
    mkdir(&real);
    std::fs::write(real.join(ARCHIVE_MARKER), b"").unwrap();
    std::fs::remove_file(w.arch.join(ARCHIVE_MARKER)).unwrap();
    std::fs::remove_dir(&w.arch).unwrap();
    symlink(&real, &w.arch).unwrap();
    let (usage, cfg) = (w.fake(1 << 40, 1 << 40), w.cfg());
    let (mut lp, _) = Storage::open(cfg, w.index, usage).unwrap();
    let rep = lp.tick(now()).unwrap();
    assert_eq!(
        rep.archive,
        ArchiveProbe::Unavailable(UnavailableCause::Missing)
    );
}

#[test]
fn every_non_regular_marker_is_no_marker() {
    for kind in ["dir", "fifo", "symlink", "dangling"] {
        let w = World::new();
        let m = w.arch.join(ARCHIVE_MARKER);
        std::fs::remove_file(&m).unwrap();
        match kind {
            "dir" => mkdir(&m),
            "fifo" => mkfifo(&m),
            "symlink" => {
                let real = w.tmp.path().join("real-marker");
                std::fs::write(&real, b"").unwrap();
                symlink(&real, &m).unwrap();
            }
            _ => symlink(w.tmp.path().join("nowhere"), &m).unwrap(),
        }
        let (usage, cfg) = (w.fake(1 << 40, 1 << 40), w.cfg());
        let (mut lp, _) = Storage::open(cfg, w.index, usage).unwrap();
        let rep = lp.tick(now()).unwrap();
        assert_eq!(
            rep.archive,
            ArchiveProbe::Unavailable(UnavailableCause::NoMarker),
            "{kind}"
        );
    }
}

#[test]
fn a_delete_while_the_archive_is_unavailable_never_touches_the_archive_twin() {
    let mut w = World::new();
    let id = w.add(0, Tier::Hot, true);
    // An archive twin of the hot row (a crash after M6), on an archive that is unavailable.
    let a = w.arch.join(rel(0));
    std::fs::create_dir_all(a.parent().unwrap()).unwrap();
    std::fs::write(&a, vec![7_u8; SEG]).unwrap();
    std::fs::remove_file(w.arch.join(ARCHIVE_MARKER)).unwrap();
    let (usage, cfg) = (w.fake(SEG as u64 + 1, 1 << 40), w.cfg());
    let (mut lp, files) = Storage::open(cfg, w.index, usage).unwrap();
    let rep = lp.tick(now()).unwrap();
    assert_eq!(rep.deleted, 1, "{rep:?}");
    assert_eq!(tier_of(&files, id).unwrap_err(), SegmentOpenError::NotFound);
    assert_eq!(std::fs::metadata(&a).unwrap().len(), SEG as u64);
}

#[test]
fn files_port_never_hangs_on_a_fifo_archive_copy() {
    let mut w = World::new();
    let id = w.add(0, Tier::Archive, false);
    let a = w.arch.join(rel(0));
    std::fs::create_dir_all(a.parent().unwrap()).unwrap();
    mkfifo(&a);
    let (usage, cfg) = (w.fake(1 << 40, 1 << 40), w.cfg());
    let (mut lp, files) = Storage::open(cfg, w.index, usage).unwrap();
    lp.tick(now()).unwrap();
    assert!(matches!(
        files.open_segment(id),
        Err(SegmentOpenError::Io { .. })
    ));
}
