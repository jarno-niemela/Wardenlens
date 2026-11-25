//! Test kit: a temporary hot and archive directory, the real SQLite index behind a fault
//! switch, and a fake volume-usage source that measures the two directories.

use std::collections::HashMap;
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

use crate::{ProbeError, StorageConfig, VolumeUsage};

pub(crate) const T0: i64 = 1_700_000_000_000;

#[derive(Default)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "one independent switch per index call"
)]
pub(crate) struct IdxFaults {
    /// Runs once, right after the next successful `get` returned its row (a move racing a reader).
    pub(crate) get_hook: Option<Box<dyn FnOnce() + Send>>,
    pub(crate) gets: u32,
    pub(crate) set_tier: bool,
    pub(crate) get: bool,
    pub(crate) delete: bool,
    pub(crate) oldest: bool,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum TestIdxError {
    #[error("injected")]
    Injected,
    #[error("{0}")]
    Real(#[from] IndexError),
}

/// The real index, shared so the test can keep inserting after the loop took one handle.
#[derive(Clone)]
pub(crate) struct TestIndex {
    pub(crate) inner: Arc<Mutex<Index>>,
    pub(crate) faults: Arc<Mutex<IdxFaults>>,
}

impl TestIndex {
    fn with<R>(&self, f: impl FnOnce(&mut Index) -> R) -> R {
        f(&mut self.inner.lock().unwrap_or_else(PoisonError::into_inner))
    }
    fn faulty(&self, pick: impl FnOnce(&IdxFaults) -> bool) -> Result<(), TestIdxError> {
        if pick(&self.faults.lock().unwrap_or_else(PoisonError::into_inner)) {
            Err(TestIdxError::Injected)
        } else {
            Ok(())
        }
    }
}

impl SegmentIndex for TestIndex {
    type Error = TestIdxError;
    fn insert(&mut self, record: &SegmentRecord, tier: Tier) -> Result<SegmentId, Self::Error> {
        Ok(self.with(|i| i.insert(record, tier))?)
    }
    fn get(&self, id: SegmentId) -> Result<Option<IndexedSegment>, Self::Error> {
        self.faulty(|f| f.get)?;
        let row = self.with(|i| i.get(id))?;
        let hook = {
            let mut f = self.faults.lock().unwrap_or_else(PoisonError::into_inner);
            f.gets += 1;
            f.get_hook.take()
        };
        if let Some(h) = hook {
            h();
        }
        Ok(row)
    }
    fn list(
        &self,
        camera: &CameraId,
        from: Timestamp,
        to: Timestamp,
        limit: usize,
        cursor: Option<&SegmentCursor>,
    ) -> Result<SegmentPage, Self::Error> {
        Ok(self.with(|i| i.list(camera, from, to, limit, cursor))?)
    }
    fn set_tier(&mut self, id: SegmentId, tier: Tier) -> Result<(), Self::Error> {
        self.faulty(|f| f.set_tier)?;
        Ok(self.with(|i| i.set_tier(id, tier))?)
    }
    fn delete(&mut self, id: SegmentId) -> Result<(), Self::Error> {
        self.faulty(|f| f.delete)?;
        Ok(self.with(|i| i.delete(id))?)
    }
    fn oldest(
        &self,
        tier: Tier,
        after: Option<(Timestamp, SegmentId)>,
        n: usize,
    ) -> Result<Vec<StoredSegment>, Self::Error> {
        self.faulty(|f| f.oldest)?;
        Ok(self.with(|i| i.oldest(tier, after, n))?)
    }
    fn bytes_by_tier(&self) -> Result<TierTotals, Self::Error> {
        Ok(self.with(|i| i.bytes_by_tier())?)
    }
    fn latest_started_at(&self, camera: &CameraId) -> Result<Option<UnixMs>, Self::Error> {
        Ok(self.with(|i| i.latest_started_at(camera))?)
    }
}

/// Free space = a pretend capacity minus the bytes under the directory of the tier (quarantine
/// included).
#[derive(Clone)]
pub(crate) struct FakeUsage {
    pub(crate) hot: PathBuf,
    pub(crate) arch: PathBuf,
    pub(crate) caps: Arc<Mutex<HashMap<&'static str, u64>>>,
    /// Tiers whose probe fails with an I/O error.
    pub(crate) io_error: Arc<Mutex<Vec<Tier>>>,
    /// Report more free space than capacity for the hot volume.
    pub(crate) hot_overfull: Arc<Mutex<bool>>,
}

pub(crate) fn du(dir: &Path) -> u64 {
    let mut total = 0;
    let Ok(rd) = std::fs::read_dir(dir) else {
        return 0;
    };
    for e in rd.flatten() {
        let Ok(m) = e.metadata() else { continue };
        total += if m.is_dir() { du(&e.path()) } else { m.len() };
    }
    total
}

impl VolumeUsage for FakeUsage {
    fn space(&self, tier: Tier, _root: &RootDir) -> Result<VolumeSpace, ProbeError> {
        let (dir, key) = match tier {
            Tier::Hot => (&self.hot, "hot"),
            _ => (&self.arch, "arch"),
        };
        if self.io_error.lock().unwrap().contains(&tier) {
            return Err(ProbeError::Io(Some(rustix::io::Errno::IO)));
        }
        if tier == Tier::Hot && *self.hot_overfull.lock().unwrap() {
            return Ok(VolumeSpace {
                capacity_bytes: 10,
                free_bytes: 11,
            });
        }
        let cap = *self
            .caps
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(key)
            .unwrap_or(&0);
        if cap == 0 {
            return Err(ProbeError::Unusable);
        }
        Ok(VolumeSpace {
            capacity_bytes: cap,
            free_bytes: cap.saturating_sub(du(dir)),
        })
    }
}

pub(crate) struct Env {
    pub(crate) tmp: tempfile::TempDir,
    pub(crate) hot: PathBuf,
    pub(crate) arch: PathBuf,
    pub(crate) index: TestIndex,
    pub(crate) usage: FakeUsage,
}

impl Env {
    /// Both capacities are huge, so nothing is below a floor unless a test lowers them.
    pub(crate) fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let hot = tmp.path().join("hot");
        let arch = tmp.path().join("arch");
        let idx = tmp.path().join("idx");
        for d in [&hot, &arch, &idx] {
            std::fs::DirBuilder::new().mode(0o700).create(d).unwrap();
        }
        std::fs::write(arch.join(crate::ARCHIVE_MARKER), b"").unwrap();
        let index = TestIndex {
            inner: Arc::new(Mutex::new(Index::open(&idx.join("index.db")).unwrap())),
            faults: Arc::default(),
        };
        let caps = Arc::new(Mutex::new(HashMap::from([
            ("hot", 1_u64 << 40),
            ("arch", 1 << 40),
        ])));
        let usage = FakeUsage {
            hot: hot.clone(),
            arch: arch.clone(),
            caps,
            io_error: Arc::default(),
            hot_overfull: Arc::default(),
        };
        Self {
            tmp,
            hot,
            arch,
            index,
            usage,
        }
    }

    pub(crate) fn set_cap(&self, tier: &'static str, cap: u64) {
        self.usage.caps.lock().unwrap().insert(tier, cap);
    }

    pub(crate) fn cfg(&self) -> StorageConfig {
        StorageConfig {
            hot_root: self.hot.clone(),
            archive_root: self.arch.clone(),
            policy: Policy {
                hot_min_free: MinFreePercent::new(25).unwrap(),
                archive_min_free: MinFreePercent::new(25).unwrap(),
                hot_max_age: DurationMs::from_secs(12 * 3600),
                emergency_reserve_bytes: 0,
            },
            max_actions_per_tick: 64,
            allow_same_filesystem: true,
        }
    }

    pub(crate) fn rel(cam: &str, n: i64) -> String {
        let cam: CameraId = cam.parse().unwrap();
        RelPath::new(&cam, UnixMs::new(T0 + n * 60_000).unwrap()).to_string()
    }

    /// Write a file of `bytes` bytes (a recognisable pattern) on `tier` and insert its row.
    pub(crate) fn add(&self, cam: &str, n: i64, bytes: usize, tier: Tier) -> SegmentId {
        let root = if tier == Tier::Hot {
            &self.hot
        } else {
            &self.arch
        };
        let p = root.join(Self::rel(cam, n));
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, pattern(bytes)).unwrap();
        self.row(cam, n, bytes, tier)
    }

    /// Insert a row only (no file).
    pub(crate) fn row(&self, cam: &str, n: i64, bytes: usize, tier: Tier) -> SegmentId {
        let rec = SegmentRecord::new(
            cam.parse().unwrap(),
            UnixMs::new(T0 + n * 60_000).unwrap(),
            1000,
            bytes as u64,
            30,
        );
        self.index.clone().insert(&rec, tier).unwrap()
    }

    pub(crate) fn tier_of(&self, id: SegmentId) -> Option<Tier> {
        self.index.get(id).unwrap().map(|r| r.tier)
    }

    pub(crate) fn hot_file(&self, cam: &str, n: i64) -> PathBuf {
        self.hot.join(Self::rel(cam, n))
    }

    pub(crate) fn arch_file(&self, cam: &str, n: i64) -> PathBuf {
        self.arch.join(Self::rel(cam, n))
    }

    /// Every file below `root/_quarantine`, with its content.
    pub(crate) fn quarantined(root: &Path) -> Vec<Vec<u8>> {
        fn walk(d: &Path, out: &mut Vec<Vec<u8>>) {
            let Ok(rd) = std::fs::read_dir(d) else { return };
            for e in rd.flatten() {
                if e.path().is_dir() {
                    walk(&e.path(), out);
                } else {
                    out.push(std::fs::read(e.path()).unwrap());
                }
            }
        }
        let mut out = Vec::new();
        walk(&root.join("_quarantine"), &mut out);
        out
    }
}

pub(crate) fn pattern(n: usize) -> Vec<u8> {
    (0..n).map(|i| u8::try_from(i % 251).unwrap()).collect()
}

pub(crate) fn now() -> Timestamp {
    Timestamp::from_unix_millis(T0 + 3_600_000)
}
