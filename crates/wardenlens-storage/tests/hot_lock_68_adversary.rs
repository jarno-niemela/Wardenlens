//! Adversarial tests for PR #198 round 2 (ticket #68): the service's lock file
//! `<hot_root>/.wardenlens.lock` is skipped by the start-up reconciliation **at the hot root
//! only**, and `Storage::open_on` works on the handle it is given. Temporary directories only.
#![expect(clippy::unwrap_used, reason = "test code")]

use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};

use wardenlens_core::storage::{MinFreePercent, Policy};
use wardenlens_core::time::{DurationMs, Timestamp};
use wardenlens_fsutil::RootDir;
use wardenlens_index::Index;
use wardenlens_storage::{
    ARCHIVE_MARKER, HOT_LOCK_FILE, ReconcileReport, StatvfsUsage, Storage, StorageConfig,
    StorageError,
};

struct World {
    _tmp: tempfile::TempDir,
    hot: PathBuf,
    arch: PathBuf,
    idx: PathBuf,
}

impl World {
    fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let hot = tmp.path().join("hot");
        let arch = tmp.path().join("arch");
        let idx = tmp.path().join("idx");
        for d in [&hot, &arch, &idx] {
            std::fs::DirBuilder::new().mode(0o700).create(d).unwrap();
        }
        std::fs::write(arch.join(ARCHIVE_MARKER), b"").unwrap();
        Self {
            _tmp: tmp,
            hot,
            arch,
            idx,
        }
    }

    fn cfg(&self, hot_root: PathBuf) -> StorageConfig {
        StorageConfig::new(
            hot_root,
            self.arch.clone(),
            Policy {
                hot_min_free: MinFreePercent::new(5).unwrap(),
                archive_min_free: MinFreePercent::new(5).unwrap(),
                hot_max_age: DurationMs::from_secs(60),
                emergency_reserve_bytes: 0,
            },
        )
        .with_allow_same_filesystem(true)
    }

    fn reconcile(&self) -> ReconcileReport {
        let index = Index::open(&self.idx.join("index.db")).unwrap();
        let (mut lp, _files) =
            Storage::open(self.cfg(self.hot.clone()), index, StatvfsUsage).unwrap();
        lp.reconcile_startup().unwrap().report
    }
}

fn put(p: &Path, bytes: &[u8]) {
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, bytes).unwrap();
}

#[test]
fn the_lock_name_on_the_archive_root_is_still_reported_as_unknown() {
    let w = World::new();
    put(&w.arch.join(HOT_LOCK_FILE), b"");
    let r = w.reconcile();
    assert_eq!(r.unknown_left, 1, "{r:?}");
    assert!(w.arch.join(HOT_LOCK_FILE).exists());
}

#[test]
fn the_lock_name_inside_a_camera_directory_is_still_reported_as_unknown() {
    let w = World::new();
    put(&w.hot.join("cam-1").join(HOT_LOCK_FILE), b"");
    let r = w.reconcile();
    assert_eq!(r.unknown_left, 1, "{r:?}");
    assert!(w.hot.join("cam-1").join(HOT_LOCK_FILE).exists());
}

#[test]
fn the_hot_lock_file_survives_reconciliation_and_ticks_byte_identical() {
    let w = World::new();
    put(&w.hot.join(HOT_LOCK_FILE), b"pid 1234\n");
    let index = Index::open(&w.idx.join("index.db")).unwrap();
    let (mut lp, _files) = Storage::open(w.cfg(w.hot.clone()), index, StatvfsUsage).unwrap();
    let r = lp.reconcile_startup().unwrap().report;
    assert_eq!(r.unknown_left, 0, "{r:?}");
    let far = Timestamp::from_unix_millis(4_000_000_000_000);
    for _ in 0..5 {
        let _ = lp.tick(far);
    }
    assert_eq!(
        std::fs::read(w.hot.join(HOT_LOCK_FILE)).unwrap(),
        b"pid 1234\n"
    );
}

/// `open_on` must use the handle, not `cfg.hot_root`: a config path that does not exist does not
/// matter, and the walk sees the handle's directory.
#[test]
fn open_on_uses_the_handed_root_not_the_config_path() {
    let w = World::new();
    put(&w.hot.join("stray.txt"), b"x");
    let index = Index::open(&w.idx.join("index.db")).unwrap();
    let hot = RootDir::open(&w.hot).unwrap();
    let (mut lp, _files) = Storage::open_on(
        hot,
        w.cfg(w.idx.join("no-such-hot-root")),
        index,
        StatvfsUsage,
    )
    .unwrap();
    let r = lp.reconcile_startup().unwrap().report;
    assert_eq!(
        r.unknown_left, 1,
        "the walk did not see the handed root: {r:?}"
    );
    assert_eq!(r.unverified, 0, "{r:?}");
}

#[test]
fn open_on_with_zero_actions_per_tick_is_refused() {
    let w = World::new();
    let index = Index::open(&w.idx.join("index.db")).unwrap();
    let hot = RootDir::open(&w.hot).unwrap();
    let r = Storage::open_on(
        hot,
        w.cfg(w.hot.clone()).with_max_actions_per_tick(0),
        index,
        StatvfsUsage,
    );
    assert!(matches!(r, Err(StorageError::NoActions)));
}
