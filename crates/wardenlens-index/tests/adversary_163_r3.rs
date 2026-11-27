//! Adversarial tests for #163 round 3 (PR #213 at 2a101aa): `Index::open_read_only`.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::arithmetic_side_effects,
    reason = "adversary tests: a failed setup step is a test failure"
)]

use std::collections::BTreeMap;
use std::num::NonZeroU16;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use wardenlens_core::camera::{CameraId, ModelRef, RtspPath, StreamSet};
use wardenlens_core::time::UnixMs;
use wardenlens_index::{CameraRecord, Index, IndexError};

const BASE: i64 = 1_700_000_000_000;

fn private_tempdir() -> tempfile::TempDir {
    let d = tempfile::tempdir().unwrap();
    std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    d
}

fn chmod(p: &Path, mode: u32) {
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode)).unwrap();
}

fn sidecar(p: &Path, suffix: &str) -> PathBuf {
    let mut n = p.as_os_str().to_owned();
    n.push(suffix);
    n.into()
}

fn record(id: &str) -> CameraRecord {
    CameraRecord::new(
        CameraId::new(id).unwrap(),
        ModelRef::new("acme", "c1").unwrap(),
        NonZeroU16::new(554).unwrap(),
        StreamSet::new(RtspPath::new("/s").unwrap(), None),
    )
}

fn snapshot(dir: &Path) -> BTreeMap<String, Vec<u8>> {
    std::fs::read_dir(dir)
        .unwrap()
        .map(|e| {
            let e = e.unwrap();
            let name = e.file_name().to_string_lossy().into_owned();
            let ft = e.file_type().unwrap();
            let bytes = if ft.is_file() {
                std::fs::read(e.path()).unwrap()
            } else {
                b"<not a file>".to_vec()
            };
            (name, bytes)
        })
        .collect()
}

/// A directory holding the files a writer that crashed with `n` committed cameras leaves:
/// `index.db`, a non-empty `index.db-wal` and `index.db-shm` (copied while the writer is open).
fn crashed_with_shm(n: usize) -> (tempfile::TempDir, PathBuf) {
    let live = private_tempdir();
    let lp = live.path().join("index.db");
    let mut idx = Index::open(&lp).unwrap();
    for i in 0..n {
        idx.upsert_camera(
            &record(&format!("cam-{i}")),
            &[],
            UnixMs::new(BASE).unwrap(),
        )
        .unwrap();
    }
    assert!(std::fs::metadata(sidecar(&lp, "-wal")).unwrap().len() > 0);
    let g = private_tempdir();
    for name in ["index.db", "index.db-wal", "index.db-shm"] {
        let to = g.path().join(name);
        std::fs::copy(live.path().join(name), &to).unwrap();
        chmod(&to, 0o600);
    }
    drop(idx);
    let p = g.path().join("index.db");
    (g, p)
}

#[test]
fn a_crashed_writer_with_wal_and_shm_is_read_and_main_and_wal_are_untouched() {
    let (g, p) = crashed_with_shm(3);
    let before = snapshot(g.path());
    for _ in 0..5 {
        let ro = Index::open_read_only(&p).unwrap();
        assert_eq!(ro.list_cameras(&[]).unwrap().len(), 3);
        drop(ro);
    }
    let after = snapshot(g.path());
    assert_eq!(
        before.keys().collect::<Vec<_>>(),
        after.keys().collect::<Vec<_>>(),
        "a file was created or removed"
    );
    for name in ["index.db", "index.db-wal"] {
        assert_eq!(after[name], before[name], "{name} changed");
    }
    if after["index.db-shm"] != before["index.db-shm"] {
        eprintln!("NOTE: the -shm changed under the read-only open (documented)");
    }
    // The real open still agrees.
    let rw = Index::open(&p).unwrap();
    assert_eq!(rw.list_cameras(&[]).unwrap().len(), 3);
}

#[test]
fn a_zero_length_shm_with_a_live_wal_is_read_and_main_and_wal_are_untouched() {
    let (g, p) = crashed_with_shm(2);
    std::fs::write(sidecar(&p, "-shm"), b"").unwrap();
    let before = snapshot(g.path());
    let ro = Index::open_read_only(&p);
    let after = snapshot(g.path());
    for name in ["index.db", "index.db-wal"] {
        assert_eq!(after[name], before[name], "{name} changed");
    }
    let read_only_rows = ro.map(|r| r.list_cameras(&[]).unwrap().len());
    let read_write_rows = Index::open(&p).unwrap().list_cameras(&[]).unwrap().len();
    match read_only_rows {
        Ok(n) => assert_eq!(n, read_write_rows),
        Err(e) => panic!("read-only refused what the read-write open accepts: {e:?}"),
    }
}

#[test]
fn a_garbage_shm_with_a_live_wal_does_not_change_main_or_wal() {
    let (g, p) = crashed_with_shm(2);
    let shm = sidecar(&p, "-shm");
    let len = std::fs::metadata(&shm).unwrap().len();
    std::fs::write(&shm, vec![0xA5u8; usize::try_from(len).unwrap()]).unwrap();
    let before = snapshot(g.path());
    let ro = Index::open_read_only(&p);
    if let Ok(ro) = &ro {
        assert_eq!(ro.list_cameras(&[]).unwrap().len(), 2);
    }
    drop(ro);
    let after = snapshot(g.path());
    for name in ["index.db", "index.db-wal"] {
        assert_eq!(after[name], before[name], "{name} changed");
    }
}

#[test]
fn a_dangling_symlink_is_not_reported_as_a_missing_file() {
    let d = private_tempdir();
    let p = d.path().join("index.db");
    std::os::unix::fs::symlink(d.path().join("nowhere.db"), &p).unwrap();
    let err = Index::open_read_only(&p).unwrap_err();
    assert!(
        !matches!(&err, IndexError::Fs(e) if e.is_not_found()),
        "a dangling symlink is reported as not found, so the dry run would treat it as no index: {err:?}"
    );
    assert!(!d.path().join("nowhere.db").exists());
    assert!(Index::open(&p).is_err());
}

#[test]
fn a_symlinked_shm_or_wal_is_refused_and_its_target_untouched() {
    for suffix in ["-shm", "-wal"] {
        let (g, p) = crashed_with_shm(1);
        let side = sidecar(&p, suffix);
        let target = g.path().join(format!("target{suffix}"));
        std::fs::rename(&side, &target).unwrap();
        std::os::unix::fs::symlink(&target, &side).unwrap();
        let before = std::fs::read(&target).unwrap();
        let main_before = std::fs::read(&p).unwrap();
        let ro = Index::open_read_only(&p);
        assert!(ro.is_err(), "{suffix}: a symlinked sidecar was followed");
        drop(ro);
        assert_eq!(std::fs::read(&target).unwrap(), before, "{suffix}: target");
        assert_eq!(std::fs::read(&p).unwrap(), main_before, "{suffix}: main");
        assert!(Index::open(&p).is_err(), "{suffix}: read-write accepted");
    }
}

#[test]
fn a_hard_linked_index_is_refused_read_only_and_nothing_written() {
    let d = private_tempdir();
    let p = d.path().join("index.db");
    let mut idx = Index::open(&p).unwrap();
    idx.upsert_camera(&record("cam-1"), &[], UnixMs::new(BASE).unwrap())
        .unwrap();
    drop(idx);
    std::fs::hard_link(&p, d.path().join("other.db")).unwrap();
    let before = snapshot(d.path());
    for q in [p.clone(), d.path().join("other.db")] {
        let err = Index::open_read_only(&q).unwrap_err();
        assert!(matches!(err, IndexError::HardLinkedIndex), "{err:?}");
    }
    assert_eq!(snapshot(d.path()), before);
}

#[test]
fn an_insecure_parent_is_refused_like_the_real_open() {
    let d = private_tempdir();
    let p = d.path().join("index.db");
    drop(Index::open(&p).unwrap());
    chmod(d.path(), 0o777);
    let before = snapshot(d.path());
    let ro = Index::open_read_only(&p).unwrap_err();
    assert_eq!(snapshot(d.path()), before);
    let rw = Index::open(&p).unwrap_err();
    chmod(d.path(), 0o700);
    assert_eq!(ro.to_string(), rw.to_string());
}

#[test]
fn a_missing_parent_is_refused_and_not_created() {
    let d = private_tempdir();
    let p = d.path().join("nope").join("index.db");
    let err = Index::open_read_only(&p).unwrap_err();
    assert!(!d.path().join("nope").exists());
    // The same refusal as the real open, and the real open creates nothing either.
    let rw = Index::open(&p).unwrap_err();
    assert!(!d.path().join("nope").exists());
    assert_eq!(err.to_string(), rw.to_string());
    assert!(matches!(err, IndexError::Fs(_)), "{err:?}");
}

#[test]
fn a_directory_or_fifo_at_the_path_is_refused_not_missing() {
    let d = private_tempdir();
    let p = d.path().join("index.db");
    std::fs::create_dir(&p).unwrap();
    let err = Index::open_read_only(&p).unwrap_err();
    assert!(
        !matches!(&err, IndexError::Fs(e) if e.is_not_found()),
        "{err:?}"
    );
    std::fs::remove_dir(&p).unwrap();
    rustix::fs::mkfifoat(rustix::fs::CWD, &p, rustix::fs::Mode::from_raw_mode(0o600)).ok();
    if p.exists() {
        let err = Index::open_read_only(&p).unwrap_err();
        assert!(
            !matches!(&err, IndexError::Fs(e) if e.is_not_found()),
            "{err:?}"
        );
    }
}

#[test]
fn a_read_only_handle_blocks_a_read_write_open_until_dropped() {
    let d = private_tempdir();
    let p = d.path().join("index.db");
    let mut idx = Index::open(&p).unwrap();
    idx.upsert_camera(&record("cam-1"), &[], UnixMs::new(BASE).unwrap())
        .unwrap();
    drop(idx);
    let ro = Index::open_read_only(&p).unwrap();
    assert!(matches!(
        Index::open(&p),
        Err(IndexError::AlreadyOpenInProcess)
    ));
    assert!(matches!(
        Index::open_read_only(&p),
        Err(IndexError::AlreadyOpenInProcess)
    ));
    assert_eq!(ro.list_cameras(&[]).unwrap().len(), 1);
    drop(ro);
    let mut rw = Index::open(&p).unwrap();
    rw.upsert_camera(&record("cam-2"), &[], UnixMs::new(BASE).unwrap())
        .unwrap();
    assert_eq!(rw.list_cameras(&[]).unwrap().len(), 2);
}

/// A failed read-only open must release the registry entry, or the real run in the same process
/// could never open the file.
#[test]
fn a_refused_read_only_open_releases_the_registry() {
    let d = private_tempdir();
    let p = d.path().join("index.db");
    drop(Index::open(&p).unwrap());
    let j = sidecar(&p, "-journal");
    std::fs::write(&j, b"").unwrap();
    chmod(&j, 0o600);
    assert!(Index::open_read_only(&p).is_err());
    std::fs::remove_file(&j).unwrap();
    drop(Index::open_read_only(&p).unwrap());
    drop(Index::open(&p).unwrap());
    // And a NeedsRecovery / Uninitialised return releases it too.
    let e = d.path().join("empty.db");
    std::fs::write(&e, b"").unwrap();
    chmod(&e, 0o600);
    assert!(matches!(
        Index::open_read_only(&e),
        Err(IndexError::Uninitialised)
    ));
    drop(Index::open(&e).unwrap());
}

#[test]
fn an_owner_read_only_file_behaves_like_the_real_open() {
    let d = private_tempdir();
    let p = d.path().join("index.db");
    drop(Index::open(&p).unwrap());
    chmod(&p, 0o400);
    let ro = Index::open_read_only(&p).map(|_| ());
    let rw = Index::open(&p).map(|_| ());
    chmod(&p, 0o600);
    assert_eq!(
        ro.as_ref().map_err(ToString::to_string),
        rw.as_ref().map_err(ToString::to_string),
        "read-only and read-write disagree on an owner-read-only file"
    );
}

/// A `-wal` with only its 32-byte header (a writer that crashed before its first commit, or
/// after a checkpoint reset) and no `-shm`: there is nothing to recover.
#[test]
fn a_header_only_wal_without_shm() {
    let (g, p) = crashed_with_shm(1);
    let wal = sidecar(&p, "-wal");
    let bytes = std::fs::read(&wal).unwrap();
    std::fs::write(&wal, &bytes[..32]).unwrap();
    std::fs::remove_file(sidecar(&p, "-shm")).unwrap();
    let before = snapshot(g.path());
    let ro = Index::open_read_only(&p).map(|r| r.list_cameras(&[]).unwrap().len());
    assert_eq!(snapshot(g.path()), before, "read-only wrote");
    let rw = Index::open(&p).map(|r| r.list_cameras(&[]).unwrap().len());
    // A valid header counts as a usable `-wal`, so the reader must not create the `-shm`; the real
    // open recovers it.
    assert!(matches!(ro, Err(IndexError::NeedsRecovery)), "{ro:?}");
    // (The row lived in the cut-off frames, so the recovered index has none.)
    assert_eq!(rw.unwrap(), 0);
}

#[test]
fn many_cameras_in_the_wal_are_all_seen() {
    let (g, p) = crashed_with_shm(200);
    let before = snapshot(g.path());
    let ro = Index::open_read_only(&p).unwrap();
    assert_eq!(ro.list_cameras(&[]).unwrap().len(), 200);
    drop(ro);
    let after = snapshot(g.path());
    for name in ["index.db", "index.db-wal"] {
        assert_eq!(after[name], before[name], "{name} changed");
    }
}
