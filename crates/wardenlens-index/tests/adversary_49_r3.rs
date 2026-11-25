//! Adversarial tests for #49 round 3 (PR #140 at a488163): the read-only `-wal` probe, the full
//! schema and integrity identity checks, the torn-`-wal` rule and the refusal remedies.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    reason = "adversary tests: a failed setup step is a test failure"
)]

use std::collections::BTreeMap;
use std::os::unix::fs::{FileExt, PermissionsExt};
use std::path::{Path, PathBuf};

use wardenlens_core::camera::CameraId;
use wardenlens_core::recording::SegmentRecord;
use wardenlens_core::storage::{SegmentIndex, Tier};
use wardenlens_core::time::{Timestamp, UnixMs};
use wardenlens_index::{Index, IndexError};

const BASE: i64 = 1_700_000_000_000;

fn private_tempdir() -> tempfile::TempDir {
    let d = tempfile::tempdir().unwrap();
    chmod(d.path(), 0o700);
    d
}

fn cam(s: &str) -> CameraId {
    CameraId::new(s).unwrap()
}

fn rec(camera: &str, start: i64, dur: u64, bytes: u64) -> SegmentRecord {
    SegmentRecord::new(cam(camera), UnixMs::new(start).unwrap(), dur, bytes, 1)
}

fn chmod(p: &Path, mode: u32) {
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode)).unwrap();
}

fn sidecar(p: &Path, suffix: &str) -> PathBuf {
    let mut n = p.as_os_str().to_owned();
    n.push(suffix);
    n.into()
}

fn snapshot(dir: &Path) -> BTreeMap<String, Option<Vec<u8>>> {
    let mut out = BTreeMap::new();
    for e in std::fs::read_dir(dir).unwrap() {
        let e = e.unwrap();
        let name = e.file_name().to_string_lossy().into_owned();
        let bytes = if e.file_type().unwrap().is_file() {
            Some(std::fs::read(e.path()).unwrap())
        } else {
            None
        };
        out.insert(name, bytes);
    }
    out
}

fn all_time() -> (Timestamp, Timestamp) {
    (
        Timestamp::from_unix_millis(0),
        Timestamp::from_unix_millis(i64::MAX),
    )
}

fn count(idx: &Index, camera: &str) -> usize {
    let (from, to) = all_time();
    idx.list(&cam(camera), from, to, 1000, None)
        .unwrap()
        .items
        .len()
}

/// A closed index at `dir/index.db` with `n` rows of `camera`; no `-wal` left.
fn index_with(dir: &Path, camera: &str, n: i64) -> PathBuf {
    let path = dir.join("index.db");
    let mut idx = Index::open(&path).unwrap();
    for k in 0..n {
        idx.insert(&rec(camera, BASE + k * 10_000, 1000, 10), Tier::Hot)
            .unwrap();
    }
    drop(idx);
    path
}

fn place(path: &Path, bytes: &[u8]) {
    std::fs::write(path, bytes).unwrap();
    chmod(path, 0o600);
}

/// The `-wal` of another, younger index whose every page is still in its `-wal` (an index before
/// its first checkpoint looks like this; `VACUUM` in WAL mode produces the same shape).
fn complete_wal_of_another_index(camera: &str, n: i64) -> Vec<u8> {
    let other = private_tempdir();
    let path = index_with(other.path(), camera, n);
    let c = rusqlite::Connection::open(&path).unwrap();
    c.execute_batch("VACUUM").unwrap();
    let wal = std::fs::read(sidecar(&path, "-wal")).unwrap();
    assert!(wal.len() > 32);
    drop(c);
    wal
}

// ---------------------------------------------------------------------------------------------
// Identity: a -wal of another index
// ---------------------------------------------------------------------------------------------

/// The identity check proves that the replayed view is *an* index, not *this* index. A `-wal`
/// holding every page of another index (same `application_id`, schema and a clean integrity
/// check) passes it and is replayed onto ours: every row of this index is gone, the other
/// index's rows appear, and ids this index already issued are issued again. ADR 0005 section 5
/// accepts only "a `-wal` copied from another copy of this index"; this one is not.
#[test]
fn a_wal_of_another_index_is_not_replayed_onto_this_one() {
    let dir = private_tempdir();
    let path = index_with(dir.path(), "mine", 5);
    let foreign = complete_wal_of_another_index("theirs", 1);
    place(&sidecar(&path, "-wal"), &foreign);
    let main_before = std::fs::read(&path).unwrap();

    match Index::open(&path) {
        Err(_) => {
            assert_eq!(main_before, std::fs::read(&path).unwrap());
        }
        Ok(mut idx) => {
            let mine = count(&idx, "mine");
            let theirs = count(&idx, "theirs");
            let reissued = idx
                .insert(&rec("mine", BASE + 999_000, 1000, 10), Tier::Hot)
                .unwrap();
            panic!(
                "another index's -wal was replayed onto this one: rows of this index {mine} \
                 (was 5), rows of the other {theirs}, next id {reissued:?} (this index had \
                 already issued 1..=5)"
            );
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Torn -wal rule: what is treated as "empty" is then deleted by SQLite
// ---------------------------------------------------------------------------------------------

/// A `-wal` shorter than a header is classed `Torn` whatever it holds. SQLite never writes a
/// partial header with a non-WAL magic, so a short file of other bytes is not ours, yet the
/// read-write connection's close checkpoints and unlinks it: a foreign sidecar is deleted
/// without a refusal.
#[test]
fn a_short_non_wal_file_named_wal_is_not_deleted() {
    let dir = private_tempdir();
    let path = index_with(dir.path(), "cam1", 3);
    let w = sidecar(&path, "-wal");
    let junk = b"not a sqlite wal".to_vec(); // 16 bytes, no WAL magic
    place(&w, &junk);
    let res = Index::open(&path);
    drop(res);
    assert_eq!(
        std::fs::read(&w).ok(),
        Some(junk),
        "a short non-WAL file beside the index was deleted or rewritten"
    );
}

// ---------------------------------------------------------------------------------------------
// The read-only probe: refusals leave main and -wal byte-identical, with or without a -shm
// ---------------------------------------------------------------------------------------------

/// Crash image of an index whose `-wal` sets `user_version` past this build. Copies `-shm` too
/// when `with_shm` (the stale wal-index a crash leaves).
fn crash_with_newer_version(with_shm: bool) -> (tempfile::TempDir, PathBuf) {
    let live = private_tempdir();
    let path = index_with(live.path(), "cam1", 3);
    let c = rusqlite::Connection::open(&path).unwrap();
    c.execute_batch("PRAGMA user_version = 99;").unwrap();
    let crash = private_tempdir();
    let to = crash.path().join("index.db");
    let mut suffixes = vec!["", "-wal"];
    if with_shm {
        suffixes.push("-shm");
    }
    for s in suffixes {
        place(&sidecar(&to, s), &std::fs::read(sidecar(&path, s)).unwrap());
    }
    drop(c);
    (crash, to)
}

#[test]
fn a_newer_version_only_in_the_wal_is_refused_untouched_without_shm() {
    let (dir, path) = crash_with_newer_version(false);
    let before = snapshot(dir.path());
    let err = Index::open(&path).unwrap_err();
    assert!(
        matches!(err, IndexError::SchemaTooNew { found: 99, .. }),
        "{err:?}"
    );
    assert_eq!(before, snapshot(dir.path()));
}

#[test]
fn a_newer_version_only_in_the_wal_is_refused_with_main_and_wal_untouched_with_stale_shm() {
    let (dir, path) = crash_with_newer_version(true);
    let main = std::fs::read(&path).unwrap();
    let wal = std::fs::read(sidecar(&path, "-wal")).unwrap();
    let err = Index::open(&path).unwrap_err();
    assert!(
        matches!(err, IndexError::SchemaTooNew { found: 99, .. }),
        "{err:?}"
    );
    assert_eq!(main, std::fs::read(&path).unwrap());
    assert_eq!(wal, std::fs::read(sidecar(&path, "-wal")).unwrap());
    assert!(
        sidecar(&path, "-shm").exists(),
        "an existing -shm was removed"
    );
    drop(dir);
}

// ---------------------------------------------------------------------------------------------
// A live writer: the -shm of a live connection is never removed
// ---------------------------------------------------------------------------------------------

/// With another `Index` alive and its rows only in the `-wal`, a second open probes on the real
/// files (the `-shm` exists), must not remove the live `-shm`, and both handles must keep seeing
/// each other's commits.
#[test]
fn a_second_open_beside_a_live_writer_keeps_the_shared_wal_index() {
    let dir = private_tempdir();
    let path = dir.path().join("index.db");
    let mut a = Index::open(&path).unwrap();
    a.insert(&rec("cam1", BASE, 1000, 10), Tier::Hot).unwrap();
    assert!(sidecar(&path, "-wal").metadata().unwrap().len() > 32);
    assert!(sidecar(&path, "-shm").exists());
    let shm_ino = std::os::unix::fs::MetadataExt::ino(&sidecar(&path, "-shm").metadata().unwrap());
    let mut b = Index::open(&path).unwrap();
    let shm_after =
        std::os::unix::fs::MetadataExt::ino(&sidecar(&path, "-shm").metadata().unwrap());
    assert_eq!(shm_ino, shm_after, "the live -shm was replaced");
    b.insert(&rec("cam1", BASE + 10_000, 1000, 10), Tier::Hot)
        .unwrap();
    a.insert(&rec("cam1", BASE + 20_000, 1000, 10), Tier::Hot)
        .unwrap();
    assert_eq!(count(&a, "cam1"), 3);
    assert_eq!(count(&b, "cam1"), 3);
}

// ---------------------------------------------------------------------------------------------
// Remedies: following the message loses nothing and lets the index open
// ---------------------------------------------------------------------------------------------

/// `ForeignWal` says "move it and its -shm out of the directory". Doing so must open the index
/// with every row of the main file.
#[test]
fn following_the_foreign_wal_remedy_opens_the_main_file_rows() {
    let dir = private_tempdir();
    let path = index_with(dir.path(), "cam1", 4);
    // A -wal of another page size.
    let other = private_tempdir();
    let op = other.path().join("o.db");
    let c = rusqlite::Connection::open(&op).unwrap();
    c.execute_batch(
        "PRAGMA page_size = 8192; PRAGMA journal_mode = WAL; CREATE TABLE t (x); \
         INSERT INTO t VALUES (1);",
    )
    .unwrap();
    let wal = std::fs::read(sidecar(&op, "-wal")).unwrap();
    drop(c);
    let w = sidecar(&path, "-wal");
    place(&w, &wal);
    let err = Index::open(&path).unwrap_err();
    assert!(matches!(err, IndexError::ForeignWal), "{err:?}");
    let keep = private_tempdir();
    std::fs::rename(&w, keep.path().join("index.db-wal")).unwrap();
    let shm = sidecar(&path, "-shm");
    if shm.exists() {
        std::fs::rename(&shm, keep.path().join("index.db-shm")).unwrap();
    }
    let idx = Index::open(&path).unwrap();
    assert_eq!(count(&idx, "cam1"), 4);
}

/// `InvalidWal` says the `-wal` "holds no data of this index and can be deleted". Deleting it
/// opens the index with every row.
#[test]
fn following_the_invalid_wal_remedy_opens_the_main_file_rows() {
    let dir = private_tempdir();
    let path = index_with(dir.path(), "cam1", 4);
    let w = sidecar(&path, "-wal");
    place(&w, &[0x5a; 4096]);
    let err = Index::open(&path).unwrap_err();
    assert!(matches!(err, IndexError::InvalidWal), "{err:?}");
    std::fs::remove_file(&w).unwrap();
    let idx = Index::open(&path).unwrap();
    assert_eq!(count(&idx, "cam1"), 4);
}

/// When the main file is damaged and the `-wal` is this index's own, the error must not call
/// the `-wal` foreign: the owner is told the `-wal` "does not belong to this index", moves it
/// out, then meets `Damaged` on the main file with the committed `-wal` frames set aside as
/// someone else's (P6, an error that lies).
#[test]
fn a_damaged_main_file_with_its_own_wal_is_not_reported_as_a_foreign_wal() {
    let live = private_tempdir();
    let path = index_with(live.path(), "cam1", 40);
    // Damage the main file in the root page of `segments_camera_start`, which the -wal below
    // does not rewrite.
    let c = rusqlite::Connection::open(&path).unwrap();
    let root: i64 = c
        .query_row(
            "SELECT rootpage FROM sqlite_master WHERE name = 'segments_camera_start'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    // Own -wal frame: a write that touches only `sqlite_sequence`'s page via a no-op update.
    c.execute_batch("UPDATE sqlite_sequence SET seq = seq + 1000 WHERE name = 'segments';")
        .unwrap();
    let crash = private_tempdir();
    let to = crash.path().join("index.db");
    for s in ["", "-wal"] {
        place(&sidecar(&to, s), &std::fs::read(sidecar(&path, s)).unwrap());
    }
    drop(c);
    assert!(
        std::fs::metadata(sidecar(&to, "-wal")).unwrap().len() > 32,
        "setup: the -wal must hold a frame"
    );
    let f = std::fs::OpenOptions::new().write(true).open(&to).unwrap();
    f.write_all_at(&[0xff; 64], u64::try_from(root - 1).unwrap() * 4096 + 8)
        .unwrap();
    drop(f);
    let err = Index::open(&to).unwrap_err();
    assert!(
        matches!(err, IndexError::Damaged),
        "the main file is damaged and the -wal is the index's own, got {err:?}"
    );
}
