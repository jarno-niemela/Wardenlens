//! Adversarial tests for #158 round 2 (PR #185 at 826e6f2): the child-side `F_SETLK` probe.
//!
//! 1. The probe itself: it must never change the database (bytes and mtime), and must answer
//!    from the main file only (an `F_WRLCK` held by a third process on a *sidecar* is not the
//!    main-file lock).
//! 2. The invariant the probe guards ("an open Index keeps SQLite's POSIX lock on the main
//!    file", #49) across repeated operations on one Index. (A second `Index::open` of the same
//!    inode in the same process does drop the first one's lock; ADR 0005 section 5 records that
//!    as an accepted residual, so it is not asserted here.)
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    reason = "adversary tests: a failed setup step is a test failure"
)]

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use wardenlens_core::camera::CameraId;
use wardenlens_core::recording::SegmentRecord;
use wardenlens_core::storage::{SegmentIndex, Tier};
use wardenlens_core::time::UnixMs;
use wardenlens_index::Index;

const BASE: i64 = 1_700_000_000_000;
const PROBE_ENV: &str = "WL158R2_PROBE_PATH";
const MARK: &str = "WL158R2:";

fn private_tempdir() -> tempfile::TempDir {
    let d = tempfile::tempdir().unwrap();
    std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    d
}

fn rec(camera: &str, start: i64) -> SegmentRecord {
    SegmentRecord::new(
        CameraId::new(camera).unwrap(),
        UnixMs::new(start).unwrap(),
        1000,
        10,
        1,
    )
}

/// Same probe as `adversary_49_r4.rs` (copied: test binaries cannot share helpers).
fn another_process_sees_the_main_file_locked(path: &Path) -> bool {
    let out = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "child_lock_probe_entry",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(PROBE_ENV, path)
        .stdin(Stdio::null())
        .stderr(Stdio::inherit())
        .output()
        .unwrap();
    assert!(out.status.success(), "probe child failed: {:?}", out.status);
    let stdout = String::from_utf8(out.stdout).unwrap();
    let verdict = stdout
        .lines()
        .find_map(|l| l.split_once(MARK).map(|(_, rest)| rest.to_owned()))
        .unwrap_or_else(|| panic!("probe child printed no verdict: {stdout}"));
    match verdict.as_str() {
        "locked" => true,
        "unlocked" => false,
        other => panic!("probe child said {other}"),
    }
}

#[test]
fn child_lock_probe_entry() {
    let Some(path) = std::env::var_os(PROBE_ENV) else {
        return;
    };
    let f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(PathBuf::from(path))
        .unwrap();
    let verdict =
        match rustix::fs::fcntl_lock(&f, rustix::fs::FlockOperation::NonBlockingLockExclusive) {
            Ok(()) => "unlocked",
            Err(e) if e == rustix::io::Errno::AGAIN || e == rustix::io::Errno::ACCESS => "locked",
            Err(e) => panic!("unexpected probe error: {e}"),
        };
    println!("{MARK}{verdict}");
    std::io::stdout().flush().unwrap();
}

fn sidecar(p: &Path, suffix: &str) -> PathBuf {
    let mut s = p.as_os_str().to_owned();
    s.push(suffix);
    PathBuf::from(s)
}

// ---------------------------------------------------------------------------------------------
// The probe
// ---------------------------------------------------------------------------------------------

/// An "unlocked" probe takes a whole-file write lock in the child through a read-write
/// descriptor. Neither the bytes nor the mtime of the main file or the sidecars may change.
#[test]
fn an_unlocked_probe_changes_no_byte_and_no_mtime() {
    let dir = private_tempdir();
    let path = dir.path().join("index.db");
    {
        let mut idx = Index::open(&path).unwrap();
        idx.insert(&rec("cam1", BASE), Tier::Hot).unwrap();
    }
    let snap = |p: &Path| {
        std::fs::metadata(p)
            .ok()
            .map(|m| (std::fs::read(p).unwrap(), m.modified().unwrap(), m.len()))
    };
    let before = (
        snap(&path),
        snap(&sidecar(&path, "-wal")),
        snap(&sidecar(&path, "-shm")),
    );
    for _ in 0..3 {
        assert!(!another_process_sees_the_main_file_locked(&path));
    }
    let after = (
        snap(&path),
        snap(&sidecar(&path, "-wal")),
        snap(&sidecar(&path, "-shm")),
    );
    assert!(before == after, "the probe changed the database files");
}

/// The same for a "locked" probe on a live Index. Only `stat` is used afterwards: reading the
/// file here would open and close a descriptor of the inode and drop the lock being measured.
#[test]
fn a_locked_probe_changes_no_size_and_no_mtime() {
    let dir = private_tempdir();
    let path = dir.path().join("index.db");
    let mut idx = Index::open(&path).unwrap();
    idx.insert(&rec("cam1", BASE), Tier::Hot).unwrap();
    let st = |p: &Path| {
        let m = std::fs::metadata(p).unwrap();
        (m.len(), m.modified().unwrap())
    };
    let before = (
        st(&path),
        st(&sidecar(&path, "-wal")),
        st(&sidecar(&path, "-shm")),
    );
    for _ in 0..3 {
        assert!(another_process_sees_the_main_file_locked(&path));
    }
    let after = (
        st(&path),
        st(&sidecar(&path, "-wal")),
        st(&sidecar(&path, "-shm")),
    );
    assert_eq!(before, after);
    drop(idx);
}

/// The probe targets the path it is given, not a sidecar: a dropped main-file lock is
/// "unlocked" even while this process holds every `-shm` lock SQLite took, and probing the
/// `-shm` itself (which SQLite does lock) answers "locked", so the two are told apart.
#[test]
fn the_probe_tells_the_main_file_from_the_shm() {
    let dir = private_tempdir();
    let path = dir.path().join("plain.db");
    let c = rusqlite::Connection::open(&path).unwrap();
    c.query_row("PRAGMA journal_mode = WAL", [], |r| r.get::<_, String>(0))
        .unwrap();
    c.execute_batch("CREATE TABLE t (x); INSERT INTO t VALUES (1);")
        .unwrap();
    // SQLite holds a shared DMS lock on the -shm for the life of the connection.
    assert!(another_process_sees_the_main_file_locked(&sidecar(
        &path, "-shm"
    )));
    drop(std::fs::File::open(&path).unwrap());
    assert!(!another_process_sees_the_main_file_locked(&path));
    assert!(another_process_sees_the_main_file_locked(&sidecar(
        &path, "-shm"
    )));
    drop(c);
}

// ---------------------------------------------------------------------------------------------
// The #49 invariant through the other in-process entry points
// ---------------------------------------------------------------------------------------------

/// Control: the invariant holds across reads and writes on one Index.
#[test]
fn an_index_keeps_its_main_file_lock_across_operations() {
    let dir = private_tempdir();
    let path = dir.path().join("index.db");
    let mut idx = Index::open(&path).unwrap();
    for i in 0..5 {
        let id = idx
            .insert(&rec("cam1", BASE + i * 50_000), Tier::Hot)
            .unwrap();
        assert!(idx.get(id).unwrap().is_some());
        assert!(
            another_process_sees_the_main_file_locked(&path),
            "after op {i}"
        );
    }
}
