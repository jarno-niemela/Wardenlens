//! Adversarial tests for #158 (PR #185 at 0ee5c35): does the child-process probe that replaced
//! `/proc/locks` parsing in `adversary_49_r4.rs` discriminate the invariant it names (a POSIX
//! lock held on the *main* file), or could it pass for other reasons?
//!
//! The probe is copied (integration test binaries cannot share helpers) and pointed at
//! states that hold every other lock (the `-shm` locks, a read transaction, an `flock`) while the
//! main-file POSIX lock is gone, the exact regression `an_open_index_keeps_sqlites_posix_lock_on_
//! the_main_file` guards against.
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
use wardenlens_core::time::{Timestamp, UnixMs};
use wardenlens_index::Index;

const BASE: i64 = 1_700_000_000_000;
const PROBE_ENV: &str = "WL158_PROBE_PATH";
const MARK: &str = "WL158:";

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

fn count(idx: &Index, camera: &str) -> usize {
    idx.list(
        &CameraId::new(camera).unwrap(),
        Timestamp::from_unix_millis(0),
        Timestamp::from_unix_millis(i64::MAX),
        1000,
        None,
    )
    .unwrap()
    .items
    .len()
}

fn wal_conn(path: &Path) -> rusqlite::Connection {
    let c = rusqlite::Connection::open(path).unwrap();
    c.query_row("PRAGMA journal_mode = WAL", [], |r| r.get::<_, String>(0))
        .unwrap();
    c.execute_batch("CREATE TABLE t (x); INSERT INTO t VALUES (1);")
        .unwrap();
    c
}

/// Opening and closing any descriptor of the inode drops every POSIX record lock this process
/// holds on it (fcntl(2)). SQLite's own bookkeeping still believes it holds SHARED.
fn drop_process_posix_locks_on(path: &Path) {
    drop(std::fs::File::open(path).unwrap());
}

/// Does another process find a POSIX record lock held on the main file of `path`?
///
/// A child process (this test binary, selected by `PROBE_ENV`) opens the main file and tries a
/// non-blocking whole-file exclusive POSIX lock (`F_SETLK`, `F_WRLCK`, as
/// `rustix::fs::fcntl_lock(.., NonBlockingLockExclusive)` does). That conflicts with any POSIX
/// lock another process holds on the inode, such as SQLite's shared lock on the main file, and
/// with nothing on the `-wal` and `-shm` sidecars (different inodes). `EAGAIN` or `EACCES` mean
/// "locked", success means "unlocked". The probe never changes the database: it writes nothing,
/// and the child's lock is released when it exits. It runs in a child because closing a
/// descriptor in the parent would drop the very lock being measured. There is no timing and no
/// `/proc/locks` parsing (whose chunked reads can skip entries while other processes change the
/// lock table).
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

/// Runs only as a child of `another_process_sees_the_main_file_locked`.
#[test]
fn child_lock_probe_entry() {
    let Some(path) = std::env::var_os(PROBE_ENV) else {
        return;
    };
    // A write-lock request needs a descriptor open for writing; nothing is written.
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

/// Mutation check of the WAL control: the connection stays open with its `-shm` locks, only the
/// main-file POSIX lock is gone. A probe that answered from the `-shm` locks would say locked.
#[test]
fn probe_says_unlocked_when_only_the_main_file_posix_lock_is_dropped() {
    let dir = private_tempdir();
    let path = dir.path().join("plain.db");
    let c = wal_conn(&path);
    drop_process_posix_locks_on(&path);
    let locked = another_process_sees_the_main_file_locked(&path);
    drop(c);
    assert!(
        !locked,
        "probe reported locked although no POSIX lock remains on the main file"
    );
}

/// Mutation check of the Index test: simulate the regression (an Index whose main-file lock was
/// dropped by closing one of our own descriptors). The real test must then fail, i.e. the probe
/// must say unlocked.
#[test]
fn probe_says_unlocked_for_an_index_whose_main_file_lock_was_dropped() {
    let dir = private_tempdir();
    let path = dir.path().join("index.db");
    let mut idx = Index::open(&path).unwrap();
    idx.insert(&rec("cam1", BASE), Tier::Hot).unwrap();
    drop_process_posix_locks_on(&path);
    assert!(
        !another_process_sees_the_main_file_locked(&path),
        "probe cannot detect the very regression the Index lock test exists for"
    );
}

/// An open read transaction holds a WAL read mark on the `-shm`. With the main-file lock dropped,
/// the probe must still answer from the main file only.
#[test]
fn probe_ignores_a_read_mark_when_the_main_file_lock_is_gone() {
    let dir = private_tempdir();
    let path = dir.path().join("plain.db");
    let c = wal_conn(&path);
    c.execute_batch("BEGIN; SELECT * FROM t;").unwrap();
    drop_process_posix_locks_on(&path);
    let locked = another_process_sees_the_main_file_locked(&path);
    c.execute_batch("COMMIT").ok();
    assert!(!locked, "a -shm read mark made the probe say locked");
}

/// `flock` is a different lock table from POSIX record locks on Linux: holding an exclusive
/// `flock` alone (as `Index::open` does while opening) must not satisfy the probe.
#[test]
fn probe_is_not_satisfied_by_an_flock_alone() {
    let dir = private_tempdir();
    let path = dir.path().join("plain.db");
    drop(wal_conn(&path));
    let f = std::fs::File::open(&path).unwrap();
    f.lock().unwrap();
    let locked = another_process_sees_the_main_file_locked(&path);
    f.unlock().unwrap();
    assert!(!locked, "an flock alone made the probe say locked");
}

/// Positive side, repeated: the probe answers the same way every time and neither answer changes
/// the database: it stays in WAL mode with its rows.
#[test]
fn probe_is_stable_and_never_changes_the_database() {
    let dir = private_tempdir();
    let path = dir.path().join("index.db");
    let mut idx = Index::open(&path).unwrap();
    idx.insert(&rec("cam1", BASE), Tier::Hot).unwrap();
    for i in 0..20 {
        assert!(
            another_process_sees_the_main_file_locked(&path),
            "round {i}"
        );
    }
    idx.insert(&rec("cam1", BASE + 50_000), Tier::Hot).unwrap();
    assert_eq!(count(&idx, "cam1"), 2);
    drop(idx);
    let c = rusqlite::Connection::open(&path).unwrap();
    let mode: String = c
        .query_row("PRAGMA journal_mode", [], |r| r.get(0))
        .unwrap();
    assert_eq!(mode, "wal");
}

/// Closing an *unrelated* file in another thread while probing must not perturb the answer
/// (POSIX locks are per inode, not per process-wide fd table).
#[test]
fn probe_is_unaffected_by_unrelated_descriptor_churn() {
    let dir = private_tempdir();
    let path = dir.path().join("index.db");
    let other = dir.path().join("other");
    std::fs::write(&other, b"x").unwrap();
    let idx = Index::open(&path).unwrap();
    let (tx, rx) = std::sync::mpsc::channel::<()>();
    let churn = std::thread::spawn(move || {
        while rx.try_recv().is_err() {
            drop(std::fs::File::open(&other).unwrap());
        }
    });
    for i in 0..10 {
        assert!(
            another_process_sees_the_main_file_locked(&path),
            "round {i}"
        );
    }
    tx.send(()).unwrap();
    churn.join().unwrap();
    drop(idx);
}

/// The probe separates a live WAL connection, one whose lock was dropped, a closed one, and an
/// open Index with and without its lock (folded in from the round-1 oracle test).
#[test]
fn probe_discriminates_live_dropped_closed_and_index() {
    let dir = private_tempdir();

    let live = dir.path().join("live.db");
    let c_live = wal_conn(&live);
    assert!(
        another_process_sees_the_main_file_locked(&live),
        "live WAL connection"
    );

    let dropped = dir.path().join("dropped.db");
    let c_dropped = wal_conn(&dropped);
    drop_process_posix_locks_on(&dropped);
    assert!(
        !another_process_sees_the_main_file_locked(&dropped),
        "main-file lock dropped"
    );

    let closed = dir.path().join("closed.db");
    drop(wal_conn(&closed));
    assert!(
        !another_process_sees_the_main_file_locked(&closed),
        "connection closed"
    );

    let ipath = dir.path().join("index.db");
    let mut idx = Index::open(&ipath).unwrap();
    idx.insert(&rec("cam1", BASE), Tier::Hot).unwrap();
    assert!(
        another_process_sees_the_main_file_locked(&ipath),
        "open Index"
    );
    drop_process_posix_locks_on(&ipath);
    assert!(
        !another_process_sees_the_main_file_locked(&ipath),
        "Index with dropped lock"
    );

    drop((c_live, c_dropped, idx));
}
