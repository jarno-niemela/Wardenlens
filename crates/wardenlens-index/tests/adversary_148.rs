//! Adversarial tests for #148 (PR #203 at 8bcbbfe): the same-process open registry.
//!
//! The lock checks re-run this test binary as a child process (selected by an environment
//! variable) that probes for POSIX record locks; a probe must run in another process because
//! closing a descriptor here would drop the very lock being measured. No timing is relied on:
//! threads meet at a barrier and every result is kept alive until all have been collected.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::as_conversions,
    clippy::print_stdout,
    reason = "adversary tests: a failed setup step is a test failure"
)]

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Barrier};

use wardenlens_core::camera::CameraId;
use wardenlens_core::recording::SegmentRecord;
use wardenlens_core::storage::{SegmentIndex, Tier};
use wardenlens_core::time::{Timestamp, UnixMs};
use wardenlens_index::{Index, IndexError};

const BASE: i64 = 1_700_000_000_000;
const PROBE_ENV: &str = "WL148_PROBE_PATH";
const MARK: &str = "WL148:";

fn private_tempdir() -> tempfile::TempDir {
    let d = tempfile::tempdir().unwrap();
    std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    d
}

fn cam(s: &str) -> CameraId {
    CameraId::new(s).unwrap()
}

fn rec(camera: &str, start: i64) -> SegmentRecord {
    SegmentRecord::new(cam(camera), UnixMs::new(start).unwrap(), 1000, 10, 1)
}

fn sidecar(p: &Path, suffix: &str) -> PathBuf {
    let mut n = p.as_os_str().to_owned();
    n.push(suffix);
    n.into()
}

fn count(idx: &Index, camera: &str) -> usize {
    idx.list(
        &cam(camera),
        Timestamp::from_unix_millis(0),
        Timestamp::from_unix_millis(i64::MAX),
        1000,
        None,
    )
    .unwrap()
    .items
    .len()
}

fn refused<T>(r: &Result<T, IndexError>) -> bool {
    matches!(r, Err(IndexError::AlreadyOpenInProcess))
}

/// Does another process find a POSIX record lock held on `path` (any byte)?
fn another_process_sees_locked(path: &Path) -> bool {
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

/// Runs only as a child of `another_process_sees_locked`.
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

/// An index with rows in a live `-wal`.
fn live(dir: &Path) -> (PathBuf, Index) {
    let path = dir.join("index.db");
    let mut idx = Index::open(&path).unwrap();
    for k in 0..3 {
        idx.insert(&rec("c", BASE + k * 10_000), Tier::Hot).unwrap();
    }
    (path, idx)
}

// ---------------------------------------------------------------------------------------------
// A refused open never costs the first handle its POSIX locks, whatever the spelling
// ---------------------------------------------------------------------------------------------

/// Control: the probe can say "unlocked" for a live index whose lock was dropped, so the tests
/// below can fail.
#[test]
fn control_closing_any_descriptor_of_the_main_file_drops_the_lock() {
    let d = private_tempdir();
    let (path, idx) = live(d.path());
    assert!(another_process_sees_locked(&path));
    drop(std::fs::File::open(&path).unwrap());
    assert!(!another_process_sees_locked(&path));
    drop(idx);
}

#[test]
fn every_refused_spelling_leaves_the_first_handles_main_file_lock_in_place() {
    let d = private_tempdir();
    let (path, mut idx) = live(d.path());
    let other = private_tempdir();
    let dirlink = other.path().join("dirlink");
    std::os::unix::fs::symlink(d.path(), &dirlink).unwrap();
    let filelink = other.path().join("filelink.db");
    std::os::unix::fs::symlink(&path, &filelink).unwrap();
    let rel_parent = d.path().join("sub");
    std::fs::create_dir(&rel_parent).unwrap();
    std::fs::set_permissions(&rel_parent, std::fs::Permissions::from_mode(0o700)).unwrap();
    let spellings: Vec<PathBuf> = vec![
        path.clone(),
        d.path().join(".").join("index.db"),
        rel_parent.join("..").join("index.db"),
        dirlink.join("index.db"),
        filelink.clone(),
        PathBuf::from(format!(
            "/proc/self/root{}",
            std::fs::canonicalize(&path).unwrap().display()
        )),
    ];
    for s in &spellings {
        let r = Index::open(s);
        assert!(refused(&r), "{}: {:?}", s.display(), r.map(|_| ()));
        assert!(
            another_process_sees_locked(&path),
            "refusing {} dropped the first handle's lock",
            s.display()
        );
    }
    // A hard link (second name) made while open.
    let hard = other.path().join("hard.db");
    std::fs::hard_link(&path, &hard).unwrap();
    assert!(refused(&Index::open(&hard)));
    assert!(another_process_sees_locked(&path));
    std::fs::remove_file(&hard).unwrap();
    idx.insert(&rec("c", BASE + 90_000), Tier::Hot).unwrap();
    assert_eq!(count(&idx, "c"), 4);
    assert!(another_process_sees_locked(&path));
}

/// SQLite also holds POSIX locks on the `-shm` (the DMS lock that tells another process it is
/// not the first connection, and would otherwise let it reinitialise the live wal-index). An
/// `Index::open` of that sidecar's path in the same process opens and closes a descriptor of it.
#[test]
fn opening_the_live_shm_as_an_index_does_not_drop_the_first_handles_shm_lock() {
    let d = private_tempdir();
    let (path, idx) = live(d.path());
    let shm = sidecar(&path, "-shm");
    assert!(shm.exists());
    assert!(
        another_process_sees_locked(&shm),
        "control: the live connection holds a lock on its -shm"
    );
    let r = Index::open(&shm);
    println!("open of the -shm: {:?}", r.as_ref().map(|_| ()));
    assert!(r.is_err(), "the -shm opened as an index");
    drop(r);
    assert!(
        another_process_sees_locked(&shm),
        "a refused Index::open of the -shm path dropped the live handle's -shm locks"
    );
    drop(idx);
}

// ---------------------------------------------------------------------------------------------
// Concurrency: a file created on first open
// ---------------------------------------------------------------------------------------------

#[test]
fn concurrent_first_opens_of_a_missing_file_give_exactly_one_handle() {
    for _round in 0..5 {
        let d = private_tempdir();
        // (A symlinked-directory spelling is left out: SQLite's NOFOLLOW open refuses it with
        // `CannotOpen` even alone, before and after #148.)
        let names = [
            d.path().join("index.db"),
            d.path().join(".").join("index.db"),
        ];
        let n = 9;
        let barrier = Arc::new(Barrier::new(n));
        let handles: Vec<_> = (0..n)
            .map(|i| {
                let b = Arc::clone(&barrier);
                let p = names[i % names.len()].clone();
                std::thread::spawn(move || {
                    b.wait();
                    Index::open(&p)
                })
            })
            .collect();
        let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        let ok = results.iter().filter(|r| r.is_ok()).count();
        let others: Vec<_> = results
            .iter()
            .filter_map(|r| r.as_ref().err())
            .filter(|e| !matches!(e, IndexError::AlreadyOpenInProcess))
            .map(|e| format!("{e:?}"))
            .collect();
        assert_eq!(ok, 1, "handles: {ok}, other errors: {others:?}");
        assert!(others.is_empty(), "{others:?}");
        let path = d.path().join("index.db");
        assert!(another_process_sees_locked(&path));
        drop(results);
        // The entry went with the handle.
        drop(Index::open(&path).unwrap());
    }
}

// ---------------------------------------------------------------------------------------------
// Lifecycle of the entry
// ---------------------------------------------------------------------------------------------

#[test]
fn a_renamed_open_file_is_still_refused_and_its_old_name_is_a_new_file() {
    let d = private_tempdir();
    let (path, mut idx) = live(d.path());
    let moved = d.path().join("moved.db");
    std::fs::rename(&path, &moved).unwrap();
    for s in ["-wal", "-shm"] {
        std::fs::rename(sidecar(&path, s), sidecar(&moved, s)).unwrap();
    }
    assert!(refused(&Index::open(&moved)));
    // The old name is free and names no file: a new, separate index.
    let fresh = Index::open(&path).unwrap();
    assert_eq!(count(&fresh, "c"), 0);
    idx.insert(&rec("c", BASE + 99_000), Tier::Hot).unwrap();
    assert_eq!(count(&idx, "c"), 4);
    drop(fresh);
    drop(idx);
    assert_eq!(count(&Index::open(&moved).unwrap(), "c"), 4);
}

#[test]
fn a_handle_dropped_on_another_thread_releases_its_entry() {
    let d = private_tempdir();
    let (path, idx) = live(d.path());
    std::thread::spawn(move || drop(idx)).join().unwrap();
    assert_eq!(count(&Index::open(&path).unwrap(), "c"), 3);
}

#[test]
fn many_open_drop_cycles_and_refusals_never_leak_an_entry() {
    let d = private_tempdir();
    let path = d.path().join("index.db");
    for _ in 0..40 {
        let idx = Index::open(&path).unwrap();
        assert!(refused(&Index::open(&path)));
        drop(idx);
    }
    drop(Index::open(&path).unwrap());
}

#[test]
fn an_unlinked_open_file_does_not_block_a_new_file_at_its_name() {
    let d = private_tempdir();
    let (path, idx) = live(d.path());
    for s in ["", "-wal", "-shm"] {
        std::fs::remove_file(sidecar(&path, s)).unwrap();
    }
    let fresh = Index::open(&path).unwrap();
    assert_eq!(count(&fresh, "c"), 0);
    assert_eq!(count(&idx, "c"), 3);
    drop(idx);
    // Refused while the fresh one is open; a third, unrelated file opens alongside.
    assert!(refused(&Index::open(&path)));
    drop(Index::open(&d.path().join("third.db")).unwrap());
    drop(fresh);
}

/// A missing parent, a symlinked final component of a missing target and a non-index file are
/// refused for their own reasons, not as already open.
#[test]
fn unrelated_failures_are_not_reported_as_already_open() {
    let d = private_tempdir();
    let (_path, _idx) = live(d.path());
    let dangling = d.path().join("dangling.db");
    std::os::unix::fs::symlink(d.path().join("nowhere.db"), &dangling).unwrap();
    let r = Index::open(&dangling);
    assert!(r.is_err() && !refused(&r));
    assert!(!d.path().join("nowhere.db").exists());
    let junk = d.path().join("junk.db");
    std::fs::write(&junk, vec![b'x'; 4096]).unwrap();
    std::fs::set_permissions(&junk, std::fs::Permissions::from_mode(0o600)).unwrap();
    let r = Index::open(&junk);
    assert!(
        matches!(r, Err(IndexError::NotAnIndex)),
        "{:?}",
        r.map(|_| ())
    );
}
