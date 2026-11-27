//! Adversarial tests for #148 round 2 (PR #203 at d7543c8): sidecar-name refusal.
//!
//! Lock probes run in a child process (this test binary re-run, selected by an environment
//! variable), because closing a descriptor here would drop the lock being measured.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::arithmetic_side_effects,
    reason = "adversary tests: a failed setup step is a test failure"
)]

use std::ffi::OsString;
use std::io::Write;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use wardenlens_core::camera::CameraId;
use wardenlens_core::recording::SegmentRecord;
use wardenlens_core::storage::{SegmentIndex, Tier};
use wardenlens_core::time::UnixMs;
use wardenlens_index::{Index, IndexError};

const BASE: i64 = 1_700_000_000_000;
const PROBE_ENV: &str = "WL148R2_PROBE_PATH";
const MARK: &str = "WL148R2:";

fn private_tempdir() -> tempfile::TempDir {
    let d = tempfile::tempdir().unwrap();
    std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    d
}

fn sidecar(p: &Path, suffix: &str) -> PathBuf {
    let mut n = p.as_os_str().to_owned();
    n.push(suffix);
    n.into()
}

fn refused<T>(r: &Result<T, IndexError>) -> bool {
    matches!(r, Err(IndexError::AlreadyOpenInProcess))
}

fn another_process_sees_locked(path: &Path) -> bool {
    let out = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "r2_child_lock_probe_entry",
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
fn r2_child_lock_probe_entry() {
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

fn live_at(path: &Path) -> Index {
    let mut idx = Index::open(path).unwrap();
    let cam = CameraId::new("c").unwrap();
    for k in 0..3 {
        idx.insert(
            &SegmentRecord::new(
                cam.clone(),
                UnixMs::new(BASE + k * 10_000).unwrap(),
                1000,
                10,
                1,
            ),
            Tier::Hot,
        )
        .unwrap();
    }
    idx
}

/// A second name (hard link) of the live `-shm` that does not end in `-shm`: the name check
/// cannot see it, `open_private_file` opens the shm inode, then the open is refused
/// (`HardLinkedIndex` / `NotAnIndex`) and the descriptor is closed.
#[test]
fn opening_a_hard_link_of_the_live_shm_keeps_the_first_handles_shm_lock() {
    let d = private_tempdir();
    let path = d.path().join("index.db");
    let idx = live_at(&path);
    let shm = sidecar(&path, "-shm");
    assert!(another_process_sees_locked(&shm), "control: -shm is locked");
    let alias = d.path().join("other.db");
    std::fs::hard_link(&shm, &alias).unwrap();
    let r = Index::open(&alias);
    println!(
        "open of a hard link to the -shm: {:?}",
        r.as_ref().map(|_| ())
    );
    assert!(r.is_err());
    drop(r);
    std::fs::remove_file(&alias).unwrap();
    assert!(
        another_process_sees_locked(&shm),
        "a refused open of a second name of the live -shm dropped the first handle's -shm lock"
    );
    drop(idx);
}

/// Same, with the second name in another (private) directory and spelled like a sidecar of an
/// unregistered base.
#[test]
fn opening_a_hard_link_of_the_live_shm_named_as_another_sidecar_keeps_the_lock() {
    let d = private_tempdir();
    let path = d.path().join("index.db");
    let idx = live_at(&path);
    let shm = sidecar(&path, "-shm");
    let other = private_tempdir();
    let alias = other.path().join("x.db-shm");
    std::fs::hard_link(&shm, &alias).unwrap();
    let r = Index::open(&alias);
    println!("open: {:?}", r.as_ref().map(|_| ()));
    drop(r);
    std::fs::remove_file(&alias).unwrap();
    assert!(another_process_sees_locked(&shm));
    drop(idx);
}

/// A non-UTF-8 index name: its `-shm` name must be refused like any other.
#[test]
fn a_non_utf8_index_names_shm_is_refused_and_keeps_its_lock() {
    let d = private_tempdir();
    let name = OsString::from_vec(b"idx-\xff.db".to_vec());
    let path = d.path().join(&name);
    let idx = live_at(&path);
    let shm = sidecar(&path, "-shm");
    assert!(shm.exists());
    assert!(another_process_sees_locked(&shm), "control: -shm is locked");
    let r = Index::open(&shm);
    println!("open of the non-UTF-8 -shm: {:?}", r.as_ref().map(|_| ()));
    let was_refused = refused(&r);
    drop(r);
    assert!(
        another_process_sees_locked(&shm),
        "open of the -shm of a non-UTF-8 index dropped the shm lock (refused as already open: {was_refused})"
    );
    drop(idx);
}

/// Each sidecar name of a live index is refused as already open, through every spelling of the
/// base: direct, `.`-component, symlinked directory.
#[test]
fn every_sidecar_spelling_is_refused_as_already_open() {
    let d = private_tempdir();
    let path = d.path().join("index.db");
    let idx = live_at(&path);
    // A `-journal` that does not exist yet is still a sidecar name of the base.
    let other = private_tempdir();
    let dirlink = other.path().join("dl");
    std::os::unix::fs::symlink(d.path(), &dirlink).unwrap();
    for s in ["-shm", "-wal", "-journal"] {
        for base in [
            path.clone(),
            d.path().join(".").join("index.db"),
            dirlink.join("index.db"),
        ] {
            let p = sidecar(&base, s);
            let r = Index::open(&p);
            assert!(refused(&r), "{}: {:?}", p.display(), r.map(|_| ()));
        }
    }
    assert!(!sidecar(&path, "-journal").exists());
    assert!(another_process_sees_locked(&path));
    assert!(another_process_sees_locked(&sidecar(&path, "-shm")));
    drop(idx);
}

/// No false refusals: names that merely resemble sidecars of a live index open as separate
/// indexes.
#[test]
fn look_alike_names_are_not_refused() {
    let d = private_tempdir();
    let path = d.path().join("index.db");
    let idx = live_at(&path);
    for n in [
        "index.db-shm2",
        "index.db-wa",
        "index.db.wal",
        "index.db-WAL",
        "index-shm",
        "-wal",
        "index.db-journal-x",
        "xindex.db-wal",
    ] {
        let p = d.path().join(n);
        let r = Index::open(&p);
        assert!(r.is_ok(), "{n}: {:?}", r.map(|_| ()));
        drop(r);
    }
    drop(idx);
    let r = Index::open(&path);
    assert!(r.is_ok(), "{:?}", r.map(|_| ()));
}

/// The parked-descriptor path cannot be reached by a plain hard link (the stat check catches it),
/// so ordinary refusals never leak a descriptor.
#[test]
fn ordinary_refusals_open_no_descriptor() {
    let d = private_tempdir();
    let path = d.path().join("index.db");
    let idx = live_at(&path);
    // Only descriptors on files of this test's directory: other tests run in parallel.
    let dir = std::fs::canonicalize(d.path()).unwrap();
    let fds = || {
        std::fs::read_dir("/proc/self/fd")
            .unwrap()
            .filter_map(|e| std::fs::read_link(e.ok()?.path()).ok())
            .filter(|t| t.starts_with(&dir))
            .count()
    };
    let before = fds();
    for _ in 0..200 {
        assert!(refused(&Index::open(&path)));
        assert!(refused(&Index::open(&sidecar(&path, "-shm"))));
        assert!(refused(&Index::open(&sidecar(&path, "-wal"))));
    }
    assert_eq!(fds(), before);
    drop(idx);
}
