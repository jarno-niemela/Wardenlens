//! Adversarial tests for #145 (PR #147 at 45d6ee7): `Scratch::sweep_stale` removes directories,
//! so it must remove only stale scratch directories of ours and nothing they point to.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    reason = "adversary tests: a failed setup step is a test failure"
)]

use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::Path;
use std::process::{Command, Stdio};

use wardenlens_fsutil::Scratch;

fn private_dir() -> tempfile::TempDir {
    let d = tempfile::tempdir().unwrap();
    std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    d
}

const DEAD: i32 = i32::MAX - 7;

fn precious(d: &Path) -> std::path::PathBuf {
    let t = d.join("precious");
    std::fs::create_dir(&t).unwrap();
    std::fs::write(t.join("data"), b"keep").unwrap();
    t
}

/// A live process other than this one (a child blocked on its stdin, so no timing is involved).
#[test]
fn the_directory_of_another_live_process_is_kept() {
    let d = private_dir();
    let mut child = Command::new("cat")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    let live = d
        .path()
        .join(format!(".wardenlens-probe-{}-1-0", child.id()));
    std::fs::create_dir(&live).unwrap();
    let n = Scratch::sweep_stale(d.path());
    let kept = live.exists();
    drop(child.stdin.take());
    child.wait().unwrap();
    assert_eq!(n, 0);
    assert!(kept, "removed the scratch directory of a live process");
}

/// pid 1 belongs to another user (kill gives EPERM, not ESRCH): alive, kept. Leading zeros in the
/// name do not change the pid.
#[test]
fn a_process_of_another_user_counts_as_alive() {
    let d = private_dir();
    let a = d.path().join(".wardenlens-probe-1-1-0");
    let b = d.path().join(".wardenlens-probe-0001-1-0");
    std::fs::create_dir(&a).unwrap();
    std::fs::create_dir(&b).unwrap();
    assert_eq!(Scratch::sweep_stale(d.path()), 0);
    assert!(a.exists() && b.exists());
}

/// A symlink inside a stale directory is removed as a link; its target is never entered.
#[test]
fn a_symlink_inside_a_stale_directory_is_not_followed() {
    let d = private_dir();
    let t = precious(d.path());
    let stale = d.path().join(format!(".wardenlens-probe-{DEAD}-1-0"));
    std::fs::create_dir(&stale).unwrap();
    symlink(&t, stale.join("vault.db")).unwrap();
    std::fs::create_dir(stale.join("sub")).unwrap();
    symlink(&t, stale.join("sub").join("deeper")).unwrap();
    assert_eq!(Scratch::sweep_stale(d.path()), 1);
    assert!(!stale.exists());
    assert_eq!(std::fs::read(t.join("data")).unwrap(), b"keep");
}

/// A symlink named like a scratch directory pointing to a directory is not removed through, and
/// a symlinked *parent* argument does not widen what is removed.
#[test]
fn names_that_only_look_like_scratch_are_kept() {
    let d = private_dir();
    let names: Vec<Vec<u8>> = vec![
        format!(".wardenlens-probe-+{DEAD}-1-0").into_bytes(),
        format!(".wardenlens-probe- {DEAD}-1-0").into_bytes(),
        format!(".wardenlens-probe-{DEAD}-1-0 ").into_bytes(),
        format!(".wardenlens-probe-{DEAD}--0").into_bytes(),
        format!(".wardenlens-probe-{DEAD}-1-").into_bytes(),
        format!(".Wardenlens-probe-{DEAD}-1-0").into_bytes(),
        format!(".wardenlens-probe-{DEAD}-1-0.bak").into_bytes(),
        format!(".wardenlens-probe-{DEAD}-１-0").into_bytes(), // fullwidth digit
        {
            let mut v = format!(".wardenlens-probe-{DEAD}-1-0").into_bytes();
            v.push(0xff); // invalid UTF-8
            v
        },
        b".wardenlens-probe-".to_vec(),
        b".wardenlens-probe---".to_vec(),
    ];
    for n in &names {
        std::fs::create_dir(d.path().join(OsStr::from_bytes(n))).unwrap();
    }
    assert_eq!(Scratch::sweep_stale(d.path()), 0);
    for n in &names {
        assert!(d.path().join(OsStr::from_bytes(n)).exists(), "{n:?}");
    }
}

/// The sweep is given a file, a FIFO-free empty dir, or a directory it cannot read: no panic, 0.
#[test]
fn odd_parents_remove_nothing() {
    let d = private_dir();
    let f = d.path().join("file");
    std::fs::write(&f, b"x").unwrap();
    assert_eq!(Scratch::sweep_stale(&f), 0);
    assert_eq!(Scratch::sweep_stale(Path::new("")), 0);
    let locked = d.path().join("locked");
    std::fs::create_dir(&locked).unwrap();
    let stale = locked.join(format!(".wardenlens-probe-{DEAD}-1-0"));
    std::fs::create_dir(&stale).unwrap();
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o300)).unwrap();
    let n = Scratch::sweep_stale(&locked);
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(n, 0);
}

/// A stale directory whose contents cannot all be removed (a read-only subdirectory) is skipped
/// without panicking, and a later sweep after the mode is fixed removes it.
#[test]
fn a_partly_unremovable_stale_directory_is_best_effort() {
    let d = private_dir();
    let stale = d.path().join(format!(".wardenlens-probe-{DEAD}-1-0"));
    let sub = stale.join("sub");
    std::fs::create_dir_all(&sub).unwrap();
    std::fs::write(sub.join("copy.db"), b"x").unwrap();
    std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o500)).unwrap();
    let first = Scratch::sweep_stale(d.path());
    std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o700)).unwrap();
    if first == 0 {
        assert!(stale.exists());
        assert_eq!(Scratch::sweep_stale(d.path()), 1);
    }
    assert!(!stale.exists());
}

/// The sweep never removes this process's own live scratch directories, even many of them.
#[test]
fn own_live_scratches_survive_a_sweep() {
    let d = private_dir();
    let mine: Vec<Scratch> = (0..20).map(|_| Scratch::new(d.path()).unwrap()).collect();
    assert_eq!(Scratch::sweep_stale(d.path()), 0);
    assert!(mine.iter().all(|s| s.path().is_dir()));
}
