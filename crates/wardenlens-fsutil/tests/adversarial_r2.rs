//! Round-2 adversarial tests (ticket #84): the `O_NOFOLLOW` root fix and the quarantine changes.

use std::os::unix::fs::symlink;
use std::path::PathBuf;

use wardenlens_fsutil::{FsError, QuarantineOutcome, RootDir, open_private_file, quarantine};

/// Build a path string with a literal suffix appended (`Path::join` would normalise nothing,
/// but this makes the intent explicit).
fn with_suffix(p: &std::path::Path, suffix: &str) -> PathBuf {
    let mut s = p.as_os_str().to_owned();
    s.push(suffix);
    PathBuf::from(s)
}

/// ADR 0005 section 8 / round-1 fix: a symlinked root is refused. A configured root with a
/// trailing slash (`/srv/wardenlens/archive/`) must be refused just the same; otherwise the
/// kernel follows the final symlink despite `O_NOFOLLOW`.
#[test]
fn root_open_refuses_symlinked_root_written_with_trailing_slash() {
    let d = tempfile::tempdir().unwrap();
    let real = d.path().join("real");
    std::fs::create_dir(&real).unwrap();
    let link = d.path().join("link");
    symlink(&real, &link).unwrap();
    let r = RootDir::open(&with_suffix(&link, "/"));
    assert!(r.is_err(), "symlinked root followed via trailing slash");
}

#[test]
fn root_open_refuses_symlinked_root_written_with_trailing_dot() {
    let d = tempfile::tempdir().unwrap();
    let real = d.path().join("real");
    std::fs::create_dir(&real).unwrap();
    let link = d.path().join("link");
    symlink(&real, &link).unwrap();
    let r = RootDir::open(&with_suffix(&link, "/."));
    assert!(r.is_err(), "symlinked root followed via trailing /.");
}

/// A non-symlinked root with a trailing slash still opens (no regression for normal config).
#[test]
fn root_open_accepts_real_directory_with_trailing_slash() {
    let d = tempfile::tempdir().unwrap();
    RootDir::open(&with_suffix(d.path(), "/")).unwrap();
}

/// The quarantine pre-check opens the source read-only; a mode-000 source owned by us gives
/// EACCES (for non-root). That must be an error, not a silent move or a panic.
#[test]
fn quarantine_of_unreadable_source_is_typed() {
    use std::os::unix::fs::PermissionsExt;
    if rustix::process::geteuid().is_root() {
        return;
    }
    let d = tempfile::tempdir().unwrap();
    std::fs::write(d.path().join("f"), b"x").unwrap();
    std::fs::set_permissions(d.path().join("f"), std::fs::Permissions::from_mode(0o000)).unwrap();
    let root = RootDir::open(d.path()).unwrap();
    let r = quarantine(&root, &["f"]);
    assert!(matches!(r, Err(FsError::Io { .. })), "{r:?}");
    assert!(d.path().join("f").exists());
    assert!(!d.path().join("_quarantine").exists());
}

/// A quarantine source that is itself a symlink is refused (not moved, not followed).
#[test]
fn quarantine_refuses_symlink_source_and_creates_nothing() {
    let d = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    std::fs::write(outside.path().join("t"), b"t").unwrap();
    symlink(outside.path().join("t"), d.path().join("l")).unwrap();
    let root = RootDir::open(d.path()).unwrap();
    let e = quarantine(&root, &["l"]).unwrap_err();
    assert_eq!(e.errno(), Some(rustix::io::Errno::LOOP));
    assert!(!d.path().join("_quarantine").exists());
    assert!(std::fs::symlink_metadata(d.path().join("l")).is_ok());
}

/// `_quarantine` as a non-first component is legal and quarantines normally.
#[test]
fn quarantine_allows_quarantine_name_deeper_in_path() {
    let d = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(d.path().join("cam/_quarantine")).unwrap();
    std::fs::write(d.path().join("cam/_quarantine/f"), b"x").unwrap();
    let root = RootDir::open(d.path()).unwrap();
    assert_eq!(
        quarantine(&root, &["cam", "_quarantine", "f"]).unwrap(),
        QuarantineOutcome::Moved { suffix: None }
    );
    assert!(d.path().join("_quarantine/cam/_quarantine/f").exists());
}

/// A pre-existing quarantine tree whose intermediate is a planted symlink to the outside is
/// refused and nothing lands outside.
#[test]
fn quarantine_refuses_planted_symlink_at_day_level() {
    let d = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(d.path().join("cam/day")).unwrap();
    std::fs::write(d.path().join("cam/day/f"), b"x").unwrap();
    std::fs::create_dir_all(d.path().join("_quarantine/cam")).unwrap();
    symlink(outside.path(), d.path().join("_quarantine/cam/day")).unwrap();
    let root = RootDir::open(d.path()).unwrap();
    assert!(quarantine(&root, &["cam", "day", "f"]).is_err());
    assert!(d.path().join("cam/day/f").exists());
    assert_eq!(std::fs::read_dir(outside.path()).unwrap().count(), 0);
}

/// The private-file helper with a trailing slash on a symlink to a regular file must not open it.
#[test]
fn private_file_refuses_symlink_with_trailing_slash() {
    let d = tempfile::tempdir().unwrap();
    let real = d.path().join("real");
    drop(open_private_file(&real).unwrap());
    let link = d.path().join("link");
    symlink(&real, &link).unwrap();
    assert!(open_private_file(&with_suffix(&link, "/")).is_err());
}

/// The create path with an existing directory at the name returns `NotRegular` or an errno, never
/// `created == true`.
#[test]
fn private_file_on_directory_with_trailing_slash() {
    let d = tempfile::tempdir().unwrap();
    let r = open_private_file(&with_suffix(d.path(), "/"));
    assert!(matches!(r, Err(FsError::NotRegular)), "{r:?}");
}
