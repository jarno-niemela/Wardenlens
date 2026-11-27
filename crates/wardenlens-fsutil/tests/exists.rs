//! `RootDir::exists`: any entry counts as there, nothing is opened for reading.

use std::os::unix::fs::symlink;

use wardenlens_fsutil::{FsError, RootDir};

#[test]
fn every_kind_of_entry_is_there_and_a_missing_one_is_not() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path();
    std::fs::write(p.join("file"), b"x").unwrap();
    std::fs::create_dir(p.join("dir")).unwrap();
    symlink("/nonexistent-wardenlens-target", p.join("dangling")).unwrap();
    symlink(p.join("file"), p.join("live")).unwrap();
    assert!(
        std::process::Command::new("mkfifo")
            .arg(p.join("fifo"))
            .status()
            .unwrap()
            .success()
    );
    let root = RootDir::open(p).unwrap();
    for name in ["file", "dir", "dangling", "live", "fifo"] {
        assert!(root.exists(name).unwrap(), "{name}");
    }
    assert!(!root.exists("missing").unwrap());
}

#[test]
fn a_file_without_permission_is_still_found_and_bad_names_are_refused() {
    use std::os::unix::fs::PermissionsExt;
    let d = tempfile::tempdir().unwrap();
    std::fs::write(d.path().join("locked"), b"x").unwrap();
    std::fs::set_permissions(
        d.path().join("locked"),
        std::fs::Permissions::from_mode(0o000),
    )
    .unwrap();
    let root = RootDir::open(d.path()).unwrap();
    assert!(root.exists("locked").unwrap());
    for bad in ["", ".", "..", "a/b", "a\0b"] {
        assert!(
            matches!(root.exists(bad), Err(FsError::InvalidComponent)),
            "{bad:?}"
        );
    }
}
