//! Round-3 adversarial tests (ticket #84): structural `RootDir::open`, `O_PATH` quarantine check.
#![expect(clippy::unwrap_used, clippy::expect_used, reason = "test code")]

use std::ffi::OsString;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::Duration;

use rustix::fs::{CWD, FileType, Mode, mknodat};
use rustix::io::Errno;
use wardenlens_fsutil::{
    FileKind, FsError, QuarantineOutcome, RootDir, open_private_file, quarantine,
    quarantine_with_bound,
};

fn must_not_block<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(f());
    });
    rx.recv_timeout(Duration::from_secs(2))
        .expect("operation blocked")
}

fn cat(p: &Path, suffix: &[u8]) -> PathBuf {
    let mut b = p.as_os_str().as_bytes().to_vec();
    b.extend_from_slice(suffix);
    PathBuf::from(OsString::from_vec(b))
}

fn link_fixture() -> (tempfile::TempDir, PathBuf) {
    let d = tempfile::tempdir().unwrap();
    std::fs::create_dir(d.path().join("real")).unwrap();
    std::fs::create_dir(d.path().join("real/sub")).unwrap();
    symlink(d.path().join("real"), d.path().join("link")).unwrap();
    let link = d.path().join("link");
    (d, link)
}

#[test]
fn root_open_refuses_symlinked_root_in_exotic_spellings() {
    let (_d, link) = link_fixture();
    for s in [
        &b"/./"[..],
        b"/.//",
        b"///.",
        b"/.///",
        b"/./.",
        b"/sub/..",
        b"/sub/../",
        b"/sub/../.",
        b"/../link",
    ] {
        let p = cat(&link, s);
        // "/../link" re-enters the link as last segment; everything else ends in "." or "..".
        assert!(
            RootDir::open(&p).is_err(),
            "{:?}",
            String::from_utf8_lossy(s)
        );
    }
}

#[test]
fn root_open_refuses_symlinked_root_with_doubled_leading_slashes() {
    let (_d, link) = link_fixture();
    let mut b = b"//".to_vec();
    b.extend_from_slice(link.as_os_str().as_bytes());
    assert!(RootDir::open(Path::new(&OsString::from_vec(b))).is_err());
}

#[test]
fn root_open_follows_symlink_only_in_parent_and_lands_on_real_child() {
    use std::os::unix::fs::MetadataExt;
    let (d, link) = link_fixture();
    let ino = std::fs::metadata(d.path().join("real/sub")).unwrap().ino();
    let root = RootDir::open(&link.join("sub")).unwrap();
    assert_eq!(root.stat().unwrap().ino, ino);
}

#[test]
fn root_open_refuses_proc_magic_links_in_every_spelling() {
    for p in [
        "/proc/self/cwd",
        "/proc/self/cwd/",
        "/proc/self/root",
        "/proc/self/root//",
        "/dev/fd/0",
        "/proc/thread-self/cwd",
    ] {
        assert!(RootDir::open(Path::new(p)).is_err(), "{p}");
    }
    // A trailing "." is refused structurally.
    assert!(matches!(
        RootDir::open(Path::new("/proc/self/cwd/.")),
        Err(FsError::InvalidComponent)
    ));
}

#[test]
fn root_open_with_nul_bytes_is_a_typed_error_not_a_panic() {
    let d = tempfile::tempdir().unwrap();
    // NUL in the last segment: refused by component().
    let p = cat(d.path(), b"/a\0b");
    assert!(matches!(RootDir::open(&p), Err(FsError::InvalidComponent)));
    // NUL in the parent: the syscall layer must reject it as a typed error.
    let p = cat(d.path(), b"\0x/real");
    let e = RootDir::open(&p).unwrap_err();
    assert!(e.errno().is_some(), "{e:?}");
}

#[test]
fn root_open_non_utf8_last_segment_is_invalid_but_non_utf8_parent_is_fine() {
    let d = tempfile::tempdir().unwrap();
    let parent = cat(d.path(), b"/\xff\xfe");
    std::fs::create_dir(&parent).unwrap();
    std::fs::create_dir(parent.join("ok")).unwrap();
    assert!(matches!(
        RootDir::open(&parent),
        Err(FsError::InvalidComponent)
    ));
    let r = RootDir::open(&parent.join("ok")).unwrap();
    assert_eq!(r.stat().unwrap().kind, FileKind::Directory);
}

#[test]
fn root_open_of_fifo_and_device_is_refused_without_blocking() {
    let d = tempfile::tempdir().unwrap();
    let f = d.path().join("fifo");
    mknodat(CWD, &f, FileType::Fifo, Mode::RUSR | Mode::WUSR, 0).unwrap();
    let e = must_not_block(move || RootDir::open(&f).map(|_| ()));
    assert_eq!(e.unwrap_err().errno(), Some(Errno::NOTDIR));
    assert_eq!(
        RootDir::open(Path::new("/dev/null")).unwrap_err().errno(),
        Some(Errno::NOTDIR)
    );
}

#[test]
fn root_open_relative_symlink_last_segment_is_refused() {
    // Relative path with a single segment: the parent is ".", resolved against the cwd.
    let d = tempfile::tempdir().unwrap();
    std::fs::create_dir(d.path().join("real")).unwrap();
    symlink("real", d.path().join("rel-link")).unwrap();
    let cwd_rel = d.path().join("rel-link");
    assert!(RootDir::open(&cwd_rel).is_err());
    assert!(RootDir::open(&cat(&cwd_rel, b"/")).is_err());
}

// ---------- quarantine (O_PATH check) ----------

fn qsetup() -> (tempfile::TempDir, RootDir) {
    let d = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(d.path().join("cam/2026-01-02")).unwrap();
    let r = RootDir::open(d.path()).unwrap();
    (d, r)
}

#[test]
fn quarantine_of_fifo_source_does_not_block_and_creates_nothing() {
    let (d, root) = qsetup();
    mknodat(
        CWD,
        d.path().join("cam/2026-01-02/000000-000.mp4"),
        FileType::Fifo,
        Mode::RUSR | Mode::WUSR,
        0,
    )
    .unwrap();
    let r = must_not_block(move || {
        quarantine(&root, &["cam", "2026-01-02", "000000-000.mp4"]).map(|_| ())
    });
    assert!(matches!(r, Err(FsError::NotRegular)));
    assert!(!d.path().join("_quarantine").exists());
}

#[test]
fn quarantine_of_write_only_mode_zero_source_moves_it() {
    use std::os::unix::fs::PermissionsExt;
    let (d, root) = qsetup();
    let src = d.path().join("cam/2026-01-02/000000-000.mp4");
    std::fs::write(&src, b"x").unwrap();
    std::fs::set_permissions(&src, std::fs::Permissions::from_mode(0o000)).unwrap();
    assert_eq!(
        quarantine(&root, &["cam", "2026-01-02", "000000-000.mp4"]).unwrap(),
        QuarantineOutcome::Moved { suffix: None }
    );
    assert!(
        d.path()
            .join("_quarantine/cam/2026-01-02/000000-000.mp4")
            .symlink_metadata()
            .is_ok()
    );
}

#[test]
fn quarantine_of_source_in_unsearchable_parent_is_typed_error() {
    use std::os::unix::fs::PermissionsExt;
    let (d, root) = qsetup();
    std::fs::write(d.path().join("cam/2026-01-02/f"), b"x").unwrap();
    std::fs::set_permissions(
        d.path().join("cam/2026-01-02"),
        std::fs::Permissions::from_mode(0o000),
    )
    .unwrap();
    let r = quarantine(&root, &["cam", "2026-01-02", "f"]);
    std::fs::set_permissions(
        d.path().join("cam/2026-01-02"),
        std::fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    assert_eq!(r.unwrap_err().errno(), Some(Errno::ACCESS));
    assert!(d.path().join("cam/2026-01-02/f").exists());
}

/// A name of 254 bytes fits on its own but `<name>.1` does not. The documented contract
/// says only a 255-byte name turns into ENAMETOOLONG; check that a shorter one never
/// overwrites and leaves the source in place whichever outcome it reports.
#[test]
fn quarantine_long_name_where_suffix_overflows_never_overwrites() {
    let (d, root) = qsetup();
    let name = "a".repeat(254);
    std::fs::write(d.path().join("cam/2026-01-02").join(&name), b"src").unwrap();
    std::fs::create_dir_all(d.path().join("_quarantine/cam/2026-01-02")).unwrap();
    std::fs::write(
        d.path().join("_quarantine/cam/2026-01-02").join(&name),
        b"old",
    )
    .unwrap();
    let r = quarantine_with_bound(&root, &["cam", "2026-01-02", name.as_str()], 5);
    assert!(
        matches!(r, Ok(QuarantineOutcome::Exhausted))
            || r.as_ref().err().and_then(FsError::errno) == Some(Errno::NAMETOOLONG),
        "{r:?}"
    );
    assert_eq!(
        std::fs::read(d.path().join("cam/2026-01-02").join(&name)).unwrap(),
        b"src"
    );
    assert_eq!(
        std::fs::read(d.path().join("_quarantine/cam/2026-01-02").join(&name)).unwrap(),
        b"old"
    );
}

#[test]
fn quarantine_hard_linked_source_moves_only_the_name() {
    let (d, root) = qsetup();
    let src = d.path().join("cam/2026-01-02/f");
    std::fs::write(&src, b"x").unwrap();
    std::fs::hard_link(&src, d.path().join("other")).unwrap();
    quarantine(&root, &["cam", "2026-01-02", "f"]).unwrap();
    assert_eq!(std::fs::read(d.path().join("other")).unwrap(), b"x");
    assert!(!src.exists());
}

// ---------- private file ----------

#[test]
fn private_file_refuses_setuid_even_with_other_bits_clear_and_reports_mode() {
    use std::os::unix::fs::PermissionsExt;
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("db");
    std::fs::write(&p, b"").unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o6600)).unwrap();
    match open_private_file(&p) {
        Err(FsError::InsecureMode { mode }) => assert_eq!(mode & 0o7000, 0o6000),
        other => panic!("{other:?}"),
    }
}

#[test]
fn private_file_with_nul_in_path_is_typed_error() {
    let d = tempfile::tempdir().unwrap();
    let p = cat(d.path(), b"/d\0b");
    assert!(open_private_file(&p).unwrap_err().errno().is_some());
}

#[test]
fn private_file_dot_dot_through_symlinked_dir_with_trailing_slash_refused() {
    let d = tempfile::tempdir().unwrap();
    let real = d.path().join("db");
    drop(open_private_file(&real).unwrap());
    symlink(&real, d.path().join("l")).unwrap();
    for s in [&b"/"[..], b"/.", b"//"] {
        assert!(open_private_file(&cat(&d.path().join("l"), s)).is_err());
    }
}
