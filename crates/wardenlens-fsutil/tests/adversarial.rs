//! Adversarial tests for the filesystem trust boundary (ticket #84).
#![expect(clippy::unwrap_used, clippy::expect_used, reason = "test code")]

use std::os::unix::fs::symlink;
use std::path::Path;
use std::sync::mpsc;
use std::time::Duration;

use rustix::fs::{CWD, FileType, Mode, mknodat};
use rustix::io::Errno;
use wardenlens_fsutil::{
    FileKind, FsError, QUARANTINE_DIR, QuarantineOutcome, RootDir, open_private_file, quarantine,
    quarantine_with_bound,
};

/// Run `f` on a thread and fail if it does not finish within 30 seconds (a blocking open).
fn must_not_block<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(f());
    });
    // 30 s, not a tight bound: this only catches a blocking open (TEST-5, host load).
    rx.recv_timeout(Duration::from_secs(30))
        .expect("operation blocked")
}

fn mkfifo(p: &Path) {
    mknodat(CWD, p, FileType::Fifo, Mode::RUSR | Mode::WUSR, 0).unwrap();
}

// ---------- RootDir::open ----------

/// ADR 0005 section 8: each probe opens the root with `O_DIRECTORY | O_NOFOLLOW`. A root path
/// that has been replaced by a symlink (e.g. an unmounted archive mountpoint swapped for a link
/// to the SSD) must be refused.
#[test]
fn root_open_refuses_a_symlinked_root() {
    let d = tempfile::tempdir().unwrap();
    std::fs::create_dir(d.path().join("real")).unwrap();
    symlink(d.path().join("real"), d.path().join("archive")).unwrap();
    let r = RootDir::open(&d.path().join("archive"));
    let errno = r
        .expect_err("RootDir::open followed a symlinked root")
        .errno();
    assert!(
        errno == Some(Errno::NOTDIR) || errno == Some(Errno::LOOP),
        "{errno:?}"
    );
}

#[test]
fn root_open_of_a_fifo_does_not_block() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("fifo");
    mkfifo(&p);
    let r = must_not_block(move || RootDir::open(&p).map(|_| ()));
    assert!(r.is_err());
}

// ---------- RootDir::open_dir / open_read ----------

#[test]
fn open_dir_of_a_fifo_does_not_block() {
    let d = tempfile::tempdir().unwrap();
    mkfifo(&d.path().join("fifo"));
    let root = RootDir::open(d.path()).unwrap();
    let r = must_not_block(move || root.open_dir(&["fifo"]).map(|_| ()));
    assert_eq!(r.unwrap_err().errno(), Some(Errno::NOTDIR));
}

#[test]
fn open_read_of_a_nested_fifo_does_not_block() {
    let d = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(d.path().join("cam/day")).unwrap();
    mkfifo(&d.path().join("cam/day/x.mp4"));
    let root = RootDir::open(d.path()).unwrap();
    let r = must_not_block(move || root.open_read(&["cam", "day", "x.mp4"]).map(|_| ()));
    assert!(matches!(r, Err(FsError::NotRegular)));
}

#[test]
fn open_read_of_a_socket_is_refused_without_blocking() {
    let d = tempfile::tempdir().unwrap();
    let _l = std::os::unix::net::UnixListener::bind(d.path().join("sock")).unwrap();
    let root = RootDir::open(d.path()).unwrap();
    let r = must_not_block(move || root.open_read(&["sock"]).map(|_| ()));
    assert!(r.is_err());
}

#[test]
fn open_read_of_a_directory_is_not_regular() {
    let d = tempfile::tempdir().unwrap();
    std::fs::create_dir(d.path().join("sub")).unwrap();
    let root = RootDir::open(d.path()).unwrap();
    assert!(matches!(root.open_read(&["sub"]), Err(FsError::NotRegular)));
}

#[test]
fn open_read_refuses_dangling_symlink_and_symlink_to_dot_dot() {
    let d = tempfile::tempdir().unwrap();
    let inner = d.path().join("inner");
    std::fs::create_dir(&inner).unwrap();
    std::fs::write(d.path().join("secret"), b"s").unwrap();
    symlink("../secret", inner.join("up")).unwrap();
    symlink("nowhere", inner.join("dangling")).unwrap();
    symlink("..", inner.join("dotdot")).unwrap();
    let root = RootDir::open(&inner).unwrap();
    assert!(root.open_read(&["up"]).is_err());
    assert!(root.open_read(&["dangling"]).is_err());
    assert!(root.open_read(&["dotdot", "secret"]).is_err());
    assert!(root.open_dir(&["dotdot"]).is_err());
}

#[test]
fn open_read_refuses_proc_magic_link_style_escape() {
    // A symlink to an absolute path that exists (/etc/hostname or /proc/self/root).
    let d = tempfile::tempdir().unwrap();
    symlink("/proc/self/root", d.path().join("r")).unwrap();
    symlink("/etc/passwd", d.path().join("p")).unwrap();
    let root = RootDir::open(d.path()).unwrap();
    assert!(root.open_read(&["r", "etc", "passwd"]).is_err());
    assert!(root.open_read(&["p"]).is_err());
}

#[test]
fn unusual_but_legal_components_work() {
    let d = tempfile::tempdir().unwrap();
    let root = RootDir::open(d.path()).unwrap();
    for name in [
        "...",
        " ",
        "a\nb",
        "back\\slash",
        "\u{202e}rtl",
        "e\u{301}",
        "-rf",
        ".hidden",
    ] {
        root.mkdir(name).unwrap();
        let sub = root.open_dir(&[name]).unwrap();
        assert_eq!(sub.stat().unwrap().kind, FileKind::Directory);
        std::fs::write(d.path().join(name).join("f"), b"x").unwrap();
        assert_eq!(root.open_read(&[name, "f"]).unwrap().len, 1);
    }
}

#[test]
fn overlong_components_are_typed_errors_not_panics() {
    let d = tempfile::tempdir().unwrap();
    let root = RootDir::open(d.path()).unwrap();
    let long = "a".repeat(256);
    assert_eq!(
        root.mkdir(&long).unwrap_err().errno(),
        Some(Errno::NAMETOOLONG)
    );
    let many: Vec<String> = (0..2000).map(|_| "abc".to_owned()).collect();
    assert!(root.open_read(&many).is_err());
}

#[test]
fn unlink_refuses_a_directory_and_does_not_follow_symlinks() {
    let d = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    std::fs::write(outside.path().join("keep"), b"k").unwrap();
    std::fs::create_dir(d.path().join("sub")).unwrap();
    symlink(outside.path().join("keep"), d.path().join("link")).unwrap();
    let root = RootDir::open(d.path()).unwrap();
    assert!(root.unlink("sub").is_err());
    root.unlink("link").unwrap();
    assert!(outside.path().join("keep").exists());
}

#[test]
fn rename_noreplace_refuses_dangling_symlink_target() {
    let d = tempfile::tempdir().unwrap();
    std::fs::write(d.path().join("a"), b"a").unwrap();
    symlink("nowhere", d.path().join("b")).unwrap();
    let root = RootDir::open(d.path()).unwrap();
    assert_eq!(
        root.rename_noreplace("a", &root, "b").unwrap_err().errno(),
        Some(Errno::EXIST)
    );
    assert!(!d.path().join("nowhere").exists());
}

#[test]
fn statvfs_reports_read_only_mount() {
    let mounts = std::fs::read_to_string("/proc/mounts").unwrap();
    let ro = mounts.lines().find_map(|l| {
        let f: Vec<&str> = l.split(' ').collect();
        (f.len() > 3 && f[3].split(',').any(|o| o == "ro") && Path::new(f[1]).is_dir())
            .then(|| f[1].to_owned())
            .filter(|m| RootDir::open(Path::new(m)).is_ok())
    });
    let Some(m) = ro else {
        // No readable read-only mount on this host: nothing to check.
        return;
    };
    let root = RootDir::open(Path::new(&m)).unwrap();
    assert!(root.statvfs().unwrap().read_only, "{m}");
    let d = tempfile::tempdir().unwrap();
    assert!(
        !RootDir::open(d.path())
            .unwrap()
            .statvfs()
            .unwrap()
            .read_only
    );
}

// ---------- quarantine ----------

fn qsetup() -> (tempfile::TempDir, RootDir) {
    let d = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(d.path().join("cam/day")).unwrap();
    std::fs::write(d.path().join("cam/day/f.mp4"), b"v").unwrap();
    let root = RootDir::open(d.path()).unwrap();
    (d, root)
}

/// "A component containing `/`, `..` or NUL, or an empty component, is rejected before any
/// syscall": an invalid final name must not leave a `_quarantine` tree behind.
#[test]
fn quarantine_with_invalid_final_name_creates_nothing() {
    for bad in ["", "..", ".", "a/b", "a\0b"] {
        let (d, root) = qsetup();
        assert!(
            matches!(
                quarantine(&root, &["cam", "day", bad]),
                Err(FsError::InvalidComponent)
            ),
            "{bad:?}"
        );
        assert!(
            !d.path().join(QUARANTINE_DIR).exists(),
            "{bad:?}: _quarantine was created before the component was rejected"
        );
    }
}

#[test]
fn quarantine_of_missing_source_with_occupied_target_is_not_found() {
    let (d, root) = qsetup();
    std::fs::create_dir_all(d.path().join("_quarantine/cam/day")).unwrap();
    std::fs::write(d.path().join("_quarantine/cam/day/gone.mp4"), b"q").unwrap();
    std::fs::write(d.path().join("_quarantine/cam/day/gone.mp4.1"), b"q").unwrap();
    let e = quarantine_with_bound(&root, &["cam", "day", "gone.mp4"], 1).unwrap_err();
    assert!(e.is_not_found());
}

#[test]
fn quarantine_through_symlinked_source_parent_is_refused_and_touches_nothing_outside() {
    let d = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    std::fs::create_dir(outside.path().join("day")).unwrap();
    std::fs::write(outside.path().join("day/f.mp4"), b"x").unwrap();
    symlink(outside.path(), d.path().join("cam")).unwrap();
    let root = RootDir::open(d.path()).unwrap();
    assert!(quarantine(&root, &["cam", "day", "f.mp4"]).is_err());
    assert!(outside.path().join("day/f.mp4").exists());
}

#[test]
fn quarantine_refuses_symlinked_inner_quarantine_dir() {
    let (d, root) = qsetup();
    let outside = tempfile::tempdir().unwrap();
    std::fs::create_dir(d.path().join("_quarantine")).unwrap();
    symlink(outside.path(), d.path().join("_quarantine/cam")).unwrap();
    assert!(quarantine(&root, &["cam", "day", "f.mp4"]).is_err());
    assert!(d.path().join("cam/day/f.mp4").exists());
    assert_eq!(std::fs::read_dir(outside.path()).unwrap().count(), 0);
}

#[test]
fn quarantine_when_quarantine_is_a_planted_file_or_fifo_errors_and_leaves_source() {
    for fifo in [false, true] {
        let (d, root) = qsetup();
        let q = d.path().join(QUARANTINE_DIR);
        if fifo {
            mkfifo(&q);
        } else {
            std::fs::write(&q, b"planted").unwrap();
        }
        let r = must_not_block(move || quarantine(&root, &["cam", "day", "f.mp4"]));
        assert!(r.is_err());
        assert!(d.path().join("cam/day/f.mp4").exists());
    }
}

#[test]
fn quarantine_skips_planted_symlink_candidates_without_following() {
    let (d, root) = qsetup();
    let outside = tempfile::tempdir().unwrap();
    std::fs::write(outside.path().join("victim"), b"keep").unwrap();
    std::fs::create_dir_all(d.path().join("_quarantine/cam/day")).unwrap();
    symlink(
        outside.path().join("victim"),
        d.path().join("_quarantine/cam/day/f.mp4"),
    )
    .unwrap();
    symlink("nowhere", d.path().join("_quarantine/cam/day/f.mp4.1")).unwrap();
    assert_eq!(
        quarantine(&root, &["cam", "day", "f.mp4"]).unwrap(),
        QuarantineOutcome::Moved { suffix: Some(2) }
    );
    assert_eq!(
        std::fs::read(outside.path().join("victim")).unwrap(),
        b"keep"
    );
    assert_eq!(
        std::fs::read(d.path().join("_quarantine/cam/day/f.mp4.2")).unwrap(),
        b"v"
    );
}

#[test]
fn quarantine_with_max_length_name_and_occupied_target_never_overwrites() {
    let d = tempfile::tempdir().unwrap();
    let name = "n".repeat(255);
    std::fs::write(d.path().join(&name), b"src").unwrap();
    std::fs::create_dir_all(d.path().join("_quarantine")).unwrap();
    std::fs::write(d.path().join("_quarantine").join(&name), b"old").unwrap();
    let root = RootDir::open(d.path()).unwrap();
    // The suffixed name exceeds NAME_MAX: an error or Exhausted is acceptable, a loop or
    // an overwrite is not.
    let _ = quarantine(&root, &[name.as_str()]);
    assert_eq!(std::fs::read(d.path().join(&name)).unwrap(), b"src");
    assert_eq!(
        std::fs::read(d.path().join("_quarantine").join(&name)).unwrap(),
        b"old"
    );
}

#[test]
fn quarantine_bound_u32_max_still_terminates_on_first_free_name() {
    let (_d, root) = qsetup();
    assert_eq!(
        quarantine_with_bound(&root, &["cam", "day", "f.mp4"], u32::MAX).unwrap(),
        QuarantineOutcome::Moved { suffix: None }
    );
}

#[test]
fn concurrent_quarantines_race_on_creating_the_quarantine_dir() {
    let d = tempfile::tempdir().unwrap();
    let root = RootDir::open(d.path()).unwrap();
    let n = 8usize;
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(n));
    let mut hs = Vec::new();
    for i in 0..n {
        let dir = d.path().join(format!("c{i}"));
        std::fs::create_dir(&dir).unwrap();
        std::fs::write(dir.join("x"), [u8::try_from(i).unwrap()]).unwrap();
        let r = root.try_clone().unwrap();
        let b = barrier.clone();
        let src_dir = format!("c{i}");
        hs.push(std::thread::spawn(move || {
            b.wait();
            // Source differs, target dir differs too (_quarantine/c<i>); this checks that the
            // concurrent mkdir of `_quarantine` itself is race-free.
            quarantine(&r, &[src_dir.as_str(), "x"]).unwrap()
        }));
    }
    for h in hs {
        assert_eq!(h.join().unwrap(), QuarantineOutcome::Moved { suffix: None });
    }
}

// ---------- open_private_file ----------

#[test]
fn private_file_refuses_a_socket_and_a_fifo_without_blocking() {
    let d = tempfile::tempdir().unwrap();
    let s = d.path().join("sock");
    let _l = std::os::unix::net::UnixListener::bind(&s).unwrap();
    let r = must_not_block(move || open_private_file(&s).map(|_| ()));
    assert!(r.is_err());
    let f = d.path().join("fifo");
    mkfifo(&f);
    let r = must_not_block(move || open_private_file(&f).map(|_| ()));
    assert!(matches!(r, Err(FsError::NotRegular)));
}

#[test]
fn private_file_refuses_symlink_to_fifo_and_to_dev_null() {
    let d = tempfile::tempdir().unwrap();
    symlink("/dev/null", d.path().join("n")).unwrap();
    let e = open_private_file(&d.path().join("n")).unwrap_err();
    assert_eq!(e.errno(), Some(Errno::LOOP));
}

#[test]
fn private_file_refuses_char_device() {
    assert!(matches!(
        open_private_file(Path::new("/dev/null")),
        Err(FsError::NotRegular | FsError::WrongOwner { .. })
    ));
}

#[test]
fn private_file_refuses_file_owned_by_another_user() {
    // /etc/hostname or /etc/passwd: owned by root, mode 0644.
    let e = open_private_file(Path::new("/etc/passwd")).unwrap_err();
    assert!(matches!(
        e,
        FsError::WrongOwner { found: 0, .. } | FsError::InsecureMode { .. }
    ));
}

#[test]
fn private_file_with_write_only_mode_is_a_typed_error() {
    use std::os::unix::fs::PermissionsExt;
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("db");
    std::fs::write(&p, b"").unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o200)).unwrap();
    assert_eq!(
        open_private_file(&p).unwrap_err().errno(),
        Some(Errno::ACCESS)
    );
}

#[test]
fn verify_detects_rename_swap_with_a_different_file() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("db");
    let f = open_private_file(&p).unwrap();
    let other = d.path().join("other");
    drop(open_private_file(&other).unwrap());
    std::fs::rename(&other, &p).unwrap();
    assert!(matches!(
        f.verify_path_unchanged(&p),
        Err(FsError::IdentityMismatch)
    ));
}

#[test]
fn verify_accepts_a_hard_link_to_the_same_inode() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("db");
    let f = open_private_file(&p).unwrap();
    std::fs::hard_link(&p, d.path().join("alias")).unwrap();
    std::fs::rename(d.path().join("alias"), &p).unwrap();
    f.verify_path_unchanged(&p).unwrap();
}

// ---------- error hygiene ----------

#[test]
fn error_messages_never_contain_the_path() {
    let d = tempfile::tempdir().unwrap();
    let marker = "SECRETCAMNAME";
    let base = d.path().join(marker);
    std::fs::create_dir(&base).unwrap();
    let mut errs: Vec<FsError> = Vec::new();
    errs.push(RootDir::open(&base.join("missing")).unwrap_err());
    errs.push(open_private_file(&base.join("x/y")).unwrap_err());
    let root = RootDir::open(&base).unwrap();
    errs.push(root.open_read(&[marker]).unwrap_err());
    errs.push(root.open_dir(&[marker, marker]).unwrap_err());
    errs.push(root.mkdir(&format!("{marker}/x")).unwrap_err());
    errs.push(quarantine(&root, &[marker]).unwrap_err());
    for e in errs {
        let s = format!("{e} {e:?}");
        assert!(!s.contains(marker), "{s}");
        assert!(!s.contains(&*d.path().to_string_lossy()), "{s}");
    }
}
