//! Quarantine rename (ADR 0005 section 9).

use crate::error::FsError;
use crate::root::{RootDir, component};
use rustix::io::Errno;

/// Name of the quarantine directory under a root. No `CameraId` can equal it (they start with a letter).
pub const QUARANTINE_DIR: &str = "_quarantine";

/// Highest numeric suffix tried before giving up (`<name>.1` .. `<name>.1000`).
pub const MAX_QUARANTINE_SUFFIX: u32 = 1_000;

/// Result of a quarantine attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum QuarantineOutcome {
    /// Moved. `suffix` is `None` for the plain name, else the numeric suffix used.
    Moved {
        /// Numeric suffix of the target name, if any.
        suffix: Option<u32>,
    },
    /// Every candidate name was taken; the file was left in place and nothing was overwritten.
    Exhausted,
}

/// Move the file at `rel` (components below `root`) to `<root>/_quarantine/<same relative path>`
/// with `RENAME_NOREPLACE`, creating parent directories. Uses [`MAX_QUARANTINE_SUFFIX`].
///
/// # Errors
/// Invalid component (every element of `rel`, including the final name, is validated before any
/// syscall; a first component of `_quarantine` is refused too), a source that is not a regular
/// file ([`FsError::NotRegular`]: directories, FIFOs and symlinks are refused and nothing is
/// created), or any failing syscall other than `EEXIST` on the final rename (which selects the
/// next suffix).
///
/// A name of 255 bytes yields `ENAMETOOLONG` (the suffix does not fit) rather than
/// [`QuarantineOutcome::Exhausted`].
///
/// If the rename succeeded but a later directory `fsync` failed, `Err` is returned although the
/// file has already moved into quarantine.
pub fn quarantine<S: AsRef<str>>(root: &RootDir, rel: &[S]) -> Result<QuarantineOutcome, FsError> {
    quarantine_with_bound(root, rel, MAX_QUARANTINE_SUFFIX)
}

/// As [`quarantine`] with an explicit suffix bound (tests use a small one). The bound is clamped
/// to [`MAX_QUARANTINE_SUFFIX`].
///
/// # Errors
/// As [`quarantine`].
pub fn quarantine_with_bound<S: AsRef<str>>(
    root: &RootDir,
    rel: &[S],
    max_suffix: u32,
) -> Result<QuarantineOutcome, FsError> {
    let Some((name, parents)) = rel.split_last() else {
        return Err(FsError::InvalidComponent);
    };
    for c in rel {
        component(c.as_ref())?;
    }
    let max_suffix = max_suffix.min(MAX_QUARANTINE_SUFFIX);
    let name = name.as_ref();
    if rel.first().is_some_and(|c| c.as_ref() == QUARANTINE_DIR) {
        return Err(FsError::InvalidComponent);
    }
    let source_dir = if parents.is_empty() {
        root.try_clone()?
    } else {
        root.open_dir(parents)?
    };
    // Refuse a directory, FIFO, symlink or device before creating anything.
    drop(source_dir.open_read(&[name])?);
    let target_dir = ensure_quarantine_dir(root, parents)?;

    let mut candidate = name.to_owned();
    let mut suffix: Option<u32> = None;
    loop {
        match source_dir.rename_noreplace(name, &target_dir, &candidate) {
            Ok(()) => {
                source_dir.sync()?;
                target_dir.sync()?;
                return Ok(QuarantineOutcome::Moved { suffix });
            }
            Err(e) if e.errno() == Some(Errno::EXIST) => {
                let next = suffix.map_or(Some(1), |s| s.checked_add(1));
                match next {
                    Some(n) if n <= max_suffix => {
                        suffix = Some(n);
                        candidate = format!("{name}.{n}");
                    }
                    _ => return Ok(QuarantineOutcome::Exhausted),
                }
            }
            Err(e) => return Err(e),
        }
    }
}

/// Open (creating and fsyncing the parents of each new level) `_quarantine/<parents...>`.
fn ensure_quarantine_dir<S: AsRef<str>>(root: &RootDir, parents: &[S]) -> Result<RootDir, FsError> {
    let mut dir = ensure_child(root, QUARANTINE_DIR)?;
    for p in parents {
        dir = ensure_child(&dir, p.as_ref())?;
    }
    Ok(dir)
}

fn ensure_child(parent: &RootDir, name: &str) -> Result<RootDir, FsError> {
    match parent.mkdir(name) {
        Ok(()) => parent.sync()?,
        Err(e) if e.errno() == Some(Errno::EXIST) => {}
        Err(e) => return Err(e),
    }
    parent.open_dir(&[name])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> (tempfile::TempDir, RootDir) {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("cam/2026-01-02")).unwrap();
        std::fs::write(dir.path().join("cam/2026-01-02/000102-003.mp4"), b"v0").unwrap();
        let root = RootDir::open(dir.path()).unwrap();
        (dir, root)
    }

    const REL: [&str; 3] = ["cam", "2026-01-02", "000102-003.mp4"];

    fn qpath(d: &tempfile::TempDir, name: &str) -> std::path::PathBuf {
        d.path().join("_quarantine/cam/2026-01-02").join(name)
    }

    #[test]
    fn moves_into_quarantine_creating_parents() {
        let (d, root) = setup();
        let out = quarantine(&root, &REL).unwrap();
        assert_eq!(out, QuarantineOutcome::Moved { suffix: None });
        assert_eq!(std::fs::read(qpath(&d, "000102-003.mp4")).unwrap(), b"v0");
        assert!(!d.path().join("cam/2026-01-02/000102-003.mp4").exists());
    }

    #[test]
    fn suffixes_instead_of_overwriting() {
        let (d, root) = setup();
        for i in 1..=3u8 {
            quarantine(&root, &REL).unwrap();
            std::fs::write(d.path().join("cam/2026-01-02/000102-003.mp4"), [i]).unwrap();
        }
        let out = quarantine(&root, &REL).unwrap();
        assert_eq!(out, QuarantineOutcome::Moved { suffix: Some(3) });
        assert_eq!(std::fs::read(qpath(&d, "000102-003.mp4")).unwrap(), b"v0");
        assert_eq!(std::fs::read(qpath(&d, "000102-003.mp4.1")).unwrap(), [1]);
        assert_eq!(std::fs::read(qpath(&d, "000102-003.mp4.2")).unwrap(), [2]);
        assert_eq!(std::fs::read(qpath(&d, "000102-003.mp4.3")).unwrap(), [3]);
    }

    #[test]
    fn exhausted_bound_leaves_file_and_overwrites_nothing() {
        let (d, root) = setup();
        std::fs::create_dir_all(d.path().join("_quarantine/cam/2026-01-02")).unwrap();
        std::fs::write(qpath(&d, "000102-003.mp4"), b"q0").unwrap();
        std::fs::write(qpath(&d, "000102-003.mp4.1"), b"q1").unwrap();
        std::fs::write(qpath(&d, "000102-003.mp4.2"), b"q2").unwrap();
        let out = quarantine_with_bound(&root, &REL, 2).unwrap();
        assert_eq!(out, QuarantineOutcome::Exhausted);
        assert_eq!(
            std::fs::read(d.path().join("cam/2026-01-02/000102-003.mp4")).unwrap(),
            b"v0"
        );
        assert_eq!(std::fs::read(qpath(&d, "000102-003.mp4")).unwrap(), b"q0");
        assert_eq!(std::fs::read(qpath(&d, "000102-003.mp4.2")).unwrap(), b"q2");
        assert!(!qpath(&d, "000102-003.mp4.3").exists());
    }

    #[test]
    fn zero_bound_allows_only_the_plain_name() {
        let (d, root) = setup();
        std::fs::create_dir_all(d.path().join("_quarantine/cam/2026-01-02")).unwrap();
        std::fs::write(qpath(&d, "000102-003.mp4"), b"q0").unwrap();
        assert_eq!(
            quarantine_with_bound(&root, &REL, 0).unwrap(),
            QuarantineOutcome::Exhausted
        );
    }

    #[test]
    fn oversized_bound_is_clamped() {
        let (d, root) = setup();
        std::fs::create_dir_all(d.path().join("_quarantine/cam/2026-01-02")).unwrap();
        std::fs::write(qpath(&d, "000102-003.mp4"), b"q0").unwrap();
        for i in 1..=MAX_QUARANTINE_SUFFIX {
            std::fs::write(qpath(&d, &format!("000102-003.mp4.{i}")), b"q").unwrap();
        }
        assert_eq!(
            quarantine_with_bound(&root, &REL, u32::MAX).unwrap(),
            QuarantineOutcome::Exhausted
        );
        assert!(!qpath(&d, "000102-003.mp4.1001").exists());
    }

    #[test]
    fn refuses_a_directory_source_and_creates_nothing() {
        let (d, root) = setup();
        std::fs::create_dir(d.path().join("cam/sub")).unwrap();
        let e = quarantine(&root, &["cam", "sub"]).unwrap_err();
        assert!(matches!(e, FsError::NotRegular));
        assert!(d.path().join("cam/sub").is_dir());
        assert!(!d.path().join("_quarantine").exists());
    }

    #[test]
    fn missing_source_is_an_error_not_exhausted() {
        let (_d, root) = setup();
        let e = quarantine(&root, &["cam", "2026-01-02", "999999-999.mp4"]).unwrap_err();
        assert!(e.is_not_found());
    }

    #[test]
    fn works_for_a_file_directly_in_the_root() {
        let (d, root) = setup();
        std::fs::write(d.path().join("loose"), b"x").unwrap();
        quarantine(&root, &["loose"]).unwrap();
        assert!(d.path().join("_quarantine/loose").exists());
    }

    #[test]
    fn refuses_bad_components_and_quarantine_of_quarantine() {
        let (d, root) = setup();
        assert!(matches!(
            quarantine(&root, &["cam", "..", "x"]),
            Err(FsError::InvalidComponent)
        ));
        assert!(matches!(
            quarantine(&root, &["a/b"]),
            Err(FsError::InvalidComponent)
        ));
        assert!(matches!(
            quarantine(&root, &["_quarantine", "x"]),
            Err(FsError::InvalidComponent)
        ));
        let none: [&str; 0] = [];
        assert!(matches!(
            quarantine(&root, &none),
            Err(FsError::InvalidComponent)
        ));
        assert!(!d.path().join("_quarantine").exists());
    }

    #[test]
    fn refuses_a_symlinked_quarantine_directory() {
        let (d, root) = setup();
        let outside = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(outside.path(), d.path().join("_quarantine")).unwrap();
        assert!(quarantine(&root, &REL).is_err());
        assert!(!d.path().join("_quarantine/cam").exists());
        assert!(d.path().join("cam/2026-01-02/000102-003.mp4").exists());
        assert_eq!(std::fs::read_dir(outside.path()).unwrap().count(), 0);
    }
}
