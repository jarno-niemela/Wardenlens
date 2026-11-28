//! Finding the files of a scan, relative to directory descriptors (ticket #124).
//!
//! A directory is listed through a descriptor opened with `O_DIRECTORY | O_NOFOLLOW`, its
//! entries are typed with `fstatat(AT_SYMLINK_NOFOLLOW)` and subdirectories are opened with
//! `openat` on the parent descriptor, so a directory swapped for a symlink while the walk runs
//! is refused, not followed. A file found by the walk is opened again when it is scanned, the
//! same way, one `openat` per component below the directory given on the command line (a
//! descriptor per file would exhaust the process limit). A path given on the command line is
//! the owner's own choice and is followed if it is a symlink.

use std::ffi::{OsStr, OsString};
use std::fs::{self, File};
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use rustix::fs::{AtFlags, Dir, FileType, Mode, OFlags};
use rustix::io::Errno;

use crate::error::CliError;

/// Deepest directory nesting that is walked.
pub(super) const MAX_DEPTH: usize = 64;

const TOO_MANY: &str = "too many files to scan in one command; scan a smaller directory";

/// Why an input could not be scanned. The text never holds a path or a value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(super) enum Unread {
    #[error("cannot be read ({0})")]
    Io(std::io::ErrorKind),
    #[error("is not a regular file or directory")]
    NotRegular,
    #[error("is larger than the 8 MiB scan limit")]
    TooLarge,
    #[error("is nested deeper than the walk limit")]
    TooDeep,
    #[error("is not a well formed git object")]
    Malformed,
}

/// Where a file found while walking is: the directory given on the command line and the names
/// below it.
struct Below {
    root: Rc<PathBuf>,
    names: Vec<OsString>,
}

/// Something found while walking: a file to scan or one that could not be read.
pub(super) struct Input {
    /// What is printed (never opened for a file found while walking).
    pub(super) path: PathBuf,
    /// `None`: a path given on the command line, followed if it is a symlink.
    below: Option<Below>,
    pub(super) problem: Option<Unread>,
}

impl Input {
    /// Opens the file without ever blocking on it (a FIFO would hang a plain open). A file found
    /// while walking is reached through descriptors and never through a symlink.
    pub(super) fn open(&self) -> Result<File, Unread> {
        let fd = match &self.below {
            None => open_flags(&self.path, base_flags()),
            Some(b) => open_below(b),
        }?;
        let file = File::from(fd);
        let meta = file.metadata().map_err(|e| Unread::Io(e.kind()))?;
        if !meta.is_file() {
            return Err(Unread::NotRegular);
        }
        Ok(file)
    }
}

fn base_flags() -> OFlags {
    OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK | OFlags::NOCTTY
}

fn dir_flags() -> OFlags {
    OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOCTTY | OFlags::DIRECTORY
}

/// An error from the descriptor calls as an [`Unread`]: a component that is a symlink or no
/// longer a directory is "not a regular file or directory".
fn unread(e: Errno) -> Unread {
    if matches!(e, Errno::LOOP | Errno::NOTDIR) {
        Unread::NotRegular
    } else {
        Unread::Io(std::io::Error::from(e).kind())
    }
}

fn open_flags(path: &Path, flags: OFlags) -> Result<OwnedFd, Unread> {
    rustix::fs::open(path, flags, Mode::empty()).map_err(unread)
}

fn open_at(dir: &OwnedFd, name: &OsStr, flags: OFlags) -> Result<OwnedFd, Unread> {
    rustix::fs::openat(dir, name, flags | OFlags::NOFOLLOW, Mode::empty()).map_err(unread)
}

fn open_below(b: &Below) -> Result<OwnedFd, Unread> {
    let Some((last, parents)) = b.names.split_last() else {
        return Err(Unread::NotRegular);
    };
    let mut dir = open_flags(&b.root, dir_flags())?;
    for name in parents {
        dir = open_at(&dir, name, dir_flags())?;
    }
    open_at(&dir, last, base_flags())
}

pub(super) struct Walk {
    pub(super) inputs: Vec<Input>,
    pub(super) symlinks: usize,
    pub(super) special: usize,
    seen: usize,
    /// Most inputs this walk accepts.
    limit: usize,
}

impl Walk {
    fn new(limit: usize) -> Self {
        Self {
            inputs: Vec::new(),
            symlinks: 0,
            special: 0,
            seen: 0,
            limit,
        }
    }

    fn push(
        &mut self,
        path: PathBuf,
        below: Option<Below>,
        problem: Option<Unread>,
    ) -> Result<(), CliError> {
        self.seen = self.seen.saturating_add(1);
        if self.seen > self.limit {
            return Err(CliError::Refused(TOO_MANY));
        }
        self.inputs.push(Input {
            path,
            below,
            problem,
        });
        Ok(())
    }

    fn below(root: &Rc<PathBuf>, names: &[OsString]) -> Below {
        Below {
            root: Rc::clone(root),
            names: names.to_vec(),
        }
    }

    /// Lists the open directory `fd`, shown as `shown` and reached by `names` from `root`.
    fn dir(
        &mut self,
        root: &Rc<PathBuf>,
        fd: &OwnedFd,
        names: &mut Vec<OsString>,
        shown: &Path,
        depth: usize,
    ) -> Result<(), CliError> {
        if depth > MAX_DEPTH {
            return self.push(
                shown.to_owned(),
                Some(Self::below(root, names)),
                Some(Unread::TooDeep),
            );
        }
        let mut entries = match Dir::read_from(fd) {
            Ok(d) => d,
            Err(e) => return self.listing_failed(root, names, shown, e),
        };
        let mut found: Vec<OsString> = Vec::new();
        while let Some(entry) = entries.read() {
            match entry {
                Ok(e) => {
                    let name = e.file_name().to_bytes();
                    if name != b"." && name != b".." {
                        found.push(OsStr::from_bytes(name).to_owned());
                    }
                }
                Err(e) => self.listing_failed(root, names, shown, e)?,
            }
            if found.len().saturating_add(self.seen) > self.limit {
                return Err(CliError::Refused(TOO_MANY));
            }
        }
        found.sort();
        for name in found {
            self.entry(root, fd, names, shown, &name, depth)?;
        }
        Ok(())
    }

    fn listing_failed(
        &mut self,
        root: &Rc<PathBuf>,
        names: &[OsString],
        shown: &Path,
        e: Errno,
    ) -> Result<(), CliError> {
        self.push(
            shown.to_owned(),
            Some(Self::below(root, names)),
            Some(unread(e)),
        )
    }

    fn entry(
        &mut self,
        root: &Rc<PathBuf>,
        fd: &OwnedFd,
        names: &mut Vec<OsString>,
        shown: &Path,
        name: &OsStr,
        depth: usize,
    ) -> Result<(), CliError> {
        let path = shown.join(name);
        names.push(name.to_owned());
        let r = self.typed(root, fd, names, path, name, depth);
        names.pop();
        r
    }

    fn typed(
        &mut self,
        root: &Rc<PathBuf>,
        fd: &OwnedFd,
        names: &mut Vec<OsString>,
        path: PathBuf,
        name: &OsStr,
        depth: usize,
    ) -> Result<(), CliError> {
        let st = match rustix::fs::statat(fd, name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(st) => st,
            Err(e) => return self.push(path, Some(Self::below(root, names)), Some(unread(e))),
        };
        match FileType::from_raw_mode(st.st_mode) {
            FileType::Symlink => self.symlinks = self.symlinks.saturating_add(1),
            FileType::Directory => match open_at(fd, name, dir_flags()) {
                Ok(sub) => self.dir(root, &sub, names, &path, depth.saturating_add(1))?,
                Err(p) => self.push(path, Some(Self::below(root, names)), Some(p))?,
            },
            FileType::RegularFile => self.push(path, Some(Self::below(root, names)), None)?,
            _ => self.special = self.special.saturating_add(1),
        }
        Ok(())
    }
}

/// Finds the inputs of a scan: the files given, and every regular file below the directories
/// given. More than `limit` of them is refused.
pub(super) fn walk(paths: &[PathBuf], limit: usize) -> Result<Walk, CliError> {
    let mut w = Walk::new(limit);
    for p in paths {
        match fs::metadata(p) {
            Ok(m) if m.is_dir() => match open_flags(p, dir_flags()) {
                Ok(fd) => w.dir(&Rc::new(p.clone()), &fd, &mut Vec::new(), p, 0)?,
                Err(why) => w.push(p.clone(), None, Some(why))?,
            },
            Ok(m) if m.is_file() => w.push(p.clone(), None, None)?,
            Ok(_) => w.push(p.clone(), None, Some(Unread::NotRegular))?,
            Err(e) => w.push(p.clone(), None, Some(Unread::Io(e.kind())))?,
        }
    }
    Ok(w)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;

    use super::*;

    fn tree(files: usize) -> tempfile::TempDir {
        let d = tempfile::tempdir().unwrap();
        for i in 0..files {
            std::fs::write(d.path().join(format!("f{i}")), "x").unwrap();
        }
        d
    }

    #[test]
    fn the_input_limit_is_exact_and_one_more_is_refused() {
        for (files, limit, ok) in [(4, 5, true), (5, 5, true), (6, 5, false)] {
            let d = tree(files);
            let r = walk(&[d.path().to_owned()], limit);
            assert_eq!(r.is_ok(), ok, "{files} files, limit {limit}");
            if let Ok(w) = r {
                assert_eq!(w.inputs.len(), files);
            }
        }
    }

    #[test]
    fn nesting_beyond_the_depth_limit_is_reported_not_walked() {
        let d = tempfile::tempdir().unwrap();
        let mut deep = d.path().to_owned();
        for _ in 0..=MAX_DEPTH.saturating_add(1) {
            deep.push("d");
        }
        std::fs::create_dir_all(&deep).unwrap();
        std::fs::write(deep.join("leaf.txt"), "x").unwrap();
        let w = walk(&[d.path().to_owned()], 100_000).unwrap();
        assert_eq!(
            w.inputs
                .iter()
                .filter(|i| i.problem == Some(Unread::TooDeep))
                .count(),
            1
        );
        assert!(w.inputs.iter().all(|i| !i.path.ends_with("leaf.txt")));
    }

    #[test]
    fn a_walk_finds_files_in_sorted_order_and_counts_symlinks_and_specials() {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir(d.path().join("sub")).unwrap();
        std::fs::write(d.path().join("sub/b.txt"), "b").unwrap();
        std::fs::write(d.path().join("a.txt"), "a").unwrap();
        symlink("a.txt", d.path().join("link")).unwrap();
        rustix::fs::mknodat(
            rustix::fs::CWD,
            d.path().join("fifo"),
            FileType::Fifo,
            Mode::RUSR,
            0,
        )
        .unwrap();
        let w = walk(&[d.path().to_owned()], 100).unwrap();
        let shown: Vec<_> = w
            .inputs
            .iter()
            .map(|i| i.path.strip_prefix(d.path()).unwrap().to_owned())
            .collect();
        assert_eq!(shown, [PathBuf::from("a.txt"), PathBuf::from("sub/b.txt")]);
        assert_eq!((w.symlinks, w.special), (1, 1));
        for i in &w.inputs {
            assert!(i.open().is_ok());
        }
    }

    /// A directory replaced by a symlink after the walk listed it is not followed when its files
    /// are opened (the swap this module exists to stop), whichever level is swapped.
    #[test]
    fn a_directory_swapped_for_a_symlink_is_not_followed() {
        for swapped in ["a/b", "a"] {
            let d = tempfile::tempdir().unwrap();
            let outside = tempfile::tempdir().unwrap();
            // The same relative layout outside, so the swapped path would resolve.
            std::fs::create_dir_all(outside.path().join("b")).unwrap();
            std::fs::write(outside.path().join("f.txt"), "outside").unwrap();
            std::fs::write(outside.path().join("b/f.txt"), "outside").unwrap();
            std::fs::create_dir_all(d.path().join("a/b")).unwrap();
            std::fs::write(d.path().join("a/b/f.txt"), "inside").unwrap();
            let w = walk(&[d.path().to_owned()], 100).unwrap();
            assert_eq!(w.inputs.len(), 1);
            assert!(w.inputs[0].open().is_ok());
            let target = d.path().join(swapped);
            std::fs::rename(&target, d.path().join("moved")).unwrap();
            let dest = if swapped == "a" {
                outside.path().to_owned()
            } else {
                outside.path().join("b")
            };
            symlink(dest, &target).unwrap();
            let r = w.inputs[0].open();
            assert_eq!(r.err(), Some(Unread::NotRegular), "swapped {swapped}");
        }
    }

    /// The file itself replaced by a symlink is refused too.
    #[test]
    fn a_file_swapped_for_a_symlink_is_not_followed() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join("f.txt"), "x").unwrap();
        std::fs::write(d.path().join("other"), "y").unwrap();
        let w = walk(&[d.path().to_owned()], 100).unwrap();
        let idx = w
            .inputs
            .iter()
            .position(|i| i.path.ends_with("f.txt"))
            .unwrap();
        std::fs::remove_file(d.path().join("f.txt")).unwrap();
        symlink(d.path().join("other"), d.path().join("f.txt")).unwrap();
        assert!(w.inputs[idx].open().is_err());
    }

    /// A path given on the command line is followed if it is a symlink (the owner chose it).
    #[test]
    fn an_explicit_symlink_is_followed() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join("real"), "x").unwrap();
        symlink("real", d.path().join("link")).unwrap();
        let w = walk(&[d.path().join("link")], 100).unwrap();
        assert!(w.inputs[0].open().is_ok());
        // Also a directory given as a symlink is walked.
        std::fs::create_dir(d.path().join("dir")).unwrap();
        std::fs::write(d.path().join("dir/f"), "x").unwrap();
        symlink("dir", d.path().join("dlink")).unwrap();
        let w = walk(&[d.path().join("dlink")], 100).unwrap();
        assert_eq!(w.inputs.len(), 1);
        assert!(w.inputs[0].open().is_ok());
    }

    #[test]
    fn an_error_is_mapped_without_a_path() {
        assert_eq!(unread(Errno::LOOP), Unread::NotRegular);
        assert_eq!(unread(Errno::NOTDIR), Unread::NotRegular);
        assert_eq!(
            unread(Errno::ACCESS),
            Unread::Io(std::io::ErrorKind::PermissionDenied)
        );
    }
}
