//! Finding the files of a scan, relative to directory descriptors (ticket #124).
//!
//! A directory is listed through a descriptor opened with `O_DIRECTORY | O_NOFOLLOW`, its
//! entries are typed with `fstatat(AT_SYMLINK_NOFOLLOW)` and subdirectories are opened with
//! `openat` on the parent descriptor, so a directory swapped for a symlink while the walk runs
//! is refused, not followed. A file found by the walk is opened again when it is scanned, the
//! same way: one `openat` per component, starting from the descriptor of the directory given on
//! the command line (a descriptor per file would exhaust the process limit). A path given on the
//! command line is the owner's own choice and is followed if it is a symlink.
//!
//! Memory is bounded: an entry is one node (its name and a link to its parent directory's
//! node), shared by everything below it; the display path is built only when it is printed, and
//! the names of one walk may hold at most [`MAX_NAME_BYTES`] bytes in all.

use std::ffi::{OsStr, OsString};
use std::fs::{self, File};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use rustix::fs::{AtFlags, Dir, FileType, Mode, OFlags};
use rustix::io::Errno;

use crate::error::CliError;

/// Deepest directory nesting that is walked.
pub(super) const MAX_DEPTH: usize = 64;
/// Most bytes of names (each counted with a fixed per-entry overhead) one walk keeps. About
/// 16 MiB: a tree of 100,000 files with names of 100 bytes fits; a hostile tree of long names
/// is refused (exit 2) long before it exhausts memory.
pub(super) const MAX_NAME_BYTES: usize = 16 * 1024 * 1024;
/// What one entry costs besides its name, for the budget above.
const ENTRY_OVERHEAD: usize = 64;

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

/// A directory given on the command line, held open for the whole scan.
struct Root {
    shown: PathBuf,
    fd: OwnedFd,
}

/// One entry below a root: its name and the node of the directory that holds it (`None` for the
/// root directory itself, whose name is empty).
struct Node {
    parent: Option<Rc<Node>>,
    name: OsString,
}

impl Node {
    /// The names from just below the root down to this entry.
    fn chain(&self) -> Vec<&OsStr> {
        let mut names = Vec::new();
        let mut at = Some(self);
        while let Some(n) = at {
            if n.parent.is_some() {
                names.push(n.name.as_os_str());
            }
            at = n.parent.as_deref();
        }
        names.reverse();
        names
    }
}

enum Place {
    /// A path given on the command line, followed if it is a symlink.
    Explicit(PathBuf),
    /// An entry found while walking.
    Below { root: Rc<Root>, node: Rc<Node> },
}

/// Something found while walking: a file to scan or one that could not be read.
pub(super) struct Input {
    place: Place,
    pub(super) problem: Option<Unread>,
}

impl Input {
    /// What is printed. Built on demand, never stored.
    pub(super) fn path(&self) -> PathBuf {
        match &self.place {
            Place::Explicit(p) => p.clone(),
            Place::Below { root, node } => {
                let mut p = root.shown.clone();
                p.extend(node.chain());
                p
            }
        }
    }

    /// Opens the file without ever blocking on it (a FIFO would hang a plain open). A file found
    /// while walking is reached through descriptors and never through a symlink.
    pub(super) fn open(&self) -> Result<File, Unread> {
        let fd = match &self.place {
            Place::Explicit(p) => open_flags(p, base_flags()),
            Place::Below { root, node } => open_below(root, node),
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

fn open_at(dir: BorrowedFd<'_>, name: &OsStr, flags: OFlags) -> Result<OwnedFd, Unread> {
    rustix::fs::openat(dir, name, flags | OFlags::NOFOLLOW, Mode::empty()).map_err(unread)
}

fn open_below(root: &Root, node: &Node) -> Result<OwnedFd, Unread> {
    let chain = node.chain();
    let Some((last, parents)) = chain.split_last() else {
        return Err(Unread::NotRegular);
    };
    // Each directory is held only until the next one is open.
    let mut held: Option<OwnedFd> = None;
    for name in parents {
        let from = held.as_ref().map_or(root.fd.as_fd(), AsFd::as_fd);
        let next = open_at(from, name, dir_flags())?;
        held = Some(next);
    }
    let from = held.as_ref().map_or(root.fd.as_fd(), AsFd::as_fd);
    open_at(from, last, base_flags())
}

pub(super) struct Walk {
    pub(super) inputs: Vec<Input>,
    pub(super) symlinks: usize,
    pub(super) special: usize,
    seen: usize,
    /// Most inputs this walk accepts.
    limit: usize,
    /// Bytes of names kept so far, and the most this walk keeps.
    name_bytes: usize,
    name_limit: usize,
}

impl Walk {
    fn new(limit: usize, name_limit: usize) -> Self {
        Self {
            inputs: Vec::new(),
            symlinks: 0,
            special: 0,
            seen: 0,
            limit,
            name_bytes: 0,
            name_limit,
        }
    }

    fn push(&mut self, place: Place, problem: Option<Unread>) -> Result<(), CliError> {
        self.seen = self.seen.saturating_add(1);
        if self.seen > self.limit {
            return Err(CliError::Refused(TOO_MANY));
        }
        self.inputs.push(Input { place, problem });
        Ok(())
    }

    /// Charges the name of an entry that is about to be kept.
    fn charge(&mut self, name: &OsStr) -> Result<(), CliError> {
        self.name_bytes = self
            .name_bytes
            .saturating_add(name.len())
            .saturating_add(ENTRY_OVERHEAD);
        if self.name_bytes > self.name_limit {
            return Err(CliError::Refused(TOO_MANY));
        }
        Ok(())
    }

    fn below(root: &Rc<Root>, node: &Rc<Node>) -> Place {
        Place::Below {
            root: Rc::clone(root),
            node: Rc::clone(node),
        }
    }

    /// Lists the open directory `fd`, which is `node` below `root`.
    fn dir(
        &mut self,
        root: &Rc<Root>,
        fd: &OwnedFd,
        node: &Rc<Node>,
        depth: usize,
    ) -> Result<(), CliError> {
        if depth > MAX_DEPTH {
            return self.push(Self::below(root, node), Some(Unread::TooDeep));
        }
        let mut entries = match Dir::read_from(fd) {
            Ok(d) => d,
            Err(e) => return self.push(Self::below(root, node), Some(unread(e))),
        };
        let mut found: Vec<OsString> = Vec::new();
        while let Some(entry) = entries.read() {
            match entry {
                Ok(e) => {
                    let name = e.file_name().to_bytes();
                    if name != b"." && name != b".." {
                        let name = OsStr::from_bytes(name);
                        self.charge(name)?;
                        found.push(name.to_owned());
                    }
                }
                Err(e) => self.push(Self::below(root, node), Some(unread(e)))?,
            }
            if found.len().saturating_add(self.seen) > self.limit {
                return Err(CliError::Refused(TOO_MANY));
            }
        }
        found.sort();
        for name in found {
            self.entry(root, fd, node, name, depth)?;
        }
        Ok(())
    }

    fn entry(
        &mut self,
        root: &Rc<Root>,
        fd: &OwnedFd,
        parent: &Rc<Node>,
        name: OsString,
        depth: usize,
    ) -> Result<(), CliError> {
        let st = rustix::fs::statat(fd, name.as_os_str(), AtFlags::SYMLINK_NOFOLLOW);
        let node = Rc::new(Node {
            parent: Some(Rc::clone(parent)),
            name,
        });
        let st = match st {
            Ok(st) => st,
            Err(e) => return self.push(Self::below(root, &node), Some(unread(e))),
        };
        match FileType::from_raw_mode(st.st_mode) {
            FileType::Symlink => self.symlinks = self.symlinks.saturating_add(1),
            FileType::Directory => match open_at(fd.as_fd(), &node.name, dir_flags()) {
                Ok(sub) => self.dir(root, &sub, &node, depth.saturating_add(1))?,
                Err(p) => self.push(Self::below(root, &node), Some(p))?,
            },
            FileType::RegularFile => self.push(Self::below(root, &node), None)?,
            _ => self.special = self.special.saturating_add(1),
        }
        Ok(())
    }
}

/// Finds the inputs of a scan: the files given, and every regular file below the directories
/// given. More than `limit` of them is refused.
pub(super) fn walk(paths: &[PathBuf], limit: usize) -> Result<Walk, CliError> {
    walk_with(paths, limit, MAX_NAME_BYTES)
}

pub(super) fn walk_with(
    paths: &[PathBuf],
    limit: usize,
    name_limit: usize,
) -> Result<Walk, CliError> {
    let mut w = Walk::new(limit, name_limit);
    for p in paths {
        match fs::metadata(p) {
            Ok(m) if m.is_dir() => match open_flags(p, dir_flags()) {
                Ok(fd) => {
                    let root = Rc::new(Root {
                        shown: p.clone(),
                        fd,
                    });
                    let top = Rc::new(Node {
                        parent: None,
                        name: OsString::new(),
                    });
                    w.dir(&root, &root.fd, &top, 0)?;
                }
                Err(why) => w.push(Place::Explicit(p.clone()), Some(why))?,
            },
            Ok(m) if m.is_file() => w.push(Place::Explicit(p.clone()), None)?,
            Ok(_) => w.push(Place::Explicit(p.clone()), Some(Unread::NotRegular))?,
            Err(e) => w.push(Place::Explicit(p.clone()), Some(Unread::Io(e.kind())))?,
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

    /// The names of a walk are bounded in bytes, not only in count: one more entry over the
    /// budget is refused (exit 2 through `CouldNotScan`), exactly at the budget is accepted.
    #[test]
    fn the_name_budget_is_exact_and_one_byte_over_is_refused() {
        let d = tempfile::tempdir().unwrap();
        for i in 0..4 {
            std::fs::write(d.path().join(format!("file{i}")), "x").unwrap();
        }
        // Four names of five bytes, each with the fixed overhead.
        let exact = 4 * (5 + ENTRY_OVERHEAD);
        for (limit, ok) in [(exact, true), (exact - 1, false)] {
            let r = walk_with(&[d.path().to_owned()], 100, limit);
            assert_eq!(r.is_ok(), ok, "limit {limit}");
            if let Err(e) = r {
                assert!(matches!(e, CliError::Refused(_)));
                assert_eq!(CliError::CouldNotScan(Box::new(e)).exit_code(), 2);
            }
        }
    }

    /// Long names at depth are charged once each, never once per file below them: a directory
    /// of many files under long directory names costs the names once.
    #[test]
    fn a_directory_name_is_charged_once_whatever_is_below_it() {
        let d = tempfile::tempdir().unwrap();
        let long = "d".repeat(200);
        let dir = d.path().join(&long).join(&long);
        std::fs::create_dir_all(&dir).unwrap();
        for i in 0..50 {
            std::fs::write(dir.join(format!("f{i:02}")), "x").unwrap();
        }
        // Two 200 byte directory names and fifty 3 byte file names.
        let need = 2 * (200 + ENTRY_OVERHEAD) + 50 * (3 + ENTRY_OVERHEAD);
        let w = walk_with(&[d.path().to_owned()], 1000, need).unwrap();
        assert_eq!(w.inputs.len(), 50);
        assert!(walk_with(&[d.path().to_owned()], 1000, need - 1).is_err());
        // The display path is built on demand and is complete.
        assert!(w.inputs[0].path().ends_with(format!("{long}/{long}/f00")));
        for i in &w.inputs {
            assert!(i.open().is_ok());
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
        assert!(w.inputs.iter().all(|i| !i.path().ends_with("leaf.txt")));
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
            .map(|i| i.path().strip_prefix(d.path()).unwrap().to_owned())
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
            .position(|i| i.path().ends_with("f.txt"))
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
