//! The full-path walk of the new trees (ADR 0006 section 9).
//!
//! A path can spell a vault value, and a value can hold a `/`, so the unit scanned is the FULL
//! path of an entry (`parent/child`), never a name alone.
//!
//! THE INVARIANT: every full path that appears in any tree reachable from a new root (the root
//! tree of every new commit, and every new tree a tag or the end of the range points at) is
//! scanned, whatever the age of the subtrees it passes through. A new path can sit on an old
//! tree (`git mv dir new` keeps the subtree id), so the walk descends into EVERY entry, old
//! subtrees included, loading those on demand. To stay cheap it keeps a visited set of
//! (full path, entry id): the same subtree reached again at the same full path has had all its
//! full paths scanned, so it is skipped; the same subtree at a different path is walked again.
//!
//! It is an explicit stack over one shared path buffer (no recursion, so no overflow), and it is
//! bounded: a path longer than [`MAX_PATH_LEN`], more than [`MAX_PLACES`] places, more than
//! [`MAX_PATH_BYTES`] of stored paths and more than [`MAX_TREE_BYTES`] of raw trees (old ones
//! included) fail the scan closed. The bounds are read from `Collected::limits`.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::rc::Rc;

use wardenlens_core::entry::{EntryId, EntryKind};
use wardenlens_vault::{Matcher, scan};

use super::{Collected, Where};
use crate::vault_cmd::scan::git::{GitError, Sha};

/// Longest full path walked; a longer one fails the scan (git's own `PATH_MAX`).
pub(super) const MAX_PATH_LEN: usize = 4096;
/// Most distinct (path, entry) places one scan visits.
pub(super) const MAX_PLACES: usize = 500_000;
/// Most bytes of raw tree objects held for one scan.
pub(super) const MAX_TREE_BYTES: usize = 32 * 1024 * 1024;
/// Most bytes of paths the walk stores for one scan (the visited set and the paths of blobs):
/// a crafted repeating tree has up to [`MAX_PLACES`] places of [`MAX_PATH_LEN`] bytes, which
/// would be gigabytes before the places bound stops it.
pub(super) const MAX_PATH_BYTES: usize = 64 * 1024 * 1024;

/// What a tree entry is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum EntryMode {
    Tree,
    /// A submodule: the id names a commit of another repository.
    Gitlink,
    /// A file or a symlink.
    Blob,
}

/// One entry of a tree object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct TreeEntry {
    pub(super) name: Vec<u8>,
    pub(super) mode: EntryMode,
    pub(super) id: Sha,
}

/// Longest mode text accepted (git writes at most six octal digits; this leaves room for a
/// leading zero and no more). DELIBERATE: git itself accepts longer octal text (`00040000` is
/// a directory to `ls-tree` and checkout), but no tool writes it, and a mode the scan cannot
/// be sure it reads as git does is `Malformed` (exit 2), never a guess. Fail closed beats
/// matching git's leniency.
const MAX_MODE_LEN: usize = 7;

/// Classifies a tree entry's mode text the way git does: an octal number whose file-type bits
/// (`0o170000`) say tree, gitlink, symlink or regular file. Anything else (not octal, empty,
/// over-long, an unknown type) is `None`: the tree is malformed and the scan fails closed.
fn classify_mode(text: &[u8]) -> Option<EntryMode> {
    if text.is_empty() || text.len() > MAX_MODE_LEN {
        return None;
    }
    let mut mode: u32 = 0;
    for &b in text {
        let digit = char::from(b).to_digit(8)?;
        mode = mode.checked_mul(8)?.checked_add(digit)?;
    }
    match mode & 0o170_000 {
        0o040_000 => Some(EntryMode::Tree),
        0o160_000 => Some(EntryMode::Gitlink),
        0o120_000 | 0o100_000 => Some(EntryMode::Blob),
        _ => None,
    }
}

/// The entries of a raw tree (`mode SP name NUL id`, `id_len` raw bytes), or `None` when the
/// tree is not well formed. Bounds are checked with `get`; nothing is sliced by position.
pub(super) fn tree_entries(raw: &[u8], id_len: usize) -> Option<Vec<TreeEntry>> {
    let mut entries = Vec::new();
    let mut rest = raw;
    while !rest.is_empty() {
        let sp = rest.iter().position(|&b| b == b' ')?;
        let mode = classify_mode(rest.get(..sp)?)?;
        let after_mode = rest.get(sp.checked_add(1)?..)?;
        let nul = after_mode.iter().position(|&b| b == 0)?;
        let name = after_mode.get(..nul)?.to_vec();
        let after_name = after_mode.get(nul.checked_add(1)?..)?;
        let id = after_name.get(..id_len)?;
        let hex: String = id
            .iter()
            .flat_map(|b| [b >> 4, b & 15])
            .filter_map(|d| char::from_digit(u32::from(d), 16))
            .collect();
        entries.push(TreeEntry {
            name,
            mode,
            id: Sha::parse(hex.as_bytes())?,
        });
        rest = after_name.get(id_len..)?;
    }
    Some(entries)
}

/// The parsed entries of a tree, shared between the cache and the frames walking it.
pub(super) type Entries = Rc<[TreeEntry]>;

/// Loads an old tree by id: its entries, or `None` when it could not be read or parsed (the
/// loader records the problem). An error fails the scan.
pub(super) type Loader<'l> =
    dyn FnMut(&Sha, &mut Collected) -> Result<Option<Entries>, GitError> + 'l;

/// One directory being walked.
struct Frame {
    tree: Sha,
    entries: Entries,
    next: usize,
    /// Length of this directory's path in the shared buffer (0 for a root).
    dir_len: usize,
    /// Whether a `/` separates the directory path from an entry name (false for a root).
    slash: bool,
    /// Where the directory is (`None` for a root) and the vault values its own path holds. A
    /// value in a directory's path is reported at the files and directories below it (the
    /// places that publish it); only when nothing below reports it is it reported at the
    /// directory itself (an empty one, or one whose content is all already published).
    at: Option<Where>,
    hits: Vec<(EntryId, EntryKind)>,
    /// Ids reported at or below this directory.
    covered: Vec<EntryId>,
}

impl Frame {
    /// The walk of a root tree: no path yet, nothing reported at it.
    fn root(tree: &Sha, entries: Entries) -> Self {
        Self {
            tree: tree.clone(),
            entries,
            next: 0,
            dir_len: 0,
            slash: false,
            at: None,
            hits: Vec::new(),
            covered: Vec::new(),
        }
    }
}

/// Closes a directory: its own hits that nothing below reported are reported at it, and what it
/// held is reported at or below it for the directory above.
fn finish(found: &mut Collected, frame: Frame, parent: Option<&mut Frame>) {
    for (id, kind) in &frame.hits {
        if let (Some(at), false) = (&frame.at, frame.covered.contains(id)) {
            found.add(id, *kind, at.clone());
        }
    }
    if let Some(p) = parent {
        p.covered.extend(frame.hits.into_iter().map(|(id, _)| id));
        p.covered.extend(frame.covered);
    }
}

/// Bytes of paths stored so far, against the budget.
struct Stored {
    bytes: usize,
    budget: usize,
}

impl Stored {
    /// Charges `n` bytes: `TooMany` once the budget is passed.
    fn add(&mut self, n: usize) -> Result<(), GitError> {
        self.bytes = self.bytes.saturating_add(n);
        if self.bytes > self.budget {
            return Err(GitError::PathBytes);
        }
        Ok(())
    }
}

/// Test entry point: the trees are all given, nothing is loaded, the visited-set skip is on.
///
/// # Errors
/// As [`walk_with`].
#[cfg(test)]
pub(super) fn walk<'a>(
    matcher: &Matcher,
    found: &mut Collected,
    trees: &HashMap<Sha, Vec<TreeEntry>>,
    roots: impl IntoIterator<Item = &'a Sha>,
) -> Result<(), GitError> {
    let mut cache: HashMap<Sha, Entries> = trees
        .iter()
        .map(|(k, v)| (k.clone(), Entries::from(v.clone())))
        .collect();
    walk_with(
        matcher,
        found,
        &mut cache,
        roots,
        &mut |_, _| Ok(None),
        true,
    )
}

/// Walks `roots`, scanning the full path of every entry reachable from them. `cache` holds the
/// trees already read (the new ones); any other tree is fetched with `load` and cached. With
/// `skip_seen` false the visited-set skip is off (a test of the skip: same hits, more work).
///
/// # Errors
/// A path longer than [`MAX_PATH_LEN`], more than [`MAX_PLACES`] places, more than
/// [`MAX_PATH_BYTES`] of stored paths (`PathBytes`), or a loader error.
pub(super) fn walk_with<'a>(
    matcher: &Matcher,
    found: &mut Collected,
    cache: &mut HashMap<Sha, Entries>,
    roots: impl IntoIterator<Item = &'a Sha>,
    load: &mut Loader<'_>,
    skip_seen: bool,
) -> Result<(), GitError> {
    let mut seen: HashSet<(Vec<u8>, Sha)> = HashSet::new();
    let mut failed: HashSet<Sha> = HashSet::new();
    let mut places: usize = 0;
    let mut stored = Stored {
        bytes: 0,
        budget: found.limits.path_bytes,
    };
    let mut path: Vec<u8> = Vec::new();
    let mut blob_paths: BTreeMap<Sha, Vec<Vec<u8>>> = BTreeMap::new();
    for root in roots {
        let Some(entries) = cache.get(root).cloned() else {
            continue;
        };
        let mut stack = vec![Frame::root(root, entries)];
        while let Some(top) = stack.last_mut() {
            let entries = Rc::clone(&top.entries);
            let Some(entry) = entries.get(top.next) else {
                if let Some(done) = stack.pop() {
                    finish(found, done, stack.last_mut());
                }
                continue;
            };
            top.next = top.next.saturating_add(1);
            path.truncate(top.dir_len);
            if top.slash {
                path.push(b'/');
            }
            path.extend_from_slice(&entry.name);
            if path.len() > MAX_PATH_LEN {
                return Err(GitError::PathTooLong);
            }
            if seen.insert((path.clone(), entry.id.clone())) {
                stored.add(path.len())?;
            } else if skip_seen {
                continue;
            }
            places = places.saturating_add(1);
            if places > MAX_PLACES {
                return Err(GitError::TooMany);
            }
            let at = place(entry, &path, &top.tree);
            if entry.mode == EntryMode::Blob {
                stored.add(path.len())?;
                blob_paths
                    .entry(entry.id.clone())
                    .or_default()
                    .push(path.clone());
            }
            let mut hits = scan_path(matcher, found, &path, &at);
            let sub = if entry.mode == EntryMode::Tree {
                subtree(cache, &mut failed, load, found, &entry.id)?
            } else {
                None
            };
            if let Some(sub) = sub {
                stack.push(Frame {
                    tree: entry.id.clone(),
                    entries: sub,
                    next: 0,
                    dir_len: path.len(),
                    slash: true,
                    at: Some(at),
                    hits,
                    covered: Vec::new(),
                });
            } else {
                // A file, a submodule, or a directory that could not be read: a place itself.
                for (id, kind) in &hits {
                    found.add(id, *kind, at.clone());
                }
                top.covered.extend(hits.drain(..).map(|(id, _)| id));
            }
        }
    }
    for (sha, mut paths) in blob_paths {
        found.paths.entry(sha).or_default().append(&mut paths);
    }
    Ok(())
}

/// The entries of the tree `id`: cached, or loaded now. `None` for one that cannot be read
/// (remembered in `failed`, so its problem is recorded once).
fn subtree(
    cache: &mut HashMap<Sha, Entries>,
    failed: &mut HashSet<Sha>,
    load: &mut Loader<'_>,
    found: &mut Collected,
    id: &Sha,
) -> Result<Option<Entries>, GitError> {
    if let Some(e) = cache.get(id) {
        return Ok(Some(Rc::clone(e)));
    }
    if failed.contains(id) {
        return Ok(None);
    }
    let loaded = load(id, found)?;
    if let Some(e) = &loaded {
        cache.insert(id.clone(), Rc::clone(e));
    } else {
        failed.insert(id.clone());
    }
    Ok(loaded)
}

/// Where an entry at `path` in the tree `containing` is, as it is reported.
fn place(entry: &TreeEntry, path: &[u8], containing: &Sha) -> Where {
    if entry.mode == EntryMode::Blob {
        Where::BlobPath {
            path: path.to_vec(),
            sha: entry.id.clone(),
        }
    } else {
        Where::TreePath {
            path: path.to_vec(),
            sha: containing.clone(),
        }
    }
}

/// Scans one full path: the values it holds. A path too large to scan is a problem at `at`.
fn scan_path(
    matcher: &Matcher,
    found: &mut Collected,
    path: &[u8],
    at: &Where,
) -> Vec<(EntryId, EntryKind)> {
    let Ok(report) = scan(matcher, path) else {
        found.problems.push((at.clone(), super::Unread::TooLarge));
        return Vec::new();
    };
    found.truncated |= report.truncated;
    let mut hits: Vec<(EntryId, EntryKind)> = Vec::new();
    for h in report.hits {
        if !hits.iter().any(|(id, _)| *id == h.id) {
            hits.push((h.id, h.kind));
        }
    }
    hits
}
