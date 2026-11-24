//! The full-path walk of the new trees (ADR 0006 section 9).
//!
//! A path can spell a vault value, and a value can hold a `/`, so the unit scanned is the FULL
//! path of an entry (`parent/child`), never a name alone. The walk starts at the roots (the root
//! tree of every new commit, and every new tree a tag or the end of the range points at) and
//! descends only into trees that are new: every ancestor of a new tree is itself new, so every
//! changed path is visited, and an already published subtree is never walked again.
//!
//! It is an explicit stack over one shared path buffer (no recursion, so no overflow), and it is
//! bounded: a path longer than [`MAX_PATH_LEN`] and more than [`MAX_PLACES`] distinct
//! (path, entry) places fail the scan closed instead of running away on a hostile tree.

use std::collections::{BTreeMap, HashMap, HashSet};

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

/// The entries of a raw tree (`mode SP name NUL id`, `id_len` raw bytes), or `None` when the
/// tree is not well formed. Bounds are checked with `get`; nothing is sliced by position.
pub(super) fn tree_entries(raw: &[u8], id_len: usize) -> Option<Vec<TreeEntry>> {
    let mut entries = Vec::new();
    let mut rest = raw;
    while !rest.is_empty() {
        let sp = rest.iter().position(|&b| b == b' ')?;
        let mode = match rest.get(..sp)? {
            b"40000" | b"040000" => EntryMode::Tree,
            b"160000" => EntryMode::Gitlink,
            _ => EntryMode::Blob,
        };
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

/// One directory being walked.
struct Frame<'a> {
    tree: &'a Sha,
    entries: &'a [TreeEntry],
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

/// Closes a directory: its own hits that nothing below reported are reported at it, and what it
/// held is reported at or below it for the directory above.
fn finish(found: &mut Collected, frame: Frame<'_>, parent: Option<&mut Frame<'_>>) {
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

/// Walks `roots` over `trees` (the new trees, by id), scanning the full path of every entry.
///
/// # Errors
/// A path longer than [`MAX_PATH_LEN`], or more than [`MAX_PLACES`] places.
pub(super) fn walk<'a>(
    matcher: &Matcher,
    found: &mut Collected,
    trees: &'a HashMap<Sha, Vec<TreeEntry>>,
    roots: impl IntoIterator<Item = &'a Sha>,
) -> Result<(), GitError> {
    let mut seen: HashSet<(Vec<u8>, Sha)> = HashSet::new();
    let mut path: Vec<u8> = Vec::new();
    let mut blob_paths: BTreeMap<Sha, Vec<Vec<u8>>> = BTreeMap::new();
    for root in roots {
        let Some(entries) = trees.get(root) else {
            continue;
        };
        let mut stack = vec![Frame {
            tree: root,
            entries,
            next: 0,
            dir_len: 0,
            slash: false,
            at: None,
            hits: Vec::new(),
            covered: Vec::new(),
        }];
        while let Some(top) = stack.last_mut() {
            let Some(entry) = top.entries.get(top.next) else {
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
            if !seen.insert((path.clone(), entry.id.clone())) {
                continue;
            }
            if seen.len() > MAX_PLACES {
                return Err(GitError::TooMany);
            }
            let at = place(entry, &path, top.tree);
            if entry.mode == EntryMode::Blob {
                blob_paths
                    .entry(entry.id.clone())
                    .or_default()
                    .push(path.clone());
            }
            let mut hits = scan_path(matcher, found, &path, &at);
            let sub = (entry.mode == EntryMode::Tree)
                .then(|| trees.get(&entry.id))
                .flatten();
            if let Some(sub) = sub {
                stack.push(Frame {
                    tree: &entry.id,
                    entries: sub,
                    next: 0,
                    dir_len: path.len(),
                    slash: true,
                    at: Some(at),
                    hits,
                    covered: Vec::new(),
                });
            } else {
                // A file, a submodule, or a directory nothing of which is new: a place itself.
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
