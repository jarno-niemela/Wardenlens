//! `wardenlens vault scan --staged` and `--range A..B` (ADR 0006 sections 8 and 9).
//!
//! The scan is read only: it asks git to list and print objects and writes nothing, in the
//! repository or anywhere else. What a push would publish is scanned, all of it:
//!
//! - the new blobs, text and binary alike (a binary blob is matched on its raw bytes, so the
//!   literal needles and the address tokenisers still find a value stored in the clear);
//! - the full path of every entry of every new tree (empty directories, renames of unchanged
//!   content, a second path of one blob, trees only a tag or the range end leads to), see [`walk`];
//! - the raw commit and tag objects, every header and the message, each reported as the part
//!   it is in;
//! - the ref names the push publishes.
//!
//! Nothing is printed except through `render_in`, so a location never holds a value.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::Read;

use wardenlens_core::entry::{EntryId, EntryKind};
use wardenlens_vault::{Content, Matcher, classify, scan};

use self::walk::{Entries, tree_entries};
use super::Unread;
use super::git::{Body, Git, GitError, Kind, MAX_OBJECT_LEN, ObjectReader, RawEntry, Sha};
#[cfg(test)]
use super::redact::render;
use super::redact::{Loc, Part, render_in};
use crate::args::ScanArgs;
use crate::error::CliError;
use crate::terminal::Terminal;
use crate::vault_cmd::{say, warn};

/// Most findings kept for one scan; more is reported as truncated.
const MAX_FINDINGS: usize = 100_000;
/// Most `--ref` names one scan accepts.
const MAX_REFS: usize = 10_000;
/// Longest remote name accepted.
const MAX_REMOTE_LEN: usize = 100;

/// What to scan.
pub(super) enum Source {
    /// The staged changes.
    Staged,
    /// The objects a push of `to` over `from` would publish.
    Range {
        from: Option<Sha>,
        to: Sha,
        remote: Option<String>,
        refs: Vec<String>,
    },
}

/// One part of a source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SourceKind {
    Blobs,
    Paths,
    Commits,
    Tags,
    Refs,
}

/// Which parts of a source are scanned. Production scans all of them; a test drops one to
/// prove that the fixture that finds a value in it really depends on that part.
#[derive(Debug, Clone, Copy)]
pub(super) struct Sources {
    dropped: Option<SourceKind>,
}

impl Sources {
    pub(super) const BLOBS: SourceKind = SourceKind::Blobs;
    pub(super) const PATHS: SourceKind = SourceKind::Paths;
    pub(super) const COMMITS: SourceKind = SourceKind::Commits;
    pub(super) const TAGS: SourceKind = SourceKind::Tags;
    pub(super) const REFS: SourceKind = SourceKind::Refs;
    pub(super) const ALL: Self = Self { dropped: None };

    fn has(self, part: SourceKind) -> bool {
        self.dropped != Some(part)
    }

    /// Every part but `part`.
    #[cfg(test)]
    #[expect(
        clippy::unused_self,
        reason = "read as `Sources::ALL.without(x)` at the call sites; only one part is dropped"
    )]
    pub(super) fn without(self, part: SourceKind) -> Self {
        Self {
            dropped: Some(part),
        }
    }
}

/// Where a finding is, in owned form (rendered only when printed).
#[derive(Debug, Clone, PartialEq, Eq)]
enum Where {
    Index {
        path: Vec<u8>,
        sha: Option<Sha>,
        line: Option<usize>,
    },
    Blob {
        sha: Sha,
        line: Option<usize>,
    },
    BlobPath {
        path: Vec<u8>,
        sha: Sha,
    },
    TreePath {
        path: Vec<u8>,
        sha: Sha,
    },
    Commit(Sha, Part),
    Tag(Sha, Part),
    Ref(usize),
}

#[derive(Debug)]
struct Finding {
    id: EntryId,
    kind: EntryKind,
    at: Where,
}

/// The memory bounds of one scan. Production uses [`Limits::DEFAULT`] only; a test builds a
/// smaller one (a test-only constructor), so there is no way (no variable, no flag) to
/// loosen them for a real scan.
#[derive(Debug, Clone, Copy)]
struct Limits {
    /// Most bytes of raw tree objects held (old ones included).
    tree_bytes: usize,
    /// Most bytes of paths the walk stores (its visited set and the paths of the blobs).
    path_bytes: usize,
}

impl Limits {
    const DEFAULT: Self = Self {
        tree_bytes: walk::MAX_TREE_BYTES,
        path_bytes: walk::MAX_PATH_BYTES,
    };
}

/// Everything one source yielded, before anything is printed.
struct Collected {
    limits: Limits,
    findings: Vec<Finding>,
    problems: Vec<(Where, Unread)>,
    objects: usize,
    truncated: bool,
    /// Bytes of raw tree objects held so far (bounded by `limits.tree_bytes`).
    tree_bytes: usize,
    /// Paths by blob id (range scans), for naming a blob in a report.
    paths: BTreeMap<Sha, Vec<Vec<u8>>>,
}

/// The counts a finished scan reports.
pub(super) struct GitTally {
    pub(super) objects: usize,
    pub(super) hits: usize,
    pub(super) unread: usize,
    pub(super) truncated: bool,
}

impl Default for Collected {
    fn default() -> Self {
        Self {
            limits: Limits::DEFAULT,
            findings: Vec::new(),
            problems: Vec::new(),
            objects: 0,
            truncated: false,
            tree_bytes: 0,
            paths: BTreeMap::new(),
        }
    }
}

impl Collected {
    /// An empty result with smaller bounds (tests of the bounds).
    #[cfg(test)]
    fn with_limits(limits: Limits) -> Self {
        Self {
            limits,
            ..Self::default()
        }
    }

    fn add(&mut self, id: &EntryId, kind: EntryKind, at: Where) {
        if self.findings.len() >= MAX_FINDINGS {
            self.truncated = true;
        } else {
            self.findings.push(Finding {
                id: id.clone(),
                kind,
                at,
            });
        }
    }

    /// Scans `bytes`; each hit becomes a finding at `at(line)`. Returns the ids that hit.
    fn scan_with(
        &mut self,
        matcher: &Matcher,
        bytes: &[u8],
        at: &dyn Fn(Option<usize>) -> Where,
        lines: bool,
    ) -> Vec<EntryId> {
        if let Ok(report) = scan(matcher, bytes) {
            self.truncated |= report.truncated;
            for h in &report.hits {
                self.add(&h.id, h.kind, at(lines.then_some(h.line)));
            }
            report.hits.into_iter().map(|h| h.id).collect()
        } else {
            self.problems.push((at(None), Unread::TooLarge));
            Vec::new()
        }
    }
}

/// Builds the source from the arguments, or `None` when the arguments name paths.
///
/// # Errors
/// A malformed range, remote or ref list, or a revision git cannot resolve.
pub(super) fn source_of(args: &ScanArgs, git: &Git) -> Result<Option<Source>, CliError> {
    if args.staged {
        return Ok(Some(Source::Staged));
    }
    let Some(range) = &args.range else {
        return Ok(None);
    };
    let bad = |why| CliError::Refused(why);
    let (from, to) = range
        .split_once("..")
        .ok_or_else(|| bad("--range must be A..B"))?;
    if to.starts_with('.') || from.ends_with('.') {
        return Err(bad("--range takes two dots, A..B"));
    }
    // An empty or all-zero base is "no base": a new branch.
    let zero = Sha::parse(from.as_bytes()).is_some_and(|s| s.is_zero());
    let from = if from.is_empty() || zero {
        None
    } else {
        Some(git.resolve(from).map_err(git_error)?)
    };
    let to = git.resolve(to).map_err(git_error)?;
    if to.is_zero() {
        return Err(bad("--range must end at an object"));
    }
    if let Some(r) = &args.remote {
        let ok = !r.is_empty()
            && r.len() <= MAX_REMOTE_LEN
            && !r.starts_with('-')
            && r.bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
        if !ok {
            return Err(bad("--remote must be a plain remote name"));
        }
    }
    if args.refs.len() > MAX_REFS {
        return Err(bad("too many --ref names"));
    }
    Ok(Some(Source::Range {
        from,
        to,
        remote: args.remote.clone(),
        refs: args.refs.clone(),
    }))
}

fn git_error(e: GitError) -> CliError {
    CliError::Refused(match e {
        GitError::Spawn => "git could not be started",
        GitError::Failed => "git failed (is this a repository, and do the revisions exist?)",
        GitError::Malformed => "git printed something the scan does not understand",
        GitError::TooLarge => "git output is larger than the scan limit",
        GitError::Io => "reading git output failed",
        GitError::Missing => "an object listed by git is missing; fetch it and retry",
        GitError::TooMany => "too many objects for one scan; scan a smaller range",
        GitError::PathTooLong => "a path in the pushed trees is longer than the scan limit",
        GitError::PartialClone => {
            "this is a partial clone and git is older than 2.44, which cannot stop lazy fetching; upgrade git"
        }
    })
}

/// Scans a source and prints the report. Hits and problems are counted in the result.
///
/// # Errors
/// git could not be used, or the report could not be written.
pub(super) fn run<T: Terminal>(
    matcher: &Matcher,
    git: &Git,
    source: &Source,
    sources: Sources,
    term: &mut T,
) -> Result<GitTally, CliError> {
    git.guard_lazy_fetch().map_err(git_error)?;
    let found = match source {
        Source::Staged => collect_staged(matcher, git, sources),
        Source::Range {
            from,
            to,
            remote,
            refs,
        } => collect_range(
            matcher,
            git,
            (from.as_ref(), to, remote.as_deref()),
            refs,
            sources,
        ),
    }
    .map_err(git_error)?;
    print(matcher, &found, term)
}

fn loc<'a>(at: &'a Where, paths: &'a BTreeMap<Sha, Vec<Vec<u8>>>) -> Loc<'a> {
    match at {
        Where::Index { path, sha, line } => Loc::Index {
            path,
            sha: sha.as_ref().map(Sha::as_str),
            line: *line,
        },
        Where::Blob { sha, line } => Loc::Blob {
            paths: paths.get(sha).map_or(&[], Vec::as_slice),
            sha: sha.as_str(),
            line: *line,
        },
        Where::BlobPath { path, sha } => Loc::Blob {
            paths: std::slice::from_ref(path),
            sha: sha.as_str(),
            line: None,
        },
        Where::TreePath { path, sha } => Loc::Tree {
            path,
            sha: sha.as_str(),
        },
        Where::Commit(sha, part) => Loc::Commit {
            sha: sha.as_str(),
            part: *part,
        },
        Where::Tag(sha, part) => Loc::Tag {
            sha: sha.as_str(),
            part: *part,
        },
        Where::Ref(i) => Loc::Ref(*i),
    }
}

fn print<T: Terminal>(
    matcher: &Matcher,
    found: &Collected,
    term: &mut T,
) -> Result<GitTally, CliError> {
    for f in &found.findings {
        // The kind is part of the checked text: a value cannot be spelled across it and the
        // location.
        let kind = format!("{} ", f.kind);
        let at = render_in(matcher, &loc(&f.at, &found.paths), (&kind, ""));
        if let Some(l) = at.print(&format!("{} {} ", f.id, f.kind), "") {
            say(term, &l)?;
        }
    }
    for (at, why) in &found.problems {
        let post = format!(" {why}");
        let at = render_in(matcher, &loc(at, &found.paths), ("error: ", &post));
        if let Some(l) = at.print("error: ", &post) {
            warn(term, &l)?;
        }
    }
    Ok(GitTally {
        objects: found.objects,
        hits: found.findings.len(),
        unread: found.problems.len(),
        truncated: found.truncated,
    })
}

/// What reading one blob gave.
enum BlobScan {
    Hits(Vec<(EntryId, EntryKind, Option<usize>)>, bool),
    Unread(Unread),
}

/// Reads and scans one blob's content. Text is scanned line by line; a blob with a NUL in its
/// first 8 KiB is binary and is matched on its raw bytes.
fn scan_blob(matcher: &Matcher, size: u64, body: &mut Body<'_>) -> BlobScan {
    if usize::try_from(size).map_or(true, |n| n > MAX_OBJECT_LEN) {
        return BlobScan::Unread(Unread::TooLarge);
    }
    let mut bytes = Vec::new();
    if body.read_to_end(&mut bytes).is_err() {
        return BlobScan::Unread(Unread::Io(std::io::ErrorKind::UnexpectedEof));
    }
    let (text, lines) = match classify(&bytes) {
        Content::Text(t) => (t, true),
        // Binary, or a kind of content added later: matched on the raw bytes.
        _ => (std::borrow::Cow::Borrowed(bytes.as_slice()), false),
    };
    match scan(matcher, &text) {
        Ok(r) => BlobScan::Hits(
            r.hits
                .into_iter()
                .map(|h| (h.id, h.kind, lines.then_some(h.line)))
                .collect(),
            r.truncated,
        ),
        Err(_) => BlobScan::Unread(Unread::TooLarge),
    }
}

/// Reads `shas` (blobs) and scans each once.
fn scan_blobs(
    matcher: &Matcher,
    git: &Git,
    shas: &[Sha],
) -> Result<HashMap<Sha, BlobScan>, GitError> {
    let mut out = HashMap::new();
    git.objects(shas, |sha, kind, size, body| {
        if kind == Kind::Blob {
            out.insert(sha.clone(), scan_blob(matcher, size, body));
        }
        Ok(())
    })?;
    Ok(out)
}

fn collect_staged(matcher: &Matcher, git: &Git, sources: Sources) -> Result<Collected, GitError> {
    let entries = git.staged()?;
    let mut found = Collected::default();
    if sources.has(Sources::PATHS) {
        for e in &entries {
            let at = |_| Where::Index {
                path: e.path.clone(),
                sha: e.any_sha().cloned(),
                line: None,
            };
            found.scan_with(matcher, &e.path, &at, false);
        }
    }
    let mut blobs: Vec<Sha> = entries.iter().filter_map(RawEntry::blob).cloned().collect();
    blobs.sort();
    blobs.dedup();
    if sources.has(Sources::BLOBS) {
        let scanned = scan_blobs(matcher, git, &blobs)?;
        found.objects = scanned.len();
        for e in &entries {
            let Some(sha) = e.blob() else { continue };
            let at = |line| Where::Index {
                path: e.path.clone(),
                sha: Some(sha.clone()),
                line,
            };
            match scanned.get(sha) {
                Some(BlobScan::Hits(hits, truncated)) => {
                    found.truncated |= *truncated;
                    for (id, kind, line) in hits {
                        found.add(id, *kind, at(*line));
                    }
                }
                Some(BlobScan::Unread(why)) => found.problems.push((at(None), *why)),
                None => return Err(GitError::Missing),
            }
        }
    }
    Ok(found)
}

fn collect_range(
    matcher: &Matcher,
    git: &Git,
    range: (Option<&Sha>, &Sha, Option<&str>),
    refs: &[String],
    sources: Sources,
) -> Result<Collected, GitError> {
    collect_range_in(matcher, git, range, refs, sources, Collected::default())
}

/// [`collect_range`] into `found`, which carries the bounds (a test passes smaller ones).
fn collect_range_in(
    matcher: &Matcher,
    git: &Git,
    (from, to, remote): (Option<&Sha>, &Sha, Option<&str>),
    refs: &[String],
    sources: Sources,
    mut found: Collected,
) -> Result<Collected, GitError> {
    let objects = git.new_objects(from, to, remote)?;
    // The new trees (parsed), and where a walk of them starts: the root tree of every new
    // commit and every tree a tag or the end of the range points at directly.
    let mut trees: HashMap<Sha, Entries> = HashMap::new();
    let mut roots: BTreeSet<Sha> = BTreeSet::new();
    git.objects(&objects, |sha, kind, size, body| {
        found.objects = found.objects.saturating_add(1);
        match kind {
            Kind::Commit | Kind::Tag => {
                let Ok(raw) = read_object(size, body) else {
                    found.problems.push((
                        if kind == Kind::Tag {
                            Where::Tag(sha.clone(), Part::Header)
                        } else {
                            Where::Commit(sha.clone(), Part::Header)
                        },
                        Unread::TooLarge,
                    ));
                    return Ok(());
                };
                let target = if kind == Kind::Commit {
                    header_sha(&raw, b"tree ")
                } else {
                    tagged_tree(&raw)
                };
                roots.extend(target);
                let wanted = if kind == Kind::Commit {
                    Sources::COMMITS
                } else {
                    Sources::TAGS
                };
                if sources.has(wanted) {
                    scan_object_parts(matcher, &mut found, (sha, kind), &raw);
                }
            }
            Kind::Blob if sources.has(Sources::BLOBS) => match scan_blob(matcher, size, body) {
                BlobScan::Hits(hits, truncated) => {
                    found.truncated |= truncated;
                    for (id, k, line) in hits {
                        found.add(
                            &id,
                            k,
                            Where::Blob {
                                sha: sha.clone(),
                                line,
                            },
                        );
                    }
                }
                BlobScan::Unread(why) => found.problems.push((
                    Where::Blob {
                        sha: sha.clone(),
                        line: None,
                    },
                    why,
                )),
            },
            Kind::Tree if sources.has(Sources::PATHS) => {
                if sha == to {
                    roots.insert(sha.clone());
                }
                // An unreadable new tree is a problem already; it stays in the map as an empty
                // directory so the walk does not read it (and report it) a second time.
                let entries = take_tree(&mut found, Kind::Tree, sha, size, body)?;
                trees.insert(
                    sha.clone(),
                    entries.unwrap_or_else(|| Entries::from(Vec::new())),
                );
            }
            _ => {}
        }
        Ok(())
    })?;
    if sources.has(Sources::PATHS) {
        // `diff-tree -r` lists files only and never runs for a tree a tag or the end of the
        // range leads to, and a name alone cannot spell a value with a `/`: the full path of
        // every entry of every new tree is scanned instead (see `walk`).
        walk_new_trees(matcher, git, &mut found, &mut trees, &roots)?;
    }
    if sources.has(Sources::REFS) {
        for (i, name) in refs.iter().enumerate() {
            found.scan_with(matcher, name.as_bytes(), &|_| Where::Ref(i), false);
        }
    }
    Ok(found)
}

/// Walks from `roots`. Old subtrees below a new root are fetched on demand (a new path can sit
/// on an old tree), with the same bounds, through one `cat-file` process started on first use.
fn walk_new_trees(
    matcher: &Matcher,
    git: &Git,
    found: &mut Collected,
    trees: &mut HashMap<Sha, Entries>,
    roots: &BTreeSet<Sha>,
) -> Result<(), GitError> {
    let mut reader: Option<ObjectReader> = None;
    let mut load = |sha: &Sha, found: &mut Collected| -> Result<Option<Entries>, GitError> {
        if reader.is_none() {
            reader = Some(git.object_reader()?);
        }
        let Some(r) = reader.as_mut() else {
            return Err(GitError::Spawn);
        };
        let mut loaded = None;
        r.read(sha, |sha, kind, size, body| {
            loaded = take_tree(found, kind, sha, size, body)?;
            Ok(())
        })?;
        Ok(loaded)
    };
    walk::walk_with(matcher, found, trees, roots.iter(), &mut load, true)
}

/// Parses a tree read from git. A tree that cannot be read or parsed is a problem (reported
/// once, at the tree) and gives `None`, not an error; too many tree bytes held for one scan
/// (old trees included) is an error.
fn take_tree(
    found: &mut Collected,
    kind: Kind,
    sha: &Sha,
    size: u64,
    body: &mut Body<'_>,
) -> Result<Option<Entries>, GitError> {
    let at = Where::TreePath {
        path: Vec::new(),
        sha: sha.clone(),
    };
    if kind != Kind::Tree {
        found.problems.push((at, Unread::Malformed));
        return Ok(None);
    }
    match read_object(size, body) {
        Err(why) => found.problems.push((at, why)),
        Ok(raw) => {
            found.tree_bytes = found.tree_bytes.saturating_add(raw.len());
            if found.tree_bytes > found.limits.tree_bytes {
                return Err(GitError::TooLarge);
            }
            match tree_entries(&raw, sha.as_str().len() / 2) {
                Some(entries) => return Ok(Some(Entries::from(entries))),
                None => found.problems.push((at, Unread::Malformed)),
            }
        }
    }
    Ok(None)
}

/// Reads a whole object, or says why it was not read.
fn read_object(size: u64, body: &mut Body<'_>) -> Result<Vec<u8>, Unread> {
    if usize::try_from(size).map_or(true, |n| n > MAX_OBJECT_LEN) {
        return Err(Unread::TooLarge);
    }
    let mut raw = Vec::new();
    body.read_to_end(&mut raw)
        .map_err(|_| Unread::Io(std::io::ErrorKind::UnexpectedEof))?;
    Ok(raw)
}

/// The id after `key` in the first header line that starts with it (headers end at the first
/// empty line).
fn header_sha(raw: &[u8], key: &[u8]) -> Option<Sha> {
    raw.split(|&b| b == b'\n')
        .take_while(|l| !l.is_empty())
        .find_map(|l| l.strip_prefix(key))
        .and_then(Sha::parse)
}

/// The tree an annotated tag points at directly (`type tree`), if it does.
fn tagged_tree(raw: &[u8]) -> Option<Sha> {
    let direct = raw
        .split(|&b| b == b'\n')
        .take_while(|l| !l.is_empty())
        .any(|l| l == b"type tree");
    direct.then(|| header_sha(raw, b"object ")).flatten()
}

/// Scans a commit or tag object part by part and records each hit in the part it is in. The
/// parts are the headers (a header with continuation lines, such as `mergetag`, is one) and the
/// message.
fn scan_object_parts(
    matcher: &Matcher,
    found: &mut Collected,
    (sha, kind): (&Sha, Kind),
    raw: &[u8],
) {
    let at = |part| match kind {
        Kind::Tag => Where::Tag(sha.clone(), part),
        _ => Where::Commit(sha.clone(), part),
    };
    for (part, bytes) in split_object(raw, kind) {
        found.scan_with(matcher, &bytes, &|_| at(part), false);
    }
}

/// Splits a raw commit or tag into its parts: one per header (continuation lines, which start
/// with a space, belong to the header above) and the message after the first empty line.
pub(super) fn split_object(raw: &[u8], kind: Kind) -> Vec<(Part, Vec<u8>)> {
    let (head, message) = match raw.windows(2).position(|w| w == b"\n\n") {
        Some(i) => (
            raw.get(..i).unwrap_or_default(),
            raw.get(i.saturating_add(2)..),
        ),
        None => (raw, None),
    };
    let mut parts: Vec<(Part, Vec<u8>)> = Vec::new();
    for line in head.split(|&b| b == b'\n') {
        if let (Some(b' '), Some((_, last))) = (line.first().copied(), parts.last_mut()) {
            last.push(b'\n');
            last.extend_from_slice(line);
            continue;
        }
        let name = line.split(|&b| b == b' ').next().unwrap_or_default();
        let part = match (kind, name) {
            (Kind::Commit, b"author") => Part::Author,
            (Kind::Commit, b"committer") => Part::Committer,
            (Kind::Tag, b"tagger") => Part::Tagger,
            _ => Part::Header,
        };
        parts.push((part, line.to_vec()));
    }
    if let Some(m) = message {
        parts.push((Part::Message, m.to_vec()));
    }
    parts
}

mod walk;

#[cfg(test)]
mod tests;
