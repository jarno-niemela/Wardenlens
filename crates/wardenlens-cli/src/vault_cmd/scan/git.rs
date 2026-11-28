//! Running git as a subprocess and parsing what it prints (ADR 0006 section 9).
//!
//! Git output is untrusted bytes: a path can hold any byte but NUL, a commit message any byte at
//! all. So every listing is NUL separated (`-z`) or fixed width, nothing is sliced by position,
//! every read is bounded, and anything unexpected is an error (a scan that cannot tell what it
//! read has not passed). The arguments are an explicit vector, never a shell string (SEC-5),
//! and nothing here writes to the repository: plumbing commands only, no optional locks, no
//! hooks, standard error discarded (a git message can quote a path).

use std::ffi::OsStr;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use wardenlens_vault::MAX_FILE_LEN;

/// Most bytes of listing output one git command may produce (64 MiB).
pub(super) const MAX_OUTPUT: usize = 64 * 1024 * 1024;
/// Most objects, commits or index entries one scan handles.
pub(super) const MAX_OBJECTS: usize = 100_000;
/// Longest header line of `cat-file --batch` that is accepted (`sha type size`).
const MAX_HEADER: u64 = 256;
/// Largest object (commit, tag, blob) whose content is read; the same 8 MiB as a file.
pub(super) const MAX_OBJECT_LEN: usize = MAX_FILE_LEN;

/// Why git could not be used. The text never holds a path, a ref or a value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(super) enum GitError {
    #[error("git could not be started")]
    Spawn,
    #[error("git failed")]
    Failed,
    #[error("git output is not in the expected form")]
    Malformed,
    #[error("git output is larger than the scan limit")]
    TooLarge,
    #[error("reading git output failed")]
    Io,
    #[error("an object listed by git is missing")]
    Missing,
    #[error("too many objects for one scan")]
    TooMany,
    #[error("a path is longer than the scan limit")]
    PathTooLong,
    #[error("a partial clone is scanned with a git that cannot stop lazy fetching")]
    PartialClone,
    #[error("the stored paths are larger than the scan limit")]
    PathBytes,
}

/// An object id: 40 (SHA-1) or 64 (SHA-256) lowercase hex digits.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(super) struct Sha(String);

impl Sha {
    pub(super) fn parse(bytes: &[u8]) -> Option<Self> {
        let ok = matches!(bytes.len(), 40 | 64)
            && bytes.iter().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
        if !ok {
            return None;
        }
        String::from_utf8(bytes.to_vec()).ok().map(Self)
    }

    pub(super) fn as_str(&self) -> &str {
        &self.0
    }

    /// True for the all-zero id git uses for "no object".
    pub(super) fn is_zero(&self) -> bool {
        self.0.bytes().all(|b| b == b'0')
    }
}

/// The kind of an object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Kind {
    Commit,
    Tag,
    Blob,
    Tree,
}

/// One entry of a raw diff (`:old-mode new-mode old-sha new-sha status NUL path NUL`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct RawEntry {
    pub(super) new_mode: String,
    pub(super) old: Sha,
    pub(super) new: Sha,
    pub(super) status: u8,
    pub(super) path: Vec<u8>,
}

impl RawEntry {
    /// A submodule: its id names a commit of another repository.
    pub(super) fn is_gitlink(&self) -> bool {
        self.new_mode == "160000"
    }

    /// The blob that holds this entry's content now, if it has one.
    pub(super) fn blob(&self) -> Option<&Sha> {
        (!self.new.is_zero() && !self.is_gitlink() && self.status != b'D' && self.status != b'U')
            .then_some(&self.new)
    }

    /// Some blob to name in a report: the new one, else the old one.
    pub(super) fn any_sha(&self) -> Option<&Sha> {
        [&self.new, &self.old].into_iter().find(|s| !s.is_zero())
    }
}

/// The first git that honours `GIT_NO_LAZY_FETCH` (2.44). An older git ignores the variable, so
/// in a partial clone it could fetch a missing object over the network and write packs during a
/// scan; the scan refuses that combination instead ([`Git::guard_lazy_fetch_from`]).
pub(super) const LAZY_FETCH_MIN: (u32, u32) = (2, 44);

/// `(major, minor)` from the output of `git version` (`git version 2.53.0`, or with a vendor
/// suffix); `None` when it is not in that form.
pub(super) fn parse_version(out: &[u8]) -> Option<(u32, u32)> {
    let text = std::str::from_utf8(out).ok()?;
    let rest = text.trim_end().strip_prefix("git version ")?;
    let mut nums = rest.split(|c: char| !c.is_ascii_digit());
    let major = nums.next()?.parse().ok()?;
    let minor = nums.next()?.parse().ok()?;
    Some((major, minor))
}

/// The git binary to run.
pub(super) struct Git {
    exe: PathBuf,
    /// Run in this directory (tests); the process's current directory otherwise.
    dir: Option<PathBuf>,
}

/// Fixed places git is looked for before the search path is used.
const GIT_CANDIDATES: [&str; 4] = [
    "/usr/bin/git",
    "/usr/local/bin/git",
    "/bin/git",
    "/opt/homebrew/bin/git",
];

impl Git {
    /// A fixed, `PATH`-independent location if git is installed at one, else `git` from `PATH`.
    pub(super) fn locate() -> Self {
        let exe = GIT_CANDIDATES
            .iter()
            .map(Path::new)
            .find(|p| p.is_file())
            .map_or_else(|| PathBuf::from("git"), Path::to_owned);
        Self { exe, dir: None }
    }

    /// The same git, run in `dir`.
    #[cfg(test)]
    pub(super) fn at(dir: &Path) -> Self {
        Self {
            dir: Some(dir.to_owned()),
            ..Self::locate()
        }
    }

    /// The binary this runs (tests wrap it).
    #[cfg(test)]
    pub(super) fn exe_for_test(&self) -> &Path {
        &self.exe
    }

    /// A git at `exe` run in `dir` (tests with a wrapper that logs or fakes its version).
    #[cfg(test)]
    pub(super) fn with_exe(exe: &Path, dir: &Path) -> Self {
        Self {
            exe: exe.to_owned(),
            dir: Some(dir.to_owned()),
        }
    }

    /// Spawns `cmd`. In tests the spawn is held under `crate::vault_cmd::spawning`.
    fn spawn(cmd: &mut Command) -> Result<Child, GitError> {
        #[cfg(test)]
        let _guard = crate::vault_cmd::spawning();
        cmd.spawn().map_err(|_| GitError::Spawn)
    }

    fn command(&self, args: &[&OsStr]) -> Command {
        let mut c = Command::new(&self.exe);
        if let Some(d) = &self.dir {
            c.arg("-C").arg(d);
        }
        c.arg("--no-replace-objects")
            .arg("--no-optional-locks")
            .args(["-c", "core.quotePath=false", "-c", "core.fsmonitor=false"])
            .args(args)
            .env("GIT_OPTIONAL_LOCKS", "0")
            // A partial clone must never fetch over the network or write packs during a scan:
            // a missing object stays missing and fails the scan closed.
            .env("GIT_NO_LAZY_FETCH", "1")
            .env_remove("GIT_EXTERNAL_DIFF")
            // `git push` sends the real objects and ignores replace refs, grafts and a
            // shallow-file override, so the scan must read the same objects (P10: this is the
            // one place every git call goes through).
            .env("GIT_NO_REPLACE_OBJECTS", "1")
            .env_remove("GIT_REPLACE_REF_BASE")
            .env("GIT_GRAFT_FILE", "/dev/null")
            .env_remove("GIT_SHALLOW_FILE")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        #[cfg(test)]
        c.env_remove("GIT_DIR")
            .env_remove("GIT_WORK_TREE")
            .env_remove("GIT_INDEX_FILE")
            .env_remove("GIT_CONFIG_PARAMETERS")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1");
        c
    }

    /// Runs git and returns its standard output, at most `limit` bytes; `stdin` is fed from a
    /// second thread so a large input cannot deadlock against the output.
    fn capture(&self, args: &[&OsStr], stdin: &[u8], limit: usize) -> Result<Vec<u8>, GitError> {
        let mut child = Self::spawn(&mut self.command(args))?;
        let (Some(mut input), Some(output)) = (child.stdin.take(), child.stdout.take()) else {
            kill(&mut child);
            return Err(GitError::Spawn);
        };
        let mut out = Vec::new();
        let read = std::thread::scope(|s| {
            let writer = s.spawn(move || input.write_all(stdin));
            let cap = u64::try_from(limit).unwrap_or(u64::MAX).saturating_add(1);
            let r = output.take(cap).read_to_end(&mut out);
            if out.len() > limit {
                // The writer may be blocked on a child that is no longer read: end the child.
                kill(&mut child);
            }
            let written = writer.join().map_err(|_| GitError::Io);
            (r, written)
        });
        let status = child.wait().map_err(|_| GitError::Io)?;
        if out.len() > limit {
            return Err(GitError::TooLarge);
        }
        read.0.map_err(|_| GitError::Io)?;
        if !status.success() {
            return Err(GitError::Failed);
        }
        // A write error with a successful, complete run cannot be told from a lost input.
        read.1?.map_err(|_| GitError::Io)?;
        Ok(out)
    }

    /// Refuses to go on when git is older than 2.44 (or its version is not understood) and the
    /// repository is a partial clone: only a git that honours `GIT_NO_LAZY_FETCH` is trusted not
    /// to fetch or write during a scan. A full repository is fine with any git.
    #[cfg(test)]
    pub(super) fn guard_lazy_fetch(&self) -> Result<(), GitError> {
        self.guard_lazy_fetch_from(LAZY_FETCH_MIN)
    }

    pub(super) fn guard_lazy_fetch_from(&self, min: (u32, u32)) -> Result<(), GitError> {
        let out = self.capture(&args(&["version"]), b"", 1024)?;
        if parse_version(&out).is_some_and(|v| v >= min) {
            return Ok(());
        }
        let partial = [
            &["config", "--get", "extensions.partialclone"][..],
            &["config", "--get-regexp", r"^remote\..*\.promisor$"][..],
        ];
        for a in partial {
            match self.capture(&args(a), b"", 1024) {
                // The key is set.
                Ok(_) => return Err(GitError::PartialClone),
                // `config` exits 1 when no key matches.
                Err(GitError::Failed) => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    /// `git rev-parse --verify` of a revision to an object id.
    pub(super) fn resolve(&self, rev: &str) -> Result<Sha, GitError> {
        if rev.is_empty() || rev.starts_with('-') {
            return Err(GitError::Malformed);
        }
        let spec = format!("{rev}^{{object}}");
        let out = self.capture(
            &args(&[
                "rev-parse",
                "--verify",
                "--quiet",
                "--end-of-options",
                &spec,
            ]),
            b"",
            1024,
        )?;
        let line = out.strip_suffix(b"\n").ok_or(GitError::Malformed)?;
        Sha::parse(line).ok_or(GitError::Malformed)
    }

    /// The empty tree of this repository's hash algorithm (nothing is written).
    fn empty_tree(&self) -> Result<Sha, GitError> {
        let out = self.capture(&args(&["hash-object", "-t", "tree", "--stdin"]), b"", 1024)?;
        let line = out.strip_suffix(b"\n").ok_or(GitError::Malformed)?;
        Sha::parse(line).ok_or(GitError::Malformed)
    }

    /// The staged changes as raw diff entries (against `HEAD`, or the empty tree when there is
    /// no commit yet). Plumbing (`diff-index`), which no porcelain configuration such as
    /// `diff.relative` can change.
    pub(super) fn staged(&self) -> Result<Vec<RawEntry>, GitError> {
        let base = match self.resolve("HEAD") {
            Ok(sha) => sha,
            // No commit yet (or an unborn HEAD): everything staged is new.
            Err(GitError::Failed) => self.empty_tree()?,
            Err(e) => return Err(e),
        };
        let out = self.capture(
            &args(&[
                "diff-index",
                "--cached",
                "--raw",
                "-z",
                "--no-renames",
                "--no-abbrev",
                base.as_str(),
            ]),
            b"",
            MAX_OUTPUT,
        )?;
        parse_raw(&out)
    }

    /// The ids of every object that pushing `to` would publish: those reachable from `to` and
    /// neither from `from` nor from a tracking ref of `remote`.
    pub(super) fn new_objects(
        &self,
        from: Option<&Sha>,
        to: &Sha,
        remote: Option<&str>,
    ) -> Result<Vec<Sha>, GitError> {
        let mut a = args(&["rev-list", "--objects", "--no-object-names"]);
        // `--not --remotes=R --not`: the remote's tracking refs are excluded, then the
        // meaning of the revisions is the usual one again. Options come before
        // `--end-of-options`; the ids after it are validated hex, never text.
        let pattern = remote.map(|r| format!("--remotes={r}"));
        if let Some(p) = &pattern {
            a.extend([OsStr::new("--not"), OsStr::new(p), OsStr::new("--not")]);
        }
        a.push(OsStr::new("--end-of-options"));
        a.push(OsStr::new(to.as_str()));
        let exclude = from.map(|f| format!("^{}", f.as_str()));
        if let Some(e) = &exclude {
            a.push(OsStr::new(e));
        }
        parse_shas(&self.capture(&a, b"", MAX_OUTPUT)?)
    }

    /// Starts a `cat-file --batch` process that answers one request at a time.
    pub(super) fn object_reader(&self) -> Result<ObjectReader, GitError> {
        let mut child = Self::spawn(&mut self.command(&args(&["cat-file", "--batch"])))?;
        let (Some(input), Some(output)) = (child.stdin.take(), child.stdout.take()) else {
            kill(&mut child);
            let _ = child.wait();
            return Err(GitError::Spawn);
        };
        Ok(ObjectReader {
            child,
            input,
            output: BufReader::new(output),
        })
    }

    /// Reads objects with `cat-file --batch`, in order. `each` gets the kind, the size and a
    /// reader limited to the object; what it leaves unread is skipped.
    pub(super) fn objects<F>(&self, shas: &[Sha], mut each: F) -> Result<(), GitError>
    where
        F: FnMut(&Sha, Kind, u64, &mut Body<'_>) -> Result<(), GitError>,
    {
        if shas.is_empty() {
            return Ok(());
        }
        let mut child = Self::spawn(&mut self.command(&args(&["cat-file", "--batch"])))?;
        let (Some(mut input), Some(output)) = (child.stdin.take(), child.stdout.take()) else {
            kill(&mut child);
            return Err(GitError::Spawn);
        };
        let lines = sha_lines(shas);
        let result = std::thread::scope(|s| {
            let writer = s.spawn(move || input.write_all(&lines));
            let mut reader = BufReader::new(output);
            let r = read_batch(&mut reader, shas, &mut each);
            // Whatever happened, the child must end so the writer cannot stay blocked.
            drop(reader);
            kill(&mut child);
            // The writer fails with a broken pipe after a kill; only its panic matters.
            let _ = writer.join().map_err(|_| GitError::Io)?;
            r
        });
        // The child was killed or has finished; either way only the scan result matters.
        let _ = child.wait();
        result
    }
}

fn args<'a>(a: &[&'a str]) -> Vec<&'a OsStr> {
    a.iter().map(|s| OsStr::new(*s)).collect()
}

/// Ends a child; failing to is not an error (it may have exited).
fn kill(child: &mut Child) {
    let _ = child.kill();
}

fn sha_lines(shas: &[Sha]) -> Vec<u8> {
    let mut v = Vec::with_capacity(shas.len().saturating_mul(65));
    for s in shas {
        v.extend_from_slice(s.as_str().as_bytes());
        v.push(b'\n');
    }
    v
}

/// The reader of one object's content.
pub(super) type Body<'a> = io::Take<&'a mut BufReader<ChildStdout>>;

fn read_batch<F>(
    reader: &mut BufReader<ChildStdout>,
    shas: &[Sha],
    each: &mut F,
) -> Result<(), GitError>
where
    F: FnMut(&Sha, Kind, u64, &mut Body<'_>) -> Result<(), GitError>,
{
    for sha in shas {
        read_one(reader, sha, each)?;
    }
    Ok(())
}

/// Reads the answer for one requested object from a `cat-file --batch` stream.
fn read_one<F>(reader: &mut BufReader<ChildStdout>, sha: &Sha, each: &mut F) -> Result<(), GitError>
where
    F: FnMut(&Sha, Kind, u64, &mut Body<'_>) -> Result<(), GitError>,
{
    let mut header = Vec::new();
    reader
        .by_ref()
        .take(MAX_HEADER)
        .read_until(b'\n', &mut header)
        .map_err(|_| GitError::Io)?;
    let line = header.strip_suffix(b"\n").ok_or(GitError::Malformed)?;
    let (kind, size) = parse_header(line, sha)?;
    let mut body = reader.by_ref().take(size);
    let outcome = each(sha, kind, size, &mut body);
    // Skip what the callback did not read, then the newline git writes after the body.
    let left = body.limit();
    let skipped = io::copy(&mut body, &mut io::sink()).map_err(|_| GitError::Io)?;
    outcome?;
    if skipped != left {
        return Err(GitError::Malformed);
    }
    let mut nl = [0u8; 1];
    reader.read_exact(&mut nl).map_err(|_| GitError::Io)?;
    if nl != *b"\n" {
        return Err(GitError::Malformed);
    }
    Ok(())
}

/// A `cat-file --batch` process asked for one object at a time (old trees, on demand). One
/// request line is written and its whole answer read before the next, so neither pipe can fill
/// and block the other. The child is killed when the reader is dropped.
pub(super) struct ObjectReader {
    child: Child,
    input: ChildStdin,
    output: BufReader<ChildStdout>,
}

impl ObjectReader {
    /// Asks for `sha`; `each` is called as for [`Git::objects`].
    pub(super) fn read<F>(&mut self, sha: &Sha, mut each: F) -> Result<(), GitError>
    where
        F: FnMut(&Sha, Kind, u64, &mut Body<'_>) -> Result<(), GitError>,
    {
        let mut line = sha.as_str().as_bytes().to_vec();
        line.push(b'\n');
        self.input.write_all(&line).map_err(|_| GitError::Io)?;
        self.input.flush().map_err(|_| GitError::Io)?;
        read_one(&mut self.output, sha, &mut each)
    }
}

impl Drop for ObjectReader {
    fn drop(&mut self) {
        kill(&mut self.child);
        let _ = self.child.wait();
    }
}

/// `<sha> <type> <size>`; the id must be the one asked for (a desynchronised stream is never
/// trusted).
fn parse_header(line: &[u8], want: &Sha) -> Result<(Kind, u64), GitError> {
    let mut fields = line.split(|&b| b == b' ');
    let (Some(sha), Some(kind)) = (fields.next(), fields.next()) else {
        return Err(GitError::Malformed);
    };
    if sha != want.as_str().as_bytes() {
        return Err(GitError::Malformed);
    }
    if kind == b"missing" {
        return Err(GitError::Missing);
    }
    let kind = match kind {
        b"commit" => Kind::Commit,
        b"tag" => Kind::Tag,
        b"blob" => Kind::Blob,
        b"tree" => Kind::Tree,
        _ => return Err(GitError::Malformed),
    };
    let size = fields
        .next()
        .and_then(|s| std::str::from_utf8(s).ok())
        .and_then(|s| s.parse::<u64>().ok())
        .ok_or(GitError::Malformed)?;
    if fields.next().is_some() {
        return Err(GitError::Malformed);
    }
    Ok((kind, size))
}

/// Newline-separated object ids, as `rev-list --no-object-names` prints them.
pub(super) fn parse_shas(out: &[u8]) -> Result<Vec<Sha>, GitError> {
    let mut shas = Vec::new();
    for line in out
        .strip_suffix(b"\n")
        .unwrap_or(out)
        .split(|&b| b == b'\n')
    {
        if line.is_empty() && out.is_empty() {
            break;
        }
        if shas.len() >= MAX_OBJECTS {
            return Err(GitError::TooMany);
        }
        shas.push(Sha::parse(line).ok_or(GitError::Malformed)?);
    }
    Ok(shas)
}

/// NUL-separated raw diff entries. Fields alternate strictly: a metadata field that starts with
/// `:`, then one path. (A path that starts with `:` is a path, because of its position.)
pub(super) fn parse_raw(out: &[u8]) -> Result<Vec<RawEntry>, GitError> {
    let mut fields = out.split(|&b| b == 0);
    let mut entries = Vec::new();
    while let Some(meta) = fields.next() {
        if meta.is_empty() && fields.clone().next().is_none() {
            // The empty field after the final NUL.
            break;
        }
        if entries.len() >= MAX_OBJECTS {
            return Err(GitError::TooMany);
        }
        // Git has no empty path: an empty one means the output was cut after the metadata.
        let path = fields
            .next()
            .filter(|p| !p.is_empty())
            .ok_or(GitError::Malformed)?;
        let meta = meta.strip_prefix(b":").ok_or(GitError::Malformed)?;
        let mut parts = meta.split(|&b| b == b' ');
        let (Some(_), Some(new_mode), Some(old), Some(new), Some(status), None) = (
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
        ) else {
            return Err(GitError::Malformed);
        };
        entries.push(RawEntry {
            new_mode: String::from_utf8(new_mode.to_vec()).map_err(|_| GitError::Malformed)?,
            old: Sha::parse(old).ok_or(GitError::Malformed)?,
            new: Sha::parse(new).ok_or(GitError::Malformed)?,
            status: *status.first().ok_or(GitError::Malformed)?,
            path: path.to_vec(),
        });
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    const A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const Z: &str = "0000000000000000000000000000000000000000";

    fn raw(mode: &str, old: &str, new: &str, status: &str, path: &[u8]) -> Vec<u8> {
        let mut v = format!(":100644 {mode} {old} {new} {status}\0").into_bytes();
        v.extend_from_slice(path);
        v.push(0);
        v
    }

    #[test]
    fn git_commands_never_lazy_fetch_and_never_follow_replace_refs() {
        let git = Git::locate();
        let c = git.command(&[]);
        let env = |k: &str| {
            c.get_envs()
                .find(|(n, _)| *n == OsStr::new(k))
                .and_then(|(_, v)| v)
                .map(OsStr::to_owned)
        };
        assert_eq!(env("GIT_NO_LAZY_FETCH"), Some("1".into()));
        assert_eq!(env("GIT_NO_REPLACE_OBJECTS"), Some("1".into()));
        // Grafts are ignored by `git push`, so the scan must not read them either (the
        // end-to-end proof is `a_graft_does_not_hide_content_from_the_scan`).
        assert_eq!(env("GIT_GRAFT_FILE"), Some("/dev/null".into()));
    }

    #[test]
    fn git_versions_are_read_as_major_and_minor() {
        for (text, want) in [
            ("git version 2.53.0\n", Some((2, 53))),
            ("git version 2.39.5 (Apple Git-154)\n", Some((2, 39))),
            ("git version 2.44.0.windows.1", Some((2, 44))),
            ("git version 10.0", Some((10, 0))),
            ("git version 2", None),
            ("git version x.y", None),
            ("hg version 2.53.0", None),
            ("", None),
        ] {
            assert_eq!(parse_version(text.as_bytes()), want, "{text:?}");
        }
        assert!(parse_version(b"\xff\xfe").is_none());
    }

    #[test]
    fn an_old_git_refuses_a_partial_clone_and_only_that() {
        let dir = tempfile::tempdir().unwrap();
        let run = |args: &[&str]| {
            let ok = Command::new("git")
                .arg("-C")
                .arg(dir.path())
                .args(args)
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .status()
                .unwrap()
                .success();
            assert!(ok, "git {args:?}");
        };
        run(&["init", "-q"]);
        let git = Git::at(dir.path());
        // A full repository is fine whatever the version, and so is a new enough git.
        assert_eq!(git.guard_lazy_fetch_from((99, 0)), Ok(()));
        run(&["config", "extensions.partialclone", "origin"]);
        assert_eq!(git.guard_lazy_fetch_from((0, 0)), Ok(()));
        let host = Command::new("git").arg("version").output().unwrap();
        if parse_version(&host.stdout).is_some_and(|v| v >= LAZY_FETCH_MIN) {
            assert_eq!(git.guard_lazy_fetch(), Ok(()), "this git is new enough");
        }
        // An old git in a partial clone (either marker) is refused.
        assert_eq!(
            git.guard_lazy_fetch_from((99, 0)),
            Err(GitError::PartialClone)
        );
        run(&["config", "--unset", "extensions.partialclone"]);
        assert_eq!(git.guard_lazy_fetch_from((99, 0)), Ok(()));
        run(&["config", "remote.origin.promisor", "true"]);
        assert_eq!(
            git.guard_lazy_fetch_from((99, 0)),
            Err(GitError::PartialClone)
        );
    }

    #[test]
    fn raw_entries_are_paired_by_position_and_paths_keep_every_byte() {
        let mut out = raw("100644", Z, A, "A", b"a\nb :100644 x\xff");
        out.extend(raw("100644", A, A, "M", b":looks like metadata"));
        let e = parse_raw(&out).unwrap();
        assert_eq!(e.len(), 2);
        assert_eq!(e[0].path, b"a\nb :100644 x\xff");
        assert_eq!(e[1].path, b":looks like metadata");
        assert_eq!(e[0].blob().map(Sha::as_str), Some(A));
    }

    #[test]
    fn malformed_raw_output_is_an_error_not_a_guess() {
        let good = raw("100644", Z, A, "A", b"p");
        // Truncated: metadata without its path.
        let cut = good
            .get(..good.iter().position(|&b| b == 0).unwrap() + 1)
            .unwrap();
        assert_eq!(parse_raw(cut), Err(GitError::Malformed));
        // No leading colon, a short id, extra fields.
        assert_eq!(
            parse_raw(b"100644 100644 a a A\0p\0"),
            Err(GitError::Malformed)
        );
        assert_eq!(
            parse_raw(b":100644 100644 abc abc A\0p\0"),
            Err(GitError::Malformed)
        );
        let long = format!(":100644 100644 {A} {A} A extra\0p\0");
        assert_eq!(parse_raw(long.as_bytes()), Err(GitError::Malformed));
        assert_eq!(parse_raw(b""), Ok(Vec::new()));
    }

    #[test]
    fn deleted_unmerged_and_submodule_entries_have_no_blob() {
        for (mode, new, status) in [
            ("000000", Z, "D"),
            ("100644", A, "U"),
            ("160000", A, "M"),
            ("100644", Z, "M"),
        ] {
            let e = parse_raw(&raw(mode, A, new, status, b"p")).unwrap();
            assert!(e[0].blob().is_none(), "{mode} {status}");
        }
    }

    #[test]
    fn object_ids_are_exactly_hex_of_a_known_width() {
        assert!(Sha::parse(A.as_bytes()).is_some());
        assert!(Sha::parse(&[b'a'; 64]).is_some());
        for bad in [&b"abc"[..], &[b'A'; 40], &[b'g'; 40], &[b'a'; 41], b""] {
            assert!(Sha::parse(bad).is_none());
        }
        assert_eq!(
            parse_shas(format!("{A}\n{A}\n").as_bytes()).unwrap().len(),
            2
        );
        assert_eq!(parse_shas(b"").unwrap().len(), 0);
        assert_eq!(
            parse_shas(format!("{A}\nnope\n").as_bytes()),
            Err(GitError::Malformed)
        );
        assert_eq!(
            parse_shas(format!("{A} path\n").as_bytes()),
            Err(GitError::Malformed)
        );
    }

    #[test]
    fn batch_headers_must_name_the_object_asked_for() {
        let want = Sha::parse(A.as_bytes()).unwrap();
        assert_eq!(
            parse_header(format!("{A} blob 12").as_bytes(), &want),
            Ok((Kind::Blob, 12))
        );
        for bad in [
            format!("{Z} blob 12"),
            format!("{A} blob"),
            format!("{A} blob -1"),
            format!("{A} blob 1 2"),
            format!("{A} thing 1"),
        ] {
            assert_eq!(
                parse_header(bad.as_bytes(), &want),
                Err(GitError::Malformed)
            );
        }
        assert_eq!(
            parse_header(format!("{A} missing").as_bytes(), &want),
            Err(GitError::Missing)
        );
    }

    #[test]
    fn a_revision_cannot_be_an_option() {
        let g = Git::locate();
        assert_eq!(g.resolve("--output=x"), Err(GitError::Malformed));
        assert_eq!(g.resolve(""), Err(GitError::Malformed));
    }
}

#[cfg(test)]
mod adversary_128 {
    //! Adversarial tests (#128) of the old-git guard with a fake old git: a shell wrapper that
    //! answers `version` as an old (or unparseable) git and runs the real git otherwise.
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::process::Command;

    struct Fake {
        _dir: tempfile::TempDir,
        repo: PathBuf,
        exe: PathBuf,
    }

    fn real_git() -> PathBuf {
        Git::locate().exe
    }

    fn fake(version_line: &str) -> Fake {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("old-git");
        let script = format!(
            "#!/bin/sh\nfor a in \"$@\"; do if [ \"$a\" = version ]; then printf '%s\\n' '{version_line}'; exit 0; fi; done\nexec '{}' \"$@\"\n",
            real_git().display()
        );
        std::fs::write(&exe, script).unwrap();
        std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755)).unwrap();
        let repo = dir.path().join("repo");
        std::fs::create_dir(&repo).unwrap();
        let f = Fake {
            _dir: dir,
            repo,
            exe,
        };
        f.run(&["init", "-q"]);
        f
    }

    impl Fake {
        fn run(&self, args: &[&str]) {
            let ok = Command::new(real_git())
                .arg("-C")
                .arg(&self.repo)
                .args(args)
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .status()
                .unwrap()
                .success();
            assert!(ok, "git {args:?}");
        }

        fn git(&self) -> Git {
            Git {
                exe: self.exe.clone(),
                dir: Some(self.repo.clone()),
            }
        }
    }

    #[test]
    fn control_the_fake_old_git_passes_a_full_repository() {
        let f = fake("git version 2.43.0");
        assert_eq!(f.git().guard_lazy_fetch(), Ok(()));
    }

    #[test]
    fn an_old_git_refuses_the_camel_case_spelling_of_extensions_partial_clone() {
        let f = fake("git version 2.43.0");
        f.run(&["config", "extensions.partialClone", "origin"]);
        assert_eq!(f.git().guard_lazy_fetch(), Err(GitError::PartialClone));
    }

    #[test]
    fn an_old_git_refuses_a_promisor_remote_with_a_mixed_case_name() {
        let f = fake("git version 2.39.5 (Apple Git-154)");
        f.run(&["config", "remote.My.Origin.Promisor", "true"]);
        assert_eq!(f.git().guard_lazy_fetch(), Err(GitError::PartialClone));
    }

    #[test]
    fn an_old_git_refuses_a_partial_clone_set_in_the_worktree_config() {
        let f = fake("git version 2.43.0");
        f.run(&["config", "extensions.worktreeConfig", "true"]);
        f.run(&["config", "--worktree", "extensions.partialclone", "origin"]);
        assert_eq!(f.git().guard_lazy_fetch(), Err(GitError::PartialClone));
    }

    #[test]
    fn an_old_git_refuses_a_partial_clone_set_through_an_included_file() {
        let f = fake("git version 2.43.0");
        let inc = f.repo.join("extra.cfg");
        std::fs::write(&inc, "[remote \"origin\"]\n\tpromisor = true\n").unwrap();
        f.run(&["config", "include.path", inc.to_str().unwrap()]);
        assert_eq!(f.git().guard_lazy_fetch(), Err(GitError::PartialClone));
    }

    #[test]
    fn an_unparseable_version_refuses_a_partial_clone() {
        for v in [
            "git version",
            "git version  2.53.0",
            "version 2.53.0",
            "git version v2.53",
        ] {
            let f = fake(v);
            f.run(&["config", "extensions.partialclone", "origin"]);
            assert_eq!(
                f.git().guard_lazy_fetch(),
                Err(GitError::PartialClone),
                "{v:?}"
            );
        }
    }

    #[test]
    fn a_real_blobless_clone_is_refused_by_an_old_git() {
        let f = fake("git version 2.43.0");
        f.run(&[
            "-c",
            "user.name=a",
            "-c",
            "user.email=a@example.invalid",
            "commit",
            "-q",
            "--allow-empty",
            "-m",
            "x",
        ]);
        f.run(&["config", "uploadpack.allowFilter", "true"]);
        let clone = f.repo.parent().unwrap().join("clone");
        let ok = Command::new(real_git())
            .args(["clone", "-q", "--no-checkout", "--filter=blob:none"])
            .arg(format!("file://{}", f.repo.display()))
            .arg(&clone)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .status()
            .unwrap()
            .success();
        assert!(ok);
        let g = Git {
            exe: f.exe.clone(),
            dir: Some(clone),
        };
        assert_eq!(g.guard_lazy_fetch(), Err(GitError::PartialClone));
    }

    #[test]
    fn version_edge_cases_never_read_an_old_git_as_new() {
        for (text, want) in [
            ("git version 2.43.99\n", Some((2, 43))),
            ("git version 2.4.44\n", Some((2, 4))),
            ("git version 1.44.0\n", Some((1, 44))),
            ("git version 2.44.0-rc0\n", Some((2, 44))),
            ("git version 2.99999999999.0\n", None),
        ] {
            assert_eq!(parse_version(text.as_bytes()), want, "{text:?}");
            if let Some(v) = want {
                assert_eq!(v >= LAZY_FETCH_MIN, v.0 > 2 || (v.0 == 2 && v.1 >= 44));
            }
        }
    }
}
