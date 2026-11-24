//! `wardenlens vault scan PATH...` (ADR 0006 sections 7 and 8).
//!
//! Matches files and directories against every value of the vault. A hit is reported as
//! `entry-id kind location`; the matched text, the line, the value and its length never are
//! (SEC-6). A path that itself contains a hit is replaced by `<redacted-path:N>`, `N` being the
//! position of the file in this scan. Exit codes: 0 no hit, 1 a hit, 2 the scan could not run
//! or could not read an input (failing to scan is never a pass).

use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use rustix::fs::OFlags;
use wardenlens_vault::{Content, MAX_FILE_LEN, Matcher, classify, scan};

use super::session::open_read;
use super::{say, warn};
use crate::args::ScanArgs;
use crate::env::Paths;
use crate::error::CliError;
use crate::terminal::Terminal;

/// Deepest directory nesting that is walked.
const MAX_DEPTH: usize = 64;
/// Most files and directories one scan walks.
const MAX_INPUTS: usize = 100_000;
/// Binary-file notices printed individually; the rest are counted.
const MAX_BINARY_NOTICES: usize = 20;

/// Why an input could not be scanned. The text never holds a path or a value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
enum Unread {
    #[error("cannot be read ({0})")]
    Io(std::io::ErrorKind),
    #[error("is not a regular file or directory")]
    NotRegular,
    #[error("is larger than the 8 MiB scan limit")]
    TooLarge,
    #[error("is nested deeper than the walk limit")]
    TooDeep,
}

/// Something found while walking: a file to scan or one that could not be read.
struct Input {
    path: PathBuf,
    /// A path given on the command line is followed if it is a symlink; one found while walking
    /// is skipped.
    explicit: bool,
    problem: Option<Unread>,
}

struct Walk {
    inputs: Vec<Input>,
    symlinks: usize,
    special: usize,
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
        explicit: bool,
        problem: Option<Unread>,
    ) -> Result<(), CliError> {
        self.seen = self.seen.saturating_add(1);
        if self.seen > self.limit {
            return Err(CliError::Refused(
                "too many files to scan in one command; scan a smaller directory",
            ));
        }
        self.inputs.push(Input {
            path,
            explicit,
            problem,
        });
        Ok(())
    }

    fn dir(&mut self, dir: &Path, depth: usize) -> Result<(), CliError> {
        if depth > MAX_DEPTH {
            return self.push(dir.to_owned(), false, Some(Unread::TooDeep));
        }
        let entries = match fs::read_dir(dir) {
            Ok(e) => e,
            Err(e) => return self.push(dir.to_owned(), false, Some(Unread::Io(e.kind()))),
        };
        let mut paths = Vec::new();
        for entry in entries {
            match entry {
                Ok(e) => paths.push(e.path()),
                Err(e) => self.push(dir.to_owned(), false, Some(Unread::Io(e.kind())))?,
            }
            if paths.len().saturating_add(self.seen) > self.limit {
                return Err(CliError::Refused(
                    "too many files to scan in one command; scan a smaller directory",
                ));
            }
        }
        paths.sort();
        for path in paths {
            match fs::symlink_metadata(&path) {
                Ok(m) if m.is_symlink() => self.symlinks = self.symlinks.saturating_add(1),
                Ok(m) if m.is_dir() => self.dir(&path, depth.saturating_add(1))?,
                Ok(m) if m.is_file() => self.push(path, false, None)?,
                Ok(_) => self.special = self.special.saturating_add(1),
                Err(e) => self.push(path, false, Some(Unread::Io(e.kind())))?,
            }
        }
        Ok(())
    }
}

fn walk(paths: &[PathBuf], limit: usize) -> Result<Walk, CliError> {
    let mut w = Walk::new(limit);
    for p in paths {
        match fs::metadata(p) {
            Ok(m) if m.is_dir() => w.dir(p, 0)?,
            Ok(m) if m.is_file() => w.push(p.clone(), true, None)?,
            Ok(_) => w.push(p.clone(), true, Some(Unread::NotRegular))?,
            Err(e) => w.push(p.clone(), true, Some(Unread::Io(e.kind())))?,
        }
    }
    Ok(w)
}

/// Opens a regular file without ever blocking on it (a FIFO would hang a plain open).
fn open_regular(path: &Path, explicit: bool) -> Result<File, Unread> {
    let mut flags = OFlags::NONBLOCK;
    if !explicit {
        flags |= OFlags::NOFOLLOW;
    }
    let flags = i32::try_from(flags.bits()).unwrap_or(0);
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(flags)
        .open(path)
        .map_err(|e| Unread::Io(e.kind()))?;
    let meta = file.metadata().map_err(|e| Unread::Io(e.kind()))?;
    if !meta.is_file() {
        return Err(Unread::NotRegular);
    }
    if usize::try_from(meta.size()).map_or(true, |n| n > MAX_FILE_LEN) {
        return Err(Unread::TooLarge);
    }
    Ok(file)
}

fn read_bounded(file: File) -> Result<Vec<u8>, Unread> {
    let cap = u64::try_from(MAX_FILE_LEN)
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    let mut bytes = Vec::new();
    file.take(cap)
        .read_to_end(&mut bytes)
        .map_err(|e| Unread::Io(e.kind()))?;
    if bytes.len() > MAX_FILE_LEN {
        return Err(Unread::TooLarge);
    }
    Ok(bytes)
}

/// What the report knows about one scan.
#[derive(Default)]
struct Tally {
    files: usize,
    hits: usize,
    unread: usize,
    binary: usize,
    truncated: usize,
}

/// A path as it may be printed: the path itself unless it contains a hit.
fn shown(matcher: &Matcher, path: &Path, ordinal: usize) -> String {
    // A path that cannot be scanned (it cannot be too long, but fail closed) is not printed.
    match scan(matcher, path.as_os_str().as_bytes()) {
        Ok(r) if r.hits.is_empty() => path.display().to_string(),
        _ => format!("<redacted-path:{ordinal}>"),
    }
}

fn scan_input<T: Terminal>(
    matcher: &Matcher,
    input: &Input,
    ordinal: usize,
    tally: &mut Tally,
    term: &mut T,
) -> Result<(), CliError> {
    let name = shown(matcher, &input.path, ordinal);
    let outcome = match input.problem {
        Some(p) => Err(p),
        None => open_regular(&input.path, input.explicit).and_then(read_bounded),
    };
    let bytes = match outcome {
        Ok(b) => b,
        Err(why) => {
            tally.unread = tally.unread.saturating_add(1);
            return warn(term, &format!("error: {name} {why}"));
        }
    };
    let text = match classify(&bytes) {
        Content::Text(t) => t,
        Content::Binary => {
            tally.binary = tally.binary.saturating_add(1);
            if tally.binary <= MAX_BINARY_NOTICES {
                warn(term, &format!("notice: skipped binary file {name}"))?;
            }
            return Ok(());
        }
        // A kind of content added later is not silently passed over.
        _ => {
            tally.unread = tally.unread.saturating_add(1);
            return warn(term, &format!("error: {name} has an unknown content type"));
        }
    };
    tally.files = tally.files.saturating_add(1);
    let Ok(report) = scan(matcher, &text) else {
        tally.unread = tally.unread.saturating_add(1);
        return warn(term, &format!("error: {name} could not be scanned"));
    };
    if report.truncated {
        tally.truncated = tally.truncated.saturating_add(1);
    }
    for h in &report.hits {
        tally.hits = tally.hits.saturating_add(1);
        say(term, &format!("{} {} {name}:{}", h.id, h.kind, h.line))?;
    }
    Ok(())
}

pub(super) fn run<T: Terminal>(args: &ScanArgs, p: &Paths, term: &mut T) -> Result<(), CliError> {
    let could_not = |e: CliError| CliError::CouldNotScan(Box::new(e));
    let vault = open_read(p).map_err(could_not)?;
    let matcher = Matcher::from_vault(&vault).map_err(|e| could_not(e.into()))?;
    drop(vault);
    for u in matcher.unscannable() {
        warn(
            term,
            &format!(
                "warning: entry {} ({}) is unscannable (too short, or already public) and is not checked",
                u.id, u.kind
            ),
        )?;
    }
    let found = walk(&args.paths, MAX_INPUTS)?;
    let mut tally = Tally::default();
    for (ordinal, input) in found.inputs.iter().enumerate() {
        scan_input(&matcher, input, ordinal, &mut tally, term)?;
    }
    if tally.binary > MAX_BINARY_NOTICES {
        warn(
            term,
            &format!("notice: {} binary files skipped in all", tally.binary),
        )?;
    }
    if found.symlinks > 0 || found.special > 0 {
        warn(
            term,
            &format!(
                "notice: skipped {} symlink(s) and {} special file(s) found while walking",
                found.symlinks, found.special
            ),
        )?;
    }
    if tally.truncated > 0 {
        warn(
            term,
            &format!(
                "notice: {} file(s) had more hits than are listed",
                tally.truncated
            ),
        )?;
    }
    warn(
        term,
        &format!(
            "scanned {} file(s), {} entries, {} hit(s)",
            tally.files,
            matcher.scanned_len(),
            tally.hits
        ),
    )?;
    if tally.unread > 0 {
        Err(CliError::Incomplete(tally.unread))
    } else if tally.hits > 0 {
        Err(CliError::Leak(tally.hits))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
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
        let w = walk(&[d.path().to_owned()], MAX_INPUTS).unwrap();
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
    fn exit_codes_and_messages_of_the_scan_errors() {
        let cases = [
            (CliError::Leak(3), 1u8),
            (CliError::Incomplete(2), 2),
            (CliError::CouldNotScan(Box::new(CliError::Leak(1))), 2),
            (
                CliError::Scan(wardenlens_vault::ScanError::InputTooLarge),
                2,
            ),
        ];
        for (e, code) in cases {
            assert_eq!(e.exit_code(), code, "{e}");
            let shown = format!("{e} {e:?}");
            assert!(!shown.contains('/'), "no path in {shown}");
        }
        for u in [
            Unread::Io(std::io::ErrorKind::PermissionDenied),
            Unread::NotRegular,
            Unread::TooLarge,
            Unread::TooDeep,
        ] {
            assert!(!format!("{u} {u:?}").contains('/'));
        }
    }
}
