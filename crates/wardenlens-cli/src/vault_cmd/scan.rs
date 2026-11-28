//! `wardenlens vault scan PATH...` (ADR 0006 sections 7 and 8).
//!
//! Matches files and directories against every value of the vault. A hit is reported as
//! `entry-id kind location`; the matched text, the line, the value and its length never are
//! (SEC-6). A path that itself contains a hit is replaced by `<redacted-path:N>`, `N` being the
//! position of the file in this scan. Exit codes: 0 no hit, 1 a hit, 2 the scan could not run
//! or could not read an input (failing to scan is never a pass).
//!
//! `--staged` scans the staged blobs and paths and `--range A..B` what a push publishes (new
//! blobs, every path, commit and tag objects, ref names, every tree name) by reading
//! git objects (ADR 0006 section 9); the code for those sources is in `git_scan`.

use std::fs::File;
use std::io::Read;
use std::os::unix::fs::MetadataExt;

use wardenlens_vault::{BINARY_PROBE_LEN, Content, MAX_FILE_LEN, Matcher, classify, scan};

mod git;
mod git_scan;
mod redact;
mod walk;

use self::redact::Safe;
use self::walk::{Input, Unread, walk};
use super::session::open_read;
use super::{say, warn};
use crate::args::ScanArgs;
use crate::env::Paths;
use crate::error::CliError;
use crate::terminal::Terminal;

/// Most files and directories one scan walks.
const MAX_INPUTS: usize = 100_000;
/// Binary-file notices printed individually; the rest are counted.
const MAX_BINARY_NOTICES: usize = 20;

/// What a file turned out to be.
enum Loaded {
    /// Binary (ADR 0006 section 7): skipped, whatever its size.
    Binary,
    /// The bytes of a file within the 8 MiB limit.
    Bytes(Vec<u8>),
}

/// Classifies a file by its first bytes, then reads it. Only text (UTF-16 with a byte order mark
/// included) is subject to the 8 MiB limit, so a large binary file is skipped, not refused.
fn load(file: File) -> Result<Loaded, Unread> {
    let io = |e: std::io::Error| Unread::Io(e.kind());
    let size = file.metadata().map_err(io)?.size();
    let mut file = file;
    let probe_cap = u64::try_from(BINARY_PROBE_LEN).unwrap_or(u64::MAX);
    let mut bytes = Vec::new();
    (&mut file)
        .take(probe_cap)
        .read_to_end(&mut bytes)
        .map_err(io)?;
    if matches!(classify(&bytes), Content::Binary) {
        return Ok(Loaded::Binary);
    }
    if usize::try_from(size).map_or(true, |n| n > MAX_FILE_LEN) {
        return Err(Unread::TooLarge);
    }
    // The size can change between the check and the read: the read is bounded as well.
    let cap = u64::try_from(MAX_FILE_LEN)
        .unwrap_or(u64::MAX)
        .saturating_add(1)
        .saturating_sub(probe_cap);
    file.take(cap).read_to_end(&mut bytes).map_err(io)?;
    if bytes.len() > MAX_FILE_LEN {
        return Err(Unread::TooLarge);
    }
    Ok(Loaded::Bytes(bytes))
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

fn scan_input<T: Terminal>(
    matcher: &Matcher,
    input: &Input,
    ordinal: usize,
    tally: &mut Tally,
    term: &mut T,
) -> Result<(), CliError> {
    // One printed line: `pre`, the location (redacted as a whole by `location`), `post`.
    let at = |line: Option<usize>, pre: &str, post: &str| {
        let loc = Safe::path(matcher, &input.path, ordinal, line, (pre, post));
        format!("{pre}{loc}{post}")
    };
    let binary_notice = || at(None, "notice: skipped binary file ", "");
    let outcome = match input.problem {
        Some(p) => Err(p),
        None => input.open().and_then(load),
    };
    let bytes = match outcome {
        Ok(Loaded::Bytes(b)) => b,
        Ok(Loaded::Binary) => {
            return binary(binary_notice, tally, term);
        }
        Err(why) => {
            tally.unread = tally.unread.saturating_add(1);
            return warn(term, &at(None, "error: ", &format!(" {why}")));
        }
    };
    let text = match classify(&bytes) {
        Content::Text(t) => t,
        Content::Binary => {
            return binary(binary_notice, tally, term);
        }
        // A kind of content added later is not silently passed over.
        _ => {
            tally.unread = tally.unread.saturating_add(1);
            return warn(term, &at(None, "error: ", " has an unknown content type"));
        }
    };
    tally.files = tally.files.saturating_add(1);
    let Ok(report) = scan(matcher, &text) else {
        tally.unread = tally.unread.saturating_add(1);
        return warn(term, &at(None, "error: ", " could not be scanned"));
    };
    if report.truncated {
        tally.truncated = tally.truncated.saturating_add(1);
    }
    for h in &report.hits {
        tally.hits = tally.hits.saturating_add(1);
        // The id and kind are printed as they are (not secret, ADR 0006 section 8). The kind is
        // part of the text the location is checked with, so a value cannot be spelled across
        // the kind and the path.
        let kind = format!("{} ", h.kind);
        let loc = Safe::path(matcher, &input.path, ordinal, Some(h.line), (&kind, ""));
        say(term, &format!("{} {} {loc}", h.id, h.kind))?;
    }
    Ok(())
}

fn binary<T: Terminal>(
    notice: impl FnOnce() -> String,
    tally: &mut Tally,
    term: &mut T,
) -> Result<(), CliError> {
    tally.binary = tally.binary.saturating_add(1);
    if tally.binary <= MAX_BINARY_NOTICES {
        warn(term, &notice())?;
    }
    Ok(())
}

/// Runs the scan. Exit 1 means only that a value was found; every other failure, an output
/// error included, is "the scan could not run" (exit 2), never a pass and never a hit.
pub(super) fn run<T: Terminal>(args: &ScanArgs, p: &Paths, term: &mut T) -> Result<(), CliError> {
    run_with(args, p, term, MAX_INPUTS)
}

pub(super) fn run_with<T: Terminal>(
    args: &ScanArgs,
    p: &Paths,
    term: &mut T,
    limit: usize,
) -> Result<(), CliError> {
    match scan_all(args, p, term, limit) {
        Err(e @ (CliError::Leak(_) | CliError::Incomplete(_) | CliError::CouldNotScan(_))) => {
            Err(e)
        }
        Err(e) => Err(CliError::CouldNotScan(Box::new(e))),
        Ok(()) => Ok(()),
    }
}

fn scan_all<T: Terminal>(
    args: &ScanArgs,
    p: &Paths,
    term: &mut T,
    limit: usize,
) -> Result<(), CliError> {
    let could_not = |e: CliError| CliError::CouldNotScan(Box::new(e));
    let git = git::Git::locate();
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
    if let Some(source) = git_scan::source_of(args, &git)? {
        let g = git_scan::run(&matcher, &git, &source, git_scan::Sources::ALL, term)?;
        if g.truncated {
            warn(term, "notice: more hits than are listed")?;
        }
        warn(
            term,
            &format!(
                "scanned {} object(s), {} entries, {} hit(s)",
                g.objects,
                matcher.scanned_len(),
                g.hits
            ),
        )?;
        return verdict(g.unread, g.hits);
    }
    let found = walk(&args.paths, limit)?;
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
    verdict(tally.unread, tally.hits)
}

/// Failing to scan outranks a hit; neither is a pass.
fn verdict(unread: usize, hits: usize) -> Result<(), CliError> {
    if unread > 0 {
        Err(CliError::Incomplete(unread))
    } else if hits > 0 {
        Err(CliError::Leak(hits))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
            Unread::Malformed,
        ] {
            assert!(!format!("{u} {u:?}").contains('/'));
        }
    }
}
