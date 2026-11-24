//! The one place where a location becomes printable text (ADR 0006 section 8, defect pattern P10).
//!
//! A path, ref name, commit or tag part can itself hold a vault value, and printing the location
//! would print the value. Every location of every source (a path, the index, a blob, a commit,
//! a tag, a ref) is rendered here, and the report prints only a [`Safe`], which cannot be built
//! anywhere else. The text of a [`Safe`] has been run through the matcher: if it still holds a
//! value (also when the text could not be scanned), a less specific form is used.

use std::ffi::OsStr;
use std::fmt;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use wardenlens_vault::{Matcher, is_invisible, scan};

/// Text that has passed the matcher and may be printed. Built only by [`render`] and
/// [`Safe::path`].
pub(super) struct Safe(String);

impl fmt::Display for Safe {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The part of a commit or tag object a hit is in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Part {
    Message,
    Author,
    Committer,
    Tagger,
    /// Any other header (`mergetag`, `gpgsig`, `encoding`, `tag`, `object`, ...).
    Header,
}

impl Part {
    fn word(self) -> &'static str {
        match self {
            Self::Message => "message",
            Self::Author => "author",
            Self::Committer => "committer",
            Self::Tagger => "tagger",
            Self::Header => "header",
        }
    }
}

/// Where a hit is, before redaction.
#[derive(Debug, Clone, Copy)]
pub(super) enum Loc<'a> {
    /// A path in the index; `sha` is the blob when it has one.
    Index {
        path: &'a [u8],
        sha: Option<&'a str>,
        line: Option<usize>,
    },
    /// A blob and every path it has among the new commits (possibly none known).
    Blob {
        paths: &'a [Vec<u8>],
        sha: &'a str,
        line: Option<usize>,
    },
    /// An entry name inside a new tree object (an empty name: the tree itself).
    Tree {
        path: &'a [u8],
        sha: &'a str,
    },
    Commit {
        sha: &'a str,
        part: Part,
    },
    Tag {
        sha: &'a str,
        part: Part,
    },
    /// A ref name, by its position among the names given on the command line.
    Ref(usize),
}

/// The last resort when even the fixed marker text would spell a value.
const LAST_RESORT: &str = "<redacted-location>";

fn clean(matcher: &Matcher, text: &[u8]) -> bool {
    scan(matcher, text).is_ok_and(|r| r.hits.is_empty())
}

fn with_line(text: String, line: Option<usize>) -> String {
    match line {
        Some(n) => format!("{text}:{n}"),
        None => text,
    }
}

/// Renders `loc`. The candidates run from the most to the least specific; the first whose text
/// (and, for a path, whose raw bytes) holds no vault value is returned.
pub(super) fn render(matcher: &Matcher, loc: &Loc<'_>) -> Safe {
    render_in(matcher, loc, ("", ""))
}

/// Like [`render`], for a location printed as `{pre}{location}{post}`: the fixed text around it
/// is part of what must hold no vault value, as for [`Safe::path`].
pub(super) fn render_in(matcher: &Matcher, loc: &Loc<'_>, (pre, post): (&str, &str)) -> Safe {
    let mut candidates: Vec<String> = Vec::new();
    match *loc {
        Loc::Index { path, sha, line } => {
            let blob = |name: &str, line| match sha {
                Some(s) => with_line(format!("{name} blob {s}"), line),
                None => with_line(name.to_owned(), line),
            };
            if clean(matcher, path) {
                candidates.push(with_line(escaped_bytes(path), line));
            }
            candidates.push(blob("<redacted-path>", line));
            candidates.push(blob("<redacted-path>", None));
        }
        Loc::Blob { paths, sha, line } => {
            let blob = |name: &str, line| with_line(format!("{name} blob {sha}"), line);
            if let Some(first) = paths
                .iter()
                .min()
                .filter(|_| paths.iter().all(|p| clean(matcher, p)))
            {
                candidates.push(blob(&escaped_bytes(first), line));
            }
            candidates.push(blob("<redacted-path>", line));
            candidates.push(blob("<redacted-path>", None));
        }
        Loc::Tree { path, sha } => {
            if path.is_empty() {
                // The tree itself (no entry name to show or to hide).
                candidates.push(format!("tree {sha}"));
            } else {
                if clean(matcher, path) {
                    candidates.push(format!("{} tree {sha}", escaped_bytes(path)));
                }
                candidates.push(format!("<redacted-path> tree {sha}"));
            }
        }
        Loc::Commit { sha, part } => {
            candidates.push(format!("commit:{sha}:{}", part.word()));
            candidates.push(format!("commit:<redacted>:{}", part.word()));
        }
        Loc::Tag { sha, part } => {
            candidates.push(format!("tag:{sha}:{}", part.word()));
            candidates.push(format!("tag:<redacted>:{}", part.word()));
        }
        Loc::Ref(index) => candidates.push(format!("ref:{index}")),
    }
    Safe(
        candidates
            .into_iter()
            .find(|c| clean(matcher, format!("{pre}{c}{post}").as_bytes()))
            .unwrap_or_else(|| LAST_RESORT.to_owned()),
    )
}

fn escaped_bytes(path: &[u8]) -> String {
    escaped(Path::new(OsStr::from_bytes(path)))
}

impl Safe {
    /// A location for a file given on the command line or found while walking: the existing
    /// path rules (`location`), as a [`Safe`].
    pub(super) fn path(
        matcher: &Matcher,
        path: &Path,
        ordinal: usize,
        line: Option<usize>,
        around: (&str, &str),
    ) -> Self {
        Self(location(matcher, path, ordinal, line, around))
    }
}

/// True for a character that may be printed as it is: a graphic, visible one. This is an
/// allowlist: everything else (controls, `Cf` format characters, separators, invisible
/// fillers, white space other than the plain space) is escaped.
fn is_printable(c: char) -> bool {
    c == ' ' || !(c.is_control() || c.is_whitespace() || is_invisible(c))
}

/// A path as it may be printed: characters that are not printable are written as `\u{..}`
/// escapes, so a file name can neither forge a report line nor send terminal escapes.
fn escaped(path: &Path) -> String {
    let mut out = String::new();
    for c in path.to_string_lossy().chars() {
        if is_printable(c) {
            out.push(c);
        } else {
            out.extend(c.escape_unicode());
        }
    }
    out
}

/// The text one printed line shows about a path: `{pre}{name}[:{line}]{post}`, where `pre` and
/// `post` are the fixed message text around it (never the entry id or kind, which are printed
/// by the caller and are not secret). Redaction (ADR 0006 section 8) considers exactly this
/// text and the raw path bytes. When either holds a vault value the name becomes
/// `<redacted-path:N>` (`N` is the position of the file in this scan); if that text still
/// spells a value (a number equal to the line or the position) the line is dropped, then the
/// position. A text that cannot be scanned counts as holding a value (fail closed).
fn location(
    matcher: &Matcher,
    path: &Path,
    ordinal: usize,
    line: Option<usize>,
    (pre, post): (&str, &str),
) -> String {
    let raw_clean = scan(matcher, path.as_os_str().as_bytes()).is_ok_and(|r| r.hits.is_empty());
    let show = |name: &str, line: Option<usize>| match line {
        Some(n) => format!("{name}:{n}"),
        None => name.to_owned(),
    };
    let clean = |shown: &str| {
        scan(matcher, format!("{pre}{shown}{post}").as_bytes()).is_ok_and(|r| r.hits.is_empty())
    };
    let plain = show(&escaped(path), line);
    if raw_clean && clean(&plain) {
        return plain;
    }
    let numbered = format!("<redacted-path:{ordinal}>");
    for candidate in [
        show(&numbered, line),
        show(&numbered, None),
        show("<redacted-path>", None),
    ] {
        if clean(&candidate) {
            return candidate;
        }
    }
    // Nothing but the fixed marker is left to print.
    "<redacted-path>".to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn matcher_of(kind: wardenlens_core::entry::EntryKind, value: &str) -> Matcher {
        let m = Matcher::new(&[wardenlens_vault::ScanEntry {
            id: wardenlens_core::entry::EntryId::new("e:one").unwrap(),
            kind,
            value: secrecy::SecretString::from(value.to_owned()),
            unscannable: false,
        }])
        .unwrap();
        assert!(m.unscannable().is_empty(), "{value:?} is unscannable");
        m
    }

    #[test]
    fn a_number_that_equals_the_line_or_the_position_is_not_printed() {
        use wardenlens_core::entry::EntryKind::Other;
        // The value is the line number: `:1234567` would print it.
        let m = matcher_of(Other, "1234567");
        let p = Path::new("/w/a-1234567-b.txt");
        assert_eq!(
            location(&m, p, 3, Some(1_234_567), ("", "")),
            "<redacted-path:3>"
        );
        // The value is the position: the position goes too.
        let m = matcher_of(Other, "1234567");
        let p = Path::new("/w/a-1234567-b.txt");
        assert_eq!(
            location(&m, p, 1_234_567, Some(2), ("", "")),
            "<redacted-path>"
        );
        // A clean path with an id-like or unrelated value is printed as it is.
        let m = matcher_of(Other, "zq-synthetic-mark");
        assert_eq!(
            location(&m, Path::new("/w/a.txt"), 0, Some(4), ("", "")),
            "/w/a.txt:4"
        );
    }

    #[test]
    fn every_unicode_format_character_is_escaped() {
        let cf: &[(u32, u32)] = &[
            (0xAD, 0xAD),
            (0x600, 0x605),
            (0x61C, 0x61C),
            (0x6DD, 0x6DD),
            (0x70F, 0x70F),
            (0x890, 0x891),
            (0x8E2, 0x8E2),
            (0x180E, 0x180E),
            (0x200B, 0x200F),
            (0x202A, 0x202E),
            (0x2060, 0x2064),
            (0x2066, 0x206F),
            (0xFEFF, 0xFEFF),
            (0xFFF9, 0xFFFB),
            (0x110BD, 0x110BD),
            (0x110CD, 0x110CD),
            (0x13430, 0x1343F),
            (0x1BCA0, 0x1BCA3),
            (0x1D173, 0x1D17A),
            (0xE0001, 0xE0001),
            (0xE0020, 0xE007F),
        ];
        for &(lo, hi) in cf {
            for n in lo..=hi {
                let c = char::from_u32(n).unwrap();
                assert!(!is_printable(c), "U+{n:04X}");
                let shown = escaped(Path::new(&format!("a{c}b")));
                assert!(!shown.contains(c), "U+{n:04X}");
            }
        }
        for c in [
            '\u{2028}', '\u{2029}', '\u{85}', '\u{A0}', '\u{7F}', '\n', '\u{3000}',
        ] {
            assert!(!is_printable(c), "{c:?}");
        }
        for c in ['a', ' ', '/', '\u{e9}', '\u{4e2d}'] {
            assert!(is_printable(c), "{c:?}");
        }
    }
}
