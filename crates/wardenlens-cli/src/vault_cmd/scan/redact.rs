//! The one place where a location becomes printable text (ADR 0006 section 8, defect pattern P10).
//!
//! A path, ref name, commit or tag part can itself hold a vault value, and printing the location
//! would print the value. Every location of every source (a path, the index, a blob, a commit,
//! a tag, a ref) is rendered here, and the report prints only a [`Safe`], which cannot be built
//! anywhere else. The text of a [`Safe`] has been run through the matcher: if it still holds a
//! value (also when the text could not be scanned), a less specific form is used, and if even
//! the last marker would spell one the location is dropped: the line is printed without it
//! (or, if the fixed text around it spells a value too, not at all). Nothing is ever printed
//! that has not been scanned.

use std::fmt::{self, Write as _};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use wardenlens_vault::{Matcher, is_invisible, scan};

/// Text that has passed the matcher and may be printed. Built only by [`render_in`] and
/// [`Safe::path`]. It is `None` when no form of the location was clean: it then prints as
/// nothing, and [`Safe::print`] gives the line without it.
pub(super) struct Safe {
    loc: Option<String>,
    /// The fixed text around the location, without it, holds no vault value.
    bare_ok: bool,
}

impl fmt::Display for Safe {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.loc.as_deref().unwrap_or_default())
    }
}

/// The checked text of a line whose location is dropped: the fixed text before and after it.
fn bare(pre: &str, post: &str) -> String {
    format!("{} {}", pre.trim_end(), post.trim_start())
        .trim()
        .to_owned()
}

impl Safe {
    /// The printed line `{pre}{location}{post}`, where `pre` and `post` are what the caller
    /// prints around the location (the entry id included, which is not checked). Without a
    /// clean location the line is `pre` and `post` alone, and `None` if even those (as checked
    /// when this was built) held a value: such a line is not printed.
    pub(super) fn print(&self, pre: &str, post: &str) -> Option<String> {
        match &self.loc {
            Some(l) => Some(format!("{pre}{l}{post}")),
            None if self.bare_ok => Some(bare(pre, post)),
            None => None,
        }
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
#[cfg(test)]
pub(super) fn render(matcher: &Matcher, loc: &Loc<'_>) -> Safe {
    render_in(matcher, loc, ("", ""))
}

/// Like `render`, for a location printed as `{pre}{location}{post}`: the fixed text around it
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
                if line.is_some() {
                    candidates.push(escaped_bytes(path));
                }
            }
            candidates.push(blob("<redacted-path>", line));
            if line.is_some() {
                candidates.push(blob("<redacted-path>", None));
            }
        }
        Loc::Blob { paths, sha, line } => {
            let blob = |name: &str, line| with_line(format!("{name} blob {sha}"), line);
            if let Some(first) = paths
                .iter()
                .min()
                .filter(|_| paths.iter().all(|p| clean(matcher, p)))
            {
                candidates.push(blob(&escaped_bytes(first), line));
                if line.is_some() {
                    candidates.push(blob(&escaped_bytes(first), None));
                }
            }
            candidates.push(blob("<redacted-path>", line));
            if line.is_some() {
                candidates.push(blob("<redacted-path>", None));
            }
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
    Safe {
        loc: candidates
            .into_iter()
            .find(|c| clean(matcher, format!("{pre}{c}{post}").as_bytes())),
        bare_ok: clean(matcher, bare(pre, post).as_bytes()),
    }
}

fn escaped_bytes(path: &[u8]) -> String {
    escaped_raw(path)
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
        Self {
            loc: location(matcher, path, ordinal, line, around),
            bare_ok: clean(matcher, bare(around.0, around.1).as_bytes()),
        }
    }
}

/// Code points that render as nothing or as an unpredictable glyph although no category list
/// of the standard library names them: the default-ignorable code points that are not yet
/// assigned (U+FFF0..U+FFF8 and U+E0000..U+E0FFF, `DerivedCoreProperties.txt`, property
/// `Default_Ignorable_Code_Point`), private use (`Co`) and the noncharacters. A future Unicode
/// version can assign one of them; it is then escaped until this list is revisited (fail
/// closed).
fn is_reserved(c: char) -> bool {
    let n = u32::from(c);
    matches!(
        n,
        0xFFF0..=0xFFF8 | 0xE0000..=0xE0FFF | 0xE000..=0xF8FF | 0xF0000..=0x0010_FFFF | 0xFDD0..=0xFDEF
    ) || n & 0xFFFE == 0xFFFE
}

/// True for a character that may be printed as it is: a graphic, visible one. This is a
/// denylist by category, and the category list is [`is_invisible`] of the core crate (every
/// `Cf` code point of Unicode 16, from `DerivedGeneralCategory.txt`, and the other invisible
/// fillers; a test pins it), plus `Cc` (`char::is_control`: C0, DEL, C1), white space (so U+2028,
/// U+2029, U+0085 and U+00A0 included; only the plain space is kept) and [`is_reserved`].
/// Unassigned code points (`Cn`) outside [`is_reserved`] are not escaped: the standard library
/// has no table for them, and they render as at most a replacement glyph, never as a line break
/// or an escape sequence.
fn is_printable(c: char) -> bool {
    c == ' ' || !(c.is_control() || c.is_whitespace() || is_invisible(c) || is_reserved(c))
}

/// A path as it may be printed: characters that are not printable are written as `\u{..}`
/// escapes, a backslash as `\\` and a byte that is not UTF-8 as `\x{..}`, so a file name can
/// neither forge a report line nor send terminal escapes, and two different names never print
/// alike (a name holding the text `\u{202e}` and one holding U+202E, or an invalid byte and a
/// real U+FFFD).
fn escaped_raw(path: &[u8]) -> String {
    let mut out = String::new();
    for chunk in path.utf8_chunks() {
        for c in chunk.valid().chars() {
            if c == '\\' {
                out.push_str("\\\\");
            } else if is_printable(c) {
                out.push(c);
            } else {
                out.extend(c.escape_unicode());
            }
        }
        for b in chunk.invalid() {
            // Writing to a String cannot fail.
            let _ = write!(out, "\\x{{{b:02x}}}");
        }
    }
    out
}

fn escaped(path: &Path) -> String {
    escaped_raw(path.as_os_str().as_bytes())
}

/// The text one printed line shows about a path: `{pre}{name}[:{line}]{post}`, where `pre` and
/// `post` are the fixed message text around it: for a hit line the kind token (`{kind} `), for
/// a notice its message, never the entry id (printed by the caller, not secret, ADR 0006
/// section 8). Redaction considers exactly this text and the raw path bytes. The forms run from
/// the most to the least specific and the first clean one wins: the name with its line, the
/// name without the line (the line number can itself spell a value), `<redacted-path:N>:line`
/// (`N` is the position of the file in this scan), `<redacted-path:N>`, `<redacted-path>`. If
/// none is clean the result is `None`: the location is dropped. A text that cannot be scanned
/// counts as holding a value (fail closed).
fn location(
    matcher: &Matcher,
    path: &Path,
    ordinal: usize,
    line: Option<usize>,
    (pre, post): (&str, &str),
) -> Option<String> {
    let raw_clean = scan(matcher, path.as_os_str().as_bytes()).is_ok_and(|r| r.hits.is_empty());
    let show = |name: &str, line: Option<usize>| match line {
        Some(n) => format!("{name}:{n}"),
        None => name.to_owned(),
    };
    let numbered = format!("<redacted-path:{ordinal}>");
    let mut candidates = Vec::new();
    if raw_clean {
        candidates.push(show(&escaped(path), line));
        if line.is_some() {
            candidates.push(show(&escaped(path), None));
        }
    }
    candidates.push(show(&numbered, line));
    if line.is_some() {
        candidates.push(show(&numbered, None));
    }
    candidates.push(show("<redacted-path>", None));
    candidates
        .into_iter()
        .find(|c| clean(matcher, format!("{pre}{c}{post}").as_bytes()))
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
            location(&m, p, 3, Some(1_234_567), ("", "")).as_deref(),
            Some("<redacted-path:3>")
        );
        // The value is the position: the position goes too.
        let m = matcher_of(Other, "1234567");
        let p = Path::new("/w/a-1234567-b.txt");
        assert_eq!(
            location(&m, p, 1_234_567, Some(2), ("", "")).as_deref(),
            Some("<redacted-path>")
        );
        // A clean path with an id-like or unrelated value is printed as it is.
        let m = matcher_of(Other, "zq-synthetic-mark");
        assert_eq!(
            location(&m, Path::new("/w/a.txt"), 0, Some(4), ("", "")).as_deref(),
            Some("/w/a.txt:4")
        );
    }

    #[test]
    fn fallback_table() {
        use wardenlens_core::entry::EntryKind::Other;
        // (value, path, ordinal, line, pre, post, want)
        type Row = (
            &'static str,
            &'static str,
            usize,
            Option<usize>,
            &'static str,
            &'static str,
            Option<&'static str>,
        );
        let rows: &[Row] = &[
            // The line spells the value: a clean path keeps its name, loses the line.
            (
                "1234567",
                "/w/a.txt",
                3,
                Some(1_234_567),
                "",
                "",
                Some("/w/a.txt"),
            ),
            // The path holds the value and the line equals the value too.
            (
                "1234567",
                "/w/a-1234567.txt",
                3,
                Some(1_234_567),
                "",
                "",
                Some("<redacted-path:3>"),
            ),
            // No line: nothing to drop, the plain form is clean.
            ("1234567", "/w/a.txt", 3, None, "", "", Some("/w/a.txt")),
            // The position spells the value as well as the line.
            (
                "1234567",
                "/w/a-1234567.txt",
                1_234_567,
                Some(1_234_567),
                "",
                "",
                Some("<redacted-path>"),
            ),
            // No line, position spells the value, path holds it too.
            (
                "1234567",
                "/w/a-1234567.txt",
                1_234_567,
                None,
                "",
                "",
                Some("<redacted-path>"),
            ),
            // The fixed text before the path completes a value (the kind token).
            (
                "other-abcdefg",
                "abcdefg",
                0,
                Some(1),
                "other-",
                "",
                Some("<redacted-path:0>:1"),
            ),
            // Every marker spells the value: the location is dropped.
            (
                "redacted-path",
                "/w/redacted-path.txt",
                0,
                Some(1),
                "",
                "",
                None,
            ),
            ("redacted-path", "/w/redacted-path", 0, None, "", "", None),
        ];
        for &(value, path, ordinal, line, pre, post, want) in rows {
            let m = matcher_of(Other, value);
            assert_eq!(
                location(&m, Path::new(path), ordinal, line, (pre, post)).as_deref(),
                want,
                "{value} {path} {ordinal} {line:?}"
            );
        }
    }

    #[test]
    fn print_drops_the_location_then_the_line() {
        use wardenlens_core::entry::EntryKind::Other;
        let m = matcher_of(Other, "redacted-path");
        let s = Safe::path(&m, Path::new("/w/redacted-path"), 0, Some(1), ("kind ", ""));
        assert!(s.loc.is_none());
        assert_eq!(s.print("id kind ", "").as_deref(), Some("id kind"));
        // The fixed text spells the value too: nothing is printed.
        let s = Safe::path(
            &m,
            Path::new("/w/x.txt"),
            0,
            Some(1),
            ("redacted-path ", ""),
        );
        assert_eq!(s.print("id redacted-path ", ""), None);
        // A clean location is printed with what the caller adds.
        let s = Safe::path(&m, Path::new("/w/ok"), 0, None, ("kind ", ""));
        assert_eq!(s.print("id kind ", "").as_deref(), Some("id kind /w/ok"));
    }

    #[test]
    fn backslashes_and_invalid_bytes_do_not_print_like_their_escapes() {
        assert_eq!(escaped_raw(b"a\\u{202e}b"), "a\\\\u{202e}b");
        assert_ne!(
            escaped_raw("a\u{202e}b".as_bytes()),
            escaped_raw(b"a\\u{202e}b")
        );
        assert_eq!(escaped_raw(b"a\xffb"), "a\\x{ff}b");
        assert_ne!(escaped_raw(b"a\xffb"), escaped_raw("a\u{fffd}b".as_bytes()));
        assert_ne!(escaped_raw(b"a\\x{ff}b"), escaped_raw(b"a\xffb"));
    }

    #[test]
    fn reserved_code_points_are_escaped() {
        let mut all: Vec<u32> = (0xFFF0..=0xFFF8).chain(0xE0000..=0xE0FFF).collect();
        all.extend([0xE000, 0xF8FF, 0xF0000, 0xFFFFD, 0x10_0000, 0x10_FFFD]);
        all.extend(0xFDD0..=0xFDEF);
        for plane in 0..=0x10_u32 {
            all.push(plane << 16 | 0xFFFE);
            all.push(plane << 16 | 0xFFFF);
        }
        for n in all {
            let Some(c) = char::from_u32(n) else { continue };
            assert!(!is_printable(c), "U+{n:04X}");
            assert!(!escaped(Path::new(&format!("a{c}b"))).contains(c));
        }
        // The neighbours stay printable.
        for n in [
            0xFFEF, 0xFFFC, 0xE1000, 0xDFFF_u32, 0xFB00, 0x1_0000, 0xFDCF, 0xFDF0,
        ] {
            if let Some(c) = char::from_u32(n) {
                assert!(is_printable(c), "U+{n:04X}");
            }
        }
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
