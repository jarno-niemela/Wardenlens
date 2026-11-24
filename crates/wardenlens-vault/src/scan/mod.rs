//! The exact-match leak scan (ADR 0006 sections 7 and 8).
//!
//! The scan does not guess what looks like a secret. It asks whether a text contains one of the
//! values that are actually in the vault, in any of the listed renderings. A [`Matcher`] is built
//! once from the entries; [`scan`] then matches any byte string. Nothing here prints, logs or
//! returns a value, a needle or the matched text: a [`Hit`] names an entry id, its kind and a
//! line (SEC-6).
//!
//! Every collection is bounded: input at [`MAX_INPUT_LEN`] bytes, needles at
//! [`MAX_NEEDLE_BYTES`] in total, entries at [`crate::MAX_ENTRIES`], hits at [`MAX_HITS`].

mod matcher;
mod needles;
mod net;
mod search;
mod squeeze;
#[cfg(test)]
mod tests;
mod views;

use std::borrow::Cow;

use secrecy::SecretString;
use wardenlens_core::entry::{EntryId, EntryKind};

use crate::error::VaultError;

pub use matcher::Matcher;
pub use squeeze::is_invisible;

/// Largest input, in bytes, that [`scan`] accepts. It is above [`MAX_FILE_LEN`] so that a
/// UTF-16 file at the file cap, once decoded to UTF-8, still fits.
pub const MAX_INPUT_LEN: usize = 16 * 1024 * 1024;
/// A file larger than this is not scanned (ADR 0006 section 7: 8 MiB).
pub const MAX_FILE_LEN: usize = 8 * 1024 * 1024;
/// Most needle bytes (all literal needles of all entries together) a matcher accepts.
pub const MAX_NEEDLE_BYTES: usize = 16 * 1024 * 1024;
/// Most hits one [`scan`] returns; more is reported as [`ScanReport::truncated`].
pub const MAX_HITS: usize = 10_000;
/// A file with a NUL byte in this many leading bytes is binary.
pub const BINARY_PROBE_LEN: usize = 8 * 1024;

/// Why a matcher could not be built or an input could not be scanned. Never carries a value.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ScanError {
    /// The input is longer than [`MAX_INPUT_LEN`].
    #[error("input is longer than the scan limit")]
    InputTooLarge,
    /// More entries than a vault may hold.
    #[error("too many entries for the scan")]
    TooManyEntries,
    /// The needles of all entries together exceed [`MAX_NEEDLE_BYTES`].
    #[error("the needle set is larger than the scan limit")]
    NeedlesTooLarge,
    /// The matching automaton could not be built or run.
    #[error("the needle automaton failed")]
    Automaton,
    /// The vault could not be read.
    #[error("reading the vault for the scan failed")]
    Vault(#[from] VaultError),
}

/// One entry to scan for. For a credential the value is the password: usernames are not scanned.
#[derive(Debug)]
pub struct ScanEntry {
    /// The entry id.
    pub id: EntryId,
    /// The entry kind.
    pub kind: EntryKind,
    /// The value (the password of a credential). `Debug` redacts it.
    pub value: SecretString,
    /// True if the store already marked the entry unscannable (for example a secret that equals
    /// public text). It is then listed, never scanned.
    pub unscannable: bool,
}

/// An entry the scan cannot use: it is listed on every scan so the gap is visible.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Unscannable {
    /// The entry id.
    pub id: EntryId,
    /// The entry kind.
    pub kind: EntryKind,
}

/// A value of one entry occurs on a line. Never the value, the text or its length.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub struct Hit {
    /// The line (1-based; lines end at `\n`) where the occurrence starts.
    pub line: usize,
    /// The entry id.
    pub id: EntryId,
    /// The entry kind.
    pub kind: EntryKind,
}

/// The result of scanning one input.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct ScanReport {
    /// One hit per entry and line, ordered by line and then entry id.
    pub hits: Vec<Hit>,
    /// True if more than [`MAX_HITS`] hits exist; the rest is not listed.
    pub truncated: bool,
}

/// Scans `input` with `matcher` in all views of ADR 0006 section 7.
///
/// # Errors
/// [`ScanError::InputTooLarge`] for input over [`MAX_INPUT_LEN`]; [`ScanError::Automaton`] if
/// the automaton cannot run.
pub fn scan(matcher: &Matcher, input: &[u8]) -> Result<ScanReport, ScanError> {
    matcher.scan(input)
}

/// What a file's bytes are.
#[derive(Debug)]
#[non_exhaustive]
pub enum Content<'a> {
    /// Text to scan (UTF-16 with a byte order mark is already decoded to UTF-8).
    Text(Cow<'a, [u8]>),
    /// A NUL byte in the first 8 KiB: skipped, with a notice.
    Binary,
}

fn utf16_to_utf8(body: &[u8], big_endian: bool) -> Vec<u8> {
    let (pairs, rest) = body.as_chunks::<2>();
    let units = pairs.iter().map(|&pair| {
        if big_endian {
            u16::from_be_bytes(pair)
        } else {
            u16::from_le_bytes(pair)
        }
    });
    let mut text: String = char::decode_utf16(units)
        .map(|r| r.unwrap_or(char::REPLACEMENT_CHARACTER))
        .collect();
    if !rest.is_empty() {
        text.push(char::REPLACEMENT_CHARACTER);
    }
    text.into_bytes()
}

/// Classifies a file's bytes: a UTF-16 byte order mark (`FF FE` or `FE FF`) means UTF-16 text
/// (its NUL bytes are not a binary marker); otherwise a NUL byte in the first 8 KiB means binary.
#[must_use]
pub fn classify(bytes: &[u8]) -> Content<'_> {
    match bytes.get(..2) {
        Some([0xFF, 0xFE]) => Content::Text(Cow::Owned(utf16_to_utf8(
            bytes.get(2..).unwrap_or_default(),
            false,
        ))),
        Some([0xFE, 0xFF]) => Content::Text(Cow::Owned(utf16_to_utf8(
            bytes.get(2..).unwrap_or_default(),
            true,
        ))),
        _ if bytes.iter().take(BINARY_PROBE_LEN).any(|&b| b == 0) => Content::Binary,
        _ => Content::Text(Cow::Borrowed(bytes)),
    }
}
