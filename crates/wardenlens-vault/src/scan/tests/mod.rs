//! Tests of the exact-match scan. Synthetic values only: TEST-NET addresses, `*.invalid`
//! names and made-up secrets.
//!
//! A JSON `\uXXXX` escape is built with `esc!` so that no tool between the author and the
//! compiler can turn the escape text into the character it spells.

#![expect(
    clippy::arithmetic_side_effects,
    reason = "test arithmetic on small line counts and indices"
)]

mod edges;
mod props;
mod table;

use secrecy::SecretString;
use wardenlens_core::entry::{EntryId, EntryKind};

use super::{Hit, Matcher, ScanEntry, scan};

/// The text `\u` followed by four hex digits (a JSON escape as literal text).
macro_rules! esc {
    ($hex:literal) => {
        concat!("\\u", $hex)
    };
}
pub(super) use esc;

pub(super) fn id(s: &str) -> EntryId {
    EntryId::new(s).unwrap()
}

pub(super) fn entry(name: &str, kind: EntryKind, value: &str) -> ScanEntry {
    ScanEntry {
        id: id(name),
        kind,
        value: SecretString::from(value.to_owned()),
        unscannable: false,
    }
}

pub(super) fn matcher(entries: &[ScanEntry]) -> Matcher {
    Matcher::new(entries).unwrap()
}

/// All hits of `text` against one entry stored as `kind` / `value`.
pub(super) fn hits(kind: EntryKind, value: &str, text: &[u8]) -> Vec<Hit> {
    let m = matcher(&[entry("e:one", kind, value)]);
    scan(&m, text).unwrap().hits
}

pub(super) fn lines(kind: EntryKind, value: &str, text: &[u8]) -> Vec<usize> {
    hits(kind, value, text).iter().map(|h| h.line).collect()
}
