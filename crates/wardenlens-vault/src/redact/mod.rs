//! The streaming redaction filter (ADR 0006 amendment, #76).
//!
//! A [`Redactor`] replaces every occurrence of every vault value, in the literal renderings the
//! leak scan knows (raw, percent, base64, hex, XML escape, the `user:password@` prefix), and every
//! token that is a stored IPv4, IPv6 or MAC address in any spelling the scan's own recognisers
//! accept (`scan/net.rs`), with the fixed [`MARKER`]. It does not guess what looks like a secret.
//! The marker is the same for every value and run, so the output reveals neither which entry
//! matched nor how long it was; overlapping and touching matches become one marker.
//!
//! Matching ignores ASCII case only. The input is not squeezed (zero-width characters, fullwidth
//! letters and runs of white space are not normalised), and the decoded, JSON-unescaped and
//! line-split views are not applied: `vault scan` finds those, the filter does not replace them.
//!
//! [`Redactor::filter`] reads in bounded chunks and keeps at most `max(longest needle - 1,
//! MAX_TOKEN)` bytes (plus one chunk and a short left context) in memory, so a match or an
//! address token split across two reads is still found. The output is the same whatever the chunk
//! sizes of the input. Nothing here prints or returns a value.

use std::io::{self, Read, Write};

use aho_corasick::{AhoCorasick, MatchKind};
use secrecy::ExposeSecret;
use wardenlens_core::entry::{EntryId, EntryKind};

use zeroize::Zeroizing;

use crate::scan::{
    Addresses, MAX_NEEDLE_BYTES, MAX_TOKEN, ScanError, redaction_literals, userinfo_literals,
};
use crate::store::{MAX_ENTRIES, Value, Vault};

/// What replaces a value. Fixed text: it carries no length and no entry name.
pub const MARKER: &[u8] = b"[REDACTED]";

/// Bytes read from the input at a time.
const CHUNK: usize = 64 * 1024;

/// Bytes of already written input kept in front of the window, so that a token that starts in the
/// window is recognised as the scan would see it (the byte before it is known).
const CONTEXT: usize = 16;

/// Why filtering stopped. Carries no input bytes and no value.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RedactError {
    /// The input could not be read.
    #[error("reading the input failed")]
    Read(#[source] io::Error),
    /// The output could not be written.
    #[error("writing the output failed")]
    Write(#[source] io::Error),
    /// The matching automaton failed.
    #[error("the needle automaton failed")]
    Automaton,
}

/// An entry whose own value the filter cannot use (too short to match safely, or unusable): it is
/// listed so the gap is visible and its value is never replaced. The store's `unscannable` flag is
/// not consulted: such an entry is decrypted and matched like any other, which masks more, never
/// less. For a credential with a short password the `user:password@` prefix is still replaced
/// when it is long enough.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Unredactable {
    /// The entry id.
    pub id: EntryId,
    /// The entry kind.
    pub kind: EntryKind,
}

/// The compiled needles of a vault. `Debug` shows counts only.
pub struct Redactor {
    ac: Option<AhoCorasick>,
    addresses: Addresses,
    /// Bytes a match may need after its start: the window kept between reads.
    keep: usize,
    needles: usize,
    unredactable: Vec<Unredactable>,
}

impl std::fmt::Debug for Redactor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Redactor")
            .field("needles", &self.needles)
            .field("unredactable", &self.unredactable.len())
            .finish_non_exhaustive()
    }
}

/// One entry's value as the filter needs it: a credential keeps its two fields.
struct Item {
    id: EntryId,
    kind: EntryKind,
    user: Option<Zeroizing<String>>,
    secret: Zeroizing<String>,
}

impl Redactor {
    /// Builds the filter from every entry of an open vault.
    ///
    /// # Errors
    /// [`ScanError::Vault`] for a corrupt entry or a store failure, and the limits of
    /// [`Redactor::new`] as [`ScanError::TooManyEntries`] and [`ScanError::NeedlesTooLarge`].
    pub fn from_vault(vault: &Vault) -> Result<Self, ScanError> {
        let mut items = Vec::new();
        for info in vault.list()? {
            let Some(entry) = vault.get(&info.id).map_err(ScanError::from)? else {
                continue;
            };
            let (user, secret) = match entry.value {
                Value::Credential(c) => (
                    Some(Zeroizing::new(c.username.clone())),
                    Zeroizing::new(c.password.expose_secret().to_owned()),
                ),
                Value::Text(t) => (None, Zeroizing::new(t.expose_secret().to_owned())),
            };
            items.push(Item {
                id: info.id,
                kind: info.kind,
                user,
                secret,
            });
        }
        Self::build(&items)
    }

    /// Builds the filter from `(id, kind, username, value)` tuples; the username is for
    /// credentials only (the value is then the password).
    ///
    /// # Errors
    /// [`ScanError::TooManyEntries`], [`ScanError::NeedlesTooLarge`] or [`ScanError::Automaton`].
    pub fn new(entries: &[(EntryId, EntryKind, Option<&str>, &str)]) -> Result<Self, ScanError> {
        let items: Vec<Item> = entries
            .iter()
            .map(|(id, kind, user, secret)| Item {
                id: id.clone(),
                kind: *kind,
                user: user.map(|u| Zeroizing::new(u.to_owned())),
                secret: Zeroizing::new((*secret).to_owned()),
            })
            .collect();
        Self::build(&items)
    }

    fn build(items: &[Item]) -> Result<Self, ScanError> {
        if items.len() > MAX_ENTRIES {
            return Err(ScanError::TooManyEntries);
        }
        let mut texts: Vec<Zeroizing<String>> = Vec::new();
        let mut addresses = Addresses::default();
        let mut unredactable = Vec::new();
        for item in items {
            match redaction_literals(item.kind, &item.secret, &mut addresses) {
                Some(l) => texts.extend(l),
                None => unredactable.push(Unredactable {
                    id: item.id.clone(),
                    kind: item.kind,
                }),
            }
            if let Some(user) = &item.user {
                // A short username (`admin`) is public text; only a long one is a needle.
                texts.extend(
                    redaction_literals(EntryKind::Secret, user, &mut Addresses::default())
                        .unwrap_or_default(),
                );
                texts.extend(
                    userinfo_literals(user, &item.secret)
                        .into_iter()
                        .map(Zeroizing::new),
                );
            }
        }
        texts.sort_by(|a, b| a.as_str().cmp(b.as_str()));
        texts.dedup_by(|a, b| a.as_str() == b.as_str());
        let total = texts.iter().fold(0usize, |a, t| a.saturating_add(t.len()));
        if total > MAX_NEEDLE_BYTES {
            return Err(ScanError::NeedlesTooLarge);
        }
        let longest = texts.iter().map(|t| t.len()).max().unwrap_or(0);
        let needles = texts.len();
        let ac = if texts.is_empty() {
            None
        } else {
            // Standard matching, so overlapping searches find every needle at every position.
            Some(
                AhoCorasick::builder()
                    .match_kind(MatchKind::Standard)
                    .ascii_case_insensitive(true)
                    .build(texts.iter().map(|t| t.as_bytes()))
                    .map_err(|_| ScanError::Automaton)?,
            )
        };
        let token = if addresses.is_empty() { 0 } else { MAX_TOKEN };
        Ok(Self {
            ac,
            addresses,
            keep: longest.saturating_sub(1).max(token),
            needles,
            unredactable,
        })
    }

    /// The entries that are not replaced.
    #[must_use]
    pub fn unredactable(&self) -> &[Unredactable] {
        &self.unredactable
    }

    /// How many distinct literal needles are compiled (zero for an empty vault).
    #[cfg(test)]
    pub(crate) fn needle_count(&self) -> usize {
        self.needles
    }

    /// Copies `input` to `out`, replacing every match with [`MARKER`]. Bytes that are not part
    /// of a match are copied unchanged, whatever they are.
    ///
    /// # Errors
    /// [`RedactError::Read`] and [`RedactError::Write`]; bytes already written were redacted.
    pub fn filter<R: Read, W: Write>(&self, input: R, out: W) -> Result<(), RedactError> {
        self.filter_with(input, out, CHUNK)
    }

    pub(crate) fn filter_with<R: Read, W: Write>(
        &self,
        mut input: R,
        mut out: W,
        chunk: usize,
    ) -> Result<(), RedactError> {
        let keep = self.keep;
        let mut read_buf = vec![0u8; chunk.max(1)];
        let mut buf: Vec<u8> = Vec::new();
        let mut context: Vec<u8> = Vec::new();
        let mut state = Carry::default();
        loop {
            let n = match input.read(&mut read_buf) {
                Ok(n) => n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(RedactError::Read(e)),
            };
            let eof = n == 0;
            buf.extend_from_slice(read_buf.get(..n).unwrap_or_default());
            // A match that starts before `safe` is entirely inside the buffer, because every
            // needle is at most `keep + 1` bytes: it is final. Later starts wait for more input.
            let safe = if eof {
                buf.len()
            } else {
                buf.len().saturating_sub(keep)
            };
            state = self.round(&context, &buf, safe, state, &mut out)?;
            context.extend_from_slice(buf.get(..safe).unwrap_or_default());
            let excess = context.len().saturating_sub(CONTEXT);
            context.drain(..excess);
            buf.drain(..safe);
            if eof {
                return out.flush().map_err(RedactError::Write);
            }
            out.flush().map_err(RedactError::Write)?;
        }
    }

    /// Writes the first `safe` bytes of `buf`, redacted, and returns what carries over. `context`
    /// is the input that precedes `buf` (already written), for the address tokeniser.
    fn round<W: Write>(
        &self,
        context: &[u8],
        buf: &[u8],
        safe: usize,
        carry: Carry,
        out: &mut W,
    ) -> Result<Carry, RedactError> {
        let w = |out: &mut W, b: &[u8]| out.write_all(b).map_err(RedactError::Write);
        // reach[i]: the furthest end of a match that starts at i.
        let mut reach = vec![0usize; safe];
        let mut note = |start: usize, end: usize| {
            if let Some(slot) = reach.get_mut(start)
                && end > *slot
            {
                *slot = end.min(buf.len());
            }
        };
        if let Some(ac) = &self.ac {
            for m in ac
                .try_find_overlapping_iter(buf)
                .map_err(|_| RedactError::Automaton)?
            {
                note(m.start(), m.end());
            }
        }
        if !self.addresses.is_empty() {
            let mut hay = Vec::with_capacity(context.len().saturating_add(buf.len()));
            hay.extend_from_slice(context);
            hay.extend_from_slice(buf);
            let mut found = Vec::new();
            self.addresses.ranges(&hay, &mut found);
            for (s, e) in found {
                // A token that starts in the context was decided in an earlier round.
                if let Some(start) = s.checked_sub(context.len()) {
                    note(start, e.saturating_sub(context.len()));
                }
            }
        }
        let mut run_end = carry.covered;
        let mut in_run = carry.in_run;
        let mut lit_start = 0usize;
        for (i, r) in reach.iter().enumerate() {
            run_end = run_end.max(*r);
            if i < run_end {
                if !in_run {
                    w(out, buf.get(lit_start..i).unwrap_or_default())?;
                    w(out, MARKER)?;
                    in_run = true;
                }
                lit_start = i.saturating_add(1);
            } else if in_run {
                in_run = false;
                lit_start = i;
            }
        }
        if !in_run {
            w(out, buf.get(lit_start..safe).unwrap_or_default())?;
        }
        Ok(Carry {
            covered: run_end.saturating_sub(safe),
            in_run,
        })
    }
}

/// What one round hands to the next: how many leading bytes of the kept tail are already
/// replaced, and whether the last thing written was a marker (so a touching match joins it).
#[derive(Debug, Default, Clone, Copy)]
struct Carry {
    covered: usize,
    in_run: bool,
}

#[cfg(test)]
mod tests;
