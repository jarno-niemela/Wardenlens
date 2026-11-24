//! Building the matcher: needle expansion, deduplication across entries and the automata.

use std::collections::HashMap;
use std::fmt;

use aho_corasick::{AhoCorasick, MatchKind};
use secrecy::ExposeSecret;
use wardenlens_core::entry::{EntryId, EntryKind};

use super::needles::{Boundary, Expansion, Literal, Net, expand};
use super::net::Owners;
use super::{MAX_NEEDLE_BYTES, ScanEntry, ScanError, Unscannable};
use crate::store::{MAX_ENTRIES, Value, Vault};

/// An entry that is scanned (the name and kind a hit reports).
pub(super) struct Scanned {
    pub(super) id: EntryId,
    pub(super) kind: EntryKind,
}

/// One distinct needle text with its boundary rule and every entry that owns it. Entries with
/// identical values share a needle, and each is reported.
pub(super) struct Pattern {
    pub(super) boundary: Boundary,
    /// `(entry index, views)`: the same text can apply to different views for different entries.
    pub(super) owners: Vec<(u32, u8)>,
}

/// An Aho-Corasick automaton over the needles of one flavour (exact or folded).
pub(super) struct Automaton {
    pub(super) ac: Option<AhoCorasick>,
    pub(super) patterns: Vec<Pattern>,
}

#[derive(Default)]
struct PatternSet {
    index: HashMap<(Vec<u8>, Boundary), usize>,
    texts: Vec<Vec<u8>>,
    patterns: Vec<Pattern>,
}

impl PatternSet {
    fn add(&mut self, literal: Literal, entry: u32) {
        let key = (literal.text.into_bytes(), literal.boundary);
        let id = if let Some(&id) = self.index.get(&key) {
            id
        } else {
            let id = self.patterns.len();
            self.texts.push(key.0.clone());
            self.patterns.push(Pattern {
                boundary: key.1,
                owners: Vec::new(),
            });
            self.index.insert(key, id);
            id
        };
        if let Some(p) = self.patterns.get_mut(id) {
            match p.owners.last_mut() {
                Some((e, views)) if *e == entry => *views |= literal.views,
                _ => p.owners.push((entry, literal.views)),
            }
        }
    }

    fn build(self) -> Result<Automaton, ScanError> {
        let ac = if self.texts.is_empty() {
            None
        } else {
            // Standard matching is required for overlapping searches, which find every needle
            // at every position so the boundary rule can be applied to each.
            Some(
                AhoCorasick::builder()
                    .match_kind(MatchKind::Standard)
                    .build(&self.texts)
                    .map_err(|_| ScanError::Automaton)?,
            )
        };
        Ok(Automaton {
            ac,
            patterns: self.patterns,
        })
    }
}

/// The compiled needles of a vault. Holds no value in a printable form: `Debug` shows counts.
pub struct Matcher {
    pub(super) entries: Vec<Scanned>,
    unscannable: Vec<Unscannable>,
    pub(super) exact: Automaton,
    pub(super) folded: Automaton,
    /// Only the joined view can match a needle that holds a space, so it is built only then.
    pub(super) needs_joined: bool,
    pub(super) v4: HashMap<u32, Owners>,
    pub(super) v6: HashMap<u128, Owners>,
    pub(super) mac: HashMap<u64, Owners>,
}

impl fmt::Debug for Matcher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Matcher")
            .field("entries", &self.entries.len())
            .field("unscannable", &self.unscannable.len())
            .finish_non_exhaustive()
    }
}

impl Matcher {
    /// Expands every entry into its needles and compiles them.
    ///
    /// An entry whose value (or any needle after the squeeze and the fold) is under 7 bytes, or
    /// that the store marked unscannable, is listed by [`Matcher::unscannable`] and never partly
    /// scanned. IPv4, IPv6 and MAC values have fixed formats and are exempt from the minimum.
    ///
    /// # Errors
    /// [`ScanError::TooManyEntries`] over 10,000 entries, [`ScanError::NeedlesTooLarge`] if the
    /// needles exceed [`MAX_NEEDLE_BYTES`] in total, [`ScanError::Automaton`] if the automaton
    /// cannot be built.
    pub fn new(entries: &[ScanEntry]) -> Result<Self, ScanError> {
        if entries.len() > MAX_ENTRIES {
            return Err(ScanError::TooManyEntries);
        }
        let mut exact = PatternSet::default();
        let mut folded = PatternSet::default();
        let mut scanned = Vec::new();
        let mut unscannable = Vec::new();
        let (mut v4, mut v6, mut mac) = (HashMap::new(), HashMap::new(), HashMap::new());
        let mut budget = 0usize;
        let mut needs_joined = false;
        for e in entries {
            let expansion = if e.unscannable {
                Expansion::Unscannable
            } else {
                expand(e.kind, e.value.expose_secret())
            };
            let Expansion::Scannable { literals, net } = expansion else {
                unscannable.push(Unscannable {
                    id: e.id.clone(),
                    kind: e.kind,
                });
                continue;
            };
            let index = u32::try_from(scanned.len()).map_err(|_| ScanError::TooManyEntries)?;
            scanned.push(Scanned {
                id: e.id.clone(),
                kind: e.kind,
            });
            for n in net {
                match n {
                    Net::V4(k) => push_owner(&mut v4, k, index),
                    Net::V6(k) => push_owner(&mut v6, k, index),
                    Net::Mac(k) => push_owner(&mut mac, k, index),
                }
            }
            for l in literals {
                budget = budget.saturating_add(l.text.len());
                if budget > MAX_NEEDLE_BYTES {
                    return Err(ScanError::NeedlesTooLarge);
                }
                if l.folded {
                    needs_joined |= l.text.contains(' ');
                    folded.add(l, index);
                } else {
                    exact.add(l, index);
                }
            }
        }
        Ok(Self {
            entries: scanned,
            unscannable,
            exact: exact.build()?,
            folded: folded.build()?,
            needs_joined,
            v4,
            v6,
            mac,
        })
    }

    /// Builds a matcher from every entry of an open vault. Entries the store marked unscannable
    /// are not decrypted.
    ///
    /// # Errors
    /// [`ScanError::Vault`] for a corrupt entry or a store failure, and the errors of
    /// [`Matcher::new`].
    pub fn from_vault(vault: &Vault) -> Result<Self, ScanError> {
        let mut entries = Vec::new();
        for info in vault.list()? {
            let value = if info.unscannable {
                secrecy::SecretString::from(String::new())
            } else {
                match vault.get(&info.id)? {
                    Some(entry) => match entry.value {
                        Value::Credential(c) => c.password,
                        Value::Text(t) => t,
                    },
                    // Removed between `list` and `get`: nothing to scan.
                    None => continue,
                }
            };
            entries.push(ScanEntry {
                id: info.id,
                kind: info.kind,
                value,
                unscannable: info.unscannable,
            });
        }
        Self::new(&entries)
    }

    /// The entries the scan cannot use, to be listed on every scan.
    #[must_use]
    pub fn unscannable(&self) -> &[Unscannable] {
        &self.unscannable
    }

    /// How many entries are scanned.
    #[must_use]
    pub fn scanned_len(&self) -> usize {
        self.entries.len()
    }
}

fn push_owner<K: std::hash::Hash + Eq>(map: &mut HashMap<K, Owners>, key: K, entry: u32) {
    let owners = map.entry(key).or_default();
    if !owners.contains(&entry) {
        owners.push(entry);
    }
}
