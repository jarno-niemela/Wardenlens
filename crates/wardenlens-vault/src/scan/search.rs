//! Matching one input in every view (ADR 0006 section 7).
//!
//! Views: raw (unsqueezed needles), squeezed (squeezed needles), decoded and JSON-unescaped
//! (both), joined (squeezed needles; display names and `other` only). Needles of folded kinds
//! are matched in lowercased copies of the views. A view that would equal the squeezed view
//! (no `%`, no backslash) is not built: it cannot match anything the squeezed view does not.

use std::borrow::Cow;
use std::collections::HashSet;

use super::matcher::{Automaton, Matcher};
use super::needles::{Boundary, view};
use super::squeeze::{fold, lossy, squeeze_lossy};
use super::views::{View, joined_folded, json_unescaped, percent_decoded};
use super::{Hit, MAX_HITS, MAX_INPUT_LEN, ScanError, ScanReport, net};

/// Distinct `(entry, line)` pairs, bounded by [`MAX_HITS`].
#[derive(Default)]
struct Found {
    seen: HashSet<(u32, u32)>,
    list: Vec<(u32, u32)>,
    truncated: bool,
}

impl Found {
    /// Records a hit. A new pair beyond [`MAX_HITS`] only sets `truncated`.
    fn add(&mut self, entry: u32, line: u32) {
        if self.truncated || self.seen.contains(&(entry, line)) {
            return;
        }
        if self.list.len() >= MAX_HITS {
            self.truncated = true;
            return;
        }
        self.seen.insert((entry, line));
        self.list.push((line, entry));
    }
}

fn is_alnum(b: Option<&u8>) -> bool {
    b.is_some_and(u8::is_ascii_alphanumeric)
}

fn boundary_ok(rule: Boundary, bytes: &[u8], start: usize, end: usize) -> bool {
    let before = start.checked_sub(1).and_then(|i| bytes.get(i));
    let after = bytes.get(end);
    match rule {
        Boundary::None => true,
        Boundary::Alnum => !is_alnum(before) && !is_alnum(after),
        Boundary::Dns => {
            let word = |b: Option<&u8>| is_alnum(b) || matches!(b, Some(b'-' | b'_'));
            !word(before) && !word(after)
        }
    }
}

fn literals(set: &Automaton, v: &View<'_>, bit: u8, found: &mut Found) -> Result<(), ScanError> {
    let Some(ac) = &set.ac else { return Ok(()) };
    // The last line a pattern was reported on in this view: its owners are done for it, so
    // a text full of one needle costs O(1) per match, not O(owners).
    let mut last = vec![0u32; set.patterns.len()];
    for m in ac
        .try_find_overlapping_iter(v.bytes.as_ref())
        .map_err(|_| ScanError::Automaton)?
    {
        if found.truncated {
            break;
        }
        let id = m.pattern().as_usize();
        let (Some(p), Some(done)) = (set.patterns.get(id), last.get_mut(id)) else {
            continue;
        };
        if !boundary_ok(p.boundary, &v.bytes, m.start(), m.end()) {
            continue;
        }
        let line = v.line_at(m.start());
        if *done == line {
            continue;
        }
        *done = line;
        for &(entry, views) in &p.owners {
            if views & bit != 0 {
                found.add(entry, line);
            }
        }
    }
    Ok(())
}

impl Matcher {
    fn tokens(&self, v: &View<'_>, found: &mut Found) {
        let mut hit = |owners: &[u32], at: usize| {
            let line = v.line_at(at);
            for &o in owners {
                found.add(o, line);
            }
        };
        net::ipv4(&v.bytes, &self.v4, &mut hit);
        net::ipv6(&v.bytes, &self.v6, &self.v4, &mut hit);
        net::mac(&v.bytes, &self.mac, &mut hit);
    }

    /// One text view, exact and folded, with the bit of the needles that apply to it.
    fn text_view(&self, text: &[u8], bit: u8, found: &mut Found) -> Result<(), ScanError> {
        let exact = View::new(Cow::Borrowed(text));
        literals(&self.exact, &exact, bit, found)?;
        self.tokens(&exact, found);
        if self.folded.ac.is_some() {
            let lowered = fold(&lossy(text)).into_bytes();
            literals(&self.folded, &View::new(Cow::Owned(lowered)), bit, found)?;
        }
        Ok(())
    }

    pub(super) fn scan(&self, input: &[u8]) -> Result<ScanReport, ScanError> {
        if input.len() > MAX_INPUT_LEN {
            return Err(ScanError::InputTooLarge);
        }
        let mut found = Found::default();
        self.text_view(input, view::RAW, &mut found)?;
        let squeezed = squeeze_lossy(input);
        self.text_view(squeezed.as_bytes(), view::SQUEEZED, &mut found)?;
        if squeezed.contains('%') {
            let decoded = percent_decoded(&squeezed);
            self.text_view(decoded.as_bytes(), view::DECODED, &mut found)?;
        }
        if squeezed.contains('\\') {
            let json = json_unescaped(&squeezed);
            self.text_view(json.as_bytes(), view::JSON, &mut found)?;
        }
        if self.needs_joined && self.folded.ac.is_some() {
            let joined = joined_folded(&squeezed);
            literals(&self.folded, &joined, view::JOINED, &mut found)?;
        }
        Ok(self.report(found))
    }

    fn report(&self, found: Found) -> ScanReport {
        let mut list = found.list;
        list.sort_unstable();
        let hits = list
            .into_iter()
            .filter_map(|(line, entry)| {
                let e = self.entries.get(usize::try_from(entry).ok()?)?;
                Some(Hit {
                    line: usize::try_from(line).ok()?,
                    id: e.id.clone(),
                    kind: e.kind,
                })
            })
            .collect();
        ScanReport {
            hits,
            truncated: found.truncated,
        }
    }
}
