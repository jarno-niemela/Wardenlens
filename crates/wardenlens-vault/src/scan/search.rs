//! Matching one input in every view (ADR 0006 section 7).
//!
//! Views: raw (unsqueezed needles); squeezed (invisible characters deleted); the boundary form
//! (each dropped invisible character a space, so a value glued to a letter by one keeps a
//! non-alphanumeric neighbour); joined (display names and `other` only; built from the squeezed
//! and from the boundary form). The raw and the squeezed text are each decoded (percent and
//! JSON) and every decoded text is searched as it is and in its squeezed, boundary and joined
//! forms. Needles of folded kinds are matched in lowercased copies of the views. A decode that
//! cannot change the text (no `%`, no backslash) is not built.

use std::borrow::Cow;
use std::collections::HashSet;

use super::matcher::{Automaton, Matcher};
use super::needles::{Boundary, view};
use super::squeeze::{fold, lossy, squeeze, squeeze_boundary};
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
        let mut hit = |owners: &[u32], at: usize, _end: usize| {
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

    /// The joined view of an already squeezed text (display names and `other` only).
    fn joined(&self, squeezed: &str, found: &mut Found) -> Result<(), ScanError> {
        if self.needs_joined && self.folded.ac.is_some() {
            literals(&self.folded, &joined_folded(squeezed), view::JOINED, found)?;
        }
        Ok(())
    }

    /// The squeezed forms of `text`: the squeezed view (invisible characters deleted, for a
    /// value with one inside it) and its joined view, and, if `text` holds a dropped invisible
    /// character, the boundary form (each one a space) and its joined view, for a value glued to
    /// a letter by an invisible character. `bit` is the view bit of the squeezed needles.
    fn squeezed_forms(&self, text: &str, bit: u8, found: &mut Found) -> Result<(), ScanError> {
        let squeezed = squeeze(text);
        self.text_view(squeezed.as_bytes(), bit, found)?;
        self.joined(&squeezed, found)?;
        if let Some(spaced) = squeeze_boundary(text) {
            self.text_view(spaced.as_bytes(), bit, found)?;
            self.joined(&spaced, found)?;
        }
        Ok(())
    }

    /// A decoded text, searched as it is (a value glued behind a decoded invisible character
    /// keeps its boundary) and in its squeezed forms (decoding can produce characters the
    /// squeeze maps or drops). Neither form loses a hit the other finds.
    fn decoded(&self, text: &str, bit: u8, found: &mut Found) -> Result<(), ScanError> {
        self.text_view(text.as_bytes(), bit, found)?;
        self.squeezed_forms(text, bit, found)
    }

    /// Decodes `text` (and its squeezed form: a squeeze can join the halves of an escape
    /// that an invisible character split) and searches each result with `decoded`. The raw text
    /// is decoded too, so a literal invisible character before an encoded value is still there
    /// when the boundary is checked.
    fn decode_with(
        &self,
        text: &str,
        squeezed: &str,
        marker: char,
        decode: fn(&str) -> String,
        bit: u8,
        found: &mut Found,
    ) -> Result<(), ScanError> {
        if text.contains(marker) {
            self.decoded(&decode(text), bit, found)?;
        }
        if squeezed != text && squeezed.contains(marker) {
            self.decoded(&decode(squeezed), bit, found)?;
        }
        Ok(())
    }

    pub(super) fn scan(&self, input: &[u8]) -> Result<ScanReport, ScanError> {
        if input.len() > MAX_INPUT_LEN {
            return Err(ScanError::InputTooLarge);
        }
        let mut found = Found::default();
        self.text_view(input, view::RAW, &mut found)?;
        let text = lossy(input);
        self.squeezed_forms(&text, view::SQUEEZED, &mut found)?;
        // Decoded views go through the same squeeze and join as the raw text (one place), so a
        // name written with an escaped no-break space still matches its plain-space needle.
        let squeezed = squeeze(&text);
        self.decode_with(
            &text,
            &squeezed,
            '%',
            percent_decoded,
            view::DECODED,
            &mut found,
        )?;
        self.decode_with(
            &text,
            &squeezed,
            '\\',
            json_unescaped,
            view::JSON,
            &mut found,
        )?;
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
