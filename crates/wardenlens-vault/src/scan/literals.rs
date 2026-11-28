//! The literal texts of one value for the redaction filter (ADR 0006 amendment, #76).
//!
//! The leak scan asks "does this text contain a vault value"; the filter has to *replace* it, so
//! it needs the same renderings as plain byte strings. This reuses [`expand`] (the percent
//! forms, base64, hex, XML escape and the squeezed forms) and adds the text forms of the
//! numeric kinds (IPv4, IPv6, MAC) that the scan matches by number.

use std::collections::HashMap;

use percent_encoding::percent_encode;
use wardenlens_core::entry::EntryKind;
use zeroize::Zeroizing;

use super::needles::{Expansion, Net, UNRESERVED, expand};
use super::net::{self, Owners};

/// The longest token, in bytes, that a redaction window must hold whole: an IPv6 address is at
/// most 45 bytes and a MAC with one-digit groups and four-byte separators at most 32. A match that
/// starts at least this far from the end of the data is final.
pub(crate) const MAX_TOKEN: usize = 64;

/// The stored addresses (IPv4, IPv6 and MAC as numbers). The text is tokenised by the scan's own
/// recognisers (`scan/net.rs`), so redact and scan agree on what is an address: zero-padded,
/// dashed, compressed, mapped and unpadded spellings all canonicalise to the stored number.
#[derive(Default)]
pub(crate) struct Addresses {
    v4: HashMap<u32, Owners>,
    v6: HashMap<u128, Owners>,
    mac: HashMap<u64, Owners>,
}

impl Addresses {
    /// True if no address is stored (nothing to tokenise).
    pub(crate) fn is_empty(&self) -> bool {
        self.v4.is_empty() && self.v6.is_empty() && self.mac.is_empty()
    }

    fn add(&mut self, n: &Net) {
        match n {
            Net::V4(k) => drop(self.v4.insert(*k, vec![0])),
            Net::V6(k) => drop(self.v6.insert(*k, vec![0])),
            Net::Mac(k) => drop(self.mac.insert(*k, vec![0])),
        }
    }

    /// Appends the byte range of every token in `text` that is a stored address.
    pub(crate) fn ranges(&self, text: &[u8], out: &mut Vec<(usize, usize)>) {
        let mut hit = |_owners: &[u32], start: usize, end: usize| out.push((start, end));
        net::ipv4(text, &self.v4, &mut hit);
        net::ipv6(text, &self.v6, &self.v4, &mut hit);
        net::mac(text, &self.mac, &mut hit);
    }
}

/// Every literal rendering of `value` that the filter replaces, or `None` if the entry cannot
/// be redacted safely (too short, or an unusable value): such an entry is listed, never
/// partly replaced. A host, IP or MAC value goes into `addresses` instead (tokenised, not
/// spelled out). The texts are folded (lower case) where the scan folds; the filter matches
/// ASCII case only.
pub(crate) fn literals(
    kind: EntryKind,
    value: &str,
    addresses: &mut Addresses,
) -> Option<Vec<Zeroizing<String>>> {
    let Expansion::Scannable { literals, net } = expand(kind, value) else {
        return None;
    };
    let mut out: Vec<Zeroizing<String>> = literals.into_iter().map(|l| l.text).collect();
    let is_address = !net.is_empty();
    for n in &net {
        addresses.add(n);
    }
    // The stored text as it is, for kinds whose scan form is folded or normalised. An address
    // is matched as a token only: as a substring `192.0.2.7` would also eat part of `1192.0.2.7`.
    let raw = value.trim();
    if !is_address && !raw.is_empty() && raw.len() >= crate::MIN_SCANNABLE_LEN {
        out.push(Zeroizing::new(raw.to_owned()));
    }
    Some(out)
}

/// The URL userinfo renderings of a credential (`user:password@`, raw and percent-encoded in
/// both cases), so a whole `rtsp://user:password@host` prefix is replaced and not only the
/// password inside it. Empty if the result would be shorter than the scan minimum.
pub(crate) fn userinfo_literals(user: &str, pass: &str) -> Vec<String> {
    let upper = |s: &str| percent_encode(s.as_bytes(), UNRESERVED).to_string();
    let lower = |s: &str| {
        let mut o = String::with_capacity(s.len());
        for chunk in percent_encode(s.as_bytes(), UNRESERVED) {
            if chunk.starts_with('%') {
                o.push_str(&chunk.to_ascii_lowercase());
            } else {
                o.push_str(chunk);
            }
        }
        o
    };
    vec![
        format!("{user}:{pass}@"),
        format!("{}:{}@", upper(user), upper(pass)),
        format!("{}:{}@", lower(user), lower(pass)),
    ]
    .into_iter()
    .filter(|t| t.len() >= crate::MIN_SCANNABLE_LEN)
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ranges(kind: EntryKind, value: &str, text: &str) -> Vec<(usize, usize)> {
        let mut a = Addresses::default();
        assert!(literals(kind, value, &mut a).is_some());
        let mut out = Vec::new();
        a.ranges(text.as_bytes(), &mut out);
        out
    }

    #[test]
    fn numeric_kinds_are_tokenised_not_spelled_out() {
        let t = "peer ip-192-0-2-7.lan up";
        let r = ranges(EntryKind::Host, "192.0.2.7", t);
        assert_eq!(r.first().map(|&(s, e)| &t[s..e]), Some("192-0-2-7"));
        let t = "hw AABB-CC00-1122 up";
        let r = ranges(EntryKind::Mac, "AA:BB:CC:00:11:22", t);
        assert_eq!(r.first().map(|&(s, e)| &t[s..e]), Some("AABB-CC00-1122"));
        let t = "x 2001:0db8::0007 y";
        let r = ranges(EntryKind::Host, "2001:db8::7", t);
        assert_eq!(r.first().map(|&(s, e)| &t[s..e]), Some("2001:0db8::0007"));
    }

    #[test]
    fn a_short_value_has_no_literals() {
        assert!(literals(EntryKind::Secret, "short", &mut Addresses::default()).is_none());
    }

    #[test]
    fn max_token_covers_the_longest_recognised_forms() {
        // 45 bytes: a full IPv6 address; 32: a MAC of six one-digit groups with 4-byte separators.
        const { assert!(MAX_TOKEN >= 45 && MAX_TOKEN >= 32) };
    }
}
