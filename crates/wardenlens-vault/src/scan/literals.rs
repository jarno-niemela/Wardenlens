//! The literal texts of one value for the redaction filter (ADR 0006 amendment, #76).
//!
//! The leak scan asks "does this text contain a vault value"; the filter has to *replace* it, so
//! it needs the same renderings as plain byte strings. This reuses [`expand`] (the percent
//! forms, base64, hex, XML escape and the squeezed forms) and adds the text forms of the
//! numeric kinds (IPv4, IPv6, MAC) that the scan matches by number.

use std::net::{Ipv4Addr, Ipv6Addr};

use wardenlens_core::entry::EntryKind;

use percent_encoding::percent_encode;

use super::needles::{Expansion, Net, UNRESERVED, expand};

fn mac_texts(n: u64) -> Vec<String> {
    let bytes: Vec<u8> = n.to_be_bytes().iter().skip(2).copied().collect();
    let join = |sep: &str| {
        bytes
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(sep)
    };
    let flat = join("");
    let dotted = flat
        .as_bytes()
        .chunks(4)
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .collect::<Vec<_>>()
        .join(".");
    vec![join(":"), join("-"), flat, dotted]
}

fn v6_texts(n: u128) -> Vec<String> {
    let a = Ipv6Addr::from(n);
    let groups = a.segments();
    let padded = groups
        .iter()
        .map(|g| format!("{g:04x}"))
        .collect::<Vec<_>>()
        .join(":");
    let bare = groups
        .iter()
        .map(|g| format!("{g:x}"))
        .collect::<Vec<_>>()
        .join(":");
    vec![a.to_string(), padded, bare]
}

/// Every literal rendering of `value` that the filter replaces, or `None` if the entry cannot
/// be redacted safely (too short, or an unusable value): such an entry is listed, never
/// partly replaced. The texts are folded (lower case) where the scan folds; the filter
/// matches ASCII case-insensitively.
pub(crate) fn literals(kind: EntryKind, value: &str) -> Option<Vec<String>> {
    let Expansion::Scannable { literals, net } = expand(kind, value) else {
        return None;
    };
    let mut out: Vec<String> = literals.into_iter().map(|l| l.text).collect();
    for n in net {
        match n {
            Net::V4(k) => out.push(Ipv4Addr::from(k).to_string()),
            Net::V6(k) => out.extend(v6_texts(k)),
            Net::Mac(k) => out.extend(mac_texts(k)),
        }
    }
    // The stored text as it is, for kinds whose scan form is folded or normalised.
    let raw = value.trim();
    if !raw.is_empty() && raw.len() >= crate::MIN_SCANNABLE_LEN {
        out.push(raw.to_owned());
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

    #[test]
    fn numeric_kinds_get_text_forms() {
        let v4 = literals(EntryKind::Host, "192.0.2.7").unwrap_or_default();
        assert!(v4.iter().any(|t| t == "192.0.2.7"));
        let mac = literals(EntryKind::Mac, "AA:BB:CC:00:11:22").unwrap_or_default();
        for want in [
            "aa:bb:cc:00:11:22",
            "aa-bb-cc-00-11-22",
            "aabbcc001122",
            "aabb.cc00.1122",
        ] {
            assert!(mac.iter().any(|t| t == want), "{want}");
        }
        let v6 = literals(EntryKind::Host, "2001:db8::1").unwrap_or_default();
        assert!(v6.iter().any(|t| t == "2001:db8::1"));
        assert!(
            v6.iter()
                .any(|t| t == "2001:0db8:0000:0000:0000:0000:0000:0001")
        );
    }

    #[test]
    fn a_short_value_has_no_literals() {
        assert!(literals(EntryKind::Secret, "short").is_none());
    }
}
