//! The site-data guard. The repository is public, so no string in a catalogue entry may look
//! like data that identifies a particular installation.
//!
//! Heuristics, deliberately conservative (a false positive is fixed by rewording the text):
//!
//! - **IPv4**: any dotted quad (four dot-separated groups of one to three digits, each at most
//!   255), so private, loopback, link-local and public addresses are all refused.
//! - **IPv6**: any token that parses as an IPv6 address, or has three or more colons and only
//!   hex groups.
//! - **MAC**: six hex pairs separated by `:` or `-`, three dotted hex quads, or a run of twelve
//!   or more hex digits.
//! - **Serial-like**: a maximal run of at least ten characters from `[A-Z0-9]`, or of at least
//!   eight digits. Model names such as `IPC-HFW4431R-Z` stay below that because `-` ends a run.
//! - **Credentials**: a `scheme://user:pass@host` URL, or any whitespace-delimited token with
//!   `:` before an `@`.
//! - **Email**: any other token with text on both sides of an `@`.

use std::net::Ipv6Addr;

use super::entry::CatalogueEntry;
use super::error::{CatalogueError, SiteDataKind};

/// Checks an entry for completeness and for site-specific data in any string field.
///
/// # Errors
/// [`CatalogueError::Missing`] for an empty vendor, model or evidence list,
/// [`CatalogueError::OutOfRange`] for implausible stream numbers, and
/// [`CatalogueError::SiteData`] naming the field (never the value) for site data.
pub fn validate(entry: &CatalogueEntry) -> Result<(), CatalogueError> {
    if entry.vendor.trim().is_empty() {
        return Err(CatalogueError::Missing("vendor"));
    }
    if entry.model.trim().is_empty() {
        return Err(CatalogueError::Missing("model"));
    }
    if entry.evidence.is_empty() {
        return Err(CatalogueError::Missing("evidence"));
    }
    for s in &entry.streams {
        let fps_ok = s.fps.is_none_or(|f| f > 0.0 && f <= 240.0);
        let gop_ok = s.gop.is_none_or(|g| (1..=10_000).contains(&g));
        if !(1..=16_384).contains(&s.width) || !(1..=16_384).contains(&s.height) {
            return Err(CatalogueError::OutOfRange("stream resolution"));
        }
        if !fps_ok {
            return Err(CatalogueError::OutOfRange("stream fps"));
        }
        if !gop_ok {
            return Err(CatalogueError::OutOfRange("stream gop"));
        }
    }
    for (field, value) in strings(entry) {
        if let Some(kind) = site_data(value) {
            return Err(CatalogueError::SiteData { field, kind });
        }
    }
    Ok(())
}

/// Every string in the entry with a field label. Exhaustive destructuring means adding a field
/// to `CatalogueEntry` without deciding how to check it fails to compile.
fn strings(entry: &CatalogueEntry) -> Vec<(String, &str)> {
    let CatalogueEntry {
        vendor,
        model,
        aliases,
        quirks,
        evidence,
        protocols,
        support: _,
        firmware: _,
        streams: _,
        events: _,
        configurable: _,
    } = entry;
    let mut out = vec![
        ("vendor".to_owned(), vendor.as_str()),
        ("model".to_owned(), model.as_str()),
    ];
    out.extend(
        aliases
            .iter()
            .enumerate()
            .map(|(i, s)| (format!("aliases[{i}]"), s.as_str())),
    );
    out.extend(
        quirks
            .iter()
            .enumerate()
            .map(|(i, s)| (format!("quirks[{i}]"), s.as_str())),
    );
    for (i, e) in evidence.iter().enumerate() {
        out.push((format!("evidence[{i}].reference"), e.reference.as_str()));
        if let Some(section) = &e.section {
            out.push((format!("evidence[{i}].section"), section.as_str()));
        }
    }
    for (i, p) in protocols.iter().enumerate() {
        out.extend(
            p.paths
                .iter()
                .enumerate()
                .map(|(j, s)| (format!("protocols[{i}].paths[{j}]"), s.as_str())),
        );
    }
    out
}

fn site_data(text: &str) -> Option<SiteDataKind> {
    if has_credentials(text) {
        Some(SiteDataKind::Credentials)
    } else if has_email(text) {
        Some(SiteDataKind::Email)
    } else if has_ipv4(text) {
        Some(SiteDataKind::Ipv4)
    } else if has_mac(text) {
        // Before IPv6: a colon-separated MAC is also a run of hex groups.
        Some(SiteDataKind::Mac)
    } else if has_ipv6(text) {
        Some(SiteDataKind::Ipv6)
    } else if has_serial(text) {
        Some(SiteDataKind::Serial)
    } else {
        None
    }
}

/// `scheme://...@...` authority, or a token with `:` before `@`.
fn has_credentials(text: &str) -> bool {
    let in_authority = text.match_indices("://").any(|(i, sep)| {
        let rest = text.get(i.saturating_add(sep.len())..).unwrap_or_default();
        let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
        authority
            .split_whitespace()
            .next()
            .is_some_and(|a| a.contains('@'))
    });
    in_authority
        || text.split_whitespace().any(|t| {
            !t.contains("://") && at_parts(t).is_some_and(|(before, _)| before.contains(':'))
        })
}

fn has_email(text: &str) -> bool {
    text.split_whitespace().any(|t| at_parts(t).is_some())
}

/// Splits a token at its first `@` when there is text on both sides.
fn at_parts(token: &str) -> Option<(&str, &str)> {
    token
        .split_once('@')
        .filter(|(a, b)| !a.is_empty() && !b.is_empty())
}

fn has_ipv4(text: &str) -> bool {
    text.split(|c: char| !(c.is_ascii_digit() || c == '.'))
        .any(|token| {
            let parts: Vec<&str> = token.split('.').collect();
            parts.windows(4).any(|w| w.iter().all(|p| is_octet(p)))
        })
}

fn is_octet(part: &str) -> bool {
    (1..=3).contains(&part.len())
        && part.bytes().all(|b| b.is_ascii_digit())
        && part.parse::<u8>().is_ok()
}

fn has_ipv6(text: &str) -> bool {
    text.split(|c: char| !(c.is_ascii_hexdigit() || c == ':' || c == '.'))
        .any(|token| {
            if token.parse::<Ipv6Addr>().is_ok()
                || token.trim_end_matches(':').parse::<Ipv6Addr>().is_ok()
            {
                return true;
            }
            token.matches(':').count() >= 3
                && token
                    .split(':')
                    .all(|g| g.len() <= 4 && g.bytes().all(|b| b.is_ascii_hexdigit()))
        })
}

fn has_mac(text: &str) -> bool {
    let b = text.as_bytes();
    let pairs = |w: &[u8], sep: u8| {
        w.chunks(3).enumerate().all(|(i, c)| {
            let hex = c.first().is_some_and(u8::is_ascii_hexdigit)
                && c.get(1).is_some_and(u8::is_ascii_hexdigit);
            let sep_ok = i == 5 || c.get(2) == Some(&sep);
            hex && sep_ok
        })
    };
    let colon_or_dash = b.windows(17).any(|w| pairs(w, b':') || pairs(w, b'-'));
    let dotted = b.windows(14).any(|w| {
        w.chunks(5).enumerate().all(|(i, c)| {
            c.iter().take(4).all(u8::is_ascii_hexdigit) && (i == 2 || c.get(4) == Some(&b'.'))
        })
    });
    colon_or_dash || dotted || max_run(b, u8::is_ascii_hexdigit) >= 12
}

fn has_serial(text: &str) -> bool {
    let b = text.as_bytes();
    max_run(b, |c| c.is_ascii_uppercase() || c.is_ascii_digit()) >= 10
        || max_run(b, u8::is_ascii_digit) >= 8
}

/// Length of the longest run of bytes satisfying `pred`.
fn max_run(bytes: &[u8], pred: impl Fn(&u8) -> bool) -> usize {
    let mut best = 0_usize;
    let mut cur = 0_usize;
    for b in bytes {
        if pred(b) {
            cur = cur.saturating_add(1);
            best = best.max(cur);
        } else {
            cur = 0;
        }
    }
    best
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry_with_quirk(quirk: &str) -> CatalogueEntry {
        let text = format!(
            "vendor=\"A\"\nmodel=\"B\"\nsupport=\"verified\"\nquirks=['''{quirk}''']\n\
             [[evidence]]\nreference=\"docs/adr/0002-camera-integration.md\"\n"
        );
        CatalogueEntry::from_toml_str(&text).unwrap()
    }

    fn kind_of(quirk: &str) -> Option<SiteDataKind> {
        match validate(&entry_with_quirk(quirk)) {
            Ok(()) => None,
            Err(CatalogueError::SiteData { kind, .. }) => Some(kind),
            Err(other) => panic!("unexpected error {other}"),
        }
    }

    #[test]
    fn accepts_clean_entry() {
        assert_eq!(
            kind_of("Baichuan on port 9000; GOP 32 frames; 2560x1920; ONVIF 8000; fw 3.0"),
            None
        );
        assert_eq!(
            kind_of("Sub stream /h264Preview_01_sub, subtype=1, MSG_ID_GET_SERVICE_PORTS"),
            None
        );
        assert_eq!(kind_of("Dahua IPC-HFW4431R-Z and RTT-8700 and PT10S"), None);
        assert_eq!(kind_of("time 12:30:00 ratio 16:9"), None);
    }

    #[test]
    fn rejects_every_ipv4_range() {
        for ip in [
            "10.0.0.1",
            "10.255.255.254",
            "172.16.0.1",
            "172.31.9.9",
            "192.168.1.20",
            "169.254.10.10",
            "127.0.0.1",
            "8.8.8.8",
            "0.0.0.0",
            "192.168.001.020",
        ] {
            for text in [
                ip.to_owned(),
                format!("rtsp://{ip}:554/x"),
                format!("host {ip}."),
            ] {
                assert_eq!(kind_of(&text), Some(SiteDataKind::Ipv4), "{text}");
            }
        }
        assert_eq!(kind_of("192.168.001.020"), Some(SiteDataKind::Ipv4));
        assert_eq!(kind_of("1.2.3.4.5"), Some(SiteDataKind::Ipv4));
    }

    #[test]
    fn rejects_ipv6() {
        for ip in [
            "::1",
            "fe80::1",
            "2001:db8::8a2e:370:7334",
            "[fe80::1]:554",
            "2001:0db8:0000:0000:0000:ff00:0042:8329",
            "fe80::1%eth0",
            "::ffff:192.0.2.1",
        ] {
            assert!(kind_of(&format!("at {ip} now")).is_some(), "{ip}");
        }
        assert_eq!(kind_of("fe80::1"), Some(SiteDataKind::Ipv6));
    }

    #[test]
    fn rejects_mac_like_strings() {
        for mac in [
            "aa:bb:cc:dd:ee:ff",
            "AA-BB-CC-DD-EE-FF",
            "a4:5e:60:00:11:22",
            "aabb.ccdd.eeff",
            "a45e60001122",
        ] {
            assert_eq!(
                kind_of(&format!("id {mac} end")),
                Some(SiteDataKind::Mac),
                "{mac}"
            );
        }
    }

    #[test]
    fn rejects_serial_like_strings() {
        for serial in [
            "ABCD1234EFGH",
            "9C8E99123456",
            "1234567890",
            "12345678",
            "ABCDEFGHIJ",
        ] {
            assert!(kind_of(&format!("sn {serial}")).is_some(), "{serial}");
        }
        assert_eq!(kind_of("sn ABCD1234EFGH"), Some(SiteDataKind::Serial));
        assert_eq!(
            kind_of("sn ABCDEFGHI"),
            None,
            "nine letters is below the limit"
        );
        assert_eq!(
            kind_of("sn 1234567"),
            None,
            "seven digits is below the limit"
        );
    }

    #[test]
    fn rejects_credentials_in_urls() {
        for text in [
            "rtsp://admin:hunter2@host/x",
            "http://user@host/",
            "see user:pass@host",
            "x ftp://a:b@h",
        ] {
            assert_eq!(kind_of(text), Some(SiteDataKind::Credentials), "{text}");
        }
        assert_eq!(
            kind_of("rtsp://host:554/x@y"),
            Some(SiteDataKind::Email),
            "an @ in a path is not a credential"
        );
    }

    #[test]
    fn rejects_email_addresses() {
        for text in ["mail me@example.com", "a.b+c@sub.example.org"] {
            assert_eq!(kind_of(text), Some(SiteDataKind::Email), "{text}");
        }
        assert_eq!(kind_of("an @ sign alone"), None);
    }

    #[test]
    fn checks_every_string_field() {
        let base = "vendor=\"A\"\nmodel=\"B\"\nsupport=\"verified\"\n";
        let ev = "[[evidence]]\nreference=\"docs/x.md\"\n";
        let bad = "10.1.2.3";
        let cases = [
            format!("vendor=\"{bad}\"\nmodel=\"B\"\nsupport=\"verified\"\n{ev}"),
            format!("vendor=\"A\"\nmodel=\"{bad}\"\nsupport=\"verified\"\n{ev}"),
            format!("{base}aliases=[\"{bad}\"]\n{ev}"),
            format!("{base}quirks=[\"{bad}\"]\n{ev}"),
            format!("{base}[[evidence]]\nreference=\"{bad}\"\n"),
            format!("{base}[[evidence]]\nreference=\"x\"\nsection=\"{bad}\"\n"),
            format!("{base}[[protocols]]\nkind=\"rtsp\"\npaths=[\"/{bad}\"]\n{ev}"),
        ];
        for c in cases {
            let e = CatalogueEntry::from_toml_str(&c).unwrap();
            assert!(
                matches!(validate(&e), Err(CatalogueError::SiteData { .. })),
                "{c}"
            );
        }
    }

    #[test]
    fn error_names_the_field_but_not_the_value() {
        let err = validate(&entry_with_quirk("gateway 192.168.7.7")).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("quirks[0]"), "{msg}");
        assert!(!msg.contains("192.168"), "{msg}");
    }

    #[test]
    fn requires_non_empty_evidence() {
        let e = CatalogueEntry::from_toml_str("vendor=\"A\"\nmodel=\"B\"\nsupport=\"verified\"\n")
            .unwrap();
        assert_eq!(validate(&e), Err(CatalogueError::Missing("evidence")));
    }

    #[test]
    fn requires_vendor_and_model() {
        let ev = "[[evidence]]\nreference=\"x\"\n";
        let e = CatalogueEntry::from_toml_str(&format!(
            "vendor=\" \"\nmodel=\"B\"\nsupport=\"verified\"\n{ev}"
        ))
        .unwrap();
        assert_eq!(validate(&e), Err(CatalogueError::Missing("vendor")));
        let e = CatalogueEntry::from_toml_str(&format!(
            "vendor=\"A\"\nmodel=\"\"\nsupport=\"verified\"\n{ev}"
        ))
        .unwrap();
        assert_eq!(validate(&e), Err(CatalogueError::Missing("model")));
    }

    #[test]
    fn rejects_implausible_stream_numbers() {
        let head =
            "vendor=\"A\"\nmodel=\"B\"\nsupport=\"verified\"\n[[evidence]]\nreference=\"x\"\n";
        for s in [
            "width=0,height=1",
            "width=1,height=0",
            "width=16385,height=1",
            "width=1,height=1,fps=0.0",
            "width=1,height=1,fps=241.0",
            "width=1,height=1,gop=0",
            "width=1,height=1,gop=10001",
        ] {
            let text = format!(
                "{head}[[streams]]\nrole=\"main\"\ncodec=\"h264\"\n{}\n",
                s.replace(',', "\n")
            );
            let e = CatalogueEntry::from_toml_str(&text).unwrap();
            assert!(
                matches!(validate(&e), Err(CatalogueError::OutOfRange(_))),
                "{s}"
            );
        }
    }
}
