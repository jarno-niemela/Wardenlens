//! The site-data guard. The repository is public, so no text in a catalogue entry (values or
//! comments) may look like data that identifies a particular installation.
//!
//! Heuristics, deliberately conservative (a false positive is fixed by rewording the text):
//!
//! - **Encodings**: non-ASCII digits and numerals, non-ASCII whitespace, the fullwidth forms
//!   block U+FF00..U+FFEF, and the common invisible format characters (soft hyphen, zero-width
//!   and bidi controls, word joiner, BOM, tag characters). They are used to disguise the other
//!   kinds. No Unicode normalisation is attempted; the characters are simply refused.
//! - **IPv4**: any dotted quad (four dot-separated groups of one to three digits, each at most
//!   255), so private, loopback, link-local and public addresses are all refused; a partial
//!   address whose last group is `x` or `*` (`10.0.0.x`); and a `0x` literal with exactly eight
//!   hex digits.
//! - **IPv6**: any token that parses as an IPv6 address, or has three or more colons and only
//!   hex groups.
//! - **MAC**: six hex pairs separated by `:` `-` space or `_` (separators may be mixed), three
//!   dotted hex quads, or a run of twelve or more hex digits.
//! - **Serial-like**: a maximal run of at least ten characters from `[A-Z0-9]`; a run of at
//!   least eight digits; an alphanumeric token of twelve or more characters with at least two
//!   digits and two letters (catches lowercase serials); or three or more consecutive
//!   hyphen-separated groups of four to six alphanumerics that each contain a digit
//!   (`2J0A-1B2C-3D4E`). Model names stay below all of these: `IPC-HFW4431R-Z` has runs of at
//!   most eight, `RLC-520A` and `RTT-8700` have two groups.
//! - **Credentials**: a `scheme://user:pass@host` URL, any whitespace-delimited token with `:`
//!   before an `@`, or a `key=value` / `key: value` pair whose key (case-insensitive, at a word
//!   boundary) is `password`, `passwd`, `pwd`, `pass`, `user`, `username`, `token`, `auth` or
//!   `secret`. Prose such as "needs the cloud account password" is fine.
//! - **Email**: any other token with text on both sides of an `@`.
//! - **Hostnames**: names ending in `.lan`, `.local`, `.home`, `.home.arpa`, `.internal`,
//!   `.localdomain`, `.intranet` or `.corp`.

use std::net::Ipv6Addr;

use super::error::{CatalogueError, SiteDataKind};

const SECRET_KEYS: [&str; 9] = [
    "password", "passwd", "pwd", "pass", "user", "username", "token", "auth", "secret",
];
const PRIVATE_SUFFIXES: [&str; 8] = [
    ".lan",
    ".local",
    ".home",
    ".home.arpa",
    ".internal",
    ".localdomain",
    ".intranet",
    ".corp",
];
const MAC_SEPARATORS: &[u8; 4] = b":- _";

/// Runs the site-data checks on every raw line of a catalogue file, comments included.
///
/// [`CatalogueEntry::from_toml_str`](super::CatalogueEntry::from_toml_str) calls this before
/// parsing; call it directly for other files that are published next to the entries.
///
/// # Errors
/// [`CatalogueError::SiteData`] naming `line N` (never the text) for the first offending line.
pub fn check_source(text: &str) -> Result<(), CatalogueError> {
    for (index, line) in text.lines().enumerate() {
        if let Some(kind) = site_data(line) {
            let field = format!("line {}", index.saturating_add(1));
            return Err(CatalogueError::SiteData { field, kind });
        }
    }
    Ok(())
}

pub(super) fn site_data(text: &str) -> Option<SiteDataKind> {
    if has_odd_encoding(text) {
        Some(SiteDataKind::Encoding)
    } else if has_credentials(text) {
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
    } else if has_private_hostname(text) {
        Some(SiteDataKind::Hostname)
    } else if has_serial(text) {
        Some(SiteDataKind::Serial)
    } else {
        None
    }
}

fn has_odd_encoding(text: &str) -> bool {
    text.chars().any(|c| {
        !c.is_ascii()
            && (c.is_numeric()
                || c.is_whitespace()
                || matches!(c,
                    '\u{FF00}'..='\u{FFEF}'
                    | '\u{00AD}' | '\u{061C}' | '\u{180E}'
                    | '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2060}'..='\u{206F}'
                    | '\u{FEFF}' | '\u{FFF9}'..='\u{FFFB}' | '\u{E0000}'..='\u{E007F}'))
    })
}

/// `scheme://...@...` authority, a token with `:` before `@`, or a `key=value` secret pair.
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
        || has_secret_pair(text)
}

fn has_secret_pair(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    SECRET_KEYS.iter().any(|key| {
        lower.match_indices(key).any(|(i, _)| {
            let boundary = i
                .checked_sub(1)
                .and_then(|p| lower.as_bytes().get(p))
                .is_none_or(|c| !c.is_ascii_alphanumeric());
            let after = lower.get(i.saturating_add(key.len())..).unwrap_or_default();
            let after = after.trim_start_matches([' ', '\t']);
            let value = after
                .strip_prefix(['=', ':'])
                .map(|v| v.trim_start_matches([' ', '\t']));
            boundary && value.is_some_and(|v| !v.is_empty())
        })
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
    let full = text
        .split(|c: char| !(c.is_ascii_digit() || c == '.'))
        .any(|token| {
            let parts: Vec<&str> = token.split('.').collect();
            parts.windows(4).any(|w| w.iter().all(|p| is_octet(p)))
        });
    let partial = text
        .split(|c: char| !(c.is_ascii_digit() || matches!(c, '.' | '*' | 'x' | 'X')))
        .any(|token| {
            let parts: Vec<&str> = token.split('.').collect();
            parts.windows(4).any(|w| {
                w.iter().take(3).all(|p| is_octet(p))
                    && w.last().is_some_and(|l| matches!(*l, "x" | "X" | "*"))
            })
        });
    full || partial || has_hex_ipv4(text)
}

fn is_octet(part: &str) -> bool {
    (1..=3).contains(&part.len())
        && part.bytes().all(|b| b.is_ascii_digit())
        && part.parse::<u8>().is_ok()
}

/// `0x` followed by exactly eight hex digits.
fn has_hex_ipv4(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    lower.match_indices("0x").any(|(i, _)| {
        let boundary = i
            .checked_sub(1)
            .and_then(|p| lower.as_bytes().get(p))
            .is_none_or(|c| !c.is_ascii_alphanumeric());
        let digits = lower
            .get(i.saturating_add(2)..)
            .unwrap_or_default()
            .bytes()
            .take_while(u8::is_ascii_hexdigit)
            .count();
        boundary && digits == 8
    })
}

fn has_ipv6(text: &str) -> bool {
    // Split on non-alphanumerics (not non-hex) so `core::catalogue` is not read as `e::ca`.
    text.split(|c: char| !(c.is_ascii_alphanumeric() || c == ':' || c == '.'))
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
    let pairs = b.windows(17).any(|w| {
        w.chunks(3).enumerate().all(|(i, c)| {
            let hex = c.first().is_some_and(u8::is_ascii_hexdigit)
                && c.get(1).is_some_and(u8::is_ascii_hexdigit);
            hex && (i == 5 || c.get(2).is_some_and(|s| MAC_SEPARATORS.contains(s)))
        })
    });
    let dotted = b.windows(14).any(|w| {
        w.chunks(5).enumerate().all(|(i, c)| {
            c.iter().take(4).all(u8::is_ascii_hexdigit) && (i == 2 || c.get(4) == Some(&b'.'))
        })
    });
    pairs || dotted || max_run(b, u8::is_ascii_hexdigit) >= 12
}

fn has_private_hostname(text: &str) -> bool {
    text.split(|c: char| !(c.is_ascii_alphanumeric() || c == '.' || c == '-'))
        .any(|token| {
            let token = token.trim_end_matches('.').to_ascii_lowercase();
            PRIVATE_SUFFIXES.iter().any(|s| token.ends_with(s))
        })
}

fn has_serial(text: &str) -> bool {
    let b = text.as_bytes();
    max_run(b, |c| c.is_ascii_uppercase() || c.is_ascii_digit()) >= 10
        || max_run(b, u8::is_ascii_digit) >= 8
        || text.split(|c: char| !c.is_ascii_alphanumeric()).any(|t| {
            let digits = t.bytes().filter(u8::is_ascii_digit).count();
            let letters = t.bytes().filter(u8::is_ascii_alphabetic).count();
            t.len() >= 12 && digits >= 2 && letters >= 2
        })
        || text
            .split(|c: char| !(c.is_ascii_alphanumeric() || c == '-'))
            .any(|token| {
                let groups: Vec<&str> = token.split('-').collect();
                groups.windows(3).any(|w| {
                    w.iter().all(|g| {
                        (4..=6).contains(&g.len()) && g.bytes().any(|b| b.is_ascii_digit())
                    })
                })
            })
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

    #[test]
    fn accepts_clean_text() {
        for t in [
            "Baichuan on port 9000; GOP 32 frames; 2560x1920; ONVIF 8000; fw 3.0",
            "Sub stream /h264Preview_01_sub, subtype=1, MSG_ID_GET_SERVICE_PORTS",
            "Dahua IPC-HFW4431R-Z and RTT-8700 and RLC-520A and PT10S",
            "time 12:30:00 ratio 16:9",
            "The local HTTPS API needs the cloud account password; do not use it.",
            "ONVIF needs the Camera Account created in the Tapo app, not the cloud account.",
            "GetEventProperties, WSSubscriptionPolicySupport, eventManager attach",
            "docs/adr/0002-camera-integration.md",
            "see 3.0.1 and 1.2.3 and bypass authentication",
            "# comment about the model",
            "Ünïcödé text 漢字",
        ] {
            assert_eq!(site_data(t), None, "{t}");
        }
    }

    #[test]
    fn rejects_every_ipv4_form() {
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
        ] {
            for text in [
                ip.to_owned(),
                format!("rtsp://{ip}:554/x"),
                format!("host {ip}."),
            ] {
                assert_eq!(site_data(&text), Some(SiteDataKind::Ipv4), "{text}");
            }
        }
        for t in [
            "1.2.3.4.5",
            "192.168.1.x",
            "10.0.0.*",
            "10.0.0.X",
            "host 0xC0A80114",
            "0xc0a80114",
        ] {
            assert_eq!(site_data(t), Some(SiteDataKind::Ipv4), "{t}");
        }
        assert_eq!(
            site_data("0xC0A801"),
            None,
            "six hex digits is not an address"
        );
        assert_ne!(site_data("0xC0A8011400"), Some(SiteDataKind::Ipv4));
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
            assert!(site_data(&format!("at {ip} now")).is_some(), "{ip}");
        }
        assert_eq!(site_data("fe80::1"), Some(SiteDataKind::Ipv6));
    }

    #[test]
    fn rejects_mac_like_strings() {
        for mac in [
            "aa:bb:cc:dd:ee:ff",
            "AA-BB-CC-DD-EE-FF",
            "a4:5e:60:00:11:22",
            "aabb.ccdd.eeff",
            "a45e60001122",
            "a4 5e 60 00 11 22",
            "a4_5e_60_00_11_22",
            "a4:5e-60_00 11:22",
        ] {
            assert_eq!(
                site_data(&format!("id {mac} end")),
                Some(SiteDataKind::Mac),
                "{mac}"
            );
        }
    }

    #[test]
    fn rejects_serial_like_strings_on_both_sides_of_the_limits() {
        for s in [
            "ABCD1234EFGH",
            "9C8E99123456",
            "1234567890",
            "12345678",
            "ABCDEFGHIJ",
            "xk3j9q2m7z8w4p",
            "2J0A-1B2C-3D4E-5F6G",
            "2j0a-1b2c-3d4e",
        ] {
            assert!(site_data(&format!("sn {s}")).is_some(), "{s}");
        }
        for s in [
            "ABCDEFGHI",
            "1234567",
            "xk3j9q2m7z8",
            "xkjqmzwpabcdefgh",
            "2J0A-1B2C",
            "2J0A-1B2C-WXYZ",
            "IPC-HFW4431R-Z",
            "RLC-520A",
            "RTT-8700",
            "DS-2CD2143G0-IS",
            "Tapo C110",
            "HDIPC",
            "XR",
        ] {
            assert_eq!(site_data(&format!("sn {s}")), None, "{s}");
        }
    }

    #[test]
    fn rejects_credentials() {
        for t in [
            "rtsp://admin:hunter2@host/x",
            "http://user@host/",
            "see user:pass@host",
            "x ftp://a:b@h",
            "/x?user=admin&password=hunter2",
            "pwd=hunter2",
            "password: hunter2",
            "Password = x",
            "api_token=abc",
            "SECRET: s",
            "auth=basic",
            "passwd:x",
            "username = bob",
            "pass=1",
        ] {
            assert_eq!(site_data(t), Some(SiteDataKind::Credentials), "{t}");
        }
        for t in [
            "password",
            "the password is needed",
            "password:",
            "bypass: yes",
            "passwords=1",
            "authentication: x",
        ] {
            assert_eq!(site_data(t), None, "{t}");
        }
    }

    #[test]
    fn rejects_email_addresses() {
        for t in [
            "mail me@example.com",
            "a.b+c@sub.example.org",
            "rtsp://host:554/x@y",
        ] {
            assert_eq!(site_data(t), Some(SiteDataKind::Email), "{t}");
        }
        assert_eq!(site_data("an @ sign alone"), None);
    }

    #[test]
    fn rejects_private_hostnames() {
        for t in [
            "cam.lan",
            "NVR.Local.",
            "x.home",
            "a.b.home.arpa",
            "host.internal",
            "*.lan",
            "h.localdomain",
        ] {
            assert_eq!(site_data(t), Some(SiteDataKind::Hostname), "{t}");
        }
        assert_eq!(site_data("localhost lan local home"), None);
    }

    #[test]
    fn rejects_disguising_encodings() {
        for t in [
            "192.168\u{200B}.1.20",
            "192\u{FF0E}168\u{FF0E}1\u{FF0E}20",
            "\u{FF11}\u{FF19}\u{FF12}",
            "a\u{FF20}b",
            "x\u{FF1A}y",
            "\u{0663}",
            "a\u{00A0}b",
            "a\u{2028}b",
            "\u{FEFF}x",
            "a\u{202E}b",
            "a\u{00AD}b",
            "\u{E0041}",
        ] {
            assert_eq!(site_data(t), Some(SiteDataKind::Encoding), "{t:?}");
        }
    }

    #[test]
    fn source_check_reports_the_line_and_scans_comments() {
        let err = check_source("a = 1\n# camera at 192.168.1.20\n").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("line 2"), "{msg}");
        assert!(!msg.contains("192"), "{msg}");
        assert_eq!(check_source("# fine\nb = 2\n"), Ok(()));
        assert_eq!(check_source(""), Ok(()));
    }

    #[test]
    fn does_not_panic_on_edge_strings() {
        for t in [
            "",
            "@",
            "://",
            "://@",
            "a://\u{1F600}@",
            ":::::",
            "...",
            "0x",
            "*.",
            "-",
            "----",
        ] {
            let _ = site_data(t);
        }
        let _ = site_data(&"9.".repeat(20_000));
    }
}
