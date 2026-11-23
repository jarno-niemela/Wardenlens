//! The site-data guard. The repository is public, so no text in a catalogue entry (values or
//! comments) may look like data that identifies a particular installation.
//!
//! Heuristics, deliberately conservative (a false positive is fixed by rewording the text):
//!
//! - **Encodings** (allow-list): ASCII without control characters (tab is fine), plus non-ASCII
//!   characters that are alphabetic. Everything else (non-ASCII digits, spaces, punctuation,
//!   format and zero-width characters) is refused, as are the fullwidth block U+FF00..U+FFEF and
//!   the invisible Hangul/Khmer fillers. No Unicode normalisation is attempted.
//! - **IPv4**: any dotted quad (four dot-separated groups of one to three digits, each at most
//!   255), so private, loopback, link-local and public addresses are all refused; a partial
//!   address whose last group is `x` or `*` (`10.0.0.x`); and a `0x` literal with exactly eight
//!   hex digits.
//! - **IPv6**: any token that parses as an IPv6 address, or has three or more colons and only
//!   hex groups.
//! - **MAC**: six hex pairs separated by `:` `-` space or `_` (separators may be mixed), or three
//!   dotted hex quads. Plain long hex (a 40 or 64 digit commit hash) is not a MAC; tokens of
//!   exactly 40 or 64 hex digits are ignored by every rule.
//! - **Serial-like**: in a whitespace-delimited token, a run of at least ten characters from
//!   `[A-Z0-9]`; a run of at least eight digits; an alphanumeric group of twelve or more
//!   characters with at least two digits and two letters (lowercase serials); or three or more
//!   consecutive hyphen-separated groups of four to six alphanumerics that each contain a digit
//!   (`2J0A-1B2C-3D4E`). In the `model` and `aliases` fields (and the lines carrying them in raw
//!   source) a token containing a hyphen is exempt from the capital/digit run rule, so
//!   `DS-2CD2T87G2P-LSU` and `IPC-HDBW2431EP-S-0280B` pass; unhyphenated serials are still
//!   refused there, and free text keeps the strict rule.
//! - **Credentials**, after decoding `%3D`, `%3A`, `%40` (either case) and `&#61;`: a
//!   `scheme://user:pass@host` URL, a token with `:` before `@`, or a `key=value` / `key: value`
//!   pair (key case-insensitive, at a word boundary, optionally quoted as in JSON) whose key is
//!   `password`, `passwd`, `pwd`, `pw`, `pass`, `passphrase`, `pin`, `user`, `username`,
//!   `userpass`, `login`, `credentials`, `token`, `accesstoken`, `apikey`, `api_key`, `auth` or
//!   `secret`. Exempt: the schemes `digest`, `basic`, `none`, `wsse` after `auth`; `none` after
//!   `token`; and unquoted `key: <the|a|your|...>` prose. "needs the cloud account password" is
//!   fine.
//! - **Email**: any other token with text on both sides of an `@`.
//! - **Hostnames**: a label followed by `.lan`, `.local`, `.home`, `.home.arpa`, `.internal`,
//!   `.localdomain`, `.intranet` or `.corp`, in all-lowercase or all-uppercase (`Settings.Home`
//!   is UI text). A bare suffix and `_tcp.local` style service names are fine.

use std::net::Ipv6Addr;

use super::error::{CatalogueError, SiteDataKind};

const SECRET_KEYS: [&str; 18] = [
    "password",
    "passwd",
    "pwd",
    "pw",
    "pass",
    "passphrase",
    "pin",
    "user",
    "username",
    "userpass",
    "login",
    "credentials",
    "token",
    "accesstoken",
    "apikey",
    "api_key",
    "auth",
    "secret",
];
/// Values that are not secrets after `auth` (authentication schemes).
const AUTH_SCHEMES: [&str; 4] = ["digest", "basic", "none", "wsse"];
/// First words that make `user: <words>` prose rather than a value.
const PROSE_WORDS: [&str; 20] = [
    "the", "a", "an", "your", "you", "it", "its", "this", "that", "these", "those", "of", "is",
    "are", "was", "not", "no", "to", "from", "for",
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
        // Model names are structured like serials (`IPC-HDBW2431EP-S-0280B`), so the lines that
        // carry them get the model rule; everything else is free text, including a trailing
        // comment on such a line.
        let key = line.trim_start();
        let is_model_line = ["model", "aliases"].iter().any(|k| {
            key.strip_prefix(k)
                .is_some_and(|r| r.trim_start().starts_with('='))
        });
        let found = if is_model_line {
            let (code, comment) = split_comment(line);
            site_data(code, Mode::Model).or_else(|| comment.and_then(|c| site_data(c, Mode::Text)))
        } else {
            site_data(line, Mode::Text)
        };
        if let Some(kind) = found {
            let field = format!("line {}", index.saturating_add(1));
            return Err(CatalogueError::SiteData { field, kind });
        }
    }
    Ok(())
}

/// Splits a TOML line at the first `#` outside a string.
fn split_comment(line: &str) -> (&str, Option<&str>) {
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for (i, c) in line.char_indices() {
        match quote {
            Some(_) if escaped => escaped = false,
            Some('"') if c == '\\' => escaped = true,
            Some(q) if c == q => quote = None,
            None if c == '"' || c == '\'' => quote = Some(c),
            None if c == '#' => return (line.get(..i).unwrap_or_default(), line.get(i..)),
            Some(_) | None => {}
        }
    }
    (line, None)
}

/// What kind of text is being checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Mode {
    /// Free text: quirks, evidence, paths, vendor.
    Text,
    /// A model name or alias: hyphen-structured tokens may contain long runs of capitals and
    /// digits.
    Model,
}

pub(super) fn site_data(text: &str, mode: Mode) -> Option<SiteDataKind> {
    if has_odd_encoding(text) {
        return Some(SiteDataKind::Encoding);
    }
    // A git commit hash is long hex but not site data.
    let text = redact_hashes(text);
    let text = text.as_str();
    let decoded = decode_escapes(text);
    if has_credentials(&decoded) {
        Some(SiteDataKind::Credentials)
    } else if has_email(&decoded) {
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
    } else if has_serial(text, mode) {
        Some(SiteDataKind::Serial)
    } else {
        None
    }
}

/// Replaces tokens that are exactly 40 or 64 hex digits (SHA-1 / SHA-256) with a space.
fn redact_hashes(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut token = String::new();
    let flush = |token: &mut String, out: &mut String| {
        let hash = matches!(token.len(), 40 | 64) && token.bytes().all(|b| b.is_ascii_hexdigit());
        out.push_str(if hash { " " } else { token.as_str() });
        token.clear();
    };
    for c in text.chars() {
        if c.is_ascii_alphanumeric() {
            token.push(c);
        } else {
            flush(&mut token, &mut out);
            out.push(c);
        }
    }
    flush(&mut token, &mut out);
    out
}

/// Decodes `%3D`, `%3A`, `%40` (either case) and `&#61;` so encoded credentials are visible.
fn decode_escapes(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(c) = rest.chars().next() {
        let percent = rest.get(..3).map(str::to_ascii_lowercase);
        let (decoded, len) = match percent.as_deref() {
            Some("%3d") => ('=', 3),
            Some("%3a") => (':', 3),
            Some("%40") => ('@', 3),
            _ if rest.starts_with("&#61;") => ('=', 5),
            _ => (c, c.len_utf8()),
        };
        out.push(decoded);
        rest = rest.get(len..).unwrap_or_default();
    }
    out
}

/// Allow-list: ASCII (no control characters except tab) and alphabetic non-ASCII letters. That
/// refuses every non-ASCII digit, space, punctuation, format and invisible character, which are
/// the means of disguising addresses. A few letters render as nothing (Hangul fillers) and the
/// fullwidth block imitates ASCII, so those are refused as well.
fn has_odd_encoding(text: &str) -> bool {
    text.chars().any(|c| {
        if c.is_ascii() {
            c.is_ascii_control() && c != '\t'
        } else {
            !c.is_alphabetic()
                || matches!(
                    c,
                    '\u{FF00}'
                        ..='\u{FFEF}'
                            | '\u{115F}'
                            | '\u{1160}'
                            | '\u{3164}'
                            | '\u{17B4}'
                            | '\u{17B5}'
                )
        }
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

/// Keys that are secret wherever they occur in an identifier (`adminPassword`, `loginpassword`).
const LONG_KEYS: [&str; 6] = [
    "password",
    "passwd",
    "username",
    "passphrase",
    "accesstoken",
    "apikey",
];

/// Whether an identifier names a secret: exactly a secret key, containing a long key anywhere
/// (`adminPassword`), or ending in a secret key that starts at a lower-to-upper camelCase step
/// (`onvifPwd`, `apiToken`). `Compass` and `Spin` do not qualify.
fn is_secret_key(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    if SECRET_KEYS.contains(&lower.as_str()) || LONG_KEYS.iter().any(|k| lower.contains(k)) {
        return true;
    }
    let bytes = name.as_bytes();
    SECRET_KEYS.iter().any(|key| {
        lower.strip_suffix(key).is_some_and(|head| {
            let start = head.len();
            let prev = start.checked_sub(1).and_then(|p| bytes.get(p));
            prev.is_some_and(u8::is_ascii_lowercase)
                && bytes.get(start).is_some_and(u8::is_ascii_uppercase)
        })
    })
}

/// The first word of a value, up to whitespace or a closing delimiter, without a final `.`.
/// Exemptions compare this whole word, so `digest-hunter2` is not `digest`.
fn value_word(value: &str) -> &str {
    let end = |c: char| c.is_whitespace() || matches!(c, '"' | '\'' | ',' | ';' | ')' | '}' | '<');
    value
        .split(end)
        .next()
        .unwrap_or_default()
        .trim_end_matches('.')
}

/// Whether a value after the (lowercase) key name is not a secret.
fn exempt_value(name: &str, word: &str, spaced_colon: bool, quoted: bool) -> bool {
    (name == "auth" && AUTH_SCHEMES.contains(&word))
        || (name == "token" && word == "none")
        || (spaced_colon && !quoted && PROSE_WORDS.contains(&word))
}

/// `key=value`, `key: value` and `"key": "value"` pairs, plus XML elements (`<Key>value</Key>`).
fn has_secret_pair(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    let by_separator = SECRET_KEYS.iter().any(|key| {
        lower.match_indices(key).any(|(i, _)| {
            let end = i.saturating_add(key.len());
            let name = if key.contains('_') {
                text.get(i..end).unwrap_or_default()
            } else {
                let run = text
                    .get(..end)
                    .unwrap_or_default()
                    .bytes()
                    .rev()
                    .take_while(u8::is_ascii_alphanumeric)
                    .count();
                text.get(end.saturating_sub(run)..end).unwrap_or_default()
            };
            if !is_secret_key(name) {
                return false;
            }
            let after = lower.get(end..).unwrap_or_default();
            // A JSON key is quoted: `"password": "x"`.
            let after = after.strip_prefix(['"', '\'']).unwrap_or(after);
            let after = after.trim_start_matches([' ', '\t']);
            let Some(value) = after.strip_prefix(['=', ':']) else {
                return false;
            };
            let spaced_colon = after.starts_with(':') && value.starts_with([' ', '\t']);
            let value = value.trim_start_matches([' ', '\t']);
            let quoted = value.starts_with(['"', '\'']);
            let value = value.strip_prefix(['"', '\'']).unwrap_or(value);
            let exempt = exempt_value(
                &name.to_ascii_lowercase(),
                value_word(value),
                spaced_colon,
                quoted,
            );
            !value.is_empty() && !exempt
        })
    });
    by_separator || has_secret_element(text)
}

/// Removes CDATA markers (keeping their content) and comments, so markup cannot hide a value.
fn strip_markup(text: &str) -> String {
    let mut out = text.replace("<![CDATA[", "").replace("]]>", "");
    while let Some(start) = out.find("<!--") {
        let Some(len) = out.get(start..).and_then(|r| r.find("-->")) else {
            break;
        };
        out.replace_range(start..start.saturating_add(len).saturating_add(3), "");
    }
    out
}

/// `<[ns:]key[ attrs]>text</[ns:]key>`: a secret key as an XML element with non-empty text,
/// closed by a matching tag. Empty, self-closing and unclosed elements carry no secret.
fn has_secret_element(text: &str) -> bool {
    let text = strip_markup(text);
    text.match_indices('<').any(|(i, _)| {
        let tag = text.get(i.saturating_add(1)..).unwrap_or_default();
        let Some((open, rest)) = tag.split_once('>') else {
            return false;
        };
        if open.ends_with('/') {
            return false;
        }
        let name = open.split(char::is_whitespace).next().unwrap_or_default();
        let local = name.rsplit(':').next().unwrap_or_default();
        let (value, tail) = rest.split_once('<').unwrap_or((rest, ""));
        let value = value.trim();
        let closing = tail
            .strip_prefix('/')
            .and_then(|t| t.split_once('>'))
            .is_some_and(|(close, _)| close.trim().eq_ignore_ascii_case(name));
        is_secret_key(local)
            && closing
            && !value.is_empty()
            && !exempt_value(&local.to_ascii_lowercase(), value, false, false)
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
    pairs || dotted
}

/// A name ending in a private suffix with a label before it. All-lowercase or all-uppercase
/// only: `Settings.Home` is a UI path, not a host. Labels starting with `_` (`_tcp.local`, mDNS
/// service types) are fine.
fn has_private_hostname(text: &str) -> bool {
    text.split(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '*')))
        .any(|token| {
            let token = token.trim_end_matches('.');
            let single_case = !token.bytes().any(|b| b.is_ascii_lowercase())
                || !token.bytes().any(|b| b.is_ascii_uppercase());
            let lower = token.to_ascii_lowercase();
            single_case
                && PRIVATE_SUFFIXES.iter().any(|suffix| {
                    lower.strip_suffix(suffix).is_some_and(|head| {
                        let label = head.rsplit('.').next().unwrap_or_default();
                        !label.is_empty() && !label.starts_with('_')
                    })
                })
        })
}

fn has_serial(text: &str, mode: Mode) -> bool {
    // In a model name a hyphen-structured token (`IPC-HDBW2431EP-S-0280B`) may hold long runs of
    // capitals and digits; the grouped-serial and long-token rules below still apply to it.
    text.split_whitespace().any(|token| {
        let structured = mode == Mode::Model && token.contains('-');
        let b = token.as_bytes();
        (!structured && max_run(b, |c| c.is_ascii_uppercase() || c.is_ascii_digit()) >= 10)
            || max_run(b, u8::is_ascii_digit) >= 8
            || token.split(|c: char| !c.is_ascii_alphanumeric()).any(|t| {
                let digits = t.bytes().filter(u8::is_ascii_digit).count();
                let letters = t.bytes().filter(u8::is_ascii_alphabetic).count();
                t.len() >= 12 && digits >= 2 && letters >= 2
            })
            || token
                .split(|c: char| !(c.is_ascii_alphanumeric() || c == '-'))
                .any(|part| {
                    let groups: Vec<&str> = part.split('-').collect();
                    groups.windows(3).any(|w| {
                        w.iter().all(|g| {
                            (4..=6).contains(&g.len()) && g.bytes().any(|b| b.is_ascii_digit())
                        })
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

    fn site_data(text: &str) -> Option<SiteDataKind> {
        super::site_data(text, Mode::Text)
    }

    fn model_data(text: &str) -> Option<SiteDataKind> {
        super::site_data(text, Mode::Model)
    }

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
            "auth=bearer",
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
    fn rejects_quoted_encoded_and_more_secret_keys() {
        for t in [
            r#"{"password":"hunter2"}"#,
            r#"{"user": "admin", "pwd": "x"}"#,
            r"'token': 'abc'",
            r#"[{"cmd":"Login","param":{"User":{"userName":"admin","password":"hunter2"}}}]"#,
            r#"{"method":"login","params":{"username":"admin","password":"hunter2"}}"#,
            "passphrase=x",
            "apikey=x",
            "api_key=x",
            "pin=4711",
            "login=admin",
            "credentials=a",
            "accesstoken=a",
            "userpass=x",
            "pw=x",
            "/x?q=password%3Dhunter2",
            "password%3adx",
            "password&#61;hunter2",
            "admin%3Ax%40cam",
            "a%3Ab%40host",
            "auth=evil",
            "token=abc",
        ] {
            assert_eq!(site_data(t), Some(SiteDataKind::Credentials), "{t}");
        }
    }

    #[test]
    fn model_names_pass_as_models_but_serials_do_not() {
        for m in [
            "DS-2CD2T87G2P-LSU",
            "DS-2CD2387G2P-LSU",
            "IPC-HDBW2431EP-S-0280B",
            "IPC-HFW3849T1P-AS-PV",
            "IPC-HFW4431R-Z",
            "RLC-520A",
            "RTT-8700",
            "Tapo C110",
        ] {
            assert_eq!(model_data(m), None, "{m}");
        }
        for m in [
            "ABCD1234EFGH",
            "9C8E99123456",
            "2J0A-1B2C-3D4E-5F6G",
            "1234567890-AB",
        ] {
            assert!(model_data(m).is_some(), "{m}");
        }
        // The same names in free text keep the strict rule.
        assert!(site_data("DS-2CD2T87G2P-LSU").is_some());
    }

    #[test]
    fn commit_hashes_are_not_site_data_but_other_long_hex_is() {
        let sha1 = "0123456789abcdef0123456789abcdef01234567";
        assert_eq!(site_data(&format!("commit {sha1}")), None);
        assert_eq!(site_data(&format!("commit {}", "ab".repeat(32))), None);
        assert!(site_data(&format!("commit {}", &sha1[..39])).is_some());
    }

    #[test]
    fn rejects_camel_case_and_prefixed_keys() {
        for t in [
            "newPassword=x",
            "adminPassword=x",
            "onvifPwd: x",
            "rtspPass=x",
            "loginPassword=x",
            "myUsername=bob",
            "apiToken=abc",
        ] {
            assert_eq!(site_data(t), Some(SiteDataKind::Credentials), "{t}");
        }
        for t in [
            "cloud account password",
            "bypass: yes",
            "authentication: x",
            "auth: digest",
            "Camera Account password is needed",
            "the Passport: valid",
            "Compass=north",
        ] {
            assert_eq!(site_data(t), None, "{t}");
        }
    }

    #[test]
    fn rejects_xml_secret_elements_but_not_empty_ones() {
        for t in [
            "<Password>hunter2</Password>",
            "<wsse:Password Type=\"#PasswordText\">hunter2</wsse:Password>",
            "<userName>admin</userName>",
            "<token>abc</token>",
        ] {
            assert_eq!(site_data(t), Some(SiteDataKind::Credentials), "{t}");
        }
        for t in [
            "<wsse:Password Type=\"PasswordDigest\"/>",
            "<Password></Password>",
            "<Password>  </Password>",
            "<Password/>",
            "<auth>digest</auth>",
            "<UserLevel>Administrator</UserLevel>",
            "</Password>",
        ] {
            assert_eq!(site_data(t), None, "{t}");
        }
    }

    #[test]
    fn secret_key_names_by_exact_long_or_camel_suffix() {
        for n in [
            "password",
            "Pwd",
            "loginPassword",
            "adminPassword",
            "newPassword",
            "onvifPwd",
            "rtspPass",
            "userPassword",
            "AdminPassword",
            "NewPassword",
            "adminPwd",
            "apiToken",
            "api_key",
        ] {
            assert!(is_secret_key(n), "{n}");
        }
        for n in [
            "Compass",
            "Spin",
            "Passport",
            "OAuth2",
            "superuser",
            "key",
            "UserLevel",
        ] {
            assert!(!is_secret_key(n), "{n}");
        }
    }

    #[test]
    fn camel_case_xml_elements_are_secret() {
        for t in [
            "<loginPassword>x</loginPassword>",
            "<adminPassword>x</adminPassword>",
            "<newPassword>x</newPassword>",
            "<onvifPwd>x</onvifPwd>",
            "<rtspPass>x</rtspPass>",
            "<userPassword>x</userPassword>",
            "<tt:AdminPassword>x</tt:AdminPassword>",
            "<tt:NewPassword>x</tt:NewPassword>",
            "<adminPwd>x</adminPwd>",
            "<apiToken>abc</apiToken>",
        ] {
            assert_eq!(site_data(t), Some(SiteDataKind::Credentials), "{t}");
        }
        for t in [
            "<Compass>n</Compass>",
            "<Spin>3</Spin>",
            "<Passport>x</Passport>",
        ] {
            assert_eq!(site_data(t), None, "{t}");
        }
    }

    #[test]
    fn xml_elements_need_a_closing_tag_and_see_through_cdata_and_comments() {
        for t in [
            "<Password><![CDATA[x]]></Password>",
            "<Password><!-- c -->x</Password>",
            "<tt:Password>x</tt:Password>",
        ] {
            assert_eq!(site_data(t), Some(SiteDataKind::Credentials), "{t}");
        }
        for t in [
            "the <Password> element is required",
            "<Password>x",
            "<Password>x</Other>",
            "<Password><![CDATA[]]></Password>",
            "<Password><!-- c --></Password>",
            "<!-- unterminated <Password>",
        ] {
            assert_eq!(site_data(t), None, "{t}");
        }
    }

    #[test]
    fn exemptions_compare_the_whole_value() {
        for t in [
            "auth=digest-hunter2",
            "<token>none-x</token>",
            "<auth>digest hunter2</auth>",
            "token=none2",
        ] {
            assert_eq!(site_data(t), Some(SiteDataKind::Credentials), "{t}");
        }
        for t in [
            "auth: digest",
            "<auth>digest</auth>",
            "auth=basic",
            "token=none",
            "RTSP auth: digest only.",
        ] {
            assert_eq!(site_data(t), None, "{t}");
        }
    }

    #[test]
    fn comments_on_model_lines_get_the_strict_text_rule() {
        let ok = "model = \"IPC-HDBW2431EP-S-0280B\"\n";
        assert_eq!(check_source(ok), Ok(()));
        assert_eq!(check_source("model = \"A#B\" # fine\n"), Ok(()));
        for bad in [
            "model = \"IPC-HDBW2431EP-S-0280B\" # sn ABCD-EFGHIJKLMN1\n",
            "aliases = [\"X\"] # camera at 10.0.0.1\n",
            "model = \"X\" # DS-2CD2T87G2P-LSU\n",
        ] {
            assert!(check_source(bad).is_err(), "{bad}");
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
            "NVR.LOCAL.",
            "x.home",
            "a.b.home.arpa",
            "host.internal",
            "*.lan",
            "h.localdomain",
        ] {
            assert_eq!(site_data(t), Some(SiteDataKind::Hostname), "{t}");
        }
        assert_eq!(site_data("localhost lan local home"), None);
        for t in [
            ".local domain",
            "_onvif._tcp.local",
            "Settings.Home",
            "the .lan suffix",
            "x._udp.local",
        ] {
            assert_eq!(site_data(t), None, "{t}");
        }
    }

    #[test]
    fn encoding_allow_list_refuses_invisible_letters_and_controls() {
        for t in [
            "a\u{034F}b",
            "a\u{FE0F}b",
            "a\u{180B}b",
            "a\u{3164}b",
            "a\u{115F}b",
            "a\u{1D173}b",
            "a\u{E0100}b",
            "a\u{3002}b",
            "a\u{2024}b",
            "a\u{FE52}b",
            "a\u{FE6B}b",
            "a\u{2236}b",
            "a\u{0000}b",
            "a\u{001B}b",
            "a\u{007F}b",
            "a\rb",
            "\u{FF21}",
        ] {
            assert_eq!(site_data(t), Some(SiteDataKind::Encoding), "{t:?}");
        }
        for t in ["tab\there", "Ünïcödé", "漢字", "עברית", "ñ"] {
            assert_eq!(site_data(t), None, "{t:?}");
        }
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
