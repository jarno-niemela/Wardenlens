//! [`Host`]: an IPv4 address, an IPv6 address or a plain ASCII DNS name, with redacting
//! `Debug` and `Display` (ADR 0006: a host identifies the site).
//!
//! Input forms (everything not listed is refused):
//!
//! | input | result |
//! |---|---|
//! | `192.0.2.10` (std strict `Ipv4Addr`) | IPv4 |
//! | `2001:db8::1`, `::1`, `64:ff9b::192.0.2.1` (std `Ipv6Addr`) | IPv6, stored canonical (lower case, compressed) |
//! | IPv4-mapped IPv6 (`::ffff:192.0.2.1`, `::ffff:c000:201`, any spelling) | `HostSyntax`: the address has one spelling, the IPv4 one |
//! | `[2001:db8::1]` (brackets) | IPv6, same value as unbracketed |
//! | `nvr-1.example.invalid`, `localhost`, `xn--` labels, upper case | DNS name, lower-cased |
//! | `_sip._tcp.example.invalid`, `a_b.invalid` (`_` anywhere in a label: service and DNS-SD names, ADR 0006 section 1) | DNS name |
//! | empty | `HostEmpty` |
//! | more than 253 bytes | `HostTooLong` |
//! | empty label (`a..b`, leading dot, **trailing dot**), label over 63 bytes | `HostLabel` |
//! | `user@h`, `h:554`, `h/p`, `h?q`, `h#f`, `rtsp://h`, `%41`, `\`, `*` | `HostSyntax` |
//! | any whitespace or control char, anywhere | `HostSyntax` |
//! | any non-ASCII char (no IDNA in core: callers give the `xn--` form) | `HostSyntax` |
//! | label starting or ending with `-` | `HostSyntax` (a label may start or end with `_`) |
//! | IPv4 spellings std refuses (`192.000.2.1`, `0300.0.0.1`, `0x7f.0.0.1`, `192.0.2`, `3221225985`) | `HostSyntax`: a name whose last label is all digits, or `0x` plus hex digits, is not a DNS name here |
//! | zone ids (`fe80::1%eth0`), `[fe80::1%25eth0]` | `HostSyntax` |
//! | `[192.0.2.1]`, `[::1`, `::1]`, `[[::1]]`, `[]`, `[ ::1]`, `[::1]:554` | `HostSyntax` |
//!
//! A trailing dot is refused so that every host has exactly one spelling (the vault strips one
//! before it calls [`Host::new`]). This is the one host validator: the vault calls it for its
//! `host` entries, so a stored host always builds a camera (ADR 0006 section 1).

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use super::CameraError;

/// Longest host in bytes.
pub const MAX_HOST_LEN: usize = 253;
const MAX_LABEL_LEN: usize = 63;

/// The text printed by `Debug` and `Display`.
pub(crate) const REDACTED_HOST: &str = "<redacted-host>";

#[derive(Clone, PartialEq, Eq, Hash)]
enum Repr {
    V4(Ipv4Addr),
    V6(Ipv6Addr),
    Dns(String),
}

/// A validated camera host. `Debug` and `Display` print `<redacted-host>`; use [`Host::expose`]
/// or [`Host::url_host`] at the last moment.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Host(Repr);

impl Host {
    /// Validates `text` as a host (see the module table).
    ///
    /// # Errors
    /// [`CameraError`] naming the failed rule, never echoing `text`.
    pub fn new(text: &str) -> Result<Self, CameraError> {
        if text.is_empty() {
            return Err(CameraError::HostEmpty);
        }
        if text.len() > MAX_HOST_LEN {
            return Err(CameraError::HostTooLong);
        }
        if !text.is_ascii() {
            return Err(CameraError::HostSyntax);
        }
        if let Some(rest) = text.strip_prefix('[') {
            let inner = rest.strip_suffix(']').ok_or(CameraError::HostSyntax)?;
            return ipv6(inner);
        }
        if text.contains(':') {
            return ipv6(text);
        }
        if let Ok(v4) = text.parse::<Ipv4Addr>() {
            return Ok(Self(Repr::V4(v4)));
        }
        dns_name(text).map(|n| Self(Repr::Dns(n)))
    }

    /// The canonical host text without brackets. Sensitive: call at the last moment.
    #[must_use]
    pub fn expose(&self) -> String {
        match &self.0 {
            Repr::V4(a) => a.to_string(),
            Repr::V6(a) => a.to_string(),
            Repr::Dns(n) => n.clone(),
        }
    }

    /// The host as it appears in a URL authority: IPv6 in brackets. Sensitive.
    #[must_use]
    pub fn url_host(&self) -> String {
        match &self.0 {
            Repr::V6(a) => format!("[{a}]"),
            _ => self.expose(),
        }
    }
}

fn ipv6(text: &str) -> Result<Host, CameraError> {
    let addr = text
        .parse::<Ipv6Addr>()
        .map_err(|_| CameraError::HostSyntax)?;
    if addr.to_ipv4_mapped().is_some() {
        return Err(CameraError::HostSyntax);
    }
    Ok(Host(Repr::V6(addr)))
}

fn dns_name(text: &str) -> Result<String, CameraError> {
    if !text
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
    {
        return Err(CameraError::HostSyntax);
    }
    let mut last = "";
    for label in text.split('.') {
        if label.is_empty() || label.len() > MAX_LABEL_LEN {
            return Err(CameraError::HostLabel);
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(CameraError::HostSyntax);
        }
        last = label;
    }
    let hex_number = last
        .strip_prefix("0x")
        .or_else(|| last.strip_prefix("0X"))
        .is_some_and(|h| h.bytes().all(|b| b.is_ascii_hexdigit()));
    if last.bytes().all(|b| b.is_ascii_digit()) || hex_number {
        return Err(CameraError::HostSyntax);
    }
    Ok(text.to_ascii_lowercase())
}

impl fmt::Debug for Host {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED_HOST)
    }
}

impl fmt::Display for Host {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED_HOST)
    }
}

impl FromStr for Host {
    type Err = CameraError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(text: &str) -> Host {
        Host::new(text).unwrap_or_else(|e| panic!("{text:?}: {e}"))
    }

    #[test]
    fn accepts_ipv4() {
        assert_eq!(ok("192.0.2.10").expose(), "192.0.2.10");
        assert_eq!(ok("192.0.2.10").url_host(), "192.0.2.10");
    }

    #[test]
    fn ipv6_bracketed_and_bare_are_the_same_host() {
        for text in [
            "2001:db8::1",
            "[2001:db8::1]",
            "2001:DB8:0:0:0:0:0:1",
            "[2001:0db8::1]",
        ] {
            let h = ok(text);
            assert_eq!(h, ok("2001:db8::1"), "{text}");
            assert_eq!(h.expose(), "2001:db8::1");
            assert_eq!(h.url_host(), "[2001:db8::1]");
        }
        assert_eq!(ok("::1").url_host(), "[::1]");
        assert_eq!(ok("64:ff9b::192.0.2.1").expose(), "64:ff9b::c000:201");
    }

    #[test]
    fn accepts_dns_names_and_lowercases() {
        for (text, want) in [
            ("nvr-1.example.invalid", "nvr-1.example.invalid"),
            ("NVR-1.Example.INVALID", "nvr-1.example.invalid"),
            ("localhost", "localhost"),
            ("a", "a"),
            (
                "xn--bcher-kva.example.invalid",
                "xn--bcher-kva.example.invalid",
            ),
            ("1a.example.invalid", "1a.example.invalid"),
            ("example.0xg", "example.0xg"),
            ("_sip._tcp.example.invalid", "_sip._tcp.example.invalid"),
            ("A_B.invalid", "a_b.invalid"),
            ("_", "_"),
            ("_1.example.invalid", "_1.example.invalid"),
        ] {
            assert_eq!(ok(text).expose(), want, "{text}");
        }
        assert_eq!(Host::new(&"a".repeat(63)).unwrap().expose().len(), 63);
        let max = format!("{0}.{0}.{0}.{1}", "a".repeat(63), "a".repeat(61));
        assert_eq!(max.len(), 253);
        assert!(Host::new(&max).is_ok());
    }

    #[test]
    fn rejects_empty_and_too_long() {
        assert_eq!(Host::new(""), Err(CameraError::HostEmpty));
        let long = format!("{0}.{0}.{0}.{1}", "a".repeat(63), "a".repeat(62));
        assert_eq!(long.len(), 254);
        assert_eq!(Host::new(&long), Err(CameraError::HostTooLong));
    }

    #[test]
    fn rejects_label_problems() {
        for bad in [
            "a..b",
            ".a",
            "a.",
            "example.invalid.",
            ".",
            "..",
            &"a".repeat(64),
        ] {
            assert_eq!(Host::new(bad), Err(CameraError::HostLabel), "{bad:?}");
        }
    }

    #[test]
    fn rejects_url_syntax_and_odd_characters() {
        let bad = [
            "user@192.0.2.1",
            "@h",
            "h@",
            "192.0.2.1:554",
            "h.invalid:554",
            "h/p",
            "h/",
            "h?q",
            "h#f",
            "rtsp://h.invalid",
            "//h",
            "h%41",
            "h%2e",
            "h\\x",
            "*.invalid",
            "a b",
            " a",
            "a ",
            "a\t",
            "a\n",
            "a\r",
            "a\0",
            "\0",
            "a\x7f",
            "a\x1b",
            "a\u{a0}",
            "a\u{3000}",
            "a\u{2003}",
            "h'",
            "h\"",
            "h;",
            "h,",
            "h=",
            "h+",
            "h!",
            "[h.invalid]",
            "-a",
            "a-",
            "a.-b",
            "a-.b",
            "a.b-",
            "-",
        ];
        for host in bad {
            assert_eq!(Host::new(host), Err(CameraError::HostSyntax), "{host:?}");
        }
    }

    #[test]
    fn rejects_ipv4_mapped_ipv6_in_every_spelling() {
        for bad in [
            "::ffff:192.0.2.1",
            "::FFFF:192.0.2.1",
            "::ffff:c000:201",
            "[::ffff:192.0.2.1]",
            "0:0:0:0:0:ffff:192.0.2.1",
            "0000:0000:0000:0000:0000:ffff:c000:0201",
            "::ffff:0:0",
        ] {
            assert_eq!(Host::new(bad), Err(CameraError::HostSyntax), "{bad:?}");
        }
        // Not mapped: IPv4-compatible and NAT64 forms keep their own spelling.
        assert!(Host::new("::192.0.2.1").is_ok());
        assert!(Host::new("::ffff:0:192.0.2.1").is_ok());
    }

    #[test]
    fn rejects_non_ascii() {
        for bad in [
            "b\u{fc}cher.invalid",
            "\u{430}.invalid",
            "a\u{ff0e}invalid",
            "\u{ff11}\u{ff12}\u{ff17}.0.0.1",
            "a\u{200b}",
            "\u{1f600}.invalid",
            "a\u{301}.invalid",
            "\u{ff3b}::1\u{ff3d}",
            "[\u{ff1a}\u{ff1a}1]",
            "192\u{3002}0.2.1",
        ] {
            assert_eq!(Host::new(bad), Err(CameraError::HostSyntax), "{bad:?}");
        }
    }

    #[test]
    fn rejects_numeric_spellings_std_refuses() {
        for bad in [
            "192.000.2.1",
            "192.00.2.1",
            "0300.0.0.1",
            "0x7f.0.0.1",
            "0x7f.0x0.0x0.0x1",
            "192.0.2",
            "127.1",
            "3221225985",
            "1.2.3.4.5",
            "256.0.0.1",
            "192.0.2.1.",
            "1",
            "0",
            "example.123",
            "example.0x7f",
            "example.0X7F",
            "example.0x",
            "0xff",
            "01.02.03.04",
            "192.0.2.-1",
            "+1.2.3.4",
        ] {
            assert!(Host::new(bad).is_err(), "{bad:?}");
        }
        assert_eq!(Host::new("192.0.2"), Err(CameraError::HostSyntax));
    }

    #[test]
    fn rejects_zone_ids_and_bad_brackets_and_ports() {
        for bad in [
            "fe80::1%eth0",
            "[fe80::1%eth0]",
            "[fe80::1%25eth0]",
            "[192.0.2.1]",
            "[::1",
            "::1]",
            "[[::1]]",
            "[]",
            "[ ::1]",
            "[::1 ]",
            "[::1]:554",
            "::1:554]",
            "[::1]/",
            "[::1]x",
            "x[::1]",
            ":",
            "::::",
            "1:2:3:4:5:6:7:8:9",
            "[",
            "]",
            "2001:db8::g",
            "2001:db8:::1",
            " ::1",
            "::1 ",
            "::1\n",
            "12345::1",
            "[::1]\n",
            "{::1}",
            "(::1)",
        ] {
            assert_eq!(Host::new(bad), Err(CameraError::HostSyntax), "{bad:?}");
        }
    }

    #[test]
    fn debug_and_display_are_redacted_everywhere() {
        let h = ok("nvr-7.example.invalid");
        for shown in [
            format!("{h}"),
            format!("{h:?}"),
            format!("{h:#?}"),
            format!("{h:>40}"),
            format!("{:?}", Some(&h)),
            format!("{:#?}", vec![h.clone()]),
        ] {
            assert!(
                !shown.contains("nvr-7") && !shown.contains("example"),
                "{shown}"
            );
            assert!(shown.contains("redacted"), "{shown}");
        }
        for text in ["192.0.2.77", "2001:db8::77"] {
            let shown = format!("{:?}{}{:#?}", ok(text), ok(text), ok(text));
            assert!(!shown.contains("77") && !shown.contains("2001"), "{shown}");
        }
    }

    #[test]
    fn errors_never_echo_input() {
        for bad in [
            "secret-host.invalid:554",
            "user@secret.invalid",
            "secret..invalid",
            "s\u{e9}cret.invalid",
        ] {
            let msg = Host::new(bad).unwrap_err().to_string();
            assert!(!msg.contains("secret"), "{msg}");
        }
    }

    proptest::proptest! {
        #[test]
        fn arbitrary_input_never_panics_and_accepted_is_clean(s in "\\PC{0,300}") {
            if let Ok(h) = Host::new(&s) {
                let text = h.expose();
                proptest::prop_assert!(text.is_ascii());
                proptest::prop_assert!(!text.contains(['@', '/', '?', '#', '%', '\\', ' ', '[', ']']));
                proptest::prop_assert!(text.len() <= MAX_HOST_LEN);
                proptest::prop_assert_eq!(Host::new(&h.url_host()).unwrap(), h);
            }
        }

        #[test]
        fn ascii_noise_never_panics(s in "[ -~]{0,80}") {
            let _ = Host::new(&s);
        }

        #[test]
        fn accepted_dns_names_are_ldh_and_not_ip_like(s in "[A-Za-z0-9.-]{1,80}") {
            if let Ok(h) = Host::new(&s) {
                let text = h.expose();
                if text.parse::<Ipv4Addr>().is_err() {
                    let last = text.rsplit('.').next().unwrap_or("");
                    proptest::prop_assert!(!last.bytes().all(|b| b.is_ascii_digit()));
                    for label in text.split('.') {
                        proptest::prop_assert!((1..=63).contains(&label.len()));
                        proptest::prop_assert!(!label.starts_with('-') && !label.ends_with('-'));
                    }
                }
            }
        }

        #[test]
        fn ipv4_round_trips(a: u8, b: u8, c: u8, d: u8) {
            let text = format!("{a}.{b}.{c}.{d}");
            let h = Host::new(&text).unwrap();
            proptest::prop_assert_eq!(h.expose(), text);
        }

        #[test]
        fn ipv6_forms_agree(bits: u128) {
            let addr = Ipv6Addr::from(bits);
            let bare = Host::new(&addr.to_string()).unwrap();
            let bracketed = Host::new(&format!("[{addr}]")).unwrap();
            proptest::prop_assert_eq!(&bare, &bracketed);
            proptest::prop_assert_eq!(bare.url_host(), format!("[{addr}]"));
        }

        #[test]
        fn numeric_last_label_is_never_a_dns_name(a in 0u32..=u32::MAX, prefix in "[a-z]{1,5}\\.") {
            let text = format!("{prefix}{a}");
            proptest::prop_assert!(Host::new(&text).is_err());
        }
    }
}
