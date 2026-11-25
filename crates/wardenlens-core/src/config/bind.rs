//! LAN-only bind classification (ADR 0004 section 9, SEC-10).
//!
//! One classifier maps an address to a [`BindClass`]. Only classes on the pass-list are ever
//! accepted; everything else, including every special range not named below, is
//! [`BindClass::Refused`]. A new range therefore fails closed.
//!
//! Embedded-IPv4 forms other than IPv4-mapped (`::ffff:a.b.c.d`) are refused and never
//! classified by their embedded address: IPv4-compatible (`::a.b.c.d`, deprecated), the NAT64
//! prefixes `64:ff9b::/96` (RFC 6052) and `64:ff9b:1::/48` (RFC 8215), 6to4 `2002::/16`
//! (RFC 3056) and IPv4-translated `::ffff:0:0:0/96` (RFC 2765). A translator would forward the
//! traffic to an address the operator did not name.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// The class of a listen address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum BindClass {
    /// `127.0.0.0/8` or `::1`.
    Loopback,
    /// RFC 1918: `10/8`, `172.16/12`, `192.168/16`.
    Private,
    /// IPv6 unique local `fc00::/7`.
    UniqueLocal,
    /// `169.254/16` or `fe80::/10`.
    LinkLocal,
    /// Shared address space `100.64.0.0/10`; needs `api.allow_cgnat_bind`.
    Cgnat,
    /// `0.0.0.0`, `::` or `::ffff:0.0.0.0`; needs `api.allow_unspecified_bind`.
    Unspecified,
    /// Anything else.
    Refused,
}

/// Why a listen address was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum BindError {
    /// The address is not in an allowed class.
    NotLan,
    /// An unspecified address without `api.allow_unspecified_bind`.
    UnspecifiedNotAllowed,
    /// A CGNAT address without `api.allow_cgnat_bind`.
    CgnatNotAllowed,
    /// Port 0 asks the system for a random port.
    PortZero,
}

/// Classifies `ip`. An IPv6 scope id is not part of an `IpAddr` and is ignored.
#[must_use]
pub fn classify(ip: IpAddr) -> BindClass {
    match ip {
        IpAddr::V4(v4) => classify_v4(v4),
        IpAddr::V6(v6) => classify_v6(v6),
    }
}

fn classify_v4(ip: Ipv4Addr) -> BindClass {
    let [a, b, _, _] = ip.octets();
    if ip.is_unspecified() {
        BindClass::Unspecified
    } else if a == 127 {
        BindClass::Loopback
    } else if a == 10 || (a == 172 && b & 0xf0 == 16) || (a == 192 && b == 168) {
        BindClass::Private
    } else if a == 169 && b == 254 {
        BindClass::LinkLocal
    } else if a == 100 && b & 0xc0 == 64 {
        BindClass::Cgnat
    } else {
        BindClass::Refused
    }
}

fn classify_v6(ip: Ipv6Addr) -> BindClass {
    if let Some(v4) = ip.to_ipv4_mapped() {
        return classify_v4(v4);
    }
    let [first, ..] = ip.segments();
    if ip.is_unspecified() {
        BindClass::Unspecified
    } else if ip.is_loopback() {
        BindClass::Loopback
    } else if first & 0xfe00 == 0xfc00 {
        BindClass::UniqueLocal
    } else if first & 0xffc0 == 0xfe80 {
        BindClass::LinkLocal
    } else {
        BindClass::Refused
    }
}

/// Applies the LAN-only rule to a listen address.
///
/// # Errors
/// [`BindError`] naming the first rule that fails.
pub fn check_bind(
    addr: SocketAddr,
    allow_unspecified: bool,
    allow_cgnat: bool,
) -> Result<BindClass, BindError> {
    if addr.port() == 0 {
        return Err(BindError::PortZero);
    }
    let class = classify(addr.ip());
    match class {
        BindClass::Refused => Err(BindError::NotLan),
        BindClass::Unspecified if !allow_unspecified => Err(BindError::UnspecifiedNotAllowed),
        BindClass::Cgnat if !allow_cgnat => Err(BindError::CgnatNotAllowed),
        _ => Ok(class),
    }
}

#[cfg(test)]
mod tests {
    use super::BindClass::{
        Cgnat, LinkLocal, Loopback, Private, Refused, UniqueLocal, Unspecified,
    };
    use super::*;

    fn v4(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    /// Every IPv4 range edge: first, last, and the address just outside each end.
    const V4_TABLE: &[(&str, BindClass)] = &[
        // loopback 127/8
        ("126.255.255.255", Refused),
        ("127.0.0.0", Loopback),
        ("127.0.0.1", Loopback),
        ("127.255.255.255", Loopback),
        ("128.0.0.0", Refused),
        // 10/8
        ("9.255.255.255", Refused),
        ("10.0.0.0", Private),
        ("10.255.255.255", Private),
        ("11.0.0.0", Refused),
        // 172.16/12
        ("172.15.255.255", Refused),
        ("172.16.0.0", Private),
        ("172.31.255.255", Private),
        ("172.32.0.0", Refused),
        // 192.168/16
        ("192.167.255.255", Refused),
        ("192.168.0.0", Private),
        ("192.168.255.255", Private),
        ("192.169.0.0", Refused),
        // link-local 169.254/16
        ("169.253.255.255", Refused),
        ("169.254.0.0", LinkLocal),
        ("169.254.255.255", LinkLocal),
        ("169.255.0.0", Refused),
        // CGNAT 100.64/10
        ("100.63.255.255", Refused),
        ("100.64.0.0", Cgnat),
        ("100.127.255.255", Cgnat),
        ("100.128.0.0", Refused),
        // 0/8: only the exact unspecified address
        ("0.0.0.0", Unspecified),
        ("0.0.0.1", Refused),
        ("0.255.255.255", Refused),
        ("1.0.0.0", Refused),
        // documentation, benchmarking, protocol assignments
        ("192.0.2.0", Refused),
        ("192.0.2.1", Refused),
        ("192.0.2.255", Refused),
        ("198.51.100.1", Refused),
        ("203.0.113.1", Refused),
        ("198.18.0.1", Refused),
        ("198.19.255.255", Refused),
        ("192.0.0.1", Refused),
        // public, multicast, reserved, broadcast
        ("8.8.8.8", Refused),
        ("1.1.1.1", Refused),
        ("223.255.255.255", Refused),
        ("224.0.0.0", Refused),
        ("224.0.0.1", Refused),
        ("239.255.255.255", Refused),
        ("240.0.0.0", Refused),
        ("255.255.255.254", Refused),
        ("255.255.255.255", Refused),
    ];

    #[test]
    fn v4_range_edges() {
        for (text, want) in V4_TABLE {
            assert_eq!(classify(IpAddr::V4(v4(text))), *want, "{text}");
        }
    }

    #[test]
    fn every_v4_case_is_classified_the_same_when_ipv4_mapped() {
        for (text, want) in V4_TABLE {
            let mapped = v4(text).to_ipv6_mapped();
            assert_eq!(classify(IpAddr::V6(mapped)), *want, "::ffff:{text}");
        }
    }

    /// Independent reference: ranges as inclusive u32 intervals.
    fn reference(ip: Ipv4Addr) -> BindClass {
        let n = u32::from(ip);
        let within = |lo: &str, hi: &str| u32::from(v4(lo)) <= n && n <= u32::from(v4(hi));
        if n == 0 {
            Unspecified
        } else if within("127.0.0.0", "127.255.255.255") {
            Loopback
        } else if within("10.0.0.0", "10.255.255.255")
            || within("172.16.0.0", "172.31.255.255")
            || within("192.168.0.0", "192.168.255.255")
        {
            Private
        } else if within("169.254.0.0", "169.254.255.255") {
            LinkLocal
        } else if within("100.64.0.0", "100.127.255.255") {
            Cgnat
        } else {
            Refused
        }
    }

    #[test]
    fn v4_matches_reference_over_every_slash_16_edge() {
        for hi in 0..=u16::MAX {
            for low in [0_u16, 1, 255, 256, 0x8000, u16::MAX] {
                let ip = Ipv4Addr::from(u32::from(hi) << 16 | u32::from(low));
                assert_eq!(classify_v4(ip), reference(ip), "{ip}");
            }
        }
    }

    const V6_TABLE: &[(&str, BindClass)] = &[
        ("::", Unspecified),
        ("::1", Loopback),
        ("::2", Refused),
        ("0:0:0:0:0:0:1:0", Refused),
        // unique local fc00::/7
        ("fbff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", Refused),
        ("fc00::", UniqueLocal),
        ("fd12:3456::1", UniqueLocal),
        ("fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", UniqueLocal),
        ("fe00::", Refused),
        // link-local fe80::/10
        ("fe7f:ffff:ffff:ffff:ffff:ffff:ffff:ffff", Refused),
        ("fe80::", LinkLocal),
        ("fe80::1", LinkLocal),
        ("febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff", LinkLocal),
        ("fec0::", Refused),
        // multicast, documentation, public, discard
        ("ff00::", Refused),
        ("ff02::1", Refused),
        ("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", Refused),
        ("2001:db8::1", Refused),
        ("2606:4700:4700::1111", Refused),
        ("2001:4860:4860::8888", Refused),
        ("100::1", Refused),
        // embedded IPv4 forms other than IPv4-mapped: refused whatever they embed
        ("::10.0.0.1", Refused),
        ("::127.0.0.1", Refused),
        ("::192.168.1.1", Refused),
        ("::0.0.0.2", Refused),
        ("64:ff9b::10.0.0.1", Refused),
        ("64:ff9b::7f00:1", Refused),
        ("64:ff9b::808:808", Refused),
        ("64:ff9b:1::a00:1", Refused),
        ("2002:c0a8:101::", Refused),
        ("2002:a00:1::1", Refused),
        ("2002:7f00:1::1", Refused),
        ("::ffff:0:10.0.0.1", Refused),
        ("::ffff:0:a00:1", Refused),
        // mapped forms written in IPv6 notation
        ("::ffff:10.0.0.1", Private),
        ("::ffff:a00:1", Private),
        ("::ffff:0.0.0.0", Unspecified),
        ("::ffff:8.8.8.8", Refused),
        ("::ffff:192.0.2.1", Refused),
        ("::ffff:100.64.0.1", Cgnat),
        ("::ffff:255.255.255.255", Refused),
    ];

    #[test]
    fn v6_table() {
        for (text, want) in V6_TABLE {
            let ip: Ipv6Addr = text.parse().unwrap();
            assert_eq!(classify(IpAddr::V6(ip)), *want, "{text}");
        }
    }

    fn check(text: &str, unspec: bool, cgnat: bool) -> Result<BindClass, BindError> {
        check_bind(text.parse().unwrap(), unspec, cgnat)
    }

    #[test]
    fn unspecified_needs_its_own_flag_in_all_three_forms() {
        for text in ["0.0.0.0:8080", "[::]:8080", "[::ffff:0.0.0.0]:8080"] {
            assert_eq!(
                check(text, false, false),
                Err(BindError::UnspecifiedNotAllowed),
                "{text}"
            );
            assert_eq!(
                check(text, false, true),
                Err(BindError::UnspecifiedNotAllowed),
                "{text} cgnat flag must not open it"
            );
            assert_eq!(check(text, true, false), Ok(Unspecified), "{text}");
        }
    }

    #[test]
    fn cgnat_needs_its_own_flag() {
        for text in [
            "100.64.0.1:80",
            "100.127.255.255:80",
            "[::ffff:100.64.0.1]:80",
        ] {
            assert_eq!(check(text, false, false), Err(BindError::CgnatNotAllowed));
            assert_eq!(
                check(text, true, false),
                Err(BindError::CgnatNotAllowed),
                "{text} unspecified flag must not open it"
            );
            assert_eq!(check(text, false, true), Ok(Cgnat), "{text}");
        }
    }

    #[test]
    fn flags_never_open_refused_addresses() {
        for text in [
            "192.0.2.1:80",
            "8.8.8.8:80",
            "[2001:db8::1]:80",
            "[ff02::1]:80",
        ] {
            assert_eq!(check(text, true, true), Err(BindError::NotLan), "{text}");
        }
    }

    #[test]
    fn default_flags_accept_the_lan_classes() {
        for (text, class) in [
            ("127.0.0.1:80", Loopback),
            ("[::1]:80", Loopback),
            ("10.1.2.3:80", Private),
            ("172.16.0.1:80", Private),
            ("192.168.1.1:80", Private),
            ("[fd00::1]:80", UniqueLocal),
            ("169.254.1.1:80", LinkLocal),
            ("[fe80::1]:80", LinkLocal),
            ("[::ffff:192.168.1.1]:80", Private),
        ] {
            assert_eq!(check(text, false, false), Ok(class), "{text}");
        }
    }

    #[test]
    fn port_zero_is_refused_for_every_class() {
        for text in ["127.0.0.1:0", "[fe80::1]:0", "0.0.0.0:0"] {
            assert_eq!(check(text, true, true), Err(BindError::PortZero), "{text}");
        }
    }

    #[test]
    fn numeric_scope_ids_are_ignored_for_classification() {
        assert_eq!(check("[fe80::1%2]:80", false, false), Ok(LinkLocal));
        assert_eq!(
            check("[fe80::1%4294967295]:80", false, false),
            Ok(LinkLocal)
        );
        assert_eq!(
            check("[2001:db8::1%2]:80", false, false),
            Err(BindError::NotLan)
        );
    }

    #[test]
    fn non_numeric_scope_ids_missing_ports_and_hostnames_do_not_parse() {
        for text in [
            "[fe80::1%eth0]:80",
            "[fe80::1%]:80",
            "fe80::1%2:80",
            "127.0.0.1",
            "[::1]",
            "localhost:80",
            "example.com:80",
            ":80",
            "",
            "127.0.0.1:99999",
            "127.0.0.1:-1",
            "1.2.3:80",
            "0x7f.0.0.1:80",
            "127.1:80",
            "010.0.0.1:80",
        ] {
            assert!(text.parse::<SocketAddr>().is_err(), "{text:?}");
        }
    }
}
