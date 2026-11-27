//! Where `camera add` may connect, and how text from the network is shown (#67, the security
//! notes of #53).
//!
//! A discovered address is a suggestion from an unauthenticated LAN reply. Before any request is
//! made the host of `camera add` is resolved (a name) or parsed (an address) and **every**
//! address it stands for must pass [`refusal`]:
//!
//! | address | result |
//! |---|---|
//! | `169.254.169.254`, `fd00:ec2::254` (cloud metadata services) | refused |
//! | an address of this machine: loopback, unspecified, or one that a UDP socket can bind | refused |
//! | anything else | allowed |
//!
//! "An address of this machine" is tested by binding a UDP socket to it (port 0): the kernel
//! accepts exactly the addresses it owns, so no interface list is parsed. A name that resolves to
//! a refused address is refused whole. The probe then connects to the vetted address, not to the
//! name again, so a second answer from the resolver cannot move it (the recorder resolves the
//! stored name later, as `import` has always made it do).

use std::fmt::Write as _;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs, UdpSocket};

use wardenlens_core::camera::Host;

/// The most addresses of one name that are looked at.
const MAX_RESOLVED: usize = 16;

/// The cloud metadata service address (IPv4).
const METADATA_V4: Ipv4Addr = Ipv4Addr::new(169, 254, 169, 254);
/// The EC2 metadata service address (IPv6).
const METADATA_V6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254);

/// The machine's network, behind a trait so tests can use loopback.
pub(crate) trait Network {
    /// True if `ip` is an address of this machine.
    fn is_own_address(&self, ip: IpAddr) -> bool;
    /// The addresses of a DNS name.
    ///
    /// # Errors
    /// The resolver's error.
    fn resolve(&self, name: &str) -> io::Result<Vec<IpAddr>>;
}

/// The real machine.
pub(crate) struct SystemNetwork;

impl Network for SystemNetwork {
    fn is_own_address(&self, ip: IpAddr) -> bool {
        ip.is_loopback() || ip.is_unspecified() || UdpSocket::bind(SocketAddr::new(ip, 0)).is_ok()
    }

    fn resolve(&self, name: &str) -> io::Result<Vec<IpAddr>> {
        Ok((name, 0_u16)
            .to_socket_addrs()?
            .map(|a| a.ip())
            .take(MAX_RESOLVED)
            .collect())
    }
}

/// Why an address is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum Refusal {
    /// The cloud metadata service.
    #[error("the address is a cloud metadata service address")]
    Metadata,
    /// An address of this machine.
    #[error("the address belongs to this machine")]
    OwnAddress,
}

/// Why a host cannot be used.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum GuardError {
    /// An address of the host is refused.
    #[error("host refused: {0}")]
    Refused(#[from] Refusal),
    /// The name did not resolve.
    #[error("the host name did not resolve to an address")]
    Unresolved,
}

/// Why `ip` may not be connected to, if so.
pub(crate) fn refusal(ip: IpAddr, net: &dyn Network) -> Option<Refusal> {
    let metadata = match ip {
        IpAddr::V4(a) => a == METADATA_V4,
        IpAddr::V6(a) => a == METADATA_V6 || a.to_ipv4_mapped() == Some(METADATA_V4),
    };
    if metadata {
        Some(Refusal::Metadata)
    } else if net.is_own_address(ip)
        || matches!(ip, IpAddr::V6(a) if a.to_ipv4_mapped().is_some_and(|m| net.is_own_address(IpAddr::V4(m))))
    {
        Some(Refusal::OwnAddress)
    } else {
        None
    }
}

/// The address to connect to for `host`, after every address it stands for passed [`refusal`].
///
/// # Errors
/// [`GuardError`].
pub(crate) fn vet_host(host: &Host, net: &dyn Network) -> Result<IpAddr, GuardError> {
    let text = host.expose();
    let all = match text.parse::<IpAddr>() {
        Ok(ip) => vec![ip],
        Err(_) => net.resolve(&text).map_err(|_| GuardError::Unresolved)?,
    };
    for ip in &all {
        if let Some(r) = refusal(*ip, net) {
            return Err(GuardError::Refused(r));
        }
    }
    all.first().copied().ok_or(GuardError::Unresolved)
}

/// The longest text shown from the network, in characters.
const MAX_SHOWN: usize = 256;

/// `text` made safe to print: printable ASCII is kept, every other character (controls, bidi and
/// other format characters, anything non-ASCII) becomes `\u{XXXX}`. At most 256 characters are
/// kept, then `...`. Discovery already limits endpoint references and scopes to printable ASCII;
/// this is the second layer, so the output of the command never carries a character that could
/// reorder or hide text.
pub(crate) fn display_safe(text: &str) -> String {
    let mut out = String::new();
    for (n, c) in text.chars().enumerate() {
        if n >= MAX_SHOWN {
            out.push_str("...");
            break;
        }
        if c.is_ascii_graphic() || c == ' ' {
            out.push(c);
        } else {
            let _ = write!(out, "\\u{{{:04x}}}", u32::from(c));
        }
    }
    out
}

#[cfg(test)]
pub(super) mod testing {
    use super::*;

    /// Everything is foreign except the listed addresses.
    pub(crate) struct Fake {
        pub(crate) own: Vec<IpAddr>,
        pub(crate) names: Vec<(&'static str, Vec<IpAddr>)>,
    }

    impl Network for Fake {
        fn is_own_address(&self, ip: IpAddr) -> bool {
            self.own.contains(&ip)
        }
        fn resolve(&self, name: &str) -> io::Result<Vec<IpAddr>> {
            self.names
                .iter()
                .find(|(n, _)| *n == name)
                .map(|(_, a)| a.clone())
                .ok_or_else(|| io::Error::other("no such name"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testing::Fake;
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn fake() -> Fake {
        Fake {
            own: vec![ip("192.0.2.77"), ip("2001:db8::77")],
            names: vec![
                ("cam.example.invalid", vec![ip("192.0.2.10")]),
                (
                    "mixed.example.invalid",
                    vec![ip("192.0.2.10"), ip("169.254.169.254")],
                ),
                ("self.example.invalid", vec![ip("192.0.2.77")]),
                ("none.example.invalid", vec![]),
            ],
        }
    }

    fn vet(host: &str) -> Result<IpAddr, GuardError> {
        vet_host(&Host::new(host).unwrap(), &fake())
    }

    #[test]
    fn the_table() {
        let net = fake();
        let refused = [
            ("169.254.169.254", Refusal::Metadata),
            ("fd00:ec2::254", Refusal::Metadata),
            ("192.0.2.77", Refusal::OwnAddress),
            ("2001:db8::77", Refusal::OwnAddress),
        ];
        for (text, why) in refused {
            assert_eq!(refusal(ip(text), &net), Some(why), "{text}");
        }
        // The mapped spelling of the metadata address is the metadata address.
        assert_eq!(
            refusal(ip("::ffff:169.254.169.254"), &net),
            Some(Refusal::Metadata)
        );
        assert_eq!(
            refusal(ip("::ffff:192.0.2.77"), &net),
            Some(Refusal::OwnAddress)
        );
        for ok in [
            "192.0.2.10",
            "169.254.169.253",
            "169.254.169.255",
            "10.0.0.1",
            "2001:db8::1",
        ] {
            assert_eq!(refusal(ip(ok), &net), None, "{ok}");
        }
    }

    #[test]
    fn a_host_is_vetted_as_an_address_or_as_every_address_of_its_name() {
        assert_eq!(vet("192.0.2.10"), Ok(ip("192.0.2.10")));
        assert_eq!(vet("cam.example.invalid"), Ok(ip("192.0.2.10")));
        assert_eq!(
            vet("169.254.169.254"),
            Err(GuardError::Refused(Refusal::Metadata))
        );
        assert_eq!(
            vet("192.0.2.77"),
            Err(GuardError::Refused(Refusal::OwnAddress))
        );
        assert_eq!(
            vet("self.example.invalid"),
            Err(GuardError::Refused(Refusal::OwnAddress))
        );
        // One bad address among good ones refuses the whole name.
        assert_eq!(
            vet("mixed.example.invalid"),
            Err(GuardError::Refused(Refusal::Metadata))
        );
        assert_eq!(vet("none.example.invalid"), Err(GuardError::Unresolved));
        assert_eq!(vet("unknown.example.invalid"), Err(GuardError::Unresolved));
    }

    /// The real network: a socket this process holds proves its address is the machine's own;
    /// loopback and the unspecified address are always refused.
    #[test]
    fn the_system_network_refuses_loopback_unspecified_and_bound_addresses() {
        let net = SystemNetwork;
        for own in ["127.0.0.1", "127.0.0.2", "::1", "0.0.0.0", "::"] {
            assert!(net.is_own_address(ip(own)), "{own}");
            assert!(refusal(ip(own), &net).is_some(), "{own}");
        }
        // TEST-NET-1 is not an address of any interface here.
        assert!(!net.is_own_address(ip("192.0.2.1")));
        assert_eq!(refusal(ip("192.0.2.1"), &net), None);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let bound = listener.local_addr().unwrap().ip();
        assert!(net.is_own_address(bound));
    }

    #[test]
    fn text_from_the_network_is_printable_ascii_only() {
        assert_eq!(
            display_safe("onvif://www.onvif.org/name/Cam 1"),
            "onvif://www.onvif.org/name/Cam 1"
        );
        // Bidi override, zero-width space, BOM, line separator, controls, a non-ASCII letter.
        let shown = display_safe("a\u{202e}b\u{200b}c\u{feff}d\u{2028}e\nf\u{7f}g\u{e9}h\0");
        assert_eq!(
            shown,
            "a\\u{202e}b\\u{200b}c\\u{feff}d\\u{2028}e\\u{000a}f\\u{007f}g\\u{00e9}h\\u{0000}"
        );
        assert!(shown.bytes().all(|b| (0x20..0x7f).contains(&b)));
        // Long text is cut.
        let long = display_safe(&"x".repeat(1000));
        assert_eq!(long.len(), MAX_SHOWN + 3);
        assert!(long.ends_with("..."));
    }
}
