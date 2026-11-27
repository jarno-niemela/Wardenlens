//! `wardenlens camera discover` (#67): what WS-Discovery found, shown so that the operator
//! decides. The security notes of #53 are the contract:
//!
//! * **Every** address of a device is shown, and a device whose addresses name different hosts is
//!   flagged: a host on the LAN can merge its own address into a real camera's endpoint
//!   reference, so one reply can carry a camera's address and an attacker's.
//! * Nothing is picked for the operator and nothing is fetched. `camera add` takes `--host`
//!   explicitly and vets it ([`super::guard`]) before it connects.
//! * An address that is this machine's own, or the metadata address, is marked, and so is an
//!   address that a registered camera already has.
//! * Text from the network (endpoint reference, scopes) is limited to printable ASCII by the
//!   discovery layer (its tests pin that); [`display_safe`] escapes anything else again, so a
//!   bidi override or a zero-width character cannot reach the terminal.
//! * The port is built with `NonZeroU16::new(xaddr.port())`; a zero would drop the hint.

use std::collections::{BTreeSet, HashMap};
use std::fmt::Write as _;
use std::io::{self, Write};
use std::net::IpAddr;
use std::num::NonZeroU16;
use std::time::Duration;

use wardenlens_onvif::discovery::{DiscoveredDevice, XAddr};

use super::guard::{Network, Refusal, display_safe, refusal};

/// One address of a device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct FoundAddr {
    /// The canonical URL, for the operator to read.
    pub(super) url: String,
    pub(super) host: IpAddr,
    /// The ONVIF port; `None` is impossible for a validated address and shows no hint.
    pub(super) port: Option<NonZeroU16>,
}

impl From<&XAddr> for FoundAddr {
    fn from(x: &XAddr) -> Self {
        Self {
            url: x.to_string(),
            host: x.host(),
            port: NonZeroU16::new(x.port()),
        }
    }
}

/// One device, as shown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Found {
    pub(super) endpoint: String,
    pub(super) scopes: Vec<String>,
    pub(super) addrs: Vec<FoundAddr>,
}

impl From<&DiscoveredDevice> for Found {
    fn from(d: &DiscoveredDevice) -> Self {
        Self {
            endpoint: d.endpoint_ref().to_owned(),
            scopes: d.scopes().to_vec(),
            addrs: d.xaddrs().iter().map(FoundAddr::from).collect(),
        }
    }
}

/// True when the addresses of `found` name more than one host.
pub(super) fn hosts_differ(found: &Found) -> bool {
    found
        .addrs
        .iter()
        .map(|a| a.host)
        .collect::<BTreeSet<_>>()
        .len()
        > 1
}

/// Registered camera ids by host address.
pub(super) type Registered = HashMap<IpAddr, Vec<String>>;

/// Writes the listing. Every line is printable ASCII.
pub(super) fn render(
    devices: &[Found],
    registered: &Registered,
    net: &dyn Network,
    window: Duration,
    out: &mut dyn Write,
) -> io::Result<()> {
    if devices.is_empty() {
        return writeln!(
            out,
            "no ONVIF device answered within {}ms",
            window.as_millis()
        );
    }
    writeln!(
        out,
        "{} device(s) answered; these are unverified suggestions",
        devices.len()
    )?;
    for (n, device) in devices.iter().enumerate() {
        writeln!(
            out,
            "device {}: endpoint {}",
            n.saturating_add(1),
            display_safe(&device.endpoint)
        )?;
        if hosts_differ(device) {
            writeln!(
                out,
                "  WARNING: the addresses below name different hosts; another machine may be answering for this device. Check each one yourself"
            )?;
        }
        for addr in &device.addrs {
            let mut line = format!("  address {}", display_safe(&addr.url));
            if let Some(port) = addr.port {
                let _ = write!(line, "  (--host {} --onvif-port {port})", addr.host);
            }
            match refusal(addr.host, net) {
                Some(Refusal::OwnAddress) => {
                    line.push_str("  [this machine's own address: `camera add` refuses it]");
                }
                Some(Refusal::Metadata) => {
                    line.push_str("  [metadata service address: `camera add` refuses it]");
                }
                None => {}
            }
            if let Some(ids) = registered.get(&addr.host) {
                let ids: Vec<String> = ids.iter().map(|i| display_safe(i)).collect();
                let _ = write!(line, "  [already registered as {}]", ids.join(", "));
            }
            writeln!(out, "{line}")?;
        }
        for scope in &device.scopes {
            writeln!(out, "  scope {}", display_safe(scope))?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::guard::testing::Fake;
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn addr(host: &str, port: u16) -> FoundAddr {
        FoundAddr {
            url: format!("http://{host}:{port}/onvif/device_service"),
            host: ip(host),
            port: NonZeroU16::new(port),
        }
    }

    fn device(endpoint: &str, addrs: Vec<FoundAddr>, scopes: &[&str]) -> Found {
        Found {
            endpoint: endpoint.to_owned(),
            scopes: scopes.iter().map(|s| (*s).to_owned()).collect(),
            addrs,
        }
    }

    fn net() -> Fake {
        Fake {
            own: vec![ip("192.0.2.77")],
            names: Vec::new(),
        }
    }

    fn shown(devices: &[Found], registered: &Registered) -> String {
        let mut out = Vec::new();
        render(
            devices,
            registered,
            &net(),
            Duration::from_secs(3),
            &mut out,
        )
        .unwrap();
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn no_device_is_said_plainly() {
        assert_eq!(
            shown(&[], &Registered::new()),
            "no ONVIF device answered within 3000ms\n"
        );
    }

    #[test]
    fn every_address_is_shown_and_none_is_picked() {
        let d = device(
            "urn:uuid:one",
            vec![addr("192.0.2.10", 80), addr("192.0.2.11", 8080)],
            &["onvif://www.onvif.org/name/Cam"],
        );
        let text = shown(&[d], &Registered::new());
        assert!(
            text.contains("http://192.0.2.10:80/onvif/device_service"),
            "{text}"
        );
        assert!(
            text.contains("http://192.0.2.11:8080/onvif/device_service"),
            "{text}"
        );
        assert!(text.contains("--host 192.0.2.10 --onvif-port 80"));
        assert!(text.contains("--host 192.0.2.11 --onvif-port 8080"));
        assert!(text.contains("scope onvif://www.onvif.org/name/Cam"));
        assert!(text.contains("WARNING"), "two hosts are flagged");
    }

    #[test]
    fn addresses_of_one_host_are_not_flagged_and_other_hosts_are() {
        let same = device(
            "urn:uuid:a",
            vec![addr("192.0.2.10", 80), addr("192.0.2.10", 8080)],
            &[],
        );
        assert!(!hosts_differ(&same));
        assert!(!shown(&[same], &Registered::new()).contains("WARNING"));
        let single = device("urn:uuid:b", vec![addr("192.0.2.10", 80)], &[]);
        assert!(!hosts_differ(&single));
        let mixed = device(
            "urn:uuid:c",
            vec![addr("192.0.2.10", 80), addr("198.51.100.9", 80)],
            &[],
        );
        assert!(hosts_differ(&mixed));
        // The same host as IPv4 and a different one as IPv6 differ too.
        let v6 = device(
            "urn:uuid:d",
            vec![addr("192.0.2.10", 80), addr("fd00::10", 80)],
            &[],
        );
        assert!(hosts_differ(&v6));
    }

    #[test]
    fn own_metadata_and_registered_addresses_are_marked() {
        let d = device(
            "urn:uuid:e",
            vec![
                addr("192.0.2.77", 80),
                addr("169.254.169.254", 80),
                addr("192.0.2.10", 80),
                addr("192.0.2.11", 80),
            ],
            &[],
        );
        let mut registered = Registered::new();
        registered.insert(
            ip("192.0.2.10"),
            vec!["front".to_owned(), "back".to_owned()],
        );
        let text = shown(&[d], &registered);
        let lines: Vec<&str> = text
            .lines()
            .filter(|l| l.starts_with("  address "))
            .collect();
        assert!(lines[0].contains("this machine's own address"), "{text}");
        assert!(lines[1].contains("metadata service address"), "{text}");
        assert!(
            lines[2].contains("already registered as front, back"),
            "{text}"
        );
        assert!(!lines[3].contains('['), "{text}");
    }

    /// Format characters and controls in text from the network never reach the output, even if a
    /// lower layer let one through.
    #[test]
    fn hostile_text_is_escaped() {
        let d = device(
            "urn:uuid:\u{202e}evil\u{200b}",
            vec![addr("192.0.2.10", 80)],
            &["onvif://x/\u{2066}name\r\nforged line", "\u{e9}"],
        );
        let mut registered = Registered::new();
        registered.insert(ip("192.0.2.10"), vec!["id\u{202e}".to_owned()]);
        let text = shown(&[d], &registered);
        assert!(text.contains("\\u{202e}evil\\u{200b}"), "{text}");
        assert!(
            text.contains("\\u{2066}name\\u{000d}\\u{000a}forged line"),
            "{text}"
        );
        assert!(
            text.bytes()
                .all(|b| b == b'\n' || (0x20..0x7f).contains(&b)),
            "{text:?}"
        );
        assert!(!text.lines().any(|l| l.starts_with("forged")));
    }

    #[test]
    fn a_zero_port_shows_no_hint() {
        let mut a = addr("192.0.2.10", 80);
        a.port = None;
        let text = shown(&[device("urn:uuid:f", vec![a], &[])], &Registered::new());
        assert!(!text.contains("--onvif-port"));
    }
}
