//! Adversarial tests for PR #200 round 2 (ticket #53): canonical typed `XAddr`, the shared
//! `ServicePath` predicate, printable-ASCII pass-lists and the merge. Pure; no socket.

use std::fmt::Write as _;

use proptest::prelude::*;

use crate::OnvifClient;
use crate::discovery::{
    Collector, DiscoveredDevice, DropReason, XAddrDrop, parse as parse_probe_matches,
    xaddr_validate,
};

const ID: &str = "urn:uuid:00000000-0000-4000-8000-000000000001";

fn reply(matches: &str) -> String {
    format!(
        r#"<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery"><s:Header><a:RelatesTo>{ID}</a:RelatesTo></s:Header><s:Body><d:ProbeMatches>{matches}</d:ProbeMatches></s:Body></s:Envelope>"#
    )
}

fn pm(endpoint: &str, xaddrs: &str) -> String {
    format!(
        "<d:ProbeMatch><a:EndpointReference><a:Address>{endpoint}</a:Address></a:EndpointReference><d:XAddrs>{xaddrs}</d:XAddrs></d:ProbeMatch>"
    )
}

fn client() -> OnvifClient {
    OnvifClient::new(
        wardenlens_core::camera::Host::new("10.0.0.1").unwrap(),
        std::num::NonZeroU16::new(80).unwrap(),
        None,
    )
}

/// The typed value is meant to be canonical: two spellings of one service address (same host,
/// same effective port, same path) must be one `XAddr`, or dedup and merge keep both.
#[test]
fn an_explicit_default_port_is_the_same_xaddr_as_no_port() {
    let bare = xaddr_validate("http://10.0.0.1/onvif/device_service").unwrap();
    let explicit = xaddr_validate("http://10.0.0.1:80/onvif/device_service").unwrap();
    assert_eq!(bare.port(), explicit.port());
    assert_eq!(bare.to_string(), explicit.to_string(), "display differs");
    assert_eq!(bare, explicit, "one address, two XAddr values");
}

#[test]
fn one_reply_listing_both_spellings_keeps_one_xaddr() {
    let r = parse_probe_matches(
        reply(&pm(
            "urn:uuid:a",
            "http://10.0.0.1/x http://10.0.0.1:80/x http://10.0.0.1:00080/x",
        ))
        .as_bytes(),
        ID,
    )
    .unwrap();
    assert_eq!(
        r.devices[0].xaddrs().len(),
        1,
        "duplicates of one address kept"
    );
}

#[test]
fn leading_zero_ports_display_canonically() {
    let x = xaddr_validate("http://10.0.0.1:08080/x").unwrap();
    assert_eq!(x.port(), 8080);
    assert_eq!(x.to_string(), "http://10.0.0.1:8080/x");
}

#[test]
fn ipv6_spellings_collapse_to_one_value() {
    let forms = [
        "http://[fd00::1]/x",
        "http://[FD00::1]/x",
        "http://[fd00:0:0:0:0:0:0:1]/x",
        "http://[fd00:0000::0001]/x",
    ];
    let first = xaddr_validate(forms[0]).unwrap();
    for f in forms {
        assert_eq!(xaddr_validate(f).unwrap(), first, "{f}");
    }
    assert_eq!(first.to_string(), "http://[fd00::1]/x");
}

/// Hosts that are not private, or that a URL parser could read differently, never pass.
#[test]
fn host_spellings_outside_the_lan_or_ambiguous_are_refused() {
    for h in [
        "[::ffff:10.0.0.1]",
        "[::ffff:a00:1]",
        "[::10.0.0.1]",
        "[64:ff9b::a00:1]",
        "[2002:a00:1::1]",
        "[fec0::1]",
        "[fe80::1]",
        "[febf::1]",
        "[ff02::1]",
        "[fd00::1%25eth0]",
        "[fd00::1%eth0]",
        "[fd00::1",
        "fd00::1",
        "[10.0.0.1]",
        "010.0.0.1",
        "10.0.0.01",
        "0x0a.0.0.1",
        "10.1",
        "167772161",
        "10.0.0.1.",
        " 10.0.0.1",
        "10.0.0.256",
        "",
        "169.254.0.0.1",
        "172.32.0.1",
        "172.15.255.255",
        "192.169.0.1",
        "100.64.0.1",
        "127.0.0.1",
        "0.0.0.0",
        "255.255.255.255",
        "224.0.0.1",
        "8.8.8.8",
    ] {
        let raw = format!("http://{h}/x");
        assert!(xaddr_validate(&raw).is_err(), "{raw} accepted");
    }
}

/// Paths a client might normalise into something else never pass, and everything that passes is
/// accepted by the client unchanged.
#[test]
fn path_tricks_are_refused_by_the_shared_predicate() {
    for p in [
        "/a/../b",
        "/..",
        "/.",
        "/a/.",
        "//evil/x",
        "/a?b",
        "/a#b",
        "/%2e%2e/x",
        "/a\\b",
        "/a b",
        "/a@b",
        "/a[b]",
        "/a\"b",
        "/a<b",
        "/a{b}",
        "/a|b",
        "/a^b",
        "/a`b",
    ] {
        let raw = format!("http://10.0.0.1{p}");
        assert!(xaddr_validate(&raw).is_err(), "{raw:?} accepted");
        assert!(client().with_device_path(p).is_err(), "client took {p:?}");
    }
    for raw in [
        "http://10.0.0.1?x",
        "http://10.0.0.1#x",
        "http://10.0.0.1:80?x",
        "http://10.0.0.1:80#/x",
        "http://[fd00::1]?/x",
        "http://10.0.0.1\\@8.8.8.8/x",
        "http://10.0.0.1\\x",
        "http:/10.0.0.1/x",
        "http:10.0.0.1/x",
        "http//10.0.0.1/x",
        "://10.0.0.1/x",
        "http+unix://10.0.0.1/x",
        " http://10.0.0.1/x",
    ] {
        assert!(xaddr_validate(raw).is_err(), "{raw:?} accepted");
    }
    let longest = format!("/{}", "a".repeat(255));
    assert!(xaddr_validate(&format!("http://10.0.0.1{longest}")).is_ok());
    let over = format!("/{}", "a".repeat(256));
    assert_eq!(
        xaddr_validate(&format!("http://10.0.0.1{over}")),
        Err(XAddrDrop::BadPath)
    );
}

fn lan_host() -> impl Strategy<Value = String> {
    prop_oneof![
        (any::<u8>(), any::<u8>(), any::<u8>()).prop_map(|(a, b, c)| format!("10.{a}.{b}.{c}")),
        (16_u8..32, any::<u8>(), any::<u8>()).prop_map(|(a, b, c)| format!("172.{a}.{b}.{c}")),
        (any::<u8>(), any::<u8>()).prop_map(|(b, c)| format!("192.168.{b}.{c}")),
        (any::<u8>(), any::<u8>()).prop_map(|(b, c)| format!("169.254.{b}.{c}")),
        (0xfc00_u16..=0xfdff, any::<u16>(), any::<u16>())
            .prop_map(|(a, b, c)| format!("[{a:X}:{b:x}::0:{c:x}]")),
    ]
}

fn path_char() -> impl Strategy<Value = char> {
    // The client's whole allowed set plus a few it refuses, so both branches are reached.
    prop::sample::select(
        "abcXYZ019-._~:!$&'()*+,;=/%?#@[] \\"
            .chars()
            .collect::<Vec<_>>(),
    )
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    /// Display is canonical: re-validating it gives the same value and the same text, and the
    /// parts are exactly what the client is handed.
    #[test]
    fn display_round_trips_and_the_path_is_client_valid(
        host in lan_host(),
        port in prop::option::of(prop_oneof![Just(80_u16), 1_u16..=65535]),
        zeros in 0_usize..3,
        path in prop::collection::vec(path_char(), 0..20),
        upper in any::<bool>(),
    ) {
        let path: String = path.into_iter().collect();
        let path = if path.is_empty() { String::new() } else { format!("/{path}") };
        let port_text = port.map_or_else(String::new, |p| format!(":{}{p}", "0".repeat(zeros)));
        let scheme = if upper { "HTTP" } else { "http" };
        let raw = format!("{scheme}://{host}{port_text}{path}");
        let client_ok = path.is_empty() || client().with_device_path(&path).is_ok();
        match xaddr_validate(&raw) {
            Ok(x) => {
                prop_assert!(client_ok, "{raw:?} accepted but the client refuses its path");
                prop_assert!(client().with_device_path(x.path()).is_ok());
                let shown = x.to_string();
                let again = xaddr_validate(&shown).unwrap();
                prop_assert_eq!(&again, &x);
                prop_assert_eq!(again.to_string(), shown.clone());
                prop_assert_eq!(x.port(), port.unwrap_or(80));
                prop_assert!(shown.starts_with("http://"));
            }
            Err(e) => {
                // Only the path or an over-long port spelling can be the reason here.
                let over_long_port = port_text.len() > 6;
                prop_assert!(
                    (!client_ok && (e == XAddrDrop::BadPath || (path.contains(' ') && e == XAddrDrop::BadCharacters))) || (over_long_port && e == XAddrDrop::BadPort),
                    "{raw:?} refused as {e:?}"
                );
            }
        }
    }
}

/// Two entries in one reply with the same endpoint reference but different spellings of one
/// address are merged by the collector into a single `XAddr`.
#[test]
fn the_merge_does_not_keep_two_spellings_of_one_address() {
    let mut c = Collector::default();
    let mut drops: Vec<DropReason> = Vec::new();
    c.add(
        DiscoveredDevice::for_test("urn:uuid:a", &["http://10.0.0.1/x"], &[]),
        &mut drops,
    );
    c.add(
        DiscoveredDevice::for_test("urn:uuid:a", &["http://10.0.0.1:80/x"], &[]),
        &mut drops,
    );
    let d = c.into_devices();
    assert_eq!(d.len(), 1);
    assert_eq!(
        d[0].xaddrs().len(),
        1,
        "merged device holds one address twice"
    );
}

/// Character references cannot smuggle a non-printable or non-ASCII byte past the pass-lists.
#[test]
fn character_references_do_not_bypass_the_pass_lists() {
    for r in [
        "&#x7f;", "&#xA0;", "&#x85;", "&#x200B;", "&#x202E;", "&#xFEFF;", "&#x2028;", "&#x20;",
        "&#xD;", "&#x9;", "&#xA;", "&#xC;", "&#xB;",
    ] {
        let x = parse_probe_matches(
            reply(&pm(&format!("urn:uuid:a{r}b"), "http://10.0.0.1/x")).as_bytes(),
            ID,
        );
        if let Ok(x) = x {
            for d in &x.devices {
                assert!(
                    d.endpoint_ref().bytes().all(|b| (0x21..=0x7e).contains(&b)),
                    "{r}: endpoint kept a non-printable byte"
                );
            }
        }
        let x = parse_probe_matches(
            reply(&pm("urn:uuid:a", &format!("http://10.0.0.1/a{r}b"))).as_bytes(),
            ID,
        );
        if let Ok(x) = x {
            for d in &x.devices {
                for a in d.xaddrs() {
                    assert!(
                        a.to_string().bytes().all(|b| (0x21..=0x7e).contains(&b)),
                        "{r}: xaddr kept a non-printable byte"
                    );
                }
            }
        }
    }
}

/// A heavy echoing reply: 16 entries whose only `XAddr` is refused, padded with siblings up to
/// the element cap, so each datagram costs the most parsing and yields no device.
fn heavy(id: &str) -> Vec<u8> {
    let mut m = String::new();
    for i in 0..16 {
        let _ = write!(
            m,
            "<d:ProbeMatch><a:EndpointReference><a:Address>urn:uuid:{i}</a:Address></a:EndpointReference><d:XAddrs>https://10.0.0.1/x</d:XAddrs></d:ProbeMatch>"
        );
    }
    let mut pad = String::new();
    // 16 entries use 4 elements each, the envelope 5: fill the rest of the 4096-element cap.
    for _ in 0..(4096 - 5 - 16 * 4) {
        pad.push_str("<q/>");
    }
    format!(
        r#"<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery"><s:Header><a:RelatesTo>{id}</a:RelatesTo></s:Header><s:Body><d:ProbeMatches>{pad}{m}</d:ProbeMatches></s:Body></s:Envelope>"#
    )
    .into_bytes()
}

#[test]
fn a_heavy_echoing_reply_parses_and_yields_nothing() {
    let d = heavy(ID);
    assert!(d.len() <= crate::discovery::MAX_DATAGRAM);
    let r = parse_probe_matches(&d, ID).unwrap();
    assert_eq!(r.devices, Vec::new());
    // Each entry: its https XAddr, then the entry itself for having none left.
    assert_eq!(r.drops.len(), 32);
}

/// An endless flood of heavy, echoing, device-less replies from another OS thread (so it really
/// is continuous) cannot keep `run` past its window by much.
#[tokio::test]
async fn a_continuous_echoing_flood_cannot_extend_the_window() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    let sock = std::net::UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
    let to = sock.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let stop2 = Arc::clone(&stop);
    let flooder = std::thread::spawn(move || {
        let mut buf = vec![0_u8; 70_000];
        let Ok((n, from)) = sock.recv_from(&mut buf) else {
            return 0_usize;
        };
        let probe = String::from_utf8_lossy(&buf[..n]).into_owned();
        let id = probe
            .split("<w:MessageID>")
            .nth(1)
            .and_then(|r| r.split("</w:MessageID>").next())
            .unwrap_or("")
            .to_owned();
        let d = heavy(&id);
        let mut sent = 0;
        while !stop2.load(Ordering::Relaxed) {
            if sock.send_to(&d, from).is_ok() {
                sent += 1;
            }
        }
        sent
    });
    let started = std::time::Instant::now();
    let got = crate::discovery::run(
        to,
        std::net::Ipv4Addr::LOCALHOST,
        std::time::Duration::from_millis(500),
        crate::discovery::MAX_REPLIES,
        ID,
    )
    .await;
    let took = started.elapsed();
    stop.store(true, Ordering::Relaxed);
    let sent = flooder.join().unwrap();
    assert_eq!(got, Ok(Vec::new()));
    assert!(sent > 0);
    // A flood that keeps the loop alive past its window would never end, so the bound is far
    // above the 500 ms window and the scheduler's slack (TEST-5: it must not gauge host load).
    assert!(
        took < std::time::Duration::from_secs(20),
        "{took:?} for a 500 ms window ({sent} sent)"
    );
}
