//! WS-Discovery (#53). Synthetic replies on private addresses only. The socket path is driven
//! over loopback UDP; nothing is ever sent to the multicast group.
//!
//! Input spaces enumerated here (TEST-9): the `XAddr` pass-list (`XADDR_TABLE`, one row per
//! scheme, userinfo, host spelling, address boundary, port and path form), the reply envelope
//! (`NOT_OURS`, `BAD_XML`), and the per-device caps.

use std::collections::BTreeSet;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use proptest::prelude::*;
use tokio::net::UdpSocket;

use crate::OnvifError;
use crate::discovery::{
    DEFAULT_WINDOW, DiscoveredDevice, DiscoveryError, DropReason, MAX_DATAGRAM, MAX_DEVICES,
    MAX_REPLIES, MAX_SCOPES, MAX_WINDOW, MAX_XADDRS, ProbeReplyError, XAddrDrop, build_probe,
    effective_window, parse as parse_probe_matches, run,
};

const ID: &str = "uuid:00000000000000000000000000000001";
const NS: &str = r#"xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery""#;

fn pm(endpoint: &str, xaddrs: &str, scopes: &str) -> String {
    format!(
        "<d:ProbeMatch><a:EndpointReference><a:Address>{endpoint}</a:Address></a:EndpointReference>\
         <d:Types>dn:NetworkVideoTransmitter</d:Types><d:Scopes>{scopes}</d:Scopes>\
         <d:XAddrs>{xaddrs}</d:XAddrs><d:MetadataVersion>1</d:MetadataVersion></d:ProbeMatch>"
    )
}

fn reply_for(relates: &str, matches: &[String]) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?><s:Envelope {NS}><s:Header><a:RelatesTo>{relates}</a:RelatesTo></s:Header><s:Body><d:ProbeMatches>{}</d:ProbeMatches></s:Body></s:Envelope>"#,
        matches.concat()
    )
}

fn reply(matches: &[String]) -> String {
    reply_for(ID, matches)
}

fn good() -> String {
    reply(&[pm(
        "urn:uuid:aaaa",
        "http://192.168.1.10/onvif/device_service",
        "onvif://www.onvif.org/name/Cam onvif://www.onvif.org/hardware/X",
    )])
}

fn dev(refr: &str, xaddrs: &[&str], scopes: &[&str]) -> DiscoveredDevice {
    let d = DiscoveredDevice::for_test(refr, xaddrs, scopes);
    assert_eq!(
        d.xaddrs().len(),
        xaddrs.len(),
        "test fixture xaddr must validate"
    );
    d
}

// ---- the XAddr pass-list ----

/// (input, expected canonical output or the drop reason)
#[expect(
    clippy::too_many_lines,
    reason = "one row per enumerated form (TEST-9)"
)]
fn xaddr_table() -> Vec<(String, Result<String, XAddrDrop>)> {
    use XAddrDrop::*;
    let ok = |a: &str, b: &str| (a.to_owned(), Ok(b.to_owned()));
    let no = |a: &str, r: XAddrDrop| (a.to_owned(), Err(r));
    vec![
        // good forms
        ok(
            "http://192.168.1.10/onvif/device_service",
            "http://192.168.1.10/onvif/device_service",
        ),
        ok("http://192.168.1.10:8080/x", "http://192.168.1.10:8080/x"),
        ok("HTTP://10.0.0.1/x", "http://10.0.0.1/x"),
        ok("http://10.0.0.1", "http://10.0.0.1/"),
        ok("http://[fd12::1]:2020/onvif", "http://[fd12::1]:2020/onvif"),
        no("http://[FE80::0:1]/x", OutsideLan),
        ok("http://[FD00::0:1]/x", "http://[fd00::1]/x"),
        // schemes
        no("https://192.168.1.10/x", Https),
        no("HTTPS://192.168.1.10/x", Https),
        no("rtsp://192.168.1.10/x", OtherScheme),
        no("httpx://192.168.1.10/x", OtherScheme),
        no("192.168.1.10/x", NoScheme),
        no("//192.168.1.10/x", NoScheme),
        // userinfo and host spellings
        no("http://user@192.168.1.10/x", Userinfo),
        no("http://user:pw@192.168.1.10/x", Userinfo),
        no("http://192.168.1.10@8.8.8.8/x", Userinfo),
        no("http://192.168.1.10:80@10.0.0.1/x", Userinfo),
        no("http://camera.local/x", NotIpLiteral),
        no("http://192.168.1.10.evil.example/x", NotIpLiteral),
        no("http://3232235786/x", NotIpLiteral),
        no("http://0xc0.0xa8.1.10/x", NotIpLiteral),
        no("http://0300.168.1.10/x", NotIpLiteral),
        no("http://192.168.1/x", NotIpLiteral),
        no("http://192.168.1.10./x", NotIpLiteral),
        no("http:///x", NotIpLiteral),
        no("http://[fe80::1%25eth0]/x", NotIpLiteral),
        no("http://[fe80::1/x", NotIpLiteral),
        no("http://[fe80::1]x/x", NotIpLiteral),
        no("http://[::ffff:192.168.1.10]/x", OutsideLan),
        no("http://192.168.1.10:80:80/x", BadPort),
        // address boundaries
        no("http://9.255.255.255/x", OutsideLan),
        ok("http://10.0.0.0/x", "http://10.0.0.0/x"),
        ok("http://10.255.255.255/x", "http://10.255.255.255/x"),
        no("http://11.0.0.0/x", OutsideLan),
        no("http://172.15.255.255/x", OutsideLan),
        ok("http://172.16.0.0/x", "http://172.16.0.0/x"),
        ok("http://172.31.255.255/x", "http://172.31.255.255/x"),
        no("http://172.32.0.0/x", OutsideLan),
        no("http://192.167.255.255/x", OutsideLan),
        ok("http://192.168.0.0/x", "http://192.168.0.0/x"),
        ok("http://192.168.255.255/x", "http://192.168.255.255/x"),
        no("http://192.169.0.0/x", OutsideLan),
        no("http://169.253.255.255/x", OutsideLan),
        ok("http://169.254.0.1/x", "http://169.254.0.1/x"),
        ok("http://169.254.255.255/x", "http://169.254.255.255/x"),
        no("http://169.255.0.0/x", OutsideLan),
        no("http://127.0.0.1/x", OutsideLan),
        no("http://0.0.0.0/x", OutsideLan),
        no("http://255.255.255.255/x", OutsideLan),
        no("http://100.64.0.1/x", OutsideLan),
        no("http://192.0.2.10/x", OutsideLan),
        no("http://8.8.8.8/x", OutsideLan),
        no("http://[::1]/x", OutsideLan),
        no("http://[::]/x", OutsideLan),
        no("http://[2001:db8::1]/x", OutsideLan),
        no("http://[fbff::1]/x", OutsideLan),
        ok("http://[fc00::1]/x", "http://[fc00::1]/x"),
        ok("http://[fdff::1]/x", "http://[fdff::1]/x"),
        no("http://[fe00::1]/x", OutsideLan),
        no("http://[fe80::1]/x", OutsideLan),
        no("http://[febf::1]/x", OutsideLan),
        no("http://[fe80::1]:80/x", OutsideLan),
        no("http://[fec0::1]/x", OutsideLan),
        no("http://[ff02::1]/x", OutsideLan),
        // ports
        ok("http://10.0.0.1:1/x", "http://10.0.0.1:1/x"),
        ok("http://10.0.0.1:65535/x", "http://10.0.0.1:65535/x"),
        no("http://10.0.0.1:0/x", BadPort),
        no("http://10.0.0.1:65536/x", BadPort),
        no("http://10.0.0.1:/x", BadPort),
        no("http://10.0.0.1:80a/x", BadPort),
        no("http://10.0.0.1:+80/x", BadPort),
        no("http://10.0.0.1:000080/x", BadPort),
        // paths
        no("http://10.0.0.1/x#frag", BadPath),
        no("http://10.0.0.1/x?q=1", BadPath),
        no("http://10.0.0.1?q=1", BadPath),
        no("http://10.0.0.1#f", BadPath),
        no("http://10.0.0.1/a%2fb", BadPath),
        no("http://10.0.0.1//x", BadPath),
        no("http://10.0.0.1//8.8.8.8/x", BadPath),
        no("http://10.0.0.1/a/../b", BadPath),
        no("http://10.0.0.1/..", BadPath),
        no("http://10.0.0.1/./x", BadPath),
        no("http://10.0.0.1/a@b", BadPath),
        no("http://10.0.0.1/@", BadPath),
        no("http://10.0.0.1/a\"b", BadPath),
        no("http://10.0.0.1/a<b", BadPath),
        no("http://10.0.0.1/a\\b", BadPath),
        // characters
        no("http://10.0.0.1/a b", BadCharacters),
        no("", NoScheme),
        no("http://10.0.0.1/\u{e9}", BadCharacters),
        no("http://10.0.0.1/\u{7f}", BadCharacters),
        no("http://10.0.0.1/a\nb", BadCharacters),
        no("http://10.0.0.1/\u{2028}", BadCharacters),
        no("http://\u{ff11}\u{ff10}.0.0.1/x", BadCharacters),
    ]
}

#[test]
fn xaddr_pass_list_table() {
    use crate::discovery::xaddr_validate as validate;
    for (input, want) in xaddr_table() {
        assert_eq!(
            validate(&input).map(|x| x.to_string()),
            want,
            "input {input:?}"
        );
    }
}

#[test]
fn xaddr_length_boundaries() {
    use crate::discovery::xaddr_validate as validate;
    // Path: 256 bytes is the client's limit (the `/` counts).
    let path = |n: usize| format!("http://10.0.0.1/{}", "a".repeat(n - 1));
    assert!(validate(&path(255)).is_ok());
    assert!(validate(&path(256)).is_ok());
    assert_eq!(validate(&path(257)), Err(XAddrDrop::BadPath));
    assert_eq!(validate(&path(300)), Err(XAddrDrop::BadPath));
    // Whole URL: 512 bytes is looked at, one more is refused before anything else.
    let url = |n: usize| format!("{}{}", "x".repeat(n - 1), "y");
    assert_eq!(validate(&url(512)), Err(XAddrDrop::NoScheme));
    assert_eq!(validate(&url(513)), Err(XAddrDrop::TooLong));
}

fn lan_oracle(u: &str) -> bool {
    let Some(rest) = u.strip_prefix("http://") else {
        return false;
    };
    let authority = rest.split('/').next().unwrap_or("");
    if let Some(inner) = authority.strip_prefix('[') {
        let host = inner.split(']').next().unwrap_or("");
        // Unique local only: `fe80::/10` needs a zone id and is refused.
        return host
            .parse::<std::net::Ipv6Addr>()
            .is_ok_and(|a| a.segments()[0] >> 9 == 0x7e);
    }
    let host = authority.split(':').next().unwrap_or("");
    host.parse::<Ipv4Addr>()
        .is_ok_and(|a| a.is_private() || a.is_link_local())
}

fn hostile_url() -> impl Strategy<Value = String> {
    let scheme =
        prop_oneof![8 => Just("http".to_owned()), 1 => Just("https".to_owned()), 1 => ".{0,6}"];
    let user = prop_oneof![9 => Just(String::new()), 1 => ".{1,8}@"];
    let host = prop_oneof![
        2 => (0..=255u8, 0..=255u8, 0..=255u8, 0..=255u8)
            .prop_map(|(a, b, c, d)| format!("{a}.{b}.{c}.{d}")),
        8 => prop_oneof![
            Just("10.1.2.3".to_owned()),
            Just("192.168.7.7".to_owned()),
            Just("172.20.0.9".to_owned()),
            Just("169.254.9.9".to_owned()),
            Just("[fe80::7]".to_owned()),
            Just("[fd00::7]".to_owned()),
        ],
        2 => ".{0,16}",
    ];
    let port = prop_oneof![6 => Just(String::new()), 3 => (1u32..65536).prop_map(|p| format!(":{p}")), 1 => ":.{0,6}"];
    let path =
        prop_oneof![6 => Just("/onvif/x".to_owned()), 3 => "/[a-z0-9._~-]{0,24}", 1 => ".{0,8}"];
    (scheme, user, host, port, path).prop_map(|(s, u, h, p, t)| format!("{s}://{u}{h}{p}{t}"))
}

#[test]
fn xaddr_hostile_components_keep_the_invariant_and_reach_ok() {
    use crate::discovery::xaddr_validate as validate;
    let mut runner = proptest::test_runner::TestRunner::default();
    let ok_count = std::cell::Cell::new(0_u32);
    runner
        .run(&hostile_url(), |url| {
            if let Ok(x) = validate(&url) {
                let u = x.to_string();
                ok_count.set(ok_count.get() + 1);
                prop_assert!(x.path().starts_with('/') && x.port() != 0);
                prop_assert!(u.starts_with("http://"));
                prop_assert!(u.bytes().all(|b| (0x21..=0x7e).contains(&b)));
                prop_assert!(!u.contains(['@', '%', '#', '?']));
                prop_assert!(lan_oracle(&u), "{url:?} -> {u:?}");
                // Canonical form is a fixed point.
                prop_assert_eq!(validate(&u), Ok(x));
            }
            Ok(())
        })
        .unwrap();
    assert!(
        ok_count.get() > 20,
        "generator barely reaches Ok: {}",
        ok_count.get()
    );
}

// ---- the parser ----

#[test]
fn parses_a_good_reply() {
    let r = parse_probe_matches(good().as_bytes(), ID).unwrap();
    assert_eq!(r.drops.len(), 0);
    assert_eq!(
        r.devices,
        vec![dev(
            "urn:uuid:aaaa",
            &["http://192.168.1.10/onvif/device_service"],
            &[
                "onvif://www.onvif.org/name/Cam",
                "onvif://www.onvif.org/hardware/X"
            ]
        )]
    );
}

#[test]
fn relates_to_must_equal_our_message_id() {
    let m = [pm("urn:uuid:a", "http://10.0.0.1/x", "")];
    let cases = [
        reply_for("uuid:00000000000000000000000000000002", &m),
        reply_for("uuid:0000000000000000000000000000000", &m),
        reply_for("uuid:000000000000000000000000000000011", &m),
        reply_for(&ID.to_uppercase(), &m),
        reply_for("", &m),
        reply_for(&format!("urn:{ID}"), &m),
        // our id only in another element
        format!(
            r"<s:Envelope {NS}><s:Header><a:MessageID>{ID}</a:MessageID></s:Header><s:Body><d:ProbeMatches>{}</d:ProbeMatches></s:Body></s:Envelope>",
            m.concat()
        ),
        // no header at all
        format!(
            r"<s:Envelope {NS}><s:Body><d:ProbeMatches>{}</d:ProbeMatches></s:Body></s:Envelope>",
            m.concat()
        ),
    ];
    for c in &cases {
        assert_eq!(
            parse_probe_matches(c.as_bytes(), ID),
            Err(ProbeReplyError::NotOurs),
            "{c}"
        );
    }
    // surrounding white space in the element is tolerated, the value is not changed
    let spaced = reply_for(&format!("  {ID}\n"), &m);
    assert!(parse_probe_matches(spaced.as_bytes(), ID).is_ok());
}

#[test]
fn bad_xml_is_an_xml_error() {
    let long = "a".repeat(5000);
    let deep = format!("{}{}", "<x>".repeat(70), "</x>".repeat(70));
    let cases: Vec<(String, OnvifError)> = vec![
        (String::new(), OnvifError::EmptyReply),
        ("   ".to_owned(), OnvifError::EmptyReply),
        (
            format!("<!DOCTYPE x [<!ENTITY e \"x\">]>{}", good()),
            OnvifError::DocType,
        ),
        (
            format!(
                r"<s:Envelope {NS}><s:Header><a:RelatesTo>{ID}</a:RelatesTo></s:Header><s:Body><s:Fault><s:Code><s:Value>s:Sender</s:Value></s:Code></s:Fault></s:Body></s:Envelope>"
            ),
            OnvifError::SoapFault,
        ),
        (
            format!(
                r"<s:Envelope {NS}><s:Header><a:RelatesTo>{ID}</a:RelatesTo></s:Header><s:Body><d:Other/></s:Body></s:Envelope>"
            ),
            OnvifError::MissingElement {
                element: "ProbeMatches",
            },
        ),
        (
            format!(
                r"<s:Envelope {NS}><s:Header><a:RelatesTo>{ID}</a:RelatesTo></s:Header></s:Envelope>"
            ),
            OnvifError::MissingElement { element: "Body" },
        ),
        (deep, OnvifError::TooDeep),
        (
            format!("<x>{long}</y>"),
            OnvifError::Malformed { position: 0 },
        ),
    ];
    for (xml, want) in cases {
        let got = parse_probe_matches(xml.as_bytes(), ID);
        match (want, got) {
            (
                OnvifError::Malformed { .. },
                Err(ProbeReplyError::Xml(OnvifError::Malformed { .. })),
            ) => {}
            (w, g) => {
                // a deep document is not ours (no RelatesTo) when depth is not what trips first
                if w == OnvifError::TooDeep {
                    assert!(
                        matches!(g, Err(ProbeReplyError::Xml(OnvifError::TooDeep))),
                        "{g:?}"
                    );
                } else {
                    assert_eq!(g, Err(ProbeReplyError::Xml(w)), "{xml}");
                }
            }
        }
    }
    assert_eq!(
        parse_probe_matches(&[0xff, 0xfe, 0x00], ID),
        Err(ProbeReplyError::Xml(OnvifError::NotUtf8))
    );
}

#[test]
fn every_strict_prefix_of_a_good_reply_is_refused() {
    let full = good();
    for n in 0..full.len() {
        if let Some(p) = full.as_bytes().get(..n) {
            assert!(parse_probe_matches(p, ID).is_err(), "prefix {n}");
        }
    }
}

#[test]
fn entry_level_drops_are_reported_with_their_reason() {
    let r = parse_probe_matches(
        reply(&[
            pm("", "http://10.0.0.1/x", ""),
            pm("urn:uuid:b", "https://10.0.0.1/x", ""),
            pm("urn:uuid:c", "http://8.8.8.8/x http://10.0.0.3/y", ""),
            pm("urn:uuid:d", "", ""),
            "<d:ProbeMatch><d:XAddrs>http://10.0.0.1/x</d:XAddrs></d:ProbeMatch>".to_owned(),
        ])
        .as_bytes(),
        ID,
    )
    .unwrap();
    assert_eq!(
        r.devices,
        vec![dev("urn:uuid:c", &["http://10.0.0.3/y"], &[])]
    );
    assert_eq!(
        r.drops,
        vec![
            DropReason::BadEndpointReference,
            DropReason::XAddrs(XAddrDrop::Https),
            DropReason::NoUsableXAddr,
            DropReason::XAddrs(XAddrDrop::OutsideLan),
            DropReason::NoUsableXAddr,
            DropReason::BadEndpointReference,
        ]
    );
}

#[test]
fn endpoint_reference_bounds() {
    let mk = |e: &str| {
        parse_probe_matches(reply(&[pm(e, "http://10.0.0.1/x", "")]).as_bytes(), ID)
            .unwrap()
            .devices
            .len()
    };
    assert_eq!(mk(&"u".repeat(256)), 1);
    assert_eq!(mk(&"u".repeat(257)), 0);
    assert_eq!(mk(&"u".repeat(5000)), 0);
    assert_eq!(mk("a\tb"), 0);
    assert_eq!(mk("   "), 0);
}

#[test]
fn xaddr_and_scope_and_match_caps_at_minus_one_exact_plus_one() {
    let xs = |n: usize| {
        (0..n)
            .map(|i| format!("http://10.0.0.{}/x", i + 1))
            .collect::<Vec<_>>()
            .join(" ")
    };
    let sc = |n: usize| {
        (0..n)
            .map(|i| format!("onvif://s/{i}"))
            .collect::<Vec<_>>()
            .join(" ")
    };
    for (n, kept, drops) in [
        (MAX_XADDRS - 1, MAX_XADDRS - 1, 0),
        (MAX_XADDRS, MAX_XADDRS, 0),
        (MAX_XADDRS + 1, MAX_XADDRS, 1),
    ] {
        let r = parse_probe_matches(reply(&[pm("urn:uuid:a", &xs(n), "")]).as_bytes(), ID).unwrap();
        assert_eq!(r.devices[0].xaddrs().len(), kept);
        assert_eq!(r.drops.len(), drops);
    }
    for (n, kept, drops) in [
        (MAX_SCOPES - 1, MAX_SCOPES - 1, 0),
        (MAX_SCOPES, MAX_SCOPES, 0),
        (MAX_SCOPES + 1, MAX_SCOPES, 1),
    ] {
        let r = parse_probe_matches(
            reply(&[pm("urn:uuid:a", "http://10.0.0.1/x", &sc(n))]).as_bytes(),
            ID,
        )
        .unwrap();
        assert_eq!(r.devices[0].scopes().len(), kept);
        assert_eq!(r.drops.len(), drops);
        if drops == 1 {
            assert_eq!(r.drops[0], DropReason::TooManyScopes);
        }
    }
    for (n, kept, drops) in [(15, 15, 0), (16, 16, 0), (17, 16, 1)] {
        let ms: Vec<String> = (0..n)
            .map(|i| pm(&format!("urn:uuid:{i}"), "http://10.0.0.1/x", ""))
            .collect();
        let r = parse_probe_matches(reply(&ms).as_bytes(), ID).unwrap();
        assert_eq!(r.devices.len(), kept);
        assert_eq!(r.drops.len(), drops);
    }
}

#[test]
fn a_huge_xaddrs_list_keeps_the_drop_list_small() {
    let many = "http://8.8.8.8/x ".repeat(200);
    let r = parse_probe_matches(reply(&[pm("urn:uuid:a", &many, "")]).as_bytes(), ID).unwrap();
    assert_eq!(r.devices.len(), 0);
    assert!(r.drops.len() <= MAX_XADDRS + 2, "{}", r.drops.len());
    let too_long = "x".repeat(5000);
    let r = parse_probe_matches(reply(&[pm("urn:uuid:a", &too_long, "")]).as_bytes(), ID).unwrap();
    assert_eq!(r.drops, vec![DropReason::XAddrs(XAddrDrop::TooLong)]);
}

#[test]
fn bad_scopes_are_reported_not_silently_lost() {
    let long = "s".repeat(257);
    let r = parse_probe_matches(
        reply(&[pm(
            "urn:uuid:a",
            "http://10.0.0.1/x",
            &format!("onvif://ok {long} onvif://ok onvif://two"),
        )])
        .as_bytes(),
        ID,
    )
    .unwrap();
    assert_eq!(r.devices[0].scopes(), vec!["onvif://ok", "onvif://two"]);
    assert_eq!(r.drops, vec![DropReason::BadScope]);
    let r = parse_probe_matches(
        reply(&[pm("urn:uuid:a", "http://10.0.0.1/x", &"y".repeat(5000))]).as_bytes(),
        ID,
    )
    .unwrap();
    assert_eq!(r.devices[0].scopes().len(), 0);
    assert_eq!(r.drops, vec![DropReason::BadScope]);
}

fn merged(devs: Vec<DiscoveredDevice>) -> (Vec<DiscoveredDevice>, Vec<DropReason>) {
    let mut c = crate::discovery::Collector::default();
    let mut drops = Vec::new();
    for d in devs {
        c.add(d, &mut drops);
    }
    (c.into_devices(), drops)
}

#[test]
fn duplicate_endpoint_references_are_merged() {
    let (d, drops) = merged(vec![
        dev("urn:uuid:a", &["http://10.0.0.1/x"], &["s1", "s2"]),
        dev("urn:uuid:b", &["http://10.0.0.9/x"], &[]),
        dev(
            "urn:uuid:a",
            &["http://10.0.0.1/x", "http://10.0.0.2/x"],
            &["s2", "s3"],
        ),
    ]);
    assert_eq!(drops.len(), 0);
    assert_eq!(
        d,
        vec![
            dev(
                "urn:uuid:a",
                &["http://10.0.0.1/x", "http://10.0.0.2/x"],
                &["s1", "s2", "s3"]
            ),
            dev("urn:uuid:b", &["http://10.0.0.9/x"], &[]),
        ]
    );
    // exact match only: a different spelling is another device
    let (d, _) = merged(vec![
        dev("urn:uuid:a", &["http://10.0.0.1/x"], &[]),
        dev("URN:UUID:A", &["http://10.0.0.1/x"], &[]),
    ]);
    assert_eq!(d.len(), 2);
}

#[test]
fn merge_caps_hold_at_minus_one_exact_plus_one() {
    for (n, drops) in [(MAX_DEVICES - 1, 0), (MAX_DEVICES, 0), (MAX_DEVICES + 1, 1)] {
        let (d, dr) = merged(
            (0..n)
                .map(|i| dev(&format!("urn:uuid:{i}"), &["http://10.0.0.1/x"], &[]))
                .collect(),
        );
        assert_eq!(d.len(), n.min(MAX_DEVICES));
        assert_eq!(dr.len(), drops);
        if drops == 1 {
            assert_eq!(dr, vec![DropReason::TooManyDevices]);
        }
    }
    // a known endpoint can still merge when the table is full
    let mut v: Vec<_> = (0..MAX_DEVICES)
        .map(|i| dev(&format!("urn:uuid:{i}"), &["http://10.0.0.1/x"], &[]))
        .collect();
    v.push(dev("urn:uuid:0", &["http://10.0.0.2/x"], &[]));
    let (d, dr) = merged(v);
    assert_eq!(dr.len(), 0);
    assert_eq!(d[0].xaddrs().len(), 2);
    // merging cannot grow xaddrs or scopes past the caps
    let many: Vec<String> = (0..MAX_XADDRS + 3)
        .map(|i| format!("http://10.0.1.{i}/x"))
        .collect();
    let refs: Vec<&str> = many.iter().map(String::as_str).collect();
    let sc: Vec<String> = (0..MAX_SCOPES + 3).map(|i| format!("s{i}")).collect();
    let srefs: Vec<&str> = sc.iter().map(String::as_str).collect();
    let (d, dr) = merged(vec![
        dev("urn:uuid:a", &[], &[]),
        dev("urn:uuid:a", &refs, &srefs),
    ]);
    assert_eq!(d[0].xaddrs().len(), MAX_XADDRS);
    assert_eq!(d[0].scopes().len(), MAX_SCOPES);
    assert_eq!(dr.len(), 6);
}

proptest! {
    #[test]
    fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..2048)) {
        let _ = parse_probe_matches(&bytes, ID);
    }

    /// Well-formed replies with hostile text in every field: every kept value satisfies the
    /// invariants and the merge stays within its caps.
    #[test]
    fn hostile_components_in_well_formed_replies(
        e in ".{0,40}", x in ".{0,200}", s in ".{0,200}",
        good_x in prop::collection::vec(0..=255u8, 0..12),
    ) {
        let esc = |t: &str| t.replace('&', "&amp;").replace('<', "&lt;");
        let mut xaddrs = esc(&x);
        for b in &good_x {
            xaddrs = format!("{xaddrs} http://192.168.0.{b}:80/p");
        }
        let r = parse_probe_matches(reply(&[pm(&esc(&e), &xaddrs, &esc(&s))]).as_bytes(), ID);
        if let Ok(r) = r {
            let (devices, _) = merged(r.devices);
            for d in devices {
                prop_assert!(!d.xaddrs().is_empty() && d.xaddrs().len() <= MAX_XADDRS);
                prop_assert!(d.scopes().len() <= MAX_SCOPES);
                prop_assert!(!d.endpoint_ref().is_empty() && d.endpoint_ref().len() <= 256);
                prop_assert!(d.endpoint_ref().bytes().all(|b| (0x21..=0x7e).contains(&b)));
                for u in d.xaddrs() {
                    prop_assert!(lan_oracle(&u.to_string()));
                }
                for sc in d.scopes() {
                    prop_assert!(sc.len() <= 256 && sc.bytes().all(|b| (0x21..=0x7e).contains(&b)));
                }
            }
        }
    }
}

// ---- pure helpers ----

#[test]
fn window_is_capped_at_ten_seconds() {
    assert_eq!(DEFAULT_WINDOW, Duration::from_secs(4));
    assert_eq!(effective_window(Duration::ZERO), Duration::ZERO);
    assert_eq!(effective_window(DEFAULT_WINDOW), DEFAULT_WINDOW);
    assert_eq!(
        effective_window(MAX_WINDOW.checked_sub(Duration::from_nanos(1)).unwrap()),
        MAX_WINDOW.checked_sub(Duration::from_nanos(1)).unwrap()
    );
    assert_eq!(effective_window(MAX_WINDOW), Duration::from_secs(10));
    assert_eq!(
        effective_window(MAX_WINDOW + Duration::from_nanos(1)),
        Duration::from_secs(10)
    );
    assert_eq!(effective_window(Duration::MAX), Duration::from_secs(10));
}

#[test]
fn datagram_limit_boundary() {
    use crate::discovery::datagram_within_limit as ok;
    assert_eq!(MAX_DATAGRAM, 65536);
    assert!(ok(0));
    assert!(ok(MAX_DATAGRAM - 1));
    assert!(ok(MAX_DATAGRAM));
    assert!(!ok(MAX_DATAGRAM + 1));
}

#[test]
fn caps_match_adr_0004() {
    assert_eq!(MAX_REPLIES, 64);
    assert_eq!(MAX_DEVICES, 64);
}

#[test]
fn the_probe_is_well_formed_and_carries_the_id() {
    let p = build_probe(ID);
    let doc = crate::soap::Doc::parse(p.as_bytes()).unwrap();
    let id = doc.path(0, &["Header", "MessageID"]).unwrap();
    assert_eq!(doc.elem(id).unwrap().text, ID);
    let types = doc.path(0, &["Body", "Probe", "Types"]).unwrap();
    assert_eq!(doc.elem(types).unwrap().text, "dn:NetworkVideoTransmitter");
}

#[test]
fn message_ids_are_random_rfc4122_v4_uuids() {
    let a = crate::discovery::new_message_id().unwrap();
    let b = crate::discovery::new_message_id().unwrap();
    assert_ne!(a, b);
    for _ in 0..200 {
        let id = crate::discovery::new_message_id().unwrap();
        let uuid = id.strip_prefix("urn:uuid:").unwrap();
        let parts: Vec<&str> = uuid.split('-').collect();
        assert_eq!(
            parts.iter().map(|p| p.len()).collect::<Vec<_>>(),
            [8, 4, 4, 4, 12]
        );
        assert!(
            uuid.bytes()
                .all(|c| c == b'-' || (c.is_ascii_hexdigit() && !c.is_ascii_uppercase()))
        );
        assert!(parts[2].starts_with('4'), "{uuid}");
        assert!(
            matches!(parts[3].as_bytes()[0], b'8' | b'9' | b'a' | b'b'),
            "{uuid}"
        );
    }
}

// ---- the socket path, over loopback only ----

const LOOP: Ipv4Addr = Ipv4Addr::LOCALHOST;

/// A fake device on loopback: waits for one probe, reads its `MessageID`, then sends every reply
/// from `make(id)` back to the probe's source.
async fn responder(make: impl Fn(&str) -> Vec<Vec<u8>> + Send + 'static) -> SocketAddr {
    let sock = UdpSocket::bind((LOOP, 0)).await.unwrap();
    let addr = sock.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0_u8; 70_000];
        let Ok((n, from)) = sock.recv_from(&mut buf).await else {
            return;
        };
        let probe = String::from_utf8_lossy(&buf[..n]).into_owned();
        let id = probe
            .split("<w:MessageID>")
            .nth(1)
            .and_then(|r| r.split("</w:MessageID>").next())
            .unwrap_or("")
            .to_owned();
        for dgram in make(&id) {
            let _ = sock.send_to(&dgram, from).await;
            // Paced: let the receiver drain before the next send, so the default socket buffer
            // is never the thing under test.
            tokio::task::yield_now().await;
        }
    });
    addr
}

const LONG: Duration = Duration::from_secs(10);

#[tokio::test]
async fn loopback_collects_and_merges_matching_replies() {
    let to = responder(|id| {
        vec![
            reply_for(
                id,
                &[pm(
                    "urn:uuid:a",
                    "http://192.168.1.10/onvif/device_service",
                    "s1",
                )],
            )
            .into_bytes(),
            reply_for(
                id,
                &[pm(
                    "urn:uuid:a",
                    "http://192.168.1.11/onvif/device_service",
                    "s2",
                )],
            )
            .into_bytes(),
            reply_for(id, &[pm("urn:uuid:b", "http://10.0.0.5:8080/onvif", "")]).into_bytes(),
        ]
    })
    .await;
    let got = run(to, LOOP, LONG, 3, ID).await.unwrap();
    assert_eq!(
        got,
        vec![
            dev(
                "urn:uuid:a",
                &[
                    "http://192.168.1.10/onvif/device_service",
                    "http://192.168.1.11/onvif/device_service"
                ],
                &["s1", "s2"]
            ),
            dev("urn:uuid:b", &["http://10.0.0.5:8080/onvif"], &[]),
        ]
    );
}

#[tokio::test]
async fn loopback_ignores_strays_garbage_and_foreign_ids() {
    let to = responder(|id| {
        vec![
            reply_for(
                "uuid:ffffffffffffffffffffffffffffffff",
                &[pm("urn:uuid:evil", "http://10.6.6.6/x", "")],
            )
            .into_bytes(),
            b"not xml at all".to_vec(),
            Vec::new(),
            reply_for(id, &[pm("urn:uuid:evil2", "http://10.6.6.6/y", "")])
                .replace("</s:Envelope>", "")
                .into_bytes(),
            reply_for(
                id,
                &[pm(
                    "urn:uuid:ok",
                    "http://10.0.0.7/x https://10.0.0.8/x http://8.8.8.8/x",
                    "",
                )],
            )
            .into_bytes(),
        ]
    })
    .await;
    let got = run(to, LOOP, LONG, 1, ID).await.unwrap();
    assert_eq!(got, vec![dev("urn:uuid:ok", &["http://10.0.0.7/x"], &[])]);
}

#[tokio::test]
async fn loopback_stops_at_64_replies_and_64_devices() {
    let to = responder(|id| {
        (0..70)
            .map(|i| {
                reply_for(
                    id,
                    &[pm(&format!("urn:uuid:{i:03}"), "http://10.0.0.5/x", "")],
                )
                .into_bytes()
            })
            .collect()
    })
    .await;
    let got = run(to, LOOP, LONG, MAX_REPLIES, ID).await.unwrap();
    assert_eq!(got.len(), 64);
    assert_eq!(got.first().unwrap().endpoint_ref(), "urn:uuid:000");
    assert_eq!(got.last().unwrap().endpoint_ref(), "urn:uuid:063");
}

#[tokio::test]
async fn loopback_accepts_the_largest_udp_datagram() {
    // 65507 bytes is the most a UDP/IPv4 datagram can carry, and it is under the 64 KiB limit.
    let to = responder(|id| {
        let base = reply_for(id, &[pm("urn:uuid:big", "http://10.0.0.5/x", "")]);
        let pad = 65_507 - base.len() - "<!---->".len();
        let padded = base.replacen(
            "<s:Body>",
            &format!("<!--{}--><s:Body>", "p".repeat(pad)),
            1,
        );
        assert_eq!(padded.len(), 65_507);
        vec![padded.into_bytes()]
    })
    .await;
    let got = run(to, LOOP, LONG, 1, ID).await.unwrap();
    assert_eq!(got.len(), 1);
}

#[tokio::test]
async fn loopback_returns_empty_when_nobody_answers() {
    let to = responder(|_| Vec::new()).await;
    let got = run(to, LOOP, Duration::from_millis(50), MAX_REPLIES, ID)
        .await
        .unwrap();
    assert_eq!(got.len(), 0);
    let to = responder(|_| Vec::new()).await;
    let got = run(to, LOOP, Duration::ZERO, MAX_REPLIES, ID)
        .await
        .unwrap();
    assert_eq!(got.len(), 0);
}

// ---- error variants (P6) ----

#[tokio::test]
async fn an_interface_address_that_is_not_ours_is_a_socket_error() {
    let to = SocketAddr::from((LOOP, 9));
    let err = run(to, Ipv4Addr::new(192, 0, 2, 77), LONG, 1, ID)
        .await
        .unwrap_err();
    assert_eq!(err, DiscoveryError::Socket(io::ErrorKind::AddrNotAvailable));
}

/// Exhaustive on purpose: a new variant breaks this until it is named and driven or listed.
fn label(e: DiscoveryError) -> &'static str {
    match e {
        DiscoveryError::Random => "Random",
        DiscoveryError::Socket(_) => "Socket",
    }
}

#[test]
fn every_discovery_error_variant_is_driven_or_listed() {
    // `Random` (the OS RNG failing) cannot be provoked from a test. A receive error is not an
    // error of the run: see `a_receive_error_keeps_what_was_found`.
    let undrivable: BTreeSet<&str> = ["Random"].into();
    let driven: BTreeSet<&str> = [label(DiscoveryError::Socket(
        io::ErrorKind::AddrNotAvailable,
    ))]
    .into();
    let all: BTreeSet<&str> = [
        label(DiscoveryError::Random),
        label(DiscoveryError::Socket(io::ErrorKind::Other)),
    ]
    .into();
    let covered: BTreeSet<&str> = driven.union(&undrivable).copied().collect();
    assert_eq!(all, covered);
    for e in [
        DiscoveryError::Random,
        DiscoveryError::Socket(io::ErrorKind::Other),
    ] {
        assert!(e.to_string().len() > 1);
    }
}

#[test]
fn probe_reply_errors_are_both_driven() {
    // `NotOurs`: relates_to_must_equal_our_message_id; `Xml`: bad_xml_is_an_xml_error.
    assert!(ProbeReplyError::NotOurs.to_string().contains("MessageID"));
    assert!(
        ProbeReplyError::Xml(OnvifError::DocType)
            .to_string()
            .contains("DOCTYPE")
    );
}

// ---- logging ----

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl io::Write for Capture {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if let Ok(mut v) = self.0.lock() {
            v.extend_from_slice(buf);
        }
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Capture {
    type Writer = Capture;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

fn capture() -> &'static Capture {
    static CAPTURE: OnceLock<Capture> = OnceLock::new();
    CAPTURE.get_or_init(|| {
        let capture = Capture::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(capture.clone())
            .with_max_level(tracing::Level::TRACE)
            .finish();
        let _ = tracing::subscriber::set_global_default(subscriber);
        capture
    })
}

#[tokio::test]
async fn every_drop_is_logged_with_its_reason_and_never_the_text() {
    let sink = capture();
    let probe = "uuid:logtest0000000000000000000000aa";
    let to = responder(|id| {
        vec![
            b"garbage-SENTINEL".to_vec(),
            reply_for(
                id,
                &[pm(
                    "urn:uuid:log",
                    "https://192.168.9.9/HTTPSSENTINEL http://8.8.4.4/LANSENTINEL http://10.0.0.7/ok",
                    "",
                )],
            )
            .into_bytes(),
        ]
    })
    .await;
    let got = run(to, LOOP, LONG, 1, probe).await.unwrap();
    assert_eq!(got.len(), 1);
    let text = String::from_utf8(sink.0.lock().unwrap().clone()).unwrap();
    let mine: Vec<&str> = text.lines().filter(|l| l.contains(probe)).collect();
    assert!(
        mine.iter().any(|l| l.contains("xaddr is https")),
        "{mine:?}"
    );
    assert!(
        mine.iter()
            .any(|l| l.contains("xaddr address is not private or link-local")),
        "{mine:?}"
    );
    assert!(
        mine.iter()
            .any(|l| l.contains("does not echo our MessageID") || l.contains("not a usable")),
        "{mine:?}"
    );
    for l in &mine {
        for s in ["SENTINEL", "8.8.4.4", "192.168.9.9"] {
            assert!(!l.contains(s), "{l}");
        }
    }
}

#[tokio::test]
async fn loopback_the_65th_reply_is_not_read_even_when_devices_would_fit() {
    // 64 replies for one endpoint, then one for another: only the reply cap can exclude it.
    let to = responder(|id| {
        let mut v: Vec<Vec<u8>> = (0..64)
            .map(|_| reply_for(id, &[pm("urn:uuid:first", "http://10.0.0.5/x", "")]).into_bytes())
            .collect();
        v.push(reply_for(id, &[pm("urn:uuid:late", "http://10.0.0.6/x", "")]).into_bytes());
        v
    })
    .await;
    let got = run(to, LOOP, LONG, MAX_REPLIES, ID).await.unwrap();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].endpoint_ref(), "urn:uuid:first");
}

// ---- round 2: the ASCII pass-list, redaction, reply and datagram bounds ----

/// Every spelling a denylist of control characters lets through (TEST-9): format, bidi, zero
/// width, no-break and separator characters, a fullwidth letter, a space inside, at the start,
/// inside and at the end.
const NOT_PRINTABLE_ASCII: [&str; 8] = [
    "\u{202e}", "\u{200b}", "\u{feff}", "\u{a0}", "\u{2028}", "\u{ff21}", "\u{e9}", "\u{7f}",
];

#[test]
fn endpoint_references_and_scopes_are_printable_ascii_only() {
    // The space is not in the list: inside an endpoint reference it is refused too (below), and
    // in a scope list it is a separator.
    for bad in NOT_PRINTABLE_ASCII {
        for field in [format!("{bad}a"), format!("a{bad}b"), format!("a{bad}")] {
            let r =
                parse_probe_matches(reply(&[pm(&field, "http://10.0.0.1/x", "")]).as_bytes(), ID)
                    .unwrap();
            assert_eq!(r.devices.len(), 0, "endpoint {field:?} accepted");
            assert_eq!(r.drops, vec![DropReason::BadEndpointReference], "{field:?}");
            let scopes = format!("onvif://ok {field}");
            let r = parse_probe_matches(
                reply(&[pm("urn:uuid:a", "http://10.0.0.1/x", &scopes)]).as_bytes(),
                ID,
            )
            .unwrap();
            assert_eq!(
                r.devices[0].scopes(),
                ["onvif://ok"],
                "scope {field:?} kept"
            );
            assert_eq!(r.drops, vec![DropReason::BadScope], "{field:?}");
        }
    }
    let r = parse_probe_matches(
        reply(&[pm("urn:uuid: a", "http://10.0.0.1/x", "")]).as_bytes(),
        ID,
    )
    .unwrap();
    assert_eq!(r.devices.len(), 0);
    // ASCII whitespace around the value is still trimmed.
    let r = parse_probe_matches(
        reply(&[pm(" \turn:uuid:a\r\n", "http://10.0.0.1/x", "")]).as_bytes(),
        ID,
    )
    .unwrap();
    assert_eq!(r.devices[0].endpoint_ref(), "urn:uuid:a");
}

#[test]
fn debug_shows_no_host_scope_or_endpoint() {
    let d = dev(
        "urn:uuid:ENDPOINT-SENTINEL",
        &["http://192.168.77.66:8081/PATH-SENTINEL"],
        &["onvif://SCOPE-SENTINEL"],
    );
    let shown = format!("{d:?} {:?} {:?}", d.xaddrs(), d.xaddrs().first());
    for s in ["SENTINEL", "192.168", "8081"] {
        assert!(!shown.contains(s), "{shown}");
    }
    let r = parse_probe_matches(good().as_bytes(), ID).unwrap();
    let shown = format!("{r:?}");
    for s in ["192.168.1.10", "aaaa", "Cam"] {
        assert!(!shown.contains(s), "{shown}");
    }
}

#[test]
fn typed_xaddr_exposes_host_port_and_path_without_reparsing() {
    let d = dev(
        "urn:uuid:a",
        &[
            "http://10.0.0.7/onvif/device_service",
            "http://[fd00::7]:8080/x",
        ],
        &[],
    );
    let (a, b) = (&d.xaddrs()[0], &d.xaddrs()[1]);
    assert_eq!(a.host(), std::net::IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7)));
    assert_eq!((a.port(), a.path()), (80, "/onvif/device_service"));
    assert_eq!(b.host(), "fd00::7".parse::<std::net::IpAddr>().unwrap());
    assert_eq!((b.port(), b.path()), (8080, "/x"));
    assert_eq!(a.to_string(), "http://10.0.0.7/onvif/device_service");
}

#[tokio::test]
async fn empty_spoofed_replies_do_not_use_up_the_reply_cap() {
    // 64 echoing replies that yield no device (https only), then a real one.
    let to = responder(|id| {
        let mut v: Vec<Vec<u8>> = (0..64)
            .map(|_| reply_for(id, &[pm("urn:uuid:spoof", "https://10.0.0.1/x", "")]).into_bytes())
            .collect();
        v.push(reply_for(id, &[]).into_bytes());
        v.push(reply_for(id, &[pm("urn:uuid:real", "http://10.0.0.9/x", "")]).into_bytes());
        v
    })
    .await;
    let got = run(to, LOOP, LONG, 1, ID).await.unwrap();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].endpoint_ref(), "urn:uuid:real");
}

#[tokio::test]
async fn the_datagram_bound_stops_a_flood_at_4096() {
    use crate::discovery::MAX_DATAGRAMS;
    assert_eq!(MAX_DATAGRAMS, 4096);
    for (strays, found) in [(MAX_DATAGRAMS - 1, 1), (MAX_DATAGRAMS, 0)] {
        let to = responder(move |id| {
            let mut v: Vec<Vec<u8>> = (0..strays).map(|_| b"x".to_vec()).collect();
            v.push(reply_for(id, &[pm("urn:uuid:real", "http://10.0.0.9/x", "")]).into_bytes());
            v
        })
        .await;
        let got = run(to, LOOP, LONG, 1, ID).await.unwrap();
        assert_eq!(got.len(), found, "{strays} strays before the reply");
    }
}
