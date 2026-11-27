//! Adversarial tests for PR #200 (ticket #53, WS-Discovery): hostile `ProbeMatches` datagrams
//! through the pure parser only (moved from `tests/` into the crate when the parser became
//! `pub(crate)` in round 2; expectations unchanged). Nothing here opens a socket.
use std::num::NonZeroU16;

use proptest::prelude::*;
use wardenlens_core::camera::Host;

use crate::OnvifClient;
use crate::discovery::{
    DiscoveredDevice, DropReason, ProbeReplyError, XAddrDrop, parse as parse_probe_matches,
};

const ID: &str = "uuid:0123456789abcdef0123456789abcdef";
const NS: &str = r#"xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery""#;

fn pm(endpoint: &str, xaddrs: &str) -> String {
    format!(
        "<d:ProbeMatch><a:EndpointReference><a:Address>{endpoint}</a:Address></a:EndpointReference>\
         <d:Scopes>onvif://www.onvif.org/name/x</d:Scopes><d:XAddrs>{xaddrs}</d:XAddrs></d:ProbeMatch>"
    )
}

fn env(header: &str, body: &str) -> String {
    format!("<s:Envelope {NS}><s:Header>{header}</s:Header><s:Body>{body}</s:Body></s:Envelope>")
}

fn reply(relates: &str, matches: &str) -> String {
    env(
        &format!("<a:RelatesTo>{relates}</a:RelatesTo>"),
        &format!("<d:ProbeMatches>{matches}</d:ProbeMatches>"),
    )
}

/// The `XAddrs` of the single device, or the drops.
fn one(xaddr: &str) -> Result<Vec<String>, Vec<DropReason>> {
    let Ok(r) = parse_probe_matches(reply(ID, &pm("urn:uuid:a", xaddr)).as_bytes(), ID) else {
        return Err(Vec::new());
    };
    match r.devices.as_slice() {
        [d] => Ok(d.xaddrs().iter().map(ToString::to_string).collect()),
        [] => Err(r.drops),
        _ => panic!("more than one device"),
    }
}

// ---- MessageID matching ----

#[test]
fn relates_to_near_misses_are_not_ours() {
    let upper = ID.to_uppercase();
    let prefix = &ID[..ID.len() - 1];
    let longer = format!("{ID}0");
    let urn = format!("urn:{ID}");
    let nul = format!("{ID}&#0;");
    for relates in [
        upper.as_str(),
        prefix,
        longer.as_str(),
        urn.as_str(),
        "",
        nul.as_str(),
    ] {
        let got = parse_probe_matches(
            reply(relates, &pm("urn:uuid:a", "http://10.0.0.1/x")).as_bytes(),
            ID,
        );
        assert!(
            matches!(got, Err(ProbeReplyError::NotOurs | ProbeReplyError::Xml(_))),
            "{relates:?} -> {got:?}"
        );
    }
}

#[test]
fn relates_to_outside_the_header_or_second_in_line_is_not_ours() {
    // Only the Header's first RelatesTo counts.
    let body = format!(
        "<a:RelatesTo>{ID}</a:RelatesTo><d:ProbeMatches>{}</d:ProbeMatches>",
        pm("urn:uuid:a", "http://10.0.0.1/x")
    );
    let got = parse_probe_matches(env("", &body).as_bytes(), ID);
    assert_eq!(got, Err(ProbeReplyError::NotOurs));
    let two = format!("<a:RelatesTo>uuid:other</a:RelatesTo><a:RelatesTo>{ID}</a:RelatesTo>");
    let doc = env(
        &two,
        &format!(
            "<d:ProbeMatches>{}</d:ProbeMatches>",
            pm("urn:uuid:a", "http://10.0.0.1/x")
        ),
    );
    assert_eq!(
        parse_probe_matches(doc.as_bytes(), ID),
        Err(ProbeReplyError::NotOurs)
    );
}

#[test]
fn an_empty_message_id_never_matches_a_missing_relates_to() {
    let doc = env(
        "",
        &format!(
            "<d:ProbeMatches>{}</d:ProbeMatches>",
            pm("urn:uuid:a", "http://10.0.0.1/x")
        ),
    );
    assert_eq!(
        parse_probe_matches(doc.as_bytes(), ""),
        Err(ProbeReplyError::NotOurs)
    );
}

#[test]
fn a_fault_that_echoes_our_id_is_an_xml_error_not_a_device() {
    let doc = env(
        &format!("<a:RelatesTo>{ID}</a:RelatesTo>"),
        "<s:Fault><s:Code><s:Value>s:Sender</s:Value></s:Code></s:Fault>",
    );
    assert!(matches!(
        parse_probe_matches(doc.as_bytes(), ID),
        Err(ProbeReplyError::Xml(_))
    ));
}

// ---- XML bombs and structure ----

#[test]
fn xml_bombs_and_deep_nesting_fail_cleanly() {
    let lol = format!(
        r#"<?xml version="1.0"?><!DOCTYPE l [<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;&a;&a;">]>{}"#,
        reply(ID, &pm("urn:uuid:a", "http://10.0.0.1/&b;"))
    );
    assert!(parse_probe_matches(lol.as_bytes(), ID).is_err());
    let deep = format!("{}{}", "<x>".repeat(10_000), "</x>".repeat(10_000));
    assert!(parse_probe_matches(deep.as_bytes(), ID).is_err());
    let wide = reply(ID, &"<x/>".repeat(16_000));
    assert!(wide.len() < 65_507);
    assert!(parse_probe_matches(wide.as_bytes(), ID).is_err());
    let ext = reply(ID, &pm("urn:uuid:a", "http://10.0.0.1/&ext;"));
    assert!(parse_probe_matches(ext.as_bytes(), ID).is_err());
}

#[test]
fn probe_matches_nested_too_deep_are_not_found() {
    // A ProbeMatch inside a wrapper is not a direct child and is ignored.
    let doc = reply(
        ID,
        &format!("<d:Wrap>{}</d:Wrap>", pm("urn:uuid:a", "http://10.0.0.1/x")),
    );
    let r = parse_probe_matches(doc.as_bytes(), ID).unwrap();
    assert_eq!(r.devices, Vec::new());
}

#[test]
fn xaddr_split_across_cdata_entities_and_comments_is_validated_as_one() {
    // Text pieces are concatenated before validation, so a spelled-out address is still checked.
    let r = one("http://8.8<!-- c -->.8.8/x");
    assert!(r.is_err(), "{r:?}");
    let r = one("<![CDATA[http://127.0.0.1/x]]>");
    assert!(r.is_err(), "{r:?}");
    // &#32; becomes a separator, so this is two entries: one bad, one good.
    assert_eq!(
        one("http://8.8.8.8/x&#32;http://10.0.0.2/y"),
        Ok(vec!["http://10.0.0.2/y".to_owned()])
    );
    // Child elements inside XAddrs do not smuggle text past the check.
    let r = one("http://10.0.0.1<b>@8.8.8.8</b>/x");
    assert!(
        r.as_ref()
            .is_ok_and(|v| v.iter().all(|x| x.starts_with("http://10.0.0.1")))
            || r.is_err(),
        "{r:?}"
    );
}

// ---- XAddr spellings ----

#[test]
fn hostile_xaddr_spellings_never_survive() {
    for raw in [
        "http://010.0.0.1/x",
        "http://10.0.0.01/x",
        "http://10.000.0.1/x",
        "http://10.0.0.1%2e/x",
        "http://0x0a.0.0.1/x",
        "http://167772161/x",
        "http://10.1/x",
        "http://10.0.0.1\\@8.8.8.8/x",
        "http://8.8.8.8\\@10.0.0.1/x",
        "http://8.8.8.8#@10.0.0.1/x",
        "http://8.8.8.8?@10.0.0.1/x",
        "http://[::ffff:10.0.0.1]/x",
        "http://[::ffff:a00:1]/x",
        "http://[::10.0.0.1]/x",
        "http://[64:ff9b::a00:1]/x",
        "http://[fe80::1%eth0]/x",
        "http://[fe80::1%25eth0]/x",
        "http://[fc00::1]]/x",
        "http://[[fc00::1]]/x",
        "http://[fc00::1]:80:80/x",
        "http://[fc00::1].evil/x",
        "http://[10.0.0.1]/x",
        "http://10.0.0.1:080a/x",
        "http://10.0.0.1:99999/x",
        "http://10.0.0.1:-1/x",
        "http:/10.0.0.1/x",
        "http:\\\\10.0.0.1/x",
        "ht\ttp://10.0.0.1/x",
        "http ://10.0.0.1/x",
        "http://10.0.0.1/x\u{0}",
        "http://10.0.0.1/\u{202e}x",
        "http://10.0.0.1/x/%2e%2e/",
        "javascript://10.0.0.1/%0aalert(1)",
        "file://10.0.0.1/etc/passwd",
        "http://localhost/x",
        "http://[::1]:80/x",
        "http://127.1/x",
        "http://0/x",
        "http://224.0.0.1/x",
        "http://239.255.255.250:3702/x",
    ] {
        let got = one(raw);
        assert!(got.is_err(), "{raw:?} survived as {got:?}");
    }
}

#[test]
fn accepted_xaddrs_are_canonical_and_idempotent() {
    for raw in [
        "HtTp://10.0.0.1:0080/a",
        "http://[FD00:0:0:0:0:0:0:1]:1/x",
        "http://[fc00::10.0.0.1]/x",
        "http://192.168.0.1",
    ] {
        let first = one(raw).unwrap();
        assert_eq!(first.len(), 1, "{raw}");
        let again = one(&first[0]).unwrap();
        assert_eq!(first, again, "{raw}: not idempotent");
        assert!(first[0].starts_with("http://"), "{first:?}");
        assert!(!first[0].contains(":0080"), "{first:?}");
    }
}

#[test]
fn https_is_dropped_with_its_own_reason() {
    assert_eq!(
        one("https://10.0.0.1/x"),
        Err(vec![
            DropReason::XAddrs(XAddrDrop::Https),
            DropReason::NoUsableXAddr
        ])
    );
}

/// The address the CLI would later fetch: split the canonical URL into host, port and path.
fn split(url: &str) -> (String, u16, String) {
    let rest = url.strip_prefix("http://").unwrap();
    let slash = rest.find('/').unwrap();
    let (auth, path) = rest.split_at(slash);
    let (host, port) = if let Some(b) = auth.strip_prefix('[') {
        let (h, p) = b.split_once(']').unwrap();
        (
            h.to_owned(),
            p.strip_prefix(':').map_or(80, |p| p.parse().unwrap()),
        )
    } else {
        match auth.split_once(':') {
            Some((h, p)) => (h.to_owned(), p.parse().unwrap()),
            None => (auth.to_owned(), 80),
        }
    };
    (host, port, path.to_owned())
}

/// Every `XAddr` discovery hands out should be something this crate's own client can use as a
/// device service: the pass-list is the only filter between the LAN and the later CLI fetch.
#[test]
fn every_accepted_xaddr_is_usable_by_the_onvif_client() {
    let long = format!("http://10.0.0.1/{}", "a".repeat(300));
    let mut refused: Vec<String> = Vec::new();
    for raw in [
        "http://10.0.0.1//8.8.8.8/x",
        "http://10.0.0.1/onvif/../../admin",
        "http://10.0.0.1/./x",
        "http://10.0.0.1/a@b",
        long.as_str(),
    ] {
        let Ok(xs) = one(raw) else { continue };
        for x in xs {
            let (host, port, path) = split(&x);
            let host = Host::new(&host).expect("host");
            let client = OnvifClient::new(host, NonZeroU16::new(port).unwrap(), None);
            if client.with_device_path(&path).is_err() {
                refused.push(x);
            }
        }
    }
    assert!(
        refused.is_empty(),
        "discovery accepted XAddrs the client refuses: {refused:?}"
    );
}

// ---- endpoint references ----

#[test]
fn endpoint_references_with_invisible_or_bidi_characters_are_refused() {
    for refr in [
        "urn:uuid:a\u{202e}gpj",
        "urn:uuid:a\u{200b}",
        "urn:uuid:\u{feff}a",
        "urn:uuid:a\u{2028}b",
    ] {
        let r =
            parse_probe_matches(reply(ID, &pm(refr, "http://10.0.0.1/x")).as_bytes(), ID).unwrap();
        assert!(
            r.devices.is_empty(),
            "endpoint {refr:?} accepted: {:?}",
            r.devices
        );
    }
}

#[test]
fn whitespace_variants_of_one_endpoint_merge_or_stay_distinct_but_never_panic() {
    let doc = reply(
        ID,
        &[
            pm("urn:uuid:a", "http://10.0.0.1/x"),
            pm("  urn:uuid:a\n", "http://10.0.0.2/x"),
        ]
        .concat(),
    );
    let r = parse_probe_matches(doc.as_bytes(), ID).unwrap();
    assert_eq!(r.devices.len(), 2);
    assert!(r.devices.iter().all(|d| d.endpoint_ref() == "urn:uuid:a"));
}

// ---- properties ----

fn assert_device_invariants(d: &DiscoveredDevice) {
    assert!(!d.xaddrs().is_empty() && d.xaddrs().len() <= 8);
    assert!(d.scopes().len() <= 32);
    assert!(!d.endpoint_ref().is_empty() && d.endpoint_ref().len() <= 256);
    for x in d.xaddrs() {
        let x = x.to_string();
        let (host, _, path) = split(&x);
        assert!(path.starts_with('/'));
        assert!(!path.contains(['?', '#', '%', ' ']));
        let ip: std::net::IpAddr = host.parse().expect("ip literal");
        match ip {
            std::net::IpAddr::V4(a) => assert!(a.is_private() || a.is_link_local(), "{x}"),
            std::net::IpAddr::V6(a) => {
                let s = a.segments()[0];
                assert!((s & 0xfe00) == 0xfc00 || (s & 0xffc0) == 0xfe80, "{x}");
            }
        }
    }
}

proptest! {
    #[test]
    fn random_authorities_keep_the_invariant(
        a in 0_u16..300, b in 0_u16..300, c in 0_u16..300, d in 0_u16..300,
        sep in prop::sample::select(vec![".", ":", "@", "%", "[", "]", "\\", ""]),
        zeros in 0_usize..3,
        port in prop::option::of(0_u32..70_000),
    ) {
        let z = "0".repeat(zeros);
        let raw = format!(
            "http://{z}{a}.{b}{sep}{c}.{d}{}/x",
            port.map_or_else(String::new, |p| format!(":{p}"))
        );
        if let Ok(r) = parse_probe_matches(reply(ID, &pm("urn:uuid:p", &raw)).as_bytes(), ID) {
            for dev in &r.devices {
                assert_device_invariants(dev);
            }
        }
    }

    #[test]
    fn arbitrary_xaddr_text_keeps_the_invariant(s in "[ -~]{0,80}") {
        let esc = s.replace('&', "&amp;").replace('<', "&lt;");
        if let Ok(r) = parse_probe_matches(reply(ID, &pm("urn:uuid:p", &esc)).as_bytes(), ID) {
            for dev in &r.devices {
                assert_device_invariants(dev);
            }
        }
    }
}
