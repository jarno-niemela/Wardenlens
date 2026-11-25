//! Property tests: no panic on arbitrary or mutated bytes, round trips of the URL split over
//! generated components (including multibyte ones), and the accounting invariant.

use proptest::prelude::*;
use secrecy::ExposeSecret;

use crate::{ImportError, parse};

use super::fixtures::{Cam, doc, one};

const PW: &str = "Pw-S3ntinel-9x";

fn valid_doc() -> Vec<u8> {
    let cams = [
        Cam::new(
            "Caf\u{e9} \u{4e2d} &<",
            "rtsp://user:Pw-S3ntinel-9x@192.0.2.10:8554/s?a=1&b=2",
        ),
        Cam::new("Back", "rtsp://[2001:db8::1]/s").login("user", PW),
        Cam::new("Skip", "http://192.0.2.3/x"),
    ];
    let mut d = doc(&cams);
    d.insert_str(d.find("<objects").unwrap_or(0), "<!-- c --><?pi x?>");
    d.into_bytes()
}

fn assert_no_leak(r: &Result<crate::Import, ImportError>) {
    let shown = format!("{r:?}{r:#?}");
    assert!(!shown.contains("S3ntinel"), "{shown}");
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..4096)) {
        let r = parse(&bytes);
        assert_no_leak(&r);
    }

    #[test]
    fn arbitrary_text_in_xml_clothes_never_panics(s in "[ -~\u{80}-\u{2fff}<>&/=\"'!?\\[\\]-]{0,600}") {
        let r = parse(s.as_bytes());
        assert_no_leak(&r);
        let wrapped = format!("<objects><cameras>{s}</cameras></objects>");
        let r = parse(wrapped.as_bytes());
        assert_no_leak(&r);
    }

    #[test]
    fn mutated_valid_documents_never_panic_or_leak(
        edits in proptest::collection::vec((any::<usize>(), 0u8..4, any::<u8>(), 0usize..40), 1..6)
    ) {
        let mut b = valid_doc();
        for (at, kind, byte, len) in edits {
            if b.is_empty() { break; }
            let at = at % b.len();
            match kind {
                0 => b[at] = byte,
                1 => { let end = (at + len).min(b.len()); b.drain(at..end); }
                2 => { let chunk: Vec<u8> = b[at..(at + len).min(b.len())].to_vec(); for (i, c) in chunk.into_iter().enumerate() { b.insert(at + i, c); } }
                _ => { b.insert(at, byte); }
            }
        }
        let r = parse(&b);
        assert_no_leak(&r);
    }

    #[test]
    fn truncations_and_splices_never_panic(cut in 0usize..2000, other in 0usize..2000) {
        let b = valid_doc();
        let cut = cut % (b.len() + 1);
        let other = other % (b.len() + 1);
        let mut spliced = b[..cut].to_vec();
        spliced.extend_from_slice(&b[other..]);
        assert_no_leak(&parse(&b[..cut]));
        assert_no_leak(&parse(&spliced));
    }

    /// Well-formed documents with hostile components: arbitrary names, sources and logins
    /// (multibyte included), never a panic, every camera accounted for, ids unique.
    #[test]
    fn hostile_components_in_a_well_formed_document(
        cams in proptest::collection::vec(
            (
                proptest::option::of("[^\u{0}-\u{8}\u{b}\u{c}\u{e}-\u{1f}]{0,40}"),
                proptest::option::of("[^\u{0}-\u{8}\u{b}\u{c}\u{e}-\u{1f}]{0,80}"),
                proptest::option::of("[^\u{0}-\u{8}\u{b}\u{c}\u{e}-\u{1f}]{0,20}"),
                proptest::option::of("[^\u{0}-\u{8}\u{b}\u{c}\u{e}-\u{1f}]{0,20}"),
            ),
            0..8,
        )
    ) {
        let cams: Vec<Cam> = cams.into_iter().map(|(name, source, login, password)| {
            let mut c = Cam::new("x", "x");
            c.name = name;
            c.source = source;
            c.login = login.map(|l| format!("{l}{PW}"));
            c.password = password.map(|p| format!("{p}{PW}"));
            c
        }).collect();
        let n = cams.len();
        let r = parse(doc(&cams).as_bytes());
        assert_no_leak(&r);
        match r {
            Ok(i) => {
                prop_assert_eq!(i.cameras.len() + i.skipped.len(), n);
                let ids: std::collections::BTreeSet<_> = i.cameras.iter().map(|c| c.id.as_str()).collect();
                prop_assert_eq!(ids.len(), i.cameras.len());
                for c in &i.cameras {
                    prop_assert!(c.id.as_str().len() <= 32);
                }
            }
            Err(e) => prop_assert_eq!(e, ImportError::DuplicateName),
        }
    }
}

fn pct_all(s: &str) -> String {
    s.bytes().fold(String::new(), |mut acc, b| {
        acc.push_str(&format!("%{b:02X}"));
        acc
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// Host, port, path and credential written into a URL come back out unchanged, for every
    /// host form, with and without port, path and userinfo.
    #[test]
    fn url_split_round_trips(
        host in prop_oneof![
            (1u8..=254, 0u8..=255, 0u8..=255, 1u8..=254).prop_map(|(a, b, c, d)| format!("{a}.{b}.{c}.{d}")),
            "[a-z][a-z0-9]{0,10}(\\.[a-z][a-z0-9]{0,8}){0,2}",
            (1u16.., any::<u16>(), any::<u16>()).prop_map(|(a, b, c)| format!("[2001:db8:{a:x}:{b:x}::{c:x}]")),
        ],
        port in proptest::option::of(1u16..=65535),
        path in "(/[A-Za-z0-9_.~,-]{1,12}){0,4}(\\?zq[a-z]{0,4}=[0-9]{1,3}(&zq[a-z]{0,4}=[0-9]{1,3}){0,2})?",
        user_pw in proptest::option::of(("\\PC{0,12}", "\\PC{0,12}")),
    ) {
        prop_assume!(!path.split(['/', '?']).any(|s| s == "." || s == ".."));
        let userinfo = user_pw.as_ref().map_or_else(String::new, |(u, p)| format!("{}:{}@", pct_all(u), pct_all(p)));
        let port_text = port.map_or_else(String::new, |p| format!(":{p}"));
        let src = format!("rtsp://{userinfo}{host}{port_text}{path}");
        let d = one(&src).unwrap_or_else(|r| panic!("{src}: {r}"));
        let bare = host.trim_matches(['[', ']']);
        let want_host = bare.parse::<std::net::Ipv6Addr>().map_or_else(|_| bare.to_owned(), |a| a.to_string());
        prop_assert_eq!(d.host.expose(), want_host);
        prop_assert_eq!(d.port.get(), port.unwrap_or(554));
        let want_path = if path.is_empty() { "/".to_owned() } else if path.starts_with('?') { format!("/{path}") } else { path.clone() };
        prop_assert_eq!(d.path.as_str(), want_path.as_str());
        let want_cred = user_pw.filter(|(u, p)| !u.is_empty() || !p.is_empty());
        let got = d.credential.as_ref().map(|c| (c.user.clone(), c.password.expose_secret().to_owned()));
        prop_assert_eq!(got, want_cred);
    }
}
