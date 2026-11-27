//! Adversary tests of #76 (PR #181): `Redactor`, the streaming `vault redact` filter. The scan
//! (`Matcher`) is the oracle: a rendering the scan finds in the raw text of a log line must not
//! survive the filter, unless the ADR "As built" note names it as out of scope (decoded,
//! JSON-unescaped, joined views). Synthetic values only.

#![expect(
    clippy::unwrap_used,
    reason = "integration-test helpers outside #[test] fns; clippy.toml in-tests allowances do not reach them"
)]
#![expect(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::assert_is_empty,
    reason = "carried adversary test, kept as written; bounds are checked by the test's own inputs"
)]

use std::io::{self, Read};

use proptest::prelude::*;
use secrecy::SecretString;
use wardenlens_core::entry::{EntryId, EntryKind};
use wardenlens_vault::{MARKER, Matcher, Redactor, ScanEntry, scan};

fn id(s: &str) -> EntryId {
    EntryId::new(s).unwrap()
}

fn redactor(kind: EntryKind, value: &str) -> Redactor {
    Redactor::new(&[(id("e:one"), kind, None, value)]).unwrap()
}

fn matcher(kind: EntryKind, value: &str) -> Matcher {
    Matcher::new(&[ScanEntry {
        id: id("e:one"),
        kind,
        value: SecretString::from(value.to_owned()),
        unscannable: false,
    }])
    .unwrap()
}

fn filter(r: &Redactor, input: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    r.filter(input, &mut out).unwrap();
    out
}

/// The scan finds `text` before the filter (so the rendering is a real leak form the vault
/// knows) and finds nothing after it.
fn assert_scan_clean_after_redact(kind: EntryKind, value: &str, text: &str) {
    let m = matcher(kind, value);
    assert!(m.unscannable().is_empty(), "{value:?} unscannable");
    let before = scan(&m, text.as_bytes()).unwrap().hits.len();
    assert!(before > 0, "precondition: the scan finds {text:?}");
    let r = redactor(kind, value);
    assert!(r.unredactable().is_empty());
    let out = filter(&r, text.as_bytes());
    let after = scan(&m, &out).unwrap().hits.len();
    assert_eq!(
        after,
        0,
        "the scan still finds the value after redact: {:?}",
        String::from_utf8_lossy(&out)
    );
}

// ---------------------------------------------------------------- net renderings (raw view)

#[test]
fn ipv6_host_in_another_valid_compression_is_redacted() {
    // 2001:db8::1:0:0:1 is the RFC 5952 form; 2001:db8:0:0:1::1 is an equally valid text.
    assert_scan_clean_after_redact(
        EntryKind::Host,
        "2001:db8:0:0:1:0:0:1",
        "peer 2001:db8:0:0:1::1 up",
    );
}

#[test]
fn ipv6_host_with_partly_padded_groups_is_redacted() {
    assert_scan_clean_after_redact(EntryKind::Host, "2001:db8::7", "peer 2001:0db8::0007 up");
}

#[test]
fn ipv4_host_with_leading_zeros_is_redacted() {
    assert_scan_clean_after_redact(EntryKind::Host, "192.0.2.7", "peer 192.000.002.007 up");
}

#[test]
fn ipv4_host_in_a_dashed_reverse_name_is_redacted() {
    assert_scan_clean_after_redact(EntryKind::Host, "192.0.2.7", "peer ip-192-0-2-7.lan up");
}

#[test]
fn ipv4_host_as_mapped_ipv6_hex_is_redacted() {
    assert_scan_clean_after_redact(EntryKind::Host, "192.0.2.7", "peer ::ffff:c000:207 up");
}

#[test]
fn mac_with_unpadded_octets_is_redacted() {
    assert_scan_clean_after_redact(
        EntryKind::Mac,
        "AA:BB:CC:00:11:22",
        "hw aa:bb:cc:0:11:22 up",
    );
}

#[test]
fn mac_in_three_dashed_groups_is_redacted() {
    assert_scan_clean_after_redact(EntryKind::Mac, "AA:BB:CC:00:11:22", "hw AABB-CC00-1122 up");
}

#[test]
fn mac_in_dotted_octets_is_redacted() {
    assert_scan_clean_after_redact(
        EntryKind::Mac,
        "AA:BB:CC:00:11:22",
        "hw aa.bb.cc.00.11.22 up",
    );
}

// ---------------------------------------------------------------- text renderings (raw view)

#[test]
fn every_ascii_case_variant_of_a_host_is_redacted() {
    let r = redactor(EntryKind::Host, "Cam-Yard.Example.Test");
    for t in [
        "cam-yard.example.test",
        "CAM-YARD.EXAMPLE.TEST",
        "cAm-YaRd.ExAmPlE.tEsT",
    ] {
        assert_eq!(filter(&r, t.as_bytes()), MARKER, "{t}");
    }
}

#[test]
fn a_short_password_is_listed_and_its_userinfo_is_not_partly_replaced() {
    // Ruling 5 (round 2): the entry is listed (its password is never replaced on its own), but the
    // `user:pass@` prefix is long enough to be a needle and is still replaced, as documented.
    let r = Redactor::new(&[(
        id("cam:x:login"),
        EntryKind::Credential,
        Some("admin"),
        "pw12",
    )])
    .unwrap();
    assert_eq!(r.unredactable().len(), 1);
    let out = filter(&r, b"rtsp://admin:pw12@h/");
    assert_eq!(
        out,
        b"rtsp://[REDACTED]h/",
        "{}",
        String::from_utf8_lossy(&out)
    );
}

#[test]
fn a_value_that_contains_the_marker_text_does_not_loop_or_grow() {
    let r = redactor(EntryKind::Secret, "[REDACTED]-synthetic");
    let once = filter(&r, b"x [REDACTED]-synthetic y");
    assert_eq!(once, b"x [REDACTED] y");
    let twice = filter(&r, &once);
    assert_eq!(twice, once);
}

#[test]
fn a_crlf_split_multiline_secret_is_found_in_its_lf_form() {
    let r = redactor(EntryKind::Secret, "line-one-synthetic\nline-two-synthetic");
    assert_eq!(
        filter(&r, b"a line-one-synthetic\nline-two-synthetic b"),
        b"a [REDACTED] b"
    );
}

/// A reader that returns the input in the given read sizes, cycling.
struct Cuts<'a> {
    data: &'a [u8],
    sizes: Vec<usize>,
    i: usize,
}

impl Read for Cuts<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.data.is_empty() {
            return Ok(0);
        }
        let want = self.sizes[self.i % self.sizes.len()].max(1);
        self.i += 1;
        let n = want.min(self.data.len()).min(buf.len());
        let (h, t) = self.data.split_at(n);
        buf[..n].copy_from_slice(h);
        self.data = t;
        Ok(n)
    }
}

/// Naive oracle over the alphabet {a, b, -}: mark every byte inside an occurrence of a raw
/// value, emit one marker per maximal marked run. Other renderings (percent, hex, base64,
/// every-byte) cannot occur in this alphabet... except base64 fragments, which are checked
/// by requiring the filter to cover at least what the oracle covers.
fn oracle(values: &[String], input: &[u8]) -> Vec<u8> {
    let mut covered = vec![false; input.len()];
    for v in values {
        let v = v.as_bytes();
        if v.len() > input.len() {
            continue;
        }
        for s in 0..=input.len() - v.len() {
            if &input[s..s + v.len()] == v {
                covered[s..s + v.len()].iter_mut().for_each(|c| *c = true);
            }
        }
    }
    let mut out = Vec::new();
    let mut i = 0;
    while i < input.len() {
        if covered[i] {
            out.extend_from_slice(MARKER);
            while i < input.len() && covered[i] {
                i += 1;
            }
        } else {
            out.push(input[i]);
            i += 1;
        }
    }
    out
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(400))]

    #[test]
    fn streaming_matches_a_naive_oracle_for_any_cuts(
        values in proptest::collection::vec("[ab-]{7,14}", 1..4),
        input in "[ab-]{0,120}",
        sizes in proptest::collection::vec(1usize..40, 1..6),
        plant in any::<bool>(),
    ) {
        let mut input = input;
        if plant {
            // Make sure the target branch (a match) is reached.
            let mid = input.len() / 2;
            input.insert_str(mid, &values[0]);
        }
        let entries: Vec<_> = values
            .iter()
            .enumerate()
            .map(|(i, v)| (id(&format!("e:v{i}")), EntryKind::Secret, None, v.as_str()))
            .collect();
        let r = Redactor::new(&entries).unwrap();
        let mut out = Vec::new();
        r.filter(Cuts { data: input.as_bytes(), sizes, i: 0 }, &mut out).unwrap();
        let whole = filter(&r, input.as_bytes());
        prop_assert_eq!(&out, &whole, "chunking changed the output");
        let want = oracle(&values, input.as_bytes());
        // No raw value may survive anywhere in the output.
        for v in &values {
            let s = String::from_utf8_lossy(&out);
            prop_assert!(!s.contains(v.as_str()), "value survived: {:?}", s);
        }
        prop_assert_eq!(out, want);
    }
}
