//! Adversary tests (#61 round 2) for `RtspPath::redacted_for_display`: no byte of a
//! `name=value` value may survive, whatever characters the value holds. Synthetic data only.
#![expect(clippy::expect_used, reason = "test code")]

use wardenlens_core::camera::RtspPath;

const SECRET_A: &str = "SYNTHA";
const SECRET_B: &str = "SYNTHB";

fn shown(text: &str) -> String {
    RtspPath::new(text)
        .expect("self-check: the path must be accepted")
        .redacted_for_display()
}

/// In a query, `/` and `?` are ordinary value characters (RFC 3986 section 3.4), and
/// base64 tokens contain `/` and `+`. A value spelled with them must be hidden in full.
#[test]
fn a_query_value_containing_slash_question_or_semicolon_is_hidden_in_full() {
    let rows = [
        format!("/live?sig2={SECRET_A}/{SECRET_B}"),
        format!("/live?sig2={SECRET_A}?{SECRET_B}"),
        format!("/live?sig2={SECRET_A};{SECRET_B}"),
        format!("/live?sig2={SECRET_A}/{SECRET_B}=="),
        format!("/live?channel=1&sig2={SECRET_A}/{SECRET_B}&subtype=0"),
    ];
    let mut leaked = Vec::new();
    for r in &rows {
        let s = shown(r);
        if s.contains(SECRET_A) || s.contains(SECRET_B) {
            leaked.push(format!("{r} -> {s}"));
        }
    }
    assert!(leaked.is_empty(), "value bytes shown: {leaked:#?}");
}

/// Forms that are already fully hidden; kept as regression coverage.
#[test]
fn values_in_other_delimiter_shapes_are_hidden() {
    for r in [
        format!("/cam1=admin_pin2={SECRET_A}_channel=1_stream=0.sdp?real_stream"),
        format!("/a?={SECRET_A}"),
        format!("/a?flag,pin2={SECRET_A}"),
        format!("/a?x={SECRET_A}=={SECRET_B}"),
        format!("/a:pin2={SECRET_A}"),
        format!("/a;pin2={SECRET_A}/b"),
        format!("/a?pin2={SECRET_A},{SECRET_B}"),
        format!("/a?pin2={SECRET_A}:{SECRET_B}"),
        format!("/a?pin2=({SECRET_A})!{SECRET_B}"),
    ] {
        let s = shown(&r);
        assert!(!s.contains(SECRET_A) && !s.contains(SECRET_B), "{r} -> {s}");
    }
}

#[test]
fn redaction_is_idempotent_and_its_output_is_a_valid_path() {
    for r in [
        "/",
        "/main",
        "/live?a=1&b=2;c=3",
        "/a?=x",
        "/a?b?c=d",
        "/cam1=x_y=z/q",
    ] {
        let once = shown(r);
        let twice = shown(&once);
        assert_eq!(once, twice, "{r}");
        assert!(once.len() <= r.len().max(1) + 3 * r.matches('=').count());
    }
}

#[test]
fn debug_and_display_still_hide_the_whole_path() {
    let p = RtspPath::new(&format!("/live?pin2={SECRET_A}")).unwrap();
    assert!(!format!("{p:?}").contains(SECRET_A));
    assert!(!format!("{p}").contains(SECRET_A));
    assert!(!format!("{p:?}").contains("pin2"));
}

proptest::proptest! {
    #![proptest_config(proptest::test_runner::Config {
        failure_persistence: None,
        ..proptest::test_runner::Config::default()
    })]
    /// Oracle: in the query, a value runs to the next `&` (the separator every RTSP server
    /// uses), so it may hold any other allowed character. Values use uppercase letters, which
    /// the rest of the generated path never contains.
    #[test]
    fn no_query_value_byte_survives(
        pairs in proptest::collection::vec(
            ("[a-z]{1,4}[0-9]", "[A-Z][A-Z/?;,:=]{0,10}"),
            1..5,
        )
    ) {
        let mut text = String::from("/live?");
        for (i, (k, v)) in pairs.iter().enumerate() {
            if i > 0 {
                text.push('&');
            }
            text.push_str(k);
            text.push('=');
            text.push_str(v);
        }
        if let Ok(p) = RtspPath::new(&text) {
            let s = p.redacted_for_display();
            proptest::prop_assert!(
                !s.bytes().any(|b| b.is_ascii_uppercase()),
                "{} -> {}", text, s
            );
        }
    }
}
