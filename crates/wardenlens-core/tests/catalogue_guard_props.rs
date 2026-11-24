//! Property tests: formatted network identifiers are rejected wherever they appear in text.

use std::net::Ipv4Addr;

use proptest::prelude::*;
use wardenlens_core::catalogue::check_source;

/// Surrounding prose: letters, spaces and light punctuation, no digits, so it cannot extend or
/// split an identifier and cannot form a secret-key pair.
fn prose() -> impl Strategy<Value = String> {
    "[a-zA-Z ,;]{0,24}"
}

proptest! {
    #[test]
    #[ignore = "shape heuristics superseded by the vault exact-match scan (ADR 0006, #75); see PR #71"]
    fn any_ipv4_in_text_is_rejected(octets in any::<[u8; 4]>(), pre in prose(), post in prose()) {
        let ip = Ipv4Addr::from(octets);
        let text = format!("{pre} {ip} {post}");
        prop_assert!(check_source(&text).is_err(), "{}", text);
    }

    #[test]
    #[ignore = "shape heuristics superseded by the vault exact-match scan (ADR 0006, #75); see PR #71"]
    fn any_mac_in_text_is_rejected(
        bytes in any::<[u8; 6]>(),
        sep in prop::sample::select(vec![':', '-']),
        upper in any::<bool>(),
        pre in prose(),
        post in prose(),
    ) {
        let parts: Vec<String> = bytes
            .iter()
            .map(|b| if upper { format!("{b:02X}") } else { format!("{b:02x}") })
            .collect();
        let text = format!("{pre} {} {post}", parts.join(&sep.to_string()));
        prop_assert!(check_source(&text).is_err(), "{}", text);
    }

    #[test]
    fn prose_alone_is_accepted(text in prose()) {
        // Guards against the guard being trivially strict: words without digits are clean unless
        // they form a long run of capitals.
        prop_assume!(!text.bytes().collect::<Vec<_>>().windows(10).any(|w| w.iter().all(u8::is_ascii_uppercase)));
        prop_assert!(check_source(&text).is_ok(), "{}", text);
    }
}
