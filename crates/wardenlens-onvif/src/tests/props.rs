//! Properties over hostile input (P4): never panic, and every `Ok` satisfies the invariants.

use proptest::prelude::*;

use super::fixtures::*;
use crate::{
    parse_device_information, parse_profiles, parse_stream_uri, pick_streams, reduce_stream_uri,
};

proptest! {
    #[test]
    fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..2048)) {
        let _ = parse_device_information(&bytes);
        let _ = parse_profiles(&bytes);
        let _ = parse_stream_uri(&bytes);
    }

    /// Well-formed envelopes with hostile text in each component.
    #[test]
    fn hostile_components_in_well_formed_envelopes(
        a in ".{0,40}", b in ".{0,40}", c in ".{0,40}", d in ".{0,40}",
    ) {
        let esc = |s: &str| s.replace('&', "&amp;").replace('<', "&lt;");
        if let Ok(info) = parse_device_information(
            device_info(&esc(&a), &esc(&b), &esc(&c), &esc(&d), "h").as_bytes(),
        ) {
            prop_assert!(info.manufacturer.chars().all(|ch| !ch.is_control()));
            prop_assert!(info.manufacturer.len() <= 256);
        }
        if let Ok(ps) = parse_profiles(
            profiles(&[profile(&esc(&a), &esc(&b), &esc(&c), &esc(&d), "H264")]).as_bytes(),
        ) {
            for p in &ps {
                prop_assert!((1..=65535).contains(&p.width) && (1..=65535).contains(&p.height));
                prop_assert!(p.token.as_str().bytes().all(|x| x.is_ascii_alphanumeric() || b".:_-".contains(&x)));
            }
            let _ = pick_streams(&ps);
        }
        let _ = parse_stream_uri(stream_uri(&esc(&a)).as_bytes());
    }

    #[test]
    fn stream_uri_arbitrary_text(s in ".{0,200}") {
        if let Ok(e) = reduce_stream_uri(&s) {
            prop_assert!(e.path.as_str().starts_with('/'));
            prop_assert!(!e.path.as_str().contains('@'));
        }
    }

    /// `rtsp://{user}@{host}:{port}{path}` with arbitrary characters in each component.
    #[test]
    fn stream_uri_hostile_components(
        user in ".{0,20}", host in ".{0,20}", port in ".{0,8}", path in "/.{0,40}",
    ) {
        let uri = format!("rtsp://{user}@{host}:{port}{path}");
        if let Ok(e) = reduce_stream_uri(&uri) {
            // The path is a suffix of the whole URI (a synthesised leading `/` aside), so the
            // userinfo, which comes first, can never be in it.
            prop_assert!(uri.trim().ends_with(&e.path.as_str()[1..]));
            prop_assert!(!e.path.as_str().contains('@'));
        }
    }
}

#[test]
fn every_prefix_of_every_good_reply_fails() {
    let docs = [good_device_info(), good_profiles(), good_stream_uri()];
    for (i, doc) in docs.iter().enumerate() {
        for at in 0..doc.len() {
            let p = &doc.as_bytes()[..at];
            let r = match i {
                0 => parse_device_information(p).map(|_| ()),
                1 => parse_profiles(p).map(|_| ()),
                _ => parse_stream_uri(p).map(|_| ()),
            };
            assert!(r.is_err(), "doc {i} prefix {at}");
        }
    }
}
