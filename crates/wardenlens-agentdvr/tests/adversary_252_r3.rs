//! Adversary round 3 for #252: attribute-flood edges past the hashed duplicate-check threshold.

use std::fmt::Write as _;
use std::time::Duration;

use wardenlens_agentdvr::parse;

/// A duplicate key far past the 32-attribute linear phase (the hashed path) is still refused.
#[test]
fn a_duplicate_key_after_the_hashed_threshold_is_refused() {
    for n in [31_u32, 32, 33, 64, 10_000] {
        let mut s = String::from("<objects");
        for k in 0..n {
            let _ = write!(s, " a{k}=\"\"");
        }
        s.push_str(" a0=\"\"/>");
        assert!(parse(s.as_bytes()).is_err(), "duplicate a0 after {n} keys");
        // Duplicate of the last key too.
        let mut s = String::from("<objects");
        for k in 0..n {
            let _ = write!(s, " a{k}=\"\"");
        }
        let _ = write!(s, " a{}=\"\"/>", n - 1);
        assert!(parse(s.as_bytes()).is_err(), "duplicate last key after {n}");
    }
}

/// The flood on a nested element (not the root) and on a `camera` element is linear too:
/// checks run on every start tag, so the root is not the only entry point. A quadratic
/// duplicate scan takes hours at 200k; the 60 s guard fails it instead of hanging.
#[test]
fn attribute_floods_on_nested_and_camera_tags_parse_or_refuse_fast() {
    let mut attrs = String::new();
    for k in 0..200_000_u32 {
        let _ = write!(attrs, " a{k}=\"\"");
    }
    for doc in [
        format!("<objects><cameras{attrs}/></objects>"),
        format!("<objects><cameras><camera id=\"1\" name=\"x\"{attrs}/></cameras></objects>"),
    ] {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(parse(doc.as_bytes()).is_ok());
        });
        assert!(
            rx.recv_timeout(Duration::from_secs(60)).is_ok(),
            "nested attribute flood did not finish in 60 s"
        );
    }
}
