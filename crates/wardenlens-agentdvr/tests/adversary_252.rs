//! Adversary tests for #252: the attribute-flood ratio at sizes where a quadratic duplicate-key
//! scan is measurable, so a regression fails the assertion within seconds.
//!
//! At 175k vs 700k attributes a quadratic scan takes about 3 minutes and 45 minutes for each
//! parse, so the in-crate ratio test can only "fail" by hanging the gate. Measured on a mutant
//! that replaces quick-xml's hashed check with a linear scan: 2k in 25 ms, 8k in 395 ms, 32k in
//! 5.5 s (about 16x per 4x); the unmutated parser gives 3 ms, 12.6 ms, 52 ms (about 4x).

use std::fmt::Write as _;
use std::time::{Duration, Instant};

use wardenlens_agentdvr::parse;

/// An `<objects>` element with `n` empty attributes.
fn attribute_flood(n: u32) -> String {
    let mut s = String::from("<objects");
    for k in 0..n {
        let _ = write!(s, " a{k}=\"\"");
    }
    s.push_str("/>");
    s
}

/// Best of five parse times: a load spike inflates one run, rarely all of them.
fn best_parse_time(doc: &str) -> Duration {
    (0..5)
        .map(|_| {
            let t = Instant::now();
            assert!(parse(doc.as_bytes()).is_ok());
            t.elapsed()
        })
        .min()
        .unwrap_or_default()
}

/// 4k vs 16k attributes (both far past quick-xml's 32-attribute linear-scan threshold): linear
/// work gives about 4x, quadratic about 16x. A quadratic mutant fails here within about 10 s.
#[test]
fn attribute_flood_ratio_fails_fast_on_quadratic_work() {
    const N: u32 = 4_000;
    const MAX_RATIO: u32 = 10;
    let small = attribute_flood(N);
    let large = attribute_flood(4 * N);
    let t_small = best_parse_time(&small);
    let t_large = best_parse_time(&large);
    assert!(
        t_large < t_small.max(Duration::from_millis(1)) * MAX_RATIO,
        "{N} attributes took {t_small:?}, {} took {t_large:?}",
        4 * N
    );
}
