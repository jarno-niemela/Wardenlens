//! Attribute-flood cost check for #252: parse time must grow linearly with the attribute count.
//!
//! Each sample does the same linear work on both sides (four parses of N attributes against one
//! of 4N), so host load inflates both alike: linear work gives a ratio near 1, a quadratic
//! duplicate-key scan near 4. A quadratic mutant fails this within tens of seconds.

use std::fmt::Write as _;
use std::time::{Duration, Instant};

use wardenlens_agentdvr::parse;

fn attribute_flood(n: u32) -> String {
    let mut s = String::from("<objects");
    for k in 0..n {
        let _ = write!(s, " a{k}=\"\"");
    }
    s.push_str("/>");
    s
}

fn timed(f: impl Fn()) -> Duration {
    let t = Instant::now();
    f();
    t.elapsed()
}

/// Four parses of N attributes and one of 4N take the same linear work; a quadratic scan makes
/// the single large parse four times slower. Samples alternate, best of seven each.
#[test]
fn equal_work_attribute_flood_ratio_is_linear() {
    const N: u32 = 4_000;
    let small = attribute_flood(N);
    let large = attribute_flood(4 * N);
    let mut best_small = Duration::MAX;
    let mut best_large = Duration::MAX;
    for _ in 0..7 {
        best_small = best_small.min(timed(|| {
            for _ in 0..4 {
                assert!(parse(small.as_bytes()).is_ok());
            }
        }));
        best_large = best_large.min(timed(|| assert!(parse(large.as_bytes()).is_ok())));
    }
    // Linear: about 1x. Quadratic: about 4x. 2.5x splits them with margin on both sides.
    assert!(
        best_large * 2 < best_small.max(Duration::from_millis(1)) * 5,
        "4 x {N} attributes took {best_small:?}, 1 x {} took {best_large:?}",
        4 * N
    );
}
