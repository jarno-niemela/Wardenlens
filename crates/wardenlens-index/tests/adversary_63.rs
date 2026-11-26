//! Adversarial tests for #63 (PR #172): `SegmentIndex::newest` on the real SQLite index,
//! checked against the full oldest-first listing after random inserts, tier changes and deletes.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::cast_possible_wrap,
    reason = "adversary tests: a failed setup step is a test failure"
)]

use std::os::unix::fs::PermissionsExt;

use proptest::prelude::*;
use wardenlens_core::camera::CameraId;
use wardenlens_core::recording::SegmentRecord;
use wardenlens_core::storage::{SegmentId, SegmentIndex, StoredSegment, Tier};
use wardenlens_core::time::UnixMs;
use wardenlens_index::Index;

const BASE: i64 = 1_700_000_000_000;

fn open() -> (tempfile::TempDir, Index) {
    let d = tempfile::tempdir().unwrap();
    std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let idx = Index::open(&d.path().join("index.db")).unwrap();
    (d, idx)
}

fn listing(idx: &Index, tier: Tier) -> Vec<StoredSegment> {
    let mut out: Vec<StoredSegment> = Vec::new();
    loop {
        let after = out.last().map(|s| (s.ended_at, s.id));
        let page = idx.oldest(tier, after, 3).unwrap();
        if page.is_empty() {
            return out;
        }
        out.extend(page);
    }
}

#[derive(Debug, Clone)]
enum Op {
    /// camera index, start offset (s), duration (ms), bytes, tier
    Insert(u8, u16, u16, u32, bool),
    SetTier(usize, bool),
    Delete(usize),
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        4 => (0_u8..3, 0_u16..20, 0_u16..3, 0_u32..1000, any::<bool>())
            .prop_map(|(c, s, d, b, t)| Op::Insert(c, s, d, b, t)),
        1 => (any::<usize>(), any::<bool>()).prop_map(|(i, t)| Op::SetTier(i, t)),
        1 => any::<usize>().prop_map(Op::Delete),
    ]
}

fn tier(b: bool) -> Tier {
    if b { Tier::Archive } else { Tier::Hot }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// `newest(tier)` is exactly the last row of the oldest-first listing, ties on the end time
    /// (many: starts and durations are drawn from tiny ranges) broken by the larger id.
    #[test]
    fn newest_is_always_the_last_of_the_oldest_first_listing(ops in prop::collection::vec(op(), 1..60)) {
        let (_d, mut idx) = open();
        let mut ids: Vec<SegmentId> = Vec::new();
        for o in ops {
            match o {
                Op::Insert(c, s, d, b, t) => {
                    let cam = CameraId::new(&format!("cam-{c}")).unwrap();
                    // Distinct (camera, start) per insert: the start is offset by the count.
                    let start = BASE + i64::from(s) * 1000 + ids.len() as i64;
                    let r = SegmentRecord::new(
                        cam,
                        UnixMs::new(start).unwrap(),
                        u64::from(d) * 1000 + 1000 - ids.len() as u64,
                        u64::from(b),
                        1,
                    );
                    if let Ok(id) = idx.insert(&r, tier(t)) {
                        ids.push(id);
                    }
                }
                Op::SetTier(i, t) if !ids.is_empty() => {
                    let id = ids[i % ids.len()];
                    let _ = idx.set_tier(id, tier(t));
                }
                Op::Delete(i) if !ids.is_empty() => {
                    let id = ids.remove(i % ids.len());
                    idx.delete(id).unwrap();
                }
                _ => {}
            }
            for t in [Tier::Hot, Tier::Archive] {
                let all = listing(&idx, t);
                let n = idx.newest(t).unwrap();
                prop_assert_eq!(n, all.last().copied());
                if let Some(n) = n {
                    prop_assert_eq!(n.tier, t);
                    // Independent max over (ended_at, id).
                    let m = all.iter().max_by_key(|s| (s.ended_at, s.id)).copied();
                    prop_assert_eq!(Some(n), m);
                }
            }
        }
    }
}

/// Ties on the end time across cameras pick the larger id, whatever the insertion order of the
/// end times, and a row moved to the other tier leaves this tier's newest.
#[test]
fn newest_breaks_ties_by_id_and_follows_tier_moves_and_deletes() {
    let (_d, mut idx) = open();
    let cam = |s: &str| CameraId::new(s).unwrap();
    // All three end at BASE + 10_000.
    let a = idx
        .insert(
            &SegmentRecord::new(cam("a"), UnixMs::new(BASE).unwrap(), 10_000, 1, 1),
            Tier::Hot,
        )
        .unwrap();
    let b = idx
        .insert(
            &SegmentRecord::new(cam("b"), UnixMs::new(BASE + 5_000).unwrap(), 5_000, 1, 1),
            Tier::Hot,
        )
        .unwrap();
    let c = idx
        .insert(
            &SegmentRecord::new(cam("c"), UnixMs::new(BASE + 9_999).unwrap(), 1, 1, 1),
            Tier::Hot,
        )
        .unwrap();
    assert!(a < b && b < c);
    assert_eq!(idx.newest(Tier::Hot).unwrap().unwrap().id, c);
    idx.set_tier(c, Tier::Archive).unwrap();
    assert_eq!(idx.newest(Tier::Hot).unwrap().unwrap().id, b);
    assert_eq!(idx.newest(Tier::Archive).unwrap().unwrap().id, c);
    idx.delete(b).unwrap();
    assert_eq!(idx.newest(Tier::Hot).unwrap().unwrap().id, a);
    idx.delete(a).unwrap();
    assert_eq!(idx.newest(Tier::Hot).unwrap(), None);
    // A later-starting but earlier-ending segment is not the newest.
    let long = idx
        .insert(
            &SegmentRecord::new(cam("a"), UnixMs::new(BASE).unwrap(), 200_000, 1, 1),
            Tier::Hot,
        )
        .unwrap();
    let _late = idx
        .insert(
            &SegmentRecord::new(cam("b"), UnixMs::new(BASE + 60_000).unwrap(), 1_000, 1, 1),
            Tier::Hot,
        )
        .unwrap();
    assert_eq!(idx.newest(Tier::Hot).unwrap().unwrap().id, long);
}
