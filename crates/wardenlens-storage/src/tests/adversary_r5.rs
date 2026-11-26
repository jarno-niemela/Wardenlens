//! Adversary round 5: per-tier truncation. An archive-only truncation understates the archive's
//! total, and the planner derives `room` (free + archive video) from it, so it changes the hot
//! decisions too.

use wardenlens_core::storage::Tier;

use super::support::{Env, now};
use crate::Storage;

/// Hot 1 MB with 600 kB foreign and 3 x 100 kB segments (free 100 kB, floor 250 kB, reachable:
/// hot state Ok). Archive 1 MB holding 10 x 80 kB segments (free 200 kB, below its 250 kB floor),
/// so the archive must evict its oldest video to take the hot video it can absorb.
fn world() -> (Env, Vec<wardenlens_core::storage::SegmentId>) {
    let env = Env::new();
    env.set_cap("hot", 1_000_000);
    env.set_cap("arch", 1_000_000);
    std::fs::write(env.hot.join("foreign"), vec![0_u8; 600_000]).unwrap();
    for n in 0..10 {
        env.add("cam-2", n, 80_000, Tier::Archive);
    }
    let hot = (50..53)
        .map(|n| env.add("cam-1", n, 100_000, Tier::Hot))
        .collect();
    (env, hot)
}

fn tick(env: &Env, cap: Option<usize>) -> crate::TickReport {
    let (mut lp, _) = Storage::open(env.cfg(), env.index.clone(), env.usage.clone()).unwrap();
    if let Some(c) = cap {
        lp.set_max_segments(c);
    }
    lp.tick(now()).unwrap()
}

#[test]
fn baseline_untruncated_archive_takes_the_hot_video_and_deletes_none() {
    let (env, hot) = world();
    let r = tick(&env, None);
    assert!(!r.segments_truncated, "{r:?}");
    assert!(!r.archive_full, "{r:?}");
    for id in hot {
        assert!(env.tier_of(id).is_some(), "hot row {id:?} deleted: {r:?}");
    }
}

#[test]
fn archive_only_truncation_never_deletes_hot_video_the_archive_could_take() {
    let (env, hot) = world();
    // Cap 3: the hot tier (3 rows) is whole, only the archive (10 rows) is cut to its prefix.
    let r = tick(&env, Some(3));
    assert!(r.segments_truncated, "{r:?}");
    for id in hot {
        assert!(
            env.tier_of(id).is_some(),
            "hot row {id:?} deleted on an archive-only truncation: {r:?}"
        );
    }
}

#[test]
fn archive_only_truncation_does_not_report_a_full_archive_that_is_not_full() {
    let (env, _) = world();
    let r = tick(&env, Some(3));
    assert!(r.segments_truncated, "{r:?}");
    assert!(!r.archive_full, "{r:?}");
}

/// Hot 1 MB, 800 kB foreign, 2 x 75 kB hot segments: the hot floor is unreachable by deleting.
/// The archive (10 x 80 kB, free 200 kB) can take both segments after evicting its oldest video.
fn rolling_world() -> (Env, Vec<wardenlens_core::storage::SegmentId>) {
    let env = Env::new();
    env.set_cap("hot", 1_000_000);
    env.set_cap("arch", 1_000_000);
    std::fs::write(env.hot.join("foreign"), vec![0_u8; 800_000]).unwrap();
    for n in 0..10 {
        env.add("cam-2", n, 80_000, Tier::Archive);
    }
    let hot = (50..52)
        .map(|n| env.add("cam-1", n, 75_000, Tier::Hot))
        .collect();
    (env, hot)
}

fn rolling_tick(env: &Env, cap: Option<usize>) -> crate::TickReport {
    let mut cfg = env.cfg();
    cfg.policy.emergency_reserve_bytes = 200_000;
    let (mut lp, _) = Storage::open(cfg, env.index.clone(), env.usage.clone()).unwrap();
    if let Some(c) = cap {
        lp.set_max_segments(c);
    }
    lp.tick(now()).unwrap()
}

#[test]
fn baseline_untruncated_archive_takes_both_unsatisfiable_hot_segments() {
    let (env, hot) = rolling_world();
    let r = rolling_tick(&env, None);
    for id in hot {
        assert_eq!(env.tier_of(id), Some(Tier::Archive), "{r:?}");
    }
}

#[test]
fn archive_only_truncation_does_not_start_a_rolling_buffer_that_deletes_hot_video() {
    let (env, hot) = rolling_world();
    // Cap 2: hot (2 rows) is whole, the archive (10 rows) is cut.
    let r = rolling_tick(&env, Some(2));
    assert!(r.segments_truncated, "{r:?}");
    for id in hot {
        assert!(env.tier_of(id).is_some(), "hot row {id:?} deleted: {r:?}");
    }
}

#[test]
fn archive_only_truncation_does_not_stall_the_archive_below_its_floor_forever() {
    // Archive 45 x 20 kB (free 100 kB, floor 250 kB, really recoverable). With cap 3 the plan
    // sees 60 kB of archive video: room 160 kB < floor, so no eviction is ever planned.
    let env = Env::new();
    env.set_cap("hot", 1_000_000);
    env.set_cap("arch", 1_000_000);
    std::fs::write(env.hot.join("foreign"), vec![0_u8; 600_000]).unwrap();
    for n in 0..45 {
        env.add("cam-2", n, 20_000, Tier::Archive);
    }
    let hot: Vec<_> = (50..53)
        .map(|n| env.add("cam-1", n, 100_000, Tier::Hot))
        .collect();
    let (mut lp, _) = Storage::open(env.cfg(), env.index.clone(), env.usage.clone()).unwrap();
    lp.set_max_segments(3);
    let mut last = None;
    for _ in 0..10 {
        last = Some(lp.tick(now()).unwrap());
    }
    let r = last.unwrap();
    let free = match r.archive {
        crate::ArchiveProbe::Available(s) => s.free_bytes,
        _ => 0,
    };
    let hot_deleted = hot.iter().filter(|id| env.tier_of(**id).is_none()).count();
    assert!(
        free >= 250_000 && hot_deleted == 0,
        "after 10 ticks: archive free {free} (floor 250000), {hot_deleted} hot rows deleted: {r:?}"
    );
}

#[test]
fn a_regular_file_planted_over_the_twin_directory_does_not_pin_a_hot_delete() {
    let env = Env::new();
    let id = env.add("cam-1", 0, 100, Tier::Hot);
    let rel = Env::rel("cam-1", 0);
    let first = rel.split('/').next().unwrap();
    std::fs::write(env.arch.join(first), b"planted").unwrap();
    let (mut lp, _) = Storage::open(env.cfg(), env.index.clone(), env.usage.clone()).unwrap();
    let _ = &mut lp;
    let out = lp.delete_now(id, true);
    assert_eq!(
        env.tier_of(id),
        None,
        "{out:?}: row {rel} pinned by a planted file"
    );
}
