//! Adversary for ticket #59, round 4: the back-off reset on a new return, the health error it
//! governs, and the loaded-row filter of the held own-floor deletes.

use wardenlens_core::storage::Tier;
use wardenlens_core::time::Timestamp;

use super::support::{Env, T0, good, put};
use crate::{ARCHIVE_MARKER, RETURNED_PASS_TRIES, Storage};

fn late() -> Timestamp {
    Timestamp::from_unix_millis(T0 + 48 * 3_600_000)
}

fn unmount(env: &Env) {
    std::fs::remove_file(env.arch.join(ARCHIVE_MARKER)).unwrap();
}

fn mount(env: &Env) {
    std::fs::write(env.arch.join(ARCHIVE_MARKER), b"").unwrap();
}

/// A loop whose returned pass can never finish (walk cap of 1), archive away at start.
fn never_finishing(
    env: &Env,
) -> crate::StorageLoop<super::support::TestIndex, crate::RealFs, super::support::FakeUsage> {
    unmount(env);
    env.add("cam-1", 0, 100, Tier::Hot);
    put(&env.arch, &Env::rel("cam-2", 0), &good());
    let cfg = env.cfg().with_walk_max_entries(1);
    let (mut lp, _) = Storage::open(cfg, env.index.clone(), env.usage.clone()).unwrap();
    lp.set_initial_archive_state(false);
    lp
}

/// ADR 0005 section 9: the health error is raised "until a pass finishes". A brief absence of
/// the archive is not a finished pass.
#[test]
fn the_unfinished_pass_health_error_is_not_cleared_by_a_flap_without_a_finished_pass() {
    let env = Env::new();
    let mut lp = never_finishing(&env);
    mount(&env);
    for _ in 0..RETURNED_PASS_TRIES {
        let r = lp.tick(late()).unwrap();
        assert!(r.returned.is_some());
    }
    assert!(lp.returned_pass_unfinished());
    unmount(&env);
    lp.tick(late()).unwrap();
    mount(&env);
    let r = lp.tick(late()).unwrap();
    let pass = r.returned.as_ref().expect("the pass ran on the new return");
    assert!(
        pass.walk_cap_exceeded,
        "the pass still did not finish: {pass:?}"
    );
    assert!(r.archive_returned, "the hold stays");
    assert!(
        r.returned_pass_unfinished,
        "the pass never finished, yet the health error was cleared by the flap: {r:?}"
    );
}

/// A flapping archive (present two ticks, away one) whose pass never finishes: the hold lasts
/// forever (no move ever runs), so the health error must be raised at some point.
#[test]
fn a_flapping_archive_whose_pass_never_finishes_still_raises_the_health_error() {
    let env = Env::new();
    let mut lp = never_finishing(&env);
    let mut raised = false;
    let mut passes = 0;
    for t in 0..90 {
        if t % 3 == 2 {
            unmount(&env);
        } else {
            mount(&env);
        }
        let r = lp.tick(late()).unwrap();
        if let Some(p) = r.returned.as_ref() {
            assert!(p.walk_cap_exceeded);
            passes += 1;
        }
        assert_eq!(r.moved, 0);
        raised |= r.returned_pass_unfinished;
    }
    assert!(passes >= 30, "passes {passes}");
    assert!(
        raised,
        "{passes} unfinished passes over 90 ticks and the health error was never raised"
    );
}

/// No hot rows at all: the stand-in id (`max loaded id + 1`) is then the next real archive row
/// beyond the loaded prefix. Neither the held own-floor plan nor the plain plan may execute it.
fn archive_only_standin(
    env: &Env,
) -> (
    Vec<wardenlens_core::storage::SegmentId>,
    wardenlens_core::storage::SegmentId,
) {
    env.set_cap("arch", 1_000_000);
    let visible: Vec<_> = (0..3)
        .map(|n| env.add("cam-2", n, 1_000, Tier::Archive))
        .collect();
    let next = env.add("cam-2", 3, 120_000, Tier::Archive);
    for n in 4..10 {
        env.add("cam-2", n, 120_000, Tier::Archive);
    }
    (visible, next)
}

#[test]
fn with_no_hot_rows_the_stand_in_is_an_unloaded_archive_row_and_is_never_executed_while_held() {
    let env = Env::new();
    let (visible, next) = archive_only_standin(&env);
    let (mut lp, _) = Storage::open(env.cfg(), env.index.clone(), env.usage.clone()).unwrap();
    lp.set_max_segments(3);
    lp.set_initial_archive_state(false);
    let r = lp.tick(late()).unwrap();
    assert!(r.archive_returned || r.returned.is_some(), "{r:?}");
    assert_eq!(env.tier_of(next), Some(Tier::Archive), "{r:?}");
    assert!(env.arch_file("cam-2", 3).exists(), "{r:?}");
    // The visible prefix is the archive's own floor eviction: it still runs while held.
    assert!(visible.iter().all(|id| env.tier_of(*id).is_none()), "{r:?}");
}

#[test]
fn with_no_hot_rows_the_stand_in_is_never_executed_without_a_hold() {
    let env = Env::new();
    let (_, next) = archive_only_standin(&env);
    let (mut lp, _) = Storage::open(env.cfg(), env.index.clone(), env.usage.clone()).unwrap();
    lp.set_max_segments(3);
    let r = lp.tick(late()).unwrap();
    assert_eq!(env.tier_of(next), Some(Tier::Archive), "{r:?}");
    assert!(env.arch_file("cam-2", 3).exists(), "{r:?}");
}

/// Over many held ticks with a truncated archive the archive's floor is restored page by page,
/// one loaded prefix per tick, and the hot recording sharing an id with the stand-in survives.
#[test]
fn a_long_hold_with_a_truncated_archive_never_executes_a_stand_in_id() {
    let env = Env::new();
    env.set_cap("arch", 1_000_000);
    for n in 0..30 {
        env.add("cam-2", n, 40_000, Tier::Archive);
    }
    let hot: Vec<_> = (100..103)
        .map(|n| env.add("cam-1", n, 1_000, Tier::Hot))
        .collect();
    let cfg = env.cfg().with_walk_max_entries(1);
    let (mut lp, _) = Storage::open(cfg, env.index.clone(), env.usage.clone()).unwrap();
    lp.set_max_segments(3);
    lp.set_initial_archive_state(false);
    let mut later = Vec::new();
    for t in 0..40 {
        // A new recording every tick: each one may get the stand-in's id.
        later.push((t, env.add("cam-1", 200 + t, 1_000, Tier::Hot)));
        let r = lp.tick(late()).unwrap();
        assert!(r.archive_returned, "tick {t}: {r:?}");
        assert_eq!(r.moved, 0);
        for (n, id) in &later {
            assert_eq!(
                env.tier_of(*id),
                Some(Tier::Hot),
                "tick {t}: recording {n} lost: {r:?}"
            );
        }
        for id in &hot {
            assert_eq!(env.tier_of(*id), Some(Tier::Hot), "tick {t}: {r:?}");
        }
    }
}

/// A flapping archive whose pass never finishes, a recorder writing every tick and a reserve
/// above the floor: the reset makes every return tick a "first held tick" again, planned with the
/// plain hold (no move, no hot delete). The plain hot floor must still hold after every tick once
/// the hold has been unfinished (before the reset, `returned_unfinished > 0` kept every later
/// return tick on the degraded plan).
#[test]
fn a_flapping_never_finishing_hold_keeps_the_hot_floor_on_return_ticks() {
    let env = Env::new();
    env.set_cap("hot", 1_000_000);
    for n in 0..10 {
        env.add("cam-1", n, 60_000, Tier::Hot);
    }
    for n in 0..3 {
        env.add("cam-2", n, 1_000, Tier::Archive);
    }
    unmount(&env);
    let mut cfg = env.cfg().with_walk_max_entries(1);
    cfg.policy.emergency_reserve_bytes = 350_000;
    let (mut lp, _) = Storage::open(cfg, env.index.clone(), env.usage.clone()).unwrap();
    lp.set_initial_archive_state(false);
    let mut frees = Vec::new();
    for t in 0..40 {
        if t % 2 == 0 {
            mount(&env);
        } else {
            unmount(&env);
        }
        env.add("cam-1", 100 + t, 40_000, Tier::Hot);
        let r = lp.tick(late()).unwrap();
        assert_eq!(r.moved, 0);
        frees.push((
            t,
            1_000_000_u64.saturating_sub(super::support::du(&env.hot)),
        ));
    }
    for (t, f) in frees.iter().skip(4) {
        assert!(
            *f >= 250_000,
            "tick {t}: hot free {f} below the 25% floor: {frees:?}"
        );
    }
}
