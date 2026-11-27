//! Adversary, #195 round 2: "a name is not an identity" on the delete path (eviction), an
//! entry point the reconciliation fix did not cover.

use wardenlens_core::storage::Tier;

use super::matrix::build;
use super::support::{Env, pattern};

fn foreign(n: usize) -> Vec<u8> {
    let mut v = pattern(n);
    for b in &mut v {
        *b = b.wrapping_add(7);
    }
    v
}

/// An archive row is evicted while a hot file of the same size but other bytes sits at its key
/// (the recorder's unchecked rename bump, ADR 0005 §3(a)(i), or a planted file). The hot file
/// is not this row's copy: it must not be unlinked (quarantine at most).
#[test]
fn adversary_evicting_an_archive_row_never_unlinks_a_foreign_hot_file_of_the_same_size() {
    let env = Env::new();
    let id = env.add("cam-1", 0, 100, Tier::Archive);
    let hp = env.hot_file("cam-1", 0);
    std::fs::create_dir_all(hp.parent().unwrap()).unwrap();
    let other = foreign(100);
    std::fs::write(&hp, &other).unwrap();
    let (lp, _) = build(&env, None);
    let out = lp.delete_now(id, true);
    let kept = hp.exists() || Env::quarantined(&env.hot).contains(&other);
    assert!(
        kept,
        "foreign hot recording destroyed by eviction ({out:?})"
    );
}

/// The mirror: a hot row is evicted while an archive file of its size but other bytes is at its
/// key. That archive file is not this row's copy.
#[test]
fn adversary_evicting_a_hot_row_never_unlinks_a_foreign_archive_file_of_the_same_size() {
    let env = Env::new();
    let id = env.add("cam-1", 0, 100, Tier::Hot);
    let ap = env.arch_file("cam-1", 0);
    std::fs::create_dir_all(ap.parent().unwrap()).unwrap();
    let other = foreign(100);
    std::fs::write(&ap, &other).unwrap();
    let (lp, _) = build(&env, None);
    let out = lp.delete_now(id, true);
    let kept = ap.exists() || Env::quarantined(&env.arch).contains(&other);
    assert!(kept, "foreign archive file destroyed by eviction ({out:?})");
}

/// Control: a byte-identical twin is still deleted with the row.
#[test]
fn adversary_evicting_a_row_deletes_its_identical_twin() {
    let env = Env::new();
    let id = env.add("cam-1", 0, 100, Tier::Archive);
    let hp = env.hot_file("cam-1", 0);
    std::fs::create_dir_all(hp.parent().unwrap()).unwrap();
    std::fs::write(&hp, pattern(100)).unwrap();
    let (lp, _) = build(&env, None);
    assert_eq!(lp.delete_now(id, true), crate::Outcome::Deleted);
    assert!(!hp.exists());
    assert_eq!(env.tier_of(id), None);
}

/// A sealed segment the recorder kept under `<name>.mp4.unsealed` (no free name, no quarantine)
/// is not a `.part`: start-up reconciliation leaves it where it is and reports it `unknown_left`.
#[test]
fn a_kept_unsealed_segment_is_left_in_place_and_reported_unknown_left() {
    let env = Env::new();
    let p = super::support::put(
        &env.hot,
        "cam-1/2023-11-14/221320-100.mp4.unsealed",
        &super::support::good(),
    );
    let (mut lp, _) = build(&env, None);
    let out = lp.reconcile_startup().unwrap();
    assert_eq!(out.report.part_deleted, 0, "{:?}", out.report);
    assert_eq!(out.report.unknown_left, 1, "{:?}", out.report);
    assert_eq!(std::fs::read(&p).unwrap(), super::support::good());
}
