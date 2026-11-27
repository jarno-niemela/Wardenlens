//! Adversary round 2 (ticket #57): the read-back after a transient insert failure, the rename
//! retry, and the derived health state.

mod common;

use common::rig::*;
use common::*;
use wardenlens_core::recording::{RelPath, SegmentRecord};
use wardenlens_core::storage::{SegmentIndex, Tier};
use wardenlens_index::IndexError;
use wardenlens_recorder::{HoldReason, RecorderState};

fn quarantined(root: &std::path::Path) -> Vec<String> {
    tree(root)
        .into_iter()
        .filter(|n| n.starts_with("_quarantine"))
        .collect()
}

/// Commit, then Busy (the row is durable); the retry meets its own row as a duplicate. The
/// read-back that should find the row is itself refused once (the database is still busy).
/// An unknown answer is not "no row": the indexed file must not be moved to quarantine.
#[test]
fn a_busy_read_back_after_commit_then_error_does_not_quarantine_an_indexed_segment() {
    let mut r = Rig::new();
    r.start();
    r.feed(Slice::P);
    {
        let mut s = r.index.lock().unwrap();
        s.commit_then_error = vec![IndexError::Busy { op: "insert" }].into();
        // The key probes at the start are done; this hits only the read-back.
        s.list_errors = 1;
    }
    let d = r.finish();
    assert_eq!(d.rows.len(), 1, "the row was committed");
    let row = &d.rows[0].record;
    let path = d
        .root
        .join(RelPath::new(&row.camera, row.started_at_ms).to_string());
    assert!(
        path.exists(),
        "the indexed segment's file was moved away: tree {:?}, health {:?}",
        tree(&d.root),
        d.end
    );
    assert!(quarantined(&d.root).is_empty(), "{:?}", tree(&d.root));
    assert_eq!(d.end.segments_quarantined, 0, "{:?}", d.end);
}

/// Same, with the retries run out instead of a duplicate: an unknown read-back leaves the file in
/// place (reconciliation judges it), never quarantines it.
#[test]
fn a_busy_read_back_when_the_retries_run_out_leaves_the_file_in_place() {
    let config = fast().with_insert_retries(0, std::time::Duration::ZERO);
    let mut r = Rig::build(config, None, |_, _| {});
    r.start();
    r.feed(Slice::P);
    {
        let mut s = r.index.lock().unwrap();
        s.commit_then_error = vec![IndexError::Busy { op: "insert" }].into();
        s.list_errors = 1;
    }
    let d = r.finish();
    assert_eq!(d.rows.len(), 1);
    assert_eq!(quarantined(&d.root).len(), 0);
    assert_eq!(tree(&d.root).len(), 1);
}

/// Round 2 found: the rename retry bumps the key past a planted file, and a row may already hold
/// the bumped key (its file is on another tier or gone). The good segment must then not be
/// refused as a duplicate and quarantined: it stays where it is.
#[test]
fn a_rename_bump_onto_a_key_that_the_index_holds_does_not_lose_the_segment() {
    let mut r = Rig::build(fast(), None, |_, index| {
        // A row at T0 + 101 whose file is on the archive tier, not on the hot volume.
        let rec = SegmentRecord::new(cam(), ms(T0 + 101), 1_000, 4_096, 10);
        index.insert(&rec, Tier::Archive).unwrap();
    });
    r.start(); // arrival T0 + 100: free (the row starts at T0 + 101)
    r.feed(Slice::P);
    // Someone plants a file at the final name of T0 + 100 while the segment is open.
    let planted = r.root.join(RelPath::new(&cam(), ms(T0 + 100)).to_string());
    std::fs::write(&planted, b"foreign").unwrap();
    let d = r.finish();
    assert_eq!(std::fs::read(&planted).unwrap(), b"foreign");
    assert!(
        quarantined(&d.root).is_empty(),
        "the finished segment was quarantined: {:?} {:?}",
        tree(&d.root),
        d.end
    );
    assert_eq!(d.end.segments_quarantined, 0, "{:?}", d.end);
}

/// A directory or a dangling symlink planted at the final name is never replaced either.
#[test]
fn a_directory_or_symlink_planted_at_the_final_name_is_skipped() {
    for kind in ["dir", "symlink"] {
        let mut r = Rig::new();
        r.start();
        r.feed(Slice::P);
        let planted = r.root.join(RelPath::new(&cam(), ms(T0 + 100)).to_string());
        match kind {
            "dir" => std::fs::create_dir(&planted).unwrap(),
            _ => std::os::unix::fs::symlink("/nonexistent/target", &planted).unwrap(),
        }
        let d = r.finish();
        let meta = std::fs::symlink_metadata(&planted).unwrap();
        match kind {
            "dir" => assert!(meta.is_dir()),
            _ => assert!(meta.file_type().is_symlink()),
        }
        assert_eq!(d.rows.len(), 1, "{kind}");
        assert_eq!(d.rows[0].record.started_at_ms.as_i64(), T0 + 101, "{kind}");
        assert_eq!(part_files(&d.root).len(), 0);
    }
}

/// After a recovered storage hold the state is Recording, and after a later graceful stop the
/// health says Waiting with no stale reason.
#[test]
fn the_state_follows_the_conditions_across_a_full_volume_and_recovery() {
    let mut r = Rig::new();
    r.store.lock().unwrap().create_error = Some(wardenlens_recorder::StoreError::NoSpace);
    r.start();
    assert_eq!(r.state(), RecorderState::Held(HoldReason::StorageFull));
    r.store.lock().unwrap().available = Some(u64::MAX);
    r.feed(Slice::Idr); // back-off: skipped
    assert_eq!(r.state(), RecorderState::Held(HoldReason::StorageFull));
    r.feed(Slice::Idr);
    assert_eq!(r.state(), RecorderState::Recording);
    let d = r.finish();
    assert_eq!(d.end.state, RecorderState::Waiting);
    assert_eq!(d.rows.len(), 1);
}
