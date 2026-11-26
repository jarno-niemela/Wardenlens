//! #175: many processes open, write to and close one index in parallel. Every `Index::open` must
//! succeed even while another process closes its last connection (which deletes `-wal` and
//! `-shm`), and no row may be lost.
//!
//! The test binary re-runs itself as the worker (`WL_STRESS_DIR` selects the mode), so no helper
//! binary is needed. Coordination uses no sleeps: every worker blocks reading its stdin until the
//! parent has spawned all of them and closes the pipes, then the parent waits for the exits.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "stress test: a failed setup step is a test failure"
)]

use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Stdio};

use wardenlens_core::camera::CameraId;
use wardenlens_core::recording::SegmentRecord;
use wardenlens_core::storage::{SegmentIndex, Tier};
use wardenlens_core::time::{Timestamp, UnixMs};
use wardenlens_index::Index;

const BASE: i64 = 1_700_000_000_000;
const WORKERS: usize = 8;
const ROUNDS: i64 = 20;
const DIR_VAR: &str = "WL_STRESS_DIR";
const ID_VAR: &str = "WL_STRESS_ID";

fn cam(k: usize) -> CameraId {
    CameraId::new(&format!("c{k}")).unwrap()
}

/// Runs only as a spawned worker; a no-op in a normal test run.
#[test]
fn worker() {
    let Ok(dir) = std::env::var(DIR_VAR) else {
        return;
    };
    let id: usize = std::env::var(ID_VAR).unwrap().parse().unwrap();
    // The start barrier: returns when the parent closes our stdin.
    let mut sink = Vec::new();
    std::io::stdin().read_to_end(&mut sink).unwrap();
    let path = std::path::Path::new(&dir).join("index.db");
    for round in 0..ROUNDS {
        // Open, write one row, close: the close is the last connection when the others are
        // between rounds, so it checkpoints and deletes the sidecars under the other openers.
        let mut idx = Index::open(&path).unwrap_or_else(|e| panic!("worker {id} open: {e:?}"));
        let rec = SegmentRecord::new(
            cam(id),
            UnixMs::new(BASE + round * 10_000).unwrap(),
            1000,
            10,
            1,
        );
        idx.insert(&rec, Tier::Hot).unwrap();
    }
}

#[test]
fn parallel_open_write_close_never_fails_and_loses_no_row() {
    if std::env::var(DIR_VAR).is_ok() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let exe = std::env::current_exe().unwrap();
    let mut children = Vec::new();
    for id in 0..WORKERS {
        children.push(
            Command::new(&exe)
                .args(["--exact", "worker", "--nocapture", "--test-threads=1"])
                .env(DIR_VAR, dir.path())
                .env(ID_VAR, id.to_string())
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap(),
        );
    }
    // Release them together.
    for c in &mut children {
        drop(c.stdin.take());
    }
    for (id, c) in children.into_iter().enumerate() {
        let out = c.wait_with_output().unwrap();
        assert!(
            out.status.success(),
            "worker {id} failed:\n{}\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let idx = Index::open(&dir.path().join("index.db")).unwrap();
    for id in 0..WORKERS {
        let page = idx
            .list(
                &cam(id),
                Timestamp::from_unix_millis(0),
                Timestamp::from_unix_millis(i64::MAX),
                1000,
                None,
            )
            .unwrap();
        assert_eq!(
            i64::try_from(page.items.len()).unwrap(),
            ROUNDS,
            "worker {id}"
        );
    }
}
