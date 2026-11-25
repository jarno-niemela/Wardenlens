//! Adversarial tests for #49 round 2 (PR #140 at 0d2cac6): the SQLite segment index.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    reason = "adversary tests: a failed setup step is a test failure"
)]

use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use wardenlens_core::camera::CameraId;
use wardenlens_core::recording::SegmentRecord;
use wardenlens_core::storage::{SegmentId, SegmentIndex, Tier};
use wardenlens_core::time::{Timestamp, UnixMs};
use wardenlens_index::{Index, IndexError};

const BASE: i64 = 1_700_000_000_000;

fn private_tempdir() -> tempfile::TempDir {
    let d = tempfile::tempdir().unwrap();
    chmod(d.path(), 0o700);
    d
}

fn cam(s: &str) -> CameraId {
    CameraId::new(s).unwrap()
}

fn rec(camera: &str, start: i64, dur: u64, bytes: u64) -> SegmentRecord {
    SegmentRecord::new(cam(camera), UnixMs::new(start).unwrap(), dur, bytes, 1)
}

fn chmod(p: &Path, mode: u32) {
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode)).unwrap();
}

fn sidecar(p: &Path, suffix: &str) -> PathBuf {
    let mut n = p.as_os_str().to_owned();
    n.push(suffix);
    n.into()
}

fn snapshot(dir: &Path) -> BTreeMap<String, Option<Vec<u8>>> {
    let mut out = BTreeMap::new();
    for e in std::fs::read_dir(dir).unwrap() {
        let e = e.unwrap();
        let name = e.file_name().to_string_lossy().into_owned();
        let bytes = if e.file_type().unwrap().is_file() {
            Some(std::fs::read(e.path()).unwrap())
        } else {
            None
        };
        out.insert(name, bytes);
    }
    out
}

fn all_time() -> (Timestamp, Timestamp) {
    (
        Timestamp::from_unix_millis(0),
        Timestamp::from_unix_millis(i64::MAX),
    )
}

/// Copies `index.db` and its `-wal` while `conn` keeps the WAL alive: the files a crash leaves.
fn crash_copy(src: &Path, dst_dir: &Path) -> PathBuf {
    let dst = dst_dir.join("index.db");
    for s in ["", "-wal"] {
        let to = sidecar(&dst, s);
        std::fs::copy(sidecar(src, s), &to).unwrap();
        chmod(&to, 0o600);
    }
    dst
}

// ---------------------------------------------------------------------------------------------
// oldest(): the keyset continuation
// ---------------------------------------------------------------------------------------------

/// `after = (T, id)` means "rows whose `(ended_at, id)` sorts after `(T, id)`". A row that ends
/// later than `T` sorts after `(T, any id)`, whatever the id. An id above `i64::MAX` cannot name
/// a row, but it is still a valid key: the natural "skip everything that ends at or before T"
/// key is `(T, SegmentId::new(u64::MAX))`.
#[test]
fn oldest_after_a_key_with_a_huge_id_still_returns_rows_that_end_later() {
    let dir = private_tempdir();
    let mut idx = Index::open(&dir.path().join("index.db")).unwrap();
    let a = idx.insert(&rec("cam1", BASE, 1000, 10), Tier::Hot).unwrap();
    let b = idx
        .insert(&rec("cam1", BASE + 5000, 1000, 10), Tier::Hot)
        .unwrap();
    // Oracle: (ended_at, id) order; key (BASE + 1000, u64::MAX) sits after `a` and before `b`.
    let key = (
        Timestamp::from_unix_millis(BASE + 1000),
        SegmentId::new(u64::MAX),
    );
    let got: Vec<SegmentId> = idx
        .oldest(Tier::Hot, Some(key), 10)
        .unwrap()
        .into_iter()
        .map(|s| s.id)
        .collect();
    assert_eq!(got, vec![b], "row a = {a:?} is before the key, b after it");
}

/// Same with `i64::MAX + 1` (the first id that cannot be stored) and an earlier `ended_at`.
#[test]
fn oldest_after_an_unstorable_id_at_an_early_time_returns_the_whole_tier() {
    let dir = private_tempdir();
    let mut idx = Index::open(&dir.path().join("index.db")).unwrap();
    let a = idx.insert(&rec("cam1", BASE, 1000, 10), Tier::Hot).unwrap();
    let key = (
        Timestamp::from_unix_millis(0),
        SegmentId::new(u64::try_from(i64::MAX).unwrap() + 1),
    );
    let got: Vec<SegmentId> = idx
        .oldest(Tier::Hot, Some(key), 10)
        .unwrap()
        .into_iter()
        .map(|s| s.id)
        .collect();
    assert_eq!(got, vec![a]);
}

/// Control: a storable id behaves as the keyset says (the code path above differs only in the
/// id's size).
#[test]
fn oldest_after_a_key_with_i64_max_id_returns_rows_that_end_later() {
    let dir = private_tempdir();
    let mut idx = Index::open(&dir.path().join("index.db")).unwrap();
    idx.insert(&rec("cam1", BASE, 1000, 10), Tier::Hot).unwrap();
    let b = idx
        .insert(&rec("cam1", BASE + 5000, 1000, 10), Tier::Hot)
        .unwrap();
    let key = (
        Timestamp::from_unix_millis(BASE + 1000),
        SegmentId::new(u64::try_from(i64::MAX).unwrap()),
    );
    let got: Vec<SegmentId> = idx
        .oldest(Tier::Hot, Some(key), 10)
        .unwrap()
        .into_iter()
        .map(|s| s.id)
        .collect();
    assert_eq!(got, vec![b]);
}

/// Paging through a tier by the last row's key while rows are deleted and inserted between
/// pages visits each surviving original row exactly once, in order.
#[test]
fn oldest_paging_under_deletes_and_inserts_is_exactly_once() {
    let dir = private_tempdir();
    let mut idx = Index::open(&dir.path().join("index.db")).unwrap();
    let mut ids = Vec::new();
    for i in 0..50 {
        // Equal ended_at for pairs from two cameras: ties broken by id.
        let c = if i % 2 == 0 { "cama" } else { "camb" };
        let start = BASE + (i / 2) * 10_000;
        ids.push(idx.insert(&rec(c, start, 1000, 7), Tier::Hot).unwrap());
    }
    let mut seen = Vec::new();
    let mut after = None;
    let mut round = 0;
    loop {
        let page = idx.oldest(Tier::Hot, after, 3).unwrap();
        for s in &page {
            seen.push(s.id);
        }
        let Some(last) = page.last() else { break };
        after = Some((last.ended_at, last.id));
        // Delete the row just returned and insert a later one.
        idx.delete(last.id).unwrap();
        idx.insert(
            &rec("camc", BASE + 10_000_000 + round * 10_000, 1000, 7),
            Tier::Hot,
        )
        .unwrap();
        round += 1;
        if round > 200 {
            break;
        }
    }
    let originals: Vec<SegmentId> = seen.iter().copied().filter(|id| ids.contains(id)).collect();
    assert_eq!(originals, ids, "each original row exactly once, in order");
}

// ---------------------------------------------------------------------------------------------
// Open: crash recovery of an own index
// ---------------------------------------------------------------------------------------------

/// An own index that lost power while a connection was open (a `-wal` with committed frames)
/// must open again: refusing it makes `serve` refuse to start (ADR 0005 section 9, #68), and
/// deleting the `-wal` loses committed M8 writes. The copy-based probe caps the main file at
/// 256 MiB, so an index above that size can never recover from a crash. The index size depends
/// on the site (cameras x segments x retention), so the cap is a hidden site-size limit.
///
/// The file is grown past the cap with a sparse tail that SQLite ignores (the header's page
/// count is authoritative), which shows the open opens it cleanly and refuses it only because
/// a `-wal` is present.
#[test]
fn a_large_own_index_with_a_crash_wal_still_opens() {
    let dir = private_tempdir();
    let path = dir.path().join("index.db");
    let mut idx = Index::open(&path).unwrap();
    idx.insert(&rec("cam1", BASE, 1000, 10), Tier::Hot).unwrap();
    drop(idx);
    let pad = 256 * 1024 * 1024 + 4096;
    std::fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .unwrap()
        .set_len(pad)
        .unwrap();
    // Clean: opens.
    drop(Index::open(&path).expect("a large clean index opens"));
    // Crash: a connection writes a row and the files are copied while it is open.
    let c = rusqlite::Connection::open(&path).unwrap();
    c.execute_batch(
        "INSERT INTO segments (camera_id, started_at_ms, duration_ms, ended_at_ms, bytes, \
         frame_count, tier) VALUES ('cam1', 1700000010000, 1000, 1700000011000, 5, 1, 0);",
    )
    .unwrap();
    let crash = private_tempdir();
    let crashed = crash_copy(&path, crash.path());
    drop(c);
    let len = std::fs::metadata(&crashed).unwrap().len();
    assert!(len > 256 * 1024 * 1024, "{len}");
    let res = Index::open(&crashed);
    assert!(
        res.is_ok(),
        "own index refused after a crash only because of its size: {:?}",
        res.err()
    );
    let idx = res.unwrap();
    let (from, to) = all_time();
    assert_eq!(
        idx.list(&cam("cam1"), from, to, 10, None)
            .unwrap()
            .items
            .len(),
        2
    );
}

/// Restoring `index.db` from a backup while the `-wal` of the live file is still beside it (an
/// operator mistake SQLite documents) replays pages of one database onto another. The probe
/// judges the result with `quick_check`, which does not compare index b-trees with the table.
/// Here the `-wal` holds a `set_tier` (table page and `segments_tier_end` page), so the
/// replayed file has a row that `segments_camera_start` does not know. The open must refuse the
/// `-wal` or the index must still answer consistently.
#[test]
fn a_wal_from_another_copy_of_the_index_never_yields_an_inconsistent_index() {
    let live_dir = private_tempdir();
    let live = live_dir.path().join("index.db");
    let mut idx = Index::open(&live).unwrap();
    idx.insert(&rec("cam1", BASE, 1000, 10), Tier::Hot).unwrap();
    drop(idx);
    let backup = std::fs::read(&live).unwrap();
    let c = rusqlite::Connection::open(&live).unwrap();
    c.execute_batch(
        "INSERT INTO segments (camera_id, started_at_ms, duration_ms, ended_at_ms, bytes, \
         frame_count, tier) VALUES ('cam2', 1700000100000, 1000, 1700000101000, 5, 1, 0);",
    )
    .unwrap();
    let new_id = c.last_insert_rowid();
    // Keep every b-tree's entry count equal to the backup's: quick_check compares counts only.
    c.execute_batch("DELETE FROM segments WHERE camera_id = 'cam1'")
        .unwrap();
    c.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()))
        .unwrap();
    c.execute("UPDATE segments SET tier = 1 WHERE id = ?1", [new_id])
        .unwrap();
    let wal = std::fs::read(sidecar(&live, "-wal")).unwrap();
    assert_ne!(wal.len(), 0);
    drop(c);

    let dir = private_tempdir();
    let path = dir.path().join("index.db");
    std::fs::write(&path, &backup).unwrap();
    chmod(&path, 0o600);
    let w = sidecar(&path, "-wal");
    std::fs::write(&w, &wal).unwrap();
    chmod(&w, 0o600);

    // Observed: the replayed copy passes `quick_check` (entry counts agree) but
    // `integrity_check` reports "row .. missing from index segments_camera_start".
    let Ok(mut idx) = Index::open(&path) else {
        return; // refused: fine
    };
    let id = SegmentId::new(u64::try_from(new_id).unwrap());
    let got = idx.get(id).unwrap();
    let (from, to) = all_time();
    let listed = idx.list(&cam("cam2"), from, to, 10, None).unwrap().items;
    assert_eq!(
        got.is_some(),
        listed.iter().any(|s| s.id == id),
        "get() and list() disagree after the open accepted a -wal of another copy"
    );
    // And the unique (camera, start) key must still hold.
    if got.is_some() {
        let dup = idx.insert(&rec("cam2", 1_700_000_100_000, 1000, 5), Tier::Hot);
        assert!(
            matches!(dup, Err(IndexError::Duplicate)),
            "second row with the same camera and start accepted: {dup:?}"
        );
    }
}

/// A `-wal` of SQLite's own making whose header is not complete (a crash while the first
/// frame's header was written leaves a short or zero-filled file) is an empty WAL to SQLite.
/// It is not foreign; refusing it with "frames not yet checkpointed are lost" sends the owner
/// to delete a file of their own index.
#[test]
fn a_short_or_zeroed_wal_of_an_own_index_is_not_called_foreign() {
    for wal in [vec![0u8; 8], vec![0u8; 32], vec![0u8; 4096 + 24 + 32]] {
        let dir = private_tempdir();
        let path = dir.path().join("index.db");
        let mut idx = Index::open(&path).unwrap();
        idx.insert(&rec("cam1", BASE, 1000, 10), Tier::Hot).unwrap();
        drop(idx);
        let w = sidecar(&path, "-wal");
        std::fs::write(&w, &wal).unwrap();
        chmod(&w, 0o600);
        let res = Index::open(&path);
        assert!(
            !matches!(res, Err(IndexError::ForeignWal)),
            "own index with an empty-to-SQLite -wal of {} zero bytes refused as foreign",
            wal.len()
        );
    }
}

// ---------------------------------------------------------------------------------------------
// Open: identity
// ---------------------------------------------------------------------------------------------

/// The identity check compares `(type, name)` of every schema object, not its SQL. A database
/// with our `application_id`, version 1 and objects of the right names but another definition
/// (here the unique index is not unique) is adopted, and the `Duplicate` guarantee of the port is
/// gone.
#[test]
fn a_database_with_the_right_names_but_another_schema_is_refused() {
    let dir = private_tempdir();
    let path = dir.path().join("index.db");
    {
        let c = rusqlite::Connection::open(&path).unwrap();
        c.execute_batch(
            "PRAGMA application_id = 1464617304; PRAGMA journal_mode = WAL;
             CREATE TABLE segments (
               id INTEGER PRIMARY KEY AUTOINCREMENT, camera_id TEXT NOT NULL,
               started_at_ms INTEGER NOT NULL, duration_ms INTEGER NOT NULL,
               ended_at_ms INTEGER NOT NULL, bytes INTEGER NOT NULL,
               frame_count INTEGER NOT NULL, tier INTEGER NOT NULL);
             CREATE INDEX segments_camera_start ON segments (camera_id, started_at_ms);
             CREATE INDEX segments_tier_end ON segments (tier, ended_at_ms, id, bytes);
             PRAGMA user_version = 1;",
        )
        .unwrap();
    }
    chmod(&path, 0o600);
    let before = snapshot(dir.path());
    match Index::open(&path) {
        Err(_) => assert_eq!(before, snapshot(dir.path()), "refusal modified the files"),
        Ok(mut idx) => {
            idx.insert(&rec("cam1", BASE, 1000, 10), Tier::Hot).unwrap();
            let dup = idx.insert(&rec("cam1", BASE, 1000, 10), Tier::Hot);
            panic!("foreign schema adopted; duplicate insert gave {dup:?}");
        }
    }
}

/// A database with our application id and a trigger is refused (control: triggers are rows of
/// `sqlite_master`).
#[test]
fn a_trigger_in_an_index_is_refused_and_untouched() {
    let dir = private_tempdir();
    let path = dir.path().join("index.db");
    drop(Index::open(&path).unwrap());
    {
        let c = rusqlite::Connection::open(&path).unwrap();
        c.execute_batch(
            "CREATE TRIGGER t AFTER INSERT ON segments BEGIN DELETE FROM segments; END;",
        )
        .unwrap();
    }
    let before = snapshot(dir.path());
    let err = Index::open(&path).unwrap_err();
    assert!(matches!(err, IndexError::UnexpectedSchema), "{err:?}");
    assert_eq!(before, snapshot(dir.path()));
}

/// A relative path whose text is a SQLite URI must open the file that was checked, not what the
/// URI names. (The read-write open passes the path to SQLite without `SQLITE_OPEN_URI`; if the
/// library build enables URIs globally the two differ.)
#[test]
fn a_path_that_looks_like_a_uri_opens_the_checked_file() {
    let dir = private_tempdir();
    let path = dir.path().join("file:idx.db");
    let mut idx = Index::open(&path).unwrap();
    idx.insert(&rec("cam1", BASE, 1000, 10), Tier::Hot).unwrap();
    drop(idx);
    let idx = Index::open(&path).unwrap();
    let (from, to) = all_time();
    assert_eq!(
        idx.list(&cam("cam1"), from, to, 10, None)
            .unwrap()
            .items
            .len(),
        1
    );
}

// ---------------------------------------------------------------------------------------------
// Rows and aggregates
// ---------------------------------------------------------------------------------------------

/// Stored values that make `SUM(bytes)` overflow give a typed error, never a panic.
#[test]
fn bytes_by_tier_overflow_on_tampered_rows_is_a_typed_error() {
    let dir = private_tempdir();
    let path = dir.path().join("index.db");
    let mut idx = Index::open(&path).unwrap();
    idx.insert(&rec("cam1", BASE, 1000, 10), Tier::Hot).unwrap();
    idx.insert(&rec("cam1", BASE + 2000, 1000, 10), Tier::Hot)
        .unwrap();
    {
        let c = rusqlite::Connection::open(&path).unwrap();
        c.execute("UPDATE segments SET bytes = ?1", [i64::MAX - 1])
            .unwrap();
    }
    let res = idx.bytes_by_tier();
    assert!(res.is_err(), "{res:?}");
    let msg = res.unwrap_err().to_string();
    assert!(!msg.contains('/') && !msg.contains("index.db"), "{msg}");
}

/// The cursor of one range, used with another range of the same camera, never returns rows
/// outside the second range.
#[test]
fn a_cursor_reused_with_another_range_stays_inside_that_range() {
    let dir = private_tempdir();
    let mut idx = Index::open(&dir.path().join("index.db")).unwrap();
    for i in 0..20 {
        idx.insert(&rec("cam1", BASE + i * 10_000, 1000, 10), Tier::Hot)
            .unwrap();
    }
    let (from, to) = all_time();
    let page = idx.list(&cam("cam1"), from, to, 2, None).unwrap();
    let cur = page.next.unwrap();
    let f2 = Timestamp::from_unix_millis(BASE + 100_000);
    let t2 = Timestamp::from_unix_millis(BASE + 150_000);
    let p2 = idx.list(&cam("cam1"), f2, t2, 100, Some(&cur)).unwrap();
    for s in &p2.items {
        let st = s.record.started_at_ms.as_i64();
        assert!(st < BASE + 150_000 && st + 1000 > BASE + 100_000, "{st}");
    }
    assert_eq!(p2.items.len(), 5);
}
