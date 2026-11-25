//! Adversarial tests for #49 (PR #140): the SQLite segment index.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "adversary tests: a failed setup step is a test failure"
)]

use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use wardenlens_core::camera::CameraId;
use wardenlens_core::recording::SegmentRecord;
use wardenlens_core::storage::{SegmentIndex, Tier};
use wardenlens_core::time::{Timestamp, UnixMs};
use wardenlens_index::{Index, IndexError};

const BASE: i64 = 1_700_000_000_000;

/// A temporary directory nobody else can write: tempfile follows the umask, and the index
/// refuses a group-writable parent (fixture only: the tests do not depend on the runner's umask).
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

fn new_index(dir: &Path) -> PathBuf {
    let path = dir.join("index.db");
    let mut idx = Index::open(&path).unwrap();
    idx.insert(&rec("cam1", BASE, 1000, 10), Tier::Hot).unwrap();
    drop(idx);
    path
}

/// A `-journal` next to a WAL-mode index is not SQLite's (WAL never writes one). The open must
/// not delete or replay it: either refuse it, or leave it byte-identical.
#[test]
fn a_stray_journal_next_to_a_wal_index_is_not_deleted() {
    let dir = private_tempdir();
    let path = new_index(dir.path());
    let j = sidecar(&path, "-journal");
    std::fs::write(&j, [0xd9u8; 512]).unwrap();
    chmod(&j, 0o600);
    let before = std::fs::read(&j).unwrap();
    let res = Index::open(&path);
    let after = std::fs::read(&j).ok();
    assert_eq!(
        after.as_deref(),
        Some(before.as_slice()),
        "stray -journal was modified or deleted by open (result {:?})",
        res.as_ref().map(|_| ())
    );
}

/// Builds a real hot rollback journal of a foreign database `other` (same page size).
fn hot_journal_of_foreign_db(dir: &Path) -> Vec<u8> {
    let other = dir.join("foreign.db");
    let c = rusqlite::Connection::open(&other).unwrap();
    c.execute_batch(
        "PRAGMA journal_mode = DELETE; PRAGMA page_size = 4096; \
         CREATE TABLE t(x BLOB); ",
    )
    .unwrap();
    for _ in 0..50 {
        c.execute("INSERT INTO t VALUES (zeroblob(3000))", [])
            .unwrap();
    }
    c.execute_batch("PRAGMA cache_size = 2; BEGIN; UPDATE t SET x = zeroblob(3001);")
        .unwrap();
    // The cache spill has synced the journal header and written original pages.
    let journal = std::fs::read(sidecar(&other, "-journal")).unwrap();
    c.execute_batch("ROLLBACK").unwrap();
    drop(c);
    journal
}

/// A hot journal planted next to a WAL index must never be rolled back into it: it would
/// overwrite index pages with foreign pages.
#[test]
fn a_foreign_hot_journal_next_to_a_wal_index_is_never_replayed() {
    let dir = private_tempdir();
    let path = new_index(dir.path());
    let journal = hot_journal_of_foreign_db(dir.path());
    assert!(journal.len() > 4096, "journal was not written");
    let main_before = std::fs::read(&path).unwrap();
    let j = sidecar(&path, "-journal");
    std::fs::write(&j, &journal).unwrap();
    chmod(&j, 0o600);
    let res = Index::open(&path).map(|idx| idx.bytes_by_tier().map(|_| ()));
    let main_after = std::fs::read(&path).unwrap();
    // Observed: open succeeds, the main file grows from 5 to 52 pages of foreign content,
    // and every later full read reports `DatabaseCorrupt`.
    assert_eq!(
        main_before.len(),
        main_after.len(),
        "foreign journal rolled back into the index (open result {res:?})"
    );
    assert_eq!(
        std::fs::read(&j).ok().as_deref(),
        Some(journal.as_slice()),
        "foreign journal consumed"
    );
}

/// A file of a newer build with a leftover `-wal` (a crash) must stay byte-identical, sidecars
/// included: refusing must not checkpoint it.
#[test]
fn a_newer_index_with_a_leftover_wal_is_left_byte_identical() {
    let dir = private_tempdir();
    let path = new_index(dir.path());
    // Make it "newer" and leave a -wal behind as a crash would: copy the files while a
    // connection holds the WAL open.
    let crash = private_tempdir();
    let c = rusqlite::Connection::open(&path).unwrap();
    c.execute_batch("PRAGMA user_version = 99; CREATE TABLE future(x);")
        .unwrap();
    for s in ["", "-wal"] {
        let from = sidecar(&path, s);
        let to = sidecar(&crash.path().join("index.db"), s);
        std::fs::copy(&from, &to).unwrap();
        chmod(&to, 0o600);
    }
    drop(c);
    let crashed = crash.path().join("index.db");
    assert!(sidecar(&crashed, "-wal").exists());
    let before = snapshot(crash.path());
    let err = Index::open(&crashed).unwrap_err();
    assert!(
        matches!(err, IndexError::SchemaTooNew { found: 99, .. }),
        "{err:?}"
    );
    assert_eq!(before, snapshot(crash.path()), "newer file was modified");
}

/// The vault refuses a group- or world-writable parent (another user could plant a `-wal` that
/// SQLite then replays). The index opens one without complaint.
#[test]
fn an_index_in_a_world_writable_directory_is_refused() {
    let dir = private_tempdir();
    let shared = dir.path().join("shared");
    std::fs::create_dir(&shared).unwrap();
    chmod(&shared, 0o777);
    let res = Index::open(&shared.join("index.db"));
    assert!(res.is_err(), "index opened in a 0777 directory");
}

/// SQLite creates `-wal` with the main file's mode (0600). A world-writable `-wal` was planted
/// by someone else; its frames must not be replayed into the index.
#[test]
fn a_planted_world_writable_wal_is_not_replayed() {
    let dir = private_tempdir();
    let path = new_index(dir.path());
    // Forge a -wal: a byte copy of our index, written through SQLite, WAL captured mid-life.
    let forge_dir = private_tempdir();
    let forge = forge_dir.path().join("index.db");
    std::fs::copy(&path, &forge).unwrap();
    let c = rusqlite::Connection::open(&forge).unwrap();
    c.execute_batch(
        "INSERT INTO segments (camera_id, started_at_ms, duration_ms, ended_at_ms, bytes, \
         frame_count, tier) VALUES ('evil', 1700000000000, 1000, 1700000001000, 1, 1, 0);",
    )
    .unwrap();
    let wal = std::fs::read(sidecar(&forge, "-wal")).unwrap();
    drop(c);
    let w = sidecar(&path, "-wal");
    std::fs::write(&w, &wal).unwrap();
    chmod(&w, 0o666);
    let res = Index::open(&path);
    if let Ok(idx) = res {
        let page = idx
            .list(
                &cam("evil"),
                Timestamp::from_unix_millis(0),
                Timestamp::from_unix_millis(i64::MAX),
                10,
                None,
            )
            .unwrap();
        assert!(
            page.items.is_empty(),
            "planted world-writable -wal was replayed: {} rows injected",
            page.items.len()
        );
    }
}

/// Two segments the insert accepts must not make `bytes_by_tier` fail for ever after.
#[test]
fn accepted_inserts_never_make_bytes_by_tier_fail() {
    let dir = private_tempdir();
    let mut idx = Index::open(&dir.path().join("index.db")).unwrap();
    let big = u64::try_from(i64::MAX).unwrap();
    let a = idx.insert(&rec("cam1", BASE, 1000, big), Tier::Hot);
    let b = idx.insert(&rec("cam1", BASE + 1000, 1000, big), Tier::Hot);
    if a.is_ok() && b.is_ok() {
        let totals = idx.bytes_by_tier();
        assert!(
            totals.is_ok(),
            "insert accepted both rows, bytes_by_tier then fails: {totals:?}"
        );
    }
}

/// A stored `started_at_ms` of the wrong storage class (file edited outside SQLite, STRICT
/// removed) is a `CorruptRow`, like every other bad stored value.
#[test]
fn latest_started_at_with_a_text_start_is_a_corrupt_row() {
    let dir = private_tempdir();
    let path = new_index(dir.path());
    let idx = Index::open(&path).unwrap();
    {
        let c = rusqlite::Connection::open(&path).unwrap();
        let sql: String = c
            .query_row(
                "SELECT sql FROM sqlite_master WHERE name = 'segments'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        let loose = sql.replace(") STRICT", ")");
        assert_ne!(loose, sql);
        c.execute_batch("PRAGMA writable_schema = ON").unwrap();
        c.execute(
            "UPDATE sqlite_master SET sql = ?1 WHERE name = 'segments'",
            [loose],
        )
        .unwrap();
        c.execute_batch("PRAGMA writable_schema = OFF").unwrap();
    }
    {
        let c = rusqlite::Connection::open(&path).unwrap();
        c.execute_batch(
            "PRAGMA ignore_check_constraints = ON; \
             INSERT INTO segments (camera_id, started_at_ms, duration_ms, ended_at_ms, bytes, \
             frame_count, tier) VALUES ('cam1', 'x', 1000, 1000, 5, 1, 0);",
        )
        .unwrap();
    }
    let err = idx.latest_started_at(&cam("cam1")).unwrap_err();
    assert!(
        matches!(
            err,
            IndexError::CorruptRow {
                field: "started_at_ms",
                ..
            }
        ),
        "{err:?}"
    );
}
