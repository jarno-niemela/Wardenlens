//! Adversarial tests for #225 (PR #231): the per-camera Basic authentication opt-in in the
//! registry (migration 4). Synthetic data only.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    reason = "adversary tests: a failed setup step is a test failure"
)]

use std::num::NonZeroU16;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use rusqlite::Connection;
use wardenlens_core::camera::{Camera, CameraId, DisplayName, Host, ModelRef, RtspPath, StreamSet};
use wardenlens_core::time::UnixMs;
use wardenlens_index::{CameraRecord, Index, IndexError};

const T0: i64 = 1_700_000_000_000;

struct Fx {
    _dir: tempfile::TempDir,
    path: PathBuf,
}

fn fixture() -> Fx {
    let d = tempfile::tempdir().unwrap();
    std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let path = d.path().join("index.db");
    Fx { _dir: d, path }
}

fn cam(s: &str) -> CameraId {
    CameraId::new(s).unwrap()
}

fn at(ms: i64) -> UnixMs {
    UnixMs::new(ms).unwrap()
}

fn record(id: &str) -> CameraRecord {
    CameraRecord::new(
        cam(id),
        ModelRef::new("acme", "c1").unwrap(),
        NonZeroU16::new(554).unwrap(),
        StreamSet::new(RtspPath::new("/main").unwrap(), None),
    )
}

fn flags(idx: &Index) -> Vec<(String, bool)> {
    idx.list_cameras(&[])
        .unwrap()
        .iter()
        .map(|s| (s.record().id().to_string(), s.record().allow_basic_auth()))
        .collect()
}

/// A version-3 index (the previous release: no `allow_basic_auth` column), with `rows` cameras.
fn v3_fixture(f: &Fx, rows: &[&str]) {
    drop(Index::open(&f.path).unwrap());
    let c = Connection::open(&f.path).unwrap();
    c.execute_batch("ALTER TABLE cameras DROP COLUMN allow_basic_auth; PRAGMA user_version = 3;")
        .unwrap();
    for id in rows {
        c.execute(
            "INSERT INTO cameras VALUES (?1, 'acme/c1', 554, '/main', NULL, ?2, ?2)",
            rusqlite::params![id, T0],
        )
        .unwrap();
    }
}

fn user_version(c: &Connection) -> i64 {
    c.query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap()
}

/// Every out-of-range integer a damaged file could hold is a typed error naming the column, on
/// the read-write and the read-only path; never read as "allowed".
#[test]
fn every_out_of_range_flag_is_corrupt_on_both_read_paths() {
    for bad in [2_i64, -1, 255, i64::MAX, i64::MIN] {
        let f = fixture();
        drop(Index::open(&f.path).unwrap());
        {
            let c = Connection::open(&f.path).unwrap();
            c.execute_batch("PRAGMA ignore_check_constraints = ON;")
                .unwrap();
            c.execute(
                "INSERT INTO cameras VALUES ('cam1', 'acme/c1', 554, '/main', NULL, ?1, ?1, ?2)",
                rusqlite::params![T0, bad],
            )
            .unwrap();
        }
        let idx = Index::open(&f.path).unwrap();
        for e in [
            idx.list_cameras(&[]).unwrap_err(),
            idx.get_camera(&cam("cam1"), &[]).unwrap_err(),
        ] {
            assert!(
                matches!(
                    e,
                    IndexError::CorruptCameraRow {
                        field: "allow_basic_auth"
                    }
                ),
                "{bad}: {e:?}"
            );
        }
        drop(idx);
        let ro = Index::open_read_only(&f.path).unwrap();
        assert!(
            matches!(
                ro.list_cameras(&[]).unwrap_err(),
                IndexError::CorruptCameraRow {
                    field: "allow_basic_auth"
                }
            ),
            "{bad}"
        );
    }
}

/// The STRICT table refuses a non-integer flag outright, even with CHECKs ignored, so the reader
/// never meets text or a real.
#[test]
fn the_strict_table_refuses_a_non_integer_flag_even_with_checks_ignored() {
    let f = fixture();
    drop(Index::open(&f.path).unwrap());
    let c = Connection::open(&f.path).unwrap();
    c.execute_batch("PRAGMA ignore_check_constraints = ON;")
        .unwrap();
    for bad in ["'yes'", "1.5", "x'01'", "NULL"] {
        let r = c.execute_batch(&format!(
            "INSERT INTO cameras VALUES ('cam1', 'acme/c1', 554, '/main', NULL, {T0}, {T0}, {bad})"
        ));
        assert!(r.is_err(), "{bad} was stored");
    }
}

/// The read-only open of a version-3 index that is live (a writer holds frames in the `-wal`)
/// reports `NeedsMigration` and does not write; the read-write open then migrates it.
#[test]
fn a_live_wal_version_3_index_is_needs_migration_read_only_then_migrates() {
    let f = fixture();
    v3_fixture(&f, &[]);
    let w = Connection::open(&f.path).unwrap();
    w.execute_batch("PRAGMA journal_mode = WAL; PRAGMA wal_autocheckpoint = 0;")
        .unwrap();
    w.execute(
        "INSERT INTO cameras VALUES ('live1', 'acme/c1', 554, '/main', NULL, ?1, ?1)",
        [T0],
    )
    .unwrap();
    let wal = f.path.with_extension("db-wal");
    assert!(
        std::fs::metadata(&wal).unwrap().len() > 0,
        "frames in the wal"
    );
    let main_before = std::fs::read(&f.path).unwrap();
    assert!(matches!(
        Index::open_read_only(&f.path).err(),
        Some(IndexError::NeedsMigration)
    ));
    assert_eq!(std::fs::read(&f.path).unwrap(), main_before);
    assert_eq!(user_version(&w), 3);
    let idx = Index::open(&f.path).unwrap();
    assert_eq!(flags(&idx), [("live1".to_owned(), false)]);
    assert_eq!(user_version(&w), 4);
}

/// A reader holding a snapshot of the version-3 schema does not block migration 4, keeps reading
/// its old snapshot, and sees the new column after its transaction ends.
#[test]
fn a_concurrent_reader_does_not_block_migration_and_sees_the_column_afterwards() {
    let f = fixture();
    v3_fixture(&f, &["old1"]);
    {
        let c = Connection::open(&f.path).unwrap();
        c.execute_batch("PRAGMA journal_mode = WAL;").unwrap();
    }
    let r = Connection::open(&f.path).unwrap();
    r.execute_batch("BEGIN").unwrap();
    let n: i64 = r
        .query_row("SELECT count(*) FROM cameras", [], |x| x.get(0))
        .unwrap();
    assert_eq!(n, 1);
    let mut idx = Index::open(&f.path).unwrap();
    // Still the old snapshot inside the open transaction.
    assert_eq!(user_version(&r), 3);
    r.execute_batch("COMMIT").unwrap();
    assert_eq!(user_version(&r), 4);
    let v: i64 = r
        .query_row(
            "SELECT allow_basic_auth FROM cameras WHERE id = 'old1'",
            [],
            |x| x.get(0),
        )
        .unwrap();
    assert_eq!(v, 0);
    assert!(
        idx.set_camera_basic_auth(&cam("old1"), true, at(T0 + 1))
            .unwrap()
    );
    let v: i64 = r
        .query_row(
            "SELECT allow_basic_auth FROM cameras WHERE id = 'old1'",
            [],
            |x| x.get(0),
        )
        .unwrap();
    assert_eq!(v, 1);
}

/// A version-3 index that someone already gave an `allow_basic_auth` column (for example set to
/// 1) fails migration 4 and stays at version 3: the hand-made value is never adopted.
#[test]
fn a_hand_added_column_fails_migration_4_and_is_not_adopted() {
    let f = fixture();
    v3_fixture(&f, &["cam1"]);
    {
        let c = Connection::open(&f.path).unwrap();
        c.execute_batch(
            "ALTER TABLE cameras ADD COLUMN allow_basic_auth INTEGER NOT NULL DEFAULT 1",
        )
        .unwrap();
    }
    let Err(e) = Index::open(&f.path) else {
        panic!("must not open")
    };
    assert!(
        matches!(
            e,
            IndexError::Migration { version: 4, .. } | IndexError::UnexpectedSchema
        ),
        "{e:?}"
    );
    assert_eq!(user_version(&Connection::open(&f.path).unwrap()), 3);
}

/// Migration 4 sets every existing row off, however many there are.
#[test]
fn migration_4_turns_every_existing_row_off() {
    let f = fixture();
    let ids: Vec<String> = (0..50).map(|n| format!("c{n:02}")).collect();
    let refs: Vec<&str> = ids.iter().map(String::as_str).collect();
    v3_fixture(&f, &refs);
    let idx = Index::open(&f.path).unwrap();
    let got = flags(&idx);
    assert_eq!(got.len(), 50);
    assert!(got.iter().all(|(_, b)| !b));
}

/// `set_camera_basic_auth` touches exactly one row: the other cameras' flags and `updated_at`
/// stay as they were.
#[test]
fn set_touches_only_the_named_row() {
    let f = fixture();
    let mut idx = Index::open(&f.path).unwrap();
    for id in ["a", "b", "c"] {
        idx.insert_camera(&record(id), &[], at(T0)).unwrap();
    }
    idx.insert_camera(&record("d").with_allow_basic_auth(true), &[], at(T0))
        .unwrap();
    assert!(
        idx.set_camera_basic_auth(&cam("b"), true, at(T0 + 9))
            .unwrap()
    );
    assert!(
        !idx.set_camera_basic_auth(&cam("zz"), false, at(T0 + 9))
            .unwrap()
    );
    assert_eq!(
        flags(&idx),
        [
            ("a".to_owned(), false),
            ("b".to_owned(), true),
            ("c".to_owned(), false),
            ("d".to_owned(), true)
        ]
    );
    for s in idx.list_cameras(&[]).unwrap() {
        let want = if s.record().id().as_str() == "b" {
            T0 + 9
        } else {
            T0
        };
        assert_eq!(s.updated_at(), at(want), "{}", s.record().id());
    }
}

/// A clock that went backwards (`now` before `created_at`) must not leave a row that no longer
/// reads back.
#[test]
fn set_with_a_clock_before_created_at_keeps_the_row_readable() {
    let f = fixture();
    let mut idx = Index::open(&f.path).unwrap();
    idx.insert_camera(&record("a"), &[], at(T0)).unwrap();
    let _ = idx.set_camera_basic_auth(&cam("a"), true, at(T0 - 86_400_000));
    idx.get_camera(&cam("a"), &[]).unwrap().unwrap();
    idx.list_cameras(&[]).unwrap();
    drop(idx);
    Index::open_read_only(&f.path)
        .unwrap()
        .list_cameras(&[])
        .unwrap();
}

/// Setting the flag on a removed camera never re-creates it, and repeating a set is idempotent.
#[test]
fn set_after_remove_is_false_and_repeat_is_idempotent() {
    let f = fixture();
    let mut idx = Index::open(&f.path).unwrap();
    idx.insert_camera(&record("a"), &[], at(T0)).unwrap();
    for _ in 0..3 {
        assert!(
            idx.set_camera_basic_auth(&cam("a"), true, at(T0 + 1))
                .unwrap()
        );
    }
    assert_eq!(flags(&idx), [("a".to_owned(), true)]);
    assert!(idx.remove_camera(&cam("a")).unwrap());
    assert!(
        !idx.set_camera_basic_auth(&cam("a"), true, at(T0 + 2))
            .unwrap()
    );
    assert_eq!(idx.list_cameras(&[]).unwrap().len(), 0);
    // Re-registered with the default, the old opt-in does not come back.
    idx.insert_camera(&record("a"), &[], at(T0 + 3)).unwrap();
    assert_eq!(flags(&idx), [("a".to_owned(), false)]);
}

/// `from_camera` carries the flag both ways, and a core camera built with `new` is off.
#[test]
fn from_camera_carries_the_flag() {
    let base = Camera::new(
        cam("a"),
        DisplayName::new("A").unwrap(),
        ModelRef::new("acme", "c1").unwrap(),
        Host::new("192.0.2.1").unwrap(),
        NonZeroU16::new(554).unwrap(),
        StreamSet::new(RtspPath::new("/main").unwrap(), None),
    );
    assert!(!CameraRecord::from_camera(&base).allow_basic_auth());
    assert!(
        CameraRecord::from_camera(&base.clone().with_allow_basic_auth(true)).allow_basic_auth()
    );
}
