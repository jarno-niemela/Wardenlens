//! Adversary (#149 round 2): the autocommit check against SQLite's own automatic rollbacks.

use rusqlite::ErrorCode;
use wardenlens_core::storage::SegmentIndex;
use wardenlens_core::storage::Tier;

use crate::error::IndexError;
use crate::sql;
use crate::tests::{BASE, open_new, rec};

/// SQLite rolls the whole transaction back itself on `SQLITE_FULL` when the statement has no
/// statement journal (a single-row `INSERT`). That is a disk-full write, which `is_transient`
/// classifies as transient; the autocommit check must not turn it into a permanent
/// `TransactionEnded` (the recorder would quarantine a good file instead of retrying).
#[test]
fn a_disk_full_insert_stays_a_transient_disk_full_error() {
    let (_f, mut idx) = open_new();
    let pages: i64 = idx
        .conn
        .query_row("PRAGMA page_count", [], |r| r.get(0))
        .unwrap();
    let _: i64 = idx
        .conn
        .query_row(&format!("PRAGMA max_page_count = {pages}"), [], |r| {
            r.get(0)
        })
        .unwrap();
    let mut err = None;
    for i in 0..10_000i64 {
        match idx.insert(&rec("cam", BASE + i * 10_000, 1000, 1, 1), Tier::Hot) {
            Ok(_) => {}
            Err(e) => {
                err = Some(e);
                break;
            }
        }
    }
    let e = err.expect("max_page_count never hit");
    assert!(
        matches!(
            e,
            IndexError::Sqlite {
                code: Some(ErrorCode::DiskFull),
                ..
            }
        ),
        "disk full surfaced as {e:?}"
    );
    assert!(e.is_transient(), "disk full is not transient: {e:?}");
}

/// The same through a migration-shaped `write_batch`: the cause (`DiskFull`) must survive.
#[test]
fn a_disk_full_write_batch_keeps_the_disk_full_code() {
    let (_f, mut idx) = open_new();
    let pages: i64 = idx
        .conn
        .query_row("PRAGMA page_count", [], |r| r.get(0))
        .unwrap();
    let _: i64 = idx
        .conn
        .query_row(&format!("PRAGMA max_page_count = {pages}"), [], |r| {
            r.get(0)
        })
        .unwrap();
    let r: Result<(), IndexError> = sql::write_tx(&mut idx.conn, "adv", |w| {
        w.write_batch(
            "CREATE TABLE adv_big (x BLOB); INSERT INTO adv_big VALUES (zeroblob(1000000));",
        )
        .map_err(IndexError::sqlite("adv"))
    });
    let e = r.unwrap_err();
    assert!(
        matches!(
            e,
            IndexError::Sqlite {
                code: Some(ErrorCode::DiskFull),
                ..
            }
        ),
        "disk full surfaced as {e:?}"
    );
}

/// An ordinary rusqlite `InvalidParameterName` (not the sentinel) is not mistaken for a refusal.
#[test]
fn a_real_invalid_parameter_name_is_not_a_sentinel() {
    let (_f, mut idx) = open_new();
    let r: Result<(), IndexError> = sql::write_tx(&mut idx.conn, "adv", |w| {
        w.write(
            "UPDATE index_meta SET generation = generation WHERE id = :id",
            rusqlite::named_params! { ":nope": 1 },
        )
        .map(|_| ())
        .map_err(IndexError::sqlite("adv"))
    });
    let e = r.unwrap_err();
    assert!(
        !matches!(
            e,
            IndexError::NotADataWrite { .. } | IndexError::TransactionEnded { .. }
        ),
        "{e:?}"
    );
}

/// The sentinel text never reaches the user-visible message.
#[test]
fn the_new_variants_do_not_show_the_sentinel_text() {
    for e in [
        IndexError::sqlite("op")(rusqlite::Error::InvalidParameterName(
            "wardenlens: not a data write".into(),
        )),
        IndexError::sqlite("op")(rusqlite::Error::InvalidParameterName(
            "wardenlens: transaction ended".into(),
        )),
    ] {
        let s = e.to_string();
        assert!(!s.contains("wardenlens:"), "{s}");
        assert!(!s.contains("parameter"), "{s}");
    }
}

fn gen_and_rows(c: &rusqlite::Connection) -> (i64, i64) {
    (
        c.query_row("SELECT generation FROM index_meta", [], |r| r.get(0))
            .unwrap(),
        c.query_row("SELECT count(*) FROM segments", [], |r| r.get(0))
            .unwrap(),
    )
}

/// A trigger's `RAISE(ROLLBACK)` in the middle of a batch: the statements after it never run
/// in autocommit, the closure that ignores the error cannot commit, and nothing is written.
#[test]
fn a_raise_rollback_mid_batch_commits_nothing_even_if_the_closure_ignores_it() {
    let (_f, mut idx) = open_new();
    let before = gen_and_rows(&idx.conn);
    let r: Result<(), IndexError> = sql::write_tx(&mut idx.conn, "adv", |w| {
        let e = w.write_batch(
            "CREATE TEMP TRIGGER adv_t BEFORE INSERT ON segments WHEN NEW.bytes = 7 \
             BEGIN SELECT RAISE(ROLLBACK, 'x'); END; \
             INSERT INTO segments (camera_id, started_at_ms, duration_ms, ended_at_ms, bytes, frame_count, tier) VALUES ('c', 1700000000000, 1000, 1700000001000, 1, 1, 0); \
             INSERT INTO segments (camera_id, started_at_ms, duration_ms, ended_at_ms, bytes, frame_count, tier) VALUES ('c', 1700000002000, 1000, 1700000003000, 7, 1, 0); \
             INSERT INTO segments (camera_id, started_at_ms, duration_ms, ended_at_ms, bytes, frame_count, tier) VALUES ('c', 1700000004000, 1000, 1700000005000, 1, 1, 0);",
        );
        assert!(sql::is_transaction_ended(e.as_ref().unwrap_err()), "{e:?}");
        let later = w.write(
            "INSERT INTO segments (camera_id, started_at_ms, duration_ms, ended_at_ms, bytes, frame_count, tier) VALUES ('c', 1700000009000, 1000, 1700000010000, 1, 1, 0)",
            [],
        );
        assert!(later.is_err());
        Ok(()) // ignore everything
    });
    assert!(
        matches!(r, Err(IndexError::TransactionEnded { .. })),
        "{r:?}"
    );
    assert_eq!(gen_and_rows(&idx.conn), before);
    // The connection is usable afterwards and the next write bumps once.
    idx.insert(&rec("cam", BASE, 1000, 1, 1), Tier::Hot)
        .unwrap();
    let after = gen_and_rows(&idx.conn);
    assert_eq!(after, (before.0 + 1, before.1 + 1));
}

/// `RETURNING` makes a write return rows; `write` must still run it once inside the
/// transaction (or refuse it), never commit it unbumped.
#[test]
fn insert_returning_through_write_is_never_unbumped() {
    let (_f, mut idx) = open_new();
    let before = gen_and_rows(&idx.conn);
    let _ = sql::write_tx(&mut idx.conn, "adv", |w| {
        w.write(
            "INSERT INTO segments (camera_id, started_at_ms, duration_ms, ended_at_ms, bytes, frame_count, tier) VALUES ('c', 1700000000000, 1000, 1700000001000, 1, 1, 0) RETURNING id",
            [],
        )
        .map(|_| ())
        .map_err(IndexError::sqlite("adv"))
    });
    let after = gen_and_rows(&idx.conn);
    assert!(
        after == before || after == (before.0 + 1, before.1 + 1),
        "{before:?} -> {after:?}"
    );
}
