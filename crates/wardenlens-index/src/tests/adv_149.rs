//! Adversary (#149 round 1): the write wrappers' transaction-control refusal.

use rusqlite::Connection;

use crate::error::IndexError;
use crate::sql;
use crate::tests::open_new;

fn generation(c: &Connection) -> i64 {
    c.query_row("SELECT generation FROM index_meta", [], |r| r.get(0))
        .unwrap()
}

fn count(c: &Connection) -> i64 {
    c.query_row("SELECT count(*) FROM segments", [], |r| r.get(0))
        .unwrap()
}

const INSERT_A: &str = "INSERT INTO segments (camera_id, started_at_ms, duration_ms, ended_at_ms, bytes, frame_count, tier) VALUES ('c', 1700000000000, 1000, 1700000001000, 1, 1, 0)";
const INSERT_A_OR_ROLLBACK: &str = "INSERT OR ROLLBACK INTO segments (camera_id, started_at_ms, duration_ms, ended_at_ms, bytes, frame_count, tier) VALUES ('c', 1700000000000, 1000, 1700000001000, 1, 1, 0)";
const INSERT_B: &str = "INSERT INTO segments (camera_id, started_at_ms, duration_ms, ended_at_ms, bytes, frame_count, tier) VALUES ('c', 1700000005000, 1000, 1700000006000, 1, 1, 0)";

fn w(w: &sql::WriteTx<'_>, s: &'static str) -> Result<(), IndexError> {
    w.write(s, [])
        .map(|_| ())
        .map_err(IndexError::sqlite("adv"))
}

/// Spelling variants of transaction control are refused like the bare keywords.
#[test]
fn the_write_wrappers_refuse_spelling_variants_of_transaction_control() {
    for stmt in [
        "/* c */ COMMIT",
        "-- c\nCOMMIT",
        "  \n\tCOMMIT  ",
        "COMMIT;",
        "COMMIT TRANSACTION",
        "END TRANSACTION",
        "ROLLBACK TRANSACTION",
        "commit",
        ";COMMIT",
        "; ;COMMIT",
    ] {
        let (_f, mut idx) = open_new();
        let gen_before = generation(&idx.conn);
        let r: Result<(), IndexError> = sql::write_tx(&mut idx.conn, "adv", |x| {
            w(x, INSERT_A)?;
            let _ = x.write(stmt, []);
            let _ = x.write_batch(stmt);
            Err(IndexError::Duplicate)
        });
        assert!(r.is_err());
        let rows = count(&idx.conn);
        assert!(
            rows == 0 || generation(&idx.conn) > gen_before,
            "{stmt:?}: a failed write_tx left {rows} committed row(s) with no generation bump"
        );
    }
}

/// `write` takes one statement: a script is refused, not silently truncated.
#[test]
fn write_refuses_a_multi_statement_string() {
    let (_f, mut idx) = open_new();
    let r = sql::write_tx(&mut idx.conn, "adv", |x| {
        w(x, "DELETE FROM segments; COMMIT")
    });
    assert!(r.is_err(), "{r:?}");
}

/// A parse error mid-script rolls back the statements before it.
#[test]
fn a_parse_error_mid_script_rolls_back_the_earlier_statements() {
    let (_f, mut idx) = open_new();
    let r = sql::write_tx(&mut idx.conn, "adv", |x| {
        x.write_batch("INSERT INTO segments (camera_id, started_at_ms, duration_ms, ended_at_ms, bytes, frame_count, tier) VALUES ('c', 1700000000000, 1000, 1700000001000, 1, 1, 0); NOT SQL;")
            .map_err(IndexError::sqlite("adv"))
    });
    assert!(r.is_err());
    assert_eq!(count(&idx.conn), 0);
    // an empty / comment-only tail is fine
    sql::write_tx(&mut idx.conn, "adv", |x| {
        x.write_batch("DELETE FROM segments; -- tail\n ; /* c */ ")
            .map_err(IndexError::sqlite("adv"))
    })
    .unwrap();
}

/// A conflict clause `OR ROLLBACK` ends the transaction as surely as `ROLLBACK` does, but it is
/// not read-only, so the `readonly()` check lets it through. Same shape as the carried
/// `the_write_wrappers_refuse_transaction_control`: after it, later writes run in autocommit and
/// land with no bump although `write_tx` fails.
#[test]
fn a_conflict_rollback_cannot_end_the_transaction_early() {
    let (_f, mut idx) = open_new();
    let gen_before = generation(&idx.conn);
    let r: Result<(), IndexError> = sql::write_tx(&mut idx.conn, "adv", |x| {
        w(x, INSERT_A)?;
        let _ = x.write(INSERT_A_OR_ROLLBACK, []);
        let _ = w(x, INSERT_B);
        Err(IndexError::Duplicate)
    });
    assert!(r.is_err());
    let rows = count(&idx.conn);
    assert!(
        rows == 0 || generation(&idx.conn) > gen_before,
        "a failed write_tx left {rows} committed row(s) with no generation bump"
    );
}

/// The same with a closure that returns Ok: `write_tx` must not report failure for a write that
/// was in fact committed (or must not commit it).
#[test]
fn a_conflict_rollback_does_not_commit_writes_behind_a_failed_write_tx() {
    let (_f, mut idx) = open_new();
    let r: Result<(), IndexError> = sql::write_tx(&mut idx.conn, "adv", |x| {
        w(x, INSERT_A)?;
        let _ = x.write(INSERT_A_OR_ROLLBACK, []);
        let _ = w(x, INSERT_B);
        Ok(())
    });
    let rows = count(&idx.conn);
    assert!(
        r.is_ok() || rows == 0,
        "write_tx returned {r:?} but {rows} row(s) were committed"
    );
}

/// The refusal error's message should describe the refusal (the write wrapper refuses a
/// statement that IS read-only).
#[test]
fn the_write_refusal_message_does_not_say_the_opposite() {
    let (_f, mut idx) = open_new();
    let r = sql::write_tx(&mut idx.conn, "probe", |x| w(x, "COMMIT"));
    let msg = r.unwrap_err().to_string();
    assert!(!msg.contains("not read-only"), "{msg}");
}
