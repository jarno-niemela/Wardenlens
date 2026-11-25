//! The read wrappers of `sql.rs` (SEC-10): no statement that can write, end a transaction or
//! change the connection runs through `prepare` or `query_row`, so no write skips `write_tx` and
//! its generation bump. In the crate the wrappers take a `ReadSql` token that only `sql.rs` can
//! make; these tests build the token from a literal (a test-only conversion) to prove the
//! run-time checks behind it, and check every real token.

use rusqlite::Connection;

use crate::error::IndexError;
use crate::sql::{self, ReadSql};
use crate::tests::open_new;

/// Every data-writing or state-changing statement, including the ones SQLite itself reports as
/// read-only (`BEGIN`, `COMMIT`, `END`, `ROLLBACK`, `SAVEPOINT`, `RELEASE`, `ATTACH`, `DETACH`,
/// `PRAGMA optimize` and setter pragmas), which the run-time check refuses because they return
/// no column. (`PRAGMA locking_mode = ...` and `synchronous = ...` return a column and are
/// read-only to SQLite: only the `ReadSql` token keeps them out, see
/// `the_token_list_has_no_setter_transaction_or_attach_statement`.)
const WRITES: &[&str] = &[
    sql::INSERT,
    sql::SET_TIER,
    sql::DELETE,
    sql::BUMP_GENERATION,
    sql::SET_WAL,
    "UPDATE segments SET tier = 1 WHERE id = 1 RETURNING id",
    "DELETE FROM segments RETURNING id",
    "INSERT INTO index_meta (id) VALUES (2) RETURNING id",
    "CREATE TABLE evil (a)",
    "DROP TABLE segments",
    "PRAGMA user_version = 9",
    "PRAGMA application_id = 1",
    "PRAGMA writable_schema = 1",
    "VACUUM",
    "BEGIN",
    "BEGIN IMMEDIATE",
    "COMMIT",
    "END",
    "ROLLBACK",
    "SAVEPOINT s",
    "RELEASE s",
    "ATTACH DATABASE ':memory:' AS x",
    "DETACH DATABASE x",
];

/// Statements SQLite calls read-only that return a column, so no run-time check refuses them:
/// only the `ReadSql` token (a pass-list) keeps them out of the read wrappers. None is a token.
const TOKEN_ONLY: &[&str] = &[
    "PRAGMA optimize",
    "PRAGMA locking_mode = EXCLUSIVE",
    "PRAGMA synchronous = OFF",
    "PRAGMA foreign_keys = OFF",
    "PRAGMA main.locking_mode = EXCLUSIVE",
];

/// Every read token of the crate, listed by hand; `every_read_token_is_listed` checks the list
/// against the source.
fn tokens() -> Vec<ReadSql> {
    vec![
        sql::GET,
        sql::LIST,
        sql::TIER_OF,
        sql::OLDEST,
        sql::BYTES_BY_TIER,
        sql::LATEST_START,
        sql::GET_APP_ID,
        sql::USER_VERSION,
        sql::OBJECT_COUNT,
        sql::INSTANCE_ID,
        sql::GET_SYNC,
        sql::GET_FK,
        sql::GET_JOURNAL_LIMIT,
        sql::GET_BUSY,
        sql::SCHEMA_ROWS,
        sql::INTEGRITY_CHECK,
    ]
}

#[test]
fn prepare_refuses_every_write_statement() {
    let (_f, idx) = open_new();
    for w in WRITES {
        match sql::prepare(&idx.conn, *w) {
            Err(rusqlite::Error::InvalidQuery) => {}
            Err(e) => panic!("{w}: unexpected error {e}"),
            Ok(_) => panic!("{w}: prepare accepted a statement that is not a read"),
        }
    }
}

#[test]
fn query_row_refuses_every_write_statement_and_changes_nothing() {
    let (_f, idx) = open_new();
    let generation = |c: &Connection| -> i64 {
        c.query_row("SELECT generation FROM index_meta", [], |r| r.get(0))
            .unwrap()
    };
    let before = generation(&idx.conn);
    for w in WRITES {
        // `[]` and a parameter slice are both `Params`; the refusal comes before binding.
        let none = sql::query_row(&idx.conn, *w, [], |r| r.get::<_, i64>(0));
        assert!(
            matches!(none, Err(rusqlite::Error::InvalidQuery)),
            "{w}: {none:?}"
        );
        let some = sql::query_row(&idx.conn, *w, [1_i64], |r| r.get::<_, i64>(0));
        assert!(
            matches!(some, Err(rusqlite::Error::InvalidQuery)),
            "{w} with a parameter: {some:?}"
        );
    }
    assert_eq!(generation(&idx.conn), before);
}

#[test]
fn the_refusal_is_the_typed_not_read_only_error() {
    let (_f, idx) = open_new();
    let e = sql::prepare(&idx.conn, sql::DELETE)
        .map(|_| ())
        .map_err(IndexError::sqlite("probe"))
        .unwrap_err();
    assert!(
        matches!(e, IndexError::NotReadOnly { op: "probe" }),
        "{e:?}"
    );
    assert!(!e.to_string().contains("DELETE"), "{e}");
    assert!(!e.is_transient());
}

#[test]
fn every_read_token_prepares_and_runs_through_both_wrappers() {
    let (_f, idx) = open_new();
    for t in tokens() {
        let text = t.text();
        let stmt = sql::prepare(&idx.conn, t).unwrap_or_else(|e| panic!("{text}: {e}"));
        assert!(stmt.readonly() && stmt.column_count() > 0, "{text}");
        drop(stmt);
        // Only the statements without parameters can run here; the others are run by ops.
        if !text.contains('?') {
            let r = sql::query_row(&idx.conn, t, [], |r| r.get::<_, rusqlite::types::Value>(0));
            match r {
                Ok(_) | Err(rusqlite::Error::QueryReturnedNoRows) => {}
                Err(e) => panic!("{text}: {e}"),
            }
        }
    }
}

/// The pass-list is reviewed text, not a shape check: none of its statements is transaction
/// control, `ATTACH`/`DETACH`, a setter pragma (`=` or a call form) or anything but a `SELECT`
/// or a getter pragma, and each is read-only and returns a column.
#[test]
fn the_token_list_has_no_setter_transaction_or_attach_statement() {
    let (_f, idx) = open_new();
    for t in tokens() {
        let text = t.text();
        let upper = text.trim_start().to_ascii_uppercase();
        let ok_start = upper.starts_with("SELECT ")
            || upper.starts_with("WITH ")
            || (upper.starts_with("PRAGMA ") && !upper.contains('=') && !upper.contains('('));
        // `PRAGMA integrity_check(1)` is the one call form: a check, not a setter.
        let integrity = text == sql::INTEGRITY_CHECK.text();
        assert!(ok_start || integrity, "{text}");
        assert!(!TOKEN_ONLY.contains(&text), "{text}");
        let words: Vec<&str> = upper
            .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
            .collect();
        for bad in [
            "BEGIN",
            "COMMIT",
            "END",
            "ROLLBACK",
            "SAVEPOINT",
            "RELEASE",
            "ATTACH",
            "DETACH",
            "OPTIMIZE",
            "WRITABLE_SCHEMA",
            "LOCKING_MODE",
        ] {
            assert!(!words.contains(&bad), "{text}: {bad}");
        }
        let stmt = idx.conn.prepare(text).unwrap();
        assert!(stmt.readonly(), "{text}");
        assert!(stmt.column_count() > 0, "{text}");
    }
}

/// The list in `tokens` is every `ReadSql` constant of `sql.rs`.
#[test]
fn every_read_token_is_listed() {
    let src = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/sql.rs")).unwrap();
    let declared = src.lines().filter(|l| l.contains(": ReadSql =")).count();
    assert_eq!(declared, tokens().len());
}

#[test]
fn the_unversioned_pragma_wrapper_still_sets_the_write_pragmas() {
    let conn = sql::Db::new(Connection::open_in_memory().unwrap());
    let mode: String = sql::query_row_unversioned(&conn, sql::SET_WAL, |r| r.get(0)).unwrap();
    assert_eq!(mode, "memory"); // an in-memory database cannot use WAL; the statement ran
}
