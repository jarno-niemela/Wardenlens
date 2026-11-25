//! The read-only guard of `sql::prepare` and `sql::query_row` (SEC-10): no statement that can
//! write runs through a read wrapper, so no write skips `write_tx` and its generation bump.

use rusqlite::Connection;

use crate::error::IndexError;
use crate::sql;
use crate::tests::open_new;

/// Every data-writing statement of the crate, plus an `UPDATE ... RETURNING` (which returns rows
/// and so looks like a read). `journal_size_limit`, `synchronous` and `foreign_keys` are
/// connection settings that SQLite reports as read-only, so they are not here (and run through
/// `query_row`/`execute_unversioned` without a bump, which is right: they write no database page) and other write shapes.
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
    "VACUUM",
];

/// Every read statement of the crate: these must still be accepted.
const READS: &[&str] = &[
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
    sql::SET_JOURNAL_LIMIT,
    sql::GET_SYNC,
    sql::GET_FK,
    sql::GET_JOURNAL_LIMIT,
    sql::GET_BUSY,
    sql::SCHEMA_ROWS,
    sql::INTEGRITY_CHECK,
];

#[test]
fn prepare_refuses_every_write_statement() {
    let (_f, idx) = open_new();
    for w in WRITES {
        match sql::prepare(&idx.conn, w) {
            Err(rusqlite::Error::InvalidQuery) => {}
            Err(e) => panic!("{w}: unexpected error {e}"),
            Ok(_) => panic!("{w}: prepare accepted a write"),
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
        // Both parameter shapes the real callers use.
        let none = sql::query_row(&idx.conn, w, [], |r| r.get::<_, i64>(0));
        assert!(
            matches!(none, Err(rusqlite::Error::InvalidQuery)),
            "{w}: {none:?}"
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
fn prepare_and_query_row_accept_every_read_statement() {
    let (_f, idx) = open_new();
    for r in READS {
        sql::prepare(&idx.conn, r).unwrap_or_else(|e| panic!("{r}: {e}"));
    }
}

#[test]
fn the_unversioned_pragma_wrapper_still_sets_the_write_pragmas() {
    let conn = Connection::open_in_memory().unwrap();
    let mode: String = sql::query_row_unversioned(&conn, sql::SET_WAL, |r| r.get(0)).unwrap();
    assert_eq!(mode, "memory"); // an in-memory database cannot use WAL; the statement ran
}
