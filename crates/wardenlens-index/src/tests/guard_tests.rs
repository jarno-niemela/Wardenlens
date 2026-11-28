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
        sql::NEWEST,
        sql::BYTES_BY_TIER,
        sql::LATEST_START,
        sql::GET_CAMERA,
        sql::LIST_CAMERAS,
        sql::CAMERA_EXISTS,
        sql::CAMERA_COUNT,
        sql::ORPHAN_CAMERAS,
        sql::TOKEN_EXISTS,
        sql::TOKEN_COUNT,
        sql::FIND_TOKEN,
        sql::LIST_TOKENS,
        sql::TOKEN_TOUCH_DUE,
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

/// The only pragmas a `ReadSql` may be: a bare getter named here, or the one call form
/// `integrity_check(1)`. An allow-list, so a pragma SQLite adds later (or one that acts when
/// read, like `wal_checkpoint`, `incremental_vacuum`, `shrink_memory`, `optimize`) is refused
/// until someone reviews it and names it here.
const ALLOWED_PRAGMA_GETTERS: &[&str] = &[
    "application_id",
    "user_version",
    "synchronous",
    "foreign_keys",
    "journal_size_limit",
    "busy_timeout",
    "integrity_check(1)",
];

fn pragma_is_an_allowed_getter(text: &str) -> bool {
    let Some(rest) = text.trim().strip_prefix("PRAGMA ") else {
        return false;
    };
    ALLOWED_PRAGMA_GETTERS.contains(&rest)
}

/// Self-test of the allow-list: pragmas that act on read, setters and spelling tricks are out.
#[test]
fn the_pragma_allow_list_refuses_acting_and_setter_pragmas() {
    for bad in [
        "PRAGMA wal_checkpoint",
        "PRAGMA wal_checkpoint(TRUNCATE)",
        "PRAGMA incremental_vacuum",
        "PRAGMA shrink_memory",
        "PRAGMA optimize",
        "PRAGMA locking_mode",
        "PRAGMA journal_mode",
        "PRAGMA user_version = 1",
        "PRAGMA main.user_version",
        "PRAGMA integrity_check(100)",
        "PRAGMA integrity_check",
        "pragma user_version",
        "SELECT 1",
    ] {
        assert!(!pragma_is_an_allowed_getter(bad), "{bad}");
    }
    for ok in ["PRAGMA application_id", "PRAGMA integrity_check(1)"] {
        assert!(pragma_is_an_allowed_getter(ok), "{ok}");
    }
}

/// The pass-list is reviewed text, not a shape check: none of its statements is transaction
/// control, `ATTACH`/`DETACH`, a setter pragma (`=` or a call form) or anything but a `SELECT`
/// or a getter pragma named in `ALLOWED_PRAGMA_GETTERS`, and each is read-only and returns a column.
#[test]
fn the_token_list_has_no_setter_transaction_or_attach_statement() {
    let (_f, idx) = open_new();
    for t in tokens() {
        let text = t.text();
        let upper = text.trim_start().to_ascii_uppercase();
        let ok_start = upper.starts_with("SELECT ")
            || upper.starts_with("WITH ")
            || (upper.starts_with("PRAGMA ") && pragma_is_an_allowed_getter(text));
        assert!(ok_start, "{text}");
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

/// The write wrappers refuse a read-only statement with the typed error, a script is checked
/// statement by statement (a `COMMIT` after a write is refused before it runs and the write rolls
/// back), and an ordinary multi-statement script still runs.
#[test]
fn the_write_wrappers_refuse_with_the_typed_error_and_check_every_statement_of_a_script() {
    use wardenlens_core::storage::SegmentIndex as _;
    let (_f, mut idx) = open_new();
    idx.insert(
        &crate::tests::rec("c", crate::tests::BASE, 1000, 10, 1),
        wardenlens_core::storage::Tier::Hot,
    )
    .unwrap();
    let count = |c: &Connection| -> i64 {
        c.query_row("SELECT count(*) FROM segments", [], |r| r.get(0))
            .unwrap()
    };
    assert_eq!(count(&idx.conn), 1);
    let before: i64 = idx
        .conn
        .query_row("SELECT generation FROM index_meta", [], |r| r.get(0))
        .unwrap();
    let r = sql::write_tx(&mut idx.conn, "probe", |w| {
        w.write_batch("DELETE FROM segments; COMMIT;")
            .map_err(IndexError::sqlite("probe"))
    });
    assert!(
        matches!(r, Err(IndexError::NotADataWrite { op: "probe" })),
        "{r:?}"
    );
    assert_eq!(count(&idx.conn), 1, "the DELETE before the COMMIT was kept");
    let r = sql::write_tx(&mut idx.conn, "probe", |w| {
        w.write("SELECT 1", [])
            .map(|_| ())
            .map_err(IndexError::sqlite("probe"))
    });
    assert!(matches!(r, Err(IndexError::NotADataWrite { .. })), "{r:?}");
    let msg = r.unwrap_err().to_string();
    assert!(!msg.contains("not read-only"), "{msg}");
    let after: i64 = idx
        .conn
        .query_row("SELECT generation FROM index_meta", [], |r| r.get(0))
        .unwrap();
    assert_eq!(before, after, "a refused write_tx bumped the generation");
    sql::write_tx(&mut idx.conn, "probe", |w| {
        w.write_batch("DELETE FROM segments; DELETE FROM segments;")
            .map_err(IndexError::sqlite("probe"))
    })
    .unwrap();
}

/// One test per new error variant: the message names the refusal and nothing else, and the
/// variants are distinct from the read-side `NotReadOnly`.
#[test]
fn the_write_side_error_variants_have_their_own_messages() {
    let a = IndexError::NotADataWrite { op: "t" };
    let b = IndexError::TransactionEnded { op: "t" };
    assert_eq!(
        a.to_string(),
        "t: refused a statement that does not change data"
    );
    assert_eq!(b.to_string(), "t: the write transaction was ended early");
    assert!(!a.is_transient() && !b.is_transient());
}

/// A closure that ignores the error of a transaction-ending statement and goes on: nothing it
/// writes afterwards runs outside a transaction (the next write is refused with the typed
/// error), and `write_tx` never reports success.
#[test]
fn a_statement_that_ends_the_transaction_makes_every_later_write_fail() {
    let (_f, mut idx) = open_new();
    let r = sql::write_tx(&mut idx.conn, "probe", |w| {
        let ins = |w: &sql::WriteTx<'_>| {
            w.write(
                sql::INSERT,
                rusqlite::params![
                    "c",
                    1_700_000_000_000i64,
                    1000i64,
                    1_700_000_001_000i64,
                    1i64,
                    1i64,
                    0i64
                ],
            )
            .map(|_| ())
            .map_err(IndexError::sqlite("probe"))
        };
        ins(w)?;
        // A conflict: `OR ROLLBACK` ends the transaction.
        let _ = w.write(
            "INSERT OR ROLLBACK INTO segments (camera_id, started_at_ms, duration_ms, ended_at_ms, \
             bytes, frame_count, tier) VALUES ('c', 1700000000000, 1000, 1700000001000, 1, 1, 0)",
            [],
        );
        let later = ins(w);
        assert!(
            matches!(later, Err(IndexError::TransactionEnded { op: "probe" })),
            "{later:?}"
        );
        Ok(())
    });
    assert!(
        matches!(r, Err(IndexError::TransactionEnded { .. })),
        "{r:?}"
    );
    let n: i64 = idx
        .conn
        .query_row("SELECT count(*) FROM segments", [], |r| r.get(0))
        .unwrap();
    assert_eq!(n, 0);
}
