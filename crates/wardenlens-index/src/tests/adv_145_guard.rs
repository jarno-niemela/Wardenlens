//! Adversary (#145): statements that `sqlite3_stmt_readonly` may call read-only yet that change
//! the database (data, schema or committed state) must not run through the read wrappers.

use std::path::Path;

use crate::sql;
use crate::tests::{open_new, rec};
use wardenlens_core::storage::SegmentIndex as _;
use wardenlens_core::storage::Tier;

fn files(dir: &Path) -> Vec<(String, Vec<u8>)> {
    let mut v: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap())
        .filter(|e| e.file_type().unwrap().is_file())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| !n.ends_with("-shm"))
        .map(|n| {
            let b = std::fs::read(dir.join(&n)).unwrap();
            (n, b)
        })
        .collect();
    v.sort();
    v
}

/// Each statement, if the read wrapper accepts it and runs it, must leave the main file and the
/// `-wal` byte-identical.
#[test]
fn no_statement_the_read_wrapper_accepts_changes_the_files() {
    let candidates: &[&'static str] = &[
        "PRAGMA wal_checkpoint(TRUNCATE)",
        "PRAGMA wal_checkpoint",
        "PRAGMA optimize",
        "PRAGMA optimize(0x10002)",
        "ANALYZE",
        "REINDEX",
        "PRAGMA incremental_vacuum",
        "PRAGMA schema_version = 99",
        "PRAGMA writable_schema = 1",
        "PRAGMA auto_vacuum = 1",
        "PRAGMA page_size = 1024",
        "PRAGMA journal_mode = DELETE",
        "PRAGMA main.journal_mode = DELETE",
        "PRAGMA journal_mode",
        "PRAGMA locking_mode = EXCLUSIVE",
        "PRAGMA secure_delete = ON",
        "PRAGMA wal_autocheckpoint = 1",
        "SELECT 1; DELETE FROM segments",
        "WITH x AS (SELECT 1) DELETE FROM segments RETURNING id",
        "REPLACE INTO index_meta (id) VALUES (1) RETURNING id",
        "INSERT OR IGNORE INTO segments DEFAULT VALUES RETURNING id",
        "VACUUM INTO 'adv145-vacuum-into.db'",
        "BEGIN IMMEDIATE",
        "SAVEPOINT s",
        "COMMIT",
    ];
    let mut wrote = Vec::new();
    for stmt in candidates {
        let (f, mut idx) = open_new();
        for i in 0..20 {
            idx.insert(
                &rec("c", crate::tests::BASE + i * 10_000, 1000, 10, 1),
                Tier::Hot,
            )
            .unwrap();
        }
        let before = files(f.dir.path());
        let ran = match sql::prepare(&idx.conn, stmt) {
            Ok(mut s) => {
                let mut rows = s.query([]).map(|_| ()).err();
                let _ = rows.take();
                true
            }
            Err(_) => false,
        };
        let after = files(f.dir.path());
        if ran && before != after {
            wrote.push(*stmt);
        }
    }
    assert!(wrote.is_empty(), "read wrapper ran writes: {wrote:?}");
}

fn generation(c: &rusqlite::Connection) -> i64 {
    c.query_row("SELECT generation FROM index_meta", [], |r| r.get(0))
        .unwrap()
}

fn count(c: &rusqlite::Connection) -> i64 {
    c.query_row("SELECT count(*) FROM segments", [], |r| r.get(0))
        .unwrap()
}

/// Transaction control (`COMMIT`, `END`, `RELEASE`, `ROLLBACK`) is read-only to
/// `sqlite3_stmt_readonly`, but run through the read wrapper inside `write_tx` it ends the
/// transaction early: the write before it is committed **without the generation bump**, and an
/// error from the closure no longer rolls it back. The read wrappers must refuse it.
#[test]
fn read_wrapper_refuses_transaction_control() {
    for stmt in [
        "COMMIT",
        "END",
        "ROLLBACK",
        "BEGIN",
        "SAVEPOINT s",
        "RELEASE s",
    ] {
        let (_f, idx) = open_new();
        assert!(
            sql::prepare(&idx.conn, stmt).is_err(),
            "{stmt}: the read wrapper accepted transaction control"
        );
    }
}

#[test]
fn a_commit_through_the_read_wrapper_cannot_land_a_write_without_the_bump() {
    let (_f, mut idx) = open_new();
    let gen_before = generation(&idx.conn);
    let rows_before = count(&idx.conn);
    let r: Result<(), crate::error::IndexError> = sql::write_tx(&mut idx.conn, "adv", |w| {
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
        .map_err(crate::error::IndexError::sqlite("adv"))?;
        // A read-wrapper call that SQLite calls read-only.
        let _ = sql::query_row(w.read_conn(), "COMMIT", [], |r| r.get::<_, i64>(0));
        Err(crate::error::IndexError::Duplicate)
    });
    assert!(r.is_err());
    let rows_after = count(&idx.conn);
    let gen_after = generation(&idx.conn);
    assert!(
        rows_after == rows_before || gen_after > gen_before,
        "a row was committed by a failed write_tx with no generation bump: rows {rows_before}->{rows_after}, generation {gen_before}->{gen_after}"
    );
}

/// `ATTACH` is read-only to `sqlite3_stmt_readonly`; through the read wrapper it must not create
/// a file next to the index (or anywhere).
#[test]
fn attach_through_the_read_wrapper_creates_no_file() {
    let (f, idx) = open_new();
    let target = std::env::current_dir().unwrap().join("adv145-attached.db");
    let _ = std::fs::remove_file(&target);
    let before = files(f.dir.path());
    let accepted = match sql::prepare(&idx.conn, "ATTACH DATABASE 'adv145-attached.db' AS x") {
        Ok(mut s) => {
            let _ = s.raw_execute();
            true
        }
        Err(_) => false,
    };
    let created = target.exists();
    let _ = std::fs::remove_file(&target);
    assert_eq!(before, files(f.dir.path()));
    assert!(
        !created,
        "ATTACH via the read wrapper (accepted={accepted}) created a file"
    );
}
