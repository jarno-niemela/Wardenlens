//! Adversary (#145 round 2): the write side of `write_tx`. `WriteTx::write` and `write_batch`
//! take any `&'static str`; the module docs say a data write "cannot skip the generation bump"
//! because only `write_tx` makes a `WriteTx`. Transaction control through them ends the
//! transaction early, so a write lands with no bump and a closure error no longer rolls it back.

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

fn insert(w: &sql::WriteTx<'_>) -> Result<(), IndexError> {
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
    .map_err(IndexError::sqlite("adv"))
}

/// Transaction control is not a data write: the write wrappers should refuse it (as the read
/// wrappers now do), so a failed `write_tx` cannot leave a committed, un-bumped row.
#[test]
fn the_write_wrappers_refuse_transaction_control() {
    for stmt in [
        "COMMIT",
        "END",
        "ROLLBACK",
        "BEGIN",
        "SAVEPOINT s",
        "RELEASE s",
    ] {
        let (_f, mut idx) = open_new();
        let gen_before = generation(&idx.conn);
        let r: Result<(), IndexError> = sql::write_tx(&mut idx.conn, "adv", |w| {
            insert(w)?;
            let _ = w.write(stmt, []);
            let _ = w.write_batch(stmt);
            Err(IndexError::Duplicate)
        });
        assert!(r.is_err());
        let rows = count(&idx.conn);
        let gen_after = generation(&idx.conn);
        assert!(
            rows == 0 || gen_after > gen_before,
            "{stmt}: a failed write_tx left {rows} committed row(s) with no generation bump"
        );
    }
}
