//! Every SQL statement of the crate, as a `&'static str` with `?N` placeholders.
//!
//! What this file enforces, and by what (SEC-10, one choke point for writes):
//!
//! 1. **No SQL is built from data.** Every statement is a `&'static str` constant here, and the
//!    only functions that hand SQL text to `rusqlite` are the wrappers at the bottom of this file,
//!    which take `&'static str`: the compiler refuses a string built at run time. Values only
//!    ever travel as bound parameters.
//! 2. **Every data write bumps the generation.** The statement-running wrappers split in two:
//!    - [`WriteTx::write`] and [`WriteTx::write_batch`] need a `&WriteTx`, which only [`write_tx`]
//!      can make (the compiler enforces this), and [`write_tx`] runs [`BUMP_GENERATION`] before
//!      `COMMIT`;
//!    - [`prepare`] and [`query_row`] are for reads: **at run time** they prepare the statement and
//!      refuse it with [`IndexError::NotReadOnly`] if SQLite says it is not read-only
//!      (`sqlite3_stmt_readonly`, which is false for `UPDATE ... RETURNING` too). They cannot run
//!      a write that skips the bump.
//!    - The exceptions that do not bump, each limited to the open sequence and the reference
//!      schema: [`execute_unversioned`] and [`query_row_unversioned`] (setup pragmas that write,
//!      the creation bootstrap).
//! 3. **The `hygiene` test greps** every production source file for a direct `rusqlite` call and
//!    for `*_unversioned` uses outside `open.rs` and `migrate.rs`. That part is a text check, not
//!    the compiler: `Connection` is a plain field of `Index`, so a direct `conn.execute(` is only
//!    caught by the grep.

use rusqlite::{Connection, Params, Result, Row, Statement, Transaction, TransactionBehavior};

use crate::error::IndexError;

// The column list of a full row is repeated in `GET` and `LIST` on purpose, in the order
// `rows::decode_segment` reads it: a `concat!` would be one more way to build SQL.
pub(crate) const INSERT: &str = "INSERT INTO segments \
    (camera_id, started_at_ms, duration_ms, ended_at_ms, bytes, frame_count, tier) \
    VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)";

pub(crate) const GET: &str = "SELECT id, camera_id, started_at_ms, duration_ms, ended_at_ms, \
    bytes, frame_count, tier FROM segments WHERE id = ?1";

/// ?1 camera, ?2 `from` minus the longest duration, ?3 `to`, ?4 `from`, ?5 and ?6 the cursor
/// position `(started_at_ms, id)`, ?7 the row count to fetch.
pub(crate) const LIST: &str = "SELECT id, camera_id, started_at_ms, duration_ms, ended_at_ms, \
    bytes, frame_count, tier FROM segments \
    WHERE camera_id = ?1 AND started_at_ms >= ?2 AND started_at_ms < ?3 AND ended_at_ms > ?4 \
    AND (started_at_ms, id) > (?5, ?6) \
    ORDER BY started_at_ms, id LIMIT ?7";

/// ?1 id, ?2 the new tier, ?3 the tier it must be on now.
pub(crate) const SET_TIER: &str = "UPDATE segments SET tier = ?2 WHERE id = ?1 AND tier = ?3";

pub(crate) const TIER_OF: &str = "SELECT tier FROM segments WHERE id = ?1";

pub(crate) const DELETE: &str = "DELETE FROM segments WHERE id = ?1";

/// ?1 tier, ?2 and ?3 the keyset position `(ended_at_ms, id)` to continue after, ?4 the row count.
pub(crate) const OLDEST: &str = "SELECT id, tier, bytes, ended_at_ms FROM segments \
    WHERE tier = ?1 AND (ended_at_ms, id) > (?2, ?3) ORDER BY ended_at_ms, id LIMIT ?4";

pub(crate) const BYTES_BY_TIER: &str =
    "SELECT tier, SUM(bytes), COUNT(*), MIN(bytes), MAX(bytes) FROM segments GROUP BY tier";

pub(crate) const LATEST_START: &str =
    "SELECT MAX(started_at_ms) FROM segments WHERE camera_id = ?1";

// Open and migration statements.
pub(crate) const GET_APP_ID: &str = "PRAGMA application_id";
pub(crate) const USER_VERSION: &str = "PRAGMA user_version";
pub(crate) const OBJECT_COUNT: &str = "SELECT count(*) FROM sqlite_master";
/// Creation bootstrap: sets the `application_id` (must equal `open::APPLICATION_ID`; a test
/// checks) and creates `index_meta` with the random instance id, in one transaction.
pub(crate) const BOOTSTRAP: &str = include_str!("../migrations/000_bootstrap.sql");
/// Run by [`write_tx`] at the end of every write transaction: it rewrites the page that holds the
/// instance id, so every non-empty `-wal` this crate writes carries that page and a replayed
/// foreign `-wal` always shows the foreign id.
pub(crate) const BUMP_GENERATION: &str =
    "UPDATE index_meta SET generation = generation + 1 WHERE id = 1";
pub(crate) const INSTANCE_ID: &str = "SELECT instance_id FROM index_meta WHERE id = 1";
pub(crate) const SET_WAL: &str = "PRAGMA journal_mode = WAL";
pub(crate) const SET_SYNC: &str = "PRAGMA synchronous = FULL";
pub(crate) const SET_FK: &str = "PRAGMA foreign_keys = ON";
/// Must equal `open::JOURNAL_SIZE_LIMIT` (a test checks).
pub(crate) const SET_JOURNAL_LIMIT: &str = "PRAGMA journal_size_limit = 67108864";
pub(crate) const GET_SYNC: &str = "PRAGMA synchronous";
pub(crate) const GET_FK: &str = "PRAGMA foreign_keys";
pub(crate) const GET_JOURNAL_LIMIT: &str = "PRAGMA journal_size_limit";
pub(crate) const GET_BUSY: &str = "PRAGMA busy_timeout";
pub(crate) const SCHEMA_ROWS: &str = "SELECT type, name, tbl_name, sql FROM sqlite_master";
pub(crate) const INTEGRITY_CHECK: &str = "PRAGMA integrity_check(1)";

// The only places SQL text reaches `rusqlite`. Each takes `&'static str`.

/// Prepares a **read-only** statement; any other statement is refused, unprepared for use, with
/// `rusqlite::Error::InvalidQuery` (mapped to [`IndexError::NotReadOnly`] by
/// [`IndexError::sqlite`]), so a write cannot be run through here and skip the generation bump.
pub(crate) fn prepare<'c>(conn: &'c Connection, sql: &'static str) -> Result<Statement<'c>> {
    let stmt = conn.prepare(sql)?;
    if stmt.readonly() {
        Ok(stmt)
    } else {
        Err(rusqlite::Error::InvalidQuery)
    }
}

/// Runs a statement that is not index data: connection setup pragmas, the creation bootstrap
/// (rollback mode, before any WAL exists) and the in-memory reference schema. It does **not**
/// bump the generation. Data writes cannot use it: they need a [`WriteTx`].
pub(crate) fn execute_unversioned(conn: &Connection, sql: &'static str) -> Result<()> {
    conn.execute_batch(sql)
}

/// [`execute_unversioned`] for the setup pragma that returns a row and writes (`journal_mode`).
/// Open sequence only.
pub(crate) fn query_row_unversioned<T>(
    conn: &Connection,
    sql: &'static str,
    f: impl FnOnce(&Row<'_>) -> Result<T>,
) -> Result<T> {
    conn.query_row(sql, [], f)
}

/// A single-row read; refuses a statement that is not read-only (see [`prepare`]).
pub(crate) fn query_row<T, P: Params>(
    conn: &Connection,
    sql: &'static str,
    params: P,
    f: impl FnOnce(&Row<'_>) -> Result<T>,
) -> Result<T> {
    prepare(conn, sql)?.query_row(params, f)
}

/// A write transaction opened by [`write_tx`]. It is the only way to run a data-changing
/// statement ([`write`](Self::write), [`write_batch`](Self::write_batch)): they take a
/// `&WriteTx`, which only [`write_tx`] can make, so a write method cannot skip the generation
/// bump (SEC-10: one choke point; the compiler enforces that these two need a `WriteTx`, and
/// [`prepare`]/[`query_row`] refuse a write at run time).
pub(crate) struct WriteTx<'a> {
    tx: &'a Transaction<'a>,
}

impl WriteTx<'_> {
    /// For reads inside the transaction (use [`prepare`] or [`query_row`] on it).
    pub(crate) fn read_conn(&self) -> &Connection {
        self.tx
    }

    pub(crate) fn write<P: Params>(&self, sql: &'static str, params: P) -> Result<usize> {
        self.tx.execute(sql, params)
    }

    pub(crate) fn write_batch(&self, sql: &'static str) -> Result<()> {
        self.tx.execute_batch(sql)
    }
}

/// The one way to change the database after creation: `BEGIN IMMEDIATE`, `f`, the generation
/// bump, `COMMIT`. `f` returning `Ok(None)` or an error rolls everything back (no bump, no
/// frame). Every segment write and every migration step goes through here.
pub(crate) fn write_tx_opt<T>(
    conn: &mut Connection,
    op: &'static str,
    f: impl FnOnce(&WriteTx<'_>) -> std::result::Result<Option<T>, IndexError>,
) -> std::result::Result<Option<T>, IndexError> {
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(IndexError::sqlite(op))?;
    let out = {
        let w = WriteTx { tx: &tx };
        let Some(out) = f(&w)? else {
            return Ok(None);
        };
        w.write(BUMP_GENERATION, [])
            .map_err(IndexError::sqlite(op))?;
        out
    };
    tx.commit().map_err(IndexError::sqlite(op))?;
    Ok(Some(out))
}

/// [`write_tx_opt`] for a closure that always produces a value.
pub(crate) fn write_tx<T>(
    conn: &mut Connection,
    op: &'static str,
    f: impl FnOnce(&WriteTx<'_>) -> std::result::Result<T, IndexError>,
) -> std::result::Result<T, IndexError> {
    write_tx_opt(conn, op, |w| f(w).map(Some))?.ok_or(IndexError::Sqlite { op, code: None })
}
