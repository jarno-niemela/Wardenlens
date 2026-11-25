//! Every SQL statement of the crate, as a `&'static str` with `?N` placeholders.
//!
//! This is the whole enforcement of "no SQL is built from data". Every statement is a
//! `&'static str` constant here, and the only functions in the crate that hand SQL text to
//! `rusqlite` are the wrappers at the bottom of this file, which take `&'static str`: the compiler
//! refuses a string built at run time. Values only ever travel as bound parameters. The
//! `hygiene` test also greps every production source file for a direct call.

use rusqlite::{Connection, Params, Result, Row, Statement};

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
/// Must equal `open::APPLICATION_ID` (a test checks).
pub(crate) const SET_APP_ID: &str = "PRAGMA application_id = 1464617304";
pub(crate) const SET_WAL: &str = "PRAGMA journal_mode = WAL";
pub(crate) const SET_SYNC: &str = "PRAGMA synchronous = FULL";
pub(crate) const SET_FK: &str = "PRAGMA foreign_keys = ON";
/// Must equal `open::JOURNAL_SIZE_LIMIT` (a test checks).
pub(crate) const SET_JOURNAL_LIMIT: &str = "PRAGMA journal_size_limit = 67108864";
pub(crate) const GET_SYNC: &str = "PRAGMA synchronous";
pub(crate) const GET_FK: &str = "PRAGMA foreign_keys";
pub(crate) const GET_JOURNAL_LIMIT: &str = "PRAGMA journal_size_limit";
pub(crate) const GET_BUSY: &str = "PRAGMA busy_timeout";
pub(crate) const SCHEMA_OBJECTS: &str = "SELECT type, name FROM sqlite_master \
    WHERE substr(name, 1, 17) != 'sqlite_autoindex_'";
pub(crate) const QUICK_CHECK: &str = "PRAGMA quick_check(1)";

// The only places SQL text reaches `rusqlite`. Each takes `&'static str`.

pub(crate) fn prepare<'c>(conn: &'c Connection, sql: &'static str) -> Result<Statement<'c>> {
    conn.prepare(sql)
}

pub(crate) fn execute<P: Params>(conn: &Connection, sql: &'static str, params: P) -> Result<usize> {
    conn.execute(sql, params)
}

pub(crate) fn execute_batch(conn: &Connection, sql: &'static str) -> Result<()> {
    conn.execute_batch(sql)
}

pub(crate) fn query_row<T, P: Params>(
    conn: &Connection,
    sql: &'static str,
    params: P,
    f: impl FnOnce(&Row<'_>) -> Result<T>,
) -> Result<T> {
    conn.query_row(sql, params, f)
}
