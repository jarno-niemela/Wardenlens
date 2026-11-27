//! Every SQL statement of the crate, and the only code that touches `rusqlite` (SEC-10: one
//! choke point for writes). What is enforced, and by what:
//!
//! 1. **The compiler: no code outside this file can run SQL.** The connection is a [`Db`], a
//!    newtype whose `rusqlite::Connection` field is private to this module. Outside it there is no
//!    `.execute`, `.query_row`, `.pragma_update`, `.prepare_with_flags`, `.transaction` or any other
//!    driver method on it; the only ways to run SQL are the functions below.
//! 2. **The compiler: no SQL is built from data.** Those functions take a `&'static str` (writes
//!    and setup) or a [`ReadSql`] (reads), and values only travel as bound parameters.
//! 3. **The compiler: reads are a pass-list.** [`prepare`] and [`query_row`] take a [`ReadSql`],
//!    a token whose constructor is private to this module and which exists only for the reviewed
//!    `SELECT`s and getter pragmas below (a test checks every one). It is not a shape check:
//!    `sqlite3_stmt_readonly` is true for `COMMIT`, `ATTACH`, `PRAGMA locking_mode = ...` and more,
//!    so the token, not that flag, decides what a read is.
//!    As defence in depth `prepare` also refuses, at run time, a statement that is not
//!    `readonly()` or returns no column (`IndexError::NotReadOnly`).
//! 4. **The compiler: a data write bumps the generation.** [`WriteTx::write`] and
//!    [`WriteTx::write_batch`] need a `&WriteTx`, which only [`write_tx`] makes, and it runs
//!    [`BUMP_GENERATION`] before `COMMIT`. They keep `&'static str` rather than a token because a
//!    `WriteTx` is already the proof that the bump will follow, and the migration scripts are
//!    whole files.
//! 5. **By convention, checked by test:** [`execute_unversioned`], [`query_row_unversioned`] and
//!    [`unversioned_tx`] do not bump. They are the setup wrappers (the creation bootstrap,
//!    connection pragmas, the reference schema) and the `hygiene` test limits them to `open.rs`
//!    and `migrate.rs`. That limit is a text check, not the compiler.

use rusqlite::{Connection, Params, Result, Row, Statement};

use crate::error::IndexError;

// The column list of a full row is repeated in `GET` and `LIST` on purpose, in the order
// `rows::decode_segment` reads it: a `concat!` would be one more way to build SQL.
pub(crate) const INSERT: &str = "INSERT INTO segments \
    (camera_id, started_at_ms, duration_ms, ended_at_ms, bytes, frame_count, tier) \
    VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)";

pub(crate) const GET: ReadSql = ReadSql(
    "SELECT id, camera_id, started_at_ms, duration_ms, ended_at_ms, \
    bytes, frame_count, tier FROM segments WHERE id = ?1",
);

/// ?1 camera, ?2 `from` minus the longest duration, ?3 `to`, ?4 `from`, ?5 and ?6 the cursor
/// position `(started_at_ms, id)`, ?7 the row count to fetch.
pub(crate) const LIST: ReadSql = ReadSql(
    "SELECT id, camera_id, started_at_ms, duration_ms, ended_at_ms, \
    bytes, frame_count, tier FROM segments \
    WHERE camera_id = ?1 AND started_at_ms >= ?2 AND started_at_ms < ?3 AND ended_at_ms > ?4 \
    AND (started_at_ms, id) > (?5, ?6) \
    ORDER BY started_at_ms, id LIMIT ?7",
);

/// ?1 id, ?2 the new tier, ?3 the tier it must be on now.
pub(crate) const SET_TIER: &str = "UPDATE segments SET tier = ?2 WHERE id = ?1 AND tier = ?3";

pub(crate) const TIER_OF: ReadSql = ReadSql("SELECT tier FROM segments WHERE id = ?1");

pub(crate) const DELETE: &str = "DELETE FROM segments WHERE id = ?1";

/// ?1 tier, ?2 and ?3 the keyset position `(ended_at_ms, id)` to continue after, ?4 the row count.
pub(crate) const OLDEST: ReadSql = ReadSql(
    "SELECT id, tier, bytes, ended_at_ms FROM segments \
    WHERE tier = ?1 AND (ended_at_ms, id) > (?2, ?3) ORDER BY ended_at_ms, id LIMIT ?4",
);

/// ?1 tier. The last row of [`OLDEST`]'s order.
pub(crate) const NEWEST: ReadSql = ReadSql(
    "SELECT id, tier, bytes, ended_at_ms FROM segments \
    WHERE tier = ?1 ORDER BY ended_at_ms DESC, id DESC LIMIT 1",
);

pub(crate) const BYTES_BY_TIER: ReadSql = ReadSql(
    "SELECT tier, SUM(bytes), COUNT(*), MIN(bytes), MAX(bytes) FROM segments GROUP BY tier",
);

pub(crate) const LATEST_START: ReadSql =
    ReadSql("SELECT MAX(started_at_ms) FROM segments WHERE camera_id = ?1");

// The camera registry (ticket #50). The column list is repeated in `GET_CAMERA` and `LIST_CAMERAS`
// on purpose, in the order `cameras::decode` reads it.

/// ?1 id, ?2 model, ?3 port, ?4 main path, ?5 sub path or NULL, ?6 now. A new row gets `?6` as
/// both timestamps; an existing row keeps `created_at_ms`.
pub(crate) const UPSERT_CAMERA: &str = "INSERT INTO cameras \
    (id, model, rtsp_port, main_path, sub_path, created_at_ms, updated_at_ms) \
    VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6) \
    ON CONFLICT (id) DO UPDATE SET model = excluded.model, rtsp_port = excluded.rtsp_port, \
    main_path = excluded.main_path, sub_path = excluded.sub_path, \
    updated_at_ms = excluded.updated_at_ms";

/// Insert only: a row with the id makes this a constraint error (the caller checks first).
pub(crate) const INSERT_CAMERA: &str = "INSERT INTO cameras \
    (id, model, rtsp_port, main_path, sub_path, created_at_ms, updated_at_ms) \
    VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6)";

pub(crate) const GET_CAMERA: ReadSql = ReadSql(
    "SELECT id, model, rtsp_port, main_path, sub_path, created_at_ms, updated_at_ms \
    FROM cameras WHERE id = ?1",
);

/// ?1 the row count to fetch.
pub(crate) const LIST_CAMERAS: ReadSql = ReadSql(
    "SELECT id, model, rtsp_port, main_path, sub_path, created_at_ms, updated_at_ms \
    FROM cameras ORDER BY id LIMIT ?1",
);

pub(crate) const CAMERA_EXISTS: ReadSql = ReadSql("SELECT count(*) FROM cameras WHERE id = ?1");

pub(crate) const CAMERA_COUNT: ReadSql = ReadSql("SELECT count(*) FROM cameras");

/// Removes the registry row only: segments carry no foreign key and stay (ADR 0005 section 5).
pub(crate) const DELETE_CAMERA: &str = "DELETE FROM cameras WHERE id = ?1";

/// The camera ids that have segments but no registry row, ?1 the row count to fetch.
pub(crate) const ORPHAN_CAMERAS: ReadSql = ReadSql(
    "SELECT DISTINCT s.camera_id FROM segments s LEFT JOIN cameras c ON c.id = s.camera_id \
    WHERE c.id IS NULL ORDER BY s.camera_id LIMIT ?1",
);

// The API tokens (ticket #65). Plain data access: nothing here hashes or compares a secret.

pub(crate) const TOKEN_EXISTS: ReadSql = ReadSql("SELECT count(*) FROM api_tokens WHERE id = ?1");

pub(crate) const TOKEN_COUNT: ReadSql = ReadSql("SELECT count(*) FROM api_tokens");

/// ?1 id, ?2 digest, ?3 name, ?4 created at.
pub(crate) const INSERT_TOKEN: &str = "INSERT INTO api_tokens \
    (id, digest, name, created_at_ms) VALUES (?1, ?2, ?3, ?4)";

pub(crate) const FIND_TOKEN: ReadSql =
    ReadSql("SELECT digest, revoked FROM api_tokens WHERE id = ?1");

/// ?1 the row count to fetch. `rowid` is insertion order.
pub(crate) const LIST_TOKENS: ReadSql = ReadSql(
    "SELECT id, name, created_at_ms, last_used_at_ms, revoked FROM api_tokens \
    ORDER BY rowid LIMIT ?1",
);

/// ?1 id. Only an active token changes.
pub(crate) const REVOKE_TOKEN: &str =
    "UPDATE api_tokens SET revoked = 1 WHERE id = ?1 AND revoked = 0";

/// ?1 id, ?2 now, ?3 the latest `last_used_at_ms` that still counts as old enough
/// (`now - TOUCH_INTERVAL_MS`). The rate limit lives in this predicate.
pub(crate) const TOUCH_TOKEN: &str = "UPDATE api_tokens SET last_used_at_ms = ?2 \
    WHERE id = ?1 AND (last_used_at_ms IS NULL OR last_used_at_ms <= ?3)";

/// Same predicate as [`TOUCH_TOKEN`] as a read, so a token used a moment ago takes no write lock.
pub(crate) const TOKEN_TOUCH_DUE: ReadSql = ReadSql(
    "SELECT count(*) FROM api_tokens \
    WHERE id = ?1 AND (last_used_at_ms IS NULL OR last_used_at_ms <= ?2)",
);

// Open and migration statements.
pub(crate) const GET_APP_ID: ReadSql = ReadSql("PRAGMA application_id");
pub(crate) const USER_VERSION: ReadSql = ReadSql("PRAGMA user_version");
pub(crate) const OBJECT_COUNT: ReadSql = ReadSql("SELECT count(*) FROM sqlite_master");
/// Creation bootstrap: sets the `application_id` (must equal `open::APPLICATION_ID`; a test
/// checks) and creates `index_meta` with the random instance id, in one transaction.
pub(crate) const BOOTSTRAP: &str = include_str!("../migrations/000_bootstrap.sql");
/// Run by [`write_tx`] at the end of every write transaction: it rewrites the page that holds the
/// instance id, so every non-empty `-wal` this crate writes carries that page and a replayed
/// foreign `-wal` always shows the foreign id.
pub(crate) const BUMP_GENERATION: &str =
    "UPDATE index_meta SET generation = generation + 1 WHERE id = 1";
pub(crate) const INSTANCE_ID: ReadSql = ReadSql("SELECT instance_id FROM index_meta WHERE id = 1");
pub(crate) const SET_WAL: &str = "PRAGMA journal_mode = WAL";
pub(crate) const SET_SYNC: &str = "PRAGMA synchronous = FULL";
pub(crate) const SET_FK: &str = "PRAGMA foreign_keys = ON";
/// Must equal `open::JOURNAL_SIZE_LIMIT` (a test checks).
pub(crate) const SET_JOURNAL_LIMIT: &str = "PRAGMA journal_size_limit = 67108864";
pub(crate) const GET_SYNC: ReadSql = ReadSql("PRAGMA synchronous");
pub(crate) const GET_FK: ReadSql = ReadSql("PRAGMA foreign_keys");
pub(crate) const GET_JOURNAL_LIMIT: ReadSql = ReadSql("PRAGMA journal_size_limit");
pub(crate) const GET_BUSY: ReadSql = ReadSql("PRAGMA busy_timeout");
pub(crate) const SCHEMA_ROWS: ReadSql =
    ReadSql("SELECT type, name, tbl_name, sql FROM sqlite_master");
pub(crate) const INTEGRITY_CHECK: ReadSql = ReadSql("PRAGMA integrity_check(1)");

/// A read statement: a reviewed `SELECT` or getter pragma. The field and so the constructor are
/// private to this module, so only the constants above can be one.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ReadSql(&'static str);

/// The database connection. The `rusqlite::Connection` is private to this module, so code
/// elsewhere cannot run SQL except through the functions below (see the module docs).
pub(crate) struct Db(Connection);

impl Db {
    /// Wraps a connection that was opened (and configured) by `open.rs` or `migrate.rs`.
    pub(crate) fn new(conn: Connection) -> Self {
        Self(conn)
    }

    /// The row id of the last insert on this connection.
    pub(crate) fn last_insert_rowid(&self) -> i64 {
        self.0.last_insert_rowid()
    }
}

// The only places SQL text reaches `rusqlite`.

/// Prepares a read statement. Besides the [`ReadSql`] token (the pass-list), a statement that
/// SQLite does not call read-only, or that returns no column (transaction control, `ATTACH`,
/// setter pragmas that return nothing), is refused with `rusqlite::Error::InvalidQuery`, mapped
/// to [`IndexError::NotReadOnly`] by [`IndexError::sqlite`].
pub(crate) fn prepare(db: &Db, sql: impl Into<ReadSql>) -> Result<Statement<'_>> {
    let stmt = db.0.prepare(sql.into().0)?;
    if stmt.readonly() && stmt.column_count() > 0 {
        Ok(stmt)
    } else {
        Err(rusqlite::Error::InvalidQuery)
    }
}

/// A single-row read; the same refusals as [`prepare`].
pub(crate) fn query_row<T, P: Params>(
    db: &Db,
    sql: impl Into<ReadSql>,
    params: P,
    f: impl FnOnce(&Row<'_>) -> Result<T>,
) -> Result<T> {
    prepare(db, sql)?.query_row(params, f)
}

/// Runs a statement that is not index data: connection setup pragmas, the creation bootstrap
/// (rollback mode, before any WAL exists) and the in-memory reference schema. It does **not**
/// bump the generation. Data writes cannot use it: they need a [`WriteTx`]. Setup only.
pub(crate) fn execute_unversioned(db: &Db, sql: &'static str) -> Result<()> {
    db.0.execute_batch(sql)
}

/// [`execute_unversioned`] for the setup pragma that returns a row and writes (`journal_mode`,
/// `journal_size_limit`). Setup only.
pub(crate) fn query_row_unversioned<T>(
    db: &Db,
    sql: &'static str,
    f: impl FnOnce(&Row<'_>) -> Result<T>,
) -> Result<T> {
    db.0.query_row(sql, [], f)
}

/// The creation claim: `BEGIN IMMEDIATE`, `f`, then `COMMIT` if `f` returns `Some`; `None` or an
/// error rolls back. No generation bump: it is the creation of the file, before any WAL exists.
/// Setup only (`open::claim_new`).
pub(crate) fn unversioned_tx<T>(
    db: &mut Db,
    op: &'static str,
    f: impl FnOnce(&Db) -> std::result::Result<Option<T>, IndexError>,
) -> std::result::Result<Option<T>, IndexError> {
    let guard = Tx::begin(db, op)?;
    let Some(out) = f(guard.db)? else {
        return Ok(None);
    };
    guard.commit(op)?;
    Ok(Some(out))
}

/// An open `BEGIN IMMEDIATE` transaction, rolled back on drop unless committed.
struct Tx<'a> {
    db: &'a Db,
    open: bool,
}

impl<'a> Tx<'a> {
    fn begin(db: &'a Db, op: &'static str) -> std::result::Result<Self, IndexError> {
        db.0.execute_batch("BEGIN IMMEDIATE")
            .map_err(IndexError::sqlite(op))?;
        Ok(Self { db, open: true })
    }

    fn commit(mut self, op: &'static str) -> std::result::Result<(), IndexError> {
        self.db
            .0
            .execute_batch("COMMIT")
            .map_err(IndexError::sqlite(op))?;
        self.open = false;
        Ok(())
    }
}

impl Drop for Tx<'_> {
    fn drop(&mut self) {
        if self.open {
            // ERR-4: best effort; closing the connection rolls back too.
            let _ = self.db.0.execute_batch("ROLLBACK");
        }
    }
}

/// A write transaction opened by [`write_tx`]. It is the only way to run a data-changing
/// statement ([`write`](Self::write), [`write_batch`](Self::write_batch)): they take a
/// `&WriteTx`, which only [`write_tx`] can make, so a write cannot skip the generation bump.
pub(crate) struct WriteTx<'a> {
    db: &'a Db,
}

impl WriteTx<'_> {
    /// For reads inside the transaction (use [`prepare`] or [`query_row`] on it).
    pub(crate) fn read_conn(&self) -> &Db {
        self.db
    }

    pub(crate) fn write<P: Params>(&self, sql: &'static str, params: P) -> Result<usize> {
        self.db.0.execute(sql, params)
    }

    pub(crate) fn write_batch(&self, sql: &'static str) -> Result<()> {
        self.db.0.execute_batch(sql)
    }
}

/// The one way to change the database after creation: `BEGIN IMMEDIATE`, `f`, the generation
/// bump, `COMMIT`. `f` returning `Ok(None)` or an error rolls everything back (no bump, no
/// frame). Every segment write and every migration step goes through here.
pub(crate) fn write_tx_opt<T>(
    db: &mut Db,
    op: &'static str,
    f: impl FnOnce(&WriteTx<'_>) -> std::result::Result<Option<T>, IndexError>,
) -> std::result::Result<Option<T>, IndexError> {
    let guard = Tx::begin(db, op)?;
    let out = {
        let w = WriteTx { db: guard.db };
        let Some(out) = f(&w)? else {
            return Ok(None);
        };
        w.write(BUMP_GENERATION, [])
            .map_err(IndexError::sqlite(op))?;
        out
    };
    guard.commit(op)?;
    Ok(Some(out))
}

/// [`write_tx_opt`] for a closure that always produces a value.
pub(crate) fn write_tx<T>(
    db: &mut Db,
    op: &'static str,
    f: impl FnOnce(&WriteTx<'_>) -> std::result::Result<T, IndexError>,
) -> std::result::Result<T, IndexError> {
    write_tx_opt(db, op, |w| f(w).map(Some))?.ok_or(IndexError::Sqlite { op, code: None })
}

// Test-only conveniences. They are after everything else because the `hygiene` scan stops at the
// first `#[cfg(test)]` line; production code cannot compile a call that relies on them.

#[cfg(test)]
impl ReadSql {
    /// The statement text.
    pub(crate) const fn text(self) -> &'static str {
        self.0
    }
}

/// A token for any literal, to prove the run-time checks of [`prepare`] on their
/// own. Production code cannot compile a call that relies on it.
#[cfg(test)]
impl From<&'static str> for ReadSql {
    fn from(text: &'static str) -> Self {
        Self(text)
    }
}

#[cfg(test)]
impl From<&&'static str> for ReadSql {
    fn from(text: &&'static str) -> Self {
        Self(text)
    }
}

/// Tests only: raw access to the connection, so a test can inspect what the crate wrote or build
/// a hostile fixture. Production code cannot compile a call that relies on it.
#[cfg(test)]
impl std::ops::Deref for Db {
    type Target = Connection;
    fn deref(&self) -> &Connection {
        &self.0
    }
}
