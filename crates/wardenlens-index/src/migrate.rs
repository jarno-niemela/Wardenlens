//! `PRAGMA user_version` migrations (ADR 0005 section 5): an ordered list of scripts compiled in
//! with `include_str!`. Each script ends with its own `PRAGMA user_version = <n>;`, so the version
//! can never drift from the DDL, and the runner verifies that it did.

use rusqlite::Connection;

use crate::error::IndexError;
use crate::sql;

/// One migration step.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Migration {
    /// The `user_version` after the script ran. Versions are 1, 2, 3, ... without gaps.
    pub(crate) version: i64,
    /// The script, ending with `PRAGMA user_version = <version>;`.
    pub(crate) sql: &'static str,
}

/// All migrations of this build. Append-only.
pub(crate) const MIGRATIONS: &[Migration] = &[Migration {
    version: 1,
    sql: include_str!("../migrations/001_segments.sql"),
}];

/// The newest version `migrations` reaches.
pub(crate) fn latest(migrations: &[Migration]) -> i64 {
    migrations.last().map_or(0, |m| m.version)
}

/// Reads `user_version`; a negative value is refused.
pub(crate) fn user_version(conn: &Connection) -> Result<i64, IndexError> {
    let v: i64 = sql::query_row(conn, sql::USER_VERSION, [], |r| r.get(0))
        .map_err(IndexError::sqlite("read schema version"))?;
    if v < 0 {
        return Err(IndexError::InvalidSchemaVersion { found: v });
    }
    Ok(v)
}

/// Refuses a stored version newer than `migrations` reach.
pub(crate) fn check_not_newer(found: i64, migrations: &[Migration]) -> Result<(), IndexError> {
    let supported = latest(migrations);
    if found > supported {
        return Err(IndexError::SchemaTooNew { found, supported });
    }
    Ok(())
}

/// Runs every script above the stored version, one write transaction (`BEGIN IMMEDIATE`, the
/// script, the generation bump, `COMMIT`; see `sql::write_tx`) per script. The version is read
/// again inside the transaction, so a competing process that migrated first is noticed. A failure
/// rolls the failing step back and leaves earlier steps committed.
pub(crate) fn run(conn: &mut Connection, migrations: &[Migration]) -> Result<(), IndexError> {
    for m in migrations {
        sql::write_tx_opt(conn, "migrate", |w| {
            let stored = user_version(w.read_conn())?;
            check_not_newer(stored, migrations)?;
            if stored >= m.version {
                return Ok(None);
            }
            w.write_batch(m.sql).map_err(|e| IndexError::Migration {
                version: m.version,
                code: e.sqlite_error_code(),
            })?;
            if user_version(w.read_conn())? != m.version {
                return Err(IndexError::MigrationDidNotAdvance { version: m.version });
            }
            Ok(Some(()))
        })?;
    }
    Ok(())
}

/// One `sqlite_master` row: `(type, name, tbl_name, sql)`.
pub(crate) type SchemaRow = (String, String, String, Option<String>);

/// Reads every `sqlite_master` row of `conn`, sorted.
pub(crate) fn schema_rows(conn: &Connection) -> rusqlite::Result<Vec<SchemaRow>> {
    let mut stmt = sql::prepare(conn, sql::SCHEMA_ROWS)?;
    let mut rows: Vec<SchemaRow> = stmt
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?
        .collect::<rusqlite::Result<_>>()?;
    rows.sort();
    Ok(rows)
}

/// The schema a database at `version` must have, built by running the creation bootstrap and then
/// the compiled-in scripts up to `version` on an empty in-memory database. Nothing about it is hand-listed, so it cannot drift
/// from the migrations.
pub(crate) fn reference_schema(
    migrations: &[Migration],
    version: i64,
) -> Result<Vec<SchemaRow>, IndexError> {
    let conn = Connection::open_in_memory().map_err(IndexError::sqlite("reference schema"))?;
    sql::execute_unversioned(&conn, sql::BOOTSTRAP)
        .map_err(IndexError::sqlite("reference schema"))?;
    for m in migrations.iter().filter(|m| m.version <= version) {
        sql::execute_unversioned(&conn, m.sql).map_err(|e| IndexError::Migration {
            version: m.version,
            code: e.sqlite_error_code(),
        })?;
    }
    schema_rows(&conn).map_err(IndexError::sqlite("reference schema"))
}
