//! `PRAGMA user_version` migrations (ADR 0005 section 5): an ordered list of scripts compiled in
//! with `include_str!`. Each script ends with its own `PRAGMA user_version = <n>;`, so the version
//! can never drift from the DDL, and the runner verifies that it did.

use rusqlite::{Connection, TransactionBehavior};

use crate::error::IndexError;
use crate::sql;

/// One migration step.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Migration {
    /// The `user_version` after the script ran. Versions are 1, 2, 3, ... without gaps.
    pub(crate) version: i64,
    /// The script, ending with `PRAGMA user_version = <version>;`.
    pub(crate) sql: &'static str,
    /// The `(type, name)` of the tables and indexes the script creates (`sqlite_sequence` is implied once
    /// any migration ran). The identity probe requires the schema to be exactly these.
    pub(crate) objects: &'static [(&'static str, &'static str)],
}

/// All migrations of this build. Append-only.
pub(crate) const MIGRATIONS: &[Migration] = &[Migration {
    version: 1,
    sql: include_str!("../migrations/001_segments.sql"),
    objects: &[
        ("table", "segments"),
        ("index", "segments_camera_start"),
        ("index", "segments_tier_end"),
    ],
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

/// Runs every script above the stored version, one transaction (`BEGIN IMMEDIATE`) per script.
/// The version is read again inside the transaction, so a competing process that migrated first
/// is noticed. A failure rolls the failing step back and leaves earlier steps committed.
pub(crate) fn run(conn: &mut Connection, migrations: &[Migration]) -> Result<(), IndexError> {
    for m in migrations {
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(IndexError::sqlite("begin migration"))?;
        let stored = user_version(&tx)?;
        check_not_newer(stored, migrations)?;
        if stored >= m.version {
            continue;
        }
        sql::execute_batch(&tx, m.sql).map_err(|e| IndexError::Migration {
            version: m.version,
            code: e.sqlite_error_code(),
        })?;
        if user_version(&tx)? != m.version {
            return Err(IndexError::MigrationDidNotAdvance { version: m.version });
        }
        tx.commit().map_err(|e| IndexError::Migration {
            version: m.version,
            code: e.sqlite_error_code(),
        })?;
    }
    Ok(())
}
