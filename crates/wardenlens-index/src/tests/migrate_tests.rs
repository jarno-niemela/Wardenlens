//! Migrations: from empty, step by step, too new, and interrupted at every statement.

use rusqlite::Connection;
use wardenlens_core::storage::{SegmentIndex, Tier};

use super::*;
use crate::error::IndexError;
use crate::migrate::{MIGRATIONS, Migration};

/// Synthetic steps on top of the real migrations 1 to 4.
const S5: Migration = Migration {
    version: 5,
    sql: "ALTER TABLE segments ADD COLUMN note TEXT; CREATE TABLE extra (x INTEGER); \
          INSERT INTO extra VALUES (1); PRAGMA user_version = 5;",
};
const S6: Migration = Migration {
    version: 6,
    sql: "CREATE TABLE fifth (y INTEGER); PRAGMA user_version = 6;",
};

fn version(c: &Connection) -> i64 {
    c.query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap()
}

fn schema(c: &Connection) -> Vec<(String, String)> {
    let mut s = c
        .prepare("SELECT type, name FROM sqlite_master ORDER BY 1, 2")
        .unwrap();
    s.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect()
}

#[test]
fn migrations_are_numbered_1_to_n_and_each_script_sets_its_own_version() {
    for (i, m) in MIGRATIONS.iter().enumerate() {
        assert_eq!(m.version, i64::try_from(i + 1).unwrap());
        assert!(
            m.sql
                .contains(&format!("PRAGMA user_version = {};", m.version))
        );
    }
}

#[test]
fn empty_database_migrates_from_zero() {
    let (f, idx) = open_new();
    assert_eq!(version(&idx.conn), 4);
    let names: Vec<_> = schema(&idx.conn).into_iter().map(|(_, n)| n).collect();
    for want in [
        "segments",
        "segments_camera_start",
        "segments_tier_end",
        "cameras",
        "api_tokens",
    ] {
        assert!(names.iter().any(|n| n == want), "{want}");
    }
    assert!(!names.iter().any(|n| n == "schema_version"));
    drop(idx);
    assert_eq!(version(&raw(&f.path)), 4);
}

#[test]
fn older_database_migrates_step_by_step_keeping_its_rows() {
    let f = fixture();
    let mut idx = Index::open(&f.path).unwrap();
    idx.insert(&rec("cam1", BASE, 1000, 5, 1), Tier::Hot)
        .unwrap();
    drop(idx);
    let v5 = [
        MIGRATIONS[0],
        MIGRATIONS[1],
        MIGRATIONS[2],
        MIGRATIONS[3],
        S5,
        S6,
    ];
    let idx = Index::open_with(&f.path, &v5, || {}).unwrap();
    assert_eq!(version(&idx.conn), 6);
    let rows: i64 = idx
        .conn
        .query_row("SELECT count(*) FROM segments", [], |r| r.get(0))
        .unwrap();
    assert_eq!(rows, 1);
    let extra: i64 = idx
        .conn
        .query_row("SELECT x FROM extra", [], |r| r.get(0))
        .unwrap();
    assert_eq!(extra, 1);
}

#[test]
fn a_failing_step_rolls_back_alone_and_the_older_version_stays_usable() {
    let f = fixture();
    drop(Index::open(&f.path).unwrap());
    let bad = Migration {
        version: 5,
        sql: "CREATE TABLE half (x); SELECT * FROM nope; PRAGMA user_version = 5;",
    };
    let err = Index::open_with(
        &f.path,
        &[
            MIGRATIONS[0],
            MIGRATIONS[1],
            MIGRATIONS[2],
            MIGRATIONS[3],
            bad,
        ],
        || {},
    )
    .unwrap_err();
    assert!(
        matches!(err, IndexError::Migration { version: 5, .. }),
        "{err:?}"
    );
    let mut idx = Index::open(&f.path).unwrap();
    assert_eq!(version(&idx.conn), 4);
    assert!(!schema(&idx.conn).iter().any(|(_, n)| n == "half"));
    idx.insert(&rec("cam1", BASE, 1000, 5, 1), Tier::Hot)
        .unwrap();
}

#[test]
fn step_one_commits_even_when_step_two_fails() {
    let f = fixture();
    let bad = Migration {
        version: 2,
        sql: "SELECT * FROM nope;",
    };
    let err = Index::open_with(&f.path, &[MIGRATIONS[0], bad], || {}).unwrap_err();
    assert!(matches!(err, IndexError::Migration { version: 2, .. }));
    assert_eq!(version(&raw(&f.path)), 1);
}

#[test]
fn a_script_that_forgets_its_version_is_rolled_back() {
    let f = fixture();
    drop(Index::open(&f.path).unwrap());
    let lazy = Migration {
        version: 5,
        sql: "CREATE TABLE lazy (x);",
    };
    let err = Index::open_with(
        &f.path,
        &[
            MIGRATIONS[0],
            MIGRATIONS[1],
            MIGRATIONS[2],
            MIGRATIONS[3],
            lazy,
        ],
        || {},
    )
    .unwrap_err();
    assert!(
        matches!(err, IndexError::MigrationDidNotAdvance { version: 5 }),
        "{err:?}"
    );
    let c = raw(&f.path);
    assert_eq!(version(&c), 4);
    assert!(!schema(&c).iter().any(|(_, n)| n == "lazy"));
}

#[test]
fn newer_version_is_a_typed_error_and_the_file_is_untouched() {
    for newer in [5_i64, 6, 1_000_000, i64::from(i32::MAX)] {
        let f = fixture();
        drop(Index::open(&f.path).unwrap());
        raw(&f.path)
            .execute_batch(&format!("PRAGMA user_version = {newer};"))
            .unwrap();
        let before = snapshot(f.dir.path());
        let err = Index::open(&f.path).unwrap_err();
        assert!(
            matches!(err, IndexError::SchemaTooNew { found, supported: 4 } if found == newer),
            "{err:?}"
        );
        assert_eq!(before, snapshot(f.dir.path()), "version {newer}");
    }
}

#[test]
fn negative_version_is_refused_untouched() {
    let f = fixture();
    drop(Index::open(&f.path).unwrap());
    raw(&f.path)
        .execute_batch("PRAGMA user_version = -5;")
        .unwrap();
    let before = snapshot(f.dir.path());
    assert!(matches!(
        Index::open(&f.path).unwrap_err(),
        IndexError::InvalidSchemaVersion { found: -5 }
    ));
    assert_eq!(before, snapshot(f.dir.path()));
}

/// The statements of a script, split on `;` (the scripts here hold no `;` inside strings).
fn statements(sql: &str) -> Vec<String> {
    sql.lines()
        .filter(|l| !l.trim_start().starts_with("--"))
        .collect::<Vec<_>>()
        .join("\n")
        .split(';')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| format!("{s};"))
        .collect()
}

/// Crash image: copy main and -wal while the migration transaction is open after `k` statements.
/// The copy is what a power cut would leave; it must open at the old version, usable.
#[test]
fn a_crash_after_any_statement_of_a_migration_leaves_the_old_version_usable() {
    // Migrations 1 to 4 from empty (real); migration 5 (synthetic) on top, with a real row.
    let m = [
        MIGRATIONS[0],
        MIGRATIONS[1],
        MIGRATIONS[2],
        MIGRATIONS[3],
        S5,
    ];
    for step in m {
        let base = &m[..usize::try_from(step.version - 1).unwrap()];
        let label = step.version;
        let stmts = statements(step.sql);
        assert!(stmts.len() >= 2, "{label}");
        for k in 0..=stmts.len() {
            let src = fixture();
            let old_version = i64::try_from(base.len()).unwrap();
            let mut idx = Index::open_with(&src.path, base, || {}).unwrap();
            if !base.is_empty() {
                idx.insert(&rec("cam1", BASE, 1000, 5, 1), Tier::Hot)
                    .unwrap();
            }
            drop(idx);
            let mut c = raw(&src.path);
            let tx = c
                .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                .unwrap();
            for s in stmts.iter().take(k) {
                tx.execute_batch(s).unwrap();
            }
            // Snapshot with the transaction still open: what the disk holds at the crash.
            let dst = fixture();
            for suffix in ["", "-wal"] {
                let mut from = src.path.as_os_str().to_owned();
                from.push(suffix);
                let mut to = dst.path.as_os_str().to_owned();
                to.push(suffix);
                if std::path::Path::new(&from).exists() {
                    std::fs::copy(&from, &to).unwrap();
                    chmod(std::path::Path::new(&to), 0o600);
                }
            }
            drop(tx);
            drop(c);
            let probe = Connection::open(&dst.path).unwrap();
            // Opened as the crashed process would restart: old version, intact schema.
            assert_eq!(version(&probe), old_version, "m{label} k={k}");
            drop(probe);
            let mut idx = Index::open_with(&dst.path, &m[..=base.len()], || {}).unwrap();
            assert_eq!(version(&idx.conn), step.version, "m{label} k={k}");
            idx.insert(&rec("cam1", BASE + 60_000, 1000, 5, 1), Tier::Hot)
                .unwrap();
        }
    }
}

/// A failure injected after `k` statements: the transaction rolls back to the exact old schema.
#[test]
fn a_failure_after_any_statement_rolls_back_to_the_exact_old_schema() {
    let all = [
        MIGRATIONS[0],
        MIGRATIONS[1],
        MIGRATIONS[2],
        MIGRATIONS[3],
        S5,
    ];
    for step in all {
        let stmts = statements(step.sql);
        let base: Vec<Migration> = all[..usize::try_from(step.version - 1).unwrap()].to_vec();
        for k in 0..stmts.len() {
            let f = fixture();
            drop(Index::open_with(&f.path, &base, || {}).unwrap());
            let before = schema(&raw(&f.path));
            let mut script: String = stmts.iter().take(k).cloned().collect::<Vec<_>>().join("\n");
            script.push_str("\nSELECT * FROM table_that_does_not_exist;");
            let leaked: &'static str = Box::leak(script.into_boxed_str());
            let mut migs = base.clone();
            migs.push(Migration {
                version: step.version,
                sql: leaked,
            });
            let err = Index::open_with(&f.path, &migs, || {}).unwrap_err();
            assert!(matches!(err, IndexError::Migration { .. }), "k={k} {err:?}");
            let c = raw(&f.path);
            assert_eq!(schema(&c), before, "v{} k={k}", step.version);
            assert_eq!(version(&c), step.version - 1);
        }
    }
}
