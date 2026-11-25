//! The identity checks can fail (P3, TEST-8): every way a database can differ from the schema of
//! its version is refused, whether the difference is in the main file or only in the `-wal`, and
//! the refusal leaves the directory byte-identical.

use std::os::unix::fs::FileExt;

use rusqlite::Connection;
use wardenlens_core::storage::{SegmentIndex, Tier};

use super::*;
use crate::error::IndexError;
use crate::migrate::MIGRATIONS;
use crate::open::probe_wal_readonly;

#[derive(Debug, Clone, Copy)]
enum Mutation {
    ExtraTable,
    ExtraTrigger,
    ExtraView,
    ExtraIndex,
    MissingIndex,
    LooseSegmentsSql,
    /// A damaged b-tree: bytes of a page overwritten (main) or a root page pointed at the wrong
    /// page (`-wal`, where a frame cannot be altered without breaking its checksum).
    DamagedBtree,
}

const MUTATIONS: [Mutation; 7] = [
    Mutation::ExtraTable,
    Mutation::ExtraTrigger,
    Mutation::ExtraView,
    Mutation::ExtraIndex,
    Mutation::MissingIndex,
    Mutation::LooseSegmentsSql,
    Mutation::DamagedBtree,
];

fn apply_sql(c: &Connection, m: Mutation) {
    let sql = match m {
        Mutation::ExtraTable => "CREATE TABLE extra (x);",
        Mutation::ExtraTrigger => {
            "CREATE TRIGGER trg AFTER INSERT ON segments BEGIN SELECT 1; END;"
        }
        Mutation::ExtraView => "CREATE VIEW v AS SELECT id FROM segments;",
        Mutation::ExtraIndex => "CREATE INDEX extra_idx ON segments (bytes);",
        Mutation::MissingIndex => "DROP INDEX segments_tier_end;",
        Mutation::LooseSegmentsSql => {
            "PRAGMA writable_schema = ON; \
             UPDATE sqlite_master SET sql = replace(sql, ') STRICT', ')') WHERE name = 'segments'; \
             PRAGMA writable_schema = OFF;"
        }
        Mutation::DamagedBtree => {
            "PRAGMA writable_schema = ON; \
             UPDATE sqlite_master SET rootpage = 2 WHERE name = 'segments_tier_end'; \
             PRAGMA writable_schema = OFF;"
        }
    };
    c.execute_batch(sql).unwrap();
}

/// A closed index with a few rows, at `dir/index.db`.
fn base(dir: &std::path::Path) -> std::path::PathBuf {
    let path = dir.join("index.db");
    let mut idx = Index::open(&path).unwrap();
    for k in 0..40 {
        idx.insert(&rec("cam1", BASE + k * 10_000, 1000, 10, 1), Tier::Hot)
            .unwrap();
    }
    path
}

fn crash_image(src: &std::path::Path, to: &std::path::Path) {
    for s in ["", "-wal"] {
        let (mut a, mut b) = (src.as_os_str().to_owned(), to.as_os_str().to_owned());
        a.push(s);
        b.push(s);
        std::fs::copy(&a, &b).unwrap();
        chmod(std::path::Path::new(&b), 0o600);
    }
}

#[test]
fn every_schema_mutation_in_the_main_file_is_refused_untouched() {
    for m in MUTATIONS {
        let dir = private_tempdir();
        let path = base(dir.path());
        if let Mutation::DamagedBtree = m {
            // Overwrite the middle of the `segments` root page.
            let c = raw(&path);
            let root: i64 = c
                .query_row(
                    "SELECT rootpage FROM sqlite_master WHERE name = 'segments'",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            drop(c);
            let f = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
            f.write_all_at(&[0xff; 64], u64::try_from(root - 1).unwrap() * 4096 + 8)
                .unwrap();
        } else {
            let c = raw(&path);
            apply_sql(&c, m);
        }
        chmod(&path, 0o600);
        let before = snapshot(dir.path());
        let err = Index::open(&path).unwrap_err();
        let ok = match m {
            Mutation::DamagedBtree => matches!(err, IndexError::Damaged),
            _ => matches!(err, IndexError::UnexpectedSchema),
        };
        assert!(ok, "{m:?}: {err:?}");
        assert_eq!(before, snapshot(dir.path()), "{m:?}: directory changed");
    }
}

#[test]
fn every_schema_mutation_only_in_the_wal_is_refused_untouched() {
    for m in MUTATIONS {
        let dir = private_tempdir();
        let path = base(dir.path());
        let c = raw(&path); // WAL mode is persistent: the change stays in the `-wal`
        apply_sql(&c, m);
        let crash = private_tempdir();
        let crashed = crash.path().join("index.db");
        crash_image(&path, &crashed);
        drop(c);
        assert!(
            std::fs::metadata(format!("{}-wal", crashed.display()))
                .unwrap()
                .len()
                > 32
        );
        let before = snapshot(crash.path());
        let err = Index::open(&crashed).unwrap_err();
        assert!(matches!(err, IndexError::ForeignWal), "{m:?}: {err:?}");
        assert_eq!(before, snapshot(crash.path()), "{m:?}: directory changed");
    }
}

#[test]
fn an_extra_object_in_a_version_zero_index_is_refused() {
    let f = fixture();
    let c = raw(&f.path);
    c.execute_batch(crate::sql::BOOTSTRAP).unwrap();
    c.execute_batch("CREATE TABLE sneaky (x);").unwrap();
    drop(c);
    chmod(&f.path, 0o600);
    let before = snapshot(f.dir.path());
    assert!(matches!(
        Index::open(&f.path).unwrap_err(),
        IndexError::UnexpectedSchema
    ));
    assert_eq!(before, snapshot(f.dir.path()));
}

#[test]
fn the_reference_schema_is_built_from_the_migrations() {
    use crate::migrate::{reference_schema, schema_rows};
    let v0 = reference_schema(MIGRATIONS, 0).unwrap();
    assert_eq!(v0.len(), 1);
    assert_eq!(v0[0].1, "index_meta");
    let (_f, idx) = open_new();
    assert_eq!(
        reference_schema(MIGRATIONS, 1).unwrap(),
        schema_rows(&idx.conn).unwrap()
    );
}

/// The `-wal` probe writes neither the main file nor the `-wal`. On success a `-shm` may remain
/// (the read-write open uses it, so the probe never removes it); on refusal a `-shm` that did not
/// exist is gone again.
#[test]
fn the_wal_probe_writes_neither_main_nor_wal_and_removes_a_new_shm_only_on_refusal() {
    let dir = private_tempdir();
    let path = base(dir.path());
    let c = raw(&path);
    c.execute_batch(
        "INSERT INTO segments (camera_id, started_at_ms, duration_ms, ended_at_ms, bytes, \
         frame_count, tier) VALUES ('cam2', 1700000900000, 1000, 1700000901000, 5, 1, 0);",
    )
    .unwrap();
    let crash = private_tempdir();
    let crashed = crash.path().join("index.db");
    crash_image(&path, &crashed);
    drop(c);
    let main = std::fs::read(&crashed).unwrap();
    let wal = std::fs::read(format!("{}-wal", crashed.display())).unwrap();
    let file = wardenlens_fsutil::open_private_file(&crashed).unwrap();
    probe_wal_readonly(&crashed, &file, MIGRATIONS).unwrap();
    assert_eq!(main, std::fs::read(&crashed).unwrap());
    assert_eq!(
        wal,
        std::fs::read(format!("{}-wal", crashed.display())).unwrap()
    );
    assert!(
        crash.path().join("index.db-shm").exists(),
        "success leaves the -shm the probe created: removing it could race another opener"
    );
    // Refusal: a newer version only in the -wal, no -shm before: none after.
    let (dir2, p2) = {
        let live = private_tempdir();
        let lp = base(live.path());
        let c = raw(&lp);
        c.execute_batch("PRAGMA user_version = 99;").unwrap();
        let to = private_tempdir();
        let tp = to.path().join("index.db");
        crash_image(&lp, &tp);
        drop(c);
        (to, tp)
    };
    let f2 = wardenlens_fsutil::open_private_file(&p2).unwrap();
    assert!(matches!(
        probe_wal_readonly(&p2, &f2, MIGRATIONS),
        Err(IndexError::SchemaTooNew { found: 99, .. })
    ));
    assert!(!dir2.path().join("index.db-shm").exists());
}

/// The guards that keep the probe from writing, pinned (not just observed).
#[test]
fn probe_connection_is_read_only_and_never_checkpoints() {
    use rusqlite::config::DbConfig;
    let dir = private_tempdir();
    let path = base(dir.path());
    let file = wardenlens_fsutil::open_private_file(&path).unwrap();
    let conn = crate::open::open_wal_probe(&path, &file).unwrap();
    assert!(conn.is_readonly(rusqlite::MAIN_DB).unwrap());
    assert!(
        conn.db_config(DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE)
            .unwrap()
    );
    // It cannot write: a write transaction is refused.
    assert!(conn.execute_batch("CREATE TABLE nope (x)").is_err());
    // Our own main-file descriptor cannot write either.
    assert!(file.file().write_at(b"x", 0).is_err());
}

#[test]
fn every_index_gets_its_own_random_16_byte_instance_id() {
    let mut ids = std::collections::BTreeSet::new();
    for _ in 0..8 {
        let (_f, idx) = open_new();
        let id: Vec<u8> = idx
            .conn
            .query_row(crate::sql::INSTANCE_ID, [], |r| r.get(0))
            .unwrap();
        assert_eq!(id.len(), 16);
        ids.insert(id);
    }
    assert_eq!(ids.len(), 8, "instance ids collide");
}

/// A `-wal` made from an index with the same schema and a clean integrity check, but another
/// instance id, is refused and nothing is replayed (adversary r3, here with the exact variant).
#[test]
fn a_wal_of_another_index_is_foreign_even_when_it_is_a_clean_index() {
    let other = private_tempdir();
    let op = base(other.path());
    let oc = raw(&op);
    oc.execute_batch("VACUUM").unwrap();
    let wal = std::fs::read(format!("{}-wal", op.display())).unwrap();
    drop(oc);
    let dir = private_tempdir();
    let path = base(dir.path());
    let w = format!("{}-wal", path.display());
    std::fs::write(&w, &wal).unwrap();
    chmod(std::path::Path::new(&w), 0o600);
    let before = snapshot(dir.path());
    assert!(matches!(
        Index::open(&path).unwrap_err(),
        IndexError::ForeignWal
    ));
    assert_eq!(before, snapshot(dir.path()));
}

/// Two openers exclude each other: a held lock makes the open wait, then report `Busy`; after
/// the holder lets go it opens.
#[test]
fn a_held_file_lock_makes_a_second_open_wait_then_report_busy() {
    let f = fixture();
    drop(Index::open(&f.path).unwrap());
    let holder = wardenlens_fsutil::open_private_file(&f.path).unwrap();
    let lock = holder.try_lock_exclusive().unwrap().unwrap();
    let before = snapshot(f.dir.path());
    let err = Index::open_with_lock_wait(
        &f.path,
        MIGRATIONS,
        || {},
        std::time::Duration::from_millis(100),
    )
    .unwrap_err();
    assert!(
        matches!(
            err,
            IndexError::Busy {
                op: "lock index file"
            }
        ),
        "{err:?}"
    );
    assert_eq!(before, snapshot(f.dir.path()));
    drop(lock);
    drop(Index::open(&f.path).unwrap());
    // And the lock is not kept after a successful open: a second handle opens beside the first.
    let a = Index::open(&f.path).unwrap();
    let b = Index::open(&f.path).unwrap();
    drop((a, b));
}
