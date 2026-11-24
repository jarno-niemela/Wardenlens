//! Round-5 adversarial tests for the vault library (synthetic values only).

#![expect(
    clippy::unwrap_used,
    reason = "integration-test helpers outside #[test] fns; clippy.toml in-tests allowances do not reach them"
)]

use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use tempfile::TempDir;
use wardenlens_secrets::KeyFile;
use wardenlens_vault::{Vault, VaultError};

fn dir() -> TempDir {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    tmp
}

fn listing(tmp: &Path) -> Vec<std::ffi::OsString> {
    let mut names: Vec<_> = std::fs::read_dir(tmp)
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    names.sort();
    names
}

fn key(tmp: &TempDir, name: &str) -> KeyFile {
    KeyFile::generate(&tmp.path().join(name)).unwrap()
}

fn chmod600(db: &Path) {
    std::fs::set_permissions(db, std::fs::Permissions::from_mode(0o600)).unwrap();
}

/// A foreign WAL database that happens to have a table named `meta` (a common name) is not a
/// vault: `open` must refuse it without converting it out of WAL mode.
#[test]
fn open_on_a_foreign_wal_db_with_a_meta_table_leaves_it_unchanged() {
    let tmp = dir();
    let db = tmp.path().join("v.db");
    let conn = rusqlite::Connection::open(&db).unwrap();
    let _: String = conn
        .query_row("PRAGMA journal_mode = WAL", [], |res| res.get(0))
        .unwrap();
    conn.execute_batch(
        "CREATE TABLE meta(key TEXT, value BLOB); INSERT INTO meta VALUES ('k', 'synthetic');",
    )
    .unwrap();
    drop(conn);
    chmod600(&db);
    let before = std::fs::read(&db).unwrap();
    assert_eq!(before[18], 2, "fixture is in WAL mode");
    let kf = key(&tmp, "k");
    let names = listing(tmp.path());
    let res = Vault::open(&db, kf);
    assert!(res.is_err(), "{res:?}");
    assert_eq!(
        std::fs::read(&db).unwrap(),
        before,
        "open modified a foreign database it refused ({res:?})"
    );
    assert_eq!(listing(tmp.path()), names);
}

/// Same, with a crashed writer's `-wal` sidecar left behind: `open` must not checkpoint it into
/// the foreign main file or delete it.
#[test]
fn open_on_a_foreign_wal_db_with_meta_and_a_leftover_wal_leaves_both_unchanged() {
    let tmp = dir();
    let db = tmp.path().join("v.db");
    let wal = tmp.path().join("v.db-wal");
    let conn = rusqlite::Connection::open(&db).unwrap();
    let _: String = conn
        .query_row("PRAGMA journal_mode = WAL", [], |res| res.get(0))
        .unwrap();
    conn.execute_batch(
        "CREATE TABLE meta(key TEXT, value BLOB); PRAGMA wal_checkpoint(TRUNCATE);
         PRAGMA wal_autocheckpoint = 0; INSERT INTO meta VALUES ('k', 'synthetic');",
    )
    .unwrap();
    // Simulate a crash: copy the files while the writer still holds them.
    let snap_main = std::fs::read(&db).unwrap();
    let snap_wal = std::fs::read(&wal).unwrap();
    drop(conn);
    std::fs::write(&db, &snap_main).unwrap();
    std::fs::write(&wal, &snap_wal).unwrap();
    let _ = std::fs::remove_file(tmp.path().join("v.db-shm"));
    chmod600(&db);
    let kf = key(&tmp, "k");
    let res = Vault::open(&db, kf);
    assert!(res.is_err(), "{res:?}");
    assert_eq!(
        std::fs::read(&db).unwrap(),
        snap_main,
        "main file changed ({res:?})"
    );
    assert_eq!(
        std::fs::read(&wal).ok(),
        Some(snap_wal),
        "-wal sidecar changed or deleted ({res:?})"
    );
}

/// A foreign rollback database with `meta` and a hot journal: `open` must not roll the journal
/// back into the foreign file.
#[test]
fn open_on_a_foreign_db_with_meta_and_a_hot_journal_leaves_it_unchanged() {
    let tmp = dir();
    let db = tmp.path().join("v.db");
    let journal = tmp.path().join("v.db-journal");
    let conn = rusqlite::Connection::open(&db).unwrap();
    conn.execute_batch(
        "PRAGMA journal_mode = PERSIST; CREATE TABLE meta(key TEXT, value BLOB);
         INSERT INTO meta VALUES ('k', 'synthetic');",
    )
    .unwrap();
    // Leave a hot journal: mid-transaction snapshot of main + journal.
    conn.execute_batch(
        "PRAGMA cache_size = 1; BEGIN; INSERT INTO meta SELECT 'x', randomblob(20000);",
    )
    .unwrap();
    conn.execute_batch("INSERT INTO meta SELECT 'y', randomblob(20000);")
        .unwrap();
    let snap_main = std::fs::read(&db).unwrap();
    let snap_j = std::fs::read(&journal).unwrap();
    drop(conn);
    std::fs::write(&db, &snap_main).unwrap();
    std::fs::write(&journal, &snap_j).unwrap();
    chmod600(&db);
    let kf = key(&tmp, "k");
    let res = Vault::open(&db, kf);
    assert!(res.is_err(), "{res:?}");
    assert_eq!(
        std::fs::read(&db).unwrap(),
        snap_main,
        "main file changed ({res:?})"
    );
    assert_eq!(
        std::fs::read(&journal).unwrap(),
        snap_j,
        "journal changed ({res:?})"
    );
}

/// A truncated vault (only the 16-byte header) is refused by open, not accepted.
#[test]
fn open_on_a_bare_header_is_not_initialized_and_unchanged() {
    let tmp = dir();
    let db = tmp.path().join("v.db");
    std::fs::write(&db, b"SQLite format 3\0").unwrap();
    chmod600(&db);
    let res = Vault::open(&db, key(&tmp, "k"));
    assert!(matches!(res, Err(VaultError::NotInitialized)), "{res:?}");
    assert_eq!(std::fs::read(&db).unwrap(), b"SQLite format 3\0");
    let res = Vault::create(&db, KeyFile::load(&tmp.path().join("k")).unwrap());
    assert!(matches!(res, Err(VaultError::NotEmpty)), "{res:?}");
    assert_eq!(std::fs::read(&db).unwrap(), b"SQLite format 3\0");
}

/// Relative path (resolved against cwd for the probe) still opens the vault it created.
#[test]
fn open_after_create_round_trips_through_a_dot_dot_path() {
    let tmp = dir();
    std::fs::create_dir(tmp.path().join("sub")).unwrap();
    std::fs::set_permissions(
        tmp.path().join("sub"),
        std::fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    let db = tmp.path().join("sub").join("..").join("v.db");
    drop(Vault::create(&db, key(&tmp, "k")).unwrap());
    let kk = KeyFile::load(&tmp.path().join("k")).unwrap();
    assert!(Vault::open(&db, kk).is_ok());
}
