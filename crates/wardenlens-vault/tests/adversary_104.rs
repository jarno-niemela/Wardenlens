//! Adversarial tests for #104 (the read-only vault probe). Synthetic values only.

#![expect(
    clippy::unwrap_used,
    reason = "integration-test helpers outside #[test] fns; clippy.toml in-tests allowances do not reach them"
)]

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::time::Duration;

use secrecy::SecretString;
use tempfile::TempDir;
use wardenlens_core::entry::{EntryId, EntryKind};
use wardenlens_secrets::KeyFile;
use wardenlens_vault::{Scan, Value, Vault, VaultError};

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

fn new_vault(tmp: &TempDir) -> std::path::PathBuf {
    let db = tmp.path().join("v.db");
    let mut v = Vault::create(&db, KeyFile::generate(&tmp.path().join("k")).unwrap()).unwrap();
    v.set(
        &EntryId::new("secret:one").unwrap(),
        EntryKind::Secret,
        &Value::Text(SecretString::from("synthetic-value-0123456789")),
        Scan::Normal,
    )
    .unwrap();
    drop(v);
    db
}

fn load_key(tmp: &TempDir) -> KeyFile {
    KeyFile::load(&tmp.path().join("k")).unwrap()
}

/// ADR 0006 section 3: "Every connection sets a busy timeout of 5 seconds, so a scan during a
/// write waits instead of failing." A writer in another connection holds the vault's own
/// `-journal` for a moment; `open` must wait for it, not report the vault as uninitialised.
#[test]
fn open_during_a_concurrent_write_waits_instead_of_failing() {
    let tmp = dir();
    let db = new_vault(&tmp);
    let writer = rusqlite::Connection::open(&db).unwrap();
    writer
        .execute_batch("BEGIN IMMEDIATE; UPDATE entries SET updated_at = updated_at + 1;")
        .unwrap();
    assert!(
        tmp.path().join("v.db-journal").exists(),
        "fixture: the writer holds a rollback journal"
    );
    let releaser = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(300));
        writer.execute_batch("COMMIT;").unwrap();
    });
    let res = Vault::open(&db, load_key(&tmp));
    releaser.join().unwrap();
    assert!(res.is_ok(), "open during a write failed: {res:?}");
}

/// Same, for `create` on an existing vault: a concurrent write must not turn
/// `AlreadyInitialized` into `NotEmpty`.
#[test]
fn create_during_a_concurrent_write_still_reports_already_initialized() {
    let tmp = dir();
    let db = new_vault(&tmp);
    let writer = rusqlite::Connection::open(&db).unwrap();
    writer
        .execute_batch("BEGIN IMMEDIATE; UPDATE entries SET updated_at = updated_at + 1;")
        .unwrap();
    let releaser = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(300));
        writer.execute_batch("COMMIT;").unwrap();
    });
    let res = Vault::create(&db, load_key(&tmp));
    releaser.join().unwrap();
    assert!(
        matches!(res, Err(VaultError::AlreadyInitialized)),
        "{res:?}"
    );
}

/// A genuine vault after an unclean shutdown in the middle of a write (a hot `-journal` in its
/// own directory). Before #104 SQLite rolled the journal back on the next open. It must not now
/// be reported as "not an initialised vault": that is false, and the obvious "fix" a user would
/// try (deleting the journal) corrupts the vault.
#[test]
fn open_after_a_crash_mid_write_is_not_reported_as_uninitialized() {
    let tmp = dir();
    let db = new_vault(&tmp);
    let journal = tmp.path().join("v.db-journal");
    let writer = rusqlite::Connection::open(&db).unwrap();
    writer
        .execute_batch(
            "PRAGMA cache_size = 1; BEGIN;
             UPDATE entries SET record = randomblob(3000), updated_at = 1;
             INSERT INTO entries SELECT 'secret:pad' || value, 6, randomblob(3000), 0, 1, 1
               FROM generate_series(1, 20);",
        )
        .unwrap_or_else(|_| {
            // generate_series may be missing: fall back to a recursive CTE.
            writer
                .execute_batch(
                    "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 20)
                     INSERT INTO entries SELECT 'secret:pad' || i, 6, randomblob(3000), 0, 1, 1 FROM n;",
                )
                .unwrap();
        });
    let snap_main = std::fs::read(&db).unwrap();
    let snap_j = std::fs::read(&journal).unwrap();
    drop(writer);
    std::fs::write(&db, &snap_main).unwrap();
    std::fs::write(&journal, &snap_j).unwrap();
    let res = Vault::open(&db, load_key(&tmp));
    let v = res.unwrap_or_else(|e| panic!("crashed genuine vault did not open: {e:?}"));
    // Rolled back to the last committed state: the padding rows are gone, the entry is intact.
    let ids: Vec<_> = v.list().unwrap().into_iter().map(|i| i.id).collect();
    assert_eq!(ids, [EntryId::new("secret:one").unwrap()]);
    assert!(v.get(&ids[0]).unwrap().is_some());
}

/// A zero-length `-journal` (not hot; SQLite ignores it) next to a healthy vault.
#[test]
fn open_with_an_empty_stale_journal_is_not_reported_as_uninitialized() {
    let tmp = dir();
    let db = new_vault(&tmp);
    std::fs::write(tmp.path().join("v.db-journal"), b"").unwrap();
    let res = Vault::open(&db, load_key(&tmp));
    assert!(res.is_ok(), "healthy vault with an empty journal: {res:?}");
}

/// `create` on an empty file must leave a foreign sidecar of the same name alone (SQLite
/// deletes a `-journal` / `-wal` next to a zero-page database on first open).
#[test]
fn create_on_an_empty_file_leaves_a_foreign_journal_sidecar_unchanged() {
    create_on_empty_with_sidecar("-journal");
}

#[test]
fn create_on_an_empty_file_leaves_a_foreign_wal_sidecar_unchanged() {
    create_on_empty_with_sidecar("-wal");
}

fn create_on_empty_with_sidecar(suffix: &str) {
    {
        let tmp = dir();
        let db = tmp.path().join("v.db");
        std::fs::write(&db, b"").unwrap();
        std::fs::set_permissions(&db, std::fs::Permissions::from_mode(0o600)).unwrap();
        let side = tmp.path().join(format!("v.db{suffix}"));
        std::fs::write(&side, b"synthetic foreign sidecar bytes").unwrap();
        let _ = Vault::create(&db, KeyFile::generate(&tmp.path().join("k")).unwrap());
        assert_eq!(
            std::fs::read(&side).ok().as_deref(),
            Some(&b"synthetic foreign sidecar bytes"[..]),
            "create removed or changed a foreign {suffix} sidecar"
        );
    }
}

/// The probe doc says the schema must be "exactly the vault schema ... nothing else". A vault
/// file to which a trigger has been added is not exactly the vault schema.
#[test]
fn open_refuses_a_vault_with_an_extra_trigger() {
    let tmp = dir();
    let db = new_vault(&tmp);
    let c = rusqlite::Connection::open(&db).unwrap();
    c.execute_batch(
        "CREATE TRIGGER t AFTER INSERT ON entries BEGIN
           UPDATE meta SET value = NEW.record WHERE key = 'schema_version'; END;",
    )
    .unwrap();
    drop(c);
    let res = Vault::open(&db, load_key(&tmp));
    assert!(res.is_err(), "vault with an injected trigger opened");
}

/// A view or index is also not part of the vault schema.
#[test]
fn open_refuses_a_vault_with_an_extra_view() {
    let tmp = dir();
    let db = new_vault(&tmp);
    let c = rusqlite::Connection::open(&db).unwrap();
    c.execute_batch("CREATE VIEW w AS SELECT id FROM entries;")
        .unwrap();
    drop(c);
    let res = Vault::open(&db, load_key(&tmp));
    assert!(res.is_err(), "vault with an extra view opened");
}

/// A genuine vault whose schema page is damaged is corrupt, not "not initialised" (the ticket:
/// only "not a database" and schema errors mean "not a vault").
#[test]
fn open_on_a_vault_with_a_damaged_schema_page_is_not_reported_as_uninitialized() {
    let tmp = dir();
    let db = new_vault(&tmp);
    let mut bytes = std::fs::read(&db).unwrap();
    // Page 1 b-tree header starts at offset 100; break the page type.
    bytes[100] = 0x07;
    std::fs::write(&db, &bytes).unwrap();
    let res = Vault::open(&db, load_key(&tmp));
    assert!(
        !matches!(res, Err(VaultError::NotInitialized)),
        "corrupt vault reported as not initialised"
    );
    assert_eq!(std::fs::read(&db).unwrap(), bytes, "open modified it");
}

// ---- passing coverage ----

/// Exact vault schema but no keycheck and a wrong version: typed errors, file unchanged.
#[test]
fn open_on_a_lookalike_with_the_vault_schema_is_typed_and_unchanged() {
    let tmp = dir();
    let db = tmp.path().join("v.db");
    let c = rusqlite::Connection::open(&db).unwrap();
    c.execute_batch(
        "CREATE TABLE meta(key TEXT PRIMARY KEY, value BLOB NOT NULL);
         CREATE TABLE entries(id TEXT PRIMARY KEY, kind INTEGER NOT NULL, record BLOB NOT NULL,
           unscannable INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL,
           updated_at INTEGER NOT NULL);
         INSERT INTO meta VALUES ('schema_version', CAST('2' AS BLOB));",
    )
    .unwrap();
    drop(c);
    std::fs::set_permissions(&db, std::fs::Permissions::from_mode(0o600)).unwrap();
    let kf = KeyFile::generate(&tmp.path().join("k")).unwrap();
    let before = std::fs::read(&db).unwrap();
    let names = listing(tmp.path());
    let res = Vault::open(&db, kf);
    assert!(matches!(res, Err(VaultError::UnsupportedSchema)), "{res:?}");
    assert_eq!(std::fs::read(&db).unwrap(), before);
    assert_eq!(listing(tmp.path()), names);

    let c = rusqlite::Connection::open(&db).unwrap();
    c.execute_batch("UPDATE meta SET value = CAST('1' AS BLOB);")
        .unwrap();
    drop(c);
    let before = std::fs::read(&db).unwrap();
    let res = Vault::open(&db, load_key(&tmp));
    assert!(matches!(res, Err(VaultError::NotInitialized)), "{res:?}");
    assert_eq!(std::fs::read(&db).unwrap(), before);

    let res = Vault::create(&db, load_key(&tmp));
    assert!(
        matches!(res, Err(VaultError::AlreadyInitialized)),
        "{res:?}"
    );
    assert_eq!(std::fs::read(&db).unwrap(), before);
}

/// Wrong key on a genuine vault: `WrongKey`, nothing written, no sidecar left behind, and the
/// error text carries no key or ciphertext bytes (SEC-6).
#[test]
fn open_with_the_wrong_key_is_refused_read_only() {
    let tmp = dir();
    let db = new_vault(&tmp);
    let other = KeyFile::generate(&tmp.path().join("k2")).unwrap();
    let before = std::fs::read(&db).unwrap();
    let names = listing(tmp.path());
    let res = Vault::open(&db, other);
    let Err(e) = res else {
        panic!("wrong key accepted")
    };
    assert!(matches!(e, VaultError::WrongKey), "{e:?}");
    let msg = format!("{e} {e:?}");
    assert!(!msg.contains("synthetic"), "{msg}");
    assert_eq!(std::fs::read(&db).unwrap(), before);
    assert_eq!(listing(tmp.path()), names);
}

/// A foreign rollback DB with the exact table names but different columns is not a vault,
/// on either entry point, and is left as it was.
#[test]
fn lookalike_tables_with_other_columns_are_not_a_vault() {
    let tmp = dir();
    let db = tmp.path().join("v.db");
    let c = rusqlite::Connection::open(&db).unwrap();
    c.execute_batch(
        "CREATE TABLE meta(key TEXT, value BLOB); CREATE TABLE entries(id TEXT);
         INSERT INTO meta VALUES ('schema_version', '1');",
    )
    .unwrap();
    drop(c);
    std::fs::set_permissions(&db, std::fs::Permissions::from_mode(0o600)).unwrap();
    let before = std::fs::read(&db).unwrap();
    let kf = KeyFile::generate(&tmp.path().join("k")).unwrap();
    let res = Vault::open(&db, kf);
    assert!(matches!(res, Err(VaultError::NotInitialized)), "{res:?}");
    let res = Vault::create(&db, load_key(&tmp));
    assert!(matches!(res, Err(VaultError::NotEmpty)), "{res:?}");
    assert_eq!(std::fs::read(&db).unwrap(), before);
}

/// Round trip: create, write, reopen and rekey all keep working; no sidecar is left.
#[test]
fn genuine_vault_round_trips_and_leaves_no_sidecar() {
    let tmp = dir();
    let db = new_vault(&tmp);
    let mut v = Vault::open(&db, load_key(&tmp)).unwrap();
    let new = KeyFile::generate(&tmp.path().join("k2")).unwrap();
    v.rekey(new).unwrap();
    drop(v);
    let v = Vault::open(&db, KeyFile::load(&tmp.path().join("k2")).unwrap()).unwrap();
    assert!(
        v.get(&EntryId::new("secret:one").unwrap())
            .unwrap()
            .is_some()
    );
    drop(v);
    assert_eq!(
        listing(tmp.path()),
        ["k", "k2", "v.db"].map(std::ffi::OsString::from)
    );
}

/// Leaves a hot journal next to a real vault: a mid-transaction snapshot of main + journal.
fn crash_with_hot_journal(tmp: &TempDir, db: &Path) -> (Vec<u8>, Vec<u8>) {
    let journal = tmp.path().join("v.db-journal");
    let writer = rusqlite::Connection::open(db).unwrap();
    writer
        .execute_batch(
            "PRAGMA cache_size = 1; BEGIN;
             UPDATE entries SET record = randomblob(3000), updated_at = 1;
             WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 20)
             INSERT INTO entries SELECT 'secret:pad' || i, 6, randomblob(3000), 0, 1, 1 FROM n;",
        )
        .unwrap();
    let snap_main = std::fs::read(db).unwrap();
    let snap_j = std::fs::read(&journal).unwrap();
    drop(writer);
    std::fs::write(db, &snap_main).unwrap();
    std::fs::write(&journal, &snap_j).unwrap();
    (snap_main, snap_j)
}

/// A crash after entry pages (but not the keycheck page) were rewritten still opens with the
/// old key, data intact.
#[test]
fn crash_with_only_entry_pages_rewritten_opens_with_the_old_key() {
    let tmp = dir();
    let db = new_vault(&tmp);
    let journal = tmp.path().join("v.db-journal");
    let writer = rusqlite::Connection::open(&db).unwrap();
    writer
        .execute_batch(
            "PRAGMA cache_size = 1; BEGIN IMMEDIATE;
             UPDATE entries SET record = randomblob(3000), updated_at = 5;
             WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 20)
             INSERT INTO entries SELECT 'secret:pad' || i, 6, randomblob(3000), 0, 1, 1 FROM n;",
        )
        .unwrap();
    let snap_main = std::fs::read(&db).unwrap();
    let snap_j = std::fs::read(&journal).unwrap();
    drop(writer);
    std::fs::write(&db, &snap_main).unwrap();
    std::fs::write(&journal, &snap_j).unwrap();
    let v = Vault::open(&db, load_key(&tmp)).unwrap();
    let got = v.get(&EntryId::new("secret:one").unwrap()).unwrap();
    assert!(got.is_some(), "entry lost or unreadable after rollback");
}

/// A foreign database with a hot journal: refused, both files byte-identical.
#[test]
fn foreign_db_with_a_hot_journal_is_refused_and_unchanged() {
    let tmp = dir();
    let db = tmp.path().join("v.db");
    let journal = tmp.path().join("v.db-journal");
    let c = rusqlite::Connection::open(&db).unwrap();
    c.execute_batch(
        "CREATE TABLE t(a BLOB); INSERT INTO t VALUES (randomblob(3000));
         PRAGMA cache_size = 1; BEGIN; UPDATE t SET a = randomblob(3000);
         INSERT INTO t SELECT randomblob(3000) FROM t;",
    )
    .unwrap();
    let (m, j) = (
        std::fs::read(&db).unwrap(),
        std::fs::read(&journal).unwrap(),
    );
    drop(c);
    std::fs::write(&db, &m).unwrap();
    std::fs::write(&journal, &j).unwrap();
    std::fs::set_permissions(&db, std::fs::Permissions::from_mode(0o600)).unwrap();
    let kf = KeyFile::generate(&tmp.path().join("k")).unwrap();
    let res = Vault::open(&db, kf);
    assert!(matches!(res, Err(VaultError::NotInitialized)), "{res:?}");
    assert_eq!(std::fs::read(&db).unwrap(), m);
    assert_eq!(std::fs::read(&journal).unwrap(), j);
}

/// The wrong key on a real vault with a hot journal is `WrongKey` (judged on a rolled-back
/// private copy), and both files stay unchanged: the real file is never opened read-write.
#[test]
fn wrong_key_with_a_hot_journal_is_wrong_key_and_unchanged() {
    let tmp = dir();
    let db = new_vault(&tmp);
    let (m, j) = crash_with_hot_journal(&tmp, &db);
    let other = KeyFile::generate(&tmp.path().join("k2")).unwrap();
    let res = Vault::open(&db, other);
    assert!(matches!(res, Err(VaultError::WrongKey)), "{res:?}");
    assert_eq!(std::fs::read(&db).unwrap(), m);
    assert_eq!(std::fs::read(tmp.path().join("v.db-journal")).unwrap(), j);
}

/// `create` with a hot journal that never goes away is `PendingJournal`, nothing removed.
#[test]
fn create_with_a_hot_journal_is_pending_journal_and_unchanged() {
    let tmp = dir();
    let db = new_vault(&tmp);
    let (m, j) = crash_with_hot_journal(&tmp, &db);
    let res = Vault::create(&db, load_key(&tmp));
    assert!(matches!(res, Err(VaultError::PendingJournal)), "{res:?}");
    assert_eq!(std::fs::read(&db).unwrap(), m);
    assert_eq!(std::fs::read(tmp.path().join("v.db-journal")).unwrap(), j);
}

/// A torn `meta` page in the main file (garbage) with a valid journal that restores it: the old
/// key opens, because identification runs on the rolled-back copy.
#[test]
fn torn_meta_page_restored_by_the_journal_opens_with_the_old_key() {
    let tmp = dir();
    let db = new_vault(&tmp);
    let journal = tmp.path().join("v.db-journal");
    let writer = rusqlite::Connection::open(&db).unwrap();
    writer
        .execute_batch(
            "PRAGMA cache_size = 1; BEGIN IMMEDIATE;
             UPDATE meta SET value = randomblob(length(value));
             WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 30)
             INSERT INTO entries SELECT 'secret:pad' || i, 6, randomblob(3000), 0, 1, 1 FROM n;",
        )
        .unwrap();
    let snap_main = std::fs::read(&db).unwrap();
    let snap_j = std::fs::read(&journal).unwrap();
    drop(writer);
    // Tear the page that holds `meta` (its root page, which the journal has the original of).
    let root: usize = rusqlite::Connection::open(&db)
        .map(|c| {
            c.query_row(
                "SELECT rootpage FROM sqlite_master WHERE name = 'meta'",
                [],
                |r| r.get::<_, i64>(0),
            )
        })
        .unwrap()
        .unwrap()
        .try_into()
        .unwrap();
    let page = 4096;
    let mut torn = snap_main.clone();
    torn[(root - 1) * page + 100..root * page].fill(0xA5);
    std::fs::write(&db, &torn).unwrap();
    std::fs::write(&journal, &snap_j).unwrap();
    let v = Vault::open(&db, load_key(&tmp)).unwrap();
    assert!(
        v.get(&EntryId::new("secret:one").unwrap())
            .unwrap()
            .is_some()
    );
}
