//! Round-2 adversarial tests for #104 (probe wait / recover / refuse). Synthetic values only.

#![expect(
    clippy::unwrap_used,
    reason = "integration-test helpers outside #[test] fns; clippy.toml in-tests allowances do not reach them"
)]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
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

fn id(s: &str) -> EntryId {
    EntryId::new(s).unwrap()
}

fn text(s: &str) -> Value {
    Value::Text(SecretString::from(s.to_owned()))
}

/// A vault at `<tmp>/<name>` sealed under `<tmp>/<keyname>`, with `n` secret entries.
fn vault_with(tmp: &TempDir, name: &str, keyname: &str, n: usize) -> PathBuf {
    let db = tmp.path().join(name);
    let mut v = Vault::create(&db, KeyFile::generate(&tmp.path().join(keyname)).unwrap()).unwrap();
    for i in 0..n {
        v.set(
            &id(&format!("secret:s{i}")),
            EntryKind::Secret,
            &text(&format!("synthetic-value-{i:04}-abcdefghij")),
            Scan::Normal,
        )
        .unwrap();
    }
    drop(v);
    db
}

fn keycheck_of(db: &Path) -> Vec<u8> {
    let c = rusqlite::Connection::open(db).unwrap();
    c.query_row("SELECT value FROM meta WHERE key = 'keycheck'", [], |r| {
        r.get(0)
    })
    .unwrap()
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

/// Builds the on-disk image of a process that died in the middle of `Vault::rekey` from key `k`
/// to key `k2`: the new keycheck has already reached the main file (spilled page), the old
/// page images are in the hot `-journal`. Returns (main, journal, new keycheck).
fn crash_mid_rekey(tmp: &TempDir) -> (PathBuf, Vec<u8>, Vec<u8>, Vec<u8>) {
    let db = vault_with(tmp, "v.db", "k", 30);
    // A second vault under the new key supplies a genuine keycheck sealed under `k2`.
    let other = vault_with(tmp, "other.db", "k2", 0);
    let new_kc = keycheck_of(&other);
    std::fs::remove_file(&other).unwrap();
    let journal = tmp.path().join("v.db-journal");
    let writer = rusqlite::Connection::open(&db).unwrap();
    writer
        .execute_batch("PRAGMA cache_size = 1; BEGIN IMMEDIATE;")
        .unwrap();
    // Same order as rekey's dirty set at commit: entries rewritten, then the keycheck.
    writer
        .execute_batch("UPDATE entries SET record = randomblob(length(record)), updated_at = 7;")
        .unwrap();
    writer
        .execute(
            "UPDATE meta SET value = ?1 WHERE key = 'keycheck'",
            [&new_kc],
        )
        .unwrap();
    // Force more spills so the dirty meta page reaches the main file.
    writer
        .execute_batch(
            "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 40)
             INSERT INTO entries SELECT 'secret:pad' || i, 2, randomblob(3000), 0, 1, 1 FROM n;",
        )
        .unwrap();
    let main = std::fs::read(&db).unwrap();
    let j = std::fs::read(&journal).unwrap();
    drop(writer);
    std::fs::write(&db, &main).unwrap();
    std::fs::write(&journal, &j).unwrap();
    assert!(
        contains(&main, &new_kc),
        "fixture: the new keycheck must already be in the main file"
    );
    (db, main, j, new_kc)
}

/// `Vault::rekey` rustdoc: "On any failure the transaction rolls back and the vault is
/// unchanged: the old key still opens it." A crash (power loss, SIGKILL) during rekey's commit
/// is such a failure. SQLite's own recovery would roll the journal back, so the old key should
/// open the vault. The probe instead reads the torn main file (new keycheck), sees `WrongKey` for
/// the old key, and refuses with `PendingJournal` without ever letting SQLite roll back.
#[test]
fn crash_mid_rekey_commit_still_opens_with_the_old_key() {
    let tmp = dir();
    let (db, _, _, _) = crash_mid_rekey(&tmp);
    let res = Vault::open(&db, KeyFile::load(&tmp.path().join("k")).unwrap());
    let v = res.unwrap_or_else(|e| panic!("old key refused after a crash mid-rekey: {e:?}"));
    let got = v.get(&id("secret:s0")).unwrap();
    assert!(got.is_some(), "entry lost after rollback");
}

/// The same state with the old key must at least be retried successfully: a second attempt
/// with the old key also ends in `PendingJournal` (it is a permanent state, not a transient
/// one), so the vault is unopenable with the key the caller actually holds.
#[test]
fn crash_mid_rekey_is_not_permanently_pending_for_the_old_key() {
    let tmp = dir();
    let (db, main, j, _) = crash_mid_rekey(&tmp);
    let k = || KeyFile::load(&tmp.path().join("k")).unwrap();
    let first = Vault::open(&db, k());
    let second = Vault::open(&db, k());
    // Whatever the first attempt did, the files must not have been modified by a refusal ...
    if first.is_err() {
        assert_eq!(std::fs::read(&db).unwrap(), main);
        assert_eq!(std::fs::read(tmp.path().join("v.db-journal")).unwrap(), j);
    }
    // ... and the vault must open eventually with the old key.
    assert!(
        first.is_ok() || second.is_ok(),
        "old key never opens: {first:?} / {second:?}"
    );
}

/// The "new key" side of the same crash: the main file holds the new keycheck but the rolled-back
/// state holds the old one, so the new key is `WrongKey`. The probe judges a private copy, so the
/// real main file and journal stay byte-identical, and the old key still opens afterwards.
/// (Before the copy-based probe this accepted the torn page, rolled the real files back and then
/// failed; the outcome is the same typed error but the files are no longer touched.)
#[test]
fn crash_mid_rekey_then_new_key_is_wrong_key_and_old_key_recovers() {
    let tmp = dir();
    let (db, main, j, _) = crash_mid_rekey(&tmp);
    let res = Vault::open(&db, KeyFile::load(&tmp.path().join("k2")).unwrap());
    assert!(matches!(res, Err(VaultError::WrongKey)), "{res:?}");
    drop(res);
    assert_eq!(std::fs::read(&db).unwrap(), main);
    assert_eq!(std::fs::read(tmp.path().join("v.db-journal")).unwrap(), j);
    assert!(
        !std::fs::read_dir(tmp.path()).unwrap().any(|e| e
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".wardenlens-probe")),
        "scratch directory left behind"
    );
    let res = Vault::open(&db, KeyFile::load(&tmp.path().join("k")).unwrap());
    assert!(res.is_ok(), "old key after recovery: {res:?}");
}

/// Opens racing a stream of committed writes from another connection must all succeed (ADR 0006
/// section 3: a scan during a write waits). Exercises the window between the probe's journal
/// check and its immutable (lock-free) read of the main file.
#[test]
fn opens_racing_committed_writes_never_fail() {
    let tmp = dir();
    let db = vault_with(&tmp, "v.db", "k", 5);
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let writer = {
        let db = db.clone();
        let stop = stop.clone();
        std::thread::spawn(move || {
            let c = rusqlite::Connection::open(&db).unwrap();
            c.busy_timeout(Duration::from_secs(5)).unwrap();
            let mut i = 0u64;
            while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                c.execute_batch(
                    "BEGIN IMMEDIATE; UPDATE entries SET updated_at = updated_at + 1; COMMIT;",
                )
                .unwrap();
                i += 1;
            }
            i
        })
    };
    let mut failures = Vec::new();
    let start = std::time::Instant::now();
    let mut n = 0;
    while start.elapsed() < Duration::from_secs(3) {
        match Vault::open(&db, KeyFile::load(&tmp.path().join("k")).unwrap()) {
            Ok(v) => drop(v),
            Err(e) => failures.push(format!("{e:?}")),
        }
        n += 1;
    }
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    let write_count = writer.join().unwrap();
    assert!(write_count > 0 && n > 0);
    assert!(
        failures.is_empty(),
        "{} of {n} opens failed: {:?}",
        failures.len(),
        &failures[..failures.len().min(3)]
    );
}

/// A crash in the middle of `create` (hot journal for a database that had zero pages). The file
/// holds nothing of value; the API must not leave it in a state that neither `create` nor
/// `open` can ever get out of. Records what happens; nothing may be modified on refusal.
#[test]
fn crash_mid_create_is_refused_without_modification() {
    let tmp = dir();
    let db = tmp.path().join("v.db");
    std::fs::write(&db, b"").unwrap();
    std::fs::set_permissions(&db, std::fs::Permissions::from_mode(0o600)).unwrap();
    let journal = tmp.path().join("v.db-journal");
    let c = rusqlite::Connection::open(&db).unwrap();
    c.execute_batch(
        "PRAGMA journal_mode = DELETE; PRAGMA cache_size = 1; BEGIN IMMEDIATE;
         CREATE TABLE meta(key TEXT PRIMARY KEY, value BLOB NOT NULL);
         CREATE TABLE entries(id TEXT PRIMARY KEY, kind INTEGER NOT NULL, record BLOB NOT NULL,
           unscannable INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL,
           updated_at INTEGER NOT NULL);
         WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 40)
         INSERT INTO entries SELECT 'secret:pad' || i, 2, randomblob(3000), 0, 1, 1 FROM n;",
    )
    .unwrap();
    let main = std::fs::read(&db).unwrap();
    let j = std::fs::read(&journal).unwrap_or_default();
    drop(c);
    std::fs::write(&db, &main).unwrap();
    std::fs::write(&journal, &j).unwrap();
    let kf = KeyFile::generate(&tmp.path().join("k")).unwrap();
    let names = listing(tmp.path());
    let res = Vault::create(&db, kf);
    assert!(res.is_err(), "create over a crashed create: {res:?}");
    assert_eq!(std::fs::read(&db).unwrap(), main);
    assert_eq!(std::fs::read(&journal).unwrap(), j);
    assert_eq!(listing(tmp.path()), names);
}

/// SEC-6: the new error's text and debug form carry no value or path bytes.
#[test]
fn pending_journal_error_carries_no_values() {
    let e = VaultError::PendingJournal;
    let msg = format!("{e} {e:?}");
    assert!(!msg.contains('/'), "{msg}");
    assert!(!msg.contains("synthetic"), "{msg}");
}

/// A `-wal` next to a genuine rollback-mode vault: refused, both files untouched.
#[test]
fn stray_wal_next_to_a_genuine_vault_is_refused_and_untouched() {
    let tmp = dir();
    let db = vault_with(&tmp, "v.db", "k", 1);
    let wal = tmp.path().join("v.db-wal");
    std::fs::write(&wal, b"synthetic stray wal bytes").unwrap();
    let before = std::fs::read(&db).unwrap();
    let res = Vault::open(&db, KeyFile::load(&tmp.path().join("k")).unwrap());
    assert!(res.is_err(), "opened with a stray -wal: {res:?}");
    assert_eq!(std::fs::read(&db).unwrap(), before);
    assert_eq!(std::fs::read(&wal).unwrap(), b"synthetic stray wal bytes");
    let res = Vault::create(&db, KeyFile::load(&tmp.path().join("k")).unwrap());
    assert!(res.is_err());
    assert_eq!(std::fs::read(&wal).unwrap(), b"synthetic stray wal bytes");
}

/// A foreign DB with a hot journal under `create`: `PendingJournal` or `NotEmpty`, nothing modified.
#[test]
fn create_on_a_foreign_db_with_a_hot_journal_leaves_both_unchanged() {
    let tmp = dir();
    let db = tmp.path().join("v.db");
    let journal = tmp.path().join("v.db-journal");
    let c = rusqlite::Connection::open(&db).unwrap();
    c.execute_batch(
        "CREATE TABLE meta(key TEXT PRIMARY KEY, value BLOB NOT NULL); CREATE TABLE t(a BLOB);
         INSERT INTO t VALUES (randomblob(3000));
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
    let res = Vault::create(&db, kf);
    assert!(
        matches!(res, Err(VaultError::PendingJournal | VaultError::NotEmpty)),
        "{res:?}"
    );
    assert_eq!(std::fs::read(&db).unwrap(), m);
    assert_eq!(std::fs::read(&journal).unwrap(), j);
}
