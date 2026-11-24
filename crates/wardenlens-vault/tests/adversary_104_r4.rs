//! Round-4 adversarial tests for #104 (retry cap, typed verdicts on the copy, odd journals).
//! Synthetic values only.

#![expect(
    clippy::unwrap_used,
    reason = "integration-test helpers outside #[test] fns; clippy.toml in-tests allowances do not reach them"
)]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

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

fn no_scratch_left(tmp: &Path) -> bool {
    !listing(tmp)
        .iter()
        .any(|n| n.to_string_lossy().starts_with(".wardenlens-probe"))
}

fn key(tmp: &TempDir) -> KeyFile {
    KeyFile::load(&tmp.path().join("k")).unwrap()
}

fn new_vault(tmp: &TempDir) -> PathBuf {
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

/// Leaves a hot journal after running `sql` inside an open transaction. Returns (main, journal).
fn crash_after(db: &Path, sql: &str) -> (Vec<u8>, Vec<u8>) {
    let journal = PathBuf::from(format!("{}-journal", db.display()));
    let w = rusqlite::Connection::open(db).unwrap();
    w.execute_batch("PRAGMA cache_size = 1; BEGIN IMMEDIATE;")
        .unwrap();
    w.execute_batch(sql).unwrap();
    w.execute_batch(
        "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 30)
         INSERT INTO entries SELECT 'secret:pad' || i, 6, randomblob(3000), 0, 1, 1 FROM n;",
    )
    .unwrap();
    let m = std::fs::read(db).unwrap();
    let j = std::fs::read(&journal).unwrap();
    drop(w);
    std::fs::write(db, &m).unwrap();
    std::fs::write(&journal, &j).unwrap();
    (m, j)
}

/// An unknown schema version committed before the crash is `UnsupportedSchema` when judged on
/// the rolled-back copy, and both files stay byte-identical.
#[test]
fn hot_journal_on_an_unsupported_schema_is_typed_and_unchanged() {
    let tmp = dir();
    let db = new_vault(&tmp);
    {
        let c = rusqlite::Connection::open(&db).unwrap();
        c.execute(
            "UPDATE meta SET value = X'32' WHERE key = 'schema_version'",
            [],
        )
        .unwrap();
    }
    let (m, j) = crash_after(&db, "UPDATE entries SET updated_at = 9;");
    let res = Vault::open(&db, key(&tmp));
    assert!(matches!(res, Err(VaultError::UnsupportedSchema)), "{res:?}");
    assert_eq!(std::fs::read(&db).unwrap(), m);
    assert_eq!(std::fs::read(tmp.path().join("v.db-journal")).unwrap(), j);
    assert!(no_scratch_left(tmp.path()));
}

/// A vault whose keycheck row was removed before the crash is `NotInitialized` on the copy.
#[test]
fn hot_journal_on_a_vault_without_keycheck_is_not_initialized_and_unchanged() {
    let tmp = dir();
    let db = new_vault(&tmp);
    {
        let c = rusqlite::Connection::open(&db).unwrap();
        c.execute("DELETE FROM meta WHERE key = 'keycheck'", [])
            .unwrap();
    }
    let (m, j) = crash_after(&db, "UPDATE entries SET updated_at = 9;");
    let res = Vault::open(&db, key(&tmp));
    assert!(matches!(res, Err(VaultError::NotInitialized)), "{res:?}");
    assert_eq!(std::fs::read(&db).unwrap(), m);
    assert_eq!(std::fs::read(tmp.path().join("v.db-journal")).unwrap(), j);
    assert!(no_scratch_left(tmp.path()));
}

/// A crash whose rollback restores a deleted keycheck: the journal holds the page with the
/// keycheck, the torn main file lacks it. The copy rolls back, so the right key opens.
#[test]
fn hot_journal_restoring_a_deleted_keycheck_opens_with_the_key() {
    let tmp = dir();
    let db = new_vault(&tmp);
    let _ = crash_after(&db, "DELETE FROM meta WHERE key = 'keycheck';");
    let v = Vault::open(&db, key(&tmp)).unwrap();
    assert!(
        v.get(&EntryId::new("secret:one").unwrap())
            .unwrap()
            .is_some()
    );
    drop(v);
    assert_eq!(
        listing(tmp.path()),
        ["k", "v.db"].map(std::ffi::OsString::from)
    );
}

/// A writer that keeps growing the journal: `open` returns in bounded time (busy timeout plus the
/// retry cap). Whether the churn thread lands a write between the probe's stamps depends on the
/// scheduler, so both outcomes are legitimate: `PendingJournal` (the probe never saw a stable
/// copy) or `Ok` (it did). What is guaranteed is checked: the bound, the typed outcome, the main
/// file unchanged whenever the open is refused, and no scratch directory left. The retry-cap
/// branch itself is reached deterministically in the unit test
/// `a_journal_that_changes_during_every_copy_hits_the_retry_cap`.
#[test]
fn open_against_a_churning_journal_is_bounded_and_clean() {
    let tmp = dir();
    let db = new_vault(&tmp);
    let (m, _j) = crash_after(&db, "UPDATE entries SET updated_at = 9;");
    let journal = tmp.path().join("v.db-journal");
    let stop = Arc::new(AtomicBool::new(false));
    let s2 = Arc::clone(&stop);
    let j2 = journal.clone();
    let churn = std::thread::spawn(move || {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new().append(true).open(&j2).unwrap();
        while !s2.load(Ordering::Relaxed) {
            // The journal may be consumed by a successful open: stop quietly then.
            if f.write_all(&[0u8; 512]).is_err() {
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    });
    let start = Instant::now();
    let res = Vault::open(&db, key(&tmp));
    let took = start.elapsed();
    stop.store(true, Ordering::Relaxed);
    churn.join().unwrap();
    assert!(took < Duration::from_secs(30), "took {took:?}");
    match res {
        Err(VaultError::PendingJournal) => {
            assert_eq!(std::fs::read(&db).unwrap(), m);
            assert!(journal.exists());
        }
        Ok(_) => {}
        Err(e) => panic!("unexpected outcome: {e:?}"),
    }
    assert!(no_scratch_left(tmp.path()));
}

/// Two openers racing on the same crashed vault: both succeed, data intact, directory clean.
#[test]
fn concurrent_opens_of_a_crashed_vault_both_succeed() {
    let tmp = dir();
    let db = new_vault(&tmp);
    let _ = crash_after(&db, "UPDATE entries SET record = randomblob(3000);");
    let kp = tmp.path().join("k");
    let handles: Vec<_> = (0..2)
        .map(|_| {
            let db = db.clone();
            let kp = kp.clone();
            std::thread::spawn(move || {
                let v = Vault::open(&db, KeyFile::load(&kp).unwrap())?;
                let got = v.get(&EntryId::new("secret:one").unwrap())?;
                Ok::<bool, VaultError>(got.is_some())
            })
        })
        .collect();
    for h in handles {
        let r = h.join().unwrap();
        assert!(matches!(r, Ok(true)), "{r:?}");
    }
    assert_eq!(
        listing(tmp.path()),
        ["k", "v.db"].map(std::ffi::OsString::from)
    );
}

/// A `-journal` that is a directory: `PendingJournal`, not a hang, nothing changed, no scratch.
#[test]
fn directory_journal_is_pending_and_unchanged() {
    let tmp = dir();
    let db = new_vault(&tmp);
    let before = std::fs::read(&db).unwrap();
    std::fs::create_dir(tmp.path().join("v.db-journal")).unwrap();
    let res = Vault::open(&db, key(&tmp));
    assert!(matches!(res, Err(VaultError::PendingJournal)), "{res:?}");
    assert_eq!(std::fs::read(&db).unwrap(), before);
    assert!(tmp.path().join("v.db-journal").is_dir());
    assert!(no_scratch_left(tmp.path()));
}

/// A dangling `-journal` symlink: refused, the symlink stays, its target is never created.
#[test]
fn dangling_symlink_journal_is_refused_and_target_not_created() {
    let tmp = dir();
    let elsewhere = dir();
    let db = new_vault(&tmp);
    let target = elsewhere.path().join("would-be-created");
    std::os::unix::fs::symlink(&target, tmp.path().join("v.db-journal")).unwrap();
    let res = Vault::open(&db, key(&tmp));
    assert!(res.is_err(), "{res:?}");
    assert!(!target.exists());
    assert!(
        tmp.path()
            .join("v.db-journal")
            .symlink_metadata()
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert!(no_scratch_left(tmp.path()));
}

/// A `-journal` that is a hard link to the vault file itself (garbage as a journal): the vault
/// still opens with its data, and the vault file's content is not damaged.
#[test]
fn journal_hardlinked_to_the_vault_file_does_not_damage_the_vault() {
    let tmp = dir();
    let db = new_vault(&tmp);
    std::fs::hard_link(&db, tmp.path().join("v.db-journal")).unwrap();
    let res = Vault::open(&db, key(&tmp));
    match res {
        Ok(v) => assert!(
            v.get(&EntryId::new("secret:one").unwrap())
                .unwrap()
                .is_some()
        ),
        Err(e) => assert!(matches!(e, VaultError::PendingJournal), "{e:?}"),
    }
    let _ = std::fs::remove_file(tmp.path().join("v.db-journal"));
    let v = Vault::open(&db, key(&tmp)).unwrap();
    assert!(
        v.get(&EntryId::new("secret:one").unwrap())
            .unwrap()
            .is_some()
    );
    assert!(no_scratch_left(tmp.path()));
}

/// The scratch copy holds vault ciphertext: while it exists it is 0700 / 0600.
#[test]
fn scratch_directory_is_private_while_it_exists() {
    let tmp = dir();
    let db = new_vault(&tmp);
    // A larger vault so the copy is observable.
    {
        let c = rusqlite::Connection::open(&db).unwrap();
        c.execute_batch(
            "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 3000)
             INSERT INTO entries SELECT 'secret:big' || i, 6, randomblob(3000), 0, 1, 1 FROM n;",
        )
        .unwrap();
    }
    let _ = crash_after(&db, "UPDATE entries SET updated_at = 3;");
    let stop = Arc::new(AtomicBool::new(false));
    let s2 = Arc::clone(&stop);
    let p = tmp.path().to_path_buf();
    let watcher = std::thread::spawn(move || {
        let mut seen = Vec::new();
        while !s2.load(Ordering::Relaxed) {
            if let Ok(rd) = std::fs::read_dir(&p) {
                for e in rd.flatten() {
                    if e.file_name()
                        .to_string_lossy()
                        .starts_with(".wardenlens-probe")
                    {
                        if let Ok(m) = e.path().symlink_metadata() {
                            seen.push(("dir".to_owned(), m.permissions().mode() & 0o777));
                        }
                        if let Ok(inner) = std::fs::read_dir(e.path()) {
                            for f in inner.flatten() {
                                if let Ok(m) = f.path().symlink_metadata() {
                                    seen.push((
                                        f.file_name().to_string_lossy().into_owned(),
                                        m.permissions().mode() & 0o777,
                                    ));
                                }
                            }
                        }
                    }
                }
            }
        }
        seen
    });
    let res = Vault::open(&db, key(&tmp));
    stop.store(true, Ordering::Relaxed);
    let seen = watcher.join().unwrap();
    assert!(res.is_ok(), "{res:?}");
    for (name, mode) in &seen {
        if name == "dir" {
            assert_eq!(*mode, 0o700, "scratch dir mode");
        } else {
            assert_eq!(*mode & 0o077, 0, "scratch file {name} mode {mode:o}");
        }
    }
    assert!(no_scratch_left(tmp.path()));
}

/// A crashed `create` that left a valid page 1 and a hot journal (the journal restores a file that
/// holds a valid page 1 and no vault schema): `create` says `NotEmpty` (a vault was never made;
/// the advice is to remove both files), `open` says `NotInitialized`. Nothing is modified.
#[test]
fn crashed_create_with_a_valid_page_1_and_a_hot_journal_is_not_empty() {
    let tmp = dir();
    let db = tmp.path().join("v.db");
    let journal = tmp.path().join("v.db-journal");
    std::fs::write(&db, b"").unwrap();
    std::fs::set_permissions(&db, std::fs::Permissions::from_mode(0o600)).unwrap();
    let c = rusqlite::Connection::open(&db).unwrap();
    // Page 1 only: a valid SQLite header, no tables.
    c.execute_batch("PRAGMA journal_mode = DELETE; PRAGMA user_version = 1;")
        .unwrap();
    assert!(
        std::fs::metadata(&db).unwrap().len() >= 512,
        "fixture: page 1 written"
    );
    c.execute_batch(
        "PRAGMA cache_size = 1; BEGIN IMMEDIATE;
         CREATE TABLE meta(key TEXT PRIMARY KEY, value BLOB NOT NULL);
         CREATE TABLE entries(id TEXT PRIMARY KEY, kind INTEGER NOT NULL, record BLOB NOT NULL,
           unscannable INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL,
           updated_at INTEGER NOT NULL);
         WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 40)
         INSERT INTO entries SELECT 'secret:pad' || i, 2, randomblob(3000), 0, 1, 1 FROM n;",
    )
    .unwrap();
    let main = std::fs::read(&db).unwrap();
    let j = std::fs::read(&journal).unwrap();
    assert!(!j.is_empty(), "fixture: the journal is hot (non-empty)");
    drop(c);
    std::fs::write(&db, &main).unwrap();
    std::fs::write(&journal, &j).unwrap();
    let kf = KeyFile::generate(&tmp.path().join("k")).unwrap();
    let res = Vault::create(&db, kf);
    assert!(matches!(res, Err(VaultError::NotEmpty)), "{res:?}");
    let opened = Vault::open(&db, key(&tmp));
    assert!(
        matches!(opened, Err(VaultError::NotInitialized)),
        "{opened:?}"
    );
    assert_eq!(std::fs::read(&db).unwrap(), main);
    assert_eq!(std::fs::read(&journal).unwrap(), j);
    assert!(no_scratch_left(tmp.path()));
}
