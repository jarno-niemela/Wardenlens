//! Round-3 adversarial tests for #104 (rolled-back private copy). Synthetic values only.

#![expect(
    clippy::unwrap_used,
    reason = "integration-test helpers outside #[test] fns; clippy.toml in-tests allowances do not reach them"
)]

use std::os::unix::ffi::OsStrExt;
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

/// A foreign rollback-mode database `v.db` with a hot journal. Returns (main, journal).
fn foreign_with_hot_journal(tmp: &TempDir) -> (PathBuf, Vec<u8>, Vec<u8>) {
    let db = tmp.path().join("v.db");
    let journal = tmp.path().join("v.db-journal");
    let c = rusqlite::Connection::open(&db).unwrap();
    c.execute_batch(
        "CREATE TABLE t(a BLOB); INSERT INTO t VALUES (randomblob(3000));
         PRAGMA cache_size = 1; BEGIN; UPDATE t SET a = randomblob(3000);
         INSERT INTO t SELECT randomblob(3000) FROM t;
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
    (db, m, j)
}

/// Appends a super-journal pointer (SQLite's on-disk format) naming `target` to a journal image.
fn with_super_pointer(journal: &[u8], target: &Path) -> Vec<u8> {
    const MAGIC: [u8; 8] = [0xd9, 0xd5, 0x05, 0xf9, 0x20, 0xa1, 0x63, 0xd7];
    let name = target.as_os_str().as_bytes();
    let mut out = journal.to_vec();
    let pending_pgno: u32 = 0x4000_0000 / 4096 + 1;
    out.extend_from_slice(&pending_pgno.to_be_bytes());
    out.extend_from_slice(name);
    out.extend_from_slice(&u32::try_from(name.len()).unwrap().to_be_bytes());
    let cksum = name.iter().fold(0u32, |a, &b| a.wrapping_add(u32::from(b)));
    out.extend_from_slice(&cksum.to_be_bytes());
    out.extend_from_slice(&MAGIC);
    out
}

fn no_scratch_left(tmp: &Path) -> bool {
    !listing(tmp)
        .iter()
        .any(|n| n.to_string_lossy().starts_with(".wardenlens-probe"))
}

/// The probe promises the originals are only read and that it never writes outside its scratch
/// directory. SQLite's rollback of the scratch copy follows a super-journal pointer stored in the
/// journal and deletes that super-journal after the rollback. A foreign database whose journal
/// names a file outside the scratch directory therefore gets that file deleted by `Vault::open`,
/// before the file is refused.
#[test]
fn open_on_a_foreign_db_whose_journal_names_a_super_journal_deletes_nothing() {
    let tmp = dir();
    let (db, m, j) = foreign_with_hot_journal(&tmp);
    // A super-journal file whose listed children do not exist: SQLite deletes it after rollback.
    let precious = tmp.path().join("v.db-mj0123ABCD");
    std::fs::write(&precious, b"synthetic-precious-bytes").unwrap();
    let j2 = with_super_pointer(&j, &precious);
    let journal = tmp.path().join("v.db-journal");
    std::fs::write(&journal, &j2).unwrap();
    let kf = KeyFile::generate(&tmp.path().join("k")).unwrap();
    let res = Vault::open(&db, kf);
    assert!(matches!(res, Err(VaultError::NotInitialized)), "{res:?}");
    assert_eq!(std::fs::read(&db).unwrap(), m);
    assert_eq!(std::fs::read(&journal).unwrap(), j2);
    assert!(
        precious.exists(),
        "probe of a refused foreign file deleted a file outside its scratch directory"
    );
    assert!(no_scratch_left(tmp.path()));
}

/// Same, but the target is an unrelated file in another directory.
#[test]
fn open_on_a_foreign_db_never_deletes_an_unrelated_file_named_by_its_journal() {
    let tmp = dir();
    let elsewhere = dir();
    let (db, _m, j) = foreign_with_hot_journal(&tmp);
    let precious = elsewhere.path().join("notes.txt");
    std::fs::write(&precious, b"synthetic notes without any NUL").unwrap();
    std::fs::write(
        tmp.path().join("v.db-journal"),
        with_super_pointer(&j, &precious),
    )
    .unwrap();
    let kf = KeyFile::generate(&tmp.path().join("k")).unwrap();
    let res = Vault::open(&db, kf);
    assert!(res.is_err(), "{res:?}");
    assert!(precious.exists(), "unrelated file deleted by the probe");
}

/// A `-journal` that is a FIFO (non-regular): the probe must not block forever opening it.
#[test]
fn open_with_a_fifo_journal_does_not_hang() {
    let tmp = dir();
    let db = new_vault(&tmp);
    let fifo = tmp.path().join("v.db-journal");
    let st = std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .unwrap();
    assert!(st.success());
    let key = KeyFile::load(&tmp.path().join("k")).unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    let db2 = db.clone();
    std::thread::spawn(move || {
        let res = Vault::open(&db2, key).map(drop);
        let _ = tx.send(format!("{res:?}"));
    });
    let got = rx.recv_timeout(Duration::from_secs(20));
    if got.is_err() {
        // Unblock the stuck opener so the test process can exit.
        let _ = std::fs::OpenOptions::new().write(true).open(&fifo);
    }
    assert!(got.is_ok(), "Vault::open hung on a FIFO -journal");
}

/// A `-journal` symlink to a file elsewhere is never followed: refused, target untouched, no
/// scratch left.
#[test]
fn open_with_a_symlinked_journal_is_refused_and_target_untouched() {
    let tmp = dir();
    let elsewhere = dir();
    let db = new_vault(&tmp);
    let target = elsewhere.path().join("t");
    std::fs::write(&target, b"synthetic target bytes, not a journal").unwrap();
    std::os::unix::fs::symlink(&target, tmp.path().join("v.db-journal")).unwrap();
    let before = std::fs::read(&db).unwrap();
    let res = Vault::open(&db, KeyFile::load(&tmp.path().join("k")).unwrap());
    assert!(res.is_err(), "{res:?}");
    assert_eq!(
        std::fs::read(&target).unwrap(),
        b"synthetic target bytes, not a journal"
    );
    assert_eq!(std::fs::read(&db).unwrap(), before);
    assert!(no_scratch_left(tmp.path()));
}

/// A journal over the 256 MiB copy cap (sparse): `PendingJournal`, nothing modified, no scratch.
#[test]
fn oversized_journal_is_pending_and_leaves_no_scratch() {
    let tmp = dir();
    let (db, m, j) = foreign_with_hot_journal(&tmp);
    let journal = tmp.path().join("v.db-journal");
    let f = std::fs::OpenOptions::new()
        .write(true)
        .open(&journal)
        .unwrap();
    f.set_len(300 * 1024 * 1024).unwrap();
    drop(f);
    let res = Vault::open(&db, KeyFile::generate(&tmp.path().join("k")).unwrap());
    assert!(matches!(res, Err(VaultError::PendingJournal)), "{res:?}");
    assert_eq!(std::fs::read(&db).unwrap(), m);
    let now = std::fs::read(&journal).unwrap();
    assert_eq!(now.len(), 300 * 1024 * 1024);
    assert_eq!(&now[..j.len()], &j[..]);
    assert!(no_scratch_left(tmp.path()));
}

/// A genuine vault after a crash: the right key opens it, the journal is consumed, and the
/// directory ends up with exactly the vault and key (no scratch, no sidecar).
#[test]
fn genuine_crashed_vault_recovers_and_leaves_a_clean_directory() {
    let tmp = dir();
    let db = new_vault(&tmp);
    let writer = rusqlite::Connection::open(&db).unwrap();
    writer
        .execute_batch(
            "PRAGMA cache_size = 1; BEGIN;
             UPDATE entries SET record = randomblob(3000), updated_at = 1;
             UPDATE meta SET value = randomblob(length(value));
             WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 30)
             INSERT INTO entries SELECT 'secret:pad' || i, 6, randomblob(3000), 0, 1, 1 FROM n;",
        )
        .unwrap();
    let m = std::fs::read(&db).unwrap();
    let j = std::fs::read(tmp.path().join("v.db-journal")).unwrap();
    drop(writer);
    std::fs::write(&db, &m).unwrap();
    std::fs::write(tmp.path().join("v.db-journal"), &j).unwrap();
    let v = Vault::open(&db, KeyFile::load(&tmp.path().join("k")).unwrap()).unwrap();
    assert!(
        v.get(&EntryId::new("secret:one").unwrap())
            .unwrap()
            .is_some()
    );
    assert_eq!(v.list().unwrap().len(), 1);
    drop(v);
    assert_eq!(
        listing(tmp.path()),
        ["k", "v.db"].map(std::ffi::OsString::from)
    );
}

/// A foreign WAL-mode database whose hot rollback journal restores a page 1 (rollback header
/// in the main file, journal holding a WAL-mode page 1): refused, both files unchanged, no
/// scratch and no `-wal`/`-shm` outside scratch.
#[test]
fn journal_restoring_a_wal_header_is_refused_and_clean() {
    let tmp = dir();
    let (db, m, j) = foreign_with_hot_journal(&tmp);
    // Page 1 image in the journal: pgno 1 followed by the SQLite header. Flip its bytes 18/19.
    let mut j2 = j.clone();
    let mut needle = 1u32.to_be_bytes().to_vec();
    needle.extend_from_slice(b"SQLite format 3\0");
    let at = j2
        .windows(needle.len())
        .position(|w| w == needle.as_slice())
        .expect("fixture: page 1 is in the journal");
    let page1 = at + 4;
    j2[page1 + 18] = 2;
    j2[page1 + 19] = 2;
    std::fs::write(tmp.path().join("v.db-journal"), &j2).unwrap();
    let names = listing(tmp.path());
    let res = Vault::open(&db, KeyFile::generate(&tmp.path().join("k")).unwrap());
    assert!(res.is_err(), "{res:?}");
    assert_eq!(std::fs::read(&db).unwrap(), m);
    let mut expect = names;
    expect.push("k".into());
    expect.sort();
    assert_eq!(listing(tmp.path()), expect);
}
