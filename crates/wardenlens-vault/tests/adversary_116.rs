//! Adversarial tests for #116 (vault probe hardening). Synthetic values only.

#![expect(
    clippy::unwrap_used,
    reason = "integration-test helpers outside #[test] fns; clippy.toml in-tests allowances do not reach them"
)]

use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use secrecy::SecretString;
use tempfile::TempDir;
use wardenlens_core::entry::{EntryId, EntryKind};
use wardenlens_secrets::KeyFile;
use wardenlens_vault::{Scan, Value, Vault, VaultError};

const MAGIC: [u8; 8] = [0xd9, 0xd5, 0x05, 0xf9, 0x20, 0xa1, 0x63, 0xd7];
const VALID_MJ_SUFFIX: &str = "-mj0123459AB";

fn dir() -> TempDir {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    tmp
}

fn no_scratch_left(tmp: &Path) -> bool {
    !std::fs::read_dir(tmp).unwrap().any(|e| {
        e.unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".wardenlens-probe")
    })
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

fn key(tmp: &TempDir) -> KeyFile {
    KeyFile::load(&tmp.path().join("k")).unwrap()
}

/// Own vault with a hot journal from a writer that died mid-transaction. Returns (main, journal).
fn crash_vault(db: &Path) -> (Vec<u8>, Vec<u8>) {
    let journal = PathBuf::from(format!("{}-journal", db.display()));
    let w = rusqlite::Connection::open(db).unwrap();
    w.execute_batch(
        "PRAGMA cache_size = 1; BEGIN IMMEDIATE; UPDATE entries SET updated_at = 9;
         WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 30)
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

fn super_pointer(target: &Path) -> Vec<u8> {
    let name = target.as_os_str().as_bytes();
    let mut out = Vec::new();
    let pending_pgno: u32 = 0x4000_0000 / 4096 + 1;
    out.extend_from_slice(&pending_pgno.to_be_bytes());
    out.extend_from_slice(name);
    out.extend_from_slice(&u32::try_from(name.len()).unwrap().to_be_bytes());
    let cksum = name.iter().fold(0u32, |a, &b| a.wrapping_add(u32::from(b)));
    out.extend_from_slice(&cksum.to_be_bytes());
    out.extend_from_slice(&MAGIC);
    out
}

fn mkfifo(path: &Path) {
    assert!(
        std::process::Command::new("mkfifo")
            .arg(path)
            .status()
            .unwrap()
            .success()
    );
}

/// Runs `f` on a thread; `None` if it did not return within 20 s.
fn within_20s(f: impl FnOnce() -> String + Send + 'static) -> Option<String> {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(f());
    });
    rx.recv_timeout(Duration::from_secs(20)).ok()
}

/// The realistic crashed `create`: the file was empty, the schema and keycheck were written into
/// the main file (spilled), and the journal (original size 0) is still there. The journal rolls
/// the file back to nothing, so no vault exists: `create` is `NotEmpty`, `open` (even with the key
/// the half-made vault was sealed under) is `NotInitialized`. Nothing modified.
#[test]
fn crashed_create_from_an_empty_file_is_not_empty_and_open_is_not_initialized() {
    let tmp = dir();
    // A real vault elsewhere supplies the exact schema and meta rows.
    let src_dir = dir();
    let src = new_vault(&src_dir);
    let src_conn = rusqlite::Connection::open(&src).unwrap();
    let ddl: Vec<String> = src_conn
        .prepare("SELECT sql FROM sqlite_master WHERE sql IS NOT NULL ORDER BY rowid")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    let meta: Vec<(String, Vec<u8>)> = src_conn
        .prepare("SELECT key, value FROM meta")
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    drop(src_conn);
    std::fs::copy(src_dir.path().join("k"), tmp.path().join("k")).unwrap();

    let db = tmp.path().join("v.db");
    let journal = tmp.path().join("v.db-journal");
    std::fs::write(&db, b"").unwrap();
    std::fs::set_permissions(&db, std::fs::Permissions::from_mode(0o600)).unwrap();
    let c = rusqlite::Connection::open(&db).unwrap();
    c.execute_batch("PRAGMA journal_mode = DELETE; PRAGMA cache_size = 1; BEGIN IMMEDIATE;")
        .unwrap();
    for s in &ddl {
        c.execute_batch(s).unwrap();
    }
    for (k, v) in &meta {
        c.execute("INSERT INTO meta(key, value) VALUES (?1, ?2)", (k, v))
            .unwrap();
    }
    c.execute_batch(
        "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 40)
         INSERT INTO entries SELECT 'secret:pad' || i, 6, randomblob(3000), 0, 1, 1 FROM n;",
    )
    .unwrap();
    let j = std::fs::read(&journal).unwrap();
    drop(c);
    // The commit wrote every page of the new vault into the main file, then the process died
    // before deleting the journal (which records an original size of 0 pages).
    let m = std::fs::read(&src).unwrap();
    std::fs::write(&db, &m).unwrap();
    std::fs::write(&journal, &j).unwrap();
    assert_eq!(
        u32::from_be_bytes(j[28..32].try_into().unwrap()),
        0,
        "fixture: original size 0"
    );
    assert!(m.len() >= 4096, "fixture: pages spilled into the main file");
    assert!(!j.is_empty(), "fixture: hot journal");
    // Fixture sanity: an immutable read of the main file alone sees the vault schema.
    let peek = rusqlite::Connection::open_with_flags(
        format!("file:{}?immutable=1", db.display()),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_URI,
    )
    .unwrap();
    let n: i64 = peek
        .query_row("SELECT count(*) FROM meta", [], |r| r.get(0))
        .unwrap();
    assert!(n >= 2, "fixture: meta rows are in the main file");
    drop(peek);

    let res = Vault::create(&db, key(&tmp));
    assert!(matches!(res, Err(VaultError::NotEmpty)), "{res:?}");
    let res = Vault::open(&db, key(&tmp));
    assert!(matches!(res, Err(VaultError::NotInitialized)), "{res:?}");
    assert_eq!(std::fs::read(&db).unwrap(), m);
    assert_eq!(std::fs::read(&journal).unwrap(), j);
    assert!(no_scratch_left(tmp.path()));
}

/// `create` on the owner's crashed vault whose journal ends in a super-journal pointer naming a
/// real file under a valid name: `PendingJournal`, the named file is kept, nothing modified.
#[test]
fn create_on_a_vault_whose_journal_names_a_super_journal_deletes_nothing() {
    let tmp = dir();
    let db = new_vault(&tmp);
    let (m, j) = crash_vault(&db);
    let precious = tmp.path().join(format!("v.db{VALID_MJ_SUFFIX}"));
    std::fs::write(&precious, b"synthetic-precious").unwrap();
    let mut j2 = j.clone();
    j2.extend_from_slice(&super_pointer(&precious));
    let journal = tmp.path().join("v.db-journal");
    std::fs::write(&journal, &j2).unwrap();
    let res = Vault::create(&db, key(&tmp));
    assert!(matches!(res, Err(VaultError::PendingJournal)), "{res:?}");
    assert!(precious.exists());
    assert_eq!(std::fs::read(&db).unwrap(), m);
    assert_eq!(std::fs::read(&journal).unwrap(), j2);
    assert!(no_scratch_left(tmp.path()));
}

/// `create` against a FIFO journal returns promptly with `PendingJournal`.
#[test]
fn create_with_a_fifo_journal_is_pending_and_does_not_hang() {
    let tmp = dir();
    let db = new_vault(&tmp);
    let before = std::fs::read(&db).unwrap();
    let fifo = tmp.path().join("v.db-journal");
    mkfifo(&fifo);
    let k = key(&tmp);
    let db2 = db.clone();
    let got = within_20s(move || format!("{:?}", Vault::create(&db2, k).map(drop)));
    if got.is_none() {
        let _ = std::fs::OpenOptions::new().write(true).open(&fifo);
    }
    assert_eq!(got.as_deref(), Some("Err(PendingJournal)"));
    assert_eq!(std::fs::read(&db).unwrap(), before);
    assert!(
        std::fs::symlink_metadata(&fifo)
            .unwrap()
            .file_type()
            .is_fifo()
    );
    assert!(no_scratch_left(tmp.path()));
}

/// Boundary: a journal that is exactly the 8 magic bytes ends in the magic and is refused.
#[test]
fn journal_of_exactly_the_magic_is_pending() {
    let tmp = dir();
    let db = new_vault(&tmp);
    let m = std::fs::read(&db).unwrap();
    let journal = tmp.path().join("v.db-journal");
    std::fs::write(&journal, MAGIC).unwrap();
    let res = Vault::open(&db, key(&tmp));
    assert!(matches!(res, Err(VaultError::PendingJournal)), "{res:?}");
    assert_eq!(std::fs::read(&db).unwrap(), m);
    assert_eq!(std::fs::read(&journal).unwrap(), MAGIC);
    assert!(no_scratch_left(tmp.path()));
}

/// Boundary: 7 bytes of the magic (one short) is no pointer; SQLite plays back nothing and the
/// vault opens with its data.
#[test]
fn journal_one_byte_short_of_the_magic_opens() {
    let tmp = dir();
    let db = new_vault(&tmp);
    let journal = tmp.path().join("v.db-journal");
    std::fs::write(&journal, &MAGIC[1..]).unwrap();
    let v = Vault::open(&db, key(&tmp)).unwrap();
    assert!(
        v.get(&EntryId::new("secret:one").unwrap())
            .unwrap()
            .is_some()
    );
    assert!(no_scratch_left(tmp.path()));
}

/// A super-journal pointer followed by one trailing byte is not read by SQLite (it reads the
/// pointer from the very end), so a FIFO under a valid `-mj` name is never opened: the open of
/// the owner's crashed vault recovers and returns promptly; the FIFO stays.
#[test]
fn super_pointer_not_at_the_end_is_ignored_and_does_not_hang() {
    let tmp = dir();
    let db = new_vault(&tmp);
    let (_m, j) = crash_vault(&db);
    let fifo = tmp.path().join(format!("v.db{VALID_MJ_SUFFIX}"));
    mkfifo(&fifo);
    let mut j2 = j.clone();
    j2.extend_from_slice(&super_pointer(&fifo));
    j2.push(0);
    std::fs::write(tmp.path().join("v.db-journal"), &j2).unwrap();
    let k = key(&tmp);
    let db2 = db.clone();
    let got = within_20s(move || {
        let v = Vault::open(&db2, k);
        format!(
            "{:?}",
            v.map(|v| v
                .get(&EntryId::new("secret:one").unwrap())
                .unwrap()
                .is_some())
        )
    });
    if got.is_none() {
        let _ = std::fs::OpenOptions::new().write(true).open(&fifo);
    }
    assert_eq!(got.as_deref(), Some("Ok(true)"));
    assert!(
        std::fs::symlink_metadata(&fifo)
            .unwrap()
            .file_type()
            .is_fifo()
    );
    assert!(no_scratch_left(tmp.path()));
}

/// The owner's crashed vault whose journal ends in a super-journal pointer to a FIFO: `open`
/// returns `PendingJournal` promptly (the tail check, not just the identity on the copy).
#[test]
fn own_vault_journal_naming_a_fifo_super_journal_is_pending_promptly() {
    let tmp = dir();
    let db = new_vault(&tmp);
    let (m, j) = crash_vault(&db);
    let fifo = tmp.path().join(format!("v.db{VALID_MJ_SUFFIX}"));
    mkfifo(&fifo);
    let mut j2 = j.clone();
    j2.extend_from_slice(&super_pointer(&fifo));
    let journal = tmp.path().join("v.db-journal");
    std::fs::write(&journal, &j2).unwrap();
    let k = key(&tmp);
    let db2 = db.clone();
    let got = within_20s(move || format!("{:?}", Vault::open(&db2, k).map(drop)));
    if got.is_none() {
        let _ = std::fs::OpenOptions::new().write(true).open(&fifo);
    }
    assert_eq!(got.as_deref(), Some("Err(PendingJournal)"));
    assert_eq!(std::fs::read(&db).unwrap(), m);
    assert_eq!(std::fs::read(&journal).unwrap(), j2);
    assert!(no_scratch_left(tmp.path()));
}
