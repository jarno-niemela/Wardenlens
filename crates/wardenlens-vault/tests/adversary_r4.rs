//! Round-4 adversarial tests for the vault library (synthetic values only).

#![expect(
    clippy::unwrap_used,
    reason = "integration-test helpers outside #[test] fns; clippy.toml in-tests allowances do not reach them"
)]

use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use tempfile::TempDir;
use wardenlens_secrets::KeyFile;
use wardenlens_vault::legacy::{map_legacy, map_secret_json};
use wardenlens_vault::{Vault, VaultError};

fn dir() -> TempDir {
    let d = tempfile::tempdir().unwrap();
    std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    d
}

fn json(s: &str) -> serde_json::Value {
    serde_json::from_str(s).unwrap()
}

fn toml_of(s: &str) -> toml::Table {
    toml::from_str(s).unwrap()
}

fn entry_ids(i: &wardenlens_vault::legacy::LegacyImport) -> Vec<String> {
    i.entries.iter().map(|e| e.id.to_string()).collect()
}

fn listing(d: &Path) -> Vec<std::ffi::OsString> {
    let mut n: Vec<_> = std::fs::read_dir(d)
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    n.sort();
    n
}

fn foreign_db(path: &Path, wal: bool, table: &str) {
    let c = rusqlite::Connection::open(path).unwrap();
    if wal {
        let _: String = c
            .query_row("PRAGMA journal_mode = WAL", [], |r| r.get(0))
            .unwrap();
    }
    c.execute_batch(&format!(
        "CREATE TABLE {table}(x); INSERT INTO {table} VALUES ('synthetic');"
    ))
    .unwrap();
    drop(c);
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

fn key(d: &TempDir, name: &str) -> KeyFile {
    KeyFile::generate(&d.path().join(name)).unwrap()
}

// ---- create: the probe -------------------------------------------------------------------

/// Paths with characters that need URI escaping must still be probed correctly.
#[test]
fn create_twice_reports_already_initialized_for_awkward_file_names() {
    for name in [
        "v db",
        "v?x.db",
        "v#x.db",
        "v%41.db",
        "v&mode=rwc.db",
        "vä.db",
        "v'.db",
        "v\"x.db",
        "v\\x.db",
        "v;x.db",
        "v:x.db",
        "v\u{202e}x.db",
    ] {
        let d = dir();
        let p = d.path().join(name);
        drop(Vault::create(&p, key(&d, "k")).unwrap());
        let before = std::fs::read(&p).unwrap();
        let r = Vault::create(&p, key(&d, "k2"));
        assert!(
            matches!(r, Err(VaultError::AlreadyInitialized)),
            "{name:?}: {r:?}"
        );
        assert_eq!(std::fs::read(&p).unwrap(), before, "{name:?}");
    }
}

/// A foreign WAL database at an awkward name: still `NotEmpty`, still untouched.
#[test]
fn create_on_a_foreign_wal_db_with_an_awkward_name_leaves_it_unchanged() {
    for name in ["v?immutable=0&mode=rw.db", "v#x.db", "v%00.db"] {
        let d = dir();
        let p = d.path().join(name);
        foreign_db(&p, true, "t");
        let before = std::fs::read(&p).unwrap();
        let names = listing(d.path());
        let k = key(&d, "k");
        let names_k = listing(d.path());
        let r = Vault::create(&p, k);
        assert!(matches!(r, Err(VaultError::NotEmpty)), "{name:?}: {r:?}");
        assert_eq!(std::fs::read(&p).unwrap(), before, "{name:?}");
        assert_eq!(listing(d.path()), names_k, "{name:?}");
        let _ = names;
    }
}

/// A path written with a leading `//` is the same file on Linux; the URI must not turn the
/// first component into an authority.
#[test]
fn create_twice_with_a_double_slash_path_reports_already_initialized() {
    let d = dir();
    let p = d.path().join("v.db");
    drop(Vault::create(&p, key(&d, "k")).unwrap());
    let s = format!("/{}", p.display());
    let dbl = PathBuf::from(s);
    let r = Vault::create(&dbl, key(&d, "k2"));
    assert!(matches!(r, Err(VaultError::AlreadyInitialized)), "{r:?}");
}

#[test]
fn create_on_a_foreign_db_with_a_double_slash_path_is_not_empty() {
    let d = dir();
    let p = d.path().join("v.db");
    foreign_db(&p, true, "t");
    let before = std::fs::read(&p).unwrap();
    let dbl = PathBuf::from(format!("/{}", p.display()));
    let r = Vault::create(&dbl, key(&d, "k"));
    assert!(matches!(r, Err(VaultError::NotEmpty)), "{r:?}");
    assert_eq!(std::fs::read(&p).unwrap(), before);
}

/// A foreign database that happens to have a `meta` table is not a vault.
#[test]
fn create_on_a_foreign_db_with_a_meta_table_leaves_it_unchanged() {
    let d = dir();
    let p = d.path().join("v.db");
    foreign_db(&p, true, "meta");
    let before = std::fs::read(&p).unwrap();
    let k = key(&d, "k");
    let names = listing(d.path());
    assert!(Vault::create(&p, k).is_err());
    assert_eq!(std::fs::read(&p).unwrap(), before);
    assert_eq!(listing(d.path()), names);
}

/// A foreign WAL database with an un-checkpointed `-wal` sidecar present (writer still alive).
#[test]
fn create_while_a_foreign_wal_writer_holds_the_db_leaves_everything_unchanged() {
    let d = dir();
    let p = d.path().join("v.db");
    let conn = rusqlite::Connection::open(&p).unwrap();
    let _: String = conn
        .query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))
        .unwrap();
    conn.execute_batch(
        "PRAGMA wal_autocheckpoint = 0; CREATE TABLE t(x); INSERT INTO t VALUES ('synthetic');",
    )
    .unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
    let before = std::fs::read(&p).unwrap();
    let wal_before = std::fs::read(d.path().join("v.db-wal")).unwrap();
    let kf = key(&d, "k");
    let names = listing(d.path());
    let res = Vault::create(&p, kf);
    assert!(matches!(res, Err(VaultError::NotEmpty)), "{res:?}");
    assert_eq!(std::fs::read(&p).unwrap(), before);
    assert_eq!(
        std::fs::read(d.path().join("v.db-wal")).unwrap(),
        wal_before
    );
    assert_eq!(listing(d.path()), names);
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM t", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 1);
}

/// `open` on a foreign WAL database: refused, and the file is not converted out of WAL mode.
#[test]
fn open_on_a_foreign_wal_db_is_refused_and_leaves_it_unchanged() {
    let d = dir();
    let p = d.path().join("v.db");
    foreign_db(&p, true, "t");
    let before = std::fs::read(&p).unwrap();
    let k = key(&d, "k");
    let names = listing(d.path());
    let r = Vault::open(&p, k);
    assert!(matches!(r, Err(VaultError::NotInitialized)), "{r:?}");
    assert_eq!(
        std::fs::read(&p).unwrap(),
        before,
        "open modified a foreign database it refused"
    );
    assert_eq!(listing(d.path()), names);
}

/// `open` on a foreign rollback-mode database: refused and unchanged.
#[test]
fn open_on_a_foreign_rollback_db_is_refused_and_leaves_it_unchanged() {
    let d = dir();
    let p = d.path().join("v.db");
    foreign_db(&p, false, "t");
    let before = std::fs::read(&p).unwrap();
    let k = key(&d, "k");
    let r = Vault::open(&p, k);
    assert!(matches!(r, Err(VaultError::NotInitialized)), "{r:?}");
    assert_eq!(std::fs::read(&p).unwrap(), before);
}

/// An empty existing file is still initialised by `create` (the probe only runs on non-empty).
#[test]
fn create_on_an_existing_empty_private_file_initialises_it() {
    let d = dir();
    let p = d.path().join("v.db");
    std::fs::write(&p, b"").unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
    drop(Vault::create(&p, key(&d, "k")).unwrap());
    let kk = KeyFile::load(&d.path().join("k")).unwrap();
    assert!(Vault::open(&p, kk).is_ok());
}

// ---- legacy: refused credentials and mapped names ----------------------------------------

#[test]
fn bad_login_with_empty_password_reports_only_the_login() {
    let v = json(r#"[{"login":"a\u0000b","password":""}]"#);
    let i = map_secret_json(&v, &BTreeMap::new()).unwrap();
    assert!(i.entries.is_empty());
    assert!(
        i.unknown_keys
            .iter()
            .any(|k| k.rsplit('.').next() == Some("login")),
        "{:?}",
        i.unknown_keys
    );
}

#[test]
fn bad_username_and_password_report_both_under_their_keys() {
    let long = "p".repeat(5000);
    let v = json(&format!(
        r#"[{{"username":"a\u0000b","password":"{long}"}}]"#
    ));
    let i = map_secret_json(&v, &BTreeMap::new()).unwrap();
    assert!(i.entries.is_empty());
    assert_eq!(
        i.unknown_keys,
        ["import-json-1.username", "import-json-1.password"]
    );
}

#[test]
fn reports_never_contain_values() {
    let v =
        json(r#"[{"name":"Secret Cam 9","login":"zz\u0000top","password":"Hunter2-synthetic"}]"#);
    let m = BTreeMap::from([("Secret Cam 9".to_owned(), "tapo".to_owned())]);
    let i = map_secret_json(&v, &m).unwrap();
    let all = format!("{:?}", i.unknown_keys);
    assert!(!all.contains("Secret Cam") && !all.contains("Hunter2") && !all.contains("zz"));
}

/// Two cameras whose names are both unstorable and identical are not duplicates; both get
/// their own ordinal and nothing collides.
#[test]
fn identical_unstorable_names_are_not_duplicates() {
    let v = json(
        r#"[{"name":"a\u0000","login":"u","password":"p1"},{"name":"a\u0000","login":"v","password":"p2"}]"#,
    );
    let i = map_secret_json(&v, &BTreeMap::new()).unwrap();
    assert_eq!(
        entry_ids(&i),
        [
            "cam:import-json-1:credential",
            "cam:import-json-2:credential"
        ]
    );
}

/// Two storable identical names are still refused.
#[test]
fn identical_storable_names_are_still_duplicates() {
    let v = json(r#"[{"name":"Garage"},{"name":"Garage"}]"#);
    assert!(map_secret_json(&v, &BTreeMap::new()).is_err());
}

/// A mapped camera with a reserved-prefix inventory id falls back to its ordinal and keeps its
/// name there; the TOML cannot emit that id.
#[test]
fn reserved_mapped_id_keeps_the_name_under_the_ordinal_without_collision() {
    let m = BTreeMap::from([("Garage".to_owned(), "import-json-1".to_owned())]);
    let j = json(r#"[{"name":"Garage","login":"u","password":"p"}]"#);
    let t = toml_of("[cameras.import-json-1]\nname = \"Other Name\"\n");
    let i = map_legacy(Some(&j), &m, Some(&t)).unwrap();
    let ids = entry_ids(&i);
    assert!(ids.contains(&"cam:import-json-1:name".to_owned()));
    let mut dedup = ids.clone();
    dedup.sort();
    dedup.dedup();
    assert_eq!(dedup.len(), ids.len());
}
