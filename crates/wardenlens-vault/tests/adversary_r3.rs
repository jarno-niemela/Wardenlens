//! Round-3 adversarial tests for the vault library (synthetic values only).

#![expect(
    clippy::unwrap_used,
    reason = "integration-test helpers outside #[test] fns; clippy.toml in-tests allowances do not reach them"
)]

use std::collections::{BTreeMap, BTreeSet};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use secrecy::SecretString;
use tempfile::TempDir;
use wardenlens_core::entry::{EntryId, EntryKind};
use wardenlens_secrets::{Credentials, KeyFile};
use wardenlens_vault::legacy::{LegacyError, map_inventory_toml, map_legacy, map_secret_json};
use wardenlens_vault::{Scan, Value, Vault, VaultError};

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

fn ids(i: &wardenlens_vault::legacy::LegacyImport) -> Vec<String> {
    i.entries.iter().map(|e| e.id.to_string()).collect()
}

fn fresh() -> (TempDir, PathBuf, Vault) {
    let d = dir();
    let key = KeyFile::generate(&d.path().join("k")).unwrap();
    let p = d.path().join("v.db");
    let v = Vault::create(&p, key).unwrap();
    (d, p, v)
}

// ---- every legacy key is imported or reported by name ---------------------------------------

/// A login that the vault would refuse (NUL) drops the credential. The `password` key is then
/// reported by name in `unknown_keys`, not silently lost.
#[test]
fn json_password_dropped_with_an_unusable_login_is_reported() {
    let v = json(r#"[{"login":"svc\u0000reader","password":"Tr0ub4dor-x9"}]"#);
    let i = map_secret_json(&v, &BTreeMap::new()).unwrap();
    assert!(i.entries.is_empty());
    assert!(
        i.unknown_keys.iter().any(|k| k.ends_with(".password")),
        "password key neither imported nor reported: {:?}",
        i.unknown_keys
    );
}

/// A password the vault would refuse (NUL) is not imported and is reported under its own
/// `password` key.
#[test]
fn json_unusable_password_is_reported_under_its_own_key() {
    let v = json(r#"[{"login":"svc-reader","password":"Tr0ub\u0000dor"}]"#);
    let i = map_secret_json(&v, &BTreeMap::new()).unwrap();
    assert!(i.entries.is_empty());
    assert!(
        i.unknown_keys.iter().any(|k| k.ends_with(".password")),
        "{:?}",
        i.unknown_keys
    );
}

/// Oversized password (4097 bytes): the credential is not imported; the key must be named.
#[test]
fn json_oversized_password_is_reported_under_its_own_key() {
    let doc = serde_json::json!([{"login": "svc-reader", "password": "p".repeat(4097)}]);
    let i = map_secret_json(&doc, &BTreeMap::new()).unwrap();
    assert!(i.entries.is_empty());
    assert!(
        i.unknown_keys.iter().any(|k| k.ends_with(".password")),
        "{:?}",
        i.unknown_keys
    );
}

/// Every key of every camera is accounted for: emitted as an entry, or reported.
#[test]
fn json_every_non_null_key_is_imported_or_reported() {
    let cases = [
        r#"{"name":"Garage","login":"a","username":"b","password":"p"}"#,
        r#"{"name":"   ","login":"a","password":"p"}"#,
        r#"{"name":"Gar\tage","username":"u"}"#,
        r#"{"login":"","username":"","password":"p"}"#,
        r#"{"name":"Front Gate","x":1}"#,
    ];
    let m = BTreeMap::from([("Garage".to_owned(), "tapo".to_owned())]);
    for c in cases {
        let doc = json(&format!("[{c}]"));
        let obj = doc[0].as_object().unwrap().clone();
        let i = map_secret_json(&doc, &m).unwrap();
        let reported: BTreeSet<String> = i
            .unknown_keys
            .iter()
            .map(|k| k.rsplit('.').next().unwrap().to_owned())
            .collect();
        let has = |f: &str| i.entries.iter().any(|e| e.id.as_str().ends_with(f));
        for key in obj.keys() {
            let imported = match key.as_str() {
                "name" => has(":name"),
                "login" | "username" | "password" => has(":credential"),
                _ => false,
            };
            assert!(
                imported || reported.contains(key),
                "{c}: key {key} neither imported nor reported ({:?})",
                i.unknown_keys
            );
        }
    }
}

/// TOML: every key either becomes an entry, is a known public key, or is reported.
#[test]
fn toml_every_key_is_imported_skipped_as_public_or_reported() {
    let t = toml_of(
        "[cameras.a]\nhost = \"bad host\"\nmac = \"zz\"\nserial = \"  \"\nname = \"\\u0007\"\n\
         display_name = \"Rear Yard\"\nvendor = \"x\"\n[cameras.b]\ndisplay_name = \"Side Gate\"\n",
    );
    let i = map_inventory_toml(&t).unwrap();
    assert_eq!(ids(&i), ["cam:b:name"]);
    let rep: BTreeSet<&str> = i.unknown_keys.iter().map(String::as_str).collect();
    for k in ["a.host", "a.mac", "a.serial", "a.name", "a.display_name"] {
        assert!(rep.contains(k), "{k} missing from {rep:?}");
    }
}

// ---- no collisions across files or between ordinals and real ids ----------------------------

/// Brute force: inventory ids that look like ordinals in every way still never collide.
#[test]
fn ordinal_lookalikes_never_collide_in_map_legacy() {
    let lookalikes = [
        "import-json-1",
        "import-toml-1",
        "import-",
        "import-json-01",
        "import-1",
    ];
    for la in lookalikes {
        let m = BTreeMap::from([("A".to_owned(), la.to_owned())]);
        let j = json(r#"[{"name":"A","login":"u","password":"p"},{"login":"v","password":"q"}]"#);
        let t = toml_of(&format!(
            "[cameras.\"{la}\"]\nhost = \"192.0.2.10\"\n[cameras.\"Bad Name\"]\nhost = \"192.0.2.11\"\n"
        ));
        let i = map_legacy(Some(&j), &m, Some(&t)).unwrap();
        let mut seen = BTreeSet::new();
        for e in &i.entries {
            assert!(seen.insert(e.id.to_string()), "{la}: duplicate {}", e.id);
        }
        // All five values imported exactly once.
        assert_eq!(i.entries.len(), 5, "{la}: {:?}", ids(&i));
    }
}

/// Colons inside a mapped inventory id cannot forge another camera's field id.
#[test]
fn inventory_id_with_colons_cannot_alias_another_cameras_field() {
    let m = BTreeMap::from([
        ("A".to_owned(), "x:name".to_owned()),
        ("B".to_owned(), "x".to_owned()),
    ]);
    let j = json(
        r#"[{"name":"A","login":"u","password":"p"},{"name":"B","login":"v","password":"q"}]"#,
    );
    let i = map_secret_json(&j, &m).unwrap();
    let set: BTreeSet<String> = ids(&i).into_iter().collect();
    // The inventory owns display names, so only the two credentials are emitted.
    assert_eq!(set.len(), 2);
}

/// `merge` refuses a duplicate in either direction and keeps nothing from a failed merge.
#[test]
fn merge_is_symmetric_on_duplicates() {
    let first = map_inventory_toml(&toml_of("[cameras.tapo]\nname = \"Garage\"\n")).unwrap();
    let second = map_inventory_toml(&toml_of("[cameras.tapo]\nname = \"Side\"\n")).unwrap();
    let again = map_inventory_toml(&toml_of("[cameras.tapo]\nname = \"Garage\"\n")).unwrap();
    let dup = LegacyError::DuplicateId("cam:tapo:name".to_owned());
    assert_eq!(first.merge(second).unwrap_err(), dup);
    let other = map_inventory_toml(&toml_of("[cameras.tapo]\nname = \"Side\"\n")).unwrap();
    assert_eq!(other.merge(again).unwrap_err(), dup);
}

/// The full `map_legacy` output imports into a vault without any id being written twice: the
/// vault ends up with exactly as many entries as the mapping produced.
#[test]
fn map_legacy_output_imports_one_to_one() {
    let (_d, _p, mut vault) = fresh();
    let names = BTreeMap::from([
        ("Front Gate".to_owned(), "reolink-1".to_owned()),
        ("Garage".to_owned(), "tapo".to_owned()),
    ]);
    let agent = json(
        r#"[{"name":"Front Gate","login":"svc-reader","password":"Tr0ub4dor-x9"},
            {"name":"Garage","username":"admin","password":"pw-garage-1"},
            {"login":"anon","password":"pw-anon-12"}]"#,
    );
    let inv = toml_of(
        "[cameras.reolink-1]\nhost = \"192.0.2.10\"\nmac = \"02:00:5e:00:53:af\"\n\
         [cameras.tapo]\nserial = \"SN-0042-ZQ\"\n[cameras.\"Odd One\"]\nhost = \"nvr-1.example.invalid\"\n",
    );
    let imp = map_legacy(Some(&agent), &names, Some(&inv)).unwrap();
    for e in &imp.entries {
        vault.set(&e.id, e.kind, &e.value, Scan::Normal).unwrap();
    }
    assert_eq!(vault.list().unwrap().len(), imp.entries.len());
}

// ---- mapper validation matches set ----------------------------------------------------------

/// Anything the mapper emits, `set` accepts (table of nasty but valid-looking values).
#[test]
fn every_emitted_toml_value_is_accepted_by_set() {
    let (_d, _p, mut v) = fresh();
    let hosts = [
        "192.0.2.10",
        "2001:DB8::1",
        "NVR-1.EXAMPLE.INVALID.",
        "_sip._tcp.example.invalid",
        "a",
        "0x1.example",
        "1.2.3.4.",
        "255.255.255.255",
        "::ffff:192.0.2.1",
    ];
    for (n, h) in hosts.iter().enumerate() {
        let t = toml_of(&format!(
            "[cameras.c{n}]\nhost = \"{h}\"\nserial = \"  SN 1  \"\nmac = \"0200.5E00.53AF\"\nname = \" Back Door \"\n"
        ));
        let i = map_inventory_toml(&t).unwrap();
        for e in &i.entries {
            v.set(&e.id, e.kind, &e.value, Scan::Normal)
                .unwrap_or_else(|err| panic!("{h}: {} refused: {err}", e.id));
        }
    }
}

// ---- Scan::PublicOccurrence restricted --------------------------------------------------------

#[test]
fn public_occurrence_refused_for_every_non_secret_kind_and_nothing_written() {
    let (_d, _p, mut v) = fresh();
    for kind in [
        EntryKind::Host,
        EntryKind::Mac,
        EntryKind::Serial,
        EntryKind::DisplayName,
        EntryKind::Other,
    ] {
        let r = v.set(
            &EntryId::new("x:y").unwrap(),
            kind,
            &Value::Text(SecretString::from("192.0.2.10".to_owned())),
            Scan::PublicOccurrence,
        );
        assert!(
            matches!(r, Err(VaultError::PublicOccurrenceKind { .. })),
            "{kind}"
        );
    }
    assert_eq!(v.list().unwrap().len(), 0);
    v.set(
        &EntryId::new("x:c").unwrap(),
        EntryKind::Credential,
        &Value::Credential(Credentials::new("svc-reader", "Tr0ub4dor-x9")),
        Scan::PublicOccurrence,
    )
    .unwrap();
}

// ---- create: NotEmpty and never touching a foreign file ---------------------------------------

fn foreign_db(path: &std::path::Path, wal: bool) {
    let c = rusqlite::Connection::open(path).unwrap();
    if wal {
        let _: String = c
            .query_row("PRAGMA journal_mode = WAL", [], |r| r.get(0))
            .unwrap();
    }
    c.execute_batch("CREATE TABLE t(x); INSERT INTO t VALUES ('synthetic');")
        .unwrap();
    drop(c);
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

#[test]
fn create_on_a_foreign_rollback_db_is_not_empty_and_leaves_it_unchanged() {
    let d = dir();
    let p = d.path().join("v.db");
    foreign_db(&p, false);
    let before = std::fs::read(&p).unwrap();
    let key = KeyFile::generate(&d.path().join("k")).unwrap();
    assert!(matches!(Vault::create(&p, key), Err(VaultError::NotEmpty)));
    assert_eq!(std::fs::read(&p).unwrap(), before);
}

/// A WAL-mode database: `create` refuses it with `NotEmpty` and leaves its bytes and the
/// directory listing unchanged (no pragma runs before the read-only probe).
#[test]
fn create_on_a_foreign_wal_db_is_not_empty_and_leaves_it_unchanged() {
    let d = dir();
    let p = d.path().join("v.db");
    foreign_db(&p, true);
    let before = std::fs::read(&p).unwrap();
    let listing = |d: &std::path::Path| {
        let mut n: Vec<_> = std::fs::read_dir(d)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        n.sort();
        n
    };
    let key = KeyFile::generate(&d.path().join("k")).unwrap();
    let names_before = listing(d.path());
    assert!(matches!(Vault::create(&p, key), Err(VaultError::NotEmpty)));
    assert_eq!(
        std::fs::read(&p).unwrap(),
        before,
        "create modified a foreign database it refused"
    );
    assert_eq!(
        listing(d.path()),
        names_before,
        "-wal/-shm created or removed"
    );
}

#[test]
fn create_on_a_file_with_only_the_sqlite_header_does_not_initialise() {
    let d = dir();
    let p = d.path().join("v.db");
    let mut bytes = b"SQLite format 3\0".to_vec();
    bytes.extend_from_slice(&[0xAB; 200]);
    std::fs::write(&p, &bytes).unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
    let key = KeyFile::generate(&d.path().join("k")).unwrap();
    assert!(Vault::create(&p, key).is_err());
    assert_eq!(std::fs::read(&p).unwrap(), bytes);
}

#[test]
fn create_twice_reports_already_initialized() {
    let (d, p, v) = fresh();
    drop(v);
    let key = KeyFile::generate(&d.path().join("k2")).unwrap();
    assert!(matches!(
        Vault::create(&p, key),
        Err(VaultError::AlreadyInitialized)
    ));
}

#[test]
fn create_on_a_short_non_sqlite_file_is_not_empty() {
    let d = dir();
    let p = d.path().join("v.db");
    std::fs::write(&p, b"SQLite").unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
    let key = KeyFile::generate(&d.path().join("k")).unwrap();
    assert!(matches!(Vault::create(&p, key), Err(VaultError::NotEmpty)));
    assert_eq!(std::fs::read(&p).unwrap(), b"SQLite");
}

/// `open` on a foreign database (either journal mode) is refused as `NotInitialized` and the
/// file is left byte-for-byte unchanged: no pragma runs before the read-only probe.
fn open_foreign_leaves_it_unchanged(wal: bool) {
    let d = dir();
    let p = d.path().join("v.db");
    foreign_db(&p, wal);
    let before = std::fs::read(&p).unwrap();
    let key = KeyFile::generate(&d.path().join("k")).unwrap();
    assert!(matches!(
        Vault::open(&p, key),
        Err(VaultError::NotInitialized)
    ));
    assert_eq!(std::fs::read(&p).unwrap(), before);
}

#[test]
fn open_on_a_foreign_wal_db_is_refused_and_leaves_it_unchanged() {
    open_foreign_leaves_it_unchanged(true);
}

#[test]
fn open_on_a_foreign_rollback_db_is_refused_and_leaves_it_unchanged() {
    open_foreign_leaves_it_unchanged(false);
}
