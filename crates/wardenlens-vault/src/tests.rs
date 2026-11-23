//! Vault tests: temporary directories and synthetic values only.

use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};

use rusqlite::params;
use secrecy::{ExposeSecret, SecretString};
use tempfile::TempDir;
use wardenlens_core::entry::{EntryId, EntryKind};
use wardenlens_fsutil::FsError;
use wardenlens_secrets::{Credentials, KeyFile};

use crate::{Value, Vault, VaultError};

fn dir() -> TempDir {
    let d = tempfile::tempdir().unwrap();
    // tempfile follows the umask; the vault wants a directory nobody else can write.
    std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    d
}

fn new_key(dir: &Path, name: &str) -> KeyFile {
    KeyFile::generate(&dir.join(name)).unwrap()
}

fn same_key(dir: &Path, name: &str) -> KeyFile {
    KeyFile::load(&dir.join(name)).unwrap()
}

fn db(dir: &TempDir) -> PathBuf {
    dir.path().join("vault.db")
}

fn id(s: &str) -> EntryId {
    EntryId::new(s).unwrap()
}

fn text(s: &str) -> Value {
    Value::Text(SecretString::from(s.to_owned()))
}

fn read_text(v: &Vault, i: &str) -> String {
    match v.get(&id(i)).unwrap().unwrap().value {
        Value::Text(t) => t.expose_secret().to_owned(),
        _ => panic!("not text"),
    }
}

fn fresh() -> (TempDir, Vault) {
    let d = dir();
    let key = new_key(d.path(), "k1");
    let v = Vault::create(&db(&d), key).unwrap();
    (d, v)
}

// ---- open sequence -------------------------------------------------------------------------

#[test]
fn create_makes_a_private_file_and_no_sidecars() {
    let (d, mut v) = fresh();
    v.set(
        &id("cam:a:host"),
        EntryKind::Host,
        &text("192.0.2.10"),
        false,
    )
    .unwrap();
    let mode = std::fs::metadata(db(&d)).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    let mut names: Vec<String> = std::fs::read_dir(d.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    assert_eq!(names, ["k1", "vault.db"]);
}

#[test]
fn open_round_trips_entries() {
    let (d, mut v) = fresh();
    v.set(
        &id("cam:a:host"),
        EntryKind::Host,
        &text("NVR-1.example.invalid"),
        false,
    )
    .unwrap();
    drop(v);
    let v = Vault::open(&db(&d), same_key(d.path(), "k1")).unwrap();
    assert_eq!(read_text(&v, "cam:a:host"), "nvr-1.example.invalid");
}

#[test]
fn open_of_missing_file_fails_without_creating_it() {
    let d = dir();
    let key = new_key(d.path(), "k1");
    assert!(matches!(
        Vault::open(&db(&d), key),
        Err(VaultError::NotFound)
    ));
    assert!(!db(&d).exists());
}

#[test]
fn open_of_empty_file_is_not_initialized() {
    let d = dir();
    let key = new_key(d.path(), "k1");
    drop(wardenlens_fsutil::open_private_file(&db(&d)).unwrap());
    assert!(matches!(
        Vault::open(&db(&d), key),
        Err(VaultError::NotInitialized)
    ));
}

#[test]
fn create_twice_is_refused() {
    let (d, v) = fresh();
    drop(v);
    let e = Vault::create(&db(&d), same_key(d.path(), "k1")).unwrap_err();
    assert!(matches!(e, VaultError::AlreadyInitialized));
}

#[test]
fn wrong_key_is_detected_by_the_keycheck() {
    let (d, v) = fresh();
    drop(v);
    let other = new_key(d.path(), "k2");
    assert!(matches!(
        Vault::open(&db(&d), other),
        Err(VaultError::WrongKey)
    ));
}

#[test]
fn refuses_a_symlinked_database() {
    let (d, v) = fresh();
    drop(v);
    let link = d.path().join("link.db");
    symlink(db(&d), &link).unwrap();
    let e = Vault::open(&link, same_key(d.path(), "k1")).unwrap_err();
    assert!(matches!(e, VaultError::Fs(_)), "{e}");
    let e = Vault::create(&link, same_key(d.path(), "k1")).unwrap_err();
    assert!(matches!(e, VaultError::Fs(_)), "{e}");
}

#[test]
fn refuses_a_dangling_symlink_without_creating_its_target() {
    let d = dir();
    let key = new_key(d.path(), "k1");
    let target = d.path().join("target.db");
    let link = d.path().join("link.db");
    symlink(&target, &link).unwrap();
    assert!(Vault::create(&link, key).is_err());
    assert!(!target.exists());
}

#[test]
fn refuses_a_file_swapped_after_our_descriptor_was_checked() {
    let (d, v) = fresh();
    drop(v);
    let path = db(&d);
    let swap = || {
        // An attacker replaces the checked file with another private file.
        let moved = path.with_extension("moved");
        std::fs::rename(&path, &moved).unwrap();
        std::fs::copy(&moved, &path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    };
    let e = Vault::open_with(&path, same_key(d.path(), "k1"), swap).unwrap_err();
    assert!(
        matches!(e, VaultError::Fs(FsError::IdentityMismatch)),
        "{e}"
    );
}

#[test]
fn refuses_a_file_replaced_by_a_symlink_after_the_check() {
    let (d, v) = fresh();
    drop(v);
    let path = db(&d);
    let other = d.path().join("other.db");
    std::fs::copy(&path, &other).unwrap();
    std::fs::set_permissions(&other, std::fs::Permissions::from_mode(0o600)).unwrap();
    let swap = || {
        std::fs::remove_file(&path).unwrap();
        symlink(&other, &path).unwrap();
    };
    assert!(Vault::open_with(&path, same_key(d.path(), "k1"), swap).is_err());
}

#[test]
fn refuses_a_group_or_world_writable_parent() {
    for mode in [0o770, 0o707, 0o777, 0o720, 0o702] {
        let d = dir();
        let key = new_key(d.path(), "k1");
        std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(mode)).unwrap();
        let e = Vault::create(&db(&d), key).unwrap_err();
        assert!(matches!(e, VaultError::ParentWritable), "{mode:o}: {e}");
        assert!(!db(&d).exists(), "{mode:o}");
    }
}

#[test]
fn accepts_a_parent_readable_by_others() {
    let d = dir();
    let key = new_key(d.path(), "k1");
    std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    Vault::create(&db(&d), key).unwrap();
}

#[test]
fn refuses_a_database_inside_a_git_work_tree() {
    let d = dir();
    let key = new_key(d.path(), "k1");
    let tree = d.path().join("work");
    std::fs::create_dir_all(tree.join(".git")).unwrap();
    std::fs::create_dir(tree.join("sub")).unwrap();
    let e = Vault::create(&tree.join("sub").join("v.db"), key).unwrap_err();
    assert!(matches!(e, VaultError::InWorkTree), "{e}");
}

#[test]
fn refuses_a_database_with_group_access() {
    let (d, v) = fresh();
    drop(v);
    std::fs::set_permissions(db(&d), std::fs::Permissions::from_mode(0o640)).unwrap();
    let e = Vault::open(&db(&d), same_key(d.path(), "k1")).unwrap_err();
    assert!(
        matches!(e, VaultError::Fs(FsError::InsecureMode { .. })),
        "{e}"
    );
}

#[test]
fn refuses_a_database_that_is_a_directory() {
    let d = dir();
    let key = new_key(d.path(), "k1");
    let sub = d.path().join("sub.db");
    std::fs::create_dir(&sub).unwrap();
    assert!(matches!(
        Vault::open(&sub, key),
        Err(VaultError::Fs(FsError::NotRegular))
    ));
}

#[test]
fn open_refuses_a_store_with_too_many_entries() {
    let (d, v) = fresh();
    insert_dummy_rows(&v, 10_001);
    drop(v);
    let e = Vault::open(&db(&d), same_key(d.path(), "k1")).unwrap_err();
    assert!(matches!(e, VaultError::TooManyEntries), "{e}");
}

fn insert_dummy_rows(v: &Vault, n: usize) {
    let tx = v.raw().unchecked_transaction().unwrap();
    for i in 0..n {
        tx.execute(
            "INSERT INTO entries(id, kind, record, created_at, updated_at) VALUES (?1, 7, x'00', 0, 0)",
            [format!("row{i}")],
        )
        .unwrap();
    }
    tx.commit().unwrap();
}

#[test]
fn set_refuses_the_10001st_entry_but_allows_replacing() {
    let (_d, mut v) = fresh();
    insert_dummy_rows(&v, 10_000);
    let e = v
        .set(
            &id("cam:new:other"),
            EntryKind::Other,
            &text("anything long"),
            false,
        )
        .unwrap_err();
    assert!(matches!(e, VaultError::TooManyEntries), "{e}");
    v.set(&id("row1"), EntryKind::Other, &text("replacement"), false)
        .unwrap();
}

// ---- set / get / list / rm -----------------------------------------------------------------

#[test]
fn credential_round_trip() {
    let (_d, mut v) = fresh();
    let c = Value::Credential(Credentials::new("svc-reader", "Tr0ub4dor-x9"));
    v.set(&id("cam:a:credential"), EntryKind::Credential, &c, false)
        .unwrap();
    let got = v.get(&id("cam:a:credential")).unwrap().unwrap();
    assert_eq!(got.kind, EntryKind::Credential);
    let Value::Credential(c) = got.value else {
        panic!("shape")
    };
    assert_eq!(c.username, "svc-reader");
    assert_eq!(c.password.expose_secret(), "Tr0ub4dor-x9");
}

#[test]
fn every_text_kind_round_trips_normalised() {
    let (_d, mut v) = fresh();
    let cases = [
        (EntryKind::Secret, "tok-Abc123xyz", "tok-Abc123xyz"),
        (EntryKind::Host, "192.0.2.10", "192.0.2.10"),
        (EntryKind::Mac, "02-00-5E-00-53-AF", "02:00:5e:00:53:af"),
        (EntryKind::Serial, " SN-0042-ZQ ", "SN-0042-ZQ"),
        (EntryKind::DisplayName, "Back Door North", "Back Door North"),
        (EntryKind::Other, "12 Example Lane", "12 Example Lane"),
    ];
    for (i, (kind, input, stored)) in cases.iter().enumerate() {
        let eid = format!("t:{i}");
        v.set(&id(&eid), *kind, &text(input), false).unwrap();
        assert_eq!(read_text(&v, &eid), *stored);
        assert_eq!(v.get(&id(&eid)).unwrap().unwrap().kind, *kind);
    }
}

#[test]
fn get_of_unknown_id_is_none() {
    let (_d, v) = fresh();
    assert!(v.get(&id("nope")).unwrap().is_none());
}

#[test]
fn set_replaces_and_can_change_kind() {
    let (_d, mut v) = fresh();
    v.set(&id("x"), EntryKind::Other, &text("first value"), false)
        .unwrap();
    v.set(&id("x"), EntryKind::Secret, &text("second value"), false)
        .unwrap();
    let got = v.get(&id("x")).unwrap().unwrap();
    assert_eq!(got.kind, EntryKind::Secret);
    assert_eq!(v.list().unwrap().len(), 1);
}

#[test]
fn list_shows_ids_kinds_and_flags_sorted() {
    let (_d, mut v) = fresh();
    v.set(
        &id("b"),
        EntryKind::Secret,
        &text("long enough secret"),
        false,
    )
    .unwrap();
    v.set(&id("a"), EntryKind::Secret, &text("short"), false)
        .unwrap();
    let l = v.list().unwrap();
    let got: Vec<(&str, EntryKind, bool)> = l
        .iter()
        .map(|e| (e.id.as_str(), e.kind, e.unscannable))
        .collect();
    assert_eq!(
        got,
        [
            ("a", EntryKind::Secret, true),
            ("b", EntryKind::Secret, false)
        ]
    );
}

#[test]
fn rm_removes_and_reports_absence() {
    let (_d, mut v) = fresh();
    v.set(&id("x"), EntryKind::Other, &text("some value"), false)
        .unwrap();
    assert!(v.rm(&id("x")).unwrap());
    assert!(!v.rm(&id("x")).unwrap());
    assert!(v.get(&id("x")).unwrap().is_none());
}

#[test]
fn value_shape_must_match_the_kind() {
    let (_d, mut v) = fresh();
    let cred = Value::Credential(Credentials::new("u", "p"));
    assert!(matches!(
        v.set(&id("x"), EntryKind::Host, &cred, false),
        Err(VaultError::ValueKindMismatch { .. })
    ));
    assert!(matches!(
        v.set(&id("x"), EntryKind::Credential, &text("u:p"), false),
        Err(VaultError::ValueKindMismatch { .. })
    ));
}

#[test]
fn value_limit_is_4096_bytes_for_every_kind() {
    let (_d, mut v) = fresh();
    for kind in [
        EntryKind::Secret,
        EntryKind::Serial,
        EntryKind::DisplayName,
        EntryKind::Other,
    ] {
        v.set(&id("x"), kind, &text(&"v".repeat(4096)), false)
            .unwrap();
        let e = v
            .set(&id("x"), kind, &text(&"v".repeat(4097)), false)
            .unwrap_err();
        assert!(matches!(e, VaultError::ValueTooLarge { .. }), "{kind}: {e}");
    }
    let big =
        |u: usize, p: usize| Value::Credential(Credentials::new("u".repeat(u), "p".repeat(p)));
    v.set(&id("c"), EntryKind::Credential, &big(4096, 4096), false)
        .unwrap();
    assert!(
        v.set(&id("c"), EntryKind::Credential, &big(4097, 1), false)
            .is_err()
    );
    assert!(
        v.set(&id("c"), EntryKind::Credential, &big(1, 4097), false)
            .is_err()
    );
    let got = v.get(&id("c")).unwrap().unwrap();
    let Value::Credential(c) = got.value else {
        panic!("shape")
    };
    assert_eq!(
        (c.username.len(), c.password.expose_secret().len()),
        (4096, 4096)
    );
}

#[test]
fn invalid_values_are_refused_per_kind() {
    let (_d, mut v) = fresh();
    let cases = [
        (EntryKind::Host, "192.0.2.300"),
        (EntryKind::Host, "bad host"),
        (EntryKind::Mac, "02:00:5e:00:53"),
        (EntryKind::Serial, ""),
        (EntryKind::Secret, ""),
    ];
    for (kind, bad) in cases {
        let e = v.set(&id("x"), kind, &text(bad), false).unwrap_err();
        assert!(
            matches!(e, VaultError::InvalidValue { .. }),
            "{kind} {bad}: {e}"
        );
    }
    assert_eq!(v.list().unwrap().len(), 0);
}

#[test]
fn errors_and_debug_never_contain_the_value() {
    let (_d, mut v) = fresh();
    let sentinel = "SENTINEL-not-a-host!";
    let e = v
        .set(&id("x"), EntryKind::Host, &text(sentinel), false)
        .unwrap_err();
    assert!(!format!("{e} {e:?}").contains("SENTINEL"));
    let big = "SENTINEL".repeat(1000);
    let e = v
        .set(&id("x"), EntryKind::Other, &text(&big), false)
        .unwrap_err();
    assert!(!format!("{e} {e:?}").contains("SENTINEL"));
    let val = Value::Credential(Credentials::new("SENTINEL-user", "SENTINEL-pass"));
    assert!(!format!("{val:?}").contains("SENTINEL"));
    assert!(!format!("{:?}", text("SENTINEL")).contains("SENTINEL"));
    v.set(&id("c"), EntryKind::Credential, &val, false).unwrap();
    let got = v.get(&id("c")).unwrap().unwrap();
    assert!(!format!("{got:?} {v:?}").contains("SENTINEL"));
}

#[test]
fn ids_with_the_reserved_prefix_cannot_be_built_or_listed() {
    assert!(EntryId::new("meta:keycheck").is_err());
    let (d, v) = fresh();
    // A row smuggled in under a reserved id is reported corrupt, not served.
    v.raw()
        .execute(
            "INSERT INTO entries(id, kind, record, created_at, updated_at) VALUES ('meta:keycheck', 7, x'00', 0, 0)",
            [],
        )
        .unwrap();
    assert!(matches!(v.list(), Err(VaultError::CorruptEntry { .. })));
    drop(d);
}

// ---- unscannable ----------------------------------------------------------------------------

#[test]
fn short_values_are_marked_unscannable() {
    let (_d, mut v) = fresh();
    assert!(
        v.set(&id("a"), EntryKind::Secret, &text("123456"), false)
            .unwrap()
    );
    assert!(
        !v.set(&id("b"), EntryKind::Secret, &text("1234567"), false)
            .unwrap()
    );
    assert!(
        v.set(&id("c"), EntryKind::Host, &text("nvr-1"), false)
            .unwrap()
    );
    assert!(
        !v.set(&id("d"), EntryKind::Host, &text("10.0.0.1"), false)
            .unwrap()
    );
    let short_pw = Value::Credential(Credentials::new("svc-reader", "pw"));
    assert!(
        v.set(&id("e"), EntryKind::Credential, &short_pw, false)
            .unwrap()
    );
    assert!(v.get(&id("a")).unwrap().unwrap().unscannable);
    assert!(!v.get(&id("b")).unwrap().unwrap().unscannable);
}

#[test]
fn force_unscannable_is_stored_and_survives_reopen() {
    let (d, mut v) = fresh();
    let long = text("a-perfectly-long-secret");
    assert!(v.set(&id("a"), EntryKind::Secret, &long, true).unwrap());
    drop(v);
    let v = Vault::open(&db(&d), same_key(d.path(), "k1")).unwrap();
    assert!(v.list().unwrap()[0].unscannable);
}

#[test]
fn replacing_a_value_recomputes_the_flag() {
    let (_d, mut v) = fresh();
    v.set(&id("a"), EntryKind::Secret, &text("short"), false)
        .unwrap();
    v.set(
        &id("a"),
        EntryKind::Secret,
        &text("a-much-longer-secret"),
        false,
    )
    .unwrap();
    assert!(!v.list().unwrap()[0].unscannable);
}

// ---- record binding -------------------------------------------------------------------------

fn record_of(v: &Vault, i: &str) -> Vec<u8> {
    v.raw()
        .query_row("SELECT record FROM entries WHERE id = ?1", [i], |r| {
            r.get(0)
        })
        .unwrap()
}

#[test]
fn swapping_two_records_is_detected() {
    let (_d, mut v) = fresh();
    v.set(&id("a"), EntryKind::Other, &text("value number one"), false)
        .unwrap();
    v.set(&id("b"), EntryKind::Other, &text("value number two"), false)
        .unwrap();
    let (ra, rb) = (record_of(&v, "a"), record_of(&v, "b"));
    v.raw()
        .execute(
            "UPDATE entries SET record = ?2 WHERE id = ?1",
            params!["a", rb],
        )
        .unwrap();
    v.raw()
        .execute(
            "UPDATE entries SET record = ?2 WHERE id = ?1",
            params!["b", ra],
        )
        .unwrap();
    assert!(matches!(
        v.get(&id("a")),
        Err(VaultError::CorruptEntry { .. })
    ));
}

#[test]
fn a_kind_column_that_disagrees_with_the_record_is_corrupt() {
    let (_d, mut v) = fresh();
    v.set(&id("a"), EntryKind::Host, &text("192.0.2.10"), false)
        .unwrap();
    v.raw()
        .execute("UPDATE entries SET kind = 1 WHERE id = 'a'", [])
        .unwrap();
    assert!(matches!(
        v.get(&id("a")),
        Err(VaultError::CorruptEntry { .. })
    ));
    v.raw()
        .execute("UPDATE entries SET kind = 99 WHERE id = 'a'", [])
        .unwrap();
    assert!(matches!(
        v.get(&id("a")),
        Err(VaultError::CorruptEntry { .. })
    ));
}

#[test]
fn the_keycheck_record_cannot_be_moved_into_entries() {
    let (_d, v) = fresh();
    let kc: Vec<u8> = v
        .raw()
        .query_row("SELECT value FROM meta WHERE key = 'keycheck'", [], |r| {
            r.get(0)
        })
        .unwrap();
    for kind in 1..=7 {
        v.raw()
            .execute(
                "INSERT OR REPLACE INTO entries(id, kind, record, created_at, updated_at) VALUES ('x', ?1, ?2, 0, 0)",
                params![kind, kc],
            )
            .unwrap();
        assert!(
            matches!(v.get(&id("x")), Err(VaultError::CorruptEntry { .. })),
            "{kind}"
        );
    }
}

#[test]
fn stored_bytes_do_not_contain_the_plaintext() {
    let (d, mut v) = fresh();
    v.set(
        &id("a"),
        EntryKind::Secret,
        &text("SENTINEL-plaintext-value"),
        false,
    )
    .unwrap();
    drop(v);
    let bytes = std::fs::read(db(&d)).unwrap();
    assert!(!bytes.windows(8).any(|w| w == b"SENTINEL"));
}

// ---- rekey ----------------------------------------------------------------------------------

fn populate(v: &mut Vault) {
    v.set(
        &id("a:host"),
        EntryKind::Host,
        &text("nvr-1.example.invalid"),
        false,
    )
    .unwrap();
    v.set(
        &id("b:cred"),
        EntryKind::Credential,
        &Value::Credential(Credentials::new("svc-reader", "Tr0ub4dor-x9")),
        false,
    )
    .unwrap();
    v.set(
        &id("c:mac"),
        EntryKind::Mac,
        &text("02:00:5e:00:53:af"),
        false,
    )
    .unwrap();
}

#[test]
fn rekey_round_trip() {
    let (d, mut v) = fresh();
    populate(&mut v);
    let before = record_of(&v, "a:host");
    v.rekey(new_key(d.path(), "k2")).unwrap();
    assert_ne!(before, record_of(&v, "a:host"));
    assert_eq!(read_text(&v, "a:host"), "nvr-1.example.invalid");
    drop(v);
    assert!(matches!(
        Vault::open(&db(&d), same_key(d.path(), "k1")),
        Err(VaultError::WrongKey)
    ));
    let v = Vault::open(&db(&d), same_key(d.path(), "k2")).unwrap();
    assert_eq!(read_text(&v, "c:mac"), "02:00:5e:00:53:af");
    let Value::Credential(c) = v.get(&id("b:cred")).unwrap().unwrap().value else {
        panic!("shape")
    };
    assert_eq!(c.password.expose_secret(), "Tr0ub4dor-x9");
}

#[test]
fn rekey_keeps_the_unscannable_flag() {
    let (d, mut v) = fresh();
    v.set(&id("a"), EntryKind::Secret, &text("short"), false)
        .unwrap();
    v.rekey(new_key(d.path(), "k2")).unwrap();
    assert!(v.list().unwrap()[0].unscannable);
}

#[test]
fn a_failed_rekey_leaves_the_old_key_valid() {
    let (d, mut v) = fresh();
    populate(&mut v);
    // Sorts after the others, so earlier rows were already re-sealed inside the transaction.
    v.raw()
        .execute(
            "INSERT INTO entries(id, kind, record, created_at, updated_at) VALUES ('zzz', 7, x'0102', 0, 0)",
            [],
        )
        .unwrap();
    let before = record_of(&v, "a:host");
    let e = v.rekey(new_key(d.path(), "k2")).unwrap_err();
    assert!(matches!(e, VaultError::CorruptEntry { .. }), "{e}");
    assert_eq!(record_of(&v, "a:host"), before);
    drop(v);
    assert!(matches!(
        Vault::open(&db(&d), same_key(d.path(), "k2")),
        Err(VaultError::WrongKey)
    ));
    let v = Vault::open(&db(&d), same_key(d.path(), "k1")).unwrap();
    assert_eq!(read_text(&v, "a:host"), "nvr-1.example.invalid");
}

#[test]
fn rekey_of_an_empty_vault_changes_the_keycheck() {
    let (d, mut v) = fresh();
    v.rekey(new_key(d.path(), "k2")).unwrap();
    drop(v);
    Vault::open(&db(&d), same_key(d.path(), "k2")).unwrap();
}
