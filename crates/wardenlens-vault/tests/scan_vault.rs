//! The scanner built from a real (temporary) vault: credentials, unscannable entries and the
//! error mapping. Synthetic values only.

#![expect(
    clippy::unwrap_used,
    reason = "integration-test helpers outside #[test] fns; clippy.toml in-tests allowances do not reach them"
)]

use std::os::unix::fs::PermissionsExt;

use secrecy::SecretString;
use tempfile::TempDir;
use wardenlens_core::entry::{EntryId, EntryKind};
use wardenlens_secrets::{Credentials, KeyFile};
use wardenlens_vault::{Matcher, Scan, Value, Vault, scan};

fn id(s: &str) -> EntryId {
    EntryId::new(s).unwrap()
}

fn text(s: &str) -> Value {
    Value::Text(SecretString::from(s.to_owned()))
}

fn vault() -> (TempDir, Vault) {
    let d = tempfile::tempdir().unwrap();
    std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let key = KeyFile::generate(&d.path().join("k")).unwrap();
    let v = Vault::create(&d.path().join("v.db"), key).unwrap();
    (d, v)
}

#[test]
fn matcher_from_a_vault_scans_passwords_not_usernames_and_lists_unscannable_entries() {
    let (_d, mut v) = vault();
    let cred = Value::Credential(Credentials::new("svc-reader-account", "Tr0ub4dor-x9"));
    v.set(
        &id("cam:a:credential"),
        EntryKind::Credential,
        &cred,
        Scan::Normal,
    )
    .unwrap();
    v.set(
        &id("cam:a:host"),
        EntryKind::Host,
        &text("192.0.2.10"),
        Scan::Normal,
    )
    .unwrap();
    v.set(
        &id("cam:a:short"),
        EntryKind::Secret,
        &text("abc"),
        Scan::Normal,
    )
    .unwrap();
    v.set(
        &id("cloud:pub"),
        EntryKind::Secret,
        &text("already-public-token"),
        Scan::PublicOccurrence,
    )
    .unwrap();

    let m = Matcher::from_vault(&v).unwrap();
    let listed: Vec<&str> = m.unscannable().iter().map(|u| u.id.as_str()).collect();
    assert_eq!(listed, vec!["cam:a:short", "cloud:pub"]);
    assert_eq!(m.scanned_len(), 2);

    let username_only = scan(&m, b"user svc-reader-account logged in").unwrap();
    assert!(username_only.hits.is_empty(), "usernames are not scanned");
    let report = scan(
        &m,
        b"pw=Tr0ub4dor-x9 at 192.0.2.10\nthe token already-public-token abc",
    )
    .unwrap();
    let got: Vec<(usize, &str)> = report
        .hits
        .iter()
        .map(|h| (h.line, h.id.as_str()))
        .collect();
    assert_eq!(got, vec![(1, "cam:a:credential"), (1, "cam:a:host")]);
}

#[test]
fn an_empty_vault_yields_a_matcher_that_finds_nothing() {
    let (_d, v) = vault();
    let m = Matcher::from_vault(&v).unwrap();
    assert_eq!(m.scanned_len(), 0);
    assert_eq!(scan(&m, b"192.0.2.10 anything").unwrap().hits, vec![]);
}
