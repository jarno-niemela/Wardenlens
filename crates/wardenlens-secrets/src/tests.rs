//! Synthetic data only: user / correct-horse, ids of the form `cam:reolink-1:credential`.

use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::PathBuf;

use proptest::prelude::*;
use secrecy::ExposeSecret;
use tempfile::TempDir;

use super::*;

const PASSWORD: &str = "correct-horse";
const ID: &str = "cam:reolink-1:credential";

/// A temp dir that is not inside a git work tree (the system temp dir).
fn dir() -> TempDir {
    tempfile::tempdir().unwrap()
}

fn key_path(d: &TempDir) -> PathBuf {
    d.path().join("vault.key")
}

fn key() -> KeyFile {
    KeyFile::from_base64("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=").unwrap()
}

fn other_key() -> KeyFile {
    KeyFile::from_base64("/v/+//7//v/+//7//v/+//7//v/+//7//v/+//7//v8=").unwrap()
}

fn creds() -> Credentials {
    Credentials::new("user", PASSWORD)
}

// ---- Credentials ----

#[test]
fn credentials_debug_hides_secret_and_username() {
    let text = format!("{:?}", Credentials::new("svc-reader", PASSWORD));
    assert!(!text.contains(PASSWORD));
    assert!(!text.contains("svc-reader"));
    assert!(text.contains("password: [redacted]"));
}

#[test]
fn credentials_round_trip() {
    let k = key();
    let rec = seal_credentials(&k, ID, &creds()).unwrap();
    let back = open_credentials(&k, ID, &rec).unwrap();
    assert_eq!(back.username, "user");
    assert_eq!(back.password.expose_secret(), PASSWORD);
}

#[test]
fn credentials_edges_empty_unicode_and_max() {
    let k = key();
    for (u, p) in [
        ("", ""),
        ("ü:ser", "pässwörd-日本"),
        (&"u".repeat(4096), &"p".repeat(4096)),
    ] {
        let rec = seal_credentials(&k, ID, &Credentials::new(u, p)).unwrap();
        let back = open_credentials(&k, ID, &rec).unwrap();
        assert_eq!(back.username, u);
        assert_eq!(back.password.expose_secret(), p);
    }
}

#[test]
fn credentials_over_limit_rejected() {
    let k = key();
    let long = "x".repeat(4097);
    assert!(matches!(
        seal_credentials(&k, ID, &Credentials::new(long.clone(), "p")),
        Err(SecretsError::TooLarge)
    ));
    assert!(matches!(
        seal_credentials(&k, ID, &Credentials::new("u", long)),
        Err(SecretsError::TooLarge)
    ));
}

#[test]
fn malformed_credential_plaintext_is_typed_error() {
    let k = key();
    // Sealed as a credential but the layout is wrong: length prefix larger than the data.
    let rec = seal(&k, RecordKind::Credential, ID, &[0xff, 0xff, b'a']).unwrap();
    assert!(matches!(
        open_credentials(&k, ID, &rec),
        Err(SecretsError::MalformedPlaintext(RecordKind::Credential))
    ));
    let rec = seal(&k, RecordKind::Credential, ID, &[0x00]).unwrap();
    assert!(matches!(
        open_credentials(&k, ID, &rec),
        Err(SecretsError::MalformedPlaintext(_))
    ));
    let rec = seal(&k, RecordKind::Credential, ID, &[0x00, 0x01, 0xff]).unwrap();
    assert!(matches!(
        open_credentials(&k, ID, &rec),
        Err(SecretsError::MalformedPlaintext(_))
    ));
}

// ---- record format ----

#[test]
fn record_layout_is_version_nonce_ciphertext_tag() {
    let rec = seal(
        &key(),
        RecordKind::Host,
        "cam:reolink-1:host",
        b"192.0.2.10",
    )
    .unwrap();
    assert_eq!(rec.first(), Some(&0x01));
    assert_eq!(rec.len(), 1 + 24 + b"192.0.2.10".len() + 16);
    assert_eq!(MIN_RECORD_LEN, 41);
}

#[test]
fn nonce_is_fresh_for_every_seal() {
    let k = key();
    let a = seal(&k, RecordKind::Secret, "cloud:example:token", b"t").unwrap();
    let b = seal(&k, RecordKind::Secret, "cloud:example:token", b"t").unwrap();
    assert_ne!(a, b);
}

#[test]
fn empty_plaintext_round_trips() {
    let k = key();
    let rec = seal(&k, RecordKind::Other, "note:1", b"").unwrap();
    assert!(
        open(&k, RecordKind::Other, "note:1", &rec)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn tampering_any_byte_fails_without_panic() {
    let k = key();
    let rec = seal(&k, RecordKind::Host, "cam:reolink-1:host", b"192.0.2.10").unwrap();
    for i in 0..rec.len() {
        let mut bad = rec.clone();
        bad[i] ^= 0x01;
        let err = open(&k, RecordKind::Host, "cam:reolink-1:host", &bad).unwrap_err();
        if i == 0 {
            assert!(matches!(err, SecretsError::UnsupportedVersion(0))); // 0x01 ^ 0x01
        } else {
            assert!(matches!(err, SecretsError::Authentication), "byte {i}");
        }
    }
}

#[test]
fn wrong_key_kind_or_id_fails() {
    let k = key();
    let rec = seal(&k, RecordKind::Host, "cam:reolink-1:host", b"192.0.2.10").unwrap();
    assert!(matches!(
        open(&other_key(), RecordKind::Host, "cam:reolink-1:host", &rec),
        Err(SecretsError::Authentication)
    ));
    assert!(matches!(
        open(&k, RecordKind::Credential, "cam:reolink-1:host", &rec),
        Err(SecretsError::Authentication)
    ));
    assert!(matches!(
        open(&k, RecordKind::Host, "cam:reolink-2:host", &rec),
        Err(SecretsError::Authentication)
    ));
}

#[test]
fn keycheck_kind_is_not_interchangeable_with_entry_kinds() {
    let k = key();
    let rec = seal(&k, RecordKind::Keycheck, "meta:keycheck", b"x").unwrap();
    assert!(open(&k, RecordKind::Other, "meta:keycheck", &rec).is_err());
    assert_eq!(RecordKind::Keycheck.code(), 0);
    assert_eq!(RecordKind::Other.code(), 7);
}

#[test]
fn truncation_is_typed_error() {
    let k = key();
    let rec = seal(&k, RecordKind::Host, "cam:reolink-1:host", b"192.0.2.10").unwrap();
    assert!(matches!(
        open(&k, RecordKind::Host, "cam:reolink-1:host", &[]),
        Err(SecretsError::Truncated)
    ));
    for n in 0..MIN_RECORD_LEN {
        assert!(matches!(
            open(&k, RecordKind::Host, "cam:reolink-1:host", &rec[..n]),
            Err(SecretsError::Truncated)
        ));
    }
    for n in MIN_RECORD_LEN..rec.len() {
        assert!(matches!(
            open(&k, RecordKind::Host, "cam:reolink-1:host", &rec[..n]),
            Err(SecretsError::Authentication)
        ));
    }
}

#[test]
fn unknown_version_is_typed_error() {
    let k = key();
    let mut rec = seal(&k, RecordKind::Host, "h", b"x").unwrap();
    rec[0] = 0x02;
    assert!(matches!(
        open(&k, RecordKind::Host, "h", &rec),
        Err(SecretsError::UnsupportedVersion(2))
    ));
}

#[test]
fn oversized_record_and_plaintext_rejected() {
    let k = key();
    assert!(matches!(
        open(&k, RecordKind::Host, "h", &vec![1u8; MAX_RECORD_LEN + 1]),
        Err(SecretsError::TooLarge)
    ));
    assert!(matches!(
        seal(&k, RecordKind::Other, "h", &vec![0u8; 2 + 2 * 4096 + 1]),
        Err(SecretsError::TooLarge)
    ));
}

#[test]
fn invalid_ids_rejected() {
    let k = key();
    let long = "a".repeat(129);
    for id in ["", "Upper", "-lead", ":lead", "sp ace", "ü", long.as_str()] {
        assert!(
            matches!(
                seal(&k, RecordKind::Other, id, b"x"),
                Err(SecretsError::InvalidId)
            ),
            "{id:?}"
        );
        assert!(matches!(
            open(&k, RecordKind::Other, id, &[0; 41]),
            Err(SecretsError::InvalidId)
        ));
    }
    assert!(seal(&k, RecordKind::Other, &"a".repeat(128), b"x").is_ok());
}

// ---- error messages ----

#[test]
fn error_messages_carry_no_secret_material() {
    let k = key();
    let b64 = k.to_base64();
    let rec = seal_credentials(&k, ID, &creds()).unwrap();
    let mut errors = vec![
        open(&other_key(), RecordKind::Credential, ID, &rec).unwrap_err(),
        open(&k, RecordKind::Credential, ID, &rec[..10]).unwrap_err(),
        open(&k, RecordKind::Credential, "BAD ID", &rec).unwrap_err(),
        KeyFile::from_base64(PASSWORD).unwrap_err(),
    ];
    let d = dir();
    let p = key_path(&d);
    fs::write(&p, PASSWORD).unwrap();
    fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
    errors.push(KeyFile::load(&p).unwrap_err());
    for e in errors {
        let shown = format!("{e} {e:?}");
        assert!(!shown.contains(PASSWORD), "{shown}");
        assert!(!shown.contains(b64.as_str()), "{shown}");
        assert!(!shown.contains("user"), "{shown}");
    }
    assert_eq!(format!("{k:?}"), "KeyFile([redacted])");
}

proptest! {
    #[test]
    fn round_trip_any_plaintext(
        kind in prop::sample::select(vec![
            RecordKind::Secret, RecordKind::Host, RecordKind::Mac, RecordKind::Serial,
            RecordKind::DisplayName, RecordKind::Other, RecordKind::Keycheck,
        ]),
        id in "[a-z0-9][a-z0-9:_.-]{0,127}",
        plaintext in prop::collection::vec(any::<u8>(), 0..4096),
    ) {
        let k = key();
        let rec = seal(&k, kind, &id, &plaintext).unwrap();
        let back = open(&k, kind, &id, &rec).unwrap();
        prop_assert_eq!(&back[..], &plaintext[..]);
    }

    #[test]
    fn credentials_round_trip_any(u in ".{0,64}", p in ".{0,64}") {
        let k = key();
        let rec = seal_credentials(&k, ID, &Credentials::new(u.clone(), p.clone())).unwrap();
        let back = open_credentials(&k, ID, &rec).unwrap();
        prop_assert_eq!(back.username, u);
        prop_assert_eq!(back.password.expose_secret(), p.as_str());
    }

    #[test]
    fn open_never_panics_and_errors_are_clean(data in prop::collection::vec(any::<u8>(), 0..200)) {
        if let Err(e) = open(&key(), RecordKind::Other, "x", &data) {
            let shown = format!("{e} {e:?}");
            prop_assert!(!shown.contains(PASSWORD));
        }
    }

    #[test]
    fn key_base64_round_trip(bytes in prop::array::uniform32(any::<u8>())) {
        use base64::Engine;
        let text = base64::engine::general_purpose::STANDARD.encode(bytes);
        let k = KeyFile::from_base64(&text).unwrap();
        let out = k.to_base64();
        prop_assert_eq!(out.as_str(), text.as_str());
    }
}

// ---- key file ----

#[test]
fn generate_creates_0600_32_byte_file_and_load_reads_it() {
    let d = dir();
    let p = key_path(&d);
    let generated = KeyFile::generate(&p).unwrap();
    let meta = fs::metadata(&p).unwrap();
    assert_eq!(meta.permissions().mode() & 0o777, 0o600);
    assert_eq!(meta.len(), 32);
    let loaded = KeyFile::load(&p).unwrap();
    assert_eq!(generated.to_base64().as_str(), loaded.to_base64().as_str());
}

#[test]
fn generate_never_overwrites() {
    let d = dir();
    let p = key_path(&d);
    KeyFile::generate(&p).unwrap();
    let before = fs::read(&p).unwrap();
    assert!(matches!(
        KeyFile::generate(&p),
        Err(SecretsError::KeyFileExists)
    ));
    assert_eq!(fs::read(&p).unwrap(), before);
}

#[test]
fn generate_refuses_symlink_target() {
    let d = dir();
    let target = d.path().join("target");
    let p = key_path(&d);
    symlink(&target, &p).unwrap();
    assert!(KeyFile::generate(&p).is_err());
    assert!(!target.exists());
}

#[test]
fn generated_keys_differ() {
    let d = dir();
    let a = KeyFile::generate(&d.path().join("a")).unwrap();
    let b = KeyFile::generate(&d.path().join("b")).unwrap();
    assert_ne!(a.to_base64().as_str(), b.to_base64().as_str());
}

#[test]
fn load_refuses_wrong_lengths() {
    let d = dir();
    let p = key_path(&d);
    for len in [0usize, 31, 33, 64] {
        fs::write(&p, vec![7u8; len]).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(
            matches!(KeyFile::load(&p), Err(SecretsError::KeyFileWrongLength)),
            "{len}"
        );
    }
}

#[test]
fn load_refuses_group_or_world_bits() {
    let d = dir();
    let p = key_path(&d);
    for mode in [0o640, 0o604, 0o660, 0o606, 0o644, 0o601, 0o610, 0o666] {
        fs::write(&p, [7u8; 32]).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(mode)).unwrap();
        assert!(
            matches!(KeyFile::load(&p), Err(SecretsError::KeyFilePermissions)),
            "{mode:o}"
        );
    }
    for mode in [0o600, 0o400] {
        fs::set_permissions(&p, fs::Permissions::from_mode(mode)).unwrap();
        assert!(KeyFile::load(&p).is_ok(), "{mode:o}");
    }
}

#[test]
fn load_refuses_symlink_even_to_a_good_file() {
    let d = dir();
    let real = d.path().join("real.key");
    KeyFile::generate(&real).unwrap();
    let link = d.path().join("link.key");
    symlink(&real, &link).unwrap();
    assert!(matches!(
        KeyFile::load(&link),
        Err(SecretsError::KeyFileSymlink)
    ));
}

#[test]
fn load_refuses_directory_and_missing_file() {
    let d = dir();
    assert!(matches!(
        KeyFile::load(d.path()),
        Err(SecretsError::KeyFileNotRegular
            | SecretsError::KeyFilePermissions
            | SecretsError::Io { .. })
    ));
    assert!(matches!(
        KeyFile::load(&key_path(&d)),
        Err(SecretsError::Io { .. })
    ));
}

#[test]
fn refuses_key_inside_git_work_tree() {
    let d = dir();
    fs::create_dir(d.path().join(".git")).unwrap();
    let sub = d.path().join("sub");
    fs::create_dir(&sub).unwrap();
    let p = sub.join("vault.key");
    assert!(matches!(
        KeyFile::generate(&p),
        Err(SecretsError::KeyFileInWorkTree)
    ));
    assert!(!p.exists());
    // A `.git` file (linked worktree) counts too.
    let d2 = dir();
    fs::write(d2.path().join(".git"), "gitdir: x").unwrap();
    let p2 = key_path(&d2);
    assert!(matches!(
        KeyFile::generate(&p2),
        Err(SecretsError::KeyFileInWorkTree)
    ));
    // load refuses too, even for a well-formed key placed there by hand.
    fs::write(&p2, [7u8; 32]).unwrap();
    fs::set_permissions(&p2, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(matches!(
        KeyFile::load(&p2),
        Err(SecretsError::KeyFileInWorkTree)
    ));
}

#[test]
fn export_import_round_trip_writes_0600() {
    let d = dir();
    let k = key();
    let text = k.to_base64();
    assert_eq!(text.len(), 44);
    let p = key_path(&d);
    KeyFile::import(&p, &text).unwrap();
    assert_eq!(
        fs::metadata(&p).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        KeyFile::load(&p).unwrap().to_base64().as_str(),
        text.as_str()
    );
    assert!(matches!(
        KeyFile::import(&p, &text),
        Err(SecretsError::KeyFileExists)
    ));
}

#[test]
fn from_base64_rejects_bad_input() {
    for bad in [
        "",
        "AAAA",
        "not base64 not base64 not base64 not base64!!",
        &"A".repeat(10_000),
        "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
    ] {
        assert!(
            matches!(
                KeyFile::from_base64(bad),
                Err(SecretsError::InvalidKeyEncoding)
            ),
            "{bad:.20}"
        );
    }
    // Surrounding whitespace (a trailing newline from a paste) is tolerated.
    assert!(KeyFile::from_base64("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=\n").is_ok());
}

#[test]
fn import_with_bad_text_creates_nothing() {
    let d = dir();
    let p = key_path(&d);
    assert!(KeyFile::import(&p, "garbage").is_err());
    assert!(!p.exists());
}
