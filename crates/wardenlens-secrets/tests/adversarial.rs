//! Adversarial tests for wardenlens-secrets. Synthetic data only.

#![expect(
    clippy::unwrap_used,
    reason = "integration-test helpers outside #[test] fns; clippy.toml in-tests allowances do not reach them"
)]

use std::fmt::Write as _;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::mpsc;
use std::time::Duration;

use proptest::prelude::*;
use secrecy::ExposeSecret;
use wardenlens_secrets::{
    KeyFile, MAX_RECORD_LEN, MIN_RECORD_LEN, RecordKind, SecretsError, open, open_credentials,
    seal, seal_credentials,
};

const ID: &str = "cam:reolink-1:credential";

fn key() -> KeyFile {
    KeyFile::from_base64("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=").unwrap()
}

const ALL_KINDS: [RecordKind; 8] = [
    RecordKind::Keycheck,
    RecordKind::Credential,
    RecordKind::Secret,
    RecordKind::Host,
    RecordKind::Mac,
    RecordKind::Serial,
    RecordKind::DisplayName,
    RecordKind::Other,
];

/// Runs `f` on a thread and fails (instead of hanging the suite) if it takes too long.
fn within<T: Send + 'static>(secs: u64, f: impl FnOnce() -> T + Send + 'static) -> Option<T> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(f());
    });
    rx.recv_timeout(Duration::from_secs(secs)).ok()
}

fn mkfifo(p: &Path) {
    let st = std::process::Command::new("mkfifo")
        .arg("-m")
        .arg("600")
        .arg(p)
        .status()
        .unwrap();
    assert!(st.success());
}

// ---- key file: non-regular files ----

#[test]
fn load_refuses_fifo_without_blocking() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("vault.key");
    mkfifo(&p);
    let p2 = p.clone();
    let res = within(3, move || KeyFile::load(&p2).map(|_| ()));
    // Unblock the hung open (if any) so the leaked thread can finish.
    let _ = std::fs::OpenOptions::new()
        .write(true)
        .custom_flags_nonblock()
        .open(&p);
    match res {
        None => panic!("KeyFile::load blocked on a FIFO instead of refusing it"),
        Some(r) => assert!(matches!(r, Err(SecretsError::KeyFileNotRegular)), "{r:?}"),
    }
}

trait NonBlock {
    fn custom_flags_nonblock(&mut self) -> &mut Self;
}
impl NonBlock for std::fs::OpenOptions {
    fn custom_flags_nonblock(&mut self) -> &mut Self {
        use std::os::unix::fs::OpenOptionsExt;
        self.custom_flags(i32::try_from(rustix::fs::OFlags::NONBLOCK.bits()).unwrap())
    }
}

#[test]
fn load_refuses_char_device() {
    // /dev/null is a char device; it must be refused as non-regular (or wrong owner).
    let r = KeyFile::load(Path::new("/dev/null"));
    assert!(
        matches!(
            r,
            Err(SecretsError::KeyFileNotRegular | SecretsError::KeyFileWrongOwner)
        ),
        "{r:?}"
    );
}

#[test]
fn generate_onto_dangling_symlink_creates_nothing() {
    let d = tempfile::tempdir().unwrap();
    let target = d.path().join("elsewhere");
    let link = d.path().join("vault.key");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    let r = KeyFile::generate(&link);
    assert!(r.is_err());
    assert!(!target.exists());
    // Link itself is untouched (still a symlink).
    assert!(
        fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink()
    );
}

#[test]
fn generate_into_missing_dir_is_typed_error() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("nope").join("vault.key");
    assert!(matches!(
        KeyFile::generate(&p),
        Err(SecretsError::Io { .. })
    ));
}

#[test]
fn generate_root_path_has_no_parent() {
    assert!(KeyFile::generate(Path::new("/")).is_err());
}

#[test]
fn work_tree_refusal_through_symlinked_parent() {
    // Parent is a symlink into a git work tree; canonicalisation must still catch it.
    let repo = tempfile::tempdir().unwrap();
    fs::create_dir(repo.path().join(".git")).unwrap();
    let inner = repo.path().join("inner");
    fs::create_dir(&inner).unwrap();
    let outside = tempfile::tempdir().unwrap();
    let alias = outside.path().join("alias");
    std::os::unix::fs::symlink(&inner, &alias).unwrap();
    let p = alias.join("vault.key");
    assert!(matches!(
        KeyFile::generate(&p),
        Err(SecretsError::KeyFileInWorkTree)
    ));
    assert!(!inner.join("vault.key").exists());
}

#[test]
fn work_tree_refusal_with_dotdot_path() {
    let repo = tempfile::tempdir().unwrap();
    fs::create_dir(repo.path().join(".git")).unwrap();
    fs::create_dir(repo.path().join("a")).unwrap();
    let p = repo.path().join("a").join("..").join("vault.key");
    assert!(matches!(
        KeyFile::generate(&p),
        Err(SecretsError::KeyFileInWorkTree)
    ));
}

#[test]
fn load_mode_edge_bits() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("vault.key");
    fs::write(&p, [9u8; 32]).unwrap();
    for mode in [0o602, 0o620, 0o607, 0o670, 0o700 | 0o001] {
        fs::set_permissions(&p, fs::Permissions::from_mode(mode)).unwrap();
        assert!(
            matches!(KeyFile::load(&p), Err(SecretsError::KeyFilePermissions)),
            "{mode:o}"
        );
    }
    fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(KeyFile::load(&p).is_ok());
}

#[test]
fn load_large_sparse_file_refused_cheaply() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("vault.key");
    let f = fs::File::create(&p).unwrap();
    f.set_len(1 << 40).unwrap();
    drop(f);
    fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(matches!(
        KeyFile::load(&p),
        Err(SecretsError::KeyFileWrongLength)
    ));
}

// ---- base64 import ----

#[test]
fn base64_rejects_non_canonical_and_variant_forms() {
    let good = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
    // Last data char '8' -> '9' only changes discarded trailing bits: must be rejected
    // so a key has exactly one text form.
    let trailing = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh9=";
    let double_pad = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHg==";
    let no_pad_33 = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8A";
    let url_safe = "_v_-__7__v_-__7__v_-__7__v_-__7__v_-__7__v8=";
    let inner_ws = "AAECAwQFBgcICQoLDA0ODxAREhMU FRYXGBkaGxwdHh8=";
    let nul = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8\0";
    for bad in [trailing, double_pad, no_pad_33, url_safe, inner_ws, nul] {
        assert!(
            matches!(
                KeyFile::from_base64(bad),
                Err(SecretsError::InvalidKeyEncoding)
            ),
            "{bad:?}"
        );
    }
    assert!(KeyFile::from_base64(good).is_ok());
    assert!(KeyFile::from_base64(&format!("\r\n\t {good} \r\n")).is_ok());
}

#[test]
fn base64_multibyte_44_bytes_rejected() {
    // 22 two-byte chars = 44 bytes, passes the length gate, must still fail.
    let s = "é".repeat(22);
    assert_eq!(s.len(), 44);
    assert!(matches!(
        KeyFile::from_base64(&s),
        Err(SecretsError::InvalidKeyEncoding)
    ));
}

// ---- record binding ----

#[test]
fn every_kind_pair_is_bound() {
    let k = key();
    for a in ALL_KINDS {
        let rec = seal(&k, a, "x:1", b"value-123").unwrap();
        for b in ALL_KINDS {
            let r = open(&k, b, "x:1", &rec);
            if a == b {
                assert_eq!(&r.unwrap()[..], b"value-123");
            } else {
                assert!(
                    matches!(r, Err(SecretsError::Authentication)),
                    "{a:?}->{b:?}"
                );
            }
        }
    }
}

#[test]
fn kind_codes_distinct_and_stable() {
    let codes: Vec<u8> = ALL_KINDS.iter().map(|k| k.code()).collect();
    assert_eq!(codes, vec![0, 1, 2, 3, 4, 5, 6, 7]);
}

#[test]
fn id_prefix_and_suffix_variants_do_not_authenticate() {
    let k = key();
    let rec = seal(&k, RecordKind::Host, "cam:1", b"192.0.2.10").unwrap();
    for other in ["cam:", "cam:10", "cam:1.", "cam", "cam:1:"] {
        assert!(matches!(
            open(&k, RecordKind::Host, other, &rec),
            Err(SecretsError::Authentication)
        ));
    }
}

#[test]
fn nonce_and_ciphertext_splice_between_records_fails() {
    let k = key();
    let a = seal(&k, RecordKind::Secret, "s:a", b"aaaaaaaa").unwrap();
    let b = seal(&k, RecordKind::Secret, "s:a", b"bbbbbbbb").unwrap();
    let mut spliced = a[..25].to_vec();
    spliced.extend_from_slice(&b[25..]);
    assert!(matches!(
        open(&k, RecordKind::Secret, "s:a", &spliced),
        Err(SecretsError::Authentication)
    ));
}

#[test]
fn version_byte_extremes() {
    let k = key();
    let mut rec = seal(&k, RecordKind::Host, "h", b"x").unwrap();
    for v in [0x00u8, 0x02, 0x7f, 0x80, 0xff] {
        rec[0] = v;
        assert!(matches!(
            open(&k, RecordKind::Host, "h", &rec),
            Err(SecretsError::UnsupportedVersion(got)) if got == v
        ));
    }
}

#[test]
fn record_length_boundaries() {
    let k = key();
    // Exactly MIN_RECORD_LEN of garbage with version 1: auth error, not truncation, no panic.
    let mut r = vec![0u8; MIN_RECORD_LEN];
    r[0] = 1;
    assert!(matches!(
        open(&k, RecordKind::Host, "h", &r),
        Err(SecretsError::Authentication)
    ));
    let mut r = vec![0u8; MAX_RECORD_LEN];
    r[0] = 1;
    assert!(matches!(
        open(&k, RecordKind::Host, "h", &r),
        Err(SecretsError::Authentication)
    ));
    // Largest sealable plaintext round-trips and opens.
    let pt = vec![0xabu8; MAX_RECORD_LEN - MIN_RECORD_LEN];
    let rec = seal(&k, RecordKind::Other, "o", &pt).unwrap();
    assert_eq!(rec.len(), MAX_RECORD_LEN);
    assert_eq!(
        &open(&k, RecordKind::Other, "o", &rec).unwrap()[..],
        &pt[..]
    );
}

#[test]
fn id_boundary_charset() {
    let k = key();
    for good in ["0", "a", "9:_.-", "a-", "a..", "z_"] {
        assert!(seal(&k, RecordKind::Other, good, b"x").is_ok(), "{good}");
    }
    for bad in [
        "_a",
        ".a",
        "a/b",
        "a\0",
        "a\n",
        "A",
        "a b",
        "a\u{200b}",
        "ａ",
    ] {
        assert!(
            matches!(
                seal(&k, RecordKind::Other, bad, b"x"),
                Err(SecretsError::InvalidId)
            ),
            "{bad:?}"
        );
    }
}

// ---- credential plaintext decoding ----

fn crafted(k: &KeyFile, pt: &[u8]) -> Result<wardenlens_secrets::Credentials, SecretsError> {
    let rec = seal(k, RecordKind::Credential, ID, pt).unwrap();
    open_credentials(k, ID, &rec)
}

#[test]
fn crafted_credential_plaintexts() {
    let k = key();
    // Username length 4097 with enough data: malformed.
    let mut pt = vec![0x10, 0x01];
    pt.extend(vec![b'u'; 4097]);
    assert!(matches!(
        crafted(&k, &pt),
        Err(SecretsError::MalformedPlaintext(_))
    ));
    // Username 4095, password 4097 (fits the seal limit): malformed.
    let mut pt = vec![0x0f, 0xff];
    pt.extend(vec![b'u'; 4095]);
    pt.extend(vec![b'p'; 4097]);
    assert!(matches!(
        crafted(&k, &pt),
        Err(SecretsError::MalformedPlaintext(_))
    ));
    // Invalid UTF-8 in username / password.
    assert!(matches!(
        crafted(&k, &[0, 1, 0xc3]),
        Err(SecretsError::MalformedPlaintext(_))
    ));
    assert!(matches!(
        crafted(&k, &[0, 0, 0xff]),
        Err(SecretsError::MalformedPlaintext(_))
    ));
    // Empty plaintext.
    assert!(matches!(
        crafted(&k, &[]),
        Err(SecretsError::MalformedPlaintext(_))
    ));
    // Zero-length username, password containing NUL: decodes faithfully.
    let c = crafted(&k, &[0, 0, b'a', 0, b'b']).unwrap();
    assert_eq!(c.username, "");
    assert_eq!(c.password.expose_secret(), "a\0b");
    // Username containing the separator-like bytes is length-delimited, not parsed.
    let c = crafted(&k, &[0, 3, b':', 0, b':', b'p']).unwrap();
    assert_eq!(c.username, ":\0:");
    assert_eq!(c.password.expose_secret(), "p");
}

#[test]
fn credential_record_cannot_be_opened_as_other_kind_and_vice_versa() {
    let k = key();
    let rec = seal_credentials(
        &k,
        ID,
        &wardenlens_secrets::Credentials::new("user", "correct-horse"),
    )
    .unwrap();
    assert!(matches!(
        open(&k, RecordKind::Secret, ID, &rec),
        Err(SecretsError::Authentication)
    ));
    let rec = seal(
        &k,
        RecordKind::Secret,
        ID,
        &[0, 4, b'u', b's', b'e', b'r', b'p'],
    )
    .unwrap();
    assert!(matches!(
        open_credentials(&k, ID, &rec),
        Err(SecretsError::Authentication)
    ));
}

#[test]
fn error_texts_never_echo_inputs() {
    let k = key();
    let secret = "correct-horse-Zq9";
    let mut errs = vec![
        crafted(&k, &[0xff, 0xff]).unwrap_err(),
        KeyFile::from_base64(&format!("{secret}{secret}{secret}12345678")).unwrap_err(),
        seal(&k, RecordKind::Other, secret, b"x").unwrap_err(),
    ];
    let mut rec = seal(&k, RecordKind::Secret, "s", secret.as_bytes()).unwrap();
    rec[0] = 9;
    errs.push(open(&k, RecordKind::Secret, "s", &rec).unwrap_err());
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join(secret);
    errs.push(KeyFile::load(&p).unwrap_err());
    for e in errs {
        let mut shown = format!("{e} {e:?}");
        let mut src = std::error::Error::source(&e);
        while let Some(s) = src {
            let _ = write!(shown, " {s} {s:?}");
            src = s.source();
        }
        assert!(!shown.contains(secret), "{shown}");
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn open_credentials_garbage_never_panics(data in prop::collection::vec(any::<u8>(), 0..300)) {
        let _ = open_credentials(&key(), ID, &data);
    }

    #[test]
    fn crafted_credential_plaintext_never_panics(pt in prop::collection::vec(any::<u8>(), 0..300)) {
        let k = key();
        let _ = crafted(&k, &pt);
    }

    #[test]
    fn single_bit_flip_anywhere_never_authenticates(
        pt in prop::collection::vec(any::<u8>(), 0..64),
        pos in any::<prop::sample::Index>(),
        bit in 0u8..8,
    ) {
        let k = key();
        let rec = seal(&k, RecordKind::Serial, "dev:1:serial", &pt).unwrap();
        let mut bad = rec.clone();
        let i = pos.index(bad.len());
        bad[i] ^= 1 << bit;
        prop_assert!(open(&k, RecordKind::Serial, "dev:1:serial", &bad).is_err());
    }

    #[test]
    fn from_base64_arbitrary_text_never_panics(s in ".{0,100}") {
        let _ = KeyFile::from_base64(&s);
    }
}
