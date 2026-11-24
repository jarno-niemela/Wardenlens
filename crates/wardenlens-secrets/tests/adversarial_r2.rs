//! Round-2 adversarial tests for wardenlens-secrets. Synthetic data only.

#![expect(
    clippy::unwrap_used,
    reason = "integration-test helpers outside #[test] fns; clippy.toml in-tests allowances do not reach them"
)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::sync::{Arc, Barrier, mpsc};
use std::time::Duration;

use secrecy::ExposeSecret;
use wardenlens_secrets::{
    Credentials, KeyFile, MAX_RECORD_LEN, MAX_VALUE_LEN, MIN_RECORD_LEN, RecordKind, SecretsError,
    open, open_credentials, seal, seal_credentials,
};

const B64: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";

fn key() -> KeyFile {
    KeyFile::from_base64(B64).unwrap()
}

fn within<T: Send + 'static>(secs: u64, f: impl FnOnce() -> T + Send + 'static) -> Option<T> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(f());
    });
    rx.recv_timeout(Duration::from_secs(secs)).ok()
}

// ---- load: non-regular files must be refused without blocking ----

#[test]
fn load_refuses_unix_socket_without_blocking() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("sock");
    let _l = UnixListener::bind(&p).unwrap();
    let r = within(5, move || KeyFile::load(&p).map(|_| ()));
    let r = r.expect("load on a socket blocked");
    // Opening a socket gives ENXIO; any refusal is fine, success is not.
    assert!(matches!(
        r,
        Err(SecretsError::KeyFileNotRegular | SecretsError::Io { .. })
    ));
}

#[test]
fn load_fifo_with_a_writer_present_is_still_refused() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("fifo");
    let st = std::process::Command::new("mkfifo")
        .arg("-m")
        .arg("600")
        .arg(&p)
        .status()
        .unwrap();
    assert!(st.success());
    // Keep a reader+writer open so the FIFO has data available.
    let mut w = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&p)
        .unwrap();
    std::io::Write::write_all(&mut w, &[7u8; 32]).unwrap();
    let r = within(5, move || KeyFile::load(&p).map(|_| ())).expect("blocked");
    assert!(matches!(r, Err(SecretsError::KeyFileNotRegular)));
}

#[test]
fn load_regular_key_still_works_with_nonblock() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("k");
    let g = KeyFile::generate(&p).unwrap();
    let l = KeyFile::load(&p).unwrap();
    assert_eq!(*g.to_base64(), *l.to_base64());
}

#[test]
fn load_accepts_0400_and_refuses_unreadable_0200() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("k");
    KeyFile::generate(&p).unwrap();
    fs::set_permissions(&p, fs::Permissions::from_mode(0o400)).unwrap();
    assert!(KeyFile::load(&p).is_ok());
    // Running as root would bypass DAC; only assert when not root.
    if rustix::process::getuid().is_root() {
        return;
    }
    fs::set_permissions(&p, fs::Permissions::from_mode(0o200)).unwrap();
    assert!(matches!(KeyFile::load(&p), Err(SecretsError::Io { .. })));
}

#[test]
fn load_trailing_slash_on_regular_file_is_refused() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("k");
    KeyFile::generate(&p).unwrap();
    let mut s = p.into_os_string();
    s.push("/");
    assert!(KeyFile::load(std::path::Path::new(&s)).is_err());
}

#[test]
fn load_symlink_to_directory_is_symlink_error() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("k");
    std::os::unix::fs::symlink(d.path(), &p).unwrap();
    assert!(matches!(
        KeyFile::load(&p),
        Err(SecretsError::KeyFileSymlink)
    ));
}

#[test]
fn load_empty_and_nonexistent_paths_do_not_panic() {
    assert!(KeyFile::load(std::path::Path::new("")).is_err());
    assert!(KeyFile::load(std::path::Path::new("/")).is_err());
    assert!(KeyFile::generate(std::path::Path::new("")).is_err());
}

// ---- generate / import ----

#[test]
fn concurrent_generate_exactly_one_wins_and_its_key_survives() {
    let d = tempfile::tempdir().unwrap();
    let p = Arc::new(d.path().join("k"));
    let n = 16;
    let bar = Arc::new(Barrier::new(n));
    let hs: Vec<_> = (0..n)
        .map(|_| {
            let p = Arc::clone(&p);
            let bar = Arc::clone(&bar);
            std::thread::spawn(move || {
                bar.wait();
                KeyFile::generate(&p).map(|k| k.to_base64().to_string())
            })
        })
        .collect();
    let mut wins = Vec::new();
    for h in hs {
        match h.join().unwrap() {
            Ok(k) => wins.push(k),
            Err(SecretsError::KeyFileExists) => {}
            Err(e) => panic!("unexpected error {e:?}"),
        }
    }
    assert_eq!(wins.len(), 1);
    let loaded = KeyFile::load(&p).unwrap();
    assert_eq!(*loaded.to_base64(), wins[0]);
}

#[test]
fn generate_in_readonly_dir_is_io_error_and_leaves_nothing() {
    if rustix::process::getuid().is_root() {
        return;
    }
    let d = tempfile::tempdir().unwrap();
    let sub = d.path().join("ro");
    fs::create_dir(&sub).unwrap();
    fs::set_permissions(&sub, fs::Permissions::from_mode(0o500)).unwrap();
    let p = sub.join("k");
    assert!(matches!(
        KeyFile::generate(&p),
        Err(SecretsError::Io { .. })
    ));
    assert!(!p.exists());
    fs::set_permissions(&sub, fs::Permissions::from_mode(0o700)).unwrap();
}

#[test]
fn generate_existing_file_is_untouched() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("k");
    fs::write(&p, b"not a key, must be preserved").unwrap();
    assert!(matches!(
        KeyFile::generate(&p),
        Err(SecretsError::KeyFileExists)
    ));
    assert!(matches!(
        KeyFile::import(&p, B64),
        Err(SecretsError::KeyFileExists)
    ));
    assert_eq!(fs::read(&p).unwrap(), b"not a key, must be preserved");
}

#[test]
fn generate_relative_path_works_without_parent_component() {
    // Relative path with an explicit parent inside a temp dir; the bare-name case uses ".".
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("./sub/../k");
    fs::create_dir(d.path().join("sub")).unwrap();
    KeyFile::generate(&p).unwrap();
    assert!(KeyFile::load(&d.path().join("k")).is_ok());
}

#[test]
fn import_trims_surrounding_whitespace_only() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("k");
    let k = KeyFile::import(&p, &format!(" \t\r\n{B64}\r\n")).unwrap();
    assert_eq!(*k.to_base64(), B64);
    // Whitespace inside the text is not accepted.
    let mut inner = B64.to_owned();
    inner.insert(10, '\n');
    assert!(matches!(
        KeyFile::from_base64(&inner),
        Err(SecretsError::InvalidKeyEncoding)
    ));
}

#[test]
fn from_base64_huge_input_is_rejected_quickly() {
    let big = "A".repeat(32 * 1024 * 1024);
    let r = within(5, move || KeyFile::from_base64(&big).map(|_| ())).expect("slow");
    assert!(matches!(r, Err(SecretsError::InvalidKeyEncoding)));
}

#[test]
fn from_base64_unpadded_and_url_safe_rejected() {
    let unpadded = B64.trim_end_matches('=');
    assert!(KeyFile::from_base64(unpadded).is_err());
    // 44 chars without padding would decode to 33 bytes.
    assert!(KeyFile::from_base64(&format!("{unpadded}A")).is_err());
    // A key whose standard form contains '+' and '/' must not be accepted in URL-safe form.
    let std_text = base64_of(&[0xfb; 32]);
    assert!(std_text.contains('+') || std_text.contains('/'));
    assert!(KeyFile::from_base64(&std_text).is_ok());
    let url = std_text.replace('+', "-").replace('/', "_");
    assert!(matches!(
        KeyFile::from_base64(&url),
        Err(SecretsError::InvalidKeyEncoding)
    ));
}

#[test]
fn to_base64_is_exact_and_does_not_reallocate() {
    for b in [[0u8; 32], [0xffu8; 32]] {
        let text = base64_of(&b);
        let k = KeyFile::from_base64(&text).unwrap();
        let out = k.to_base64();
        assert_eq!(out.len(), 44);
        assert_eq!(out.capacity(), 44, "encoder reallocated the key text");
        assert_eq!(*out, text);
    }
}

fn base64_of(b: &[u8; 32]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(b)
}

#[test]
fn key_debug_never_shows_key() {
    let k = key();
    let dbg = format!("{k:?}");
    assert!(!dbg.contains(B64));
    assert!(!dbg.contains("0, 1, 2"));
}

// ---- record: boundaries ----

#[test]
fn seal_plaintext_limit_is_exact() {
    let k = key();
    let max = MAX_RECORD_LEN - MIN_RECORD_LEN;
    let rec = seal(&k, RecordKind::Other, "o", &vec![b'a'; max]).unwrap();
    assert_eq!(rec.len(), MAX_RECORD_LEN);
    assert_eq!(open(&k, RecordKind::Other, "o", &rec).unwrap().len(), max);
    assert!(matches!(
        seal(&k, RecordKind::Other, "o", &vec![b'a'; max + 1]),
        Err(SecretsError::TooLarge)
    ));
}

#[test]
fn max_credentials_round_trip_at_record_limit() {
    let k = key();
    let c = Credentials::new("u".repeat(MAX_VALUE_LEN), "p".repeat(MAX_VALUE_LEN));
    let rec = seal_credentials(&k, "cam:x:credential", &c).unwrap();
    assert_eq!(rec.len(), MAX_RECORD_LEN);
    let back = open_credentials(&k, "cam:x:credential", &rec).unwrap();
    assert_eq!(back.username.len(), MAX_VALUE_LEN);
    assert_eq!(back.password.expose_secret().len(), MAX_VALUE_LEN);
}

#[test]
fn multibyte_credentials_count_bytes_not_chars() {
    let k = key();
    // 4-byte chars: 1025 of them is 4100 bytes > 4096.
    let c = Credentials::new("\u{1F600}".repeat(1025), "x");
    assert!(matches!(
        seal_credentials(&k, "a", &c),
        Err(SecretsError::TooLarge)
    ));
    let c = Credentials::new("x", "\u{1F600}".repeat(1024));
    let rec = seal_credentials(&k, "a", &c).unwrap();
    let back = open_credentials(&k, "a", &rec).unwrap();
    assert_eq!(back.password.expose_secret().len(), 4096);
}

#[test]
fn credentials_with_nul_and_crlf_round_trip() {
    let k = key();
    let c = Credentials::new("us\0er\r\n", "pa\0ss\r\n\u{202E}");
    let rec = seal_credentials(&k, "a", &c).unwrap();
    let back = open_credentials(&k, "a", &rec).unwrap();
    assert_eq!(back.username, "us\0er\r\n");
    assert_eq!(back.password.expose_secret(), "pa\0ss\r\n\u{202E}");
}

#[test]
fn open_checks_id_before_touching_record() {
    let k = key();
    let rec = seal(&k, RecordKind::Host, "h", b"192.0.2.10").unwrap();
    assert!(matches!(
        open(&k, RecordKind::Host, "H", &rec),
        Err(SecretsError::InvalidId)
    ));
    assert!(matches!(
        open(&k, RecordKind::Host, "", &[]),
        Err(SecretsError::InvalidId)
    ));
}

#[test]
fn record_from_one_key_does_not_open_with_a_key_differing_in_one_bit() {
    let k = key();
    let mut raw = [0u8; 32];
    for (i, b) in raw.iter_mut().enumerate() {
        *b = u8::try_from(i).unwrap();
    }
    raw[31] ^= 1;
    let k2 = KeyFile::from_base64(&base64_of(&raw)).unwrap();
    let rec = seal(&k, RecordKind::Secret, "s", b"correct-horse").unwrap();
    assert!(matches!(
        open(&k2, RecordKind::Secret, "s", &rec),
        Err(SecretsError::Authentication)
    ));
}

#[test]
fn appended_or_removed_trailing_bytes_fail_authentication() {
    let k = key();
    let rec = seal(&k, RecordKind::Secret, "s", b"correct-horse").unwrap();
    let mut longer = rec.clone();
    longer.push(0);
    assert!(matches!(
        open(&k, RecordKind::Secret, "s", &longer),
        Err(SecretsError::Authentication)
    ));
    let shorter = &rec[..rec.len() - 1];
    assert!(matches!(
        open(&k, RecordKind::Secret, "s", shorter),
        Err(SecretsError::Authentication)
    ));
}

#[test]
fn seal_and_open_are_thread_safe_with_shared_key() {
    let k = Arc::new(key());
    let hs: Vec<_> = (0..8)
        .map(|i| {
            let k = Arc::clone(&k);
            std::thread::spawn(move || {
                let id = format!("t:{i}");
                for j in 0..200u32 {
                    let pt = j.to_be_bytes();
                    let rec = seal(&k, RecordKind::Serial, &id, &pt).unwrap();
                    assert_eq!(&*open(&k, RecordKind::Serial, &id, &rec).unwrap(), &pt);
                }
            })
        })
        .collect();
    for h in hs {
        h.join().unwrap();
    }
}

#[test]
fn error_display_for_every_variant_is_free_of_inputs() {
    let k = key();
    let secret = "correct-horse-Zq9";
    let rec = seal(&k, RecordKind::Secret, "s", secret.as_bytes()).unwrap();
    let errs = [
        open(&k, RecordKind::Host, "s", &rec).unwrap_err(),
        open(&k, RecordKind::Secret, "s", &rec[..10]).unwrap_err(),
        open(&k, RecordKind::Secret, "s", &vec![0u8; MAX_RECORD_LEN + 1]).unwrap_err(),
        KeyFile::from_base64(secret).unwrap_err(),
    ];
    for e in errs {
        let shown = format!("{e} {e:?}");
        assert!(!shown.contains(secret), "{shown}");
        assert!(!shown.contains(B64), "{shown}");
    }
}
