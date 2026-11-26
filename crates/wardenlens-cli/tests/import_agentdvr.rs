//! End-to-end tests of `wardenlens import agentdvr` and `wardenlens secrets init` (#66).
//!
//! Everything is synthetic: documentation-range hosts (192.0.2.0/24), invented names and
//! passwords, temporary directories. The environment is cleared, so neither the real home nor
//! `/etc/wardenlens` is read.

#![expect(
    clippy::unwrap_used,
    reason = "integration-test helpers outside #[test] fns; clippy.toml in-tests allowances do not reach them"
)]

use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use secrecy::ExposeSecret;
use tempfile::TempDir;
use wardenlens_core::entry::EntryId;
use wardenlens_secrets::KeyFile;
use wardenlens_vault::{Value, Vault};

const PASSWORD: &str = "Zx9-fake-pass-1";
const USER: &str = "fakeuser7";
const HOST: &str = "192.0.2.77";
const NAME: &str = "Fake Porch Cam";

struct Site {
    dir: TempDir,
}

impl Site {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        for d in ["state", "keys", "in"] {
            let p = dir.path().join(d);
            fs::create_dir(&p).unwrap();
            fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let t = dir.path().display();
        let config = format!(
            "[api]\nlisten = \"127.0.0.1:8080\"\n[storage]\nhot_root = \"{t}/hot\"\n\
             archive_root = \"{t}/archive\"\n[database]\npath = \"{t}/state/index.db\"\n\
             [secrets]\nkey_file = \"{t}/keys/secrets.key\"\n"
        );
        let site = Self { dir };
        fs::write(site.config(), config).unwrap();
        fs::set_permissions(site.config(), fs::Permissions::from_mode(0o600)).unwrap();
        site
    }
    fn p(&self, rel: &str) -> PathBuf {
        self.dir.path().join(rel)
    }
    fn config(&self) -> PathBuf {
        self.p("wardenlens.toml")
    }
    fn key(&self) -> PathBuf {
        self.p("keys/secrets.key")
    }
    fn xml(&self, body: &str) -> PathBuf {
        let path = self.p("in/objects.xml");
        fs::write(
            &path,
            format!("<objects><cameras>{body}</cameras></objects>"),
        )
        .unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        path
    }
    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_wardenlens"))
            .env_clear()
            .arg("--config")
            .arg(self.config())
            .args(args)
            .stdin(Stdio::null())
            .output()
            .unwrap()
    }
    fn import(&self, file: &Path, extra: &[&str]) -> Output {
        let mut args = vec!["import", "agentdvr", file.to_str().unwrap()];
        args.extend_from_slice(extra);
        self.run(&args)
    }
    fn init_key(&self) {
        let out = self.run(&["secrets", "init"]);
        assert!(out.status.success(), "{}", text(&out.stderr));
    }
    /// Every byte under `state/`, sidecars included.
    fn state_bytes(&self) -> Vec<u8> {
        let mut all = Vec::new();
        for e in fs::read_dir(self.p("state")).unwrap() {
            all.extend(fs::read(e.unwrap().path()).unwrap());
        }
        all
    }
    fn snapshot(&self) -> Vec<(PathBuf, Vec<u8>)> {
        let mut v: Vec<_> = walk(self.dir.path())
            .into_iter()
            .map(|p| {
                let b = fs::read(&p).unwrap();
                (p, b)
            })
            .collect();
        v.sort();
        v
    }
    fn vault(&self) -> Vault {
        let key = KeyFile::load(&self.key()).unwrap();
        Vault::open(&self.p("state/vault.db"), key).unwrap()
    }
}

fn walk(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for e in fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            out.extend(walk(&p));
        } else {
            out.push(p);
        }
    }
    out
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

fn contains(hay: &[u8], needle: &str) -> bool {
    hay.windows(needle.len()).any(|w| w == needle.as_bytes())
}

fn cam(id: u32, name: &str, host: &str, path: &str, user: &str, pw: &str) -> String {
    format!(
        "<camera id=\"{id}\" name=\"{name}\"><settings>\
         <videosourcestring>rtsp://{host}:554{path}</videosourcestring>\
         <login>{user}</login><password>{pw}</password></settings></camera>"
    )
}

fn no_secrets(out: &Output) {
    for stream in [&out.stdout, &out.stderr] {
        for needle in [PASSWORD, USER] {
            assert!(!contains(stream, needle), "output holds a login value");
        }
    }
}

fn one(site: &Site) -> PathBuf {
    site.xml(&cam(1, NAME, HOST, "/stream1", USER, PASSWORD))
}

#[test]
fn import_seals_the_login_and_prints_no_credential() {
    let site = Site::new();
    site.init_key();
    let file = one(&site);
    let out = site.import(&file, &[]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let stdout = text(&out.stdout);
    assert!(stdout.contains("agentdvr-1"), "{stdout}");
    assert!(stdout.contains(HOST) && stdout.contains("/stream1"));
    assert!(stdout.contains("imported"));
    no_secrets(&out);
    // The acceptance test: no plaintext in any file the import wrote.
    let bytes = site.state_bytes();
    assert!(bytes.len() > 4096, "the files were written");
    for needle in [PASSWORD, USER, HOST, NAME] {
        assert!(!contains(&bytes, needle), "plaintext {needle:?} on disk");
    }
    // And the sealed values really are there.
    let vault = site.vault();
    let entry = vault
        .get(&EntryId::new("cam:agentdvr-1:credential").unwrap())
        .unwrap()
        .unwrap();
    match entry.value {
        Value::Credential(c) => {
            assert_eq!(c.username, USER);
            assert_eq!(c.password.expose_secret(), PASSWORD);
        }
        _ => panic!("not a credential"),
    }
    let host = vault
        .get(&EntryId::new("cam:agentdvr-1:host").unwrap())
        .unwrap()
        .unwrap();
    assert!(matches!(host.value, Value::Text(t) if t.expose_secret() == HOST));
    let name = vault
        .get(&EntryId::new("cam:agentdvr-1:name").unwrap())
        .unwrap()
        .unwrap();
    assert!(matches!(name.value, Value::Text(t) if t.expose_secret() == NAME));
}

#[test]
fn rerun_is_idempotent_and_updates_the_credential() {
    let site = Site::new();
    site.init_key();
    let file = one(&site);
    assert!(site.import(&file, &[]).status.success());
    let again = site.import(&file, &[]);
    assert!(again.status.success());
    let stdout = text(&again.stdout);
    assert!(
        stdout.contains("updated") && !stdout.contains("imported"),
        "{stdout}"
    );
    assert_eq!(stdout.matches("agentdvr-1").count(), 1);
    // A new password lands under the same id.
    let file = site.xml(&cam(1, NAME, HOST, "/stream1", USER, "Changed-fake-2"));
    assert!(site.import(&file, &[]).status.success());
    let entry = site
        .vault()
        .get(&EntryId::new("cam:agentdvr-1:credential").unwrap())
        .unwrap()
        .unwrap();
    assert!(
        matches!(entry.value, Value::Credential(c) if c.password.expose_secret() == "Changed-fake-2")
    );
    assert!(!contains(&site.state_bytes(), "Changed-fake-2"));
    // One registry row (created once, updated since) and three vault entries.
    let index = wardenlens_index::Index::open(&site.p("state/index.db")).unwrap();
    let rows = index.list_cameras(&[]).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].record().id().as_str(), "agentdvr-1");
    assert_eq!(rows[0].record().streams().main.as_str(), "/stream1");
    assert_eq!(site.vault().list().unwrap().len(), 3);
}

#[test]
fn a_login_removed_from_the_file_is_removed_from_the_vault() {
    let site = Site::new();
    site.init_key();
    assert!(site.import(&one(&site), &[]).status.success());
    let nologin = site.xml(&format!(
        "<camera id=\"1\" name=\"{NAME}\"><settings><videosourcestring>rtsp://{HOST}/stream1\
         </videosourcestring></settings></camera>"
    ));
    assert!(site.import(&nologin, &[]).status.success());
    let ids: Vec<_> = site
        .vault()
        .list()
        .unwrap()
        .into_iter()
        .map(|e| e.id.as_str().to_owned())
        .collect();
    assert_eq!(ids, ["cam:agentdvr-1:host", "cam:agentdvr-1:name"]);
}

#[test]
fn dry_run_writes_nothing_and_needs_no_key() {
    let site = Site::new();
    let file = one(&site);
    let before = site.snapshot();
    let out = site.import(&file, &["--dry-run"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(text(&out.stdout).contains("would import"));
    no_secrets(&out);
    assert_eq!(before, site.snapshot());
    assert!(!site.p("state/index.db").exists() && !site.p("state/vault.db").exists());
    assert!(!site.key().exists());
    // With a key and a finished import in place, a dry run still changes no byte.
    site.init_key();
    assert!(site.import(&file, &[]).status.success());
    let before = site.snapshot();
    assert!(site.import(&file, &["--dry-run"]).status.success());
    assert_eq!(before, site.snapshot());
}

#[test]
fn a_missing_key_points_at_secrets_init_and_writes_nothing() {
    let site = Site::new();
    let file = one(&site);
    let out = site.import(&file, &[]);
    assert_eq!(out.status.code(), Some(2));
    let err = text(&out.stderr);
    assert!(err.contains("wardenlens secrets init"), "{err}");
    no_secrets(&out);
    assert!(!site.p("state/index.db").exists() && !site.p("state/vault.db").exists());
    // Following the advice works.
    site.init_key();
    assert!(site.import(&file, &[]).status.success());
}

#[test]
fn secrets_init_is_private_and_never_overwrites() {
    let site = Site::new();
    site.init_key();
    let meta = fs::metadata(site.key()).unwrap();
    assert_eq!(meta.permissions().mode() & 0o777, 0o600);
    assert_eq!(meta.len(), 32);
    let key = fs::read(site.key()).unwrap();
    let again = site.run(&["secrets", "init"]);
    assert_eq!(again.status.code(), Some(1));
    assert!(text(&again.stderr).contains("already exists"));
    assert_eq!(fs::read(site.key()).unwrap(), key);
    // Not printed.
    assert!(!out_has_bytes(&site.run(&["secrets", "init"]), &key));
}

fn out_has_bytes(out: &Output, key: &[u8]) -> bool {
    [&out.stdout, &out.stderr]
        .iter()
        .any(|s| s.windows(key.len()).any(|w| w == key))
}

#[test]
fn secrets_init_refuses_a_symlink_at_the_key_path() {
    let site = Site::new();
    let target = site.p("keys/elsewhere");
    symlink(&target, site.key()).unwrap();
    let out = site.run(&["secrets", "init"]);
    assert!(!out.status.success());
    assert!(!target.exists());
}

#[test]
fn input_over_8_mib_is_refused_before_reading() {
    let site = Site::new();
    site.init_key();
    let file = site.p("in/big.xml");
    let f = fs::File::create(&file).unwrap();
    // Sparse: nothing is written, so only a size check can refuse it quickly.
    f.set_len(8 * 1024 * 1024 + 1).unwrap();
    let out = site.import(&file, &[]);
    assert_eq!(out.status.code(), Some(1));
    assert!(text(&out.stderr).contains("8 MiB"), "{}", text(&out.stderr));
    assert!(!site.p("state/vault.db").exists());
}

#[test]
fn input_exactly_at_the_limit_is_not_a_size_error() {
    let site = Site::new();
    let file = site.p("in/edge.xml");
    let mut body = b"<objects><cameras/></objects>".to_vec();
    body.resize(8 * 1024 * 1024, b' ');
    fs::write(&file, body).unwrap();
    let out = site.import(&file, &["--dry-run"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
}

#[test]
fn a_world_readable_input_warns_and_is_not_changed() {
    let site = Site::new();
    let file = one(&site);
    fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).unwrap();
    let out = site.import(&file, &["--dry-run"]);
    assert!(out.status.success());
    assert!(text(&out.stderr).contains("readable by everyone"));
    no_secrets(&out);
    assert_eq!(
        fs::metadata(&file).unwrap().permissions().mode() & 0o777,
        0o644
    );
    // A private file draws no warning.
    fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
    let out = site.import(&file, &["--dry-run"]);
    assert!(!text(&out.stderr).contains("readable by everyone"));
}

#[test]
fn a_symlinked_or_missing_input_is_refused() {
    let site = Site::new();
    let real = one(&site);
    let link = site.p("in/link.xml");
    symlink(&real, &link).unwrap();
    assert_eq!(site.import(&link, &["--dry-run"]).status.code(), Some(2));
    assert_eq!(
        site.import(&site.p("in/none.xml"), &["--dry-run"])
            .status
            .code(),
        Some(2)
    );
}

#[test]
fn errors_never_echo_the_login_even_with_hostile_input() {
    let site = Site::new();
    site.init_key();
    // Userinfo with the password in the URL, a duplicate name (whole import refused).
    let dup = format!(
        "<camera id=\"1\" name=\"A\"><settings><videosourcestring>rtsp://{USER}:{PASSWORD}@{HOST}/s\
         </videosourcestring></settings></camera>\
         <camera id=\"2\" name=\"A\"><settings><videosourcestring>rtsp://{USER}:{PASSWORD}@{HOST}/t\
         </videosourcestring></settings></camera>"
    );
    let out = site.import(&site.xml(&dup), &[]);
    assert_eq!(out.status.code(), Some(1));
    no_secrets(&out);
    // Malformed XML around the password.
    let bad = site.p("in/bad.xml");
    fs::write(&bad, format!("<objects><password>{PASSWORD}</objects>")).unwrap();
    let out = site.import(&bad, &[]);
    assert!(!out.status.success());
    no_secrets(&out);
    // A conflicting pair is skipped, and the skip text holds no value.
    let conflict = format!(
        "<camera id=\"3\" name=\"C\"><settings><videosourcestring>rtsp://{USER}:{PASSWORD}@{HOST}/s\
         </videosourcestring><login>other</login><password>other</password></settings></camera>"
    );
    let out = site.import(&site.xml(&conflict), &[]);
    assert!(out.status.success());
    assert!(text(&out.stdout).contains("skipped"));
    no_secrets(&out);
    assert!(!contains(&site.state_bytes(), PASSWORD));
}

#[test]
fn an_unusable_key_file_is_an_error_without_values() {
    let site = Site::new();
    site.init_key();
    fs::set_permissions(site.key(), fs::Permissions::from_mode(0o644)).unwrap();
    let out = site.import(&one(&site), &[]);
    assert_eq!(out.status.code(), Some(2));
    no_secrets(&out);
    assert!(!site.p("state/vault.db").exists());
}

#[test]
fn a_wrong_key_does_not_touch_the_vault() {
    let site = Site::new();
    site.init_key();
    let file = one(&site);
    assert!(site.import(&file, &[]).status.success());
    let before = fs::read(site.p("state/vault.db")).unwrap();
    fs::remove_file(site.key()).unwrap();
    site.init_key();
    let out = site.import(&file, &[]);
    assert_eq!(out.status.code(), Some(2));
    no_secrets(&out);
    assert_eq!(fs::read(site.p("state/vault.db")).unwrap(), before);
}

#[test]
fn a_query_string_is_skipped_in_a_dry_run_and_a_real_run_alike() {
    let site = Site::new();
    site.init_key();
    let body = [
        cam(1, "Plain", "192.0.2.10", "/stream1", USER, PASSWORD),
        cam(
            2,
            "Queried",
            "192.0.2.11",
            "/cam?channel=1&amp;subtype=0",
            USER,
            PASSWORD,
        ),
    ]
    .concat();
    let file = site.xml(&body);
    for extra in [&["--dry-run"][..], &[][..]] {
        let out = site.import(&file, extra);
        assert!(out.status.success(), "{}", text(&out.stderr));
        let stdout = text(&out.stdout);
        assert!(stdout.contains("192.0.2.10"));
        let skipped: Vec<_> = stdout.lines().filter(|l| l.contains("skipped")).collect();
        assert_eq!(skipped.len(), 1, "{stdout}");
        assert!(skipped[0].contains("192.0.2.11") && skipped[0].contains("query"));
    }
    let ids: Vec<_> = site
        .vault()
        .list()
        .unwrap()
        .into_iter()
        .map(|e| e.id.as_str().to_owned())
        .collect();
    assert!(ids.iter().all(|i| !i.contains("agentdvr-2")), "{ids:?}");
}

#[test]
fn skipped_entries_are_listed_with_a_reason() {
    let site = Site::new();
    let body = [
        cam(1, "Good", "192.0.2.10", "/s", USER, PASSWORD),
        "<camera id=\"2\" name=\"Local\"><settings><videosourcestring>/dev/video0\
         </videosourcestring></settings></camera>"
            .to_owned(),
    ]
    .concat();
    let out = site.import(&site.xml(&body), &["--dry-run"]);
    let stdout = text(&out.stdout);
    assert!(stdout.contains("would import"), "{stdout}");
    assert!(
        stdout.contains("skipped: source is not a URL (entry 1)"),
        "{stdout}"
    );
}

#[test]
fn a_database_named_vault_db_is_refused_up_front_even_in_a_dry_run() {
    let site = Site::new();
    let config = fs::read_to_string(site.config())
        .unwrap()
        .replace("state/index.db", "state/vault.db");
    fs::write(site.config(), config).unwrap();
    let before = site.snapshot();
    let out = site.import(&one(&site), &["--dry-run"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(
        text(&out.stderr).contains("same path"),
        "{}",
        text(&out.stderr)
    );
    no_secrets(&out);
    assert!(!site.p("state/vault.db").exists());
    assert_eq!(
        before.len(),
        site.snapshot().len() - 1,
        "only the input was written"
    );
}

/// An unlisted carrier (no deny-list name, no query) holding another camera's password: only the
/// import's own comparison can stop it, so this exercises `screen()` end to end.
#[test]
fn an_unlisted_carrier_of_another_cameras_password_is_refused_end_to_end() {
    let site = Site::new();
    site.init_key();
    for carrier in [
        format!("/live/{PASSWORD}/main"),
        format!("/ch0_zzq={PASSWORD}"),
    ] {
        let body = [
            cam(1, "Cam One", "192.0.2.1", "/stream1", USER, PASSWORD),
            cam(2, "Cam Two", "192.0.2.2", &carrier, "", ""),
        ]
        .concat();
        let out = site.import(&site.xml(&body), &[]);
        assert!(out.status.success(), "{}", text(&out.stderr));
        no_secrets(&out);
        assert!(!contains(&site.state_bytes(), PASSWORD), "{carrier}");
        let stdout = text(&out.stdout);
        assert!(stdout.contains("path contains the login"), "{stdout}");
        assert!(stdout.contains("agentdvr-1"));
    }
}
