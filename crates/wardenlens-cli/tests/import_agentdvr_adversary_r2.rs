//! Round-2 adversary tests for `wardenlens import agentdvr` (#66, PR #162).
//!
//! Synthetic data only: documentation-range hosts, invented names and passwords, temporary
//! directories, a cleared environment.

#![expect(
    clippy::unwrap_used,
    reason = "integration-test helpers outside #[test] fns; clippy.toml in-tests allowances do not reach them"
)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use tempfile::TempDir;

const PASSWORD: &str = "Qv7-synthetic-pw";
const USER: &str = "synthuser3";
const HOST: &str = "192.0.2.55";
const NAME: &str = "Synthetic Gate Cam";

struct Site {
    dir: TempDir,
}

impl Site {
    fn with(db_rel: &str, key_rel: &str) -> Self {
        let dir = tempfile::tempdir().unwrap();
        for d in ["state", "keys", "in"] {
            let p = dir.path().join(d);
            fs::create_dir(&p).unwrap();
            fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let site = Self { dir };
        site.write_config(db_rel, key_rel);
        site
    }
    fn new() -> Self {
        Self::with("state/index.db", "keys/secrets.key")
    }
    fn write_config(&self, db_rel: &str, key_rel: &str) {
        let t = self.dir.path().display();
        let config = format!(
            "[api]\nlisten = \"127.0.0.1:8080\"\n[storage]\nhot_root = \"{t}/hot\"\n\
             archive_root = \"{t}/archive\"\n[database]\npath = \"{t}/{db_rel}\"\n\
             [secrets]\nkey_file = \"{t}/{key_rel}\"\n"
        );
        fs::write(self.config(), config).unwrap();
        fs::set_permissions(self.config(), fs::Permissions::from_mode(0o600)).unwrap();
    }
    fn p(&self, rel: &str) -> PathBuf {
        self.dir.path().join(rel)
    }
    fn config(&self) -> PathBuf {
        self.p("wardenlens.toml")
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
    /// Every regular file under `state/` and `keys/`.
    fn disk_bytes(&self) -> Vec<u8> {
        let mut all = Vec::new();
        for d in ["state", "keys"] {
            for e in fs::read_dir(self.p(d)).unwrap() {
                let p = e.unwrap().path();
                if p.is_file() {
                    all.extend(fs::read(p).unwrap());
                }
            }
        }
        all
    }
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

/// A camera whose only source is the URL (no login fields).
fn cam_url(id: u32, name: &str, url: &str) -> String {
    format!(
        "<camera id=\"{id}\" name=\"{name}\"><settings>\
         <videosourcestring>{url}</videosourcestring></settings></camera>"
    )
}

fn assert_no_leak(site: &Site, out: &Output, needle: &str) {
    assert!(
        !contains(&site.disk_bytes(), needle),
        "{needle:?} is in plaintext on disk (exit {:?}): {}",
        out.status.code(),
        text(&out.stdout)
    );
    assert!(
        !contains(&out.stdout, needle) && !contains(&out.stderr, needle),
        "{needle:?} was printed: {}{}",
        text(&out.stdout),
        text(&out.stderr)
    );
}

// ---- the login in the path: other sources and parts -----------------------------------------

/// The credential comes from the URL userinfo, not the fields; the path repeats the password.
#[test]
fn a_userinfo_password_repeated_in_the_path_is_refused() {
    let site = Site::new();
    site.init_key();
    let url = format!("rtsp://{USER}:{PASSWORD}@{HOST}/live/{PASSWORD}/main");
    let file = site.xml(&cam_url(1, NAME, &url));
    let out = site.import(&file, &[]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(text(&out.stdout).contains("path contains the login"));
    assert_no_leak(&site, &out, PASSWORD);
}

/// A percent-encoded userinfo password: the decoded password sits verbatim in the path.
#[test]
fn a_percent_encoded_userinfo_password_repeated_in_the_path_is_refused() {
    let site = Site::new();
    site.init_key();
    // `Qv7-synthetic-pw` with its `-` encoded in the userinfo only.
    let url = format!("rtsp://{USER}:Qv7%2Dsynthetic%2Dpw@{HOST}/ch_{PASSWORD}");
    let file = site.xml(&cam_url(1, NAME, &url));
    let out = site.import(&file, &[]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_no_leak(&site, &out, PASSWORD);
}

/// The user (sensitive per ADR 0006) in a path segment, dry run and real run.
#[test]
fn the_user_in_a_path_segment_is_refused_and_not_printed() {
    let site = Site::new();
    site.init_key();
    let path = format!("/{USER}/stream1");
    let file = site.xml(&cam(1, NAME, HOST, &path, USER, PASSWORD));
    for extra in [&["--dry-run"][..], &[][..]] {
        let out = site.import(&file, extra);
        assert!(out.status.success(), "{}", text(&out.stderr));
        assert!(text(&out.stdout).contains("path contains the login"));
        assert_no_leak(&site, &out, USER);
    }
}

/// The password in the head of a query path: the login check wins over the query skip, so the
/// printed head never shows it either.
#[test]
fn a_password_before_the_query_is_not_printed_by_the_query_skip() {
    let site = Site::new();
    let path = format!("/{PASSWORD}?channel=1");
    let file = site.xml(&cam(1, NAME, HOST, &path, USER, PASSWORD));
    let out = site.import(&file, &["--dry-run"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_no_leak(&site, &out, PASSWORD);
}

/// An entity-encoded password in the XML field is compared after XML decoding.
#[test]
fn an_xml_entity_encoded_password_in_the_path_is_refused() {
    let site = Site::new();
    site.init_key();
    let encoded = "Qv7&#45;synthetic&#x2D;pw";
    let path = format!("/live/{PASSWORD}");
    let file = site.xml(&cam(1, NAME, HOST, &path, USER, encoded));
    let out = site.import(&file, &[]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_no_leak(&site, &out, PASSWORD);
}

/// Cameras on one site often share a password. Camera 2 has no login fields and carries the
/// shared password under a parameter name the deny list misses (`psw`); camera 1 gives the import
/// that very password. The import holds both, so the password must not reach disk or stdout.
#[test]
fn another_cameras_password_in_a_path_never_reaches_the_registry_or_stdout() {
    let site = Site::new();
    site.init_key();
    let body = [
        cam(1, "Cam One", "192.0.2.1", "/stream1", USER, PASSWORD),
        cam_url(
            2,
            "Cam Two",
            &format!("rtsp://192.0.2.2/live/ch0_psw={PASSWORD}"),
        ),
    ]
    .concat();
    let file = site.xml(&body);
    let out = site.import(&file, &[]);
    assert_no_leak(&site, &out, PASSWORD);
}

/// No login fields, no userinfo: the login lives only in the path, under an unlisted name.
/// The module docs promise no password is ever printed and the ticket that the DB holds no
/// plaintext password.
#[test]
fn a_path_only_login_under_an_unlisted_name_never_reaches_the_registry_or_stdout() {
    let site = Site::new();
    site.init_key();
    let url = format!("rtsp://{HOST}/live/ch0_psw={PASSWORD}");
    let file = site.xml(&cam_url(1, NAME, &url));
    let out = site.import(&file, &[]);
    assert_no_leak(&site, &out, PASSWORD);
}

// ---- vault path identity ------------------------------------------------------------------

/// `secrets.key_file` at the vault's own path (`vault.db` next to the index). The config does not
/// forbid it. The import must refuse without destroying the key.
#[test]
fn a_key_file_at_the_vault_path_is_never_damaged() {
    let site = Site::with("state/index.db", "state/vault.db");
    site.init_key();
    let key_before = fs::read(site.p("state/vault.db")).unwrap();
    let file = site.xml(&cam(1, NAME, HOST, "/stream1", USER, PASSWORD));
    let out = site.import(&file, &[]);
    assert!(
        !out.status.success(),
        "imported into a vault that is the key file: {}",
        text(&out.stdout)
    );
    assert_eq!(fs::read(site.p("state/vault.db")).unwrap(), key_before);
    assert_no_leak(&site, &out, PASSWORD);
}

/// `database.path` is a symlink to the vault (the `SameFile` check compares path text only).
/// The import must refuse and leave the vault byte-identical.
#[test]
fn an_index_symlinked_to_the_vault_is_refused_without_damage() {
    let site = Site::new();
    site.init_key();
    let file = site.xml(&cam(1, NAME, HOST, "/stream1", USER, PASSWORD));
    assert!(site.import(&file, &[]).status.success());
    let vault_before = fs::read(site.p("state/vault.db")).unwrap();
    std::os::unix::fs::symlink(site.p("state/vault.db"), site.p("state/link.db")).unwrap();
    site.write_config("state/link.db", "keys/secrets.key");
    let out = site.import(&file, &[]);
    assert_eq!(out.status.code(), Some(2), "{}", text(&out.stdout));
    assert_eq!(fs::read(site.p("state/vault.db")).unwrap(), vault_before);
    assert_no_leak(&site, &out, PASSWORD);
}

/// The same with a hard link, which no path comparison can see.
#[test]
fn an_index_hardlinked_to_the_vault_is_refused_without_damage() {
    let site = Site::new();
    site.init_key();
    let file = site.xml(&cam(1, NAME, HOST, "/stream1", USER, PASSWORD));
    assert!(site.import(&file, &[]).status.success());
    let vault_before = fs::read(site.p("state/vault.db")).unwrap();
    fs::hard_link(site.p("state/vault.db"), site.p("state/hard.db")).unwrap();
    site.write_config("state/hard.db", "keys/secrets.key");
    let out = site.import(&file, &[]);
    assert_eq!(out.status.code(), Some(2), "{}", text(&out.stdout));
    assert_eq!(fs::read(site.p("state/vault.db")).unwrap(), vault_before);
    assert_no_leak(&site, &out, PASSWORD);
}

// ---- vault order across runs --------------------------------------------------------------

/// Run 1 imports a camera with a login; run 2 the same id with a new host and no login. The old
/// login must not survive next to the new host.
#[test]
fn a_login_removed_from_the_file_is_removed_from_the_vault() {
    let site = Site::new();
    site.init_key();
    let file = site.xml(&cam(1, NAME, HOST, "/stream1", USER, PASSWORD));
    assert!(site.import(&file, &[]).status.success());
    let file = site.xml(&cam_url(1, NAME, "rtsp://192.0.2.99/stream1"));
    let out = site.import(&file, &[]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let list = site.run(&["vault", "list"]);
    let listed = text(&list.stdout);
    assert!(
        !listed.contains("cam:agentdvr-1:credential"),
        "stale credential kept: {listed} {}",
        text(&list.stderr)
    );
}

/// A refused draft (path holds the login) on a second run leaves the earlier run's entries alone
/// and prints nothing of the path.
#[test]
fn a_draft_refused_on_a_rerun_does_not_leak_and_does_not_touch_the_registry() {
    let site = Site::new();
    site.init_key();
    let file = site.xml(&cam(1, NAME, HOST, "/stream1", USER, PASSWORD));
    assert!(site.import(&file, &[]).status.success());
    let before = fs::read(site.p("state/index.db")).unwrap();
    let path = format!("/live/{PASSWORD}");
    let file = site.xml(&cam(1, NAME, "192.0.2.77", &path, USER, PASSWORD));
    let out = site.import(&file, &[]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(text(&out.stdout).contains("path contains the login"));
    assert_eq!(fs::read(site.p("state/index.db")).unwrap(), before);
    assert_no_leak(&site, &out, PASSWORD);
}
