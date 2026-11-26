//! Adversary tests for `wardenlens import agentdvr` and `wardenlens secrets init` (#66, PR #162).
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
use std::sync::mpsc;
use std::time::Duration;

use tempfile::TempDir;

const PASSWORD: &str = "Qv7-synthetic-pw";
const USER: &str = "synthuser3";
const HOST: &str = "192.0.2.55";
const NAME: &str = "Synthetic Gate Cam";

struct Site {
    dir: TempDir,
}

impl Site {
    fn new() -> Self {
        Self::with_db("state/index.db")
    }
    fn with_db(db_rel: &str) -> Self {
        let dir = tempfile::tempdir().unwrap();
        for d in ["state", "keys", "in"] {
            let p = dir.path().join(d);
            fs::create_dir(&p).unwrap();
            fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let t = dir.path().display();
        let config = format!(
            "[api]\nlisten = \"127.0.0.1:8080\"\n[storage]\nhot_root = \"{t}/hot\"\n\
             archive_root = \"{t}/archive\"\n[database]\npath = \"{t}/{db_rel}\"\n\
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
    fn cmd(&self, args: &[&str]) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_wardenlens"));
        c.env_clear()
            .arg("--config")
            .arg(self.config())
            .args(args)
            .stdin(Stdio::null());
        c
    }
    fn run(&self, args: &[&str]) -> Output {
        self.cmd(args).output().unwrap()
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
    fn state_bytes(&self) -> Vec<u8> {
        let mut all = Vec::new();
        for e in fs::read_dir(self.p("state")).unwrap() {
            let p = e.unwrap().path();
            if p.is_file() {
                all.extend(fs::read(p).unwrap());
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

/// Runs `cmd` with a generous guard so a hang fails the test instead of the whole suite.
/// The guard is not used to reach a branch (TEST-5): a correct run returns at once.
fn output_with_guard(mut cmd: Command) -> Option<Output> {
    let (tx, rx) = mpsc::channel();
    let child = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let pid = child.id();
    std::thread::spawn(move || {
        let _ = tx.send(child.wait_with_output());
    });
    if let Ok(r) = rx.recv_timeout(Duration::from_secs(30)) {
        Some(r.unwrap())
    } else {
        let _ = Command::new("kill").arg("-9").arg(pid.to_string()).status();
        None
    }
}

// ---- credentials never leak --------------------------------------------------------------

/// The import knows the password; a path that carries it verbatim (in a segment whose name is
/// on no list) must not put it into the registry or on stdout.
#[test]
fn a_password_inside_a_path_segment_never_reaches_the_registry_or_stdout() {
    let site = Site::new();
    site.init_key();
    let path = format!("/live/{PASSWORD}/main");
    let file = site.xml(&cam(1, NAME, HOST, &path, USER, PASSWORD));
    let out = site.import(&file, &[]);
    assert!(
        !contains(&site.state_bytes(), PASSWORD),
        "the password is in plaintext on disk (exit {:?})",
        out.status.code()
    );
    assert!(
        !contains(&out.stdout, PASSWORD) && !contains(&out.stderr, PASSWORD),
        "the password was printed: {}",
        text(&out.stdout)
    );
}

/// `psw` is a common abbreviation the deny list misses; in a path segment the import writes it to
/// the registry in plaintext although it holds the very password it sealed.
#[test]
fn a_password_under_an_unlisted_path_parameter_never_reaches_the_registry() {
    let site = Site::new();
    site.init_key();
    let path = format!("/live/ch0_psw={PASSWORD}");
    let file = site.xml(&cam(1, NAME, HOST, &path, USER, PASSWORD));
    let out = site.import(&file, &[]);
    assert!(
        !contains(&site.state_bytes(), PASSWORD),
        "the password is in plaintext on disk (exit {:?}): {}",
        out.status.code(),
        text(&out.stdout)
    );
}

/// A query parameter named outside the deny list (`pin`) carrying the password is skipped (query
/// string), but the skipped row still prints the whole path, query included.
#[test]
fn a_skipped_query_path_does_not_print_the_password() {
    let site = Site::new();
    let path = format!("/stream?pin={PASSWORD}");
    let file = site.xml(&cam(1, NAME, HOST, &path, USER, PASSWORD));
    let out = site.import(&file, &["--dry-run"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(text(&out.stdout).contains("skipped"));
    assert!(
        !contains(&out.stdout, PASSWORD),
        "the password was printed: {}",
        text(&out.stdout)
    );
}

#[test]
fn trace_logging_and_json_format_carry_no_login_or_name() {
    let site = Site::new();
    site.init_key();
    let file = site.xml(&cam(1, NAME, HOST, "/stream1", USER, PASSWORD));
    for fmt in ["text", "json"] {
        let out = site
            .cmd(&[
                "--log-format",
                fmt,
                "import",
                "agentdvr",
                file.to_str().unwrap(),
            ])
            .env("RUST_LOG", "trace")
            .output()
            .unwrap();
        assert!(out.status.success(), "{}", text(&out.stderr));
        for s in [&out.stdout, &out.stderr] {
            for needle in [PASSWORD, USER, NAME] {
                assert!(!contains(s, needle), "{needle:?} in output ({fmt})");
            }
        }
        // The host is only allowed on stdout (the table), never in logs.
        assert!(!contains(&out.stderr, HOST), "host in stderr ({fmt})");
    }
}

#[test]
fn the_vault_written_by_import_is_private() {
    let site = Site::new();
    site.init_key();
    let file = site.xml(&cam(1, NAME, HOST, "/stream1", USER, PASSWORD));
    assert!(site.import(&file, &[]).status.success());
    let mode = fs::metadata(site.p("state/vault.db"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o077, 0, "vault mode {mode:o}");
}

// ---- input file handling -----------------------------------------------------------------

#[test]
fn a_fifo_input_is_refused_without_blocking() {
    let site = Site::new();
    let fifo = site.p("in/fifo.xml");
    let st = Command::new("mkfifo").arg(&fifo).status().unwrap();
    assert!(st.success());
    let mut cmd = site.cmd(&["import", "agentdvr", fifo.to_str().unwrap(), "--dry-run"]);
    cmd.stdin(Stdio::null());
    let out = output_with_guard(cmd).expect("the import blocked on a FIFO");
    assert_eq!(out.status.code(), Some(2), "{}", text(&out.stderr));
    assert!(text(&out.stderr).contains("not a regular file"));
}

#[test]
fn a_directory_or_device_input_is_refused() {
    let site = Site::new();
    for p in [
        site.p("in"),
        PathBuf::from("/dev/null"),
        PathBuf::from("/dev/zero"),
    ] {
        let mut cmd = site.cmd(&["import", "agentdvr", p.to_str().unwrap(), "--dry-run"]);
        cmd.stdin(Stdio::null());
        let out = output_with_guard(cmd).expect("blocked");
        assert_eq!(out.status.code(), Some(2), "{p:?}: {}", text(&out.stderr));
    }
}

#[test]
fn a_control_character_in_the_input_path_cannot_forge_a_line() {
    let site = Site::new();
    let file = site.xml(&cam(1, NAME, HOST, "/stream1", USER, PASSWORD));
    let evil = site.p("in/a\nerror: forged.xml");
    fs::rename(&file, &evil).unwrap();
    fs::set_permissions(&evil, fs::Permissions::from_mode(0o644)).unwrap();
    let out = site.import(&evil, &["--dry-run"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let err = text(&out.stderr);
    assert!(err.contains("readable by everyone"));
    assert!(
        !err.lines().any(|l| l.starts_with("error: forged")),
        "{err}"
    );
    // Missing file with the same name: the error is escaped too.
    let out = site.import(&site.p("in/b\nerror: forged2.xml"), &["--dry-run"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(
        !text(&out.stderr)
            .lines()
            .any(|l| l.starts_with("error: forged2")),
        "{}",
        text(&out.stderr)
    );
}

#[test]
fn the_table_never_shows_the_display_name() {
    let site = Site::new();
    let file = site.xml(&cam(1, NAME, HOST, "/stream1", USER, PASSWORD));
    let out = site.import(&file, &["--dry-run"]);
    assert!(out.status.success());
    assert!(!contains(&out.stdout, NAME), "{}", text(&out.stdout));
}

// ---- key file ----------------------------------------------------------------------------

#[test]
fn an_empty_or_directory_key_is_an_error_that_writes_nothing() {
    let site = Site::new();
    let file = site.xml(&cam(1, NAME, HOST, "/stream1", USER, PASSWORD));
    fs::write(site.key(), b"").unwrap();
    fs::set_permissions(site.key(), fs::Permissions::from_mode(0o600)).unwrap();
    let out = site.import(&file, &[]);
    assert_eq!(out.status.code(), Some(2), "{}", text(&out.stderr));
    assert!(!site.p("state/vault.db").exists());
    assert!(!site.p("state/index.db").exists());
    fs::remove_file(site.key()).unwrap();
    fs::create_dir(site.key()).unwrap();
    let out = site.import(&file, &[]);
    assert_eq!(out.status.code(), Some(2), "{}", text(&out.stderr));
    assert!(!site.p("state/vault.db").exists());
}

#[test]
fn a_dangling_symlink_key_is_not_reported_as_missing_and_is_not_followed() {
    let site = Site::new();
    let target = site.p("keys/elsewhere.key");
    std::os::unix::fs::symlink(&target, site.key()).unwrap();
    let file = site.xml(&cam(1, NAME, HOST, "/stream1", USER, PASSWORD));
    let out = site.import(&file, &[]);
    assert_eq!(out.status.code(), Some(2));
    // `secrets init` must not create the target through the link either.
    let init = site.run(&["secrets", "init"]);
    assert!(!init.status.success());
    assert!(!target.exists());
    assert!(!site.p("state/vault.db").exists());
}

#[test]
fn secrets_init_never_overwrites_an_empty_file_or_a_directory() {
    let site = Site::new();
    fs::write(site.key(), b"").unwrap();
    let out = site.run(&["secrets", "init"]);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out.stderr));
    assert_eq!(fs::read(site.key()).unwrap(), b"");
    fs::remove_file(site.key()).unwrap();
    fs::create_dir(site.key()).unwrap();
    let out = site.run(&["secrets", "init"]);
    assert!(!out.status.success());
    assert!(site.key().is_dir());
}

#[test]
fn secrets_init_key_is_private_under_a_permissive_umask() {
    let site = Site::new();
    // `sh -c 'umask 000; exec ...'` keeps the environment cleared.
    let bin = env!("CARGO_BIN_EXE_wardenlens");
    let st = Command::new("sh")
        .env_clear()
        .arg("-c")
        .arg("umask 000; exec \"$0\" --config \"$1\" secrets init")
        .arg(bin)
        .arg(site.config())
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(st.status.success(), "{}", text(&st.stderr));
    let mode = fs::metadata(site.key()).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
}

// ---- vault path and re-runs ---------------------------------------------------------------

/// `database.path` named `vault.db`: the index and the vault would be the same file. The
/// import must refuse without damaging the file or leaving plaintext behind.
#[test]
fn an_index_named_vault_db_is_refused_without_damage() {
    let site = Site::with_db("state/vault.db");
    site.init_key();
    let file = site.xml(&cam(1, NAME, HOST, "/stream1", USER, PASSWORD));
    let out = site.import(&file, &[]);
    assert!(
        !out.status.success(),
        "imported into a vault that is also the index: {}",
        text(&out.stdout)
    );
    assert!(!contains(&site.state_bytes(), PASSWORD));
    assert!(!contains(&out.stdout, PASSWORD) && !contains(&out.stderr, PASSWORD));
}

/// The index cannot be opened (a directory sits at its path): the run fails with no plaintext
/// anywhere, and once fixed a re-run completes.
#[test]
fn a_failed_index_open_is_repaired_by_a_rerun() {
    let site = Site::new();
    site.init_key();
    let file = site.xml(&cam(1, NAME, HOST, "/stream1", USER, PASSWORD));
    fs::create_dir(site.p("state/index.db")).unwrap();
    let out = site.import(&file, &[]);
    assert_eq!(out.status.code(), Some(2), "{}", text(&out.stdout));
    assert!(!contains(&out.stdout, PASSWORD) && !contains(&out.stderr, PASSWORD));
    assert!(!contains(&site.state_bytes(), PASSWORD));
    fs::remove_dir(site.p("state/index.db")).unwrap();
    let out = site.import(&file, &[]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(text(&out.stdout).contains("imported"));
}

/// Dry run against an existing import reports the same set of ids as the real run.
#[test]
fn dry_run_and_real_run_list_the_same_ids() {
    let site = Site::new();
    site.init_key();
    let body = [
        cam(1, "One", "192.0.2.1", "/a", USER, PASSWORD),
        cam(7, "Seven", "192.0.2.7", "/b", USER, PASSWORD),
        "<camera name=\"NoId\"><settings><videosourcestring>rtsp://192.0.2.9/c\
         </videosourcestring></settings></camera>"
            .to_owned(),
    ]
    .concat();
    let file = site.xml(&body);
    let ids = |o: &Output| {
        let mut v: Vec<String> = text(&o.stdout)
            .lines()
            .skip(1)
            .map(|l| l.split_whitespace().next().unwrap().to_owned())
            .collect();
        v.sort();
        v
    };
    let dry = site.import(&file, &["--dry-run"]);
    let real = site.import(&file, &[]);
    assert!(real.status.success(), "{}", text(&real.stderr));
    assert_eq!(ids(&dry), ids(&real));
    let again = site.import(&file, &[]);
    assert_eq!(ids(&real), ids(&again));
    assert!(!text(&again.stdout).contains("imported"));
}
