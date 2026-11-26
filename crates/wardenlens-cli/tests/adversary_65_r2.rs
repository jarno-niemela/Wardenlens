//! Adversarial tests for #65 (PR #173) round 2: output paths of `token create` (the two
//! concurrent-index tests wait for #175 and stay in the carry directory). Synthetic data only; every path is under a temporary directory.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "adversary tests: a failed setup step is a test failure"
)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

use tempfile::TempDir;
use wardenlens_api::token::Token;
use wardenlens_index::Index;

struct Site {
    dir: TempDir,
}

impl Site {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        for d in [".", "state"] {
            let p = dir.path().join(d);
            fs::create_dir_all(&p).unwrap();
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
    fn config(&self) -> PathBuf {
        self.dir.path().join("wardenlens.toml")
    }
    fn db(&self) -> PathBuf {
        self.dir.path().join("state/index.db")
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
    fn tokens(&self) -> Vec<(String, bool)> {
        Index::open(&self.db())
            .unwrap()
            .list_tokens()
            .unwrap()
            .into_iter()
            .map(|t| (t.id.to_string(), t.revoked))
            .collect()
    }
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

fn run_with_stdout(site: &Site, redirect: &str, args: &[&str]) -> Output {
    Command::new("sh")
        .arg("-c")
        .arg(format!("exec \"$@\" {redirect}"))
        .arg("sh")
        .arg(env!("CARGO_BIN_EXE_wardenlens"))
        .arg("--config")
        .arg(site.config())
        .args(args)
        .env_clear()
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

/// A stdout that is open for writing but fails every write (`/dev/full`, ENOSPC) passes the
/// up-front check, so the write failure must revoke the stored token and exit 2.
#[test]
fn a_full_stdout_revokes_the_token_and_exits_2() {
    if !std::path::Path::new("/dev/full").exists() {
        return;
    }
    let site = Site::new();
    let out = run_with_stdout(&site, ">/dev/full", &["token", "create", "--name", "ci"]);
    assert_eq!(out.status.code(), Some(2), "{}", text(&out.stderr));
    assert!(
        text(&out.stderr).contains("cannot write to stdout"),
        "{}",
        text(&out.stderr)
    );
    let toks = site.tokens();
    assert_eq!(toks.len(), 1, "{toks:?}");
    assert!(toks[0].1, "the undelivered token is still active: {toks:?}");
}

/// A pipe whose reader is gone (EPIPE; the Rust runtime ignores SIGPIPE) is the same: revoked,
/// exit 2, and not a signal death.
#[test]
fn a_pipe_with_no_reader_revokes_the_token_and_exits_2() {
    let site = Site::new();
    let (reader, writer) = std::io::pipe().unwrap();
    drop(reader);
    let out = site
        .cmd(&["token", "create", "--name", "ci"])
        .stdout(writer)
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2), "{}", text(&out.stderr));
    let toks = site.tokens();
    assert_eq!(toks.len(), 1, "{toks:?}");
    assert!(toks[0].1, "the undelivered token is still active: {toks:?}");
}

/// After delivery, a closed stderr (reopened as /dev/null by the runtime) or a stderr pipe with
/// no reader must not fail the command: the token is printed, active, exit 0.
#[test]
fn a_broken_stderr_after_delivery_exits_0_with_an_active_token() {
    let site = Site::new();
    let (reader, writer) = std::io::pipe().unwrap();
    drop(reader);
    let out = site
        .cmd(&["token", "create", "--name", "ci"])
        .stdout(Stdio::piped())
        .stderr(writer)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    let t = Token::parse(text(&out.stdout).trim_end()).unwrap();
    assert_eq!(site.tokens(), vec![(t.id().to_string(), false)]);
    // Revoke with the same broken stderr: exit 0 and revoked.
    let (reader, writer) = std::io::pipe().unwrap();
    drop(reader);
    let out = site
        .cmd(&["token", "revoke", &t.id().to_string()])
        .stderr(writer)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(site.tokens(), vec![(t.id().to_string(), true)]);
}
