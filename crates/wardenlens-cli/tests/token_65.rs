//! #65: `wardenlens token create|list|revoke` through the real binary, and end to end through the
//! `wardenlens-api` verifier with the index store (`TokenIndex`) on a temporary database.
//!
//! Synthetic data only; every path is under a temporary directory and the environment is cleared,
//! so nothing of the user's `~/.config`, `~/.local/share` or `/etc/wardenlens` is read.

#![expect(
    clippy::unwrap_used,
    reason = "integration-test helpers outside #[test] fns; clippy.toml in-tests allowances do not reach them"
)]

use std::fs;
use std::future::Future;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::pin::pin;
use std::process::{Command, Output, Stdio};
use std::task::{Context, Poll, Waker};

use tempfile::TempDir;
use wardenlens_api::token::Token;
use wardenlens_core::time::UnixMs;
use wardenlens_core::token_store::{TokenAdmin, TokenStore, TokenSummary};
use wardenlens_index::{Index, TokenIndex};

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
    fn create(&self, name: &str) -> Token {
        let out = self.run(&["token", "create", "--name", name]);
        assert!(out.status.success(), "{}", text(&out.stderr));
        Token::parse(text(&out.stdout).trim_end()).unwrap()
    }
    /// Every byte of every regular file under `state/`.
    fn disk_bytes(&self) -> Vec<u8> {
        let mut all = Vec::new();
        for e in fs::read_dir(self.dir.path().join("state")).unwrap() {
            let p = e.unwrap().path();
            if p.is_file() {
                all.extend(fs::read(p).unwrap());
            }
        }
        all
    }
    /// The verdict of the API's verifier against the index, read after the CLI has exited.
    fn verifies(&self, token: &Token) -> bool {
        let store = TokenIndex::new(Index::open(&self.db()).unwrap());
        let record = ready(store.find(token.id())).unwrap();
        token.verify(record.as_ref())
    }
    fn list(&self) -> Vec<TokenSummary> {
        let index = Index::open(&self.db()).unwrap();
        index.list_tokens().unwrap()
    }
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

/// Polls a future that is already complete (every `TokenIndex` future is).
fn ready<F: Future>(f: F) -> F::Output {
    let Poll::Ready(v) = pin!(f).poll(&mut Context::from_waker(Waker::noop())) else {
        unreachable!("a TokenIndex future is complete when it is returned")
    };
    v
}

fn secret_of(token: &Token) -> String {
    token.expose().splitn(3, '_').nth(2).unwrap().to_owned()
}

#[test]
fn create_prints_the_token_once_and_it_verifies_through_the_api_verifier() {
    let site = Site::new();
    let out = site.run(&["token", "create", "--name", "grafana"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    // stdout is exactly the token and a newline.
    let stdout = text(&out.stdout);
    assert_eq!(stdout.matches('\n').count(), 1, "{stdout:?}");
    let token = Token::parse(stdout.strip_suffix('\n').unwrap()).unwrap();
    assert!(stdout.starts_with("wl_"));
    // The secret is nowhere else: not in stderr, not on disk (only its digest is stored).
    let secret = secret_of(&token);
    assert!(!text(&out.stderr).contains(&secret));
    assert!(text(&out.stderr).contains(token.id().as_str()));
    assert!(!contains(&site.disk_bytes(), secret.as_bytes()));
    assert!(!contains(&site.disk_bytes(), token.expose().as_bytes()));
    assert!(contains(&site.disk_bytes(), &token.secret().digest()));
    // The verifier accepts it, and rejects a wrong secret, an unknown id and a malformed token.
    assert!(site.verifies(&token));
    let wrong = Token::parse(&format!("wl_{}_{}", token.id(), "A".repeat(43))).unwrap();
    assert!(!site.verifies(&wrong));
    let unknown = Token::parse(&format!("wl_zzzzzzzz_{secret}")).unwrap();
    assert!(!site.verifies(&unknown));
    assert!(Token::parse(&format!("wl_{}", token.id())).is_err());
}

#[test]
fn two_tokens_are_distinct_and_both_verify() {
    let site = Site::new();
    let a = site.create("a");
    let b = site.create("b");
    assert_ne!(a.id(), b.id());
    assert!(site.verifies(&a) && site.verifies(&b));
    // a's secret does not open b.
    let crossed = Token::parse(&format!("wl_{}_{}", b.id(), secret_of(&a))).unwrap();
    assert!(!site.verifies(&crossed));
}

#[test]
fn revoke_makes_the_verifier_refuse_the_token_and_keeps_the_row() {
    let site = Site::new();
    let keep = site.create("keep");
    let gone = site.create("gone");
    assert!(site.verifies(&gone));
    let out = site.run(&["token", "revoke", gone.id().as_str()]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(out.stdout, b"");
    assert!(
        !site.verifies(&gone),
        "a revoked token must fail verification (401)"
    );
    assert!(site.verifies(&keep), "other tokens are unaffected");
    let rows = site.list();
    assert_eq!(rows.len(), 2, "the row is not deleted");
    assert!(rows.iter().any(|r| r.id == *gone.id() && r.revoked));
    assert!(contains(&site.disk_bytes(), &gone.secret().digest()));
    // Revoking again is a success that says so.
    let again = site.run(&["token", "revoke", gone.id().as_str()]);
    assert!(again.status.success());
    assert!(text(&again.stderr).contains("already revoked"));
}

#[test]
fn revoking_an_unknown_id_is_a_typed_error_with_exit_1_and_changes_nothing() {
    let site = Site::new();
    let t = site.create("a");
    let out = site.run(&["token", "revoke", "zzzzzzzz"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(text(&out.stderr).contains("no token with id zzzzzzzz"));
    assert_eq!(out.stdout, b"");
    assert!(site.verifies(&t));
    assert!(!site.list().iter().any(|r| r.revoked));
}

#[test]
fn a_malformed_id_is_refused_with_exit_2_and_never_echoed() {
    let site = Site::new();
    site.create("a");
    for bad in [
        "",
        "short",
        "ABCDEFGH",
        "abcdefgh1",
        "abcdefg1",
        "wl_abcdefgh_x",
        "abc\ndefg",
    ] {
        let out = site.run(&["token", "revoke", bad]);
        let code = out.status.code();
        // An empty argument is a valid argv entry; clap exits 2 for the others' usage errors.
        assert_eq!(code, Some(2), "{bad:?}: {}", text(&out.stderr));
        assert!(!text(&out.stderr).contains("wl_abcdefgh_x"));
    }
}

#[test]
fn list_shows_id_name_times_and_flag_and_never_a_secret_or_hash() {
    let site = Site::new();
    let a = site.create("grafana");
    let b = site.create("backup job");
    site.run(&["token", "revoke", b.id().as_str()]);
    let out = site.run(&["token", "list"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let stdout = text(&out.stdout);
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines[0], "id\tname\tcreated\tlast used\trevoked");
    assert_eq!(lines.len(), 3);
    let cols: Vec<&str> = lines[1].split('\t').collect();
    assert_eq!(cols[0], a.id().as_str());
    assert_eq!(cols[1], "grafana");
    assert_eq!(cols[3], "never");
    assert_eq!(cols[4], "no");
    assert!(cols[2].ends_with('Z') && cols[2].len() == 20, "{}", cols[2]);
    let cols: Vec<&str> = lines[2].split('\t').collect();
    assert_eq!(cols[0], b.id().as_str());
    assert_eq!(cols[1], "backup job");
    assert_eq!(cols[4], "yes");
    for t in [&a, &b] {
        assert!(!stdout.contains(&secret_of(t)));
        assert!(!stdout.contains(&t.expose()));
        assert!(!stdout.contains(&hex(&t.secret().digest())));
    }
    assert_eq!(out.stderr, b"");
}

#[test]
fn list_of_an_empty_index_is_just_the_header() {
    let site = Site::new();
    let out = site.run(&["token", "list"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(text(&out.stdout), "id\tname\tcreated\tlast used\trevoked\n");
}

#[test]
fn a_use_recorded_by_the_store_shows_in_list_and_is_rate_limited() {
    let site = Site::new();
    let t = site.create("a");
    let t0 = list_created(&site);
    {
        let store = TokenIndex::new(Index::open(&site.db()).unwrap());
        let first = UnixMs::new(t0.as_i64() + 1_000).unwrap();
        assert_eq!(ready(store.touch_last_used(t.id(), first)), Ok(true));
        let soon = UnixMs::new(first.as_i64() + 59_999).unwrap();
        assert_eq!(ready(store.touch_last_used(t.id(), soon)), Ok(false));
        let later = UnixMs::new(first.as_i64() + 60_000).unwrap();
        assert_eq!(ready(store.touch_last_used(t.id(), later)), Ok(true));
    }
    let out = site.run(&["token", "list"]);
    let stdout = text(&out.stdout);
    let cols: Vec<&str> = stdout.lines().nth(1).unwrap().split('\t').collect();
    assert_ne!(cols[3], "never");
    assert!(cols[3].ends_with('Z'));
}

fn list_created(site: &Site) -> UnixMs {
    site.list().first().unwrap().created_at
}

#[test]
fn name_rules_are_enforced_before_anything_is_created() {
    let max = "n".repeat(64);
    let too_long = "n".repeat(65);
    // 21 euro signs are 63 bytes, 22 are 66: the limit is in bytes.
    let wide_ok = "\u{20AC}".repeat(21);
    let wide_bad = "\u{20AC}".repeat(22);
    for (name, ok) in [
        ("x", true),
        (max.as_str(), true),
        (wide_ok.as_str(), true),
        ("", false),
        ("   ", false),
        (too_long.as_str(), false),
        (wide_bad.as_str(), false),
        ("a\nb", false),
        ("a\tb", false),
        ("a\u{1b}[31mb", false),
        ("a\u{202e}b", false),
    ] {
        let site = Site::new();
        let out = site.run(&["token", "create", "--name", name]);
        if ok {
            assert!(out.status.success(), "{name:?}: {}", text(&out.stderr));
            assert_eq!(site.list()[0].name.as_str(), name);
        } else {
            assert_eq!(out.status.code(), Some(2), "{name:?}");
            assert_eq!(out.stdout, b"", "{name:?}");
            assert!(
                text(&out.stderr).starts_with("error: invalid token name"),
                "{name:?}"
            );
            assert!(
                !site.db().exists(),
                "{name:?}: the index was created for a bad name"
            );
        }
    }
}

#[test]
fn a_missing_name_is_a_usage_error_and_a_missing_config_is_exit_2() {
    let site = Site::new();
    let out = site.run(&["token", "create"]);
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(out.stdout, b"");
    let out = Command::new(env!("CARGO_BIN_EXE_wardenlens"))
        .env_clear()
        .arg("--config")
        .arg(site.dir.path().join("missing.toml"))
        .args(["token", "list"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(out.stdout, b"");
}

#[test]
fn errors_honour_the_json_log_format_and_never_hold_a_token() {
    let site = Site::new();
    let t = site.create("a");
    let out = Command::new(env!("CARGO_BIN_EXE_wardenlens"))
        .env_clear()
        .arg("--config")
        .arg(site.config())
        .args(["--log-format", "json", "token", "revoke", "zzzzzzzz"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let line = text(&out.stderr);
    let v: serde_json::Value = serde_json::from_str(line.trim_end()).unwrap();
    assert_eq!(v["level"], "ERROR");
    assert!(!line.contains(&secret_of(&t)));
}
