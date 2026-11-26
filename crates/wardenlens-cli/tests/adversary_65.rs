//! Adversarial tests for #65 (PR #173): `wardenlens token`. Synthetic data only; every path is
//! under a temporary directory and the environment is cleared.
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
use wardenlens_core::time::UnixMs;
use wardenlens_core::token_store::{MAX_TOKENS, NewToken, TokenName};
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
    fn run(&self, args: &[&str]) -> Output {
        self.cmd(args).output().unwrap()
    }
    fn active_ids(&self) -> Vec<String> {
        let index = Index::open(&self.db()).unwrap();
        index
            .list_tokens()
            .unwrap()
            .into_iter()
            .filter(|t| !t.revoked)
            .map(|t| t.id.to_string())
            .collect()
    }
    fn all_files_bytes(&self) -> Vec<u8> {
        let mut all = Vec::new();
        for e in fs::read_dir(self.dir.path().join("state")).unwrap() {
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

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

fn dev_full() -> fs::File {
    fs::OpenOptions::new()
        .write(true)
        .open("/dev/full")
        .unwrap()
}

/// stdout that cannot take the token: exit 2 and no active token left behind.
#[test]
fn create_with_a_full_stdout_fails_and_leaves_no_active_token() {
    let site = Site::new();
    let out = site
        .cmd(&["token", "create", "--name", "ci"])
        .stdout(Stdio::from(dev_full()))
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2), "{}", text(&out.stderr));
    assert!(
        site.active_ids().is_empty(),
        "a token nobody saw is still active"
    );
    assert!(
        text(&out.stderr).contains("stdout"),
        "{}",
        text(&out.stderr)
    );
}

/// The token reached stdout but the stderr hint could not be written. Either the command
/// succeeds (the token was delivered) or it fails and the token is revoked; a failure exit with
/// an active token makes a script throw away a token that stays valid.
#[test]
fn create_never_reports_failure_while_leaving_the_printed_token_active() {
    let site = Site::new();
    let out = site
        .cmd(&["token", "create", "--name", "ci"])
        .stderr(Stdio::from(dev_full()))
        .output()
        .unwrap();
    let printed = text(&out.stdout);
    let active = site.active_ids();
    let ok = out.status.success();
    assert!(
        ok || active.is_empty(),
        "exit {:?}, stdout {:?}, active tokens {active:?}: the command reported failure but the token it printed still verifies",
        out.status.code(),
        printed.trim_end()
    );
}

/// Concurrent `create` invocations are serialised by the index lock: every one succeeds, with
/// a distinct id, and every printed token is stored.
#[test]
fn concurrent_creates_all_succeed_with_distinct_ids() {
    let site = Site::new();
    // Create the index first so the racers do not also race the creation of the file.
    drop(Index::open(&site.db()).unwrap());
    let children: Vec<_> = (0..8)
        .map(|i| {
            site.cmd(&["token", "create", "--name", &format!("n{i}")])
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap()
        })
        .collect();
    let mut ids = Vec::new();
    for c in children {
        let out = c.wait_with_output().unwrap();
        assert!(out.status.success(), "{}", text(&out.stderr));
        let t = Token::parse(text(&out.stdout).trim_end()).unwrap();
        ids.push(t.id().to_string());
    }
    ids.sort();
    ids.dedup();
    assert_eq!(ids.len(), 8);
    let mut active = site.active_ids();
    active.sort();
    assert_eq!(active, ids);
}

/// The secret never reaches stderr, the DB or its sidecars, even with the most verbose logging.
#[test]
fn verbose_logging_never_shows_the_secret() {
    let site = Site::new();
    for level in ["trace", "debug"] {
        for fmt in ["text", "json"] {
            let out = site
                .cmd(&["--log-format", fmt, "token", "create", "--name", "x"])
                .env("RUST_LOG", level)
                .output()
                .unwrap();
            assert!(out.status.success(), "{}", text(&out.stderr));
            let t = Token::parse(text(&out.stdout).trim_end()).unwrap();
            let shown = t.expose();
            let secret = shown.splitn(3, '_').nth(2).unwrap();
            assert!(!contains(&out.stderr, secret.as_bytes()), "{level} {fmt}");
            assert!(!contains(&site.all_files_bytes(), secret.as_bytes()));
            let l = site.run(&["token", "list"]);
            assert!(!contains(&l.stdout, secret.as_bytes()));
            assert!(!contains(&l.stderr, secret.as_bytes()));
        }
    }
}

/// The index and every sidecar the CLI leaves are owner-only.
#[test]
fn the_index_and_its_sidecars_are_owner_only_after_create() {
    let site = Site::new();
    let out = site.run(&["token", "create", "--name", "x"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    for e in fs::read_dir(site.dir.path().join("state")).unwrap() {
        let p = e.unwrap().path();
        let mode = fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode & 0o077, 0, "{} has mode {mode:o}", p.display());
    }
}

/// A full table: a typed, explained failure, exit 2, nothing printed.
#[test]
fn a_full_table_is_reported_as_full_and_prints_nothing() {
    let site = Site::new();
    {
        let mut index = Index::open(&site.db()).unwrap();
        for i in 0..MAX_TOKENS {
            let t = Token::generate().unwrap();
            index
                .insert_token(&NewToken {
                    id: *t.id(),
                    digest: t.secret().digest(),
                    name: TokenName::new(&format!("n{i}")).unwrap(),
                    created_at: UnixMs::new(1_700_000_000_000).unwrap(),
                })
                .unwrap();
        }
    }
    let out = site.run(&["token", "create", "--name", "one-too-many"]);
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(out.stdout, b"");
    assert!(text(&out.stderr).contains("full"), "{}", text(&out.stderr));
    // list still works at the cap.
    let l = site.run(&["token", "list"]);
    assert!(l.status.success());
    assert_eq!(text(&l.stdout).lines().count(), MAX_TOKENS + 1);
}

/// Name edge cases: bidi isolates/marks, BOM, zero-width, C1 controls and line separators are
/// refused; ordinary unicode is accepted and listed byte-identically.
#[test]
fn name_edge_cases_through_the_binary() {
    for (name, ok) in [
        ("a\u{2066}b", false),
        ("a\u{2069}b", false),
        ("a\u{200f}b", false),
        ("a\u{061c}b", false),
        ("\u{feff}a", false),
        ("a\u{200b}b", false),
        ("a\u{85}b", false),
        ("a\u{2029}b", false),
        ("a\rb", false),
        ("\u{3000}", false),
        ("Grafana \u{1F600} \u{05D0}\u{05D1}", true),
        ("e\u{301}", true),
        (" padded ", true),
    ] {
        let site = Site::new();
        let out = site.run(&["token", "create", "--name", name]);
        if ok {
            assert!(out.status.success(), "{name:?}: {}", text(&out.stderr));
            let l = site.run(&["token", "list"]);
            let s = text(&l.stdout);
            let cols: Vec<&str> = s.lines().nth(1).unwrap().split('\t').collect();
            assert_eq!(cols.len(), 5, "{name:?}");
            assert_eq!(cols[1], name);
        } else {
            assert_eq!(out.status.code(), Some(2), "{name:?}");
            assert_eq!(out.stdout, b"", "{name:?}");
            assert!(!site.db().exists(), "{name:?}");
        }
    }
}

/// A NUL inside an argv entry cannot reach the binary, but a name of non-UTF-8 bytes can; it is a
/// usage error, never a stored row.
#[test]
fn a_non_utf8_name_is_refused_and_stores_nothing() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;
    let site = Site::new();
    let out = Command::new(env!("CARGO_BIN_EXE_wardenlens"))
        .env_clear()
        .arg("--config")
        .arg(site.config())
        .args(["token", "create", "--name"])
        .arg(OsStr::from_bytes(b"a\xffb"))
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(out.stdout, b"");
    assert!(!site.db().exists());
}

/// Revoke by a full token string (a likely operator slip) is refused and never echoes the secret.
#[test]
fn revoke_given_the_whole_token_never_echoes_the_secret() {
    let site = Site::new();
    let out = site.run(&["token", "create", "--name", "x"]);
    let shown = text(&out.stdout).trim_end().to_owned();
    let secret = shown.splitn(3, '_').nth(2).unwrap().to_owned();
    for fmt in ["text", "json"] {
        let r = site.run(&["--log-format", fmt, "token", "revoke", &shown]);
        assert_eq!(r.status.code(), Some(2));
        assert!(
            !contains(&r.stderr, secret.as_bytes()),
            "{}",
            text(&r.stderr)
        );
        assert!(!contains(&r.stdout, secret.as_bytes()));
    }
    assert_eq!(site.active_ids().len(), 1);
}

/// Revoked ids stay revoked across further creates and revokes; list keeps every row.
#[test]
fn revoked_tokens_stay_revoked_and_rows_are_kept_over_many_rounds() {
    let site = Site::new();
    let mut revoked = Vec::new();
    for i in 0..6 {
        let out = site.run(&["token", "create", "--name", &format!("r{i}")]);
        let t = Token::parse(text(&out.stdout).trim_end()).unwrap();
        if i % 2 == 0 {
            assert!(
                site.run(&["token", "revoke", t.id().as_str()])
                    .status
                    .success()
            );
            revoked.push(*t.id());
        }
    }
    let index = Index::open(&site.db()).unwrap();
    let rows = index.list_tokens().unwrap();
    assert_eq!(rows.len(), 6);
    for id in &revoked {
        let r = index.find_token(id).unwrap().unwrap();
        assert!(r.revoked);
    }
    // Oldest first.
    let names: Vec<_> = rows.iter().map(|r| r.name.as_str().to_owned()).collect();
    assert_eq!(names, ["r0", "r1", "r2", "r3", "r4", "r5"]);
}
