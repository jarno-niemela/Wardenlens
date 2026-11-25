//! Adversarial tests for #64 (`wardenlens config check`, `--config`, `--log-format`). Every run
//! clears the environment and names its own config, so the real `/etc/wardenlens` and the real
//! home are never read. All values are synthetic.

#![expect(
    clippy::unwrap_used,
    reason = "integration-test helpers outside #[test] fns; clippy.toml in-tests allowances do not reach them"
)]
#![expect(
    clippy::panic,
    reason = "the watchdog fails the test with a message from a helper"
)]

use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use tempfile::TempDir;

const SENTINEL: &str = "SENTINEL-adv64";

const VALID: &str = r#"
[api]
listen = "127.0.0.1:8080"
[storage]
hot_root = "/srv/wl/hot"
archive_root = "/srv/wl/archive"
hot_min_free_percent = 20
archive_min_free_percent = 30
[recording]
segment_target_secs = 45
[database]
path = "/srv/wl/state/index.db"
[secrets]
key_file = "/srv/wl/state/secrets.key"
"#;

fn base() -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_wardenlens"));
    c.env_clear();
    c
}

/// A watchdog bound only: a hang fails the test instead of the suite.
fn run_with_stdout(mut c: Command, stdout: Stdio) -> Output {
    let mut child = c
        .stdin(Stdio::null())
        .stdout(stdout)
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let start = Instant::now();
    loop {
        if child.try_wait().unwrap().is_some() {
            return child.wait_with_output().unwrap();
        }
        if start.elapsed() > Duration::from_secs(20) {
            child.kill().unwrap();
            panic!("the binary hung");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn run(c: Command) -> Output {
    run_with_stdout(c, Stdio::piped())
}

fn check(config: &Path) -> Output {
    let mut c = base();
    c.args(["config", "check", "--config"]).arg(config);
    run(c)
}

fn write(dir: &TempDir, name: &str, bytes: &[u8]) -> PathBuf {
    let p = dir.path().join(name);
    std::fs::write(&p, bytes).unwrap();
    p
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

fn assert_no_sentinel(out: &Output) {
    assert!(!text(&out.stdout).contains(SENTINEL), "{out:?}");
    assert!(!text(&out.stderr).contains(SENTINEL), "{out:?}");
}

fn assert_all_json(stderr: &[u8]) {
    for l in text(stderr).lines() {
        assert!(
            serde_json::from_str::<serde_json::Value>(l).is_ok(),
            "stderr line is not JSON under --log-format json: {l:?}"
        );
    }
}

// ---- Invariant 3: under --log-format json every stderr line is JSON ----

#[test]
fn json_mode_vault_config_refusal_is_a_json_line() {
    let mut c = base();
    c.args([
        "--log-format",
        "json",
        "vault",
        "list",
        "--config",
        "/srv/x",
    ]);
    let out = run(c);
    assert_eq!(out.status.code(), Some(2), "{out:?}");
    assert_all_json(&out.stderr);
}

#[test]
fn json_mode_usage_error_after_a_parsed_log_format_is_a_json_line() {
    let mut c = base();
    c.args(["--log-format", "json", "config", "check", "--bogus"]);
    let out = run(c);
    assert_eq!(out.status.code(), Some(2), "{out:?}");
    assert_all_json(&out.stderr);
}

#[test]
fn json_mode_failure_with_hostile_path_bytes_is_one_json_line() {
    let dir = tempfile::tempdir().unwrap();
    let mut raw = dir.path().as_os_str().as_bytes().to_vec();
    raw.extend_from_slice(b"/q\"uo\\te\n\x1b[2J\xff\xfe\xe2\x80\xae.toml");
    let p = PathBuf::from(OsStr::from_bytes(&raw));
    let mut c = base();
    c.args(["--log-format", "json", "config", "check", "--config"])
        .arg(&p);
    let out = run(c);
    assert_eq!(out.status.code(), Some(2), "{out:?}");
    assert_eq!(text(&out.stderr).lines().count(), 1, "{out:?}");
    assert_all_json(&out.stderr);
    assert!(!out.stderr.contains(&0x1b), "raw ESC reached stderr");
    assert_eq!(text(&out.stdout), "");
}

// ---- Exit codes: 1 means "invalid config" only ----

#[test]
fn stdout_failure_does_not_claim_a_valid_config_is_invalid() {
    let dir = tempfile::tempdir().unwrap();
    let p = write(&dir, "w.toml", VALID.as_bytes());
    let full = std::fs::OpenOptions::new()
        .write(true)
        .open("/dev/full")
        .unwrap();
    let mut c = base();
    c.args(["config", "check", "--config"]).arg(&p);
    let out = run_with_stdout(c, Stdio::from(full));
    assert_ne!(
        out.status.code(),
        Some(1),
        "a valid config reported as invalid (exit 1) because stdout failed: {out:?}"
    );
    assert_ne!(out.status.code(), Some(0), "{out:?}");
}

// ---- Invariant 5: the vault commands are unchanged ----

#[test]
fn vault_commands_gain_no_rust_log_warning() {
    let home = tempfile::tempdir().unwrap();
    let run_vault = |rust_log: Option<&str>| {
        let mut c = base();
        c.env("HOME", home.path()).args(["vault", "list"]);
        if let Some(v) = rust_log {
            c.env("RUST_LOG", v);
        }
        run(c)
    };
    let before = run_vault(None);
    let with_bad_log = run_vault(Some("=[bad"));
    assert_eq!(before.status.code(), with_bad_log.status.code());
    assert_eq!(
        text(&before.stderr),
        text(&with_bad_log.stderr),
        "RUST_LOG changed the vault command's stderr"
    );
}

// ---- Summary output: deliberately printed paths must not spoof the display ----

#[test]
fn summary_never_prints_bidi_or_line_separator_characters_raw() {
    let dir = tempfile::tempdir().unwrap();
    for (i, ch) in ['\u{202e}', '\u{2028}', '\u{2029}', '\u{200b}', '\u{feff}']
        .into_iter()
        .enumerate()
    {
        let cfg = VALID.replace("/srv/wl/hot", &format!("/srv/wl/h{ch}ot"));
        let out = check(&write(&dir, &format!("b{i}.toml"), cfg.as_bytes()));
        assert!(
            !text(&out.stdout).contains(ch),
            "U+{:04X} printed raw on stdout: {out:?}",
            u32::from(ch)
        );
    }
}

// ---- Error typing: the reason given is the real one ----

#[test]
fn a_symlink_loop_in_a_parent_is_not_reported_as_the_file_being_a_symlink() {
    let dir = tempfile::tempdir().unwrap();
    let a = dir.path().join("a");
    let b = dir.path().join("b");
    symlink(&b, &a).unwrap();
    symlink(&a, &b).unwrap();
    let out = check(&a.join("wardenlens.toml"));
    assert_eq!(out.status.code(), Some(2), "{out:?}");
    assert!(
        !text(&out.stderr).contains("is a symbolic link; give its real path"),
        "the file itself is no symlink: {out:?}"
    );
}

// ---- Invariant 1: path kinds through every entry point ----

#[test]
fn path_kinds_through_the_environment_variable_are_refused_too() {
    let dir = tempfile::tempdir().unwrap();
    let target = write(&dir, "t.toml", format!("{VALID}# {SENTINEL}\n").as_bytes());
    let link = dir.path().join("link");
    symlink(&target, &link).unwrap();
    let fifo = dir.path().join("fifo");
    rustix::fs::mknodat(
        rustix::fs::CWD,
        &fifo,
        rustix::fs::FileType::Fifo,
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
        0,
    )
    .unwrap();
    for p in [
        link,
        fifo,
        dir.path().to_path_buf(),
        PathBuf::from("/dev/zero"),
    ] {
        let mut c = base();
        c.env("WARDENLENS_CONFIG", &p).args(["config", "check"]);
        let out = run(c);
        assert_eq!(out.status.code(), Some(2), "{p:?}: {out:?}");
        assert_eq!(text(&out.stdout), "");
        assert_no_sentinel(&out);
    }
}

#[test]
fn trailing_slash_and_fd_aliases_never_read_through_a_symlink() {
    let dir = tempfile::tempdir().unwrap();
    let sub = dir.path().join("d");
    std::fs::create_dir(&sub).unwrap();
    let target = write(&dir, "t.toml", format!("{VALID}# {SENTINEL}\n").as_bytes());
    let ldir = dir.path().join("ldir");
    symlink(&sub, &ldir).unwrap();
    let lfile = dir.path().join("lfile");
    symlink(&target, &lfile).unwrap();
    let mut slash_dir = ldir.into_os_string();
    slash_dir.push("/");
    let mut slash_file = lfile.clone().into_os_string();
    slash_file.push("/");
    let mut dot = lfile.into_os_string();
    dot.push("/.");
    for p in [
        PathBuf::from(slash_dir),
        PathBuf::from(slash_file),
        PathBuf::from(dot),
        PathBuf::from("/dev/stdin"),
        PathBuf::from("/dev/fd/0"),
        PathBuf::from("/proc/self/fd/0"),
    ] {
        let out = check(&p);
        assert_eq!(out.status.code(), Some(2), "{p:?}: {out:?}");
        assert_eq!(text(&out.stdout), "", "{p:?}");
        assert_no_sentinel(&out);
    }
}

#[test]
fn a_unix_socket_is_refused_with_exit_two() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("s");
    let _l = std::os::unix::net::UnixListener::bind(&sock).unwrap();
    let out = check(&sock);
    assert_eq!(out.status.code(), Some(2), "{out:?}");
    assert_eq!(text(&out.stdout), "");
}

/// A regular procfs file whose bytes the caller controls (its own environment, with NULs).
#[test]
fn proc_environ_is_read_as_bytes_and_never_echoed() {
    let mut c = base();
    c.env("X", SENTINEL)
        .args(["config", "check", "--config", "/proc/self/environ"]);
    let out = run(c);
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    assert_no_sentinel(&out);
    assert_eq!(text(&out.stdout), "");
}

// ---- Invariant 4: no echo of config text through structural errors ----

#[test]
fn structural_errors_never_echo_keys_or_values() {
    let dir = tempfile::tempdir().unwrap();
    let cases = [
        format!("{VALID}[storage.{SENTINEL}]\na = 1\n"),
        VALID.replace(
            "listen = \"127.0.0.1:8080\"",
            &format!("listen = {{ {SENTINEL} = 1 }}"),
        ),
        VALID.replace("[api]", "[[api]]"),
        format!("{VALID}[api]\nlisten = \"{SENTINEL}\"\n"),
        VALID.replace(
            "listen = \"127.0.0.1:8080\"",
            &format!("listen = \"127.0.0.1:1\"\nlisten = \"{SENTINEL}\""),
        ),
        VALID.replace("[api]", &format!("[api]\n\"{SENTINEL}\".x = 1")),
        VALID.replace("= 45", &format!("= [\"{SENTINEL}\"]")),
        VALID.replace("= 45", &format!("= 1979-05-27T07:32:00Z # {SENTINEL}")),
        VALID.replace("= 45", "= 99999999999999999999999"),
        format!("{VALID}\0{SENTINEL}"),
        format!("\u{feff}{VALID}{SENTINEL}"),
    ];
    for (i, cfg) in cases.iter().enumerate() {
        let out = check(&write(&dir, &format!("s{i}.toml"), cfg.as_bytes()));
        assert_eq!(out.status.code(), Some(1), "{i}: {out:?}");
        assert_no_sentinel(&out);
        assert_eq!(text(&out.stdout), "", "{i}");
    }
}

#[test]
fn usage_errors_that_pass_through_clap_never_echo_argv_values() {
    let cases: &[&[&str]] = &[
        &["vault", "scan", "--remote", SENTINEL],
        &["vault", "scan", "--ref", SENTINEL],
        &["vault", "set", SENTINEL],
        &["--config", SENTINEL, "vault", "set", "--kind", "secret"],
        &["--config", SENTINEL, "config"],
        &["config", "check", SENTINEL],
        &[SENTINEL],
        &["--log-format", "json", "--config", SENTINEL, "vault", "get"],
    ];
    for args in cases {
        let mut c = base();
        c.args(*args);
        let out = run(c);
        assert_eq!(out.status.code(), Some(2), "{args:?}: {out:?}");
        assert_no_sentinel(&out);
    }
}

// ---- Invariant 2: precedence ----

#[test]
fn an_empty_flag_does_not_fall_back_to_a_valid_env_path() {
    let dir = tempfile::tempdir().unwrap();
    let good = write(&dir, "good.toml", VALID.as_bytes());
    for flag in ["--config=", "--config"] {
        let mut c = base();
        c.env("WARDENLENS_CONFIG", &good).args(["config", "check"]);
        if flag == "--config" {
            c.args([flag, ""]);
        } else {
            c.arg(flag);
        }
        let out = run(c);
        assert_eq!(out.status.code(), Some(2), "{flag}: {out:?}");
        assert_eq!(text(&out.stdout), "");
    }
}

#[test]
fn a_whitespace_env_value_is_a_path_not_unset() {
    let mut c = base();
    c.env("WARDENLENS_CONFIG", " ").args(["config", "check"]);
    let out = run(c);
    assert_eq!(out.status.code(), Some(2), "{out:?}");
    assert!(text(&out.stderr).contains("\" \""), "{out:?}");
}

#[test]
fn json_logs_at_trace_level_carry_no_config_text() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = format!("# {SENTINEL}\n{VALID}");
    let p = write(&dir, "w.toml", cfg.as_bytes());
    for fmt in ["json", "text"] {
        let mut c = base();
        c.env("RUST_LOG", "trace")
            .args(["--log-format", fmt, "config", "check", "--config"])
            .arg(&p);
        let out = run(c);
        assert_eq!(out.status.code(), Some(0), "{out:?}");
        assert_no_sentinel(&out);
        if fmt == "json" {
            assert_all_json(&out.stderr);
        }
        assert!(!out.stderr.contains(&0x1b), "{fmt}: ANSI escapes on a pipe");
    }
}
