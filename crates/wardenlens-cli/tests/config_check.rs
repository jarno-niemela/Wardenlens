//! End-to-end tests of `wardenlens config check`, the global `--config`/`--log-format` flags and
//! the config-file path kinds (#64). Every run clears the environment and passes `--config` or
//! `WARDENLENS_CONFIG` itself, so the real `/etc/wardenlens` and the real home are never read.
//! All paths in configs are synthetic `/srv/...` values.

#![expect(
    clippy::unwrap_used,
    reason = "integration-test helpers outside #[test] fns; clippy.toml in-tests allowances do not reach them"
)]
#![expect(
    clippy::panic,
    reason = "the watchdog and the JSON assertion fail the test with a message from a helper"
)]

use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use tempfile::TempDir;

const SENTINEL: &str = "SENTINEL-8c1f3a";
const MAX: usize = 64 * 1024;

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

/// Runs with a watchdog: a hang (a FIFO opened blocking) fails the test instead of the suite.
fn run(c: Command) -> Output {
    run_to(c, Stdio::piped())
}

fn run_to(mut c: Command, stdout: Stdio) -> Output {
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

fn is_root() -> bool {
    rustix::process::geteuid().is_root()
}

fn assert_no_sentinel(out: &Output) {
    assert!(!text(&out.stdout).contains(SENTINEL), "{out:?}");
    assert!(!text(&out.stderr).contains(SENTINEL), "{out:?}");
}

#[test]
fn valid_config_prints_the_summary_and_exits_zero() {
    let dir = tempfile::tempdir().unwrap();
    let p = write(&dir, "w.toml", VALID.as_bytes());
    let out = check(&p);
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    assert_eq!(
        text(&out.stdout),
        "listen: 127.0.0.1:8080\n\
         hot_root: /srv/wl/hot (min free 20%)\n\
         archive_root: /srv/wl/archive (min free 30%)\n\
         segment_target_secs: 45\n\
         database: /srv/wl/state/index.db\n\
         key_file: /srv/wl/state/secrets.key\n"
    );
    assert_eq!(text(&out.stderr), "", "info logging is quiet by default");
}

#[test]
fn example_config_in_the_docs_passes_check() {
    let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/config.example.toml");
    let out = check(&p);
    assert_eq!(out.status.code(), Some(0), "{out:?}");
}

#[test]
fn key_file_contents_are_never_read_or_printed() {
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("secrets.key");
    std::fs::write(&key, SENTINEL).unwrap();
    let cfg = VALID.replace("/srv/wl/state/secrets.key", &key.display().to_string());
    let p = write(&dir, "w.toml", cfg.as_bytes());
    let out = check(&p);
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    assert!(text(&out.stdout).contains(&key.display().to_string()));
    assert_no_sentinel(&out);
}

/// The error-line substring each path-kind row must produce.
fn expected_reason(name: &str) -> &'static str {
    match name {
        "missing" => "not found",
        "directory" | "fifo" | "char device" => "not a regular file",
        "symlink to file" | "dangling symlink" | "symlink to directory" => "symbolic link",
        "mode 000" => "cannot be opened",
        "world-writable" => "writable by everyone",
        "64 KiB + 1" | "64 MiB" => "larger than",
        "invalid utf-8" => "not valid UTF-8",
        "empty" => "missing required key",
        "invalid listen" => "api.listen",
        other => panic!("no expected reason for {other}"),
    }
}

/// TEST-9: every kind of thing the config path can name, with its exit code. The file contents
/// (where there are any) hold a sentinel that must not come back.
#[test]
fn every_path_kind_has_a_defined_exit_code_and_leaks_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let with_sentinel = format!("{VALID}\n# {SENTINEL}\n");
    let mut cases: Vec<(&str, PathBuf, i32)> = Vec::new();

    cases.push((
        "regular",
        write(&dir, "regular", with_sentinel.as_bytes()),
        0,
    ));
    cases.push(("missing", dir.path().join("missing"), 2));
    cases.push(("directory", dir.path().to_path_buf(), 2));

    let target = write(&dir, "target", with_sentinel.as_bytes());
    let link = dir.path().join("link");
    symlink(&target, &link).unwrap();
    cases.push(("symlink to file", link, 2));
    let dangling = dir.path().join("dangling");
    symlink(dir.path().join("nowhere"), &dangling).unwrap();
    cases.push(("dangling symlink", dangling, 2));
    let dirlink = dir.path().join("dirlink");
    symlink(dir.path(), &dirlink).unwrap();
    cases.push(("symlink to directory", dirlink, 2));

    let fifo = dir.path().join("fifo");
    rustix::fs::mknodat(
        rustix::fs::CWD,
        &fifo,
        rustix::fs::FileType::Fifo,
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
        0,
    )
    .unwrap();
    cases.push(("fifo", fifo, 2));
    cases.push(("char device", PathBuf::from("/dev/null"), 2));

    if !is_root() {
        let locked = write(&dir, "locked", with_sentinel.as_bytes());
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
        cases.push(("mode 000", locked, 2));
    }
    let wide = write(&dir, "world-writable", with_sentinel.as_bytes());
    std::fs::set_permissions(&wide, std::fs::Permissions::from_mode(0o666)).unwrap();
    cases.push(("world-writable", wide, 2));

    let mut exact = VALID.to_owned();
    exact.push_str(&["# ", SENTINEL, "\n"].concat());
    exact.push_str(&"#".repeat(MAX - exact.len()));
    assert_eq!(exact.len(), MAX);
    cases.push(("exactly 64 KiB", write(&dir, "exact", exact.as_bytes()), 0));
    let over = format!("{exact}#");
    cases.push(("64 KiB + 1", write(&dir, "over", over.as_bytes()), 2));
    let huge = vec![b'#'; MAX * 64];
    cases.push(("64 MiB", write(&dir, "huge", &huge), 2));

    let mut bad_utf8 = VALID.as_bytes().to_vec();
    bad_utf8.extend_from_slice(format!("# {SENTINEL} ").as_bytes());
    bad_utf8.extend_from_slice(&[0xff, 0xfe, b'\n']);
    cases.push(("invalid utf-8", write(&dir, "utf8", &bad_utf8), 2));
    cases.push(("empty", write(&dir, "empty", b""), 1));
    let invalid = VALID.replace("127.0.0.1:8080", &format!("{SENTINEL}:1"));
    cases.push((
        "invalid listen",
        write(&dir, "invalid", invalid.as_bytes()),
        1,
    ));

    for (name, path, code) in cases {
        let out = check(&path);
        assert_eq!(out.status.code(), Some(code), "{name}: {out:?}");
        assert_no_sentinel(&out);
        if code != 0 {
            // The reason is the real one: swapping two error kinds fails here.
            let reason = expected_reason(name);
            assert!(text(&out.stderr).contains(reason), "{name}: {out:?}");
            assert_eq!(text(&out.stdout), "", "{name}");
            assert!(text(&out.stderr).starts_with("error: "), "{name}: {out:?}");
        }
    }
}

#[test]
fn failures_name_the_path_with_escapes_and_a_reason() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("miss\ning");
    let out = check(&missing);
    let err = text(&out.stderr);
    assert_eq!(out.status.code(), Some(2));
    assert!(err.contains("not found"), "{err}");
    assert!(
        err.contains("miss\\ning"),
        "control characters are escaped: {err}"
    );
    assert_eq!(err.lines().count(), 1, "{err}");
}

/// TEST-9: sentinels in every position a config can hold text. Nothing but the deliberately
/// printed fields may come back, and nothing at all on failure.
#[test]
fn sentinels_in_any_key_never_come_back() {
    let dir = tempfile::tempdir().unwrap();
    let broken: Vec<String> = vec![
        VALID.replace(
            "listen = \"127.0.0.1:8080\"",
            &format!("listen = \"{SENTINEL}\""),
        ),
        VALID.replace("127.0.0.1:8080", &format!("[fe80::1%{SENTINEL}]:80")),
        VALID.replace("/srv/wl/hot", SENTINEL),
        VALID.replace("/srv/wl/archive", &format!("/srv/{SENTINEL}/../x")),
        VALID.replace("/srv/wl/state/index.db", &format!("/srv/{SENTINEL}\u{1}")),
        VALID.replace(
            "key_file = \"/srv/wl/state/secrets.key\"",
            &format!("key_file = 7\n{SENTINEL} = 1"),
        ),
        VALID.replace("= 20", &format!("= \"{SENTINEL}\"")),
        VALID.replace("= 45", &format!("= {SENTINEL}")),
        format!("{VALID}\n{SENTINEL} = 1\n"),
        format!("{VALID}\n[{SENTINEL}]\nx = 1\n"),
        VALID.replace(
            "[recording]",
            &format!("[recording]\n{SENTINEL} = \"{SENTINEL}\""),
        ),
        VALID.replace("[secrets]", &format!("[secrets]\nextra = \"{SENTINEL}\"")),
        format!("{VALID}\n\"unterminated {SENTINEL}\n"),
        SENTINEL.to_owned(),
    ];
    for (i, cfg) in broken.iter().enumerate() {
        let p = write(&dir, &format!("c{i}.toml"), cfg.as_bytes());
        let out = check(&p);
        assert_ne!(out.status.code(), Some(0), "{i}: {out:?}");
        assert_no_sentinel(&out);
        assert_eq!(text(&out.stdout), "", "{i}");
    }
    // A valid config with the sentinel in a comment: success, nothing echoed.
    let ok = write(&dir, "ok.toml", format!("# {SENTINEL}\n{VALID}").as_bytes());
    let out = check(&ok);
    assert_eq!(out.status.code(), Some(0));
    assert_no_sentinel(&out);
}

#[test]
fn named_interface_scope_ids_are_refused_not_resolved() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = VALID.replace("127.0.0.1:8080", "[fe80::1%eth0]:8080");
    let out = check(&write(&dir, "scope.toml", cfg.as_bytes()));
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    assert!(text(&out.stderr).contains("api.listen"), "{out:?}");
}

#[test]
fn invalid_key_exits_one_naming_the_key() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = VALID.replace("= 45", "= 5");
    let out = check(&write(&dir, "bad.toml", cfg.as_bytes()));
    assert_eq!(out.status.code(), Some(1));
    assert!(
        text(&out.stderr).contains("recording.segment_target_secs"),
        "{out:?}"
    );
}

#[test]
fn flag_beats_env_and_env_is_used_without_a_flag() {
    let dir = tempfile::tempdir().unwrap();
    let good = write(&dir, "good.toml", VALID.as_bytes());
    let bad = write(&dir, "bad.toml", b"");

    let mut c = base();
    c.env("WARDENLENS_CONFIG", &bad)
        .args(["config", "check", "--config"])
        .arg(&good);
    assert_eq!(run(c).status.code(), Some(0), "flag over env");

    let mut c = base();
    c.env("WARDENLENS_CONFIG", &good).args(["config", "check"]);
    assert_eq!(run(c).status.code(), Some(0), "env alone");

    let mut c = base();
    c.env("WARDENLENS_CONFIG", dir.path().join("missing"))
        .args(["config", "check"]);
    let out = run(c);
    assert_eq!(out.status.code(), Some(2), "env names the file read");
    assert!(text(&out.stderr).contains("missing"), "{out:?}");
}

#[test]
fn the_flag_is_global_and_may_come_before_the_subcommand() {
    let dir = tempfile::tempdir().unwrap();
    let good = write(&dir, "good.toml", VALID.as_bytes());
    let mut c = base();
    c.arg("--config").arg(&good).args(["config", "check"]);
    assert_eq!(run(c).status.code(), Some(0));
}

#[test]
fn an_empty_config_flag_is_a_usage_error() {
    let mut c = base();
    c.args(["config", "check", "--config", ""]);
    let out = run(c);
    assert_eq!(out.status.code(), Some(2), "{out:?}");
    assert_eq!(text(&out.stdout), "");
}

#[test]
fn argv_text_is_never_echoed_by_a_usage_error() {
    let mut c = base();
    c.args(["config", "check", "--bogus", SENTINEL]);
    let out = run(c);
    assert_eq!(out.status.code(), Some(2));
    assert_no_sentinel(&out);
    let mut c = base();
    c.args(["--log-format", SENTINEL, "config", "check"]);
    let out = run(c);
    assert_eq!(out.status.code(), Some(2));
    assert_no_sentinel(&out);
}

#[test]
fn vault_still_refuses_a_config_flag() {
    let mut c = base();
    c.args(["vault", "list", "--config", "/srv/x"]);
    let out = run(c);
    assert_eq!(out.status.code(), Some(2), "{out:?}");
    assert_eq!(text(&out.stdout), "");
}

fn assert_all_json(stderr: &[u8]) -> Vec<serde_json::Value> {
    text(stderr)
        .lines()
        .map(|l| {
            serde_json::from_str::<serde_json::Value>(l).unwrap_or_else(|e| panic!("{l}: {e}"))
        })
        .collect()
}

#[test]
fn json_logs_parse_line_by_line_and_never_reach_stdout() {
    let dir = tempfile::tempdir().unwrap();
    let good = write(&dir, "good.toml", VALID.as_bytes());
    let mut c = base();
    c.env("RUST_LOG", "debug")
        .args(["--log-format", "json", "config", "check", "--config"])
        .arg(&good);
    let out = run(c);
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    assert!(
        !assert_all_json(&out.stderr).is_empty(),
        "debug level logs something"
    );
    assert!(
        text(&out.stdout)
            .lines()
            .all(|l| serde_json::from_str::<serde_json::Value>(l).is_err()),
        "stdout holds the summary only"
    );
    assert!(text(&out.stdout).starts_with("listen: "));
}

#[test]
fn json_failure_is_a_json_line_even_with_logging_off() {
    let dir = tempfile::tempdir().unwrap();
    for rust_log in ["off", "error", "info", "not a [valid directive"] {
        let mut c = base();
        c.env("RUST_LOG", rust_log)
            .args(["--log-format", "json", "config", "check", "--config"])
            .arg(dir.path().join("missing"));
        let out = run(c);
        assert_eq!(out.status.code(), Some(2), "{rust_log}");
        let lines = assert_all_json(&out.stderr);
        assert!(
            lines.iter().any(|l| l["level"] == "ERROR"),
            "{rust_log}: {lines:?}"
        );
        assert_eq!(text(&out.stdout), "");
    }
}

#[test]
fn text_failure_is_one_error_line_and_log_format_text_is_the_default() {
    let dir = tempfile::tempdir().unwrap();
    for extra in [&[][..], &["--log-format", "text"][..]] {
        let mut c = base();
        c.args(extra)
            .args(["config", "check", "--config"])
            .arg(dir.path().join("missing"));
        let out = run(c);
        let err = text(&out.stderr);
        assert_eq!(err.lines().count(), 1, "{err}");
        assert!(err.starts_with("error: "), "{err}");
    }
}

#[test]
fn rust_log_selects_the_level_and_a_bad_value_falls_back_with_a_warning() {
    let dir = tempfile::tempdir().unwrap();
    let good = write(&dir, "good.toml", VALID.as_bytes());
    let run_with = |level: &str| {
        let mut c = base();
        c.env("RUST_LOG", level)
            .args(["--log-format", "json", "config", "check", "--config"])
            .arg(&good);
        run(c)
    };
    assert_eq!(text(&run_with("error").stderr), "");
    assert_eq!(text(&run_with("off").stderr), "");
    let out = run_with("=[bad");
    assert_eq!(out.status.code(), Some(0));
    let lines = assert_all_json(&out.stderr);
    assert!(lines.iter().any(|l| l["level"] == "WARN"), "{lines:?}");
    assert!(
        !text(&out.stderr).contains("=[bad"),
        "the bad value is not echoed"
    );
}

#[test]
fn a_world_writable_parent_directory_warns_but_works() {
    let dir = tempfile::tempdir().unwrap();
    let sub = dir.path().join("open");
    std::fs::create_dir(&sub).unwrap();
    std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o777)).unwrap();
    let p = sub.join("w.toml");
    std::fs::write(&p, VALID).unwrap();
    let mut c = base();
    c.args(["--log-format", "json", "config", "check", "--config"])
        .arg(&p);
    let out = run(c);
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    let lines = assert_all_json(&out.stderr);
    assert!(lines.iter().any(|l| l["level"] == "WARN"), "{lines:?}");
}

#[test]
fn a_group_writable_file_is_accepted() {
    let dir = tempfile::tempdir().unwrap();
    let p = write(&dir, "g.toml", VALID.as_bytes());
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o664)).unwrap();
    assert_eq!(check(&p).status.code(), Some(0));
}

#[test]
fn bare_invocation_still_prints_the_version() {
    let out = run(base());
    assert_eq!(out.status.code(), Some(0));
    assert!(text(&out.stdout).starts_with("wardenlens "));
}

#[test]
fn log_format_is_validated() {
    let mut c = base();
    c.args(["--log-format", "yaml", "config", "check"]);
    assert_eq!(run(c).status.code(), Some(2));
}

#[test]
fn a_symlink_loop_in_a_parent_is_not_called_a_symlink_file() {
    let dir = tempfile::tempdir().unwrap();
    let (a, b) = (dir.path().join("a"), dir.path().join("b"));
    symlink(&b, &a).unwrap();
    symlink(&a, &b).unwrap();
    let out = check(&a.join("w.toml"));
    assert_eq!(out.status.code(), Some(2));
    let err = text(&out.stderr);
    assert!(err.contains("cannot be opened"), "{err}");
    assert!(err.contains("symbolic links"), "{err}");
    assert!(!err.contains("give its real path"), "{err}");
}

#[test]
fn a_stdout_failure_exits_two_not_one() {
    let dir = tempfile::tempdir().unwrap();
    let p = write(&dir, "w.toml", VALID.as_bytes());
    let full = std::fs::OpenOptions::new()
        .write(true)
        .open("/dev/full")
        .unwrap();
    let (reader, writer) = std::io::pipe().unwrap();
    drop(reader);
    for (name, stdout) in [
        ("/dev/full", Stdio::from(full)),
        ("closed pipe", Stdio::from(writer)),
    ] {
        let mut c = base();
        c.args(["config", "check", "--config"]).arg(&p);
        let out = run_to(c, stdout);
        assert_eq!(out.status.code(), Some(2), "{name}: {out:?}");
        assert!(
            text(&out.stderr).contains("cannot write to stdout"),
            "{name}: {out:?}"
        );
    }
}

#[test]
fn vault_gets_no_logging_and_refuses_log_format() {
    let home = tempfile::tempdir().unwrap();
    let mut c = base();
    c.env("HOME", home.path())
        .args(["--log-format", "text", "vault", "list"]);
    let out = run(c);
    assert_eq!(out.status.code(), Some(2), "{out:?}");
    assert_eq!(text(&out.stdout), "");
    let mut c = base();
    c.env("HOME", home.path())
        .args(["--log-format", "json", "vault", "list"]);
    let out = run(c);
    assert_eq!(out.status.code(), Some(2));
    assert_all_json(&out.stderr);
}

#[test]
fn config_flag_without_a_subcommand_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let good = write(&dir, "good.toml", VALID.as_bytes());
    let mut c = base();
    c.arg("--config").arg(&good);
    let out = run(c);
    assert_eq!(out.status.code(), Some(2), "{out:?}");
    assert_eq!(text(&out.stdout), "");
    assert!(text(&out.stderr).contains("needs a subcommand"), "{out:?}");
}

#[test]
fn usage_errors_are_json_when_json_was_asked_for_exactly() {
    for args in [
        &["--log-format", "json", "config", "check", "--bogus"][..],
        &["--log-format=json", "config", "check", "--bogus"][..],
        &["--log-format", "json", "config"][..],
    ] {
        let mut c = base();
        c.args(args);
        let out = run(c);
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        assert_eq!(text(&out.stderr).lines().count(), 1, "{args:?}");
        assert_all_json(&out.stderr);
    }
    // Not an exact match: plain text.
    let mut c = base();
    c.args(["--log-format", "jsonx", "config", "check"]);
    let out = run(c);
    assert_eq!(out.status.code(), Some(2));
    assert!(text(&out.stderr).starts_with("error: "));
}

#[test]
fn printed_paths_never_hold_invisible_characters() {
    let dir = tempfile::tempdir().unwrap();
    for (i, ch) in [
        '\u{202e}', '\u{2066}', '\u{2028}', '\u{2029}', '\u{200b}', '\u{feff}',
    ]
    .into_iter()
    .enumerate()
    {
        let cfg = VALID.replace("/srv/wl/hot", &format!("/srv/wl/h{ch}ot"));
        let out = check(&write(&dir, &format!("i{i}.toml"), cfg.as_bytes()));
        assert_eq!(out.status.code(), Some(1), "U+{:04X}", u32::from(ch));
        assert_eq!(text(&out.stdout), "");
        assert!(!text(&out.stderr).contains(ch));
    }
}
