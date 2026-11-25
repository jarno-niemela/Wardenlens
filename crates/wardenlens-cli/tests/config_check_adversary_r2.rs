//! Round-2 adversarial tests for #64. Every run clears the environment and names its own config,
//! so the real `/etc/wardenlens` and the real home are never read. All values are synthetic.

#![expect(
    clippy::unwrap_used,
    reason = "integration-test helpers outside #[test] fns; clippy.toml in-tests allowances do not reach them"
)]
#![expect(
    clippy::panic,
    reason = "the watchdog fails the test with a message from a helper"
)]

use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use tempfile::TempDir;

const SENTINEL: &str = "SENTINEL-adv64r2";

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
fn run(mut c: Command) -> Output {
    let mut child = c
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
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

fn check_with(config: &Path, json: bool) -> Output {
    let mut c = base();
    if json {
        c.args(["--log-format", "json"]);
    }
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

fn assert_all_json(stderr: &[u8]) {
    for l in text(stderr).lines() {
        assert!(
            serde_json::from_str::<serde_json::Value>(l).is_ok(),
            "stderr line is not JSON under --log-format json: {l:?}"
        );
    }
}

/// TEST-9, path kinds the round-1 table does not hold: a regular file used as a directory, a
/// trailing slash on a regular file, an over-long name, a symlink loop as the last component and
/// a symlink in a parent (followed, documented). Text and JSON both.
#[test]
fn more_path_kinds_have_defined_exit_codes_in_both_formats() {
    let dir = tempfile::tempdir().unwrap();
    let good = write(
        &dir,
        "good.toml",
        format!("{VALID}# {SENTINEL}\n").as_bytes(),
    );
    let mut trailing = good.clone().into_os_string();
    trailing.push("/");
    let loop_last = dir.path().join("self");
    symlink(&loop_last, &loop_last).unwrap();
    let pdir = dir.path().join("pdir");
    symlink(dir.path(), &pdir).unwrap();
    let long = dir.path().join("n".repeat(300));
    let cases: Vec<(&str, PathBuf, i32, &str)> = vec![
        ("file as dir", good.join("x.toml"), 2, "cannot be opened"),
        (
            "trailing slash on file",
            PathBuf::from(trailing),
            2,
            "cannot be opened",
        ),
        ("name too long", long, 2, "cannot be opened"),
        ("self-loop symlink", loop_last, 2, "symbolic link"),
        ("symlink in parent", pdir.join("good.toml"), 0, ""),
    ];
    for json in [false, true] {
        for (name, path, code, reason) in &cases {
            let out = check_with(path, json);
            assert_eq!(
                out.status.code(),
                Some(*code),
                "{name} json={json}: {out:?}"
            );
            assert!(!text(&out.stdout).contains(SENTINEL), "{name}");
            assert!(!text(&out.stderr).contains(SENTINEL), "{name}");
            if *code != 0 {
                assert_eq!(text(&out.stdout), "", "{name}");
                assert!(text(&out.stderr).contains(reason), "{name}: {out:?}");
                if json {
                    assert_eq!(text(&out.stderr).lines().count(), 1, "{name}");
                    assert_all_json(&out.stderr);
                }
            }
        }
    }
}

/// A regular procfs file that fails on read (not on open): exit 2, one line, JSON under json.
#[test]
fn a_read_error_after_a_good_open_exits_two() {
    for json in [false, true] {
        let out = check_with(Path::new("/proc/self/mem"), json);
        assert_eq!(out.status.code(), Some(2), "json={json}: {out:?}");
        assert_eq!(text(&out.stdout), "");
        assert!(text(&out.stderr).contains("cannot be read"), "{out:?}");
        if json {
            assert_all_json(&out.stderr);
        }
    }
}

/// The core path rule is `is_invisible`, not only the handful in the round-2 table: every printed
/// path key refuses fillers, joiners, variation and tag characters, and nothing reaches stdout.
#[test]
fn every_printed_path_key_refuses_every_class_of_invisible_character() {
    let dir = tempfile::tempdir().unwrap();
    let keys = [
        "/srv/wl/hot",
        "/srv/wl/archive",
        "/srv/wl/state/index.db",
        "/srv/wl/state/secrets.key",
    ];
    let chars = [
        '\u{3164}',
        '\u{115f}',
        '\u{ffa0}',
        '\u{034f}',
        '\u{fe0f}',
        '\u{e0001}',
        '\u{e0041}',
        '\u{061c}',
        '\u{00ad}',
        '\u{2060}',
        '\u{180e}',
        '\u{1d173}',
        '\u{e0100}',
    ];
    let mut n = 0;
    for key in keys {
        for ch in chars {
            n += 1;
            let cfg = VALID.replace(key, &format!("{key}{ch}x"));
            assert_ne!(cfg, VALID);
            let out = check_with(&write(&dir, &format!("c{n}.toml"), cfg.as_bytes()), false);
            assert_eq!(
                out.status.code(),
                Some(1),
                "{key} U+{:04X}: {out:?}",
                u32::from(ch)
            );
            assert_eq!(text(&out.stdout), "");
            assert!(!text(&out.stderr).contains(ch));
        }
    }
}

/// A visible non-ASCII path is still accepted and printed as it is (the core change must not
/// over-refuse: #47 accepts any canonical absolute path).
#[test]
fn visible_non_ascii_paths_are_still_accepted() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = VALID
        .replace("/srv/wl/hot", "/srv/wl/hét/録画")
        .replace("/srv/wl/archive", "/srv/wl/архив/אב");
    let out = check_with(&write(&dir, "ok.toml", cfg.as_bytes()), false);
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    let stdout = text(&out.stdout);
    assert!(stdout.contains("/srv/wl/hét/録画"), "{stdout}");
    assert!(stdout.contains("/srv/wl/архив/אב"), "{stdout}");
}

/// The argv pre-scan only picks the format: a `--log-format=json` that is really a positional (or
/// one of two conflicting formats) gives a fixed line and never echoes argv, in either format.
#[test]
fn json_prescan_spoofing_only_changes_the_format_never_the_content() {
    for args in [
        &["vault", "rm", "--", "--log-format=json", SENTINEL][..],
        &["vault", "rm", "--", "--log-format", "json", SENTINEL][..],
        &["--log-format=text", "--log-format=json", "config", "check"][..],
        &["--config", "--log-format", "json", "config", "check"][..],
        &["config", "check", SENTINEL, "--log-format", "json"][..],
        &["vault", "scan", "--remote", SENTINEL, "--log-format=json"][..],
    ] {
        let mut c = base();
        c.args(args);
        let out = run(c);
        assert_eq!(out.status.code(), Some(2), "{args:?}: {out:?}");
        assert_eq!(text(&out.stdout), "", "{args:?}");
        assert!(!text(&out.stderr).contains(SENTINEL), "{args:?}: {out:?}");
        assert_eq!(text(&out.stderr).lines().count(), 1, "{args:?}: {out:?}");
        assert_all_json(&out.stderr);
    }
}

/// A `RUST_LOG` that is syntactically a filter but whose field regex is refused falls back with the
/// one warning (JSON under json) and never echoes the directive.
#[test]
fn a_refused_rust_log_regex_falls_back_without_echo() {
    let dir = tempfile::tempdir().unwrap();
    let good = write(&dir, "good.toml", VALID.as_bytes());
    for rl in [
        format!("[{{x=((a{{100}}){{100}}){{100}}{SENTINEL}}}]=trace"),
        format!("{SENTINEL}[{{x=\\p{{L}}{{50}}\\w{{50}}}}]=trace"),
        format!("[{{x={SENTINEL}}}]=trace"),
    ] {
        let mut c = base();
        c.env("RUST_LOG", &rl)
            .args(["--log-format", "json", "config", "check", "--config"])
            .arg(&good);
        let out = run(c);
        assert_eq!(out.status.code(), Some(0), "{out:?}");
        assert!(!text(&out.stderr).contains(SENTINEL), "{out:?}");
        assert!(!text(&out.stdout).contains(SENTINEL), "{out:?}");
        assert!(!text(&out.stdout).contains("level"), "logs on stdout");
        assert_all_json(&out.stderr);
    }
}

/// `--config` and `--log-format` are refused for every vault subcommand, wherever on argv they
/// appear, before the vault touches stdin or the home directory (exit 2, nothing on stdout).
#[test]
fn every_vault_subcommand_refuses_the_service_flags_before_doing_anything() {
    let home = tempfile::tempdir().unwrap();
    let subs: [&[&str]; 9] = [
        &["vault", "init"],
        &["vault", "list"],
        &["vault", "rm", "cam:x:host"],
        &["vault", "get", "cam:x:host"],
        &["vault", "set", "cam:x:host", "--kind", "host"],
        &["vault", "check-key"],
        &["vault", "key", "export"],
        &["vault", "rekey"],
        &["vault", "scan", "--staged"],
    ];
    for sub in subs {
        for flag in [["--config", "/srv/x.toml"], ["--log-format", "text"]] {
            let mut c = base();
            c.env("HOME", home.path()).args(sub).args(flag);
            let out = run(c);
            assert_eq!(out.status.code(), Some(2), "{sub:?} {flag:?}: {out:?}");
            assert_eq!(text(&out.stdout), "", "{sub:?}");
            assert!(
                text(&out.stderr).contains("do not apply to the vault"),
                "{sub:?} {flag:?}: {out:?}"
            );
        }
    }
    // Nothing was created under the temporary home.
    assert_eq!(std::fs::read_dir(home.path()).unwrap().count(), 0);
}
