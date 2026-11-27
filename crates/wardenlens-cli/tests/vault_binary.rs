//! End-to-end tests of the real binary against a temporary HOME with synthetic values.
//! The environment is cleared first, so nothing of the real home is ever read.

#![expect(
    clippy::unwrap_used,
    reason = "integration-test helpers outside #[test] fns; clippy.toml in-tests allowances do not reach them"
)]

use std::io::Write;
use std::process::{Command, Output, Stdio};

use tempfile::TempDir;

fn home() -> TempDir {
    tempfile::tempdir().unwrap()
}

fn wardenlens(home: &TempDir) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_wardenlens"));
    c.env_clear().env("HOME", home.path());
    c
}

fn run_with_stdin(mut c: Command, stdin: &str) -> Output {
    let mut child = c
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // The child may exit before reading (a refusal); a broken pipe is then expected.
    let _ = child.stdin.take().unwrap().write_all(stdin.as_bytes());
    child.wait_with_output().unwrap()
}

fn vault(home: &TempDir, args: &[&str], stdin: &str) -> Output {
    let mut c = wardenlens(home);
    c.arg("vault").args(args);
    run_with_stdin(c, stdin)
}

#[test]
fn init_set_get_list_rm_over_pipes() {
    let h = home();
    assert!(vault(&h, &["init"], "").status.success());
    let set = vault(&h, &["set", "cam:a:host", "--kind", "host"], "192.0.2.50\n");
    assert!(
        set.status.success(),
        "{}",
        String::from_utf8_lossy(&set.stderr)
    );
    let get = vault(&h, &["get", "cam:a:host"], "");
    assert_eq!(get.stdout, b"192.0.2.50");
    let list = vault(&h, &["list"], "");
    let text = String::from_utf8(list.stdout).unwrap();
    assert!(text.contains("cam:a:host\thost\tscannable"), "{text}");
    assert!(!text.contains("192.0.2.50"));
    assert!(vault(&h, &["rm", "cam:a:host"], "").status.success());
    assert_eq!(vault(&h, &["get", "cam:a:host"], "").status.code(), Some(1));
}

#[test]
fn get_refuses_stdout_redirected_to_a_file() {
    let h = home();
    vault(&h, &["init"], "");
    vault(&h, &["set", "cam:a:host", "--kind", "host"], "192.0.2.50");
    let target = tempfile::tempfile().unwrap();
    let out = wardenlens(&h)
        .args(["vault", "get", "cam:a:host"])
        .stdout(Stdio::from(target.try_clone().unwrap()))
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(target.metadata().unwrap().len(), 0);
}

#[test]
fn a_value_on_argv_is_refused_by_the_parser() {
    let h = home();
    let out = vault(
        &h,
        &["set", "cam:a:host", "--kind", "host", "192.0.2.50"],
        "",
    );
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn terminal_only_commands_refuse_pipes() {
    let h = home();
    vault(&h, &["init"], "");
    let key = std::fs::read(h.path().join(".config/wardenlens/dev-vault.key")).unwrap();
    for args in [&["key", "export"][..], &["key", "import"], &["rekey"]] {
        let out = vault(&h, args, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n");
        assert_eq!(out.status.code(), Some(1), "{args:?}");
        assert_eq!(out.stdout, b"");
    }
    let after = std::fs::read(h.path().join(".config/wardenlens/dev-vault.key")).unwrap();
    assert_eq!(key, after);
}

#[test]
fn the_key_in_the_environment_is_refused() {
    let h = home();
    let mut c = wardenlens(&h);
    c.env("WARDENLENS_VAULT_KEY", "zq-not-a-real-key")
        .args(["vault", "list"]);
    let out = run_with_stdin(c, "");
    assert_eq!(out.status.code(), Some(1));
    let err = String::from_utf8(out.stderr).unwrap();
    assert!(err.contains("WARDENLENS_VAULT_KEY") && !err.contains("zq-not-a-real-key"));
}

#[test]
fn core_dumps_are_disabled_at_start() {
    let h = home();
    let mut c = wardenlens(&h);
    // `set` blocks reading stdin, which gives the test time to read the limits.
    let mut child = c
        .args(["vault", "set", "cam:a:note", "--kind", "other"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let path = format!("/proc/{}/limits", child.id());
    let mut line = String::new();
    for _ in 0..200 {
        let limits = std::fs::read_to_string(&path).unwrap_or_default();
        line = limits
            .lines()
            .find(|l| l.starts_with("Max core file size"))
            .unwrap_or("")
            .to_owned();
        if line.split_whitespace().skip(4).take(2).eq(["0", "0"]) {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
    drop(child.stdin.take());
    child.wait().unwrap();
    assert!(
        line.split_whitespace().skip(4).take(2).eq(["0", "0"]),
        "{line}"
    );
}

#[test]
fn an_error_prints_one_exact_line_with_its_cause_once() {
    let h = home();
    let out = vault(&h, &["list"], "");
    assert_eq!(out.status.code(), Some(2));
    let err = String::from_utf8(out.stderr).unwrap();
    assert_eq!(
        err,
        "error: the key file cannot be used: key file i/o failed during resolving directory: No such file or directory (os error 2)\n"
    );
}

#[test]
fn help_and_version_still_print() {
    let h = home();
    let help = vault(&h, &["set", "--help"], "");
    assert!(help.status.success());
    assert!(
        String::from_utf8(help.stdout)
            .unwrap()
            .contains("exactly two lines")
    );
}

fn assert_no_marker(out: &Output, marker: &str) {
    assert_eq!(out.status.code(), Some(2));
    let all = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!all.contains(marker), "{all}");
}

#[test]
fn clap_errors_never_echo_argv() {
    let h = home();
    let m = "zqmarker9x";
    for args in [
        vec![m],
        vec!["vault", m],
        vec!["vault", "key", m],
        vec!["vault", "get", "cam:a:host", "--field", m],
        vec!["vault", "set", "cam:a:host", "--kind", m],
        vec!["vault", "list", m],
        vec!["vault", "--zqmarker9x"],
    ] {
        let mut c = wardenlens(&h);
        c.args(&args);
        assert_no_marker(&run_with_stdin(c, ""), m);
    }
}

#[test]
fn one_line_credential_is_refused() {
    let h = home();
    vault(&h, &["init"], "");
    for input in ["svc-reader\n", "svc-reader\r\n", "svc-reader"] {
        let out = vault(&h, &["set", "cam:a:cred", "--kind", "credential"], input);
        assert_eq!(out.status.code(), Some(1), "{input:?}");
        assert!(!String::from_utf8_lossy(&out.stderr).contains("svc-reader"));
    }
}

#[test]
fn error_causes_are_not_doubled() {
    let h = home();
    vault(&h, &["init"], "");
    let out = vault(&h, &["set", "BAD_ID", "--kind", "host"], "x\n");
    let err = String::from_utf8(out.stderr).unwrap();
    assert_eq!(err.lines().count(), 1, "{err}");
    let line = err.trim_end();
    let tail = line.strip_prefix("error: ").unwrap();
    // The cause text must not appear twice.
    for part in tail.split(": ") {
        assert_eq!(tail.matches(part).count(), 1, "{line}");
    }
}

#[test]
fn redact_filters_a_pipe_and_fails_closed_without_a_vault() {
    let h = home();
    // No vault yet: nothing is copied, exit 2.
    let out = vault(&h, &["redact"], "leak 192.0.2.50 here");
    assert_eq!(out.status.code(), Some(2));
    assert!(out.stdout.is_empty(), "nothing may be written");
    vault(&h, &["init"], "");
    vault(&h, &["set", "cam:a:host", "--kind", "host"], "192.0.2.50");
    let out = vault(&h, &["redact"], "leak 192.0.2.50 here\n");
    assert!(out.status.success());
    assert_eq!(out.stdout, b"leak [REDACTED] here\n");
}
