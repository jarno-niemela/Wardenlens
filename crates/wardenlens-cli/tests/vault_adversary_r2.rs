//! Adversarial end-to-end checks of the real binary (#94 verification, round 2). Temporary HOME,
//! cleared environment, synthetic values only.

#![expect(
    clippy::unwrap_used,
    reason = "integration-test helpers outside #[test] fns"
)]

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Output, Stdio};

use tempfile::TempDir;

const MARK: &str = "zq-synthetic-mark-5531";

fn home() -> TempDir {
    let d = tempfile::tempdir().unwrap();
    std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    d
}

fn run(h: &TempDir, args: &[&str], stdin: &[u8]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_wardenlens"))
        .env_clear()
        .env("HOME", h.path())
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // The command may stop reading early (an oversized value): a broken pipe here is expected.
    let _ = child.stdin.take().unwrap().write_all(stdin);
    child.wait_with_output().unwrap()
}

#[test]
fn a_value_typed_where_a_subcommand_goes_is_never_echoed() {
    let h = home();
    for args in [&["vault", MARK][..], &[MARK], &["vault", "key", MARK]] {
        let out = run(&h, args, b"");
        assert!(!out.status.success(), "{args:?}");
        let all = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(!all.contains(MARK), "{args:?} echoed argv: {all}");
    }
}

#[test]
fn a_piped_credential_round_trips_through_the_real_stdin() {
    let h = home();
    assert!(run(&h, &["vault", "init"], b"").status.success());
    let set = run(
        &h,
        &["vault", "set", "cam:a:credential", "--kind", "credential"],
        b"svc-reader\r\npw-synthetic-9\r\n\r\n",
    );
    assert!(
        set.status.success(),
        "{}",
        String::from_utf8_lossy(&set.stderr)
    );
    let get = run(
        &h,
        &["vault", "get", "cam:a:credential", "--field", "password"],
        b"",
    );
    assert_eq!(get.stdout, b"pw-synthetic-9");
    let third = run(
        &h,
        &["vault", "set", "cam:b:credential", "--kind", "credential"],
        format!("svc\npw\n{MARK}\n").as_bytes(),
    );
    assert_eq!(third.status.code(), Some(1));
    assert!(!String::from_utf8_lossy(&third.stderr).contains(MARK));
}

#[test]
fn an_oversized_real_stdin_is_refused_without_echo() {
    let h = home();
    assert!(run(&h, &["vault", "init"], b"").status.success());
    let mut big = MARK.repeat(20_000).into_bytes();
    big.push(b'\n');
    let out = run(&h, &["vault", "set", "cam:a:note", "--kind", "other"], &big);
    assert_eq!(out.status.code(), Some(1));
    assert!(!String::from_utf8_lossy(&out.stderr).contains(MARK));
    assert_eq!(out.stdout, b"");
}
