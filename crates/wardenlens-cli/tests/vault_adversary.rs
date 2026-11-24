//! Adversarial end-to-end checks of the real binary (#94 verification). Temporary HOME,
//! cleared environment, synthetic values only.

#![expect(
    clippy::unwrap_used,
    reason = "integration-test helpers outside #[test] fns"
)]

use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use tempfile::TempDir;

fn home() -> TempDir {
    let d = tempfile::tempdir().unwrap();
    std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    d
}

fn wardenlens(home: &TempDir) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_wardenlens"));
    c.env_clear().env("HOME", home.path());
    c
}

#[test]
fn an_error_line_does_not_repeat_its_cause() {
    let h = home();
    let target = h.path().join("real.key");
    std::fs::write(&target, [0u8; 32]).unwrap();
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();
    let link = h.path().join("link.key");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    let out = wardenlens(&h)
        .args(["vault", "check-key"])
        .arg(&link)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let err = String::from_utf8(out.stderr).unwrap();
    assert_eq!(err.matches("symbolic link").count(), 1, "{err}");
}

#[test]
fn import_legacy_does_not_hang_on_a_fifo() {
    let h = home();
    assert!(
        wardenlens(&h)
            .args(["vault", "init"])
            .stdin(Stdio::null())
            .output()
            .unwrap()
            .status
            .success()
    );
    let fifo = h.path().join("secret.json");
    assert!(
        Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success()
    );
    let mut child = wardenlens(&h)
        .args(["vault", "import-legacy", "--secret-json"])
        .arg(&fifo)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let start = Instant::now();
    let mut done = None;
    while start.elapsed() < Duration::from_secs(5) {
        if let Some(s) = child.try_wait().unwrap() {
            done = Some(s);
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    if done.is_none() {
        child.kill().unwrap();
    }
    let status = child.wait().unwrap();
    assert!(done.is_some(), "import-legacy blocked on a FIFO for 5 s");
    assert!(!status.success());
}

#[test]
fn clap_errors_do_not_echo_a_value_put_on_argv_by_mistake() {
    let h = home();
    let out = wardenlens(&h)
        .args([
            "vault",
            "set",
            "cam:a:host",
            "--kind",
            "host",
            "zq-synthetic-mark-7781",
        ])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let err = String::from_utf8(out.stderr).unwrap();
    assert!(!err.contains("zq-synthetic-mark-7781"), "{err}");
}

#[test]
fn write_commands_on_a_missing_vault_exit_like_read_commands() {
    let h = home();
    let get = wardenlens(&h)
        .args(["vault", "list"])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let rm = wardenlens(&h)
        .args(["vault", "rm", "cam:a:host"])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(get.status.code(), rm.status.code());
}
