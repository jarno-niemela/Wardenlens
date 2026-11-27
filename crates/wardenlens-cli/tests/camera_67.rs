//! #67: `wardenlens camera ...` through the real binary. The paths that need a camera are tested
//! in `commands::camera::tests` against a loopback fake; here are the checks that must hold for
//! the process as a user runs it: no password on argv, refusal of this machine's own addresses
//! and the metadata address before any connection, and no side effects of the read-only commands.
//!
//! Nothing here sends multicast or reads `~/.config`: the environment is cleared, every path is
//! under a temporary directory and `discover` is only run with an argument it refuses.

#![expect(
    clippy::unwrap_used,
    reason = "integration-test helpers outside #[test] fns; clippy.toml in-tests allowances do not reach them"
)]

use std::fs;
use std::io::Write;
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

use tempfile::TempDir;

struct Site {
    dir: TempDir,
}

impl Site {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        for d in [".", "state", "keys"] {
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

    fn state_files(&self) -> Vec<String> {
        fs::read_dir(self.dir.path().join("state"))
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect()
    }

    fn run(&self, args: &[&str], stdin: &str) -> Output {
        let mut child = Command::new(env!("CARGO_BIN_EXE_wardenlens"))
            .env_clear()
            .arg("--config")
            .arg(self.config())
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        // The child may exit before it reads: a broken pipe here is not a failure.
        let _ = child.stdin.take().unwrap().write_all(stdin.as_bytes());
        child.wait_with_output().unwrap()
    }
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

const ADD: [&str; 10] = [
    "camera",
    "add",
    "--id",
    "cam-a",
    "--model",
    "reolink/rlc-520a",
    "--username",
    "synthetic-user",
    "--host",
    "HOST",
];

fn add_for(host: &str, extra: &[&str]) -> Vec<String> {
    let mut v: Vec<String> = ADD.iter().map(|s| (*s).to_owned()).collect();
    if let Some(last) = v.last_mut() {
        host.clone_into(last);
    }
    v.extend(extra.iter().map(|s| (*s).to_owned()));
    v
}

fn run_add(site: &Site, host: &str, extra: &[&str], stdin: &str) -> Output {
    let args = add_for(host, extra);
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    site.run(&refs, stdin)
}

#[test]
fn a_password_on_the_command_line_is_a_usage_error_that_does_not_echo_it() {
    let site = Site::new();
    let out = run_add(
        &site,
        "192.0.2.10",
        &["--password", "hunter2-sentinel"],
        "x\n",
    );
    assert_eq!(out.status.code(), Some(2));
    let all = format!("{}{}", text(&out.stdout), text(&out.stderr));
    assert!(!all.contains("hunter2-sentinel"), "{all}");
    assert_eq!(site.state_files().len(), 0);
}

/// This machine's own addresses and the metadata address are refused with exit 1 before a
/// connection is made and before the password is read; nothing is created.
#[test]
fn own_and_metadata_addresses_are_refused_by_the_binary() {
    let site = Site::new();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port().to_string();
    for host in [
        "127.0.0.1",
        "127.0.0.2",
        "::1",
        "0.0.0.0",
        "169.254.169.254",
    ] {
        let out = run_add(&site, host, &["--onvif-port", &port], "synthetic-pw\n");
        assert_eq!(out.status.code(), Some(1), "{host}: {}", text(&out.stderr));
        let err = text(&out.stderr);
        assert!(err.contains("host refused"), "{host}: {err}");
        assert!(!err.contains("synthetic-pw"));
    }
    assert!(
        listener.accept().is_err(),
        "the refused host was connected to"
    );
    assert_eq!(site.state_files().len(), 0);
}

#[test]
fn list_and_remove_on_an_empty_site_change_nothing() {
    let site = Site::new();
    let out = site.run(&["camera", "list"], "");
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(text(&out.stdout), "no cameras are registered\n");
    let out = site.run(&["camera", "remove", "nobody"], "");
    assert_eq!(out.status.code(), Some(1), "{}", text(&out.stderr));
    assert!(text(&out.stderr).contains("no camera with that id"));
    assert_eq!(site.state_files().len(), 0);
}

/// `discover` refuses a timeout it cannot use without sending anything.
#[test]
fn discover_refuses_a_zero_timeout_before_probing() {
    let site = Site::new();
    for t in ["0", "0s", "abc", "-1s"] {
        let out = site.run(&["camera", "discover", "--timeout", t], "");
        assert_eq!(out.status.code(), Some(2), "{t}");
    }
}
