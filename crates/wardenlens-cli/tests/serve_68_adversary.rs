//! Adversarial tests of `wardenlens serve` through the real binary (PR #198 verification).
//! Synthetic temporary sites only; the environment is cleared.

#![expect(
    clippy::unwrap_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    reason = "integration-test helpers; a panic is a failure; small synthetic durations"
)]

use std::fs;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

use rustix::process::{Pid, Signal, kill_process};
use tempfile::TempDir;

fn free_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}

fn private_dir(p: &Path) {
    fs::create_dir_all(p).unwrap();
    fs::set_permissions(p, fs::Permissions::from_mode(0o700)).unwrap();
}

/// One config (its own state directory and key) over hot and archive roots that may be shared.
struct Site {
    dir: TempDir,
    port: u16,
}

impl Site {
    fn new(hot: &Path, archive: &Path) -> Self {
        let dir = tempfile::tempdir().unwrap();
        for d in [".", "state", "keys"] {
            private_dir(&dir.path().join(d));
        }
        let port = free_port();
        let site = Self { dir, port };
        let text = format!(
            "[api]\nlisten = \"127.0.0.1:{port}\"\n[storage]\nhot_root = \"{h}\"\n\
             archive_root = \"{a}\"\n[database]\npath = \"{t}/state/index.db\"\n\
             [secrets]\nkey_file = \"{t}/keys/secrets.key\"\n",
            h = hot.display(),
            a = archive.display(),
            t = site.dir.path().display()
        );
        let p = site.config();
        fs::write(&p, text).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(site.run(&["secrets", "init"]).status.success());
        site
    }

    fn config(&self) -> PathBuf {
        self.dir.path().join("wardenlens.toml")
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_wardenlens"));
        c.env_clear().arg("--config").arg(self.config()).args(args);
        c
    }

    fn run(&self, args: &[&str]) -> Output {
        self.command(args).stdin(Stdio::null()).output().unwrap()
    }

    fn serve(&self) -> Child {
        self.command(&["serve"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap()
    }

    fn http(&self, path: &str, token: Option<&str>) -> Option<(u16, String)> {
        let mut s = TcpStream::connect(("127.0.0.1", self.port)).ok()?;
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let auth = token.map_or_else(String::new, |t| format!("Authorization: Bearer {t}\r\n"));
        write!(
            s,
            "GET {path} HTTP/1.1\r\nHost: x\r\n{auth}Connection: close\r\n\r\n"
        )
        .ok()?;
        let mut text = String::new();
        s.read_to_string(&mut text).ok()?;
        let status = text.split(' ').nth(1)?.parse().ok()?;
        let body = text
            .split_once("\r\n\r\n")
            .map_or(String::new(), |(_, b)| b.to_owned());
        Some((status, body))
    }

    fn wait_up(&self, child: &mut Child) {
        let end = Instant::now() + Duration::from_secs(20);
        while Instant::now() < end {
            if let Some(st) = child.try_wait().unwrap() {
                let mut e = String::new();
                child.stderr.take().unwrap().read_to_string(&mut e).unwrap();
                panic!("serve exited early ({st}): {e}");
            }
            if self
                .http("/api/v1/health", None)
                .is_some_and(|(s, _)| s == 200)
            {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!("the API did not come up");
    }
}

fn wait_exit(child: &mut Child, within: Duration) -> i32 {
    let at = Instant::now();
    while at.elapsed() < within {
        if let Some(st) = child.try_wait().unwrap() {
            return st.code().unwrap_or(-1);
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    child.kill().unwrap();
    panic!("serve did not exit within {within:?}");
}

fn stop(child: &mut Child) -> i32 {
    let pid = Pid::from_raw(i32::try_from(child.id()).unwrap()).unwrap();
    kill_process(pid, Signal::TERM).unwrap();
    wait_exit(child, Duration::from_secs(15))
}

fn volumes() -> (TempDir, PathBuf, PathBuf) {
    let v = tempfile::tempdir().unwrap();
    let hot = v.path().join("hot");
    private_dir(&hot);
    let archive = v.path().join("no-archive");
    (v, hot, archive)
}

/// `token create` runs alongside a live `serve` (it does not take the process lock), and the new
/// token is accepted by the running service at once.
#[test]
fn a_token_created_while_serve_runs_is_accepted_by_it() {
    let (_v, hot, archive) = volumes();
    let site = Site::new(&hot, &archive);
    let mut serve = site.serve();
    site.wait_up(&mut serve);
    let out = site.run(&["token", "create", "--name", "late"]);
    assert!(
        out.status.success(),
        "token create failed beside serve: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let token = String::from_utf8(out.stdout).unwrap().trim().to_owned();
    let (status, body) = site.http("/api/v1/storage", Some(&token)).unwrap();
    assert_eq!(status, 200, "{body}");
    assert_eq!(stop(&mut serve), 0);
}

/// Two `serve` processes with their own index (two configs) over one hot root would run two
/// storage loops and two start-up reconciliations on the same files; ADR 0005 section 7 says only
/// one storage loop may move or delete. The second must be refused.
#[test]
fn a_second_serve_over_the_same_hot_root_is_refused() {
    let (_v, hot, archive) = volumes();
    let a = Site::new(&hot, &archive);
    let b = Site::new(&hot, &archive);
    let mut first = a.serve();
    a.wait_up(&mut first);
    let mut second = b.serve();
    let refused = {
        let end = Instant::now() + Duration::from_secs(10);
        let mut code = None;
        while Instant::now() < end {
            if let Some(st) = second.try_wait().unwrap() {
                code = st.code();
                break;
            }
            if b.http("/api/v1/health", None).is_some() {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        code
    };
    if refused.is_none() {
        let _ = stop(&mut second);
    }
    let _ = second.wait();
    assert_eq!(stop(&mut first), 0);
    assert_eq!(
        refused,
        Some(2),
        "a second instance on the same hot root started"
    );
}

/// A state directory others can write to is refused (exit 2) before anything is created in it:
/// the process lock file must not be planted ahead of the index's parent-directory check.
#[test]
fn a_world_writable_state_directory_is_refused_without_creating_files_in_it() {
    let (_v, hot, archive) = volumes();
    let site = Site::new(&hot, &archive);
    let state = site.dir.path().join("state");
    fs::set_permissions(&state, fs::Permissions::from_mode(0o777)).unwrap();
    let out = site.run(&["serve"]);
    let err = String::from_utf8_lossy(&out.stderr).into_owned();
    assert_eq!(out.status.code(), Some(2), "{err}");
    let left: Vec<_> = fs::read_dir(&state)
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(
        left.is_empty(),
        "files created in the refused directory: {left:?}; {err}"
    );
}

/// A missing state directory is reported as the index problem it is, not as a lock problem.
#[test]
fn a_missing_state_directory_names_the_index() {
    let (_v, hot, archive) = volumes();
    let site = Site::new(&hot, &archive);
    fs::remove_dir(site.dir.path().join("state")).unwrap();
    let out = site.run(&["serve"]);
    let err = String::from_utf8_lossy(&out.stderr).into_owned();
    assert_eq!(out.status.code(), Some(2), "{err}");
    assert!(err.contains("index"), "{err}");
}

/// A second SIGTERM while shutting down, and a SIGINT, do not change the clean exit.
#[test]
fn repeated_signals_still_exit_zero() {
    let (_v, hot, archive) = volumes();
    let site = Site::new(&hot, &archive);
    let mut serve = site.serve();
    site.wait_up(&mut serve);
    let pid = Pid::from_raw(i32::try_from(serve.id()).unwrap()).unwrap();
    for s in [Signal::TERM, Signal::TERM, Signal::INT] {
        let _ = kill_process(pid, s);
    }
    assert_eq!(wait_exit(&mut serve, Duration::from_secs(12)), 0);
}
