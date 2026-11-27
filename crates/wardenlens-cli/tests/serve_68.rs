//! #68: `wardenlens serve` through the real binary. Synthetic temporary site only; the
//! environment is cleared, so nothing of the user's `~/.config`, `~/.local/share`,
//! `/etc/wardenlens` or vault is read. No camera is registered: the camera path (fake sources,
//! both tiers, shutdown flush, the accept loop's limits) is covered by the in-crate end-to-end
//! tests of `wiring`.

#![expect(
    clippy::unwrap_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    reason = "integration-test helpers outside #[test] fns; a panic is a failure; small synthetic durations"
)]

use std::fs;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

use rustix::process::{Pid, Signal, kill_process};
use tempfile::TempDir;

struct Site {
    dir: TempDir,
    port: u16,
}

impl Site {
    /// A site whose hot root exists and whose archive root does not.
    fn new() -> Self {
        let port = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };
        let dir = tempfile::tempdir().unwrap();
        for d in [".", "state", "keys", "hot"] {
            let p = dir.path().join(d);
            fs::create_dir_all(&p).unwrap();
            fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let site = Self { dir, port };
        site.write_config(&format!(
            "[api]\nlisten = \"127.0.0.1:{port}\"\n[storage]\nhot_root = \"{t}/hot\"\n\
             archive_root = \"{t}/no-such-archive\"\n[database]\npath = \"{t}/state/index.db\"\n\
             [secrets]\nkey_file = \"{t}/keys/secrets.key\"\n",
            t = site.dir.path().display()
        ));
        site
    }

    fn write_config(&self, text: &str) {
        let p = self.config();
        fs::write(&p, text).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
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

    /// Waits until the API answers `health`.
    fn wait_up(&self, child: &mut Child) {
        let end = Instant::now() + Duration::from_secs(20);
        while Instant::now() < end {
            assert!(child.try_wait().unwrap().is_none(), "serve exited early");
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

fn wait_exit(child: &mut Child, within: Duration) -> (i32, Duration) {
    let at = Instant::now();
    while at.elapsed() < within {
        if let Some(st) = child.try_wait().unwrap() {
            return (st.code().unwrap_or(-1), at.elapsed());
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    child.kill().unwrap();
    panic!("serve did not exit within {within:?}");
}

fn signal(child: &Child, sig: Signal) {
    let pid = Pid::from_raw(i32::try_from(child.id()).unwrap()).unwrap();
    kill_process(pid, sig).unwrap();
}

fn stderr_of(mut child: Child) -> String {
    let mut s = String::new();
    child.stderr.take().unwrap().read_to_string(&mut s).unwrap();
    s
}

#[test]
fn a_missing_key_file_refuses_to_start_and_names_the_remedy() {
    let site = Site::new();
    let out = site.run(&["serve"]);
    assert_eq!(out.status.code(), Some(2));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("secrets init"), "{err}");
}

#[test]
fn an_invalid_config_is_exit_1_and_a_missing_hot_root_is_exit_2() {
    let site = Site::new();
    assert!(site.run(&["secrets", "init"]).status.success());
    fs::remove_dir(site.dir.path().join("hot")).unwrap();
    let out = site.run(&["serve"]);
    assert_eq!(
        out.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stderr).contains("hot root"));
    site.write_config("[api]\nlisten = \"0.0.0.0:1\"\n");
    assert_eq!(site.run(&["serve"]).status.code(), Some(1));
}

/// Start-up with a missing archive succeeds in `archive_unavailable` mode, the API answers, a
/// second instance is refused while the first runs, and SIGTERM and SIGINT both stop the service
/// with exit 0 well inside 10 s.
#[test]
fn it_serves_in_archive_unavailable_mode_refuses_a_second_instance_and_stops_on_signals() {
    let site = Site::new();
    assert!(site.run(&["secrets", "init"]).status.success());
    let token = String::from_utf8(site.run(&["token", "create", "--name", "t"]).stdout).unwrap();
    let token = token.trim().to_owned();

    for sig in [Signal::TERM, Signal::INT] {
        let mut first = site.serve();
        site.wait_up(&mut first);
        let (status, body) = site.http("/api/v1/storage", Some(&token)).unwrap();
        assert_eq!(status, 200, "{body}");
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(json["archive"]["state"], "unavailable");
        assert_eq!(json["archive"]["unavailable_cause"], "missing");
        assert!(
            json["hot"]["total_bytes"].is_u64(),
            "the hot volume is measured"
        );

        // A second instance does not start while the first holds the index.
        let mut second = site.serve();
        let (code, _) = wait_exit(&mut second, Duration::from_secs(30));
        let err = stderr_of(second);
        assert_eq!(code, 2, "{err}");
        assert!(
            err.contains("another wardenlens instance is running"),
            "{err}"
        );

        signal(&first, sig);
        let (code, took) = wait_exit(&mut first, Duration::from_secs(10));
        assert_eq!(code, 0, "{}", stderr_of(first));
        assert!(took < Duration::from_secs(10), "{took:?}");
    }
}

/// One start-up refusal per cause, each exit 2 and each naming its cause without a path.
#[test]
fn every_startup_refusal_is_exit_2_and_names_its_cause() {
    // The API address is taken.
    let site = Site::new();
    assert!(site.run(&["secrets", "init"]).status.success());
    let taken = std::net::TcpListener::bind(("127.0.0.1", site.port)).unwrap();
    let out = site.run(&["serve"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("API address cannot be bound"));
    drop(taken);

    // The key file is readable by others.
    let key = site.dir.path().join("keys/secrets.key");
    fs::set_permissions(&key, fs::Permissions::from_mode(0o644)).unwrap();
    let out = site.run(&["serve"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("key file cannot be used"));
    fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();

    // The index path is a directory.
    let db = site.dir.path().join("state/index.db");
    if db.exists() {
        fs::remove_file(&db).unwrap();
    }
    fs::create_dir(&db).unwrap();
    let out = site.run(&["serve"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("index cannot be opened"));
    fs::remove_dir(&db).unwrap();

    // The lock file is a symlink (an earlier run left a regular one: replace it).
    let lock = site.dir.path().join("state/wardenlens.lock");
    fs::remove_file(&lock).unwrap();
    std::os::unix::fs::symlink("/dev/null", &lock).unwrap();
    let out = site.run(&["serve"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("process lock cannot be taken"));
}
