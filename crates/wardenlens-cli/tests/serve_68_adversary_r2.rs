//! Adversarial tests of `wardenlens serve` through the real binary, PR #198 round 2: the lock in
//! the hot root. Synthetic temporary sites only; the environment is cleared.

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

const HOT_LOCK: &str = ".wardenlens.lock";

/// The same hot root reached through another path (a symlink alias) is still one hot root: `flock`
/// is per file, not per path string.
#[test]
fn a_second_serve_over_the_same_hot_root_through_a_symlinked_path_is_refused() {
    let (v, hot, archive) = volumes();
    // The last component is opened `O_NOFOLLOW`, so alias a parent directory instead.
    let parent_alias = v.path().join("alias");
    std::os::unix::fs::symlink(v.path(), &parent_alias).unwrap();
    let alias = parent_alias.join("hot");
    let a = Site::new(&hot, &archive);
    let b = Site::new(&alias, &archive);
    let mut first = a.serve();
    a.wait_up(&mut first);
    let out = b.run(&["serve"]);
    assert_eq!(stop(&mut first), 0);
    // The alias itself is usable: alone, it starts.
    let mut alone = b.serve();
    b.wait_up(&mut alone);
    assert_eq!(stop(&mut alone), 0);
    assert_eq!(
        out.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// The lock file is created `0600`, survives a clean stop and a crash (SIGKILL), and the next
/// `serve` starts over it either way.
#[test]
fn the_lock_file_is_private_and_a_restart_after_stop_or_crash_starts() {
    let (_v, hot, archive) = volumes();
    let site = Site::new(&hot, &archive);
    let mut s = site.serve();
    site.wait_up(&mut s);
    let meta = fs::symlink_metadata(hot.join(HOT_LOCK)).unwrap();
    assert!(meta.file_type().is_file());
    assert_eq!(meta.permissions().mode() & 0o777, 0o600);
    assert_eq!(stop(&mut s), 0);

    let mut s = site.serve();
    site.wait_up(&mut s);
    s.kill().unwrap();
    s.wait().unwrap();

    let mut s = site.serve();
    site.wait_up(&mut s);
    assert_eq!(stop(&mut s), 0);
}

/// A FIFO, a directory or a dangling symlink planted at the lock name refuses the start (exit 2)
/// promptly: no hang on the FIFO, nothing followed, and the object is left as it was.
#[test]
fn a_non_regular_object_at_the_lock_name_is_refused_without_hanging() {
    for kind in ["fifo", "dir", "symlink"] {
        let (v, hot, archive) = volumes();
        let p = hot.join(HOT_LOCK);
        let target = v.path().join("elsewhere");
        match kind {
            "fifo" => rustix::fs::mknodat(
                rustix::fs::CWD,
                &p,
                rustix::fs::FileType::Fifo,
                rustix::fs::Mode::from_raw_mode(0o600),
                0,
            )
            .unwrap(),
            "dir" => private_dir(&p),
            _ => std::os::unix::fs::symlink(&target, &p).unwrap(),
        }
        let site = Site::new(&hot, &archive);
        let mut child = site.serve();
        let code = wait_exit(&mut child, Duration::from_secs(10));
        let mut err = String::new();
        child
            .stderr
            .take()
            .unwrap()
            .read_to_string(&mut err)
            .unwrap();
        assert_eq!(code, 2, "{kind}: {err}");
        assert!(err.contains("lock"), "{kind}: {err}");
        assert!(!target.exists(), "{kind}: the symlink was followed");
        let ft = fs::symlink_metadata(&p).unwrap().file_type();
        let same = match kind {
            "fifo" => std::os::unix::fs::FileTypeExt::is_fifo(&ft),
            "dir" => ft.is_dir(),
            _ => ft.is_symlink(),
        };
        assert!(same, "{kind}: the planted object was replaced");
    }
}
