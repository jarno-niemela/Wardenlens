//! #69 adversary: `wardenlens health` through the real binary, against hostile loopback servers
//! and against a real `serve`. Synthetic temporary configs only; the environment is cleared.

#![expect(
    clippy::unwrap_used,
    reason = "integration-test helpers outside #[test] fns; a panic is a failure"
)]

use std::fs;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use tempfile::TempDir;

/// A backstop against a hang, not a check of the 3 s probe deadline (the exit status and
/// message assertions catch a probe that gave up wrongly). Far above host load plus a process
/// spawn (TEST-5).
const BOUND: Duration = Duration::from_secs(30);

struct Cfg {
    dir: TempDir,
}

impl Cfg {
    fn new(listen: &str, allow_unspecified: bool) -> Self {
        let dir = tempfile::tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        for d in ["state", "keys", "hot"] {
            let p = dir.path().join(d);
            fs::create_dir_all(&p).unwrap();
            fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let flag = if allow_unspecified {
            "allow_unspecified_bind = true\n"
        } else {
            ""
        };
        let text = format!(
            "[api]\nlisten = \"{listen}\"\n{flag}[storage]\nhot_root = \"{t}/hot\"\n\
             archive_root = \"{t}/no-such-archive\"\n[database]\npath = \"{t}/state/index.db\"\n\
             [secrets]\nkey_file = \"{t}/keys/secrets.key\"\n",
            t = dir.path().display()
        );
        let p = dir.path().join("wardenlens.toml");
        fs::write(&p, text).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
        Self { dir }
    }

    fn path(&self) -> PathBuf {
        self.dir.path().join("wardenlens.toml")
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_wardenlens"));
        c.env_clear().arg("--config").arg(self.path()).args(args);
        c
    }

    fn health(&self) -> (Output, Duration) {
        let started = Instant::now();
        let out = self
            .command(&["health"])
            .stdin(Stdio::null())
            .output()
            .unwrap();
        (out, started.elapsed())
    }
}

/// A loopback server that, for the first connection, reads the request head, then runs
/// `respond` on the stream. The thread ends when `respond` returns or the peer goes away.
fn server<F>(respond: F) -> SocketAddr
where
    F: FnOnce(&mut TcpStream) + Send + 'static,
{
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    thread::spawn(move || {
        let (mut s, _) = l.accept().unwrap();
        let mut head = Vec::new();
        let mut b = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            match s.read(&mut b) {
                Ok(1) => head.push(b[0]),
                _ => return,
            }
        }
        respond(&mut s);
    });
    addr
}

#[test]
fn an_endless_chunked_200_body_is_healthy_and_never_read() {
    let addr = server(|s| {
        let _ = s.write_all(
            b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\ncontent-type: application/json\r\n\r\n",
        );
        let chunk = [b'x'; 4096];
        loop {
            if s.write_all(b"1000\r\n").is_err()
                || s.write_all(&chunk).is_err()
                || s.write_all(b"\r\n").is_err()
            {
                return;
            }
        }
    });
    let (out, took) = Cfg::new(&addr.to_string(), false).health();
    assert!(out.status.success(), "{out:?}");
    assert!(took < BOUND, "{took:?}");
}

#[test]
fn a_200_with_a_huge_content_length_and_no_body_is_healthy_at_once() {
    let (hold_tx, hold_rx) = mpsc::channel::<()>();
    let addr = server(move |s| {
        let _ = s.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 1073741824\r\n\r\n");
        // Keep the socket open until the test ends: the probe must not wait for the body.
        let _ = hold_rx.recv();
    });
    let (out, took) = Cfg::new(&addr.to_string(), false).health();
    drop(hold_tx);
    assert!(out.status.success(), "{out:?}");
    assert!(
        // The probe is capped by its own 3 s deadline, and the status assertion above catches a
        // timeout; this bound is only a backstop against a hang, far above host load (TEST-5).
        took < Duration::from_secs(60),
        "waited for the body: {took:?}"
    );
}

#[test]
fn a_status_line_dripped_slower_than_the_deadline_is_bounded() {
    let (stop_tx, stop_rx) = mpsc::channel::<()>();
    let addr = server(move |s| {
        for b in b"HTTP/1.1 200 OK\r\n\r\n" {
            if s.write_all(&[*b]).is_err() {
                return;
            }
            // One byte per 500 ms: the whole line would take ~9 s.
            if stop_rx.recv_timeout(Duration::from_millis(500)).is_ok() {
                return;
            }
        }
    });
    let (out, took) = Cfg::new(&addr.to_string(), false).health();
    drop(stop_tx);
    assert!(!out.status.success(), "{out:?}");
    assert!(took < BOUND, "{took:?}");
}

#[test]
fn a_header_flood_is_unhealthy_and_bounded() {
    let addr = server(|s| {
        let _ = s.write_all(b"HTTP/1.1 200 OK\r\n");
        loop {
            if s.write_all(b"x-flood: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n")
                .is_err()
            {
                return;
            }
        }
    });
    let (out, took) = Cfg::new(&addr.to_string(), false).health();
    assert!(!out.status.success(), "{out:?}");
    assert!(took < BOUND, "{took:?}");
}

#[test]
fn a_peer_that_reads_the_request_and_closes_is_unhealthy() {
    let addr = server(|_s| {});
    let (out, took) = Cfg::new(&addr.to_string(), false).health();
    assert!(!out.status.success(), "{out:?}");
    assert!(took < BOUND, "{took:?}");
}

#[test]
fn a_200_on_an_unspecified_listen_is_probed_on_loopback_and_prints_nothing() {
    let addr = server(|s| {
        let _ = s.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\n{}");
    });
    let cfg = Cfg::new(&format!("0.0.0.0:{}", addr.port()), true);
    let (out, _) = cfg.health();
    assert!(out.status.success(), "{out:?}");
    assert!(out.stdout.is_empty(), "{out:?}");
    assert!(out.stderr.is_empty(), "{out:?}");
}

#[test]
fn an_http_1_0_200_is_healthy_and_a_101_is_not() {
    let addr = server(|s| {
        let _ = s.write_all(b"HTTP/1.0 200 OK\r\n\r\n");
    });
    let (out, _) = Cfg::new(&addr.to_string(), false).health();
    assert!(out.status.success(), "{out:?}");
    let addr = server(|s| {
        let _ = s.write_all(
            b"HTTP/1.1 101 Switching Protocols\r\nupgrade: websocket\r\nconnection: upgrade\r\n\r\n",
        );
    });
    let (out, _) = Cfg::new(&addr.to_string(), false).health();
    assert!(!out.status.success(), "{out:?}");
}

#[test]
fn health_needs_no_key_file_and_ignores_a_key_variable_value() {
    // The healthcheck runs inside the container without the entrypoint; it must not depend on the
    // key file, and must not echo anything key-like.
    let addr = server(|s| {
        let _ = s.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n");
    });
    let cfg = Cfg::new(&addr.to_string(), false);
    let out = cfg
        .command(&["health"])
        .env("WARDENLENS_VAULT_KEY_FILE", "/nonexistent/key")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
}

#[test]
fn health_against_a_real_serve_is_healthy_and_turns_unhealthy_after_sigterm() {
    let port = {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let cfg = Cfg::new(&format!("127.0.0.1:{port}"), false);
    let init = cfg.command(&["secrets", "init"]).output().unwrap();
    assert!(init.status.success(), "{init:?}");
    let mut child = cfg
        .command(&["serve"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    // Readiness: wait until the port accepts (bounded), not a fixed sleep.
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut healthy = false;
    while Instant::now() < deadline {
        if let Some(st) = child.try_wait().unwrap() {
            panic!("serve exited early: {st:?}");
        }
        let (out, _) = cfg.health();
        if out.status.success() {
            assert!(out.stdout.is_empty() && out.stderr.is_empty(), "{out:?}");
            healthy = true;
            break;
        }
        thread::sleep(Duration::from_millis(100));
    }
    let pid = rustix::process::Pid::from_child(&child);
    rustix::process::kill_process(pid, rustix::process::Signal::TERM).unwrap();
    let st = child.wait().unwrap();
    assert!(healthy, "serve never became healthy");
    assert!(
        st.success(),
        "serve did not exit cleanly on SIGTERM: {st:?}"
    );
    let (out, took) = cfg.health();
    assert!(!out.status.success(), "{out:?}");
    assert!(took < BOUND, "{took:?}");
}

/// A pseudo-terminal: `rekey` needs a terminal on stdout. The slave end becomes the child's stdout
/// and the master is kept open until the child is done. The master is not read: the child writes
/// a few hundred bytes at most, far below the pty buffer, so it never blocks on a full buffer.
fn pty() -> (std::fs::File, std::fs::File) {
    use rustix::pty::{OpenptFlags, grantpt, openpt, ptsname, unlockpt};
    let master = openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY).unwrap();
    grantpt(&master).unwrap();
    unlockpt(&master).unwrap();
    let name = ptsname(&master, Vec::new()).unwrap();
    let slave = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(std::ffi::OsStr::from_bytes(name.to_bytes()))
        .unwrap();
    (std::fs::File::from(master), slave)
}

#[test]
fn the_deploy_guide_key_procedure_yields_a_key_that_passes_check_key_and_rekeys() {
    // docs/deploy.md "The key file", with temp paths and the current uid in place of 10001 (the
    // `sudo setpriv --reuid=10001 ...` uid switch is the one step a test cannot do unprivileged;
    // the commands, arguments and variables are otherwise the guide's):
    //   1. a key directory owned by the service uid, mode 0700 (`keys/`, made by `Cfg::new`);
    //   2. `wardenlens --config <host config> secrets init` as that uid, with NO pre-created file;
    //   3. the key passes `vault check-key` (what the entrypoint runs);
    //   4. (the vault is created by the service tooling; here with the library) and
    //      `WARDENLENS_VAULT=<state>/vault.db WARDENLENS_VAULT_KEY_FILE=<key> wardenlens vault rekey`
    //      on a terminal succeeds, and the new key passes check-key and opens the vault.
    let cfg = Cfg::new("127.0.0.1:1", false);
    let bin = env!("CARGO_BIN_EXE_wardenlens");
    let key = cfg.dir.path().join("keys/secrets.key");
    let db = cfg.dir.path().join("state/vault.db");
    let check = |k: &std::path::Path| {
        Command::new(bin)
            .env_clear()
            .args(["vault", "check-key"])
            .arg(k)
            .output()
            .unwrap()
    };

    // The guide's old step, a pre-created empty key file, is the thing that does not work.
    fs::write(&key, b"").unwrap();
    fs::set_permissions(&key, fs::Permissions::from_mode(0o400)).unwrap();
    let refused = cfg.command(&["secrets", "init"]).output().unwrap();
    assert!(
        !refused.status.success(),
        "init over an empty file: {refused:?}"
    );
    fs::remove_file(&key).unwrap();

    let init = cfg.command(&["secrets", "init"]).output().unwrap();
    assert!(init.status.success(), "init: {init:?}");
    let ck = check(&key);
    assert!(ck.status.success(), "check-key after init: {ck:?}");
    let before = fs::read(&key).unwrap();

    // Step 3 of the guide: `vault key export` with the deploy variables, on a terminal.
    let (master, slave) = pty();
    let export = Command::new(bin)
        .env_clear()
        .env("WARDENLENS_VAULT", &db)
        .env("WARDENLENS_VAULT_KEY_FILE", &key)
        .args(["vault", "key", "export"])
        .stdin(Stdio::null())
        .stdout(slave)
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    drop(master);
    assert!(export.status.success(), "export: {export:?}");

    let vault_key = wardenlens_secrets::KeyFile::load(&key).unwrap();
    drop(wardenlens_vault::Vault::create(&db, vault_key).unwrap());

    let (master, slave) = pty();
    let rekey = Command::new(bin)
        .env_clear()
        .env("WARDENLENS_VAULT", &db)
        .env("WARDENLENS_VAULT_KEY_FILE", &key)
        .args(["vault", "rekey"])
        .stdin(Stdio::null())
        .stdout(slave)
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    drop(master);
    assert!(rekey.status.success(), "rekey: {rekey:?}");
    assert!(!cfg.dir.path().join("keys/secrets.key.next").exists());
    let ck = check(&key);
    assert!(ck.status.success(), "check-key after rekey: {ck:?}");
    assert_ne!(before, fs::read(&key).unwrap(), "the key did not change");
    drop(
        wardenlens_vault::Vault::open(&db, wardenlens_secrets::KeyFile::load(&key).unwrap())
            .unwrap(),
    );
}
