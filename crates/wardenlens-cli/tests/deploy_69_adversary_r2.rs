//! #69 adversary round 2: the documented key procedure applied to the shipped
//! `docs/config.docker.toml`, and the real `docker/entrypoint.sh` driven with the real binary.
//! Temporary paths and the current uid only; the environment is cleared.

#![expect(
    clippy::unwrap_used,
    reason = "integration-test helpers outside #[test] fns; a panic is a failure"
)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use tempfile::TempDir;

const BIN: &str = env!("CARGO_BIN_EXE_wardenlens");

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

struct Host {
    dir: TempDir,
}

impl Host {
    /// A key directory owned by the current uid with mode 0700 (deploy.md step 2), a `bin/`
    /// with `wardenlens` on it for the entrypoint, and a host config made from
    /// docs/config.docker.toml by the guide's `sed` substitution.
    fn new(key_dir_name: &str) -> Self {
        let dir = tempfile::tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let kd = dir.path().join(key_dir_name);
        fs::create_dir_all(&kd).unwrap();
        fs::set_permissions(&kd, fs::Permissions::from_mode(0o700)).unwrap();
        let bin = dir.path().join("bin");
        fs::create_dir_all(&bin).unwrap();
        std::os::unix::fs::symlink(BIN, bin.join("wardenlens")).unwrap();
        let h = Self { dir };
        let shipped = fs::read_to_string(repo().join("docs/config.docker.toml")).unwrap();
        assert!(shipped.contains("/run/secrets/wardenlens_vault_key"));
        let text = shipped.replace(
            "/run/secrets/wardenlens_vault_key",
            h.key().to_str().unwrap(),
        );
        fs::write(h.config(), text).unwrap();
        fs::set_permissions(h.config(), fs::Permissions::from_mode(0o644)).unwrap();
        h
    }

    fn key_dir(&self) -> PathBuf {
        let mut it = fs::read_dir(self.dir.path()).unwrap();
        it.find_map(|e| {
            let e = e.unwrap();
            let n = e.file_name();
            (n != "bin" && e.file_type().unwrap().is_dir()).then(|| e.path())
        })
        .unwrap()
    }

    fn key(&self) -> PathBuf {
        self.key_dir().join("vault.key")
    }

    fn config(&self) -> PathBuf {
        self.dir.path().join("wl-host.toml")
    }

    fn wl(args: &[&str]) -> Output {
        Command::new(BIN)
            .env_clear()
            .args(args)
            .stdin(Stdio::null())
            .output()
            .unwrap()
    }

    /// The real entrypoint, with the real binary first on PATH.
    fn entrypoint(&self, env: &[(&str, &Path)], args: &[&str]) -> Output {
        let path = format!("{}:/usr/bin:/bin", self.dir.path().join("bin").display());
        let mut c = Command::new("sh");
        c.env_clear()
            .env("PATH", path)
            .arg(repo().join("docker/entrypoint.sh"))
            .args(args)
            .stdin(Stdio::null());
        for (k, v) in env {
            c.env(k, v);
        }
        c.output().unwrap()
    }
}

fn s(p: &Path) -> &str {
    p.to_str().unwrap()
}

#[test]
fn the_guide_sed_on_the_shipped_docker_config_yields_a_config_that_secrets_init_accepts() {
    let h = Host::new("key");
    let cfg = h.config();
    let init = Host::wl(&["--config", s(&cfg), "secrets", "init"]);
    assert!(init.status.success(), "{init:?}");
    let mode = fs::metadata(h.key()).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    let ck = Host::wl(&["vault", "check-key", s(&h.key())]);
    assert!(ck.status.success(), "{ck:?}");
    // A second init never overwrites.
    let before = fs::read(h.key()).unwrap();
    let again = Host::wl(&["--config", s(&cfg), "secrets", "init"]);
    assert!(!again.status.success());
    assert_eq!(before, fs::read(h.key()).unwrap());
}

#[test]
fn the_real_entrypoint_checks_the_configured_key_then_execs_the_command() {
    let h = Host::new("key dir with spaces");
    let cfg = h.config();
    assert!(
        Host::wl(&["--config", s(&cfg), "secrets", "init"])
            .status
            .success()
    );
    let key = h.key();
    let ok = h.entrypoint(
        &[
            ("WARDENLENS_CONFIG", &cfg),
            ("WARDENLENS_VAULT_KEY_FILE", &key),
        ],
        &["config", "check"],
    );
    assert!(ok.status.success(), "{ok:?}");
    // Without the variable the config alone decides.
    let ok = h.entrypoint(&[("WARDENLENS_CONFIG", &cfg)], &["config", "check"]);
    assert!(ok.status.success(), "{ok:?}");
    // A differing variable is refused, even a path that names the same file.
    let alias = h.key_dir().join(".").join("vault.key");
    let drift = h.entrypoint(
        &[
            ("WARDENLENS_CONFIG", &cfg),
            ("WARDENLENS_VAULT_KEY_FILE", &alias),
        ],
        &["config", "check"],
    );
    assert!(!drift.status.success(), "{drift:?}");
    // A group-readable key is refused before the command runs.
    fs::set_permissions(&key, fs::Permissions::from_mode(0o640)).unwrap();
    let bad = h.entrypoint(&[("WARDENLENS_CONFIG", &cfg)], &["config", "check"]);
    assert!(!bad.status.success(), "{bad:?}");
    assert!(
        !String::from_utf8_lossy(&bad.stdout).contains("listen:\n")
            || String::from_utf8_lossy(&bad.stdout).is_empty()
    );
    // A missing config stops the entrypoint.
    let none = h.entrypoint(
        &[("WARDENLENS_CONFIG", &h.dir.path().join("nope.toml"))],
        &["config", "check"],
    );
    assert!(!none.status.success(), "{none:?}");
}

#[test]
fn the_entrypoint_never_checks_a_different_key_than_the_command_it_execs_uses() {
    // The entrypoint's stated invariant: "the key path is the one `serve` will use ... so the two
    // cannot drift apart". The command line is forwarded verbatim, so a `--config` in the
    // container command makes the exec'd command read another config than `config check` did.
    let good = Host::new("key");
    assert!(
        Host::wl(&["--config", s(&good.config()), "secrets", "init"])
            .status
            .success()
    );
    let other = Host::new("key");
    // other's key file does not even exist.
    let out = good.entrypoint(
        &[("WARDENLENS_CONFIG", &good.config())],
        &["--config", s(&other.config()), "config", "check"],
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let used = stdout
        .lines()
        .find_map(|l| l.strip_prefix("key_file: "))
        .unwrap_or_default()
        .to_owned();
    assert!(
        !out.status.success() || used == s(&good.key()),
        "the entrypoint checked {} but the command uses {used}",
        good.key().display()
    );
}
