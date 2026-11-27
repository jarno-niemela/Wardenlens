//! #69 adversary round 3: the entrypoint's `--config` refusal against every spelling the real
//! binary accepts, and the deploy guide's uid-switch commands checked against the CLI grammar.
//! Temporary paths and the current uid only; the environment is cleared.

#![expect(
    clippy::unwrap_used,
    reason = "integration-test helpers outside #[test] fns; a panic is a failure"
)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

const BIN: &str = env!("CARGO_BIN_EXE_wardenlens");

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// A host config from docs/config.docker.toml whose key file is `<dir>/<name>/vault.key`.
fn host_config(dir: &Path, name: &str) -> (PathBuf, PathBuf) {
    let kd = dir.join(name);
    fs::create_dir_all(&kd).unwrap();
    fs::set_permissions(&kd, fs::Permissions::from_mode(0o700)).unwrap();
    let key = kd.join("vault.key");
    let shipped = fs::read_to_string(repo().join("docs/config.docker.toml")).unwrap();
    let cfg = dir.join(format!("{name}.toml"));
    fs::write(
        &cfg,
        shipped.replace("/run/secrets/wardenlens_vault_key", key.to_str().unwrap()),
    )
    .unwrap();
    (cfg, key)
}

fn wl(env_config: &Path, args: &[&str]) -> Output {
    Command::new(BIN)
        .env_clear()
        .env("WARDENLENS_CONFIG", env_config)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

fn entrypoint(dir: &Path, env_config: &Path, args: &[&str]) -> Output {
    let bin = dir.join("bin");
    if !bin.exists() {
        fs::create_dir_all(&bin).unwrap();
        std::os::unix::fs::symlink(BIN, bin.join("wardenlens")).unwrap();
    }
    Command::new("sh")
        .env_clear()
        .env("PATH", format!("{}:/usr/bin:/bin", bin.display()))
        .env("WARDENLENS_CONFIG", env_config)
        .arg(repo().join("docker/entrypoint.sh"))
        .args(args)
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

fn key_line(out: &Output) -> Option<String> {
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .find_map(|l| l.strip_prefix("key_file: ").map(str::to_owned))
}

#[test]
fn every_spelling_the_binary_accepts_for_another_config_is_refused_by_the_entrypoint() {
    let dir = tempfile::tempdir().unwrap();
    let (good_cfg, good_key) = host_config(dir.path(), "good");
    let (other_cfg, other_key) = host_config(dir.path(), "other");
    let ok = wl(
        &good_cfg,
        &["--config", good_cfg.to_str().unwrap(), "secrets", "init"],
    );
    assert!(ok.status.success(), "{ok:?}");
    let o = other_cfg.to_str().unwrap();
    let eq = |flag: &str| format!("{flag}={o}");
    let (e1, e2, e3, e4) = (eq("--config"), eq("--conf"), eq("--confi"), eq("-c"));
    let spellings: Vec<Vec<&str>> = vec![
        vec!["--config", o, "config", "check"],
        vec!["config", "--config", o, "check"],
        vec!["config", "check", "--config", o],
        vec![&e1, "config", "check"],
        vec!["config", "check", &e1],
        vec!["--conf", o, "config", "check"],
        vec![&e2, "config", "check"],
        vec![&e3, "config", "check"],
        vec!["-c", o, "config", "check"],
        vec![&e4, "config", "check"],
        vec!["--CONFIG", o, "config", "check"],
        vec!["--log-format", "text", "--config", o, "config", "check"],
    ];
    let other_key = other_key.to_str().unwrap().to_owned();
    let good_key = good_key.to_str().unwrap().to_owned();
    let mut accepted = 0;
    for args in &spellings {
        let direct = wl(&good_cfg, args);
        if key_line(&direct).as_deref() != Some(other_key.as_str()) {
            // The binary does not take this spelling as another config: nothing to bypass.
            continue;
        }
        accepted += 1;
        let ep = entrypoint(dir.path(), &good_cfg, args);
        let used = key_line(&ep);
        assert!(
            !ep.status.success() && used.is_none(),
            "{args:?}: the entrypoint checked {good_key} but ran a command that used {used:?}"
        );
    }
    // The five `--config` / `--config=` placements must all have been exercised.
    assert!(
        accepted >= 5,
        "only {accepted} spellings reached the entrypoint"
    );
}

#[test]
fn a_config_flag_after_double_dash_or_inside_a_value_never_changes_the_config_used() {
    // Over-refusal is safe; what matters is that no accepted command line reads another config.
    let dir = tempfile::tempdir().unwrap();
    let (good_cfg, good_key) = host_config(dir.path(), "good");
    let (other_cfg, _) = host_config(dir.path(), "other");
    let ok = wl(
        &good_cfg,
        &["--config", good_cfg.to_str().unwrap(), "secrets", "init"],
    );
    assert!(ok.status.success(), "{ok:?}");
    let o = other_cfg.to_str().unwrap();
    for args in [
        vec!["config", "check", "--", "--config", o],
        vec!["config", "check", " --config", o],
        vec!["config", "check", "--config\n", o],
    ] {
        let ep = entrypoint(dir.path(), &good_cfg, &args);
        if ep.status.success() {
            assert_eq!(
                key_line(&ep).as_deref(),
                good_key.to_str(),
                "{args:?}: {ep:?}"
            );
        }
    }
}

#[test]
fn every_uid_switch_in_the_deploy_guide_uses_setpriv_with_the_service_uid_and_no_sudo_user_form() {
    let doc = fs::read_to_string(repo().join("docs/deploy.md")).unwrap();
    // Join backslash continuations so a command split over lines is one string.
    let joined = doc.replace("\\\n", " ");
    let cmds: Vec<&str> = joined
        .lines()
        .map(str::trim)
        .filter(|l| l.starts_with("sudo ") && l.contains("wardenlens "))
        .filter(|l| !l.starts_with("sudo install"))
        .collect();
    assert!(cmds.len() >= 4, "{cmds:?}");
    for c in &cmds {
        assert!(!c.contains(" -u "), "sudo -u needs a passwd entry: {c}");
        assert!(
            c.contains("setpriv --reuid=10001 --regid=10001 --clear-groups \"$d\"/wardenlens "),
            "{c}"
        );
        // `sudo` resets the environment: a variable must be passed by `sudo env`, before setpriv.
        if c.contains("WARDENLENS_") {
            let (pre, _) = c.split_once("setpriv").unwrap();
            assert!(pre.starts_with("sudo env "), "{c}");
            for var in pre.split_whitespace().filter(|w| w.contains('=')) {
                let name = var.split('=').next().unwrap();
                assert!(
                    ["WARDENLENS_VAULT", "WARDENLENS_VAULT_KEY_FILE"].contains(&name),
                    "the vault commands do not read {name}: {c}"
                );
            }
        }
    }
}

#[test]
fn the_guides_vault_commands_parse_with_the_shipped_grammar() {
    // Each documented `wardenlens ...` tail, run against temp paths as the current uid. A
    // usage error (exit 2 with "invalid arguments") would mean the guide's command line is wrong.
    let dir = tempfile::tempdir().unwrap();
    let (cfg, key) = host_config(dir.path(), "key");
    let init = Command::new(BIN)
        .env_clear()
        .args(["--config", cfg.to_str().unwrap(), "secrets", "init"])
        .output()
        .unwrap();
    assert!(init.status.success(), "{init:?}");
    for tail in [
        vec!["vault", "check-key", key.to_str().unwrap()],
        vec!["vault", "key", "export"],
        vec!["vault", "rekey"],
    ] {
        let out = Command::new(BIN)
            .env_clear()
            .env("HOME", "/nonexistent")
            .env("WARDENLENS_VAULT", dir.path().join("vault.db"))
            .env("WARDENLENS_VAULT_KEY_FILE", &key)
            .args(&tail)
            .stdin(Stdio::null())
            .output()
            .unwrap();
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(!err.contains("invalid arguments"), "{tail:?}: {err}");
    }
}
