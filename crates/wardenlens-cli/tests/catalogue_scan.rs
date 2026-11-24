//! The exact-match leak guard for the public camera catalogue (ticket #32, ADR 0006 section 9):
//! `wardenlens vault scan cameras/` against a vault's real values. The shape heuristics of the
//! catalogue module are only a soft lint; this is the check whose result does not depend on how
//! a value is written. Vaults here are synthetic; the real vault is only used by the last test,
//! and only through the binary, which never prints a value.

#![expect(
    clippy::unwrap_used,
    clippy::print_stderr,
    reason = "integration-test helpers outside #[test] fns; clippy.toml in-tests allowances do not reach them; the skip notice must be visible"
)]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use tempfile::TempDir;

const SECRET: &str = "zq-synthetic-mark-4410";
const HOST: &str = "192.0.2.44";

fn cameras_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../cameras")
}

/// A HOME holding an initialised vault with synthetic values.
struct Home(TempDir);

impl Home {
    fn new() -> Self {
        let home = Self(tempfile::tempdir().unwrap());
        assert!(home.run(&["init"], "").status.success());
        for (id, kind, value) in [("tok:a", "secret", SECRET), ("cam:a:host", "host", HOST)] {
            let set = home.run(&["set", id, "--kind", kind], value);
            assert!(
                set.status.success(),
                "{}",
                String::from_utf8_lossy(&set.stderr)
            );
        }
        home
    }

    fn run(&self, args: &[&str], stdin: &str) -> Output {
        let mut child = Command::new(env!("CARGO_BIN_EXE_wardenlens"))
            .env_clear()
            .env("HOME", self.0.path())
            .arg("vault")
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let _ = child.stdin.take().unwrap().write_all(stdin.as_bytes());
        child.wait_with_output().unwrap()
    }

    fn scan(&self, path: &Path) -> Output {
        self.run(&["scan", path.to_str().unwrap()], "")
    }
}

fn text(o: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_dir(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), target).unwrap();
        }
    }
}

fn first_entry(dir: &Path) -> PathBuf {
    let mut found: Vec<PathBuf> = Vec::new();
    for vendor in std::fs::read_dir(dir).unwrap() {
        let vendor = vendor.unwrap().path();
        if vendor.is_dir() {
            for f in std::fs::read_dir(&vendor).unwrap() {
                let f = f.unwrap().path();
                if f.extension().is_some_and(|e| e == "toml") {
                    found.push(f);
                }
            }
        }
    }
    found.sort();
    found.into_iter().next().unwrap()
}

#[test]
fn the_real_catalogue_has_no_value_of_a_synthetic_vault() {
    let home = Home::new();
    let o = home.scan(&cameras_dir());
    assert_eq!(o.status.code(), Some(0), "{}", text(&o));
}

#[test]
fn control_a_planted_vault_value_in_an_entry_is_a_hit_and_is_never_printed() {
    let home = Home::new();
    let work = tempfile::tempdir().unwrap();
    let copy = work.path().join("cameras");
    copy_dir(&cameras_dir(), &copy);

    // The unmodified copy is clean, so the hit below comes from the planted value alone.
    let o = home.scan(&copy);
    assert_eq!(o.status.code(), Some(0), "{}", text(&o));

    for planted in [SECRET, HOST] {
        let entry = first_entry(&copy);
        let original = std::fs::read_to_string(&entry).unwrap();
        std::fs::write(&entry, format!("{original}# note {planted}\n")).unwrap();
        let o = home.scan(&copy);
        assert_eq!(o.status.code(), Some(1), "{}", text(&o));
        let all = text(&o);
        assert!(!all.contains(planted), "a vault value reached the output");
        assert!(!all.contains(SECRET) && !all.contains(HOST));
        std::fs::write(&entry, original).unwrap();
    }
}

/// Whether the default vault scan must run (ADR 0006 section 4). Mirrors `env.rs`: a set
/// `WARDENLENS_VAULT` (even empty) or a `HOME` that is not an absolute path is a configuration
/// the binary refuses, so the scan must run and fail rather than be skipped. Only the existence
/// of the file is checked; it is never opened, read or listed.
fn default_vault_must_be_scanned() -> bool {
    let path = match std::env::var_os("WARDENLENS_VAULT") {
        Some(p) => PathBuf::from(p),
        None => match std::env::var_os("HOME") {
            Some(h) => PathBuf::from(h).join(".local/share/wardenlens/dev-vault.db"),
            None => return true,
        },
    };
    !path.is_absolute() || path.symlink_metadata().is_ok()
}

#[test]
fn the_real_catalogue_has_no_value_of_the_default_vault_when_there_is_one() {
    // Not skipped on CI: the only reason to skip is that no vault exists on this machine.
    if !default_vault_must_be_scanned() {
        eprintln!(
            "NOTICE: no default vault on this machine; skipping the default-vault scan of cameras/ \
             (the synthetic-vault tests above still run)"
        );
        return;
    }
    let o = Command::new(env!("CARGO_BIN_EXE_wardenlens"))
        .args(["vault", "scan"])
        .arg(cameras_dir())
        .stdin(Stdio::null())
        .output()
        .unwrap();
    // The scanner prints entry ids and locations, never a value.
    assert_eq!(o.status.code(), Some(0), "{}", text(&o));
}
