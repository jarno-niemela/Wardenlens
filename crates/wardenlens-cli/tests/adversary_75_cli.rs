//! Adversary tests of `wardenlens vault scan` (#75, ADR 0006 section 8). Synthetic values only;
//! the environment is cleared and HOME is a temporary directory.

#![expect(
    clippy::unwrap_used,
    reason = "integration-test helpers outside #[test] fns; clippy.toml in-tests allowances do not reach them"
)]

use std::io::Write;
use std::path::Path;
use std::process::{Command, Output, Stdio};

const SECRET: &str = "zq-synthetic-mark-7781";
/// A secret that is a clean file name followed by `:2`, the shape of a `path:line` location.
const COMPOSED: &str = "zq-compose-mark:2";

fn command(home: &Path) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_wardenlens"));
    c.env_clear().env("HOME", home);
    c
}

fn vault(home: &Path, args: &[&str], stdin: &str) -> Output {
    let mut child = command(home)
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

/// ADR 0006 section 8: the report can never be used to learn a value, and no printed location
/// may contain a hit. The path `.../zq-compose-mark` is clean on its own, but the printed
/// location `path:line` for a hit on line 2 spells the stored secret `zq-compose-mark:2`.
/// The redaction check runs over the bare path, not over the location that is printed.
#[test]
fn a_printed_location_never_spells_a_vault_value() {
    let home = tempfile::tempdir().unwrap();
    let work = tempfile::tempdir().unwrap();
    assert!(vault(home.path(), &["init"], "").status.success());
    for (id, value) in [("tok:a", SECRET), ("tok:b", COMPOSED)] {
        let o = vault(home.path(), &["set", id, "--kind", "secret"], value);
        assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    }
    let file = work.path().join("zq-compose-mark");
    std::fs::write(&file, format!("line one\nthe token {SECRET}\n")).unwrap();
    let o = command(home.path())
        .args(["vault", "scan"])
        .arg(&file)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(1));
    let all = format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    );
    for v in [SECRET, COMPOSED] {
        assert!(!all.contains(v), "a value reached the output: {all}");
    }
}
