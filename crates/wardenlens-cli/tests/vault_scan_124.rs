//! Ticket #124: what the report prints for hostile file names, and the kind token being part of
//! the checked text, with a synthetic vault in a temporary HOME (the environment is cleared).

#![expect(
    clippy::unwrap_used,
    reason = "integration-test helpers outside #[test] fns; clippy.toml in-tests allowances do not reach them"
)]

use std::io::Write;
use std::process::{Command, Output, Stdio};

use tempfile::TempDir;

struct Setup {
    home: TempDir,
    work: TempDir,
}

impl Setup {
    fn new(entries: &[(&str, &str, &str)]) -> Self {
        let s = Self {
            home: tempfile::tempdir().unwrap(),
            work: tempfile::tempdir().unwrap(),
        };
        assert!(s.run(&["vault", "init"], "").status.success());
        for (id, kind, value) in entries {
            let o = s.run(&["vault", "set", id, "--kind", kind], value);
            assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
        }
        s
    }

    fn run(&self, args: &[&str], stdin: &str) -> Output {
        let mut child = Command::new(env!("CARGO_BIN_EXE_wardenlens"))
            .env_clear()
            .env("HOME", self.home.path())
            .env("PATH", std::env::var_os("PATH").unwrap())
            .current_dir(self.work.path())
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let _ = child.stdin.take().unwrap().write_all(stdin.as_bytes());
        child.wait_with_output().unwrap()
    }

    fn git(&self, args: &[&str]) {
        let o = Command::new("git")
            .current_dir(self.work.path())
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap())
            .env("HOME", self.work.path())
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .args(args)
            .output()
            .unwrap();
        assert!(o.status.success(), "git {args:?}");
    }
}

fn out(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

const SECRET: &str = "zq-synthetic-mark-7781";

/// Every control character a file name can hold (C0 but NUL and `/`, DEL, C1) and the line and
/// paragraph separators: the report stays one line per hit and prints none of them raw.
#[test]
fn control_characters_in_a_path_are_escaped_in_every_line() {
    let s = Setup::new(&[("tok:a", "secret", SECRET)]);
    let mut chars: Vec<char> = (1u32..0x20)
        .chain(0x7F..=0x9F)
        .chain([0x2028, 0x2029])
        .filter_map(char::from_u32)
        .filter(|&c| c != '/')
        .collect();
    chars.sort_unstable();
    for c in chars {
        let name = format!("a{c}b.txt");
        std::fs::write(s.work.path().join(&name), format!("{SECRET}\n")).unwrap();
        let o = s.run(&["vault", "scan", &name], "");
        assert_eq!(o.status.code(), Some(1), "U+{:04X}", u32::from(c));
        let (so, se) = (out(&o), String::from_utf8_lossy(&o.stderr).into_owned());
        assert!(
            !so.trim_end_matches('\n').contains(c),
            "stdout U+{:04X}: {so:?}",
            u32::from(c)
        );
        assert!(
            se.lines().all(|l| !l.contains(c)),
            "stderr U+{:04X}: {se:?}",
            u32::from(c)
        );
        assert_eq!(so.lines().count(), 1, "U+{:04X}: {so:?}", u32::from(c));
        assert!(so.contains("\\u{"), "U+{:04X}: {so:?}", u32::from(c));
        std::fs::remove_file(s.work.path().join(&name)).unwrap();
    }
}

/// The same for a path under a scanned directory, in the "cannot be read" and binary notices.
#[test]
fn control_characters_are_escaped_in_notices() {
    let s = Setup::new(&[("tok:a", "secret", SECRET)]);
    let name = "bin\u{1b}[31m\u{2028}x";
    std::fs::write(s.work.path().join(name), b"\0\x01").unwrap();
    let o = s.run(&["vault", "scan", "."], "");
    assert_eq!(o.status.code(), Some(0));
    let se = String::from_utf8_lossy(&o.stderr).into_owned();
    assert!(!se.contains('\u{1b}') && !se.contains('\u{2028}'), "{se:?}");
    assert!(se.contains("skipped binary file"), "{se:?}");
}

/// `--staged`: a MAC spelled across the kind token and a path is redacted in the hit line too.
#[test]
fn a_staged_hit_line_does_not_spell_a_mac_across_the_kind_and_the_path() {
    let s = Setup::new(&[("cam:a:mac", "mac", "ac:00:5e:00:53:af")]);
    s.git(&["init", "-q", "-b", "main"]);
    std::fs::write(
        s.work.path().join("00-5e-00-53-af"),
        "mac ac:00:5e:00:53:af\n",
    )
    .unwrap();
    s.git(&["add", "-A"]);
    let o = s.run(&["vault", "scan", "--staged"], "");
    assert_eq!(
        o.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
    let so = out(&o);
    assert!(so.starts_with("cam:a:mac mac "), "{so:?}");
    assert!(!so.contains("mac 00-5e-00-53-af"), "{so:?}");
    assert!(so.contains("<redacted-path>"), "{so:?}");
}
