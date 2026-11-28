//! Adversary round 2 for ticket #124 (PR #245): dropped lines and the exit code, notices whose
//! fixed text spells a value, output errors, and descriptors held by the fd-relative walk.
//! Synthetic vaults in a temporary HOME; the environment is cleared.

#![expect(
    clippy::unwrap_used,
    reason = "integration-test helpers outside #[test] fns; clippy.toml in-tests allowances do not reach them"
)]

use std::ffi::OsStr;
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

    fn cmd(&self, prefix: &[&str]) -> Command {
        let mut c = if let Some((first, rest)) = prefix.split_first() {
            let mut c = Command::new(first);
            c.args(rest).arg(env!("CARGO_BIN_EXE_wardenlens"));
            c
        } else {
            Command::new(env!("CARGO_BIN_EXE_wardenlens"))
        };
        c.env_clear()
            .env("HOME", self.home.path())
            .env("PATH", std::env::var_os("PATH").unwrap())
            .current_dir(self.work.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        c
    }

    fn run_os(&self, prefix: &[&str], args: &[&OsStr], stdin: &str) -> Output {
        let mut child = self.cmd(prefix).args(args).spawn().unwrap();
        let _ = child.stdin.take().unwrap().write_all(stdin.as_bytes());
        child.wait_with_output().unwrap()
    }

    fn run(&self, args: &[&str], stdin: &str) -> Output {
        let a: Vec<&OsStr> = args.iter().map(OsStr::new).collect();
        self.run_os(&[], &a, stdin)
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

fn both(o: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

/// The kind token alone spells the value (`display-name` stored as a display name): every hit
/// line is dropped, yet the hit is still counted and the scan exits 1, never 0.
#[test]
fn a_hit_whose_line_is_dropped_still_exits_one() {
    let value = "display-name";
    let s = Setup::new(&[("tok:d", "display-name", value)]);
    std::fs::write(s.work.path().join("a.txt"), format!("x {value} y\n")).unwrap();
    let o = s.run(&["vault", "scan", "a.txt"], "");
    let shown = both(&o);
    assert_eq!(o.status.code(), Some(1), "{shown}");
    assert!(
        !String::from_utf8_lossy(&o.stdout).contains(value),
        "{shown:?}"
    );
    assert!(shown.contains("1 hit(s)"), "{shown}");
}

/// The same through `--staged`.
#[test]
fn a_staged_hit_whose_line_is_dropped_still_exits_one() {
    let value = "display-name";
    let s = Setup::new(&[("tok:d", "display-name", value)]);
    s.git(&["init", "-q", "-b", "main"]);
    std::fs::write(s.work.path().join("a.txt"), format!("x {value} y\n")).unwrap();
    s.git(&["add", "-A"]);
    let o = s.run(&["vault", "scan", "--staged"], "");
    let shown = both(&o);
    assert_eq!(o.status.code(), Some(1), "{shown}");
    assert!(
        !String::from_utf8_lossy(&o.stdout).contains(value),
        "{shown:?}"
    );
}

/// A notice whose fixed text spells a value is dropped, but the unreadable input still makes the
/// scan exit 2 (failing to scan is never a pass).
#[test]
fn an_unreadable_input_whose_notice_is_dropped_still_exits_two() {
    for (value, make_fifo) in [("not a regular file", true), ("entity not found", false)] {
        let s = Setup::new(&[("tok:o", "other", value)]);
        let p = s.work.path().join("input");
        if make_fifo {
            assert!(Command::new("mkfifo").arg(&p).status().unwrap().success());
        }
        let o = s.run(&["vault", "scan", "input"], "");
        let shown = both(&o);
        assert_eq!(o.status.code(), Some(2), "{value}: {shown}");
        assert!(!shown.contains(value), "{value}: {shown:?}");
    }
}

/// A value spelled across a clean name and the fixed text after it in a notice: the name is
/// redacted, the value is never printed.
#[test]
fn a_value_across_a_name_and_the_notice_text_is_not_printed() {
    let value = "zqfifo is not a regular";
    let s = Setup::new(&[("tok:o", "other", value)]);
    let p = s.work.path().join("zqfifo");
    assert!(Command::new("mkfifo").arg(&p).status().unwrap().success());
    let o = s.run(&["vault", "scan", "zqfifo"], "");
    let shown = both(&o);
    assert_eq!(o.status.code(), Some(2), "{shown}");
    assert!(!shown.contains(value), "{shown:?}");
    assert!(shown.contains("<redacted-path"), "{shown}");
}

/// A binary file whose every location form spells the value: the notice is printed without the
/// location, the value never.
#[test]
fn a_binary_notice_with_no_clean_location_drops_the_location() {
    let value = "redacted-path";
    let s = Setup::new(&[("tok:r", "secret", value)]);
    std::fs::write(s.work.path().join("redacted-path.bin"), b"\0\0\0\x01\x02").unwrap();
    let o = s.run(&["vault", "scan", "redacted-path.bin"], "");
    let shown = both(&o);
    assert_eq!(o.status.code(), Some(0), "{shown}");
    assert!(!shown.contains(value), "{shown:?}");
}

/// Output errors are exit 2 also when the hit line is the only output.
#[test]
fn a_hit_written_to_a_full_device_exits_two() {
    let value = "zq-synthetic-mark-7781";
    let s = Setup::new(&[("tok:a", "secret", value)]);
    std::fs::write(s.work.path().join("a.txt"), format!("{value}\n")).unwrap();
    let full = std::fs::OpenOptions::new()
        .write(true)
        .open("/dev/full")
        .unwrap();
    let o = s
        .cmd(&[])
        .args(["vault", "scan", "a.txt"])
        .stdout(full)
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(2));
}

/// Many directories on the command line, each with one file: the walk holds one descriptor per
/// root for the whole scan, so a modest descriptor limit turns a clean scan into exit 2.
/// A path walk needed no descriptor per root; scanning N small directories should not need N
/// descriptors.
#[test]
#[ignore = "follow-up #251: one root fd per directory argument"]
fn many_directory_arguments_do_not_need_a_descriptor_each() {
    if Command::new("prlimit").arg("--version").output().is_err() {
        return;
    }
    let s = Setup::new(&[("tok:a", "secret", "zq-synthetic-mark-7781")]);
    let mut args: Vec<String> = vec!["vault".into(), "scan".into()];
    for i in 0..64 {
        let d = s.work.path().join(format!("d{i:02}"));
        std::fs::create_dir(&d).unwrap();
        std::fs::write(d.join("f.txt"), "clean\n").unwrap();
        args.push(format!("d{i:02}"));
    }
    let a: Vec<&OsStr> = args.iter().map(OsStr::new).collect();
    let o = s.run_os(&["prlimit", "--nofile=48:48"], &a, "");
    assert_eq!(o.status.code(), Some(0), "{}", both(&o));
}

/// Values that equal the new escapes (`\\` for a backslash, `\x{..}` for an invalid byte): the
/// raw name is clean, the escaped name spells the value, and it is never printed.
#[test]
fn a_value_equal_to_a_backslash_or_byte_escape_is_not_printed() {
    use std::os::unix::ffi::OsStrExt;
    for (value, name) in [
        ("\\\\cdefgh", b"ab\\cdefgh.txt".to_vec()),
        ("\\x{ff}cdefg", b"ab\xffcdefg.txt".to_vec()),
    ] {
        let s = Setup::new(&[("tok:e", "secret", value)]);
        let name = OsStr::from_bytes(&name);
        std::fs::write(s.work.path().join(name), format!("{value}\n")).unwrap();
        let o = s.run_os(&[], &[OsStr::new("vault"), OsStr::new("scan"), name], "");
        let shown = both(&o);
        assert_eq!(o.status.code(), Some(1), "{shown}");
        assert!(!shown.contains(value), "{value} printed: {shown:?}");
    }
}
