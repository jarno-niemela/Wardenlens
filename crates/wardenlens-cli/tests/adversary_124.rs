//! Adversary round 1 for ticket #124 (PR #245): the printed location, the redaction fallback and
//! the fd-relative walk, attacked through the binary with synthetic vaults in a temporary HOME.

#![expect(
    clippy::unwrap_used,
    reason = "integration-test helpers outside #[test] fns; clippy.toml in-tests allowances do not reach them"
)]

use std::ffi::OsStr;
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
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
}

fn both(o: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

/// A value that equals the fixed marker text: every fallback spells it. The ticket (and the PR
/// summary) says the line is then dropped; the value must never appear in the output.
#[test]
fn a_value_equal_to_the_redaction_marker_is_never_printed() {
    for value in ["redacted-path", "<redacted-path>", "redacted-location"] {
        let s = Setup::new(&[("tok:m", "secret", value)]);
        let name = format!("a-{}-b.txt", value.trim_matches(['<', '>']));
        std::fs::write(s.work.path().join(&name), format!("{value}\n")).unwrap();
        let o = s.run(&["vault", "scan", &name], "");
        let shown = both(&o);
        assert_ne!(o.status.code(), Some(0), "{value}: {shown}");
        assert!(!shown.contains(value), "{value} printed: {shown:?}");
    }
}

/// The marker spelled across the kind token: the value `secret <redacted-path` is printed by a
/// hit line whose location is redacted.
#[test]
fn a_value_spelled_across_the_kind_and_the_marker_is_never_printed() {
    let value = "secret <redacted-path";
    let s = Setup::new(&[("tok:m", "secret", value)]);
    // The path holds the value too, so it is redacted.
    let name = "secret <redacted-path.txt";
    std::fs::write(s.work.path().join(name), format!("{value}\n")).unwrap();
    let o = s.run(&["vault", "scan", name], "");
    let shown = both(&o);
    assert_eq!(o.status.code(), Some(1), "{shown}");
    assert!(!shown.contains(value), "printed: {shown:?}");
}

/// A value that is the text of an escape: the raw name is clean, the escaped name is not.
#[test]
fn a_value_equal_to_an_escape_sequence_is_not_printed() {
    let value = "\\u{202e}cdefg";
    let s = Setup::new(&[("tok:e", "secret", value)]);
    let name = "ab\u{202e}cdefg.txt";
    std::fs::write(s.work.path().join(name), format!("{value}\n")).unwrap();
    let o = s.run(&["vault", "scan", name], "");
    let shown = both(&o);
    assert_eq!(o.status.code(), Some(1), "{shown}");
    assert!(!shown.contains(value), "printed: {shown:?}");
    assert!(!shown.contains('\u{202e}'), "{shown:?}");
}

/// A name that is not UTF-8: the value in the raw bytes is never printed, and the invalid byte
/// never reaches the terminal raw.
#[test]
fn a_value_in_a_non_utf8_name_is_redacted() {
    let value = "zq-synthetic-mark-7781";
    let s = Setup::new(&[("tok:a", "secret", value)]);
    let mut name = b"pre\xff".to_vec();
    name.extend_from_slice(value.as_bytes());
    name.extend_from_slice(b"\xfe.txt");
    let name = OsStr::from_bytes(&name);
    std::fs::write(s.work.path().join(name), format!("{value}\n")).unwrap();
    for arg in [name, OsStr::new(".")] {
        let o = s.run_os(&[], &[OsStr::new("vault"), OsStr::new("scan"), arg], "");
        assert_eq!(o.status.code(), Some(1));
        assert!(!o.stdout.windows(value.len()).any(|w| w == value.as_bytes()));
        assert!(!o.stdout.contains(&0xff) && !o.stdout.contains(&0xfe));
        assert!(String::from_utf8_lossy(&o.stdout).contains("<redacted-path"));
    }
}

/// Assigned default-ignorables and fillers that are not `Cf` (variation selectors, the Hangul
/// fillers, the combining grapheme joiner) never reach the terminal raw.
#[test]
fn non_cf_invisibles_are_escaped_too() {
    let s = Setup::new(&[("tok:a", "secret", "zq-synthetic-mark-7781")]);
    for c in [
        '\u{34F}',
        '\u{115F}',
        '\u{17B4}',
        '\u{180B}',
        '\u{3164}',
        '\u{FE0F}',
        '\u{FFA0}',
        '\u{E0100}',
        '\u{FFF0}',
        '\u{E0FFF}',
        '\u{F8FF}',
        '\u{FFFF}',
    ] {
        let name = format!("x{c}y.txt");
        std::fs::write(s.work.path().join(&name), "zq-synthetic-mark-7781\n").unwrap();
        let o = s.run(&["vault", "scan", &name], "");
        assert_eq!(o.status.code(), Some(1));
        assert!(!both(&o).contains(c), "U+{:04X}", u32::from(c));
        std::fs::remove_file(s.work.path().join(&name)).unwrap();
    }
}

/// Builds `depth` nested directories with long names below `root`, fd-relative (the full path is
/// longer than `PATH_MAX`), and puts `leaf` in the deepest one.
fn deep_tree(root: &std::path::Path, depth: usize, leaf: &str) {
    use rustix::fs::{Mode, OFlags};
    let name = "d".repeat(200);
    let mut dir = rustix::fs::open(
        root,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .unwrap();
    for _ in 0..depth {
        rustix::fs::mkdirat(&dir, name.as_str(), Mode::RWXU).unwrap();
        dir = rustix::fs::openat(
            &dir,
            name.as_str(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap();
    }
    let f = rustix::fs::openat(
        &dir,
        "leaf.txt",
        OFlags::WRONLY | OFlags::CREATE | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
    .unwrap();
    rustix::io::write(&f, leaf.as_bytes()).unwrap();
}

/// Removes a tree deeper than `PATH_MAX` (tempfile's cleanup would fail on it), fd-relative.
fn remove_deep(root: &std::path::Path) {
    let _ = Command::new("rm").arg("-rf").arg(root).status();
}

/// A tree deeper than `PATH_MAX` but within the depth limit: the walk is fd-relative, so the file is
/// reached and the hit found (exit 1, never a silent pass).
#[test]
fn a_tree_longer_than_path_max_is_scanned() {
    let value = "zq-synthetic-mark-7781";
    let s = Setup::new(&[("tok:a", "secret", value)]);
    std::fs::create_dir(s.work.path().join("t")).unwrap();
    deep_tree(&s.work.path().join("t"), 40, &format!("{value}\n"));
    let o = s.run(&["vault", "scan", "t"], "");
    let code = o.status.code();
    let lines = String::from_utf8_lossy(&o.stdout).lines().count();
    remove_deep(&s.work.path().join("t"));
    assert_eq!(code, Some(1), "{}", String::from_utf8_lossy(&o.stderr));
    assert_eq!(lines, 1);
}

/// Few descriptors: a deep walk runs out of them. The scan must fail closed (exit 2), never pass
/// and never panic.
#[test]
fn running_out_of_descriptors_on_a_deep_tree_fails_closed() {
    if Command::new("prlimit").arg("--version").output().is_err() {
        return;
    }
    let value = "zq-synthetic-mark-7781";
    let s = Setup::new(&[("tok:a", "secret", value)]);
    std::fs::create_dir(s.work.path().join("t")).unwrap();
    deep_tree(&s.work.path().join("t"), 60, "clean text\n");
    let a: Vec<&OsStr> = ["vault", "scan", "t"].iter().map(OsStr::new).collect();
    let o = s.run_os(&["prlimit", "--nofile=24:24"], &a, "");
    remove_deep(&s.work.path().join("t"));
    let se = String::from_utf8_lossy(&o.stderr).into_owned();
    assert_eq!(o.status.code(), Some(2), "{se}");
    assert!(!se.contains("panicked"), "{se}");
}

/// A directory the owner may not list, below the root: exit 2 and the message holds no path when
/// the name holds a value.
#[test]
fn an_unreadable_directory_holding_a_value_in_its_name_is_redacted() {
    use std::os::unix::fs::PermissionsExt;
    let value = "zq-synthetic-mark-7781";
    let s = Setup::new(&[("tok:a", "secret", value)]);
    let d = s.work.path().join(format!("t/{value}"));
    std::fs::create_dir_all(&d).unwrap();
    std::fs::write(d.join("f"), "x\n").unwrap();
    std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o000)).unwrap();
    let o = s.run(&["vault", "scan", "t"], "");
    std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700)).unwrap();
    // Root ignores the mode; the attack needs a non-root user.
    if rustix::process::geteuid().is_root() {
        return;
    }
    let shown = both(&o);
    assert_eq!(o.status.code(), Some(2), "{shown}");
    assert!(!shown.contains(value), "{shown:?}");
}

fn git(s: &Setup, args: &[&str]) {
    let o = Command::new("git")
        .current_dir(s.work.path())
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap())
        .env("HOME", s.work.path())
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .args(args)
        .output()
        .unwrap();
    assert!(o.status.success(), "git {args:?}");
}

/// `--staged`: the last resort `<redacted-location>` is printed without a check. A value that
/// every fallback spells (`redacted`) is then printed.
#[test]
fn a_staged_hit_never_prints_a_value_through_the_last_resort() {
    let value = "redacted";
    let s = Setup::new(&[("tok:r", "secret", value)]);
    git(&s, &["init", "-q", "-b", "main"]);
    std::fs::write(s.work.path().join("redacted.txt"), format!("{value}\n")).unwrap();
    git(&s, &["add", "-A"]);
    let o = s.run(&["vault", "scan", "--staged"], "");
    let shown = both(&o);
    assert_eq!(o.status.code(), Some(1), "{shown}");
    let so = String::from_utf8_lossy(&o.stdout).into_owned();
    assert!(!so.contains(value), "printed: {so:?}");
}

/// The same value through a plain path scan.
#[test]
fn a_path_hit_never_prints_a_value_through_the_last_resort() {
    let value = "redacted";
    let s = Setup::new(&[("tok:r", "secret", value)]);
    std::fs::write(s.work.path().join("redacted.txt"), format!("{value}\n")).unwrap();
    let o = s.run(&["vault", "scan", "redacted.txt"], "");
    let shown = both(&o);
    assert_eq!(o.status.code(), Some(1), "{shown}");
    let so = String::from_utf8_lossy(&o.stdout).into_owned();
    assert!(!so.contains(value), "printed: {so:?}");
}
