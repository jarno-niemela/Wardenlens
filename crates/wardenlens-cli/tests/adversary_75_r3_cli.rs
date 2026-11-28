//! Adversary tests of `wardenlens vault scan`, #75 round 3 (ADR 0006 sections 7 and 8).
//! Synthetic values only; the environment is cleared and HOME is a temporary directory.

#![expect(
    clippy::unwrap_used,
    reason = "integration-test helpers outside #[test] fns; clippy.toml in-tests allowances do not reach them"
)]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use tempfile::TempDir;

const SECRET: &str = "zq-synthetic-mark-7781";

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
        assert!(s.vault(&["init"], "").status.success());
        for (id, kind, value) in entries {
            let o = s.vault(&["set", id, "--kind", kind], value);
            assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
        }
        s
    }

    fn command(&self) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_wardenlens"));
        c.env_clear().env("HOME", self.home.path());
        c
    }

    fn vault(&self, args: &[&str], stdin: &str) -> Output {
        let mut child = self
            .command()
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

    /// Scans paths given relative to the work directory, as a user would type them there.
    fn scan_relative(&self, paths: &[&str]) -> Output {
        self.command()
            .current_dir(self.work.path())
            .args(["vault", "scan"])
            .args(paths)
            .stdin(Stdio::null())
            .output()
            .unwrap()
    }

    fn scan(&self, paths: &[&Path]) -> Output {
        self.command()
            .args(["vault", "scan"])
            .args(paths)
            .stdin(Stdio::null())
            .output()
            .unwrap()
    }

    fn file(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let p = self.work.path().join(name);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, bytes).unwrap();
        p
    }

    /// The scanner as its own oracle: does `text` hold a vault value? The report is written to
    /// a separate clean directory so that its own path cannot hit.
    fn holds_value(&self, text: &[u8]) -> bool {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("report.txt");
        std::fs::write(&p, text).unwrap();
        let o = self.scan(&[&p]);
        assert!(
            matches!(o.status.code(), Some(0 | 1)),
            "{}",
            String::from_utf8_lossy(&o.stderr)
        );
        o.status.code() == Some(1)
    }
}

fn out(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn err(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

/// ADR 0006 section 8 / SEC-6: the report never spells a value. The kind `mac` ends in the hex
/// digits `ac`; a hit line is `id mac location`, and a location that starts with the other five
/// groups of a stored MAC spells the whole MAC across the kind and the path, although the
/// location alone (the only thing `location()` checks) is clean.
#[test]
fn a_hit_line_does_not_spell_a_mac_across_the_kind_and_the_path() {
    let s = Setup::new(&[("cam:a:mac", "mac", "ac:00:5e:00:53:af")]);
    s.file("00-5e-00-53-af", b"mac ac:00:5e:00:53:af\n");
    let o = s.scan_relative(&["00-5e-00-53-af"]);
    assert_eq!(o.status.code(), Some(1), "{}", err(&o));
    assert!(
        !s.holds_value(&o.stdout),
        "the report spells the MAC: {:?}",
        out(&o)
    );
    assert!(
        !s.holds_value(&o.stderr),
        "stderr spells the MAC: {:?}",
        err(&o)
    );
}

/// The same across the kind `other` and a path that starts with the rest of the value.
#[test]
fn a_hit_line_does_not_spell_an_other_value_across_the_kind_and_the_path() {
    let s = Setup::new(&[("site:a", "other", "Other Garage Wing")]);
    s.file("Garage Wing/notes.txt", b"the other garage wing\n");
    let o = s.scan_relative(&["Garage Wing/notes.txt"]);
    assert_eq!(o.status.code(), Some(1), "{}", err(&o));
    assert!(
        !s.holds_value(&o.stdout),
        "the report spells the value: {:?}",
        out(&o)
    );
}

/// A clean path is printed as it is, even when the value is spelled by the fixed text of a
/// notice and the path together only (the notice text is part of the check, ADR section 8):
/// `file ` ends in the hex digit `e`, so a path starting with five MAC groups would spell the
/// MAC; it must be redacted, and every other clean notice keeps its path.
#[test]
fn a_binary_notice_does_not_spell_a_mac_across_the_message_and_the_path() {
    let s = Setup::new(&[("cam:a:mac", "mac", "0e:00:5e:00:53:af")]);
    s.file("00-5e-00-53-af", b"\0\x01binary");
    let o = s.scan_relative(&["00-5e-00-53-af"]);
    assert_eq!(o.status.code(), Some(0), "{}", err(&o));
    assert!(
        !s.holds_value(&o.stderr),
        "stderr spells the MAC: {:?}",
        err(&o)
    );
    assert!(err(&o).contains("<redacted-path:0>"), "{}", err(&o));
}

/// A path whose escaped form is clean but whose raw bytes hold a value (the value split by a
/// zero-width space, which the squeeze deletes) is redacted on hit lines and notices alike.
#[test]
fn a_value_split_by_an_invisible_character_in_a_path_is_redacted() {
    let s = Setup::new(&[("tok:a", "secret", SECRET)]);
    let name = format!("{}\u{200B}{}.txt", &SECRET[..8], &SECRET[8..]);
    let f = s.file(&name, format!("{SECRET}\n").as_bytes());
    let o = s.scan(&[&f]);
    assert_eq!(o.status.code(), Some(1), "{}", err(&o));
    assert_eq!(out(&o), "tok:a secret <redacted-path:0>:1\n");
    let b = s.file(&format!("bin-{name}"), b"\0\x01");
    let o = s.scan(&[&b]);
    assert!(err(&o).contains("<redacted-path:0>"), "{}", err(&o));
    assert!(!err(&o).contains("synthetic"), "{}", err(&o));
}

/// ADR 0006 section 8: invisible formatting characters in a path are printed as escapes. The
/// default-ignorable code points that are not yet assigned (U+E0000, U+E0002..U+E001F,
/// U+E0080..U+E0FFF, U+FFF0..U+FFF8) render as nothing too.
#[test]
fn unassigned_default_ignorable_characters_in_a_path_are_escaped() {
    let s = Setup::new(&[("tok:a", "secret", SECRET)]);
    let mut raw = Vec::new();
    for c in [
        '\u{E0000}',
        '\u{E0002}',
        '\u{E0080}',
        '\u{E0FFF}',
        '\u{FFF0}',
    ] {
        let f = s.file(&format!("a{c}b.txt"), format!("{SECRET}\n").as_bytes());
        let o = s.scan(&[&f]);
        assert_eq!(o.status.code(), Some(1));
        if out(&o).contains(c) {
            raw.push(format!("U+{:04X}", u32::from(c)));
        }
        std::fs::remove_file(&f).unwrap();
    }
    assert!(raw.is_empty(), "printed raw: {raw:?}");
}

/// A clean relative path keeps its form and its line; the entry id spelling the value does not
/// hide it (round-2 regression stays fixed with relative paths too).
#[test]
fn a_clean_relative_path_is_printed_with_its_line() {
    let s = Setup::new(&[("back-door-north", "display-name", "Back Door North")]);
    s.file("sub/cams.txt", b"x\ny\nBack Door North\n");
    let o = s.scan_relative(&["sub"]);
    assert_eq!(o.status.code(), Some(1), "{}", err(&o));
    assert_eq!(out(&o), "back-door-north display-name sub/cams.txt:3\n");
}
