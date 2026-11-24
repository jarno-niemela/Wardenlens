//! Adversary tests of `wardenlens vault scan`, #75 round 2 (ADR 0006 sections 7 and 8).
//! Synthetic values only; the environment is cleared and HOME is a temporary directory.

#![expect(
    clippy::unwrap_used,
    reason = "integration-test helpers outside #[test] fns; clippy.toml in-tests allowances do not reach them"
)]

use std::fs::File;
use std::io::Write;
use std::os::unix::fs::symlink;
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

    fn scan_cmd(&self, paths: &[&Path]) -> Command {
        let mut c = self.command();
        c.args(["vault", "scan"]).args(paths).stdin(Stdio::null());
        c
    }

    fn scan(&self, paths: &[&Path]) -> Output {
        self.scan_cmd(paths).output().unwrap()
    }

    fn file(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let p = self.work.path().join(name);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, bytes).unwrap();
        p
    }
}

fn out(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn err(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

/// ADR 0006 section 8: `path:line` is printed for a clean path. An entry id that is the slug of
/// its own display name (`back-door-north` for `Back Door North`, the natural naming) is printed
/// on every hit line anyway; it must not make every clean path of every hit `<redacted-path>`.
#[test]
fn an_id_that_spells_its_display_name_does_not_hide_clean_locations() {
    let s = Setup::new(&[
        ("back-door-north", "display-name", "Back Door North"),
        ("tok:a", "secret", SECRET),
    ]);
    let f = s.file("notes.txt", format!("x\nthe token {SECRET}\n").as_bytes());
    let o = s.scan(&[&f]);
    assert_eq!(o.status.code(), Some(1), "{}", err(&o));
    assert_eq!(
        out(&o),
        format!("tok:a secret {}:2\n", f.display()),
        "a clean path was redacted"
    );
    let g = s.file("cams.txt", b"x\ncamera Back Door North\n");
    let o = s.scan(&[&g]);
    assert_eq!(o.status.code(), Some(1), "{}", err(&o));
    assert_eq!(
        out(&o),
        format!("back-door-north display-name {}:2\n", g.display()),
        "a clean path was redacted"
    );
}

/// Unread inputs together with hits exit 2, and the hits are still printed.
#[test]
fn hits_with_an_unread_input_exit_two_and_still_print_the_hits() {
    let s = Setup::new(&[("tok:a", "secret", SECRET)]);
    let f = s.file("leak.txt", format!("{SECRET}\n").as_bytes());
    let missing = s.work.path().join("missing.txt");
    let o = s.scan(&[&f, &missing]);
    assert_eq!(o.status.code(), Some(2), "{}", err(&o));
    assert_eq!(out(&o), format!("tok:a secret {}:1\n", f.display()));
    // Order reversed: the unread input first.
    let o = s.scan(&[&missing, &f]);
    assert_eq!(o.status.code(), Some(2), "{}", err(&o));
    assert_eq!(out(&o), format!("tok:a secret {}:1\n", f.display()));
}

/// An output error is never a hit and never a pass: stdout or stderr on a full device exits 2.
#[test]
fn an_output_error_exits_two() {
    let s = Setup::new(&[("tok:a", "secret", SECRET)]);
    let f = s.file("leak.txt", format!("{SECRET}\n").as_bytes());
    let o = s
        .scan_cmd(&[&f])
        .stdout(File::create("/dev/full").unwrap())
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(2), "{}", err(&o));
    let clean = s.file("clean.txt", b"nothing\n");
    let o = s
        .scan_cmd(&[&clean])
        .stdout(Stdio::piped())
        .stderr(File::create("/dev/full").unwrap())
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(2));
}

/// Binary classification boundaries for a file over 8 MiB: a NUL at the last byte of the probe
/// window is binary (skipped, exit 0); one byte later it is text (refused, exit 2).
#[test]
fn the_probe_window_is_exact_for_large_files() {
    let s = Setup::new(&[("tok:a", "secret", SECRET)]);
    let size = 8 * 1024 * 1024 + 1;
    let mut last = vec![b'x'; size];
    last[8 * 1024 - 1] = 0;
    let last = s.file("last.bin", &last);
    let o = s.scan(&[&last]);
    assert_eq!(o.status.code(), Some(0), "{}", err(&o));
    assert!(err(&o).contains("skipped binary file"), "{}", err(&o));
    // A large binary file holding the value is still only skipped (ADR gap 5), never read.
    let mut leaky = format!("\0{SECRET}").into_bytes();
    leaky.resize(size, b'x');
    let leaky = s.file("leaky.bin", &leaky);
    assert_eq!(s.scan(&[&leaky]).status.code(), Some(0));
    // A small file is classified the same way.
    let mut small = vec![b'x'; 8 * 1024 + 10];
    small[8 * 1024] = 0;
    small.extend_from_slice(SECRET.as_bytes());
    let small = s.file("small.txt", &small);
    assert_eq!(s.scan(&[&small]).status.code(), Some(1));
}

/// A text file that is exactly 8 MiB with the value at its very end is read to the last byte.
#[test]
fn the_last_bytes_of_an_eight_mebibyte_text_file_are_scanned() {
    let s = Setup::new(&[("tok:a", "secret", SECRET)]);
    let mut text = vec![b'x'; 8 * 1024 * 1024 - SECRET.len() - 1];
    text.push(b' ');
    text.extend_from_slice(SECRET.as_bytes());
    assert_eq!(text.len(), 8 * 1024 * 1024);
    let f = s.file("edge.txt", &text);
    let o = s.scan(&[&f]);
    assert_eq!(o.status.code(), Some(1), "{}", err(&o));
}

/// A symlink named on the command line that points to a FIFO is refused, not opened for a
/// blocking read.
#[test]
fn an_explicit_symlink_to_a_fifo_is_refused() {
    let s = Setup::new(&[("tok:a", "secret", SECRET)]);
    let fifo = s.work.path().join("pipe");
    assert!(
        Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success()
    );
    let link = s.work.path().join("link");
    symlink(&fifo, &link).unwrap();
    let o = s.scan(&[&link]);
    assert_eq!(o.status.code(), Some(2), "{}", err(&o));
    assert!(err(&o).contains("not a regular file"), "{}", err(&o));
}

/// ADR 0006 section 8: invisible and bidirectional formatting characters in a path are printed
/// as escapes. The arabic letter mark (U+061C, a bidi control), the word joiner and the
/// invisible operators (U+2060 to U+2064) and the soft hyphen (U+00AD) are invisible.
#[test]
fn invisible_and_bidi_formatting_characters_in_a_path_are_escaped() {
    let s = Setup::new(&[("tok:a", "secret", SECRET)]);
    let mut raw = Vec::new();
    for c in ['\u{061C}', '\u{2060}', '\u{2064}', '\u{00AD}'] {
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

/// A display name holding a narrow no-break space (valid: not a control character), present
/// verbatim in a file, is found end to end.
#[test]
fn a_display_name_with_a_narrow_no_break_space_is_found_end_to_end() {
    let s = Setup::new(&[("cam:a:name", "display-name", "Back\u{202F}Door North")]);
    for (name, text) in [
        ("v.txt", "x\nBack\u{202F}Door North\n"),
        ("s.txt", "x\nback door   north\n"),
        ("j.json", "x\n{\"n\":\"Back\\u202fDoor North\"}\n"),
    ] {
        let f = s.file(name, text.as_bytes());
        let o = s.scan(&[&f]);
        assert_eq!(o.status.code(), Some(1), "{text:?} {}", err(&o));
        assert_eq!(
            out(&o),
            format!("cam:a:name display-name {}:2\n", f.display())
        );
    }
}

/// The same for a host and a serial whose id holds the value (ids allow `.`, `-` and `:`).
#[test]
fn an_id_that_holds_its_host_or_serial_does_not_hide_clean_locations() {
    let s = Setup::new(&[
        ("nvr-1.example.invalid", "host", "nvr-1.example.invalid"),
        ("cam:sn-0042-zq", "serial", "SN-0042-ZQ"),
    ]);
    let f = s.file(
        "cfg.txt",
        b"url http://nvr-1.example.invalid/\nserial SN0042ZQ\n",
    );
    let o = s.scan(&[&f]);
    assert_eq!(o.status.code(), Some(1), "{}", err(&o));
    let p = f.display();
    assert_eq!(
        out(&o),
        format!("nvr-1.example.invalid host {p}:1\ncam:sn-0042-zq serial {p}:2\n"),
        "a clean path was redacted"
    );
}
