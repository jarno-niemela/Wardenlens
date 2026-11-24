//! End-to-end tests of `wardenlens vault scan` against a temporary HOME with synthetic values.
//! The environment is cleared first, so nothing of the real home is ever read.

#![expect(
    clippy::unwrap_used,
    reason = "integration-test helpers outside #[test] fns; clippy.toml in-tests allowances do not reach them"
)]

use std::io::Write;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use tempfile::TempDir;

const SECRET: &str = "zq-synthetic-mark-7781";
const HOST: &str = "192.0.2.77";
const MAC: &str = "02:00:5e:00:53:77";

struct Setup {
    home: TempDir,
    work: TempDir,
}

impl Setup {
    /// A HOME with an initialised vault holding a secret, a host, a MAC, a credential and an
    /// entry that is too short to scan.
    fn new() -> Self {
        let s = Self {
            home: tempfile::tempdir().unwrap(),
            work: tempfile::tempdir().unwrap(),
        };
        assert!(s.vault(&["init"], "").status.success());
        for (id, kind, value) in [
            ("tok:a", "secret", SECRET),
            ("cam:a:host", "host", HOST),
            ("cam:a:mac", "mac", MAC),
            (
                "cam:a:credential",
                "credential",
                "svc-reader-account\nPw-synthetic-5521\n",
            ),
            ("tok:short", "secret", "abc"),
        ] {
            let set = s.vault(&["set", id, "--kind", kind], value);
            assert!(
                set.status.success(),
                "{}",
                String::from_utf8_lossy(&set.stderr)
            );
        }
        s
    }

    fn command(&self) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_wardenlens"));
        c.env_clear().env("HOME", self.home.path());
        c
    }

    fn vault(&self, args: &[&str], stdin: &str) -> Output {
        let mut c = self.command();
        c.arg("vault").args(args);
        let mut child = c
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let _ = child.stdin.take().unwrap().write_all(stdin.as_bytes());
        child.wait_with_output().unwrap()
    }

    fn scan(&self, paths: &[&Path]) -> Output {
        let mut c = self.command();
        c.args(["vault", "scan"]).args(paths);
        c.stdin(Stdio::null()).output().unwrap()
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

/// No synthetic value appears anywhere in the output.
fn assert_no_value(o: &Output) {
    let all = format!("{}{}", out(o), err(o));
    for v in [SECRET, HOST, MAC, "Pw-synthetic-5521"] {
        assert!(!all.contains(v), "{v} reached the output: {all}");
    }
}

#[test]
fn a_clean_file_exits_zero_and_a_hit_exits_one_without_printing_the_value() {
    let s = Setup::new();
    let clean = s.file("clean.txt", b"nothing here 198.51.100.1\n");
    let o = s.scan(&[&clean]);
    assert_eq!(o.status.code(), Some(0), "{}", err(&o));
    assert_eq!(out(&o), "");

    let leaky = s.file(
        "leaky.txt",
        format!("line one\nhost {HOST} here\nthe token {SECRET}\nmac 02-00-5E-00-53-77\n")
            .as_bytes(),
    );
    let o = s.scan(&[&leaky]);
    assert_eq!(o.status.code(), Some(1));
    let p = leaky.display();
    assert_eq!(
        out(&o),
        format!("cam:a:host host {p}:2\ntok:a secret {p}:3\ncam:a:mac mac {p}:4\n")
    );
    assert_no_value(&o);
}

#[test]
fn a_password_is_a_hit_and_a_username_is_not() {
    let s = Setup::new();
    let user = s.file("user.txt", b"login svc-reader-account ok\n");
    assert_eq!(s.scan(&[&user]).status.code(), Some(0));
    let pw = s.file("pw.txt", b"x Pw-synthetic-5521 y\n");
    let o = s.scan(&[&pw]);
    assert_eq!(o.status.code(), Some(1));
    assert!(
        out(&o).starts_with("cam:a:credential credential "),
        "{}",
        out(&o)
    );
    assert_no_value(&o);
}

#[test]
fn directories_are_walked_in_order_and_symlinks_inside_are_skipped() {
    let s = Setup::new();
    s.file("tree/b/two.txt", format!("{SECRET}\n").as_bytes());
    s.file("tree/a/one.txt", format!("\n{HOST}\n").as_bytes());
    s.file("tree/c/clean.txt", b"clean\n");
    symlink(
        s.work.path().join("tree/b/two.txt"),
        s.work.path().join("tree/link.txt"),
    )
    .unwrap();
    let tree = s.work.path().join("tree");
    let o = s.scan(&[&tree]);
    assert_eq!(o.status.code(), Some(1));
    let t = tree.display();
    assert_eq!(
        out(&o),
        format!("cam:a:host host {t}/a/one.txt:2\ntok:a secret {t}/b/two.txt:1\n")
    );
    assert!(err(&o).contains("skipped 1 symlink"), "{}", err(&o));
    // A symlink named on the command line is followed.
    let link = tree.join("link.txt");
    assert_eq!(s.scan(&[&link]).status.code(), Some(1));
}

#[test]
fn a_path_that_contains_a_hit_is_never_printed() {
    let s = Setup::new();
    let named = s.file(&format!("{SECRET}.txt"), format!("{SECRET}\n").as_bytes());
    let dir_named = s.file(
        &format!("dir-{HOST}/inner.txt"),
        format!("{SECRET}\n").as_bytes(),
    );
    let clean = s.file("ok.txt", format!("{SECRET}\n").as_bytes());
    let o = s.scan(&[&named, dir_named.parent().unwrap(), &clean]);
    assert_eq!(o.status.code(), Some(1));
    assert_no_value(&o);
    let text = out(&o);
    assert!(text.contains("tok:a secret <redacted-path:0>:1"), "{text}");
    assert!(text.contains("tok:a secret <redacted-path:1>:1"), "{text}");
    assert!(
        text.contains(&format!("tok:a secret {}:1", clean.display())),
        "{text}"
    );

    // The same for a notice and an error: a binary file and an unreadable one with such names.
    let bin = s.file(&format!("{SECRET}.bin"), b"a\0b");
    let gone = s.work.path().join(format!("missing-{SECRET}"));
    let o = s.scan(&[&bin, &gone]);
    assert_eq!(o.status.code(), Some(2));
    assert_no_value(&o);
}

#[test]
fn binary_files_are_skipped_with_a_notice_and_utf16_files_are_scanned() {
    let s = Setup::new();
    let mut bin = format!("{SECRET}\n").into_bytes();
    bin.insert(3, 0);
    let bin = s.file("blob.bin", &bin);
    let o = s.scan(&[&bin]);
    assert_eq!(o.status.code(), Some(0));
    assert!(err(&o).contains("skipped binary file"), "{}", err(&o));

    let mut utf16 = vec![0xFF, 0xFE];
    utf16.extend(
        format!("x\n{SECRET}\n")
            .encode_utf16()
            .flat_map(u16::to_le_bytes),
    );
    let u = s.file("wide.txt", &utf16);
    let o = s.scan(&[&u]);
    assert_eq!(o.status.code(), Some(1));
    assert!(out(&o).contains("tok:a secret"), "{}", out(&o));
    assert!(out(&o).ends_with(":2\n"), "{}", out(&o));
}

#[test]
fn a_file_over_eight_mebibytes_fails_the_scan_and_exactly_eight_passes() {
    let s = Setup::new();
    let limit = 8 * 1024 * 1024;
    let at = s.file("at-limit.txt", &vec![b'x'; limit]);
    assert_eq!(s.scan(&[&at]).status.code(), Some(0));
    let over = s.file("over-limit.txt", &vec![b'x'; limit + 1]);
    let o = s.scan(&[&over]);
    assert_eq!(o.status.code(), Some(2));
    assert!(err(&o).contains("8 MiB"), "{}", err(&o));
    // Hits found elsewhere are still printed, and the exit code is still 2.
    let leaky = s.file("leaky.txt", format!("{SECRET}\n").as_bytes());
    let o = s.scan(&[&leaky, &over]);
    assert_eq!(o.status.code(), Some(2));
    assert!(out(&o).contains("tok:a secret"), "{}", out(&o));
}

#[test]
fn inputs_that_cannot_be_read_fail_the_scan() {
    let s = Setup::new();
    let missing = s.work.path().join("nope.txt");
    assert_eq!(s.scan(&[&missing]).status.code(), Some(2));
    let fifo = s.work.path().join("fifo");
    assert!(
        Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success()
    );
    let o = s.scan(&[&fifo]);
    assert_eq!(o.status.code(), Some(2), "a FIFO must not hang the scan");
    assert!(err(&o).contains("not a regular file"), "{}", err(&o));
    let locked = s.file("locked.txt", b"x");
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
    // Root can read it anyway; only assert when the mode is honoured.
    if std::fs::read(&locked).is_err() {
        assert_eq!(s.scan(&[&locked]).status.code(), Some(2));
    }
}

#[test]
fn a_vault_or_key_that_cannot_be_used_means_exit_two_never_a_pass() {
    let leaky = |s: &Setup| s.file("leaky.txt", format!("{SECRET}\n").as_bytes());

    let no_vault = Setup {
        home: tempfile::tempdir().unwrap(),
        work: tempfile::tempdir().unwrap(),
    };
    let f = leaky(&no_vault);
    let o = no_vault.scan(&[&f]);
    assert_eq!(o.status.code(), Some(2));
    assert!(err(&o).contains("the scan could not run"), "{}", err(&o));

    let s = Setup::new();
    let f = leaky(&s);
    let key = s.home.path().join(".config/wardenlens/dev-vault.key");
    let good = std::fs::read(&key).unwrap();
    std::fs::write(&key, [7u8; 32]).unwrap();
    assert_eq!(s.scan(&[&f]).status.code(), Some(2), "wrong key");
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(
        s.scan(&[&f]).status.code(),
        Some(2),
        "loose key permissions"
    );
    std::fs::remove_file(&key).unwrap();
    assert_eq!(s.scan(&[&f]).status.code(), Some(2), "missing key");
    std::fs::write(&key, good).unwrap();
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(s.scan(&[&f]).status.code(), Some(1), "restored key");

    let mut c = s.command();
    c.env_remove("HOME");
    let o = c.args(["vault", "scan"]).arg(&f).output().unwrap();
    assert_eq!(o.status.code(), Some(2), "no HOME");
}

#[test]
fn no_path_is_a_usage_error() {
    let s = Setup::new();
    let o = s.command().args(["vault", "scan"]).output().unwrap();
    assert_eq!(o.status.code(), Some(2));
}

#[test]
fn unscannable_entries_are_listed_by_id_on_every_scan() {
    let s = Setup::new();
    let clean = s.file("clean.txt", b"abc\n");
    let o = s.scan(&[&clean]);
    assert_eq!(o.status.code(), Some(0));
    assert!(
        err(&o).contains("tok:short (secret) is unscannable"),
        "{}",
        err(&o)
    );
    assert!(!out(&o).contains("abc"));
}

#[test]
fn an_empty_directory_scans_zero_files_and_passes() {
    let s = Setup::new();
    let d = s.work.path().join("empty");
    std::fs::create_dir(&d).unwrap();
    let o = s.scan(&[&d]);
    assert_eq!(o.status.code(), Some(0));
    assert!(err(&o).contains("scanned 0 file(s)"), "{}", err(&o));
}

#[test]
fn the_key_variable_makes_a_scan_exit_two() {
    let s = Setup::new();
    let f = s.file("leaky.txt", format!("{SECRET}\n").as_bytes());
    let o = s
        .command()
        .env("WARDENLENS_VAULT_KEY", "x")
        .args(["vault", "scan"])
        .arg(&f)
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(2));
    assert_no_value(&o);
}

#[test]
fn a_large_binary_file_is_skipped_and_a_large_text_file_is_refused() {
    let s = Setup::new();
    let size = 9 * 1024 * 1024;
    let mut blob = vec![b'x'; size];
    blob[0] = 0;
    let blob = s.file("big.bin", &blob);
    let o = s.scan(&[&blob]);
    assert_eq!(o.status.code(), Some(0), "{}", err(&o));
    assert!(err(&o).contains("skipped binary file"), "{}", err(&o));
    // A NUL after the probe window does not make a file binary.
    let mut late = vec![b'x'; size];
    late[8 * 1024] = 0;
    let late = s.file("big-late-nul.txt", &late);
    assert_eq!(s.scan(&[&late]).status.code(), Some(2));
    // UTF-16 with a byte order mark is text, so it is refused over the limit even with NULs.
    let mut wide = vec![0xFF, 0xFE];
    wide.resize(size, 0);
    let wide = s.file("big-wide.txt", &wide);
    assert_eq!(s.scan(&[&wide]).status.code(), Some(2));
    let text = s.file("big.txt", &vec![b'x'; size]);
    let o = s.scan(&[&text]);
    assert_eq!(o.status.code(), Some(2));
    assert!(err(&o).contains("8 MiB"), "{}", err(&o));
}

#[test]
fn a_fifo_found_while_walking_is_counted_and_not_opened() {
    let s = Setup::new();
    s.file("dir/ok.txt", b"x\n");
    let fifo = s.work.path().join("dir/pipe");
    assert!(
        Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success()
    );
    let o = s.scan(&[&s.work.path().join("dir")]);
    assert_eq!(o.status.code(), Some(0), "{}", err(&o));
    assert!(err(&o).contains("1 special file(s)"), "{}", err(&o));
}

#[test]
fn many_binary_files_are_summarised_after_twenty_notices() {
    let s = Setup::new();
    for i in 0..25 {
        s.file(&format!("bin/b{i:02}.bin"), b"a\0b");
    }
    let o = s.scan(&[&s.work.path().join("bin")]);
    assert_eq!(o.status.code(), Some(0), "{}", err(&o));
    let e = err(&o);
    assert_eq!(e.matches("skipped binary file").count(), 20, "{e}");
    assert!(e.contains("25 binary files skipped in all"), "{e}");
    // Exactly at the limit there is no summary.
    let s = Setup::new();
    for i in 0..20 {
        s.file(&format!("bin/b{i:02}.bin"), b"a\0b");
    }
    let e = err(&s.scan(&[&s.work.path().join("bin")]));
    assert_eq!(e.matches("skipped binary file").count(), 20, "{e}");
    assert!(!e.contains("in all"), "{e}");
}

#[test]
fn nesting_beyond_the_depth_limit_exits_two() {
    let s = Setup::new();
    let mut deep = PathBuf::from("deep");
    for _ in 0..70 {
        deep.push("d");
    }
    s.file(&format!("{}/leaf.txt", deep.display()), b"x\n");
    let o = s.scan(&[&s.work.path().join("deep")]);
    assert_eq!(o.status.code(), Some(2), "{}", err(&o));
    assert!(
        err(&o).contains("nested deeper than the walk limit"),
        "{}",
        err(&o)
    );
}

#[test]
fn control_characters_in_a_path_are_escaped_not_printed() {
    let s = Setup::new();
    // A file name that would forge a second report line and clear the screen.
    let name = "a\nforged secret line\u{1b}[2J\u{85}\u{2028}x.txt";
    let f = s.file(name, format!("{SECRET}\n").as_bytes());
    let o = s.scan(&[&f]);
    assert_eq!(o.status.code(), Some(1));
    assert_no_value(&o);
    let text = out(&o);
    assert_eq!(text.lines().count(), 1, "{text:?}");
    for bad in ['\u{1b}', '\u{85}', '\u{2028}'] {
        assert!(!text.contains(bad), "{text:?}");
    }
    assert!(text.contains("\\u{a}forged"), "{text:?}");
    let missing = s.work.path().join("gone\r\nerror: forged\u{7f}");
    let o = s.scan(&[&missing]);
    assert_eq!(o.status.code(), Some(2));
    let e = err(&o);
    assert!(!e.contains('\r') && !e.contains('\u{7f}'), "{e:?}");
    let forged: Vec<&str> = e.lines().filter(|l| l.contains("forged")).collect();
    assert_eq!(forged.len(), 1, "{e:?}");
    assert!(forged[0].starts_with("error: "), "{e:?}");
}
