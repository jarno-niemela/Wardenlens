//! End-to-end fail-closed tests of the on-demand reader of old trees (`wardenlens vault scan
//! --range`, ticket #128): an old subtree below a new root is read through a `cat-file` process
//! started on first use, and whatever goes wrong there must end the scan with exit 2, never with
//! a pass. Temporary repositories and a temporary HOME with synthetic values only.

#![expect(
    clippy::unwrap_used,
    reason = "integration-test helpers outside #[test] fns; clippy.toml in-tests allowances do not reach them"
)]

use std::io::Write;
use std::path::Path;
use std::process::{Command, Output, Stdio};

use tempfile::TempDir;

const SECRET: &str = "zq-synthetic-mark-7781";
const OTHER: &str = "zq-second-mark-4402";
/// A synthetic value with a slash: a path made of two directory names spells it.
const SLASHED: &str = "zqsplit-part/mark-7781";

fn out(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn err(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

fn code(o: &Output) -> i32 {
    o.status.code().unwrap()
}

struct Setup {
    home: TempDir,
    repo: TempDir,
    /// A directory on PATH with a no-op `cargo`, so the staged pre-commit's fmt/clippy lines pass.
    fakebin: TempDir,
}

impl Setup {
    fn new() -> Self {
        let s = Self {
            home: tempfile::tempdir().unwrap(),
            repo: tempfile::tempdir().unwrap(),
            fakebin: tempfile::tempdir().unwrap(),
        };
        assert!(s.vault(&["init"], "").status.success());
        for (id, value) in [("tok:a", SECRET), ("tok:b", OTHER), ("tok:c", SLASHED)] {
            assert!(
                s.vault(&["set", id, "--kind", "secret"], value)
                    .status
                    .success()
            );
        }
        s.git(&["init", "-q", "-b", "main"]);
        s
    }

    fn path_var(&self) -> std::ffi::OsString {
        let mut p = self.fakebin.path().as_os_str().to_owned();
        p.push(":");
        p.push(std::env::var_os("PATH").unwrap());
        p
    }

    fn wardenlens(&self) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_wardenlens"));
        c.env_clear()
            .env("HOME", self.home.path())
            .env("PATH", std::env::var_os("PATH").unwrap())
            .current_dir(self.repo.path());
        c
    }

    fn vault(&self, args: &[&str], stdin: &str) -> Output {
        let mut c = self.wardenlens();
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

    fn scan(&self, args: &[&str]) -> Output {
        let mut c = self.wardenlens();
        c.args(["vault", "scan"]).args(args);
        c.stdin(Stdio::null()).output().unwrap()
    }

    fn git_cmd(&self, dir: &Path) -> Command {
        let mut c = Command::new("git");
        c.current_dir(dir)
            .env_clear()
            .env("PATH", self.path_var())
            .env("HOME", self.home.path())
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_AUTHOR_NAME", "A U Thor")
            .env("GIT_AUTHOR_EMAIL", "author@example.invalid")
            .env("GIT_AUTHOR_DATE", "2026-01-01T00:00:00Z")
            .env("GIT_COMMITTER_NAME", "C O Mitter")
            .env("GIT_COMMITTER_EMAIL", "committer@example.invalid")
            .env("GIT_COMMITTER_DATE", "2026-01-01T00:00:00Z")
            .stdin(Stdio::null());
        c
    }

    /// Runs git in the repository; returns the raw output.
    fn git_out(&self, args: &[&str]) -> Output {
        self.git_cmd(self.repo.path()).args(args).output().unwrap()
    }

    fn git(&self, args: &[&str]) -> String {
        let o = self.git_out(args);
        assert!(o.status.success(), "git {args:?}: {}", err(&o));
        String::from_utf8(o.stdout).unwrap().trim().to_owned()
    }

    fn git_stdin(&self, args: &[&str], stdin: &[u8]) -> String {
        let mut child = self
            .git_cmd(self.repo.path())
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(stdin).unwrap();
        let o = child.wait_with_output().unwrap();
        assert!(o.status.success(), "git {args:?}: {}", err(&o));
        String::from_utf8(o.stdout).unwrap().trim().to_owned()
    }

    fn never_prints(o: &Output) {
        for v in [SECRET, OTHER, SLASHED] {
            assert!(!out(o).contains(v), "{}", out(o));
            assert!(!err(o).contains(v), "{}", err(o));
        }
    }

    /// Writes a tree object from raw entries `(mode, name, hex id)` without git's mode checks
    /// (`hash-object --literally`), and returns its id.
    fn raw_tree(&self, entries: &[(&str, &str, &str)]) -> String {
        let mut raw = Vec::new();
        for (mode, name, id) in entries {
            raw.extend_from_slice(mode.as_bytes());
            raw.push(b' ');
            raw.extend_from_slice(name.as_bytes());
            raw.push(0);
            raw.extend(hex(id));
        }
        self.git_stdin(
            &["hash-object", "--literally", "-w", "-t", "tree", "--stdin"],
            &raw,
        )
    }
}

fn hex(id: &str) -> Vec<u8> {
    id.as_bytes()
        .chunks(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

/// `holder` is an OLD tree (published in `c0`); the new commit `c1`'s root only moves it to
/// `moved`, so the walk reaches it through the on-demand reader. Returns `(c0, c1)`.
fn moved_old_tree(s: &Setup, holder: &str) -> (String, String) {
    let t0 = s.raw_tree(&[("40000", "old", holder)]);
    let c0 = s.git(&["commit-tree", &t0, "-m", "old"]);
    let t1 = s.raw_tree(&[("40000", "moved", holder)]);
    let c1 = s.git(&["commit-tree", &t1, "-p", &c0, "-m", "new"]);
    (c0, c1)
}

fn clean_blob(s: &Setup) -> String {
    s.git_stdin(&["hash-object", "-w", "--stdin"], b"clean\n")
}

fn scan_range(s: &Setup, c0: &str, c1: &str) -> Output {
    s.scan(&["--range", &format!("{c0}..{c1}")])
}

fn loose_object(s: &Setup, id: &str) -> std::path::PathBuf {
    let (dir, rest) = id.split_at(2);
    s.repo.path().join(".git/objects").join(dir).join(rest)
}

#[test]
fn control_an_old_subtree_with_a_value_in_a_path_is_read_and_found() {
    let s = Setup::new();
    let blob = clean_blob(&s);
    let leaf = s.raw_tree(&[("100644", &format!("f-{SECRET}.txt"), &blob)]);
    let (c0, c1) = moved_old_tree(&s, &leaf);
    let o = scan_range(&s, &c0, &c1);
    assert_eq!(code(&o), 1, "{}{}", out(&o), err(&o));
    Setup::never_prints(&o);
}

#[test]
fn control_a_clean_old_subtree_passes() {
    let s = Setup::new();
    let blob = clean_blob(&s);
    let leaf = s.raw_tree(&[("100644", "f.txt", &blob)]);
    let (c0, c1) = moved_old_tree(&s, &leaf);
    let o = scan_range(&s, &c0, &c1);
    assert_eq!(code(&o), 0, "{}{}", out(&o), err(&o));
}

#[test]
fn a_blob_behind_a_directory_entry_of_an_old_tree_fails_the_scan_closed() {
    // `x` has a directory mode but its id is a blob. git's own listing only complains on
    // standard error (the tree is old, so it is not walked for the new objects) and exits 0;
    // the on-demand reader gets a blob where a tree was promised and the scan must stop.
    let s = Setup::new();
    let blob = clean_blob(&s);
    let bad = s.raw_tree(&[("40000", "x", &blob)]);
    let (c0, c1) = moved_old_tree(&s, &bad);
    let o = scan_range(&s, &c0, &c1);
    assert_eq!(code(&o), 2, "{}{}", out(&o), err(&o));
    assert!(
        err(&o).contains("is not a well formed git object"),
        "{}",
        err(&o)
    );
    Setup::never_prints(&o);
}

#[test]
fn a_missing_old_tree_fails_the_scan_closed() {
    let s = Setup::new();
    let blob = clean_blob(&s);
    let leaf = s.raw_tree(&[("100644", &format!("f-{SECRET}.txt"), &blob)]);
    let (c0, c1) = moved_old_tree(&s, &leaf);
    let file = loose_object(&s, &leaf);
    assert!(file.is_file(), "control: the old tree is a loose object");
    std::fs::remove_file(&file).unwrap();
    let o = scan_range(&s, &c0, &c1);
    assert_eq!(code(&o), 2, "{}{}", out(&o), err(&o));
    assert!(
        err(&o).contains("an object listed by git is missing"),
        "{}",
        err(&o)
    );
    Setup::never_prints(&o);
}

#[test]
fn a_corrupt_old_tree_fails_the_scan_closed() {
    let s = Setup::new();
    let blob = clean_blob(&s);
    let leaf = s.raw_tree(&[("100644", &format!("f-{SECRET}.txt"), &blob)]);
    let (c0, c1) = moved_old_tree(&s, &leaf);
    let file = loose_object(&s, &leaf);
    std::fs::set_permissions(&file, std::os::unix::fs::PermissionsExt::from_mode(0o644)).unwrap();
    std::fs::write(&file, b"this is not a zlib stream").unwrap();
    let o = scan_range(&s, &c0, &c1);
    assert_eq!(code(&o), 2, "{}{}", out(&o), err(&o));
    Setup::never_prints(&o);
}

#[test]
fn an_old_tree_that_is_a_well_formed_tree_but_not_a_tree_object_is_not_accepted_as_one() {
    // The id of the old "tree" is a commit: same fail-closed end as a blob.
    let s = Setup::new();
    let t = s.raw_tree(&[]);
    let commit = s.git(&["commit-tree", &t, "-m", "not a tree"]);
    let bad = s.raw_tree(&[("40000", "x", &commit)]);
    let (c0, c1) = moved_old_tree(&s, &bad);
    let o = scan_range(&s, &c0, &c1);
    assert_eq!(code(&o), 2, "{}{}", out(&o), err(&o));
    assert!(
        err(&o).contains("is not a well formed git object"),
        "{}",
        err(&o)
    );
    Setup::never_prints(&o);
}
