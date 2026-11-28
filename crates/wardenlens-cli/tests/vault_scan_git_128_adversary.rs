//! Adversarial end-to-end tests (#128) of the walk bounds of `wardenlens vault scan --range`:
//! crafted repeating trees (new, old, files, tagged) must end the scan with exit 2 and never
//! print the value. Temporary repositories and a temporary HOME with synthetic values only.

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

/// A crafted repeating tree: `levels` trees, each with two directories of 100-byte names that
/// both lead to the next level (2^levels paths). The top directory's name holds the value, so
/// every path below hits. Returns the top tree.
fn repeating_tree(s: &Setup, levels: usize) -> String {
    let a = "a".repeat(100);
    let b = "b".repeat(100);
    let mut next = s.raw_tree(&[]);
    for _ in 0..levels {
        next = s.raw_tree(&[("40000", &a, &next), ("40000", &b, &next)]);
    }
    s.raw_tree(&[("40000", &format!("d-{SECRET}"), &next)])
}

#[test]
fn a_new_repeating_tree_of_long_paths_is_refused_with_exit_2_and_no_name() {
    let s = Setup::new();
    let c0 = s.git(&["commit-tree", &s.raw_tree(&[]), "-m", "base"]);
    let top = repeating_tree(&s, 38);
    let c1 = s.git(&["commit-tree", &top, "-p", &c0, "-m", "bomb"]);
    let o = scan_range(&s, &c0, &c1);
    assert_eq!(code(&o), 2, "{}{}", out(&o), err(&o));
    assert!(err(&o).contains("too many"), "{}", err(&o));
    assert!(
        out(&o).len() + err(&o).len() < 4096,
        "a refusal stays short"
    );
    Setup::never_prints(&o);
}

#[test]
fn an_old_repeating_tree_reached_through_the_reader_is_refused_with_exit_2() {
    let s = Setup::new();
    let top = repeating_tree(&s, 38);
    let (c0, c1) = moved_old_tree(&s, &top);
    let o = scan_range(&s, &c0, &c1);
    assert_eq!(code(&o), 2, "{}{}", out(&o), err(&o));
    Setup::never_prints(&o);
}

#[test]
fn a_repeating_tree_of_files_is_refused_with_exit_2() {
    // Blobs are charged twice (visited set and blob paths): many files at long paths.
    let s = Setup::new();
    let blob = clean_blob(&s);
    let names: Vec<String> = (0..64).map(|i| format!("{i:0>100}")).collect();
    let mut entries: Vec<(&str, &str, &str)> = names
        .iter()
        .map(|n| ("100644", n.as_str(), blob.as_str()))
        .collect();
    let leaf = s.raw_tree(&entries);
    let a = "a".repeat(100);
    let b = "b".repeat(100);
    let mut next = leaf;
    for _ in 0..30 {
        next = s.raw_tree(&[("40000", &a, &next), ("40000", &b, &next)]);
    }
    entries.clear();
    let c0 = s.git(&["commit-tree", &s.raw_tree(&[]), "-m", "base"]);
    let c1 = s.git(&["commit-tree", &next, "-p", &c0, "-m", "files"]);
    let o = scan_range(&s, &c0, &c1);
    assert_eq!(code(&o), 2, "{}{}", out(&o), err(&o));
}

#[test]
fn a_tag_of_a_repeating_tree_is_refused_with_exit_2() {
    // A tree only a tag points at is a root too, and is bounded the same way.
    let s = Setup::new();
    let c0 = s.git(&["commit-tree", &s.raw_tree(&[]), "-m", "base"]);
    let top = repeating_tree(&s, 38);
    let tag = s.git_stdin(
        &["mktag"],
        format!("object {top}\ntype tree\ntag t1\ntagger T <t@example.invalid> 0 +0000\n\nt\n")
            .as_bytes(),
    );
    let o = scan_range(&s, &c0, &tag);
    assert_eq!(code(&o), 2, "{}{}", out(&o), err(&o));
    Setup::never_prints(&o);
}
