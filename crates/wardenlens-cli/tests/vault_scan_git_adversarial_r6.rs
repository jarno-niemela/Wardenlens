//! Round-6 adversarial tests of `wardenlens vault scan --range`: tree entry mode classification
//! and lazy fetch in partial clones. Temporary repositories and a temporary HOME with
//! synthetic values only.

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

    fn write(&self, name: &str, text: &str) {
        let p = self.repo.path().join(name);
        if let Some(d) = p.parent() {
            std::fs::create_dir_all(d).unwrap();
        }
        std::fs::write(p, text).unwrap();
    }

    fn commit(&self, message: &str) -> String {
        self.git(&["add", "-A"]);
        // Fixture commits never run the hooks under test (they are pre-push fixtures).
        self.git(&[
            "-c",
            "core.hooksPath=/dev/null",
            "commit",
            "-q",
            "--allow-empty",
            "-m",
            message,
        ]);
        self.git(&["rev-parse", "HEAD"])
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

fn split(v: &str) -> (&str, &str) {
    v.split_once('/').unwrap()
}

// ---------------------------------------------------------------------------------------------

/// A base commit, then a commit whose root has one entry `name` with `mode` pointing at `id`.
fn commit_one(s: &Setup, mode: &str, name: &str, id: &str) -> (String, String) {
    s.write("base.txt", "base\n");
    let base = s.commit("base");
    let tree = s.raw_tree(&[(mode, name, id)]);
    let c = s.git(&["commit-tree", &tree, "-p", &base, "-m", "odd mode"]);
    (base, c)
}

fn leaf_with_secret_name(s: &Setup) -> String {
    let blob = s.git_stdin(&["hash-object", "-w", "--stdin"], b"clean\n");
    s.raw_tree(&[("100644", &format!("f-{SECRET}.txt"), &blob)])
}

fn range(base: &str, c: &str) -> String {
    format!("{base}..{c}")
}

// ---------------------------------------------------------------------------------------------
// Claim: every mode git walks as a directory is walked, or the scan fails closed.
// ---------------------------------------------------------------------------------------------

#[test]
fn directory_modes_within_the_length_bound_are_walked() {
    for mode in [
        "40000", "040000", "0040000", "40777", "47777", "0047777", "40001",
    ] {
        let s = Setup::new();
        let leaf = leaf_with_secret_name(&s);
        let (base, c) = commit_one(&s, mode, "dir", &leaf);
        assert_eq!(
            s.git(&["ls-tree", "-r", "--name-only", &c]),
            format!("dir/f-{SECRET}.txt"),
            "control: git walks {mode}"
        );
        let o = s.scan(&["--range", &range(&base, &c)]);
        assert_eq!(code(&o), 1, "mode {mode}: {}{}", out(&o), err(&o));
        Setup::never_prints(&o);
    }
}

#[test]
fn directory_modes_git_accepts_but_the_scan_rejects_fail_closed() {
    // Git's get_mode has no length limit and shifts in unsigned arithmetic, so a zero-padded or
    // wrapping mode is still a directory to git; the scan must not pass it silently.
    for mode in [
        "00040000",
        "0000000000000040000",
        // 1 << 33 plus 0o40000: wraps to 0o40000 in git's 32-bit unsigned.
        "100000000040000",
    ] {
        let s = Setup::new();
        let leaf = leaf_with_secret_name(&s);
        let (base, c) = commit_one(&s, mode, "dir", &leaf);
        let o = s.scan(&["--range", &range(&base, &c)]);
        assert_ne!(code(&o), 0, "mode {mode} passed: {}{}", out(&o), err(&o));
        Setup::never_prints(&o);
    }
}

#[test]
fn unknown_type_modes_fail_closed_never_pass_as_a_file() {
    for mode in [
        "60000", "20000", "10000", "140000", "170000", "0", "000000", "30000",
    ] {
        let s = Setup::new();
        let leaf = leaf_with_secret_name(&s);
        let (base, c) = commit_one(&s, mode, "dir", &leaf);
        let o = s.scan(&["--range", &range(&base, &c)]);
        assert_eq!(code(&o), 2, "mode {mode}: {}{}", out(&o), err(&o));
        Setup::never_prints(&o);
    }
}

#[test]
fn unparsable_modes_fail_closed() {
    for mode in ["10064x", "100689", "+100644", " 100644", "1006440 "] {
        let s = Setup::new();
        let blob = s.git_stdin(&["hash-object", "-w", "--stdin"], b"clean\n");
        let (base, c) = commit_one(&s, mode, "f.txt", &blob);
        let o = s.scan(&["--range", &range(&base, &c)]);
        assert_ne!(code(&o), 0, "mode {mode:?}: {}{}", out(&o), err(&o));
    }
}

#[test]
fn an_old_subtree_holding_a_non_canonical_directory_mode_is_walked_when_moved() {
    // The 40755 entry is inside an OLD tree reached through the loader, not a new root.
    let s = Setup::new();
    let (outer, inner) = split(SLASHED);
    s.write("base.txt", "base\n");
    let base0 = s.commit("base0");
    let blob = s.git_stdin(&["hash-object", "-w", "--stdin"], b"clean\n");
    let leaf = s.raw_tree(&[("100644", "f.txt", &blob)]);
    let holder = s.raw_tree(&[("40755", inner, &leaf)]);
    let top = s.raw_tree(&[("40000", "holder", &holder)]);
    let base = s.git(&["commit-tree", &top, "-p", &base0, "-m", "published"]);
    let top2 = s.raw_tree(&[("40000", outer, &holder)]);
    let c = s.git(&["commit-tree", &top2, "-p", &base, "-m", "mv"]);
    assert_eq!(
        s.git(&["ls-tree", "-r", "--name-only", &c]),
        format!("{SLASHED}/f.txt")
    );
    let o = s.scan(&["--range", &range(&base, &c)]);
    assert_eq!(code(&o), 1, "{}{}", out(&o), err(&o));
    Setup::never_prints(&o);
}

#[test]
fn blob_content_below_a_non_canonical_directory_mode_is_scanned() {
    let s = Setup::new();
    s.write("base.txt", "base\n");
    let base = s.commit("base");
    let blob = s.git_stdin(
        &["hash-object", "-w", "--stdin"],
        format!("x {SECRET} y\n").as_bytes(),
    );
    let leaf = s.raw_tree(&[("100644", "f.txt", &blob)]);
    let tree = s.raw_tree(&[("40711", "dir", &leaf)]);
    let c = s.git(&["commit-tree", &tree, "-p", &base, "-m", "odd"]);
    let o = s.scan(&["--range", &range(&base, &c)]);
    assert_eq!(code(&o), 1, "{}{}", out(&o), err(&o));
    Setup::never_prints(&o);
}

// ---------------------------------------------------------------------------------------------
// Claim: file, symlink and gitlink modes (canonical and not) still have their paths scanned.
// ---------------------------------------------------------------------------------------------

#[test]
fn file_symlink_and_gitlink_entries_spelling_a_value_are_found() {
    for mode in [
        "100644", "100755", "100664", "100600", "0100644", "120000", "120777",
    ] {
        let s = Setup::new();
        let blob = s.git_stdin(&["hash-object", "-w", "--stdin"], b"clean\n");
        let (base, c) = commit_one(&s, mode, &format!("f-{SECRET}"), &blob);
        let o = s.scan(&["--range", &range(&base, &c)]);
        assert_eq!(code(&o), 1, "mode {mode}: {}{}", out(&o), err(&o));
        Setup::never_prints(&o);
    }
    for mode in ["160000", "160755"] {
        let s = Setup::new();
        // A gitlink id names a commit of another repository: it need not exist here.
        let (base, c) = commit_one(
            &s,
            mode,
            &format!("sub-{SECRET}"),
            "0123456789abcdef0123456789abcdef01234567",
        );
        let o = s.scan(&["--range", &range(&base, &c)]);
        assert_eq!(code(&o), 1, "mode {mode}: {}{}", out(&o), err(&o));
        Setup::never_prints(&o);
    }
}

#[test]
fn a_clean_canonical_tree_still_passes() {
    let s = Setup::new();
    let blob = s.git_stdin(&["hash-object", "-w", "--stdin"], b"clean\n");
    let leaf = s.raw_tree(&[("100755", "run.sh", &blob), ("120000", "link", &blob)]);
    let (base, c) = commit_one(&s, "40000", "dir", &leaf);
    let o = s.scan(&["--range", &range(&base, &c)]);
    assert_eq!(code(&o), 0, "{}{}", out(&o), err(&o));
}

// ---------------------------------------------------------------------------------------------
// Claim: GIT_NO_LAZY_FETCH=1: a missing object in a partial clone fails the scan closed and is
// never fetched.
// ---------------------------------------------------------------------------------------------

fn partial_clone_scan(filter: bool) -> (Output, bool) {
    let s = Setup::new();
    s.write("base.txt", "base\n");
    s.commit("base");
    s.write("new.txt", &format!("x {SECRET}\n"));
    s.commit("new");
    s.git(&["config", "uploadpack.allowFilter", "true"]);
    s.git(&["config", "uploadpack.allowAnySHA1InWant", "true"]);
    let clone = s.home.path().join("clone");
    let url = format!("file://{}", s.repo.path().display());
    let o = s
        .git_cmd(s.home.path())
        .args(["clone", "-q", "--no-checkout"])
        .args(if filter {
            &["--filter=blob:none"][..]
        } else {
            &[][..]
        })
        .arg(&url)
        .arg(&clone)
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", err(&o));
    let blob = s.git(&["rev-parse", "HEAD:new.txt"]);
    let missing = |s: &Setup| {
        !s.git_cmd(&clone)
            .env("GIT_NO_LAZY_FETCH", "1")
            .args(["cat-file", "-e", &blob])
            .output()
            .unwrap()
            .status
            .success()
    };
    assert_eq!(
        missing(&s),
        filter,
        "control: the blob is only missing in the partial clone"
    );
    let mut c = Command::new(env!("CARGO_BIN_EXE_wardenlens"));
    c.env_clear()
        .env("HOME", s.home.path())
        .env("PATH", std::env::var_os("PATH").unwrap())
        .current_dir(&clone)
        .args(["vault", "scan", "--range", "HEAD~1..HEAD"])
        .stdin(Stdio::null());
    let o = c.output().unwrap();
    let still_missing = missing(&s);
    (o, still_missing)
}

#[test]
fn control_a_full_clone_finds_the_value_in_the_range() {
    let (o, _) = partial_clone_scan(false);
    assert_eq!(code(&o), 1, "{}{}", out(&o), err(&o));
    Setup::never_prints(&o);
}

#[test]
fn a_partial_clone_with_a_missing_blob_fails_closed_without_fetching() {
    let (o, still_missing) = partial_clone_scan(true);
    assert_eq!(code(&o), 2, "{}{}", out(&o), err(&o));
    Setup::never_prints(&o);
    assert!(still_missing, "the scan lazily fetched the blob");
}
