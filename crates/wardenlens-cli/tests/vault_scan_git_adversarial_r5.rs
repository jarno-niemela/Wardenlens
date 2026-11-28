//! Round-5 adversarial tests of `wardenlens vault scan --range`: the walk of every subtree
//! below a new root, old ones included. Temporary repositories and a temporary HOME with
//! synthetic values only.

#![expect(
    clippy::unwrap_used,
    reason = "integration-test helpers outside #[test] fns; clippy.toml in-tests allowances do not reach them"
)]

use std::io::Write;
use std::path::{Path, PathBuf};
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

    /// Installs the staged hooks (as the README says, by copying) and the real binary at the
    /// fixed path `$HOME/.cargo/bin/wardenlens`; a bare remote `origin` with `main` pushed.
    fn with_hooks(&self) -> PathBuf {
        let staged = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/hooks-staged");
        let hooks = self.home.path().join("hooks");
        std::fs::create_dir_all(&hooks).unwrap();
        for h in ["pre-commit", "pre-push"] {
            std::fs::copy(staged.join(h), hooks.join(h)).unwrap();
        }
        let bin = self.home.path().join(".cargo/bin");
        std::fs::create_dir_all(&bin).unwrap();
        // Hermetic: the binary cargo built for this test (this commit), copied into the
        // temporary HOME, never an installed copy.
        std::fs::copy(env!("CARGO_BIN_EXE_wardenlens"), bin.join("wardenlens")).unwrap();
        let cargo = self.fakebin.path().join("cargo");
        std::fs::write(&cargo, "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&cargo, std::os::unix::fs::PermissionsExt::from_mode(0o755))
            .unwrap();
        let remote = self.home.path().join("remote.git");
        let o = self
            .git_cmd(self.home.path())
            .args(["init", "-q", "--bare", "-b", "main"])
            .arg(&remote)
            .output()
            .unwrap();
        assert!(o.status.success());
        self.git(&["remote", "add", "origin", remote.to_str().unwrap()]);
        self.write("base.txt", "base\n");
        self.commit("base");
        self.git(&["push", "-q", "origin", "main"]);
        self.git(&["config", "core.hooksPath", hooks.to_str().unwrap()]);
        self.git(&["checkout", "-q", "-b", "feat/x"]);
        remote
    }

    fn remote_has(&self, remote: &Path, object: &str) -> bool {
        self.git_cmd(remote)
            .args(["cat-file", "-e", object])
            .output()
            .unwrap()
            .status
            .success()
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
// Claim: "every full path that appears in any tree reachable from a new root is scanned". Git
// decides what a tree entry is by the file-type bits of its octal mode (`S_ISDIR`), not by the
// exact text `40000`: an entry with mode `40755` is a directory to git (`ls-tree -r`, checkout,
// `rev-list --objects` and the remote all descend into it), and fsck only warns
// (`badFilemode`). The walk classifies a mode as git does (octal, file-type bits), so such an
// entry is descended into like `40000`; these tests pin that.
// ---------------------------------------------------------------------------------------------

/// A base commit with `holder/{inner}/f.txt` (published), then a commit whose root holds the
/// old `holder` tree under `outer` with the directory mode `mode`.
fn commit_with_dir_mode(s: &Setup, outer: &str, inner: &str, mode: &str) -> (String, String) {
    s.write(&format!("holder/{inner}/f.txt"), "clean\n");
    let base = s.commit("base");
    let old = s.git(&["rev-parse", "HEAD:holder"]);
    let tree = s.raw_tree(&[(mode, outer, &old)]);
    let c = s.git(&["commit-tree", &tree, "-p", &base, "-m", "odd mode"]);
    (base, c)
}

#[test]
fn control_git_itself_lists_paths_below_a_40755_directory_entry() {
    let s = Setup::new();
    let (outer, inner) = split(SLASHED);
    let (_, c) = commit_with_dir_mode(&s, outer, inner, "40755");
    let listed = s.git(&["ls-tree", "-r", "--name-only", &c]);
    assert_eq!(listed, format!("{SLASHED}/f.txt"));
}

#[test]
fn control_canonical_mode_directory_spelling_a_value_is_found() {
    let s = Setup::new();
    let (outer, inner) = split(SLASHED);
    let (base, c) = commit_with_dir_mode(&s, outer, inner, "40000");
    let o = s.scan(&["--range", &format!("{base}..{c}")]);
    assert_eq!(code(&o), 1, "{}{}", out(&o), err(&o));
    Setup::never_prints(&o);
}

#[test]
fn a_directory_entry_with_a_non_canonical_mode_is_walked_like_git_walks_it() {
    let s = Setup::new();
    let (outer, inner) = split(SLASHED);
    let (base, c) = commit_with_dir_mode(&s, outer, inner, "40755");
    let o = s.scan(&["--range", &format!("{base}..{c}")]);
    assert_eq!(
        code(&o),
        1,
        "git publishes {{outer}}/{{inner}}/f.txt (a value) but the walk did not descend: {}{}",
        out(&o),
        err(&o)
    );
    Setup::never_prints(&o);
}

#[test]
fn a_new_subtree_under_a_non_canonical_directory_mode_is_walked() {
    // The subtree is new too (rev-list lists it and its blob), so only the path is missed.
    let s = Setup::new();
    s.write("base.txt", "base\n");
    let base = s.commit("base");
    let blob = s.git_stdin(&["hash-object", "-w", "--stdin"], b"clean\n");
    let leaf = s.raw_tree(&[("100644", &format!("f-{SECRET}.txt"), &blob)]);
    let tree = s.raw_tree(&[("40775", "dir", &leaf)]);
    let c = s.git(&["commit-tree", &tree, "-p", &base, "-m", "odd mode"]);
    assert_eq!(
        s.git(&["ls-tree", "-r", "--name-only", &c]),
        format!("dir/f-{SECRET}.txt")
    );
    let o = s.scan(&["--range", &format!("{base}..{c}")]);
    assert_eq!(code(&o), 1, "{}{}", out(&o), err(&o));
    Setup::never_prints(&o);
}

// ---------------------------------------------------------------------------------------------
// Claim: an unreadable or missing old tree fails closed (exit 2), never a silent pass.
// ---------------------------------------------------------------------------------------------

#[test]
fn a_missing_old_subtree_below_a_renamed_directory_fails_closed() {
    let s = Setup::new();
    let (_, inner) = split(SLASHED);
    s.write(&format!("holder/{inner}/f.txt"), "clean\n");
    let base = s.commit("base");
    let deep = s.git(&["rev-parse", &format!("HEAD:holder/{inner}")]);
    s.git(&["mv", "holder", "renamed"]);
    let c = s.commit("mv");
    // Loose objects only: remove the old inner tree.
    let obj = s
        .repo
        .path()
        .join(".git/objects")
        .join(&deep[..2])
        .join(&deep[2..]);
    std::fs::remove_file(&obj).unwrap();
    let o = s.scan(&["--range", &format!("{base}..{c}")]);
    assert_eq!(code(&o), 2, "{}{}", out(&o), err(&o));
}

#[test]
fn a_malformed_old_subtree_below_a_renamed_directory_fails_closed() {
    let s = Setup::new();
    s.write("base.txt", "base\n");
    let base0 = s.commit("base0");
    // An old tree whose body does not parse (a truncated id).
    let bad = s.git_stdin(
        &["hash-object", "--literally", "-w", "-t", "tree", "--stdin"],
        b"100644 f\0\x01\x02",
    );
    let top = s.raw_tree(&[("40000", "holder", &bad)]);
    let base = s.git(&["commit-tree", &top, "-p", &base0, "-m", "published"]);
    let top2 = s.raw_tree(&[("40000", "renamed", &bad)]);
    let c = s.git(&["commit-tree", &top2, "-p", &base, "-m", "mv"]);
    let o = s.scan(&["--range", &format!("{base}..{c}")]);
    assert_eq!(code(&o), 2, "{}{}", out(&o), err(&o));
}

#[test]
fn an_old_tree_entry_that_is_not_a_tree_fails_closed() {
    let s = Setup::new();
    s.write("base.txt", "base\n");
    let base0 = s.commit("base0");
    let blob = s.git_stdin(&["hash-object", "-w", "--stdin"], b"clean\n");
    let top = s.raw_tree(&[("40000", "holder", &blob)]);
    let base = s.git(&["commit-tree", &top, "-p", &base0, "-m", "published"]);
    let top2 = s.raw_tree(&[("40000", "renamed", &blob)]);
    let c = s.git(&["commit-tree", &top2, "-p", &base, "-m", "mv"]);
    let o = s.scan(&["--range", &format!("{base}..{c}")]);
    assert_eq!(code(&o), 2, "{}{}", out(&o), err(&o));
}

// ---------------------------------------------------------------------------------------------
// Claim: places are counted per visit, old subtrees included, and the bound fails closed.
// ---------------------------------------------------------------------------------------------

#[test]
fn renaming_a_directory_that_expands_past_the_place_bound_fails_closed() {
    let s = Setup::new();
    s.write("base.txt", "base\n");
    let base0 = s.commit("base0");
    let blob = s.git_stdin(&["hash-object", "-w", "--stdin"], b"clean\n");
    let names: Vec<String> = (0..710).map(|i| format!("n{i:04}")).collect();
    let leaf_entries: Vec<(&str, &str, &str)> = names
        .iter()
        .map(|n| ("100644", n.as_str(), blob.as_str()))
        .collect();
    let leaf = s.raw_tree(&leaf_entries);
    let mid_entries: Vec<(&str, &str, &str)> = names
        .iter()
        .map(|n| ("40000", n.as_str(), leaf.as_str()))
        .collect();
    let mid = s.raw_tree(&mid_entries);
    // 710 * 710 = 504 100 distinct full paths below `holder`, from two small old trees.
    let top = s.raw_tree(&[("40000", "holder", &mid)]);
    let base = s.git(&["commit-tree", &top, "-p", &base0, "-m", "published"]);
    let top2 = s.raw_tree(&[("40000", "renamed", &mid)]);
    let c = s.git(&["commit-tree", &top2, "-p", &base, "-m", "mv"]);
    let o = s.scan(&["--range", &format!("{base}..{c}")]);
    assert_eq!(code(&o), 2, "{}{}", out(&o), err(&o));
}

// ---------------------------------------------------------------------------------------------
// Claim: the reader handles either hash algorithm (old trees loaded on demand by id).
// ---------------------------------------------------------------------------------------------

#[test]
fn a_renamed_directory_in_a_sha256_repository_is_scanned() {
    let s = Setup::new();
    std::fs::remove_dir_all(s.repo.path().join(".git")).unwrap();
    s.git(&["init", "-q", "-b", "main", "--object-format=sha256"]);
    let (outer, inner) = split(SLASHED);
    s.write(&format!("holder/{inner}/f.txt"), "clean\n");
    let base = s.commit("base");
    assert_eq!(base.len(), 64);
    s.git(&["mv", "holder", outer]);
    let c = s.commit("mv");
    let o = s.scan(&["--range", &format!("{base}..{c}")]);
    assert_eq!(code(&o), 1, "{}{}", out(&o), err(&o));
    Setup::never_prints(&o);
}

// ---------------------------------------------------------------------------------------------
// Claim: a subtree merge (an old tree read under a new prefix) is a new path.
// ---------------------------------------------------------------------------------------------

#[test]
fn a_subtree_merge_of_an_old_tree_under_a_value_prefix_is_found() {
    let s = Setup::new();
    let (outer, inner) = split(SLASHED);
    s.write(&format!("{inner}/f.txt"), "clean\n");
    let base = s.commit("base");
    s.git(&["read-tree", &format!("--prefix={outer}/"), "-u", &base]);
    let c = s.commit("subtree");
    let o = s.scan(&["--range", &format!("{base}..{c}")]);
    assert_eq!(code(&o), 1, "{}{}", out(&o), err(&o));
    Setup::never_prints(&o);
}

#[test]
fn the_staged_pre_push_refuses_a_non_canonical_mode_directory_spelling_a_value() {
    let s = Setup::new();
    let remote = s.with_hooks();
    let (outer, inner) = split(SLASHED);
    s.write(&format!("holder/{inner}/f.txt"), "clean\n");
    let published = s.commit("holder");
    let o = s.git_out(&["push", "-q", "origin", "feat/x"]);
    assert!(o.status.success(), "{}", err(&o));
    let old = s.git(&["rev-parse", "HEAD:holder"]);
    let tree = s.raw_tree(&[("40755", outer, &old)]);
    let c = s.git(&["commit-tree", &tree, "-p", &published, "-m", "odd"]);
    s.git(&["update-ref", "refs/heads/feat/x", &c]);
    let o = s.git_out(&["push", "-q", "origin", "feat/x"]);
    assert!(
        !s.remote_has(&remote, &c),
        "the push published {{outer}}/{{inner}}/f.txt, a path holding a vault value: {}",
        err(&o)
    );
}
