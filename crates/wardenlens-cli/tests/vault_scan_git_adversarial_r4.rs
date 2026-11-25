//! Round-4 adversarial tests of `wardenlens vault scan --range` and of the staged pre-push
//! hook, end to end with the real binary. Temporary repositories and a temporary HOME with
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
}

fn split(v: &str) -> (&str, &str) {
    v.split_once('/').unwrap()
}

// ---------------------------------------------------------------------------------------------
// Claim (round 4): the walk "descends only into new trees" because "every ancestor of a new
// tree is itself new, so every changed path is visited". The converse does not hold: an OLD
// tree placed under a NEW name publishes new full paths (new-name/old-entry) that the walk never
// visits, because it stops at the first old tree. A value with a `/` spanning that boundary is
// published unscanned. Before round 4, `diff-tree -r` listed every such file path.
// ---------------------------------------------------------------------------------------------

/// Base commit holding `holder/{inner}/f.txt`; returns the base commit.
fn base_with_old_subtree(s: &Setup, inner: &str) -> String {
    s.write(&format!("holder/{inner}/f.txt"), "clean\n");
    s.commit("base")
}

/// A commit on HEAD whose root renames `holder` (an unchanged tree) to `outer`.
fn commit_renaming_holder(s: &Setup, outer: &str) -> String {
    let old = s.git(&["rev-parse", "HEAD:holder"]);
    let entries = s.git(&["ls-tree", "HEAD"]);
    let kept: Vec<&str> = entries
        .lines()
        .filter(|l| !l.ends_with("\tholder"))
        .collect();
    let mut lines = String::new();
    for l in kept {
        lines.push_str(l);
        lines.push('\n');
    }
    lines.push_str("040000 tree ");
    lines.push_str(&old);
    lines.push('\t');
    lines.push_str(outer);
    lines.push('\n');
    let tree = s.git_stdin(&["mktree"], lines.as_bytes());
    let parent = s.git(&["rev-parse", "HEAD"]);
    let c = s.git(&["commit-tree", &tree, "-p", &parent, "-m", "rename dir"]);
    s.git(&["update-ref", "HEAD", &c]);
    c
}

#[test]
fn control_the_old_full_path_does_not_hold_the_value() {
    let s = Setup::new();
    let (_, inner) = split(SLASHED);
    let base = base_with_old_subtree(&s, inner);
    let c = commit_renaming_holder(&s, "elsewhere");
    let o = s.scan(&["--range", &format!("{base}..{c}")]);
    assert_eq!(code(&o), 0, "{}{}", out(&o), err(&o));
}

#[test]
fn renaming_an_unchanged_directory_so_its_new_full_path_spells_a_value_is_found() {
    let s = Setup::new();
    let (outer, inner) = split(SLASHED);
    let base = base_with_old_subtree(&s, inner);
    let c = commit_renaming_holder(&s, outer);
    let o = s.scan(&["--range", &format!("{base}..{c}")]);
    assert_eq!(
        code(&o),
        1,
        "{{outer}}/{{inner}}/f.txt is a new full path holding a vault value, published unscanned: {}{}",
        out(&o),
        err(&o)
    );
    Setup::never_prints(&o);
}

#[test]
fn plain_git_mv_of_a_directory_so_its_new_path_spells_a_value_is_found() {
    let s = Setup::new();
    let (outer, inner) = split(SLASHED);
    let base = base_with_old_subtree(&s, inner);
    s.git(&["mv", "holder", outer]);
    let c = s.commit("mv");
    let o = s.scan(&["--range", &format!("{base}..{c}")]);
    assert_eq!(code(&o), 1, "{}{}", out(&o), err(&o));
    Setup::never_prints(&o);
}

#[test]
fn a_tagged_new_tree_over_an_old_subtree_spelling_a_value_is_found() {
    let s = Setup::new();
    let (outer, inner) = split(SLASHED);
    let base = base_with_old_subtree(&s, inner);
    let old = s.git(&["rev-parse", "HEAD:holder"]);
    let tree = s.git_stdin(
        &["mktree"],
        format!("040000 tree {old}\t{outer}\n").as_bytes(),
    );
    s.git(&["tag", "-a", "-m", "t", "treetag", &tree]);
    let o = s.scan(&["--range", &format!("{base}..treetag")]);
    assert_eq!(code(&o), 1, "{}{}", out(&o), err(&o));
    Setup::never_prints(&o);
}

#[test]
fn the_staged_pre_push_refuses_a_directory_rename_that_spells_a_value() {
    let s = Setup::new();
    let remote = s.with_hooks();
    let (outer, inner) = split(SLASHED);
    s.write(&format!("holder/{inner}/f.txt"), "clean\n");
    s.commit("holder");
    // The old subtree is published on the remote first (a clean push).
    let o = s.git_out(&["push", "-q", "origin", "feat/x"]);
    assert!(o.status.success(), "{}", err(&o));
    s.git(&["mv", "holder", outer]);
    let c = s.commit("mv");
    let o = s.git_out(&["push", "-q", "origin", "feat/x"]);
    assert!(
        !s.remote_has(&remote, &c),
        "the push published {{outer}}/{{inner}}/f.txt, a path holding a vault value: {}",
        err(&o)
    );
}

#[test]
fn control_staged_git_mv_of_a_directory_so_its_new_path_spells_a_value_is_found() {
    let s = Setup::new();
    let (outer, inner) = split(SLASHED);
    base_with_old_subtree(&s, inner);
    s.git(&["mv", "holder", outer]);
    let o = s.scan(&["--staged"]);
    assert_eq!(code(&o), 1, "{}{}", out(&o), err(&o));
    Setup::never_prints(&o);
}
