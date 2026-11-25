//! Round-2 adversarial tests of `wardenlens vault scan --range` and of the staged pre-push
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
        for (id, value) in [("tok:a", SECRET), ("tok:b", OTHER)] {
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
        for v in [SECRET, OTHER] {
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

// ---------------------------------------------------------------------------------------------
// Claim: every path a push publishes is scanned. `diff-tree -r` lists files only, so an empty
// directory (an empty tree entry, which `git push` sends) has no file below it to list; the
// tree-name scan skips every tree a new commit reaches.
// ---------------------------------------------------------------------------------------------

/// A new commit on top of HEAD whose root tree adds an empty directory named `dir`.
fn commit_with_empty_dir(s: &Setup, dir: &str) -> String {
    let empty = s.git_stdin(&["mktree"], b"");
    let entries = format!(
        "{}\n040000 tree {empty}\t{dir}\n",
        s.git(&["ls-tree", "HEAD"])
    );
    let tree = s.git_stdin(&["mktree"], entries.as_bytes());
    let parent = s.git(&["rev-parse", "HEAD"]);
    let c = s.git(&["commit-tree", &tree, "-p", &parent, "-m", "empty dir"]);
    s.git(&["update-ref", "HEAD", &c]);
    c
}

#[test]
fn an_empty_directory_named_with_a_value_in_a_new_commit_is_found() {
    let s = Setup::new();
    s.write("a.txt", "a\n");
    let base = s.commit("base");
    let c = commit_with_empty_dir(&s, &format!("d-{SECRET}"));
    let o = s.scan(&["--range", &format!("{base}..{c}")]);
    assert_eq!(
        code(&o),
        1,
        "an empty directory name in a new commit was not scanned: {}{}",
        out(&o),
        err(&o)
    );
    Setup::never_prints(&o);
    // A new branch (no base) too.
    let o = s.scan(&["--range", &format!("..{c}")]);
    assert_eq!(code(&o), 1, "{}{}", out(&o), err(&o));
}

#[test]
fn the_staged_pre_push_refuses_an_empty_directory_named_with_a_value() {
    let s = Setup::new();
    let remote = s.with_hooks();
    let c = commit_with_empty_dir(&s, &format!("d-{SECRET}"));
    let o = s.git_out(&["push", "-q", "origin", "HEAD:refs/heads/feat/x"]);
    assert!(
        !s.remote_has(&remote, &c),
        "the push published a directory name holding a vault value: {}",
        err(&o)
    );
    assert!(!o.status.success());
}

// ---------------------------------------------------------------------------------------------
// Claim: the tree-reach exclusion (`rev-list --stdin` with `--not --remotes=R --not` and `^from`)
// leaves out only trees a new commit leads to, also with a remote and a base given.
// ---------------------------------------------------------------------------------------------

#[test]
fn a_tagged_tree_is_scanned_with_a_remote_and_a_base() {
    let s = Setup::new();
    s.write("a.txt", "a\n");
    let base = s.commit("base");
    s.git(&["update-ref", "refs/remotes/origin/main", &base]);
    s.write("b.txt", "b\n");
    s.commit("new");
    let blob = s.git_stdin(&["hash-object", "-w", "--stdin"], b"clean\n");
    let entry = format!("100644 blob {blob}\tname-{SECRET}.txt\n");
    let tree = s.git_stdin(&["mktree"], entry.as_bytes());
    s.git(&["tag", "-a", "-m", "t", "treetag", &tree]);
    let o = s.scan(&["--range", &format!("{base}..treetag"), "--remote", "origin"]);
    assert_eq!(code(&o), 1, "{}{}", out(&o), err(&o));
    Setup::never_prints(&o);
    // A tag that points at a new commit and a tagged tree reachable from that commit only
    // through the tag: the commit's paths are clean, the tree's names are not.
    let o = s.scan(&["--range", &format!("{base}..{tree}"), "--remote", "origin"]);
    assert_eq!(code(&o), 1, "{}{}", out(&o), err(&o));
}

#[test]
fn a_tree_that_is_the_root_of_a_new_commit_is_still_found_through_its_paths() {
    // The reach filter drops this tree from the tree-name scan; diff-tree must cover it.
    let s = Setup::new();
    s.write("a.txt", "a\n");
    let base = s.commit("base");
    s.git(&["update-ref", "refs/remotes/origin/main", &base]);
    s.write(&format!("n-{SECRET}.txt"), "clean\n");
    let c = s.commit("new");
    s.git(&["tag", "-a", "-m", "t", "roottree", &format!("{c}^{{tree}}")]);
    let o = s.scan(&[
        "--range",
        &format!("{base}..roottree"),
        "--remote",
        "origin",
    ]);
    assert_eq!(code(&o), 1, "{}{}", out(&o), err(&o));
    let o = s.scan(&["--range", &format!("{base}..{c}"), "--remote", "origin"]);
    assert_eq!(code(&o), 1, "{}{}", out(&o), err(&o));
    Setup::never_prints(&o);
}

// ---------------------------------------------------------------------------------------------
// Claim (hook header): "the refusal never prints a ref name" / ADR 0006 section 8: a location
// that holds a value is never printed. The hook's other refusals run before the scan.
// ---------------------------------------------------------------------------------------------

#[test]
fn the_staged_pre_push_workflow_refusal_never_prints_a_new_ref_name_with_a_value() {
    let s = Setup::new();
    let remote = s.with_hooks();
    s.write(".github/workflows/ci.yml", "on: push\n");
    let c = s.commit("wf");
    let o = s.git_out(&[
        "push",
        "-q",
        "origin",
        &format!("HEAD:refs/heads/f-{OTHER}"),
    ]);
    assert!(!o.status.success());
    assert!(!s.remote_has(&remote, &c));
    Setup::never_prints(&o);
}

#[test]
fn the_staged_pre_push_workflow_refusal_never_prints_a_workflow_path_with_a_value() {
    let s = Setup::new();
    let remote = s.with_hooks();
    s.write(&format!(".github/workflows/w-{SECRET}.yml"), "on: push\n");
    let c = s.commit("wf");
    let o = s.git_out(&["push", "-q", "origin", "feat/x"]);
    assert!(!o.status.success());
    assert!(!s.remote_has(&remote, &c));
    Setup::never_prints(&o);
}

#[test]
fn the_staged_pre_push_main_refusal_never_prints_a_local_ref_name_with_a_value() {
    let s = Setup::new();
    let remote = s.with_hooks();
    let local = format!("f-{OTHER}");
    s.git(&["checkout", "-q", "-b", &local]);
    s.write("m.txt", "m\n");
    let c = s.commit("m");
    let o = s.git_out(&["push", "-q", "origin", &format!("{local}:main")]);
    assert!(!o.status.success());
    assert!(!s.remote_has(&remote, &c));
    Setup::never_prints(&o);
}

// ---------------------------------------------------------------------------------------------
// Claim: the hook scans every ref update and passes every ref of the push (multi-ref push).
// ---------------------------------------------------------------------------------------------

#[test]
fn a_multi_ref_push_with_a_value_only_in_the_second_update_is_refused() {
    let s = Setup::new();
    let remote = s.with_hooks();
    s.write("clean.txt", "clean\n");
    let clean = s.commit("clean");
    s.git(&["checkout", "-q", "-b", "feat/y", "main"]);
    s.write("s.txt", &format!("pw {SECRET}\n"));
    let bad = s.commit("bad");
    let o = s.git_out(&["push", "-q", "origin", "feat/x", "feat/y"]);
    assert!(!o.status.success(), "the push went through");
    assert!(!s.remote_has(&remote, &bad));
    assert!(!s.remote_has(&remote, &clean));
    Setup::never_prints(&o);
}

#[test]
fn a_multi_ref_push_with_a_value_only_in_the_second_ref_name_is_refused_by_index() {
    let s = Setup::new();
    let remote = s.with_hooks();
    s.write("clean.txt", "clean\n");
    let c = s.commit("clean");
    let o = s.git_out(&[
        "push",
        "-q",
        "origin",
        "feat/x",
        &format!("feat/x:refs/heads/g-{OTHER}"),
    ]);
    assert!(!o.status.success(), "the push went through");
    assert!(!s.remote_has(&remote, &c));
    assert!(err(&o).contains("ref:1"), "{}", err(&o));
    Setup::never_prints(&o);
}

// ---------------------------------------------------------------------------------------------
// Claim: an annotated tag pushed alone is scanned (the tag object and its tag-name header).
// ---------------------------------------------------------------------------------------------

#[test]
fn the_staged_pre_push_refuses_a_tag_whose_message_holds_a_value() {
    let s = Setup::new();
    let remote = s.with_hooks();
    s.git(&["tag", "-a", "-m", &format!("rel {SECRET}"), "v1", "main"]);
    let t = s.git(&["rev-parse", "v1"]);
    let o = s.git_out(&["push", "-q", "origin", "v1"]);
    assert!(!o.status.success(), "the push went through");
    assert!(!s.remote_has(&remote, &t));
    Setup::never_prints(&o);
}

#[test]
fn a_gitlink_at_a_path_with_a_value_is_found() {
    let s = Setup::new();
    s.write("a.txt", "a\n");
    let base = s.commit("base");
    let fake = "1234567890123456789012345678901234567890";
    s.git(&[
        "update-index",
        "--add",
        "--cacheinfo",
        &format!("160000,{fake},sub-{SECRET}"),
    ]);
    let o = s.scan(&["--staged"]);
    assert_eq!(code(&o), 1, "{}{}", out(&o), err(&o));
    Setup::never_prints(&o);
    let tree = s.git(&["write-tree"]);
    let c = s.git(&["commit-tree", &tree, "-p", &base, "-m", "g"]);
    let o = s.scan(&["--range", &format!("{base}..{c}")]);
    assert_eq!(code(&o), 1, "{}{}", out(&o), err(&o));
    Setup::never_prints(&o);
}
