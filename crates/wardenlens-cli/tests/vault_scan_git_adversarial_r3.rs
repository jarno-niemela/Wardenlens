//! Round-3 adversarial tests of `wardenlens vault scan --range` and of the staged pre-push
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

/// A tree (written, not committed) whose entries are `extra` (mktree lines) on top of HEAD's.
fn tree_on_head(s: &Setup, extra: &str) -> String {
    let entries = format!("{}\n{extra}", s.git(&["ls-tree", "HEAD"]));
    s.git_stdin(&["mktree"], entries.as_bytes())
}

/// A new commit on top of HEAD that adds the empty directories `outer/inner`; HEAD moves to it.
fn commit_with_nested_empty_dirs(s: &Setup, outer: &str, inner: &str) -> String {
    let empty = s.git_stdin(&["mktree"], b"");
    let mid = s.git_stdin(
        &["mktree"],
        format!("040000 tree {empty}\t{inner}\n").as_bytes(),
    );
    let tree = tree_on_head(s, &format!("040000 tree {mid}\t{outer}\n"));
    let parent = s.git(&["rev-parse", "HEAD"]);
    let c = s.git(&[
        "commit-tree",
        &tree,
        "-p",
        &parent,
        "-m",
        "nested empty dirs",
    ]);
    s.git(&["update-ref", "HEAD", &c]);
    c
}

fn split(v: &str) -> (&str, &str) {
    v.split_once('/').unwrap()
}

// ---------------------------------------------------------------------------------------------
// Claim (round 3): every path a push publishes is scanned, empty directories too. The fix scans
// each tree ENTRY NAME on its own; a full path that no file lies under is never scanned as a
// path, so a value with a `/` spelled by nested directories is published.
// ---------------------------------------------------------------------------------------------

#[test]
fn control_a_value_with_a_slash_spelled_by_a_file_path_is_found() {
    let s = Setup::new();
    s.write("a.txt", "a\n");
    let base = s.commit("base");
    s.write(&format!("{SLASHED}/f.txt"), "clean\n");
    let c = s.commit("file below");
    let o = s.scan(&["--range", &format!("{base}..{c}")]);
    assert_eq!(code(&o), 1, "{}{}", out(&o), err(&o));
    Setup::never_prints(&o);
}

#[test]
fn a_value_with_a_slash_spelled_by_nested_empty_directories_is_found() {
    let s = Setup::new();
    s.write("a.txt", "a\n");
    let base = s.commit("base");
    let (outer, inner) = split(SLASHED);
    let c = commit_with_nested_empty_dirs(&s, outer, inner);
    let o = s.scan(&["--range", &format!("{base}..{c}")]);
    assert_eq!(
        code(&o),
        1,
        "the path {{outer}}/{{inner}} of two empty directories spells a vault value and was not found: {}{}",
        out(&o),
        err(&o)
    );
    Setup::never_prints(&o);
}

#[test]
fn a_value_with_a_slash_spelled_by_a_path_in_a_tagged_tree_is_found() {
    let s = Setup::new();
    s.write("a.txt", "a\n");
    let base = s.commit("base");
    let (outer, inner) = split(SLASHED);
    let blob = s.git_stdin(&["hash-object", "-w", "--stdin"], b"clean\n");
    let mid = s.git_stdin(
        &["mktree"],
        format!("100644 blob {blob}\t{inner}\n").as_bytes(),
    );
    let tree = s.git_stdin(
        &["mktree"],
        format!("040000 tree {mid}\t{outer}\n").as_bytes(),
    );
    s.git(&["tag", "-a", "-m", "t", "treetag", &tree]);
    let o = s.scan(&["--range", &format!("{base}..treetag")]);
    assert_eq!(
        code(&o),
        1,
        "a tagged tree publishes the path {{outer}}/{{inner}} (a vault value) unscanned: {}{}",
        out(&o),
        err(&o)
    );
    Setup::never_prints(&o);
}

#[test]
fn the_staged_pre_push_refuses_nested_empty_directories_that_spell_a_value() {
    let s = Setup::new();
    let remote = s.with_hooks();
    let (outer, inner) = split(SLASHED);
    let c = commit_with_nested_empty_dirs(&s, outer, inner);
    let o = s.git_out(&["push", "-q", "origin", "HEAD:refs/heads/feat/x"]);
    assert!(
        !s.remote_has(&remote, &c),
        "the push published a directory path holding a vault value: {}",
        err(&o)
    );
    assert!(!o.status.success());
}

// ---------------------------------------------------------------------------------------------
// Claim (round 3): the dedupe against diff-tree path hits only drops a SECOND report of the same
// place ("one finding per place, not per way of finding it"). `covered` is keyed by the name
// alone, not by the tree, so a different place with the same name is dropped.
// ---------------------------------------------------------------------------------------------

#[test]
fn the_dedupe_never_turns_a_hit_into_a_pass() {
    let s = Setup::new();
    s.write("a.txt", "a\n");
    let base = s.commit("base");
    s.write(&format!("x/d-{SECRET}/f.txt"), "clean\n");
    s.commit("file below");
    let empty = s.git_stdin(&["mktree"], b"");
    let y = s.git_stdin(
        &["mktree"],
        format!("040000 tree {empty}\td-{SECRET}\n").as_bytes(),
    );
    let tree = tree_on_head(&s, &format!("040000 tree {y}\ty\n"));
    let parent = s.git(&["rev-parse", "HEAD"]);
    let c = s.git(&["commit-tree", &tree, "-p", &parent, "-m", "y"]);
    let o = s.scan(&["--range", &format!("{base}..{c}")]);
    assert_eq!(code(&o), 1, "{}{}", out(&o), err(&o));
    Setup::never_prints(&o);
}

#[test]
fn an_empty_directory_elsewhere_with_a_name_already_found_in_a_file_path_is_still_reported() {
    let s = Setup::new();
    s.write("a.txt", "a\n");
    let base = s.commit("base");
    s.write(&format!("x/d-{SECRET}/f.txt"), "clean\n");
    s.commit("file below");
    let empty = s.git_stdin(&["mktree"], b"");
    let y = s.git_stdin(
        &["mktree"],
        format!("040000 tree {empty}\td-{SECRET}\n").as_bytes(),
    );
    let tree = tree_on_head(&s, &format!("040000 tree {y}\ty\n"));
    let parent = s.git(&["rev-parse", "HEAD"]);
    let c = s.git(&["commit-tree", &tree, "-p", &parent, "-m", "y"]);
    let o = s.scan(&["--range", &format!("{base}..{c}")]);
    assert_eq!(code(&o), 1);
    // Two places hold the value: the file path x/d-V/f.txt and the empty directory y/d-V
    // (tree `y`). The second is a different place, so it must be reported too.
    assert!(
        out(&o).contains(&format!("tree {y}")),
        "the empty directory in tree y was deduplicated away: {}",
        out(&o)
    );
}

// ---------------------------------------------------------------------------------------------
// Claim (round 3): the scan-first hook keeps every existing refusal effective WITH a vault
// present (the existing pre-push.test.sh suite runs without one).
// ---------------------------------------------------------------------------------------------

#[test]
fn with_a_vault_the_staged_pre_push_still_refuses_a_clean_push_to_main() {
    let s = Setup::new();
    let remote = s.with_hooks();
    s.write("m.txt", "m\n");
    let c = s.commit("m");
    let o = s.git_out(&["push", "-q", "origin", "HEAD:refs/heads/main"]);
    assert!(!o.status.success());
    assert!(!s.remote_has(&remote, &c));
    assert!(err(&o).contains("never push to main"), "{}", err(&o));
}

#[test]
fn with_a_vault_the_staged_pre_push_still_refuses_a_clean_deletion() {
    let s = Setup::new();
    let remote = s.with_hooks();
    s.write("m.txt", "m\n");
    s.commit("m");
    s.git(&[
        "-c",
        "core.hooksPath=/dev/null",
        "push",
        "-q",
        "origin",
        "feat/x",
    ]);
    let o = s.git_out(&["push", "-q", "origin", ":refs/heads/feat/x"]);
    assert!(!o.status.success(), "{}", err(&o));
    assert!(err(&o).contains("deleting remote branches"), "{}", err(&o));
    let o = s
        .git_cmd(&remote)
        .args(["rev-parse", "--verify", "refs/heads/feat/x"])
        .output()
        .unwrap();
    assert!(o.status.success());
}

#[test]
fn with_a_vault_the_staged_pre_push_still_refuses_a_clean_force_push() {
    let s = Setup::new();
    let _remote = s.with_hooks();
    s.write("m.txt", "m\n");
    s.commit("m");
    s.git(&[
        "-c",
        "core.hooksPath=/dev/null",
        "push",
        "-q",
        "origin",
        "feat/x",
    ]);
    s.git(&["reset", "-q", "--hard", "HEAD~1"]);
    s.write("n.txt", "n\n");
    s.commit("n");
    let o = s.git_out(&["push", "-q", "-f", "origin", "feat/x"]);
    assert!(!o.status.success());
    assert!(err(&o).contains("non-fast-forward"), "{}", err(&o));
}

#[test]
fn with_a_vault_the_staged_pre_push_still_refuses_a_clean_workflow_change() {
    let s = Setup::new();
    let remote = s.with_hooks();
    s.write(".github/workflows/ci.yml", "on: push\n");
    let c = s.commit("wf");
    let o = s.git_out(&["push", "-q", "origin", "feat/x"]);
    assert!(!o.status.success());
    assert!(!s.remote_has(&remote, &c));
    assert!(err(&o).contains(".github/workflows"), "{}", err(&o));
}

#[test]
fn with_a_vault_the_staged_pre_push_lets_a_clean_feature_push_through() {
    let s = Setup::new();
    let remote = s.with_hooks();
    s.write("m.txt", "m\n");
    let c = s.commit("m");
    let o = s.git_out(&["push", "-q", "origin", "feat/x"]);
    assert!(o.status.success(), "{}", err(&o));
    assert!(s.remote_has(&remote, &c));
}

#[test]
fn a_value_in_a_ref_name_of_a_deletion_is_refused_by_index_without_the_name() {
    let s = Setup::new();
    let remote = s.with_hooks();
    let name = format!("refs/heads/g-{OTHER}");
    s.git(&[
        "-c",
        "core.hooksPath=/dev/null",
        "push",
        "-q",
        "origin",
        &format!("feat/x:{name}"),
    ]);
    let o = s.git_out(&["push", "-q", "origin", &format!(":{name}")]);
    assert!(!o.status.success());
    assert!(err(&o).contains("ref:0"), "{}", err(&o));
    // Refused by the scan (which prints the index), not by the policy message that names the ref.
    assert!(!err(&o).contains("deleting remote branches"), "{}", err(&o));
    Setup::never_prints(&o);
    let still = s
        .git_cmd(&remote)
        .args(["rev-parse", "--verify", &name])
        .output()
        .unwrap();
    assert!(still.status.success(), "the remote branch was deleted");
}
