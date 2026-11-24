//! End-to-end tests of `wardenlens vault scan --staged` and `--range` against temporary
//! repositories and a temporary HOME with synthetic values. The environment is cleared first,
//! so nothing of the real home, git configuration or vault is ever read.

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

struct Setup {
    home: TempDir,
    repo: TempDir,
}

fn out(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn err(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

fn code(o: &Output) -> i32 {
    o.status.code().unwrap()
}

impl Setup {
    fn new() -> Self {
        let s = Self {
            home: tempfile::tempdir().unwrap(),
            repo: tempfile::tempdir().unwrap(),
        };
        assert!(s.vault(&["init"], "").status.success());
        for (id, value) in [("tok:a", SECRET), ("tok:b", OTHER)] {
            let set = s.vault(&["set", id, "--kind", "secret"], value);
            assert!(set.status.success());
        }
        s.git(&["init", "-q", "-b", "main"]);
        s
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
        self.scan_with(args, &[])
    }

    fn scan_with(&self, args: &[&str], env: &[(&str, &Path)]) -> Output {
        let mut c = self.wardenlens();
        c.args(["vault", "scan"]).args(args);
        for (k, v) in env {
            c.env(k, v);
        }
        c.stdin(Stdio::null()).output().unwrap()
    }

    fn git(&self, args: &[&str]) -> String {
        let out = Command::new("git")
            .current_dir(self.repo.path())
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap())
            .env("HOME", self.repo.path())
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_AUTHOR_NAME", "A U Thor")
            .env("GIT_AUTHOR_EMAIL", "author@example.invalid")
            .env("GIT_AUTHOR_DATE", "2026-01-01T00:00:00Z")
            .env("GIT_COMMITTER_NAME", "C O Mitter")
            .env("GIT_COMMITTER_EMAIL", "committer@example.invalid")
            .env("GIT_COMMITTER_DATE", "2026-01-01T00:00:00Z")
            .args(args)
            .output()
            .unwrap();
        assert!(out.status.success(), "git {args:?}");
        String::from_utf8(out.stdout).unwrap().trim().to_owned()
    }

    fn write(&self, name: &str, text: &str) {
        std::fs::write(self.repo.path().join(name), text).unwrap();
    }

    fn commit(&self, message: &str) -> String {
        self.git(&["add", "-A"]);
        self.git(&["commit", "-q", "--allow-empty", "-m", message]);
        self.git(&["rev-parse", "HEAD"])
    }

    /// Nothing printed may hold a value, whatever the result.
    fn never_prints(o: &Output) {
        for v in [SECRET, OTHER] {
            assert!(!out(o).contains(v), "{}", out(o));
            assert!(!err(o).contains(v), "{}", err(o));
        }
    }
}

#[test]
fn a_clean_index_passes_and_says_what_it_scanned() {
    let s = Setup::new();
    s.write("a.txt", "nothing here\n");
    s.git(&["add", "a.txt"]);
    let o = s.scan(&["--staged"]);
    assert_eq!(code(&o), 0, "{}", err(&o));
    assert!(
        err(&o).contains("scanned 1 object(s), 2 entries, 0 hit(s)"),
        "{}",
        err(&o)
    );
    assert_eq!(out(&o), "");
}

#[test]
fn a_staged_value_is_reported_by_id_kind_path_and_line() {
    let s = Setup::new();
    s.write("a.txt", &format!("one\ntwo {SECRET}\n"));
    s.git(&["add", "a.txt"]);
    // The working tree no longer has it; the index does.
    s.write("a.txt", "clean now\n");
    let o = s.scan(&["--staged"]);
    assert_eq!(code(&o), 1, "{}", err(&o));
    assert_eq!(out(&o), "tok:a secret a.txt:2\n");
    Setup::never_prints(&o);
}

#[test]
fn a_file_name_with_a_value_is_never_printed() {
    let s = Setup::new();
    s.write(&format!("name-{SECRET}.txt"), &format!("body {OTHER}\n"));
    s.git(&["add", "-A"]);
    let o = s.scan(&["--staged"]);
    assert_eq!(code(&o), 1);
    let text = out(&o);
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 2, "{lines:?}");
    assert!(
        lines.iter().all(|l| l.contains("<redacted-path> blob ")),
        "{lines:?}"
    );
    Setup::never_prints(&o);
    // The same in a range, after committing.
    s.commit("c");
    let o = s.scan(&["--range", "..HEAD"]);
    assert_eq!(code(&o), 1);
    assert!(out(&o).contains("<redacted-path> blob "));
    Setup::never_prints(&o);
}

#[test]
fn a_branch_name_with_a_value_is_reported_as_ref_index() {
    let s = Setup::new();
    s.write("a.txt", "x\n");
    s.commit("c");
    let branch = format!("refs/heads/feature-{SECRET}");
    let o = s.scan(&[
        "--range",
        "..HEAD",
        "--ref",
        "refs/heads/ok",
        "--ref",
        &branch,
    ]);
    assert_eq!(code(&o), 1);
    assert_eq!(out(&o), "tok:a secret ref:1\n");
    Setup::never_prints(&o);
}

#[test]
fn commit_messages_authors_and_tags_are_reported_by_part() {
    let s = Setup::new();
    s.write("a.txt", "x\n");
    s.git(&["add", "-A"]);
    s.git(&["commit", "-q", "-m", &format!("subject {SECRET}")]);
    let o = s.scan(&["--range", "..HEAD"]);
    assert_eq!(code(&o), 1);
    let sha = s.git(&["rev-parse", "HEAD"]);
    assert_eq!(out(&o), format!("tok:a secret commit:{sha}:message\n"));
    Setup::never_prints(&o);
    // An annotated tag with the value in its message.
    s.git(&["tag", "-a", "-m", OTHER, "v1"]);
    let tag = s.git(&["rev-parse", "v1"]);
    let o = s.scan(&["--range", "..v1"]);
    assert_eq!(code(&o), 1);
    assert!(
        out(&o).contains(&format!("tok:b secret tag:{tag}:message")),
        "{}",
        out(&o)
    );
    Setup::never_prints(&o);
}

#[test]
fn the_destination_remote_excludes_what_it_already_has() {
    let s = Setup::new();
    s.write("old.txt", &format!("{SECRET}\n"));
    let old = s.commit("old");
    s.git(&["update-ref", "refs/remotes/origin/main", &old]);
    s.write("new.txt", "fine\n");
    s.commit("new");
    let o = s.scan(&["--range", "..HEAD", "--remote", "origin"]);
    assert_eq!(code(&o), 0, "{}", out(&o));
    let o = s.scan(&["--range", "..HEAD", "--remote", "elsewhere"]);
    assert_eq!(code(&o), 1);
    let o = s.scan(&["--range", &format!("{old}..HEAD")]);
    assert_eq!(code(&o), 0);
    // An all-zero base is a new branch: everything is new.
    let zero = "0".repeat(40);
    let o = s.scan(&["--range", &format!("{zero}..HEAD")]);
    assert_eq!(code(&o), 1);
}

#[test]
fn what_cannot_be_scanned_is_exit_two_never_a_pass() {
    let s = Setup::new();
    s.write("a.txt", "x\n");
    s.commit("c");
    // Unknown revision, bad range, option-looking revision, bad remote name.
    for args in [
        vec!["--range", "..no-such-revision"],
        vec!["--range", "HEAD"],
        vec!["--range", "..--output=x"],
        vec!["--range", "..HEAD", "--remote", "--all"],
        vec!["--range", "..HEAD", "--remote", "a*"],
    ] {
        let o = s.scan(&args);
        assert_eq!(code(&o), 2, "{args:?}: {}", err(&o));
    }
    // Not a repository.
    let elsewhere = tempfile::tempdir().unwrap();
    let mut c = s.wardenlens();
    let o = c
        .current_dir(elsewhere.path())
        .args(["vault", "scan", "--staged"])
        .output()
        .unwrap();
    assert_eq!(code(&o), 2, "{}", err(&o));
    // No vault.
    let empty_home = tempfile::tempdir().unwrap();
    let o = s
        .wardenlens()
        .env("HOME", empty_home.path())
        .args(["vault", "scan", "--staged"])
        .output()
        .unwrap();
    assert_eq!(code(&o), 2);
}

#[test]
fn the_git_sources_and_paths_exclude_each_other() {
    let s = Setup::new();
    for args in [
        vec!["--staged", "--range", "..HEAD"],
        vec!["--staged", "somefile"],
        vec!["--range", "..HEAD", "somefile"],
        vec!["--remote", "origin", "--staged"],
        vec![],
    ] {
        let o = s.scan(&args);
        assert_eq!(code(&o), 2, "{args:?}");
    }
}

#[test]
fn default_paths_ignores_the_vault_variables() {
    let s = Setup::new();
    s.write("a.txt", &format!("{SECRET}\n"));
    s.git(&["add", "a.txt"]);
    let nowhere = s.home.path().join("no-such-vault.db");
    // The variable points at an empty place: the plain scan cannot find a vault.
    let o = s.scan_with(&["--staged"], &[("WARDENLENS_VAULT", &nowhere)]);
    assert_eq!(code(&o), 2);
    // With --default-paths the variable is ignored, as the hooks require.
    let o = s.scan_with(
        &["--default-paths", "--staged"],
        &[
            ("WARDENLENS_VAULT", &nowhere),
            ("WARDENLENS_VAULT_KEY_FILE", &nowhere),
        ],
    );
    assert_eq!(code(&o), 1, "{}", err(&o));
}

#[test]
fn a_scan_leaves_the_repository_as_it_was() {
    let s = Setup::new();
    s.write("a.txt", &format!("{SECRET}\n"));
    s.commit("c");
    s.write("b.txt", "staged\n");
    s.git(&["add", "b.txt"]);
    let snapshot = || {
        let o = Command::new("find")
            .arg(s.repo.path().join(".git"))
            .args(["-type", "f", "-printf", "%p %s %T@\\n"])
            .output()
            .unwrap();
        let mut v: Vec<String> = String::from_utf8(o.stdout)
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect();
        v.sort();
        v
    };
    let before = snapshot();
    let _ = s.scan(&["--staged"]);
    let _ = s.scan(&["--range", "..HEAD"]);
    assert_eq!(before, snapshot());
}
