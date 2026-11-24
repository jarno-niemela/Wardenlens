//! Adversarial tests of `wardenlens vault scan --staged` / `--range` and of the staged hooks
//! (`scripts/hooks-staged/`) run end to end with the real binary. Temporary repositories and a
//! temporary HOME with synthetic values only; the environment is cleared first.

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
// Claim: "what a push would publish is scanned, all of it" -- replace refs.
// `git push` (pack-objects) ignores refs/replace/*, so it sends the real objects; the scan must
// read the same objects, not the replacements.
// ---------------------------------------------------------------------------------------------

#[test]
fn a_replace_ref_does_not_hide_a_commit_message_from_the_range_scan() {
    let s = Setup::new();
    s.write("a.txt", "a\n");
    let base = s.commit("base");
    s.write("s.txt", "clean\n");
    let bad = s.commit(&format!("subject {SECRET}"));
    // Sanity: found without a replace ref.
    assert_eq!(code(&s.scan(&["--range", &format!("{base}..{bad}")])), 1);
    // A clean commit that stands in for it locally.
    s.git(&["checkout", "-q", "--detach", &base]);
    let good = s.commit("innocent");
    s.git(&["checkout", "-q", "main"]);
    s.git(&["replace", &bad, &good]);
    let o = s.scan(&["--range", &format!("{base}..{bad}")]);
    assert_eq!(
        code(&o),
        1,
        "a replace ref hid the commit that a push publishes: {}",
        err(&o)
    );
    Setup::never_prints(&o);
}

#[test]
fn a_replace_ref_does_not_hide_a_blob_from_the_range_scan() {
    let s = Setup::new();
    s.write("a.txt", "a\n");
    let base = s.commit("base");
    s.write("s.txt", &format!("pw {SECRET}\n"));
    let bad = s.commit("add s");
    let blob = s.git(&["rev-parse", &format!("{bad}:s.txt")]);
    let clean = s.git_stdin(&["hash-object", "-w", "--stdin"], b"nothing\n");
    s.git(&["replace", &blob, &clean]);
    let o = s.scan(&["--range", &format!("{base}..{bad}")]);
    assert_eq!(
        code(&o),
        1,
        "a replace ref hid the blob that a push publishes: {}",
        err(&o)
    );
    Setup::never_prints(&o);
}

#[test]
fn a_replace_ref_does_not_hide_a_staged_blob() {
    let s = Setup::new();
    s.write("a.txt", "a\n");
    s.commit("base");
    s.write("s.txt", &format!("pw {SECRET}\n"));
    s.git(&["add", "s.txt"]);
    let blob = s.git(&["rev-parse", ":s.txt"]);
    let clean = s.git_stdin(&["hash-object", "-w", "--stdin"], b"nothing\n");
    s.git(&["replace", &blob, &clean]);
    let o = s.scan(&["--staged"]);
    assert_eq!(
        code(&o),
        1,
        "a replace ref hid the staged blob that the commit records: {}",
        err(&o)
    );
}

#[test]
fn the_staged_pre_push_refuses_a_value_hidden_behind_a_replace_ref() {
    let s = Setup::new();
    let remote = s.with_hooks();
    s.write("s.txt", &format!("pw {SECRET}\n"));
    let bad = s.commit("add s");
    let blob = s.git(&["rev-parse", &format!("{bad}:s.txt")]);
    let clean = s.git_stdin(&["hash-object", "-w", "--stdin"], b"nothing\n");
    s.git(&["replace", &blob, &clean]);
    let o = s.git_out(&["push", "-q", "origin", "feat/x"]);
    assert!(
        !s.remote_has(&remote, &blob),
        "the push published a vault value the hook did not see: {}",
        err(&o)
    );
    assert!(!o.status.success());
}

// ---------------------------------------------------------------------------------------------
// Claim: every path a push publishes is scanned. A tag (or a ref) can point at a tree directly;
// no commit is new, so `diff-tree` over the new commits lists none of its paths.
// ---------------------------------------------------------------------------------------------

#[test]
fn the_paths_of_a_tree_pushed_through_a_tag_are_scanned() {
    let s = Setup::new();
    s.write("a.txt", "a\n");
    s.commit("base");
    let blob = s.git_stdin(&["hash-object", "-w", "--stdin"], b"clean\n");
    let entry = format!("100644 blob {blob}\tname-{SECRET}.txt\n");
    let tree = s.git_stdin(&["mktree"], entry.as_bytes());
    s.git(&["tag", "-a", "-m", "t", "treetag", &tree]);
    let o = s.scan(&["--range", "..treetag", "--ref", "refs/tags/treetag"]);
    assert_eq!(
        code(&o),
        1,
        "a path inside a tagged tree was published unscanned: {}",
        err(&o)
    );
    Setup::never_prints(&o);
    // The same with the bare tree as the end of the range (a lightweight tag to a tree).
    let o = s.scan(&["--range", &format!("..{tree}")]);
    assert_eq!(code(&o), 1, "{}", err(&o));
    Setup::never_prints(&o);
}

// ---------------------------------------------------------------------------------------------
// Attacks that the code is expected to survive (coverage worth keeping).
// ---------------------------------------------------------------------------------------------

#[test]
fn a_value_in_a_directory_name_deep_in_the_tree_is_found_and_never_printed() {
    let s = Setup::new();
    s.write(&format!("a/b/dir-{SECRET}/c/d.txt"), "clean\n");
    s.commit("c");
    let o = s.scan(&["--range", "..HEAD"]);
    assert_eq!(code(&o), 1, "{}", err(&o));
    assert!(out(&o).contains("<redacted-path> blob "), "{}", out(&o));
    Setup::never_prints(&o);
    // And staged.
    s.write(&format!("x/dir-{OTHER}/e.txt"), "clean\n");
    s.git(&["add", "-A"]);
    let o = s.scan(&["--staged"]);
    assert_eq!(code(&o), 1, "{}", err(&o));
    Setup::never_prints(&o);
}

#[test]
fn a_value_in_a_symlink_target_is_found() {
    let s = Setup::new();
    std::os::unix::fs::symlink(format!("../{SECRET}"), s.repo.path().join("link")).unwrap();
    s.git(&["add", "link"]);
    let o = s.scan(&["--staged"]);
    assert_eq!(code(&o), 1, "{}", err(&o));
    s.commit("l");
    let o = s.scan(&["--range", "..HEAD"]);
    assert_eq!(code(&o), 1, "{}", err(&o));
    Setup::never_prints(&o);
}

#[test]
fn crafted_commit_headers_and_a_headerless_tail_are_scanned_by_part() {
    let s = Setup::new();
    s.write("a.txt", "a\n");
    let base = s.commit("base");
    let tree = s.git(&["rev-parse", "HEAD^{tree}"]);
    // An extra header, a continuation line holding the value, and no message at all.
    let raw = format!(
        "tree {tree}\nparent {base}\nauthor A <a@example.invalid> 1 +0000\ncommitter C <c@example.invalid> 1 +0000\nx-extra first\n second {SECRET}\n"
    );
    let c = s.git_stdin(
        &[
            "hash-object",
            "-t",
            "commit",
            "-w",
            "--stdin",
            "--literally",
        ],
        raw.as_bytes(),
    );
    let o = s.scan(&["--range", &format!("{base}..{c}")]);
    assert_eq!(code(&o), 1, "{}", err(&o));
    assert_eq!(out(&o), format!("tok:a secret commit:{c}:header\n"));
    // The value in a later paragraph of the message.
    let raw = format!(
        "tree {tree}\nparent {base}\nauthor A <a@example.invalid> 1 +0000\ncommitter C <c@example.invalid> 1 +0000\n\nsubject\n\nbody\n\n\ntrailer {OTHER}\n"
    );
    let c = s.git_stdin(
        &["hash-object", "-t", "commit", "-w", "--stdin"],
        raw.as_bytes(),
    );
    let o = s.scan(&["--range", &format!("{base}..{c}")]);
    assert_eq!(out(&o), format!("tok:b secret commit:{c}:message\n"));
    // A value in the committer line.
    let raw = format!(
        "tree {tree}\nparent {base}\nauthor A <a@example.invalid> 1 +0000\ncommitter {SECRET} <c@example.invalid> 1 +0000\n\nm\n"
    );
    let c = s.git_stdin(
        &["hash-object", "-t", "commit", "-w", "--stdin"],
        raw.as_bytes(),
    );
    let o = s.scan(&["--range", &format!("{base}..{c}")]);
    assert_eq!(out(&o), format!("tok:a secret commit:{c}:committer\n"));
}

#[test]
fn nested_annotated_tags_are_all_scanned() {
    let s = Setup::new();
    s.write("a.txt", "a\n");
    s.commit("base");
    s.git(&["tag", "-a", "-m", &format!("inner {SECRET}"), "inner"]);
    let inner = s.git(&["rev-parse", "inner"]);
    s.git(&["tag", "-a", "-m", "outer", "outer", "inner"]);
    s.git(&["tag", "-d", "inner"]);
    let o = s.scan(&["--range", "..outer", "--remote", "origin"]);
    assert_eq!(code(&o), 1, "{}", err(&o));
    assert!(
        out(&o).contains(&format!("tok:a secret tag:{inner}:message")),
        "{}",
        out(&o)
    );
}

#[test]
fn another_remotes_tracking_refs_do_not_exclude_anything() {
    let s = Setup::new();
    s.write("old.txt", &format!("{SECRET}\n"));
    let old = s.commit("old");
    s.git(&["update-ref", "refs/remotes/upstream/main", &old]);
    // A remote whose name is a prefix of the other's.
    s.git(&["update-ref", "refs/remotes/originx/main", &old]);
    s.write("new.txt", "fine\n");
    s.commit("new");
    let o = s.scan(&["--range", "..HEAD", "--remote", "origin"]);
    assert_eq!(code(&o), 1, "{}", err(&o));
    // Odd but valid-looking names exclude nothing either.
    for r in [".", "..", "...", "origin.", "_"] {
        let o = s.scan(&["--range", "..HEAD", "--remote", r]);
        assert_ne!(code(&o), 0, "--remote {r}: {}", err(&o));
    }
}

#[test]
fn malformed_ranges_never_pass() {
    let s = Setup::new();
    s.write("a.txt", &format!("{SECRET}\n"));
    s.commit("c");
    for r in [
        "..",
        "...HEAD",
        "HEAD...",
        "HEAD..",
        "..HEAD..",
        ".. HEAD",
        "..HEAD^{tree}x",
        "..@{-1}",
        "..HEAD\n",
        "a..b..c",
    ] {
        let o = s.scan(&["--range", r]);
        assert_ne!(code(&o), 0, "{r:?}: {}", err(&o));
    }
}

#[test]
fn the_staged_scan_follows_the_index_git_commit_uses() {
    // `git commit -a` and `git commit PATH` hand the pre-commit hook a different index in
    // GIT_INDEX_FILE: the scan must read that one.
    let s = Setup::new();
    s.write("a.txt", "a\n");
    s.commit("base");
    s.write("a.txt", &format!("a {SECRET}\n"));
    let alt = s.home.path().join("alt-index");
    std::fs::copy(s.repo.path().join(".git/index"), &alt).unwrap();
    let o = s
        .git_cmd(s.repo.path())
        .env("GIT_INDEX_FILE", &alt)
        .args(["add", "a.txt"])
        .output()
        .unwrap();
    assert!(o.status.success());
    // The default index is clean.
    assert_eq!(code(&s.scan(&["--staged"])), 0);
    let o = s
        .wardenlens()
        .env("GIT_INDEX_FILE", &alt)
        .args(["vault", "scan", "--staged"])
        .output()
        .unwrap();
    assert_eq!(code(&o), 1, "{}", err(&o));
}

#[test]
fn the_staged_pre_commit_refuses_commit_all_and_a_partial_commit() {
    let s = Setup::new();
    s.with_hooks();
    s.write("w.txt", "one\n");
    s.commit("w");
    // Only the working tree holds the value; `commit -a` stages it for the hook.
    s.write("w.txt", &format!("one {SECRET}\n"));
    let o = s.git_out(&["commit", "-a", "-q", "-m", "all"]);
    assert!(!o.status.success(), "commit -a went through");
    Setup::never_prints(&o);
    // A partial commit (`git commit PATH`) uses a temporary index.
    let o = s.git_out(&["commit", "-q", "-m", "partial", "--", "w.txt"]);
    assert!(!o.status.success(), "commit PATH went through");
    // A clean commit is allowed.
    s.git(&["checkout", "--", "w.txt"]);
    s.write("ok.txt", "fine\n");
    s.git(&["add", "ok.txt"]);
    let o = s.git_out(&["commit", "-q", "-m", "ok"]);
    assert!(o.status.success(), "{}", err(&o));
}

#[test]
fn the_staged_pre_push_refuses_values_in_every_published_place() {
    let s = Setup::new();
    let remote = s.with_hooks();
    // A value in a commit message.
    s.write("m.txt", "x\n");
    let c = s.commit(&format!("subject {SECRET}"));
    let o = s.git_out(&["push", "-q", "origin", "feat/x"]);
    assert!(!o.status.success());
    assert!(!s.remote_has(&remote, &c));
    Setup::never_prints(&o);
    s.git(&["reset", "-q", "--hard", "HEAD~1"]);
    // A value already on another remote's tracking ref is still new to origin.
    s.write("u.txt", &format!("{SECRET}\n"));
    let u = s.commit("u");
    s.git(&["update-ref", "refs/remotes/upstream/feat", &u]);
    let o = s.git_out(&["push", "-q", "origin", "feat/x"]);
    assert!(!o.status.success());
    assert!(!s.remote_has(&remote, &u));
}

#[test]
fn the_staged_pre_push_never_prints_a_ref_name_that_holds_a_value() {
    // ADR 0006 section 8: a ref name with a hit is reported as `ref:<index>` and never printed,
    // in every report, error and notice. The scanner does so; the hook's own refusal must too.
    let s = Setup::new();
    let remote = s.with_hooks();
    s.write("n.txt", "y\n");
    let c = s.commit("clean");
    let o = s.git_out(&[
        "push",
        "-q",
        "origin",
        &format!("HEAD:refs/heads/f-{OTHER}"),
    ]);
    assert!(!o.status.success(), "the push went through");
    assert!(!s.remote_has(&remote, &c));
    assert!(
        out(&o).contains("ref:0") || err(&o).contains("ref:0"),
        "{}",
        err(&o)
    );
    Setup::never_prints(&o);
}

#[test]
fn the_staged_pre_push_refusal_never_prints_the_ref_name_even_with_a_fake_scanner() {
    // The scanner is replaced by one that fails and prints nothing, so anything on stderr that
    // names the ref comes from the hook itself.
    let s = Setup::new();
    let remote = s.with_hooks();
    let fake = s.home.path().join(".cargo/bin/wardenlens");
    std::fs::remove_file(&fake).unwrap();
    std::fs::write(&fake, "#!/bin/sh\nexit 1\n").unwrap();
    std::fs::set_permissions(&fake, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
    s.write("n.txt", "y\n");
    let c = s.commit("clean");
    let name = format!("refs/heads/f-{OTHER}");
    let o = s.git_out(&["push", "-q", "origin", &format!("HEAD:{name}")]);
    assert!(!o.status.success(), "the push went through");
    assert!(!s.remote_has(&remote, &c));
    assert!(!err(&o).contains(OTHER), "{}", err(&o));
    assert!(!out(&o).contains(OTHER), "{}", out(&o));
    assert!(err(&o).contains("ref:0"), "{}", err(&o));
}
