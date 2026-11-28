//! Adversarial end-to-end tests (#128 round 2): a partial clone (blobless, treeless) scanned
//! by range or staged must fail closed (exit 2), never fetch the missing objects, and never
//! print a value; refusals of bad arguments never echo a value. Temporary repositories and a
//! temporary HOME with synthetic values only.

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

/// An upstream repository (in the setup's repo dir) with one commit whose file holds the value,
/// then a partial clone of it with `filter` into a new directory. Returns (clone dir, blob id).
fn partial_clone(s: &Setup, filter: &str, checkout: bool) -> (TempDir, String) {
    let blob = s.git_stdin(
        &["hash-object", "-w", "--stdin"],
        format!("token = {SECRET}\n").as_bytes(),
    );
    let tree = s.git_stdin(
        &["mktree"],
        format!("100644 blob {blob}\tconf.txt\n").as_bytes(),
    );
    let c = s.git(&["commit-tree", &tree, "-m", "c"]);
    s.git(&["update-ref", "refs/heads/main", &c]);
    s.git(&["config", "uploadpack.allowFilter", "true"]);
    s.git(&["config", "uploadpack.allowAnySHA1InWant", "true"]);
    let dir = tempfile::tempdir().unwrap();
    let clone = dir.path().join("c");
    let mut args = vec!["clone", "-q"];
    if !checkout {
        args.push("--no-checkout");
    }
    let f = format!("--filter={filter}");
    args.push(&f);
    let url = format!("file://{}", s.repo.path().display());
    args.push(&url);
    let o = s
        .git_cmd(dir.path())
        .args(&args)
        .arg(&clone)
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", err(&o));
    (dir, blob)
}

fn clone_path(d: &TempDir) -> std::path::PathBuf {
    d.path().join("c")
}

/// Whether `id` is present in the clone without fetching.
fn present(s: &Setup, d: &TempDir, id: &str) -> bool {
    s.git_cmd(&clone_path(d))
        .env("GIT_NO_LAZY_FETCH", "1")
        .args(["cat-file", "-e", id])
        .status()
        .unwrap()
        .success()
}

fn object_files(d: &TempDir) -> usize {
    fn walk(p: &Path, n: &mut usize) {
        for e in std::fs::read_dir(p).unwrap() {
            let e = e.unwrap();
            if e.file_type().unwrap().is_dir() {
                walk(&e.path(), n);
            } else {
                *n = n.saturating_add(1);
            }
        }
    }
    let mut n = 0;
    walk(&clone_path(d).join(".git/objects"), &mut n);
    n
}

fn scan_in(s: &Setup, dir: &Path, args: &[&str]) -> Output {
    let mut c = s.wardenlens();
    c.current_dir(dir).args(["vault", "scan"]).args(args);
    c.stdin(Stdio::null()).output().unwrap()
}

#[test]
fn control_the_full_upstream_is_found_by_a_range_scan() {
    let s = Setup::new();
    let (_d, _blob) = partial_clone(&s, "blob:none", false);
    let o = scan_in(&s, s.repo.path(), &["--range", "..main"]);
    assert_eq!(code(&o), 1, "{}{}", out(&o), err(&o));
    Setup::never_prints(&o);
}

#[test]
fn a_blobless_clone_range_scan_fails_closed_and_fetches_nothing() {
    let s = Setup::new();
    let (d, blob) = partial_clone(&s, "blob:none", false);
    assert!(!present(&s, &d, &blob), "the clone is blobless");
    let before = object_files(&d);
    let o = scan_in(&s, &clone_path(&d), &["--range", "..HEAD"]);
    assert_eq!(code(&o), 2, "{}{}", out(&o), err(&o));
    Setup::never_prints(&o);
    assert!(!present(&s, &d, &blob), "the scan fetched the blob");
    assert_eq!(object_files(&d), before, "the scan wrote objects");
}

#[test]
fn a_treeless_clone_range_scan_fails_closed_and_fetches_nothing() {
    let s = Setup::new();
    let (d, blob) = partial_clone(&s, "tree:0", false);
    let before = object_files(&d);
    let o = scan_in(&s, &clone_path(&d), &["--range", "..HEAD"]);
    assert_eq!(code(&o), 2, "{}{}", out(&o), err(&o));
    Setup::never_prints(&o);
    assert!(!present(&s, &d, &blob), "the scan fetched the blob");
    assert_eq!(object_files(&d), before, "the scan wrote objects");
}

#[test]
fn a_blobless_clone_staged_scan_of_a_missing_blob_fails_closed_and_fetches_nothing() {
    let s = Setup::new();
    let (d, blob) = partial_clone(&s, "blob:none", false);
    // The index names the missing blob at a new path (staged, not in HEAD) without reading it.
    let o = s
        .git_cmd(&clone_path(&d))
        .env("GIT_NO_LAZY_FETCH", "1")
        .args(["read-tree", "HEAD"])
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", err(&o));
    let o = s
        .git_cmd(&clone_path(&d))
        .env("GIT_NO_LAZY_FETCH", "1")
        .args(["update-index", "--add", "--cacheinfo"])
        .arg(format!("100644,{blob},copy.txt"))
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", err(&o));
    assert!(!present(&s, &d, &blob));
    let before = object_files(&d);
    let o = scan_in(&s, &clone_path(&d), &["--staged"]);
    assert_eq!(code(&o), 2, "{}{}", out(&o), err(&o));
    Setup::never_prints(&o);
    assert!(!present(&s, &d, &blob), "the scan fetched the blob");
    assert_eq!(object_files(&d), before, "the scan wrote objects");
}

#[test]
fn a_blobless_clone_range_scan_with_the_remote_named_fails_closed_or_excludes_it() {
    // With --remote origin the upstream's objects are not new, so nothing missing is read: a
    // pass (exit 0) is right here, but a fetch is never allowed.
    let s = Setup::new();
    let (d, blob) = partial_clone(&s, "blob:none", false);
    let before = object_files(&d);
    let o = scan_in(
        &s,
        &clone_path(&d),
        &["--range", "..HEAD", "--remote", "origin"],
    );
    assert!(matches!(code(&o), 0 | 2), "{}{}", out(&o), err(&o));
    Setup::never_prints(&o);
    assert!(!present(&s, &d, &blob));
    assert_eq!(object_files(&d), before);
}

#[test]
fn refusals_of_bad_scan_arguments_never_echo_a_value() {
    let s = Setup::new();
    s.git(&["commit-tree", &s.raw_tree(&[]), "-m", "base"]);
    let cases: Vec<Vec<String>> = vec![
        vec!["--range".into(), format!("{SECRET}..HEAD")],
        vec!["--range".into(), format!("HEAD..{SECRET}")],
        vec!["--range".into(), format!("{SECRET}...HEAD")],
        vec!["--range".into(), SECRET.into()],
        vec!["--range".into(), format!("-{SECRET}..x")],
        vec!["--range".into(), format!("..{SECRET}")],
        vec![
            "--range".into(),
            "..HEAD".into(),
            "--remote".into(),
            format!("{SECRET}/x"),
        ],
        vec![
            "--range".into(),
            format!("{SECRET}..HEAD"),
            "--ref".into(),
            OTHER.into(),
        ],
        vec!["--staged".into(), "--ref".into(), OTHER.into()],
        vec![format!("--{SECRET}")],
    ];
    for c in cases {
        let a: Vec<&str> = c.iter().map(String::as_str).collect();
        let o = s.scan(&a);
        assert_ne!(code(&o), 0, "{a:?}: {}{}", out(&o), err(&o));
        Setup::never_prints(&o);
    }
}
fn hex(id: &str) -> Vec<u8> {
    id.as_bytes()
        .chunks(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}
