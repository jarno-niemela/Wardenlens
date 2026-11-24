//! Adversary round (PR #71 rework 1): a vault value that the catalogue accepts, written in a
//! form that TOML decodes back to the exact value, must still be a scan hit. All values are
//! synthetic (documentation ranges and made-up tokens).

#![expect(
    clippy::unwrap_used,
    reason = "integration-test helpers outside #[test] fns"
)]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use tempfile::TempDir;
use wardenlens_core::catalogue::{CatalogueEntry, CatalogueError, SiteDataKind, validate};

const SECRET: &str = "zq-synthetic-mark-4410";
const HOST: &str = "192.0.2.44";

fn cameras_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../cameras")
}

struct Home(TempDir);

impl Home {
    fn new() -> Self {
        let home = Self(tempfile::tempdir().unwrap());
        assert!(home.run(&["init"], "").status.success());
        for (id, kind, value) in [("tok:a", "secret", SECRET), ("cam:a:host", "host", HOST)] {
            let set = home.run(&["set", id, "--kind", kind], value);
            assert!(set.status.success(), "{}", text(&set));
        }
        home
    }

    fn run(&self, args: &[&str], stdin: &str) -> Output {
        let mut child = Command::new(env!("CARGO_BIN_EXE_wardenlens"))
            .env_clear()
            .env("HOME", self.0.path())
            .arg("vault")
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let _ = child.stdin.take().unwrap().write_all(stdin.as_bytes());
        child.wait_with_output().unwrap()
    }

    fn scan(&self, path: &Path) -> Output {
        self.run(&["scan", path.to_str().unwrap()], "")
    }
}

fn text(o: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

const BASE: &str = "vendor = \"Acme\"\nmodel = \"C1\"\nsupport = \"community\"\n\
[[evidence]]\nreference = \"docs/adr/0002-camera-integration.md\"\n";

/// Writes `cameras/acme/c1.toml` = BASE + `quirks = [<quirk_toml>]`, checks the catalogue accepts
/// it and that the parsed quirk is exactly `value`, then scans the directory.
///
/// Rework 2: a source containing a backslash is refused by the catalogue (`None`); that is the
/// other acceptable outcome, because a refused entry cannot be committed. Any other refusal is a
/// failure.
fn accepted_and_scanned(home: &Home, quirk_toml: &str, value: &str) -> Option<Output> {
    let src = format!("quirks = [{quirk_toml}]\n{BASE}");
    let entry = match CatalogueEntry::from_toml_str(&src) {
        Ok(entry) => entry,
        Err(e) => {
            assert!(
                src.contains('\\')
                    && matches!(
                        e,
                        CatalogueError::SiteData {
                            kind: SiteDataKind::Encoding,
                            ..
                        }
                    ),
                "refused for another reason: {e}"
            );
            return None;
        }
    };
    validate(&entry).unwrap();
    assert_eq!(
        entry.quirks,
        [value.to_owned()],
        "the fixture must decode to the value"
    );
    let work = tempfile::tempdir().unwrap();
    let dir = work.path().join("cameras/acme");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("c1.toml"), src).unwrap();
    let o = home.scan(&work.path().join("cameras"));
    drop(work);
    Some(o)
}

fn escaped(value: &str, long: bool) -> String {
    value
        .chars()
        .map(|c| {
            if long {
                format!("\\U{:08X}", u32::from(c))
            } else {
                format!("\\u{:04X}", u32::from(c))
            }
        })
        .collect()
}

#[test]
fn planted_value_in_any_catalogue_file_is_a_hit_and_never_printed() {
    let home = Home::new();
    let work = tempfile::tempdir().unwrap();
    let copy = work.path().join("cameras");
    let mut files = Vec::new();
    let mut stack = vec![(cameras_dir(), copy.clone())];
    while let Some((from, to)) = stack.pop() {
        std::fs::create_dir_all(&to).unwrap();
        for e in std::fs::read_dir(&from).unwrap() {
            let e = e.unwrap();
            let t = to.join(e.file_name());
            if e.file_type().unwrap().is_dir() {
                stack.push((e.path(), t));
            } else {
                std::fs::copy(e.path(), &t).unwrap();
                files.push(t);
            }
        }
    }
    files.sort();
    assert!(files.len() >= 6, "{files:?}");
    assert_eq!(home.scan(&copy).status.code(), Some(0));
    for f in &files {
        let original = std::fs::read_to_string(f).unwrap();
        for planted in [SECRET, HOST] {
            std::fs::write(f, format!("{original}\n# {planted}\n")).unwrap();
            let o = home.scan(&copy);
            assert_eq!(o.status.code(), Some(1), "{}: {}", f.display(), text(&o));
            let all = text(&o);
            assert!(!all.contains(SECRET) && !all.contains(HOST));
        }
        std::fs::write(f, original).unwrap();
    }
}

#[test]
fn plain_value_in_an_accepted_quirk_is_a_hit() {
    let home = Home::new();
    for v in [SECRET, HOST] {
        let o = accepted_and_scanned(&home, &format!("\"gw {v}\"").replace("gw ", ""), v)
            .expect("a plain value must be accepted");
        assert_eq!(o.status.code(), Some(1), "{v}: {}", text(&o));
    }
}

#[test]
fn short_unicode_escaped_value_in_an_accepted_quirk_is_a_hit() {
    let home = Home::new();
    for v in [SECRET, HOST] {
        let o = accepted_and_scanned(&home, &format!("\"{}\"", escaped(v, false)), v);
        if let Some(o) = o {
            assert_eq!(o.status.code(), Some(1), "{v}: {}", text(&o));
        }
    }
}

#[test]
fn long_unicode_escaped_value_in_an_accepted_quirk_is_a_hit() {
    // TOML basic strings accept `\UXXXXXXXX`; the parsed quirk is exactly the vault value.
    let home = Home::new();
    for v in [SECRET, HOST] {
        let o = accepted_and_scanned(&home, &format!("\"{}\"", escaped(v, true)), v);
        if let Some(o) = o {
            assert_eq!(o.status.code(), Some(1), "{v}: {}", text(&o));
        }
    }
}

#[test]
fn line_continued_value_in_an_accepted_quirk_is_a_hit() {
    // TOML multi-line basic string: a line-ending backslash removes the newline and the
    // following indentation, so the parsed quirk is exactly the vault value.
    let home = Home::new();
    for v in [SECRET, HOST] {
        let (a, b) = v.split_at(5);
        let o = accepted_and_scanned(&home, &format!("\"\"\"{a}\\\n    {b}\"\"\""), v);
        if let Some(o) = o {
            assert_eq!(o.status.code(), Some(1), "{v}: {}", text(&o));
        }
    }
}

#[test]
fn single_escaped_char_in_an_accepted_quirk_is_a_hit() {
    // Only one character escaped (`.` for the first dot / hyphen).
    let home = Home::new();
    for v in [SECRET, HOST] {
        let i = v.find(['.', '-']).unwrap();
        let (a, rest) = v.split_at(i);
        let lit = format!("\"{a}{}{}\"", escaped(&rest[..1], true), &rest[1..]);
        let o = accepted_and_scanned(&home, &lit, v);
        if let Some(o) = o {
            assert_eq!(o.status.code(), Some(1), "{v}: {}", text(&o));
        }
    }
}
