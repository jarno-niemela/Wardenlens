//! Adversary tests for #163 (`import agentdvr` catalogue models), end to end.
//!
//! Synthetic only: documentation-range hosts, invented names and passwords, temporary
//! directories, a cleared environment. The query path is read from the catalogue files.

#![expect(
    clippy::unwrap_used,
    reason = "integration-test helpers outside #[test] fns; clippy.toml in-tests allowances do not reach them"
)]

use std::ffi::OsStr;
use std::fmt::Write as _;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use tempfile::TempDir;

const PASSWORD: &str = "Zx9-fake-pass-adv163";
const USER: &str = "fakeuseradv163";
const MARK: &str = "Mk7Secretopt";

fn listed_query_path() -> (String, String) {
    let found: Option<(String, String)> = find_listed();
    found.unwrap()
}

fn find_listed() -> Option<(String, String)> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../cameras");
    let mut files = Vec::new();
    for v in fs::read_dir(&root).unwrap() {
        let v = v.unwrap().path();
        if v.is_dir() {
            for f in fs::read_dir(&v).unwrap() {
                files.push(f.unwrap().path());
            }
        }
    }
    files.sort();
    for f in files {
        let text = fs::read_to_string(&f).unwrap();
        for line in text.lines().filter(|l| l.trim_start().starts_with("paths")) {
            for part in line.split('"').skip(1).step_by(2) {
                if part.contains('?') {
                    let model = f.file_stem().unwrap().to_str().unwrap();
                    let vendor = f.parent().unwrap().file_name().unwrap().to_str().unwrap();
                    return Some((format!("{vendor}/{model}"), part.to_owned()));
                }
            }
        }
    }
    None
}

/// A catalogue model other than `not`.
fn other_model(not: &str) -> String {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../cameras");
    let mut all = Vec::new();
    for v in fs::read_dir(&root).unwrap() {
        let v = v.unwrap().path();
        if v.is_dir() {
            for f in fs::read_dir(&v).unwrap() {
                let f = f.unwrap().path();
                if f.extension() == Some(OsStr::new("toml")) {
                    all.push(format!(
                        "{}/{}",
                        v.file_name().unwrap().to_str().unwrap(),
                        f.file_stem().unwrap().to_str().unwrap()
                    ));
                }
            }
        }
    }
    all.sort();
    all.into_iter().find(|m| m != not).unwrap()
}

struct Site {
    dir: TempDir,
}

impl Site {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        for d in ["state", "keys", "in"] {
            let p = dir.path().join(d);
            fs::create_dir(&p).unwrap();
            fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let t = dir.path().display();
        let config = format!(
            "[api]\nlisten = \"127.0.0.1:8080\"\n[storage]\nhot_root = \"{t}/hot\"\n\
             archive_root = \"{t}/archive\"\n[database]\npath = \"{t}/state/index.db\"\n\
             [secrets]\nkey_file = \"{t}/keys/secrets.key\"\n"
        );
        let site = Self { dir };
        fs::write(site.p("wardenlens.toml"), config).unwrap();
        fs::set_permissions(site.p("wardenlens.toml"), fs::Permissions::from_mode(0o600)).unwrap();
        let out = site.run(&["secrets", "init"]);
        assert!(out.status.success(), "{}", text(&out.stderr));
        site
    }
    fn p(&self, rel: &str) -> PathBuf {
        self.dir.path().join(rel)
    }
    fn run_os(&self, args: &[&OsStr]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_wardenlens"))
            .env_clear()
            .arg("--config")
            .arg(self.p("wardenlens.toml"))
            .args(args)
            .stdin(Stdio::null())
            .output()
            .unwrap()
    }
    fn run(&self, args: &[&str]) -> Output {
        let a: Vec<&OsStr> = args.iter().map(OsStr::new).collect();
        self.run_os(&a)
    }
    fn xml_hosts(&self, cams: &[(u32, &str, &str)]) -> PathBuf {
        let mut body = String::new();
        for (id, host, path) in cams {
            let path = path.replace('&', "&amp;");
            write!(
                body,
                "<camera id=\"{id}\" name=\"Fake Cam {id}\"><settings>\
                 <videosourcestring>rtsp://{host}:554{path}</videosourcestring>\
                 <login>{USER}</login><password>{PASSWORD}</password></settings></camera>"
            )
            .unwrap();
        }
        let path = self.p("in/objects.xml");
        fs::write(
            &path,
            format!("<objects><cameras>{body}</cameras></objects>"),
        )
        .unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        path
    }
    fn xml(&self, cams: &[(u32, &str)]) -> PathBuf {
        let v: Vec<(u32, String, &str)> = cams
            .iter()
            .map(|(id, p)| (*id, format!("192.0.2.{id}"), *p))
            .collect();
        let r: Vec<(u32, &str, &str)> = v.iter().map(|(i, h, p)| (*i, h.as_str(), *p)).collect();
        self.xml_hosts(&r)
    }
    fn import(&self, file: &Path, extra: &[&str]) -> Output {
        let mut args = vec!["import", "agentdvr", file.to_str().unwrap()];
        args.extend_from_slice(extra);
        self.run(&args)
    }
    fn list(&self) -> String {
        text(&self.run(&["camera", "list"]).stdout)
    }
    fn files(&self) -> Vec<(String, Vec<u8>)> {
        let mut v: Vec<(String, Vec<u8>)> = fs::read_dir(self.p("state"))
            .unwrap()
            .map(|e| {
                let e = e.unwrap();
                (
                    e.file_name().to_string_lossy().into_owned(),
                    fs::read(e.path()).unwrap(),
                )
            })
            .collect();
        v.sort();
        v
    }
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

fn row<'a>(out: &'a str, id: &str) -> &'a str {
    out.lines().find(|l| l.starts_with(id)).unwrap()
}

/// Hostile shapes of the one listed query path never match it (exact match only), whether the
/// model is auto-matched or chosen. Each must be skipped, never registered.
#[test]
fn near_miss_query_shapes_are_skipped_under_any_model_source() {
    let (model, path) = listed_query_path();
    let (head, query) = path.split_once('?').unwrap();
    let pairs: Vec<&str> = query.split('&').collect();
    let mut reversed = pairs.clone();
    reversed.reverse();
    let first = pairs[0];
    let shapes = vec![
        // Duplicate key.
        format!("{path}&{first}"),
        // Reordered keys (only differs when there are two or more).
        format!("{head}?{}", reversed.join("&")),
        // Upper-case query.
        format!("{head}?{}", query.to_ascii_uppercase()),
        // A trailing separator.
        format!("{path}&"),
        // A second query string.
        format!("{path}?{query}"),
        // An empty value appended.
        format!("{path}&x="),
        // A prefix of the query.
        format!("{head}?{first}"),
    ];
    for shape in shapes {
        if shape == path {
            continue;
        }
        for extra in [
            vec![],
            vec!["--model".to_owned(), model.clone()],
            vec!["--camera-model".to_owned(), format!("agentdvr-1={model}")],
        ] {
            let site = Site::new();
            let file = site.xml(&[(1, &shape)]);
            let extra: Vec<&str> = extra.iter().map(String::as_str).collect();
            let out = site.import(&file, &extra);
            let list = site.list();
            assert!(
                list.contains("no cameras") || !list.contains("agentdvr-1"),
                "{shape:?} {extra:?} registered: {list}\n{}",
                text(&out.stdout)
            );
        }
    }
}

/// The listed query under the head of another path: the auto-match (exact path) does not match,
/// so without an option it is skipped.
#[test]
fn a_listed_query_on_another_head_is_not_auto_matched() {
    let (_, path) = listed_query_path();
    let (_, query) = path.split_once('?').unwrap();
    let site = Site::new();
    let file = site.xml(&[(1, &format!("/other/head?{query}"))]);
    let out = site.import(&file, &[]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(row(&text(&out.stdout), "agentdvr-1").contains("skipped"));
    assert!(site.list().contains("no cameras"), "{}", site.list());
}

/// A model listed under another model is refused for this query: `--model <other>` does not make
/// the listed query of a different model acceptable.
#[test]
fn another_catalogue_model_does_not_accept_a_query_it_does_not_list() {
    let (model, path) = listed_query_path();
    let other = other_model(&model);
    let site = Site::new();
    let file = site.xml(&[(1, &path)]);
    for extra in [
        vec!["--model", other.as_str()],
        vec!["--camera-model", &format!("agentdvr-1={other}")],
    ] {
        let out = site.import(&file, &extra);
        assert!(out.status.success(), "{}", text(&out.stderr));
        let r = row(&text(&out.stdout), "agentdvr-1").to_owned();
        assert!(r.contains("skipped") && r.contains(&other), "{r}");
        assert!(!r.contains('?'), "{r}");
        assert!(site.list().contains("no cameras"), "{}", site.list());
    }
    // And `--camera-model` wins over `--model`: the right model for camera 1 imports it.
    let out = site.import(
        &file,
        &[
            "--model",
            other.as_str(),
            "--camera-model",
            &format!("agentdvr-1={model}"),
        ],
    );
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(
        row(&site.list(), "agentdvr-1").contains(&model),
        "{}",
        site.list()
    );
}

/// No error message echoes the option text, whatever the malformed shape, and nothing is written.
#[test]
fn malformed_model_options_never_echo_their_text() {
    let site = Site::new();
    let file = site.xml(&[(1, "/a")]);
    let cases: Vec<Vec<String>> = vec![
        vec!["--model".into(), MARK.into()],
        vec!["--model".into(), format!("{MARK}/{MARK}")],
        vec!["--model".into(), format!("vendor/{MARK}")],
        vec!["--model".into(), format!("{}/x", MARK.to_ascii_lowercase())],
        vec!["--model".into(), format!("a/b/{MARK}")],
        vec!["--model".into(), format!("/{MARK}")],
        vec!["--model".into(), String::new()],
        vec!["--camera-model".into(), MARK.into()],
        vec!["--camera-model".into(), format!("{MARK}=a/b")],
        vec!["--camera-model".into(), format!("agentdvr-1={MARK}")],
        vec!["--camera-model".into(), format!("agentdvr-1=x/{MARK}")],
        vec!["--camera-model".into(), format!("agentdvr-1=={MARK}")],
        vec!["--camera-model".into(), format!("={MARK}")],
        vec![
            "--camera-model".into(),
            format!("{}=x/y", MARK.to_ascii_lowercase()),
        ],
        // The same id twice.
        vec![
            "--camera-model".into(),
            "agentdvr-1=x/y".into(),
            "--camera-model".into(),
            format!("agentdvr-1={MARK}"),
        ],
        // `--model` twice (clap).
        vec![
            "--model".into(),
            format!("a/{MARK}"),
            "--model".into(),
            format!("b/{MARK}"),
        ],
    ];
    for extra in cases {
        let e: Vec<&str> = extra.iter().map(String::as_str).collect();
        let out = site.import(&file, &e);
        assert_ne!(out.status.code(), Some(0), "{extra:?}");
        let all = format!("{}{}", text(&out.stdout), text(&out.stderr));
        assert!(
            !all.to_ascii_lowercase()
                .contains(&MARK.to_ascii_lowercase()),
            "{extra:?} echoed: {all}"
        );
        assert!(!site.p("state/vault.db").exists(), "{extra:?}");
        assert!(!site.p("state/index.db").exists(), "{extra:?}");
    }
}

/// A non-UTF-8 option value is refused without echoing it.
#[test]
fn a_non_utf8_model_option_is_refused_without_echo() {
    let site = Site::new();
    let file = site.xml(&[(1, "/a")]);
    let mut bad = b"agentdvr-1=x/".to_vec();
    bad.extend_from_slice(MARK.as_bytes());
    bad.push(0xff);
    for flag in ["--model", "--camera-model"] {
        let out = site.run_os(&[
            OsStr::new("import"),
            OsStr::new("agentdvr"),
            file.as_os_str(),
            OsStr::new(flag),
            OsStr::from_bytes(&bad),
        ]);
        assert_ne!(out.status.code(), Some(0));
        let all = format!("{}{}", text(&out.stdout), text(&out.stderr));
        assert!(!all.contains(MARK), "{flag} echoed: {all}");
    }
}

/// A dry run and the real run agree on every camera's status when the registry holds a row the
/// import will not overwrite.
#[test]
fn dry_run_agrees_with_the_real_run_over_an_existing_row_of_another_model() {
    let (model, _) = listed_query_path();
    let site = Site::new();
    let file = site.xml(&[(1, "/a")]);
    // An earlier import under a catalogue model.
    assert!(site.import(&file, &["--model", &model]).status.success());
    // Now with no model: the row is of another model and is kept.
    let dry = text(&site.import(&file, &["--dry-run"]).stdout);
    let real = text(&site.import(&file, &[]).stdout);
    let dry_skipped = row(&dry, "agentdvr-1").contains("skipped");
    let real_skipped = row(&real, "agentdvr-1").contains("skipped");
    assert!(real_skipped, "{real}");
    assert_eq!(
        dry_skipped, real_skipped,
        "dry run:\n{dry}\nreal run:\n{real}"
    );
}

/// A re-import that keeps a row of another model leaves the vault and index byte-identical.
#[test]
fn a_kept_row_leaves_the_state_directory_byte_identical() {
    let (model, _) = listed_query_path();
    let site = Site::new();
    let file = site.xml(&[(1, "/a")]);
    assert!(site.import(&file, &["--model", &model]).status.success());
    let before = site.files();
    // A different host, name and login for the same id.
    let file = site.xml_hosts(&[(1, "198.51.100.7", "/b")]);
    let out = site.import(&file, &[]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(row(&text(&out.stdout), "agentdvr-1").contains("skipped"));
    assert_eq!(before, site.files(), "state changed");
    assert!(site.list().contains("192.0.2.1"), "{}", site.list());
}

/// Every output and stderr line holds no login, whatever the option path taken.
#[test]
fn no_login_reaches_the_output_under_any_option() {
    let (model, path) = listed_query_path();
    let site = Site::new();
    let leak = format!("/{USER}{path}");
    let file = site.xml(&[(1, &path), (2, &leak), (3, "/plain")]);
    for extra in [
        vec![],
        vec!["--dry-run"],
        vec!["--model", model.as_str()],
        vec!["--camera-model", &format!("agentdvr-2={model}")],
    ] {
        let out = site.import(&file, &extra);
        for s in [text(&out.stdout), text(&out.stderr)] {
            assert!(!s.contains(USER) && !s.contains(PASSWORD), "{extra:?}: {s}");
        }
    }
    assert!(!site.list().contains("agentdvr-2"), "{}", site.list());
}
