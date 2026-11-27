//! Adversary tests for #163 / #207 round 2 (PR #213): the `agentdvr-` reservation end to end,
//! flows over reserved rows, and dry run against the real run.
//!
//! Synthetic only: documentation-range hosts, invented names and passwords, temporary
//! directories, a cleared environment.

#![expect(
    clippy::unwrap_used,
    reason = "integration-test helpers outside #[test] fns; clippy.toml in-tests allowances do not reach them"
)]

use std::fmt::Write as _;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use tempfile::TempDir;

const PASSWORD: &str = "Zx9-fake-pass-adv163r2";
const USER: &str = "fakeuseradv163r2";

/// A catalogue model and one listed path of it (any), read from the catalogue files.
fn some_model() -> String {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../cameras");
    let mut all = Vec::new();
    for v in fs::read_dir(&root).unwrap() {
        let v = v.unwrap().path();
        if v.is_dir() {
            for f in fs::read_dir(&v).unwrap() {
                let f = f.unwrap().path();
                if f.extension().and_then(|e| e.to_str()) == Some("toml") {
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
    all.into_iter().next().unwrap()
}

fn other_model(not: &str) -> String {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../cameras");
    let mut all = Vec::new();
    for v in fs::read_dir(&root).unwrap() {
        let v = v.unwrap().path();
        if v.is_dir() {
            for f in fs::read_dir(&v).unwrap() {
                let f = f.unwrap().path();
                if f.extension().and_then(|e| e.to_str()) == Some("toml") {
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
    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_wardenlens"))
            .env_clear()
            .arg("--config")
            .arg(self.p("wardenlens.toml"))
            .args(args)
            .stdin(Stdio::null())
            .output()
            .unwrap()
    }
    fn xml_hosts(&self, cams: &[(u32, &str, &str)]) -> PathBuf {
        let mut body = String::new();
        for (id, host, path) in cams {
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
    fn import(&self, file: &Path, extra: &[&str]) -> Output {
        let mut args = vec!["import", "agentdvr", file.to_str().unwrap()];
        args.extend_from_slice(extra);
        self.run(&args)
    }
    fn state(&self) -> Vec<(String, Vec<u8>)> {
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
    fn state_names(&self) -> Vec<String> {
        self.state().into_iter().map(|(n, _)| n).collect()
    }
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

fn status_of(out: &str, id: &str) -> String {
    let line = out
        .lines()
        .find(|l| l.split_whitespace().next() == Some(id))
        .unwrap();
    if line.contains("skipped") {
        "skipped".to_owned()
    } else {
        "written".to_owned()
    }
}

/// The binary refuses every reserved id with exit 1 and creates no index or vault; near misses
/// get past the reservation (they fail later, on the host, which is fine).
#[test]
fn camera_add_refuses_reserved_ids_end_to_end_and_creates_nothing() {
    let model = some_model();
    for id in ["agentdvr-1", "agentdvr-pos-0", "agentdvr-", "agentdvr-x-y"] {
        let site = Site::new();
        let before = site.state_names();
        let out = site.run(&[
            "camera",
            "add",
            "--id",
            id,
            "--host",
            "192.0.2.10",
            "--model",
            &model,
            "--username",
            USER,
        ]);
        assert_eq!(out.status.code(), Some(1), "{id}: {}", text(&out.stderr));
        let err = text(&out.stderr);
        assert!(err.contains("reserved"), "{id}: {err}");
        assert_eq!(before, site.state_names(), "{id}: a file was created");
    }
    for id in ["agentdvr", "agentdv-1", "xagentdvr-1"] {
        let site = Site::new();
        let out = site.run(&[
            "camera",
            "add",
            "--id",
            id,
            "--host",
            "192.0.2.10",
            "--model",
            &model,
            "--username",
            USER,
        ]);
        assert!(
            !text(&out.stderr).contains("reserved"),
            "{id}: {}",
            text(&out.stderr)
        );
    }
}

/// The reservation does not stop list, remove and re-import of rows the import made, and
/// `camera add` over an imported id is refused without touching the row.
#[test]
fn reserved_rows_are_listed_removed_and_reimported_and_never_touched_by_add() {
    let model = some_model();
    let site = Site::new();
    let file = site.xml_hosts(&[(1, "192.0.2.21", "/s1"), (2, "192.0.2.22", "/s2")]);
    let out = site.import(&file, &[]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let list = text(&site.run(&["camera", "list"]).stdout);
    assert!(
        list.contains("agentdvr-1") && list.contains("agentdvr-2"),
        "{list}"
    );
    let before = site.state();
    let out = site.run(&[
        "camera",
        "add",
        "--id",
        "agentdvr-1",
        "--host",
        "192.0.2.99",
        "--model",
        &model,
        "--username",
        "someone-else",
    ]);
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(before, site.state(), "camera add changed the state");
    let out = site.run(&["camera", "remove", "agentdvr-1"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let list = text(&site.run(&["camera", "list"]).stdout);
    assert!(
        !list.contains("agentdvr-1 ") && list.contains("agentdvr-2"),
        "{list}"
    );
    let out = site.import(&file, &[]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let list = text(&site.run(&["camera", "list"]).stdout);
    assert!(list.contains("agentdvr-1"), "{list}");
}

/// The dry run that reads an existing index leaves the state directory byte-identical (no
/// sidecar left behind, the main file unchanged), in every conflict state.
#[test]
fn a_dry_run_over_an_existing_index_changes_no_byte() {
    let model = some_model();
    let other = other_model(&model);
    let site = Site::new();
    let file = site.xml_hosts(&[(1, "192.0.2.31", "/s1")]);
    assert!(site.import(&file, &["--model", &model]).status.success());
    let before = site.state();
    for extra in [
        vec!["--dry-run"],
        vec!["--dry-run", "--model", &model],
        vec!["--dry-run", "--model", &other],
        vec!["--dry-run", "--camera-model", "agentdvr-1=x/y"],
    ] {
        let _ = site.import(&file, &extra);
        assert_eq!(before, site.state(), "{extra:?} changed the state");
    }
}

/// Dry run and real run report the same status for every camera across a sequence of model
/// choices over one registry (the real run is applied after each comparison).
#[test]
fn dry_run_and_real_run_agree_across_a_sequence_of_model_choices() {
    let model = some_model();
    let other = other_model(&model);
    let site = Site::new();
    let file = site.xml_hosts(&[
        (1, "192.0.2.41", "/s1"),
        (2, "192.0.2.42", "/s2"),
        (3, "192.0.2.43", "/s3"),
    ]);
    let cm1 = format!("agentdvr-1={model}");
    let cm2 = format!("agentdvr-2={other}");
    let steps: Vec<Vec<&str>> = vec![
        vec![],
        vec!["--model", &model],
        vec![],
        vec!["--model", &other],
        vec!["--camera-model", &cm1, "--camera-model", &cm2],
        vec!["--model", &other, "--camera-model", &cm1],
        vec![],
    ];
    for step in &steps {
        let mut dry_args = vec!["--dry-run"];
        dry_args.extend_from_slice(step);
        let dry = site.import(&file, &dry_args);
        let real = site.import(&file, step);
        assert_eq!(dry.status.code(), real.status.code(), "{step:?}");
        let (dry, real) = (text(&dry.stdout), text(&real.stdout));
        for id in ["agentdvr-1", "agentdvr-2", "agentdvr-3"] {
            assert_eq!(
                status_of(&dry, id),
                status_of(&real, id),
                "{step:?} {id}\ndry:\n{dry}\nreal:\n{real}"
            );
        }
    }
}

/// A stray `-wal` with no main file: the real run refuses (the index cannot be opened). The dry
/// run must not promise an import the real run will not do.
#[test]
fn dry_run_agrees_with_the_real_run_when_the_index_cannot_be_opened() {
    let site = Site::new();
    let file = site.xml_hosts(&[(1, "192.0.2.51", "/s1")]);
    fs::write(site.p("state/index.db-wal"), b"not a wal").unwrap();
    fs::set_permissions(
        site.p("state/index.db-wal"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let dry = site.import(&file, &["--dry-run"]);
    let real = site.import(&file, &[]);
    assert_eq!(
        dry.status.success(),
        real.status.success(),
        "dry: {} {}\nreal: {} {}",
        text(&dry.stdout),
        text(&dry.stderr),
        text(&real.stdout),
        text(&real.stderr)
    );
}
