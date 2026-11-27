//! `import agentdvr` maps cameras to catalogue models (#163), end to end.
//!
//! Synthetic only: documentation-range hosts, invented names and passwords, temporary
//! directories, a cleared environment. The query path is the one `cameras/` lists for a model
//! (read here from the catalogue files, so no model id is written in this test).

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

const PASSWORD: &str = "Qv7-fake-pass-163";
const USER: &str = "fakeuser163";

/// The first catalogue entry that lists an RTSP path with a query: `(vendor/model slug, path)`.
fn listed_query_path() -> (String, String) {
    find_listed_query_path().unwrap()
}

fn find_listed_query_path() -> Option<(String, String)> {
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
        site.run(&["secrets", "init"]);
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
    fn xml(&self, cams: &[(u32, &str)]) -> PathBuf {
        let mut body = String::new();
        for (id, path) in cams {
            let path = path.replace('&', "&amp;");
            write!(
                body,
                "<camera id=\"{id}\" name=\"Fake Cam {id}\"><settings>\
                 <videosourcestring>rtsp://192.0.2.{id}:554{path}</videosourcestring>\
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
    fn list(&self) -> String {
        text(&self.run(&["camera", "list"]).stdout)
    }
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

fn no_secrets(out: &Output) {
    for s in [text(&out.stdout), text(&out.stderr)] {
        assert!(!s.contains(PASSWORD) && !s.contains(USER), "{s}");
    }
}

#[test]
fn a_catalogue_listed_query_path_imports_under_its_matched_model() {
    let (model, path) = listed_query_path();
    let site = Site::new();
    let file = site.xml(&[(1, &path), (2, "/plain")]);
    // A dry run shows the match and writes no registry.
    let out = site.import(&file, &["--dry-run"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let stdout = text(&out.stdout);
    let line = stdout.lines().find(|l| l.contains("agentdvr-1")).unwrap();
    assert!(
        line.contains(&model) && line.contains("would import"),
        "{stdout}"
    );
    assert!(stdout.contains(&path), "{stdout}");
    // The real run.
    let out = site.import(&file, &[]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    no_secrets(&out);
    assert!(
        !text(&out.stdout).contains("skipped"),
        "{}",
        text(&out.stdout)
    );
    let list = site.list();
    let row1 = list.lines().find(|l| l.starts_with("agentdvr-1")).unwrap();
    assert!(row1.contains(&model), "{list}");
    let row2 = list.lines().find(|l| l.starts_with("agentdvr-2")).unwrap();
    assert!(row2.contains("agentdvr/imported"), "{list}");
    // Re-running updates the same rows.
    let again = text(&site.import(&file, &[]).stdout);
    assert_eq!(again.matches("updated").count(), 2, "{again}");
}

#[test]
fn an_unlisted_query_is_still_refused_with_or_without_a_chosen_model() {
    let (model, path) = listed_query_path();
    let site = Site::new();
    let other = format!("{path}&extra=1");
    let file = site.xml(&[(1, &other)]);
    for extra in [
        vec![],
        vec!["--model", model.as_str()],
        vec!["--camera-model", &format!("agentdvr-1={model}")],
    ] {
        let out = site.import(&file, &extra);
        assert!(out.status.success(), "{}", text(&out.stderr));
        let stdout = text(&out.stdout);
        assert!(
            stdout.contains("skipped") && stdout.contains("query"),
            "{stdout}"
        );
        // The skipped row shows the path only up to the query.
        assert!(!stdout.contains('?'), "{stdout}");
        assert!(site.list().contains("no cameras"), "{}", site.list());
    }
}

#[test]
fn a_chosen_model_applies_to_the_whole_file_or_to_one_camera() {
    let (model, path) = listed_query_path();
    let site = Site::new();
    let file = site.xml(&[(1, "/a"), (2, "/b")]);
    let out = site.import(&file, &["--camera-model", &format!("agentdvr-2={model}")]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let list = site.list();
    assert!(
        list.lines()
            .any(|l| l.starts_with("agentdvr-1") && l.contains("agentdvr/imported"))
    );
    assert!(
        list.lines()
            .any(|l| l.starts_with("agentdvr-2") && l.contains(&model))
    );
    // `--model` for all, a query path that the model lists.
    let site = Site::new();
    let file = site.xml(&[(1, &path), (2, "/b")]);
    let out = site.import(&file, &["--model", &model]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let list = site.list();
    assert_eq!(list.matches(model.as_str()).count(), 2, "{list}");
}

#[test]
fn bad_model_options_are_refused_before_anything_is_written() {
    let (model, _) = listed_query_path();
    let site = Site::new();
    let file = site.xml(&[(1, "/a")]);
    for extra in [
        vec!["--model", "nonsense"],
        vec!["--model", "no-such-vendor/no-such-model"],
        vec!["--camera-model", "agentdvr-1"],
        vec!["--camera-model", "agentdvr-9=x/y"],
    ] {
        let out = site.import(&file, &extra);
        assert_eq!(
            out.status.code(),
            Some(1),
            "{extra:?}: {}",
            text(&out.stderr)
        );
        no_secrets(&out);
        assert!(!site.p("state/vault.db").exists(), "{extra:?}");
        assert!(!site.p("state/index.db").exists(), "{extra:?}");
    }
    // A well-formed id that is not in the file.
    let out = site.import(&file, &["--camera-model", &format!("agentdvr-9={model}")]);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out.stderr));
    assert!(!site.p("state/vault.db").exists());
}

#[test]
fn a_camera_removed_from_the_file_stays_registered() {
    let site = Site::new();
    let both = site.xml(&[(1, "/a"), (2, "/b")]);
    assert!(site.import(&both, &[]).status.success());
    let one = site.xml(&[(1, "/a")]);
    let out = site.import(&one, &[]);
    assert!(out.status.success());
    let list = site.list();
    assert!(
        list.contains("agentdvr-1") && list.contains("agentdvr-2"),
        "{list}"
    );
}

#[test]
fn a_directory_as_input_is_refused_as_not_a_regular_file() {
    let site = Site::new();
    let out = site.import(&site.p("in"), &["--dry-run"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(
        text(&out.stderr).contains("not a regular file"),
        "{}",
        text(&out.stderr)
    );
}

/// Every byte under `dir`, by path, sidecars included.
fn bytes_under(dir: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    let mut out = Vec::new();
    for e in fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            out.extend(bytes_under(&p));
        } else {
            out.push((p.clone(), fs::read(&p).unwrap()));
        }
    }
    out.sort();
    out
}

#[test]
fn a_dry_run_writes_no_byte_over_an_index_a_zero_length_file_or_none() {
    let (model, _) = listed_query_path();
    let site = Site::new();
    let file = site.xml(&[(1, "/a")]);
    // No index at all.
    let before = bytes_under(site.dir.path());
    assert!(site.import(&file, &["--dry-run"]).status.success());
    assert_eq!(bytes_under(site.dir.path()), before);
    // A zero-length file: the real run formats it; the dry run leaves it empty.
    let index = site.p("state/index.db");
    fs::write(&index, b"").unwrap();
    fs::set_permissions(&index, fs::Permissions::from_mode(0o600)).unwrap();
    let before = bytes_under(site.dir.path());
    let out = site.import(&file, &["--dry-run"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(text(&out.stdout).contains("would import"));
    assert_eq!(bytes_under(site.dir.path()), before);
    assert_eq!(fs::metadata(&index).unwrap().len(), 0);
    // A current-schema index with a row, in every conflict state.
    assert!(site.import(&file, &["--model", &model]).status.success());
    let before = bytes_under(site.dir.path());
    for extra in [vec!["--dry-run"], vec!["--dry-run", "--model", &model]] {
        let out = site.import(&file, &extra);
        assert!(out.status.success(), "{}", text(&out.stderr));
        assert_eq!(bytes_under(site.dir.path()), before, "{extra:?}");
    }
}

/// A sidecar that the real open refuses is refused the same way by the dry run (same message,
/// same exit code), with nothing written.
#[test]
fn a_dry_run_refuses_a_bad_sidecar_exactly_as_the_real_run_does() {
    let site = Site::new();
    let file = site.xml(&[(1, "/a")]);
    let wal = site.p("state/index.db-wal");
    fs::write(&wal, b"not a wal").unwrap();
    fs::set_permissions(&wal, fs::Permissions::from_mode(0o600)).unwrap();
    let before = bytes_under(&site.p("state"));
    let dry = site.import(&file, &["--dry-run"]);
    assert_eq!(bytes_under(&site.p("state")), before);
    let real = site.import(&file, &[]);
    assert_eq!(dry.status.code(), Some(2), "{}", text(&dry.stderr));
    assert_eq!(dry.status.code(), real.status.code());
    assert_eq!(text(&dry.stderr), text(&real.stderr));
}
