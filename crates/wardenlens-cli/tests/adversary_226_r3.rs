//! Adversary round 3 for #226: the JSON importer against the Basic opt-in that #225 added on
//! main (merged into the branch at 3f63d9f). Synthetic inputs only, temporary directories, a
//! cleared environment; every run is given its file, so no install path is opened.

#![expect(
    clippy::unwrap_used,
    reason = "integration-test helpers outside #[test] fns; clippy.toml in-tests allowances do not reach them"
)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use serde_json::json;
use tempfile::TempDir;

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
        let cfg = site.dir.path().join("wardenlens.toml");
        fs::write(&cfg, config).unwrap();
        fs::set_permissions(&cfg, fs::Permissions::from_mode(0o600)).unwrap();
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
    fn import(&self, file: &Path, extra: &[&str]) -> Output {
        let mut args = vec!["import", "agentdvr", file.to_str().unwrap()];
        args.extend_from_slice(extra);
        self.run(&args)
    }
    fn json_file(&self) -> PathBuf {
        let body = json!({"cameras": [{
            "id": 1, "name": "Fake R3 Cam", "ptz": 0,
            "settings": {
                "videosourcestring": "rtsp://192.0.2.233:554/stream1",
                "login": "fakeuser-r3", "password": "fake-pass-r3", "sourceindex": 2,
                "allowbasicauth": true, "basicauth": true, "allow_basic_auth": true
            }
        }]});
        let path = self.p("in/objects.json");
        fs::write(&path, body.to_string()).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        path
    }
    fn flag(&self) -> bool {
        let index = wardenlens_index::Index::open(&self.p("state/index.db")).unwrap();
        let rows = index.list_cameras(&[]).unwrap();
        assert_eq!(rows.len(), 1);
        rows.first().unwrap().record().allow_basic_auth()
    }
}

fn ok(out: &Output) {
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// A JSON file that carries opt-in-looking fields never turns the Basic opt-in on.
#[test]
fn json_fields_that_look_like_a_basic_opt_in_are_ignored() {
    let site = Site::new();
    ok(&site.run(&["secrets", "init"]));
    let file = site.json_file();
    ok(&site.import(&file, &["--format", "json"]));
    assert!(!site.flag());
}

/// A JSON re-import fails closed like the XML one: the opt-in set with `camera set` is off again.
#[test]
fn a_json_reimport_turns_the_basic_opt_in_off() {
    let site = Site::new();
    ok(&site.run(&["secrets", "init"]));
    let file = site.json_file();
    ok(&site.import(&file, &[]));
    ok(&site.run(&["camera", "set", "agentdvr-1", "--allow-basic-auth", "true"]));
    assert!(site.flag());
    ok(&site.import(&file, &[]));
    assert!(!site.flag());
}

/// A JSON dry run writes nothing: the opt-in the operator set survives it.
#[test]
fn a_json_dry_run_leaves_the_basic_opt_in_alone() {
    let site = Site::new();
    ok(&site.run(&["secrets", "init"]));
    let file = site.json_file();
    ok(&site.import(&file, &[]));
    ok(&site.run(&["camera", "set", "agentdvr-1", "--allow-basic-auth", "true"]));
    let before = fs::read(site.p("state/index.db")).unwrap();
    ok(&site.import(&file, &["--dry-run"]));
    assert_eq!(fs::read(site.p("state/index.db")).unwrap(), before);
    assert!(site.flag());
}
