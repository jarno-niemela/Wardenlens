//! Adversarial end-to-end tests for #225 (PR #231): `camera set --allow-basic-auth`, the `BASIC`
//! column of `camera list`. Synthetic data only: the
//! documentation range 192.0.2.0/24, invented logins, temporary directories, environment cleared.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "adversary tests: a failed setup step is a test failure"
)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

use tempfile::TempDir;

const PASSWORD: &str = "Qw7-fake-pass-225";
const USER: &str = "fakeuser225";
const HOST: &str = "192.0.2.225";
const NAME: &str = "Fake Gate Cam";
const ID: &str = "agentdvr-1";

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
    /// A key and one imported camera, `agentdvr-1`.
    fn with_camera() -> Self {
        let site = Self::new();
        let out = site.run(&["secrets", "init"]);
        assert!(out.status.success(), "{}", text(&out.stderr));
        let path = site.p("in/objects.xml");
        fs::write(
            &path,
            format!(
                "<objects><cameras><camera id=\"1\" name=\"{NAME}\"><settings>\
                 <videosourcestring>rtsp://{HOST}:554/stream1</videosourcestring>\
                 <login>{USER}</login><password>{PASSWORD}</password></settings></camera>\
                 </cameras></objects>"
            ),
        )
        .unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let out = site.run(&["import", "agentdvr", path.to_str().unwrap()]);
        assert!(out.status.success(), "{}", text(&out.stderr));
        site
    }
    fn flag(&self) -> bool {
        let index = wardenlens_index::Index::open(&self.p("state/index.db")).unwrap();
        let rows = index.list_cameras(&[]).unwrap();
        assert_eq!(rows.len(), 1);
        rows[0].record().allow_basic_auth()
    }
    fn state_files(&self) -> Vec<PathBuf> {
        let mut v: Vec<_> = fs::read_dir(self.p("state"))
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        v.sort();
        v
    }
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

fn no_site_values(out: &Output) {
    for stream in [&out.stdout, &out.stderr] {
        let s = text(stream);
        for needle in [PASSWORD, USER, HOST, NAME, "stream1"] {
            assert!(!s.contains(needle), "output holds {needle:?}: {s}");
        }
    }
}

/// Both directions print only the id and fixed words: no host, name, path or login.
#[test]
fn set_prints_nothing_of_the_site_either_way() {
    let site = Site::with_camera();
    let on = site.run(&["camera", "set", ID, "--allow-basic-auth", "true"]);
    assert!(on.status.success(), "{}", text(&on.stderr));
    no_site_values(&on);
    assert!(text(&on.stdout).contains(ID));
    assert!(text(&on.stderr).contains("cleartext"));
    assert!(site.flag());
    let off = site.run(&["camera", "set", ID, "--allow-basic-auth", "false"]);
    assert!(off.status.success(), "{}", text(&off.stderr));
    no_site_values(&off);
    assert!(text(&off.stderr).is_empty(), "{}", text(&off.stderr));
    assert!(!site.flag());
}

/// `camera list` follows the flag; the header and the row agree on the column.
#[test]
fn list_follows_set() {
    let site = Site::with_camera();
    let row = |site: &Site| {
        let out = site.run(&["camera", "list"]);
        assert!(out.status.success(), "{}", text(&out.stderr));
        let s = text(&out.stdout);
        let lines: Vec<String> = s.lines().map(str::to_owned).collect();
        let col = lines[0].find("BASIC").unwrap();
        let row = lines.iter().find(|l| l.starts_with(ID)).unwrap().clone();
        (col, row)
    };
    let (col, r) = row(&site);
    assert_eq!(&r[col..col + 7], "refused", "{r}");
    assert!(
        site.run(&["camera", "set", ID, "--allow-basic-auth", "true"])
            .status
            .success()
    );
    let (col, r) = row(&site);
    assert_eq!(&r[col..col + 7], "allowed", "{r}");
}

/// A missing or malformed value is a usage error and changes nothing.
#[test]
fn set_without_a_valid_value_is_a_usage_error_and_writes_nothing() {
    let site = Site::with_camera();
    assert!(
        site.run(&["camera", "set", ID, "--allow-basic-auth", "true"])
            .status
            .success()
    );
    for bad in [
        vec!["camera", "set", ID],
        vec!["camera", "set", ID, "--allow-basic-auth"],
        vec!["camera", "set", ID, "--allow-basic-auth", "1"],
        vec!["camera", "set", ID, "--allow-basic-auth", "yes"],
        vec!["camera", "set", ID, "--allow-basic-auth", "TRUE"],
        vec!["camera", "set", ID, "--allow-basic-auth", ""],
        vec!["camera", "set", "--allow-basic-auth", "false"],
    ] {
        let out = site.run(&bad);
        assert_eq!(out.status.code(), Some(2), "{bad:?}: {}", text(&out.stderr));
        assert!(site.flag(), "{bad:?} changed the flag");
    }
}

/// A malformed id is refused before any file is created; on a site with a camera it changes
/// nothing.
#[test]
fn set_of_a_malformed_id_is_refused_and_creates_nothing() {
    let fresh = Site::new();
    for id in [
        "",
        "../agentdvr-1",
        "AGENTDVR-1",
        "agentdvr-1\u{202e}",
        "agentdvr-1\0",
        &"a".repeat(33),
        " agentdvr-1",
    ] {
        if id.contains('\0') {
            continue; // an OS argument cannot hold NUL
        }
        let out = fresh.run(&["camera", "set", id, "--allow-basic-auth", "true"]);
        assert!(!out.status.success(), "{id:?}");
        assert!(fresh.state_files().is_empty(), "{id:?} created a file");
    }
    let site = Site::with_camera();
    for id in ["AGENTDVR-1", "agentdvr-2", " agentdvr-1"] {
        let out = site.run(&["camera", "set", id, "--allow-basic-auth", "true"]);
        assert!(!out.status.success(), "{id:?}");
        assert!(!site.flag(), "{id:?} set the flag");
    }
}
