//! `import agentdvr` reads `objects.json` (#226), end to end.
//!
//! Synthetic only: documentation-range hosts, invented names and passwords, temporary
//! directories, a cleared environment. The JSON layout is an assumption (the XML importer's field
//! names in JSON form); no real file was read. Nothing here opens an install path: every run is
//! given its file.

#![expect(
    clippy::unwrap_used,
    reason = "integration-test helpers outside #[test] fns; clippy.toml in-tests allowances do not reach them"
)]

use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use secrecy::ExposeSecret;
use serde_json::{Value, json};
use tempfile::TempDir;
use wardenlens_core::entry::EntryId;
use wardenlens_secrets::KeyFile;
use wardenlens_vault::{Value as VaultValue, Vault};

const PASSWORD: &str = "Jq4-fake-pass-226";
const USER: &str = "fakeuser226";
const HOST: &str = "192.0.2.226";
const NAME: &str = "Fake Json Cam";

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
        fs::write(site.config(), config).unwrap();
        fs::set_permissions(site.config(), fs::Permissions::from_mode(0o600)).unwrap();
        site
    }
    fn p(&self, rel: &str) -> PathBuf {
        self.dir.path().join(rel)
    }
    fn config(&self) -> PathBuf {
        self.p("wardenlens.toml")
    }
    fn key(&self) -> PathBuf {
        self.p("keys/secrets.key")
    }
    fn write(&self, name: &str, body: &str) -> PathBuf {
        let path = self.p(&format!("in/{name}"));
        fs::write(&path, body).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        path
    }
    fn json(&self, cameras: &[Value]) -> PathBuf {
        self.write(
            "objects.json",
            &json!({"cameras": cameras, "version": 1}).to_string(),
        )
    }
    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_wardenlens"))
            .env_clear()
            .arg("--config")
            .arg(self.config())
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
    fn init_key(&self) {
        let out = self.run(&["secrets", "init"]);
        assert!(out.status.success(), "{}", text(&out.stderr));
    }
    fn state_bytes(&self) -> Vec<u8> {
        let mut all = Vec::new();
        for e in fs::read_dir(self.p("state")).unwrap() {
            all.extend(fs::read(e.unwrap().path()).unwrap());
        }
        all
    }
    fn snapshot(&self) -> Vec<(PathBuf, Vec<u8>)> {
        let mut v: Vec<_> = walk(self.dir.path())
            .into_iter()
            .map(|p| {
                let b = fs::read(&p).unwrap();
                (p, b)
            })
            .collect();
        v.sort();
        v
    }
    fn vault(&self) -> Vault {
        let key = KeyFile::load(&self.key()).unwrap();
        Vault::open(&self.p("state/vault.db"), key).unwrap()
    }
}

fn walk(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for e in fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            out.extend(walk(&p));
        } else {
            out.push(p);
        }
    }
    out
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

fn contains(hay: &[u8], needle: &str) -> bool {
    hay.windows(needle.len()).any(|w| w == needle.as_bytes())
}

fn cam(id: u32, name: &str, host: &str, path: &str, user: &str, pw: &str) -> Value {
    json!({
        "id": id, "name": name, "ptz": 0,
        "settings": {
            "videosourcestring": format!("rtsp://{host}:554{path}"),
            "login": user, "password": pw, "sourceindex": 2
        }
    })
}

fn cam_xml(id: u32, name: &str, host: &str, path: &str, user: &str, pw: &str) -> String {
    format!(
        "<camera id=\"{id}\" name=\"{name}\"><settings>\
         <videosourcestring>rtsp://{host}:554{path}</videosourcestring>\
         <login>{user}</login><password>{pw}</password></settings></camera>"
    )
}

fn no_secrets(out: &Output) {
    for stream in [&out.stdout, &out.stderr] {
        for needle in [PASSWORD, USER] {
            assert!(!contains(stream, needle), "output holds a login value");
        }
    }
}

fn one(site: &Site) -> PathBuf {
    site.json(&[cam(1, NAME, HOST, "/stream1", USER, PASSWORD)])
}

#[test]
fn a_json_import_seals_the_login_and_prints_no_credential() {
    let site = Site::new();
    site.init_key();
    let file = one(&site);
    let out = site.import(&file, &[]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let stdout = text(&out.stdout);
    assert!(
        stdout.contains("agentdvr-1") && stdout.contains(HOST),
        "{stdout}"
    );
    assert!(stdout.contains("/stream1") && stdout.contains("imported"));
    no_secrets(&out);
    let bytes = site.state_bytes();
    for needle in [PASSWORD, USER, HOST, NAME] {
        assert!(!contains(&bytes, needle), "plaintext {needle:?} on disk");
    }
    let vault = site.vault();
    let entry = vault
        .get(&EntryId::new("cam:agentdvr-1:credential").unwrap())
        .unwrap()
        .unwrap();
    match entry.value {
        VaultValue::Credential(c) => {
            assert_eq!(c.username, USER);
            assert_eq!(c.password.expose_secret(), PASSWORD);
        }
        _ => panic!("not a credential"),
    }
    let name = vault
        .get(&EntryId::new("cam:agentdvr-1:name").unwrap())
        .unwrap()
        .unwrap();
    assert!(matches!(name.value, VaultValue::Text(t) if t.expose_secret() == NAME));
    let index = wardenlens_index::Index::open(&site.p("state/index.db")).unwrap();
    let rows = index.list_cameras(&[]).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].record().streams().main.as_str(), "/stream1");
}

#[test]
fn json_and_xml_of_the_same_cameras_give_the_same_table_and_vault() {
    let args: [(u32, &str, &str, &str, &str, &str); 3] = [
        (1, NAME, HOST, "/stream1", USER, PASSWORD),
        (2, "Second Cam", "192.0.2.227", "/s2", "", ""),
        (4, "Third Cam", "192.0.2.228", "/a/b", "u3", "p3"),
    ];
    let xml_body: String = args
        .iter()
        .map(|a| cam_xml(a.0, a.1, a.2, a.3, a.4, a.5))
        .collect();
    let json_cams: Vec<Value> = args
        .iter()
        .map(|a| cam(a.0, a.1, a.2, a.3, a.4, a.5))
        .collect();
    let mut results = Vec::new();
    for use_json in [false, true] {
        let site = Site::new();
        site.init_key();
        let file = if use_json {
            site.json(&json_cams)
        } else {
            site.write(
                "objects.xml",
                &format!("<objects><cameras>{xml_body}</cameras></objects>"),
            )
        };
        let out = site.import(&file, &[]);
        assert!(out.status.success(), "{}", text(&out.stderr));
        let ids: Vec<String> = site
            .vault()
            .list()
            .unwrap()
            .into_iter()
            .map(|e| e.id.as_str().to_owned())
            .collect();
        results.push((text(&out.stdout), ids));
    }
    assert_eq!(results[0], results[1]);
}

#[test]
fn the_format_is_detected_by_content_not_by_name() {
    let site = Site::new();
    site.init_key();
    let body = json!({"cameras":[cam(1, NAME, HOST, "/s", USER, PASSWORD)]}).to_string();
    for name in ["objects.xml", "objects", "objects.json.bak", "objects.txt"] {
        let file = site.write(name, &body);
        let out = site.import(&file, &["--dry-run"]);
        assert!(out.status.success(), "{name}: {}", text(&out.stderr));
        assert!(text(&out.stdout).contains("would import"), "{name}");
    }
    // A leading BOM and white space are fine.
    let file = site.write("bom.json", &format!("\u{FEFF}\n  {body}"));
    assert!(site.import(&file, &["--dry-run"]).status.success());
}

#[test]
fn format_can_be_forced_and_a_wrong_force_is_refused() {
    let site = Site::new();
    let js = one(&site);
    let xml = site.write(
        "objects.xml",
        &format!(
            "<objects><cameras>{}</cameras></objects>",
            cam_xml(1, NAME, HOST, "/s", USER, PASSWORD)
        ),
    );
    for (file, format, ok) in [
        (&js, "json", true),
        (&js, "auto", true),
        (&js, "xml", false),
        (&xml, "xml", true),
        (&xml, "auto", true),
        (&xml, "json", false),
    ] {
        let out = site.import(file, &["--dry-run", "--format", format]);
        assert_eq!(out.status.success(), ok, "{format}: {}", text(&out.stderr));
        if !ok {
            assert_eq!(out.status.code(), Some(1));
            assert!(text(&out.stderr).contains("refused"));
            no_secrets(&out);
        }
    }
    let out = site.import(&js, &["--format", "yaml"]);
    assert!(!out.status.success());
}

#[test]
fn json_refusals_exit_1_write_nothing_and_echo_no_input() {
    let site = Site::new();
    site.init_key();
    let before = site.snapshot();
    let deep = format!(
        "{{\"cameras\":[],\"x\":{}{}}}",
        "[".repeat(40),
        "]".repeat(40)
    );
    let many: Vec<Value> = (0..257).map(|i| json!({"name": format!("C{i}")})).collect();
    let bad_field = json!({"cameras":[{"name": NAME, "settings":
        {"videosourcestring": "rtsp://192.0.2.1/s", "login": USER, "password": [PASSWORD]}}]})
    .to_string();
    let dup = format!(
        "{{\"cameras\":[{{\"name\":\"{NAME}\",\"settings\":{{\"login\":\"{USER}\",\"login\":\"{PASSWORD}\"}}}}]}}"
    );
    let truncated =
        format!("{{\"cameras\":[{{\"name\":\"{NAME}\",\"settings\":{{\"password\":\"{PASSWORD}\"");
    let same_name = json!({"cameras":[
        cam(1, NAME, HOST, "/a", USER, PASSWORD), cam(2, NAME, HOST, "/b", USER, PASSWORD)]})
    .to_string();
    let rows: [(&str, String); 6] = [
        ("deep", deep),
        ("many", json!({"cameras": many}).to_string()),
        ("bad_field", bad_field),
        ("dup", dup),
        ("truncated", truncated),
        ("same_name", same_name),
    ];
    for (label, body) in rows {
        let file = site.write("objects.json", &body);
        for extra in [vec!["--dry-run"], vec![]] {
            let out = site.import(&file, &extra);
            assert_eq!(out.status.code(), Some(1), "{label}: {}", text(&out.stderr));
            no_secrets(&out);
            for stream in [&out.stdout, &out.stderr] {
                assert!(!contains(stream, NAME), "{label}: name echoed");
            }
        }
        // Only the input file changed between rows; nothing else was written.
        let after = site.snapshot();
        let changed: Vec<_> = after
            .iter()
            .filter(|e| !before.contains(e))
            .map(|e| e.0.clone())
            .collect();
        assert_eq!(changed, std::slice::from_ref(&file), "{label}");
    }
}

#[test]
fn an_oversized_json_file_is_refused_by_the_shared_reader() {
    let site = Site::new();
    let file = site.write("objects.json", "{\"cameras\":[]}");
    fs::File::create(&file)
        .unwrap()
        .set_len(8 * 1024 * 1024 + 1)
        .unwrap();
    let out = site.import(&file, &["--dry-run"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(text(&out.stderr).contains("8 MiB"));
}

#[test]
fn a_symlinked_json_input_is_refused() {
    let site = Site::new();
    let real = one(&site);
    let link = site.p("in/link.json");
    symlink(&real, &link).unwrap();
    let out = site.import(&link, &["--dry-run"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(text(&out.stderr).contains("symbolic link"));
}

#[test]
fn a_world_readable_json_warns_and_is_not_changed() {
    let site = Site::new();
    let file = one(&site);
    fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).unwrap();
    let before = fs::read(&file).unwrap();
    let out = site.import(&file, &["--dry-run"]);
    assert!(out.status.success());
    assert!(text(&out.stderr).contains("readable by everyone"));
    no_secrets(&out);
    assert_eq!(fs::read(&file).unwrap(), before);
    assert_eq!(
        fs::metadata(&file).unwrap().permissions().mode() & 0o777,
        0o644
    );
}

#[test]
fn dry_run_writes_nothing_and_needs_no_key() {
    let site = Site::new();
    let file = one(&site);
    let before = site.snapshot();
    let out = site.import(&file, &["--dry-run"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(text(&out.stdout).contains("would import"));
    no_secrets(&out);
    assert_eq!(site.snapshot(), before);
}

#[test]
fn a_login_hidden_in_another_cameras_path_is_skipped_as_in_xml() {
    let site = Site::new();
    site.init_key();
    let leaky = format!("/live/{PASSWORD}/main");
    let file = site.json(&[
        cam(1, NAME, HOST, "/stream1", USER, PASSWORD),
        cam(2, "Leaky Cam", "192.0.2.229", &leaky, "other", "otherpw"),
    ]);
    let out = site.import(&file, &[]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let stdout = text(&out.stdout);
    let line = stdout.lines().find(|l| l.contains("agentdvr-2")).unwrap();
    assert!(
        line.contains("skipped") && line.contains("login"),
        "{stdout}"
    );
    no_secrets(&out);
    assert!(!contains(&site.state_bytes(), PASSWORD));
}

#[test]
fn a_skipped_cameras_logins_still_screen_paths() {
    // The deleted camera's password is in a live camera's path.
    let site = Site::new();
    let mut gone = cam(1, "Gone Cam", HOST, "/s", USER, PASSWORD);
    gone["deleted"] = json!(true);
    let file = site.json(&[
        gone,
        cam(2, NAME, "192.0.2.230", &format!("/x/{PASSWORD}"), "", ""),
    ]);
    let out = site.import(&file, &["--dry-run"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let stdout = text(&out.stdout);
    assert!(stdout.contains("path contains the login"), "{stdout}");
    assert!(stdout.contains("deleted"), "{stdout}");
    no_secrets(&out);
}

#[test]
fn a_catalogue_listed_query_path_maps_and_an_unlisted_one_is_skipped() {
    let (model, path) = listed_query_path();
    let site = Site::new();
    site.init_key();
    let file = site.json(&[
        cam(1, "Listed", "192.0.2.231", &path, USER, PASSWORD),
        cam(2, "Plain", "192.0.2.232", "/plain", USER, PASSWORD),
        cam(
            3,
            "Unlisted",
            "192.0.2.233",
            "/p?zz_unlisted=1",
            USER,
            PASSWORD,
        ),
    ]);
    let out = site.import(&file, &["--dry-run"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let stdout = text(&out.stdout);
    let l1 = stdout.lines().find(|l| l.contains("agentdvr-1")).unwrap();
    assert!(
        l1.contains(&model) && l1.contains("would import"),
        "{stdout}"
    );
    let l3 = stdout.lines().find(|l| l.contains("agentdvr-3")).unwrap();
    assert!(l3.contains("skipped") && l3.contains("query"), "{stdout}");
    assert!(!stdout.contains("zz_unlisted"), "{stdout}");
    // `--camera-model` addresses a JSON camera by its `agentdvr-<id>` like an XML one.
    let out = site.import(
        &file,
        &[
            "--dry-run",
            "--camera-model",
            &format!("agentdvr-2={model}"),
        ],
    );
    assert!(out.status.success(), "{}", text(&out.stderr));
    let stdout = text(&out.stdout);
    let l2 = stdout.lines().find(|l| l.contains("agentdvr-2")).unwrap();
    assert!(
        l2.contains(&model) && l2.contains("would import"),
        "{stdout}"
    );
}

#[test]
fn a_camera_model_for_an_id_not_in_the_json_is_refused() {
    let site = Site::new();
    let file = one(&site);
    let (model, _) = listed_query_path();
    let out = site.import(
        &file,
        &[
            "--dry-run",
            "--camera-model",
            &format!("agentdvr-9={model}"),
        ],
    );
    assert_eq!(out.status.code(), Some(1));
}

#[test]
fn unknown_members_and_other_cameras_fields_are_ignored() {
    let site = Site::new();
    let body = json!({
        "cameras": [{
            "id": 1, "name": NAME, "mystery": {"login": "deep-user", "password": "deep-pw"},
            "settings": {
                "videosourcestring": format!("rtsp://{HOST}/s"), "login": USER, "password": PASSWORD,
                "onvif": {"login": "o-user"}, "extra": [1, 2, {"password": "x"}]
            }
        }],
        "microphones": [{"settings": {"login": "mic", "password": "mic-pw"}}],
        "version": "7"
    })
    .to_string();
    let file = site.write("objects.json", &body);
    let out = site.import(&file, &["--dry-run"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(text(&out.stdout).contains("would import"));
}
