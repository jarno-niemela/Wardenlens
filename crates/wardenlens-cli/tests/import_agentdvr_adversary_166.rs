//! Adversary tests for #166 (PR #167): logins hidden from the screen by a child element.
//!
//! Synthetic data only: documentation-range hosts, invented names and passwords, temporary
//! directories, a cleared environment.

#![expect(
    clippy::unwrap_used,
    reason = "integration-test helpers outside #[test] fns; clippy.toml in-tests allowances do not reach them"
)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use tempfile::TempDir;

const USER: &str = "synthuser3";

struct Site {
    dir: TempDir,
}

impl Site {
    fn with(db_rel: &str, key_rel: &str) -> Self {
        let dir = tempfile::tempdir().unwrap();
        for d in ["state", "keys", "in"] {
            let p = dir.path().join(d);
            fs::create_dir(&p).unwrap();
            fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let site = Self { dir };
        site.write_config(db_rel, key_rel);
        site
    }
    fn new() -> Self {
        Self::with("state/index.db", "keys/secrets.key")
    }
    fn write_config(&self, db_rel: &str, key_rel: &str) {
        let t = self.dir.path().display();
        let config = format!(
            "[api]\nlisten = \"127.0.0.1:8080\"\n[storage]\nhot_root = \"{t}/hot\"\n\
             archive_root = \"{t}/archive\"\n[database]\npath = \"{t}/{db_rel}\"\n\
             [secrets]\nkey_file = \"{t}/{key_rel}\"\n"
        );
        fs::write(self.config(), config).unwrap();
        fs::set_permissions(self.config(), fs::Permissions::from_mode(0o600)).unwrap();
    }
    fn p(&self, rel: &str) -> PathBuf {
        self.dir.path().join(rel)
    }
    fn config(&self) -> PathBuf {
        self.p("wardenlens.toml")
    }
    fn xml(&self, body: &str) -> PathBuf {
        let path = self.p("in/objects.xml");
        fs::write(
            &path,
            format!("<objects><cameras>{body}</cameras></objects>"),
        )
        .unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        path
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
    /// Every regular file under `state/` and `keys/`.
    fn disk_bytes(&self) -> Vec<u8> {
        let mut all = Vec::new();
        for d in ["state", "keys"] {
            for e in fs::read_dir(self.p(d)).unwrap() {
                let p = e.unwrap().path();
                if p.is_file() {
                    all.extend(fs::read(p).unwrap());
                }
            }
        }
        all
    }
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

fn contains(hay: &[u8], needle: &str) -> bool {
    hay.windows(needle.len()).any(|w| w == needle.as_bytes())
}

/// A camera whose only source is the URL (no login fields).
fn cam_url(id: u32, name: &str, url: &str) -> String {
    format!(
        "<camera id=\"{id}\" name=\"{name}\"><settings>\
         <videosourcestring>{url}</videosourcestring></settings></camera>"
    )
}

fn assert_no_leak(site: &Site, out: &Output, needle: &str) {
    assert!(
        !contains(&site.disk_bytes(), needle),
        "{needle:?} is in plaintext on disk (exit {:?}): {}",
        out.status.code(),
        text(&out.stdout)
    );
    assert!(
        !contains(&out.stdout, needle) && !contains(&out.stderr, needle),
        "{needle:?} was printed"
    );
}

fn cam_fields(id: u32, name: &str, url: &str, fields: &str) -> String {
    format!(
        "<camera id=\"{id}\" name=\"{name}\"><settings>\
         <videosourcestring>{url}</videosourcestring>{fields}</settings></camera>"
    )
}

/// Camera One's password is `Qv7synthpw` as used (direct text only); a child element hides it
/// from the collected text. Camera Two's path holds it.
fn hidden_password_site(field: &str) -> (Site, PathBuf) {
    let site = Site::new();
    site.init_key();
    let body = [
        cam_fields(1, "Cam One", "rtsp://192.0.2.1/s", field),
        cam_url(2, "Cam Two", "rtsp://192.0.2.2/live/Qv7synthpw/main"),
    ]
    .concat();
    let file = site.xml(&body);
    (site, file)
}

#[test]
fn a_password_split_by_a_child_element_never_reaches_another_path_dry_run() {
    let (site, file) = hidden_password_site(&format!(
        "<login>{USER}</login><password>Qv7<b>x</b>synthpw</password>"
    ));
    let out = site.import(&file, &["--dry-run"]);
    assert_no_leak(&site, &out, "Qv7synthpw");
}

#[test]
fn a_password_split_by_a_child_element_never_reaches_the_registry() {
    let (site, file) = hidden_password_site(&format!(
        "<login>{USER}</login><password>Qv7<b>x</b>synthpw</password>"
    ));
    let out = site.import(&file, &[]);
    assert_no_leak(&site, &out, "Qv7synthpw");
}

#[test]
fn a_url_password_split_by_a_child_element_never_reaches_the_registry() {
    let site = Site::new();
    site.init_key();
    let body = [
        cam_url(
            1,
            "Cam One",
            &format!("rtsp://{USER}:Qv7synth<i>X</i>pw@192.0.2.1/s"),
        ),
        cam_url(2, "Cam Two", "rtsp://192.0.2.2/live/Qv7synthpw/main"),
    ]
    .concat();
    let file = site.xml(&body);
    let out = site.import(&file, &[]);
    assert_no_leak(&site, &out, "Qv7synthpw");
}
