//! #166: bounded login collection and credential parameters for `wardenlens import agentdvr` (#66).
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

#[test]
fn a_document_past_the_login_cap_is_refused_whole_and_nothing_is_written() {
    let site = Site::new();
    site.init_key();
    let before = site.disk_bytes();
    let ats = "a@".repeat(5000);
    let body = [
        cam_url(1, "Cam One", "rtsp://192.0.2.1/ok"),
        cam_url(2, "Cam Two", &format!("rtsp://u:{ats}192.0.2.2/s")),
    ]
    .concat();
    let file = site.xml(&body);
    for extra in [&[][..], &["--dry-run"][..]] {
        let out = site.import(&file, extra);
        assert!(!out.status.success(), "{}", text(&out.stdout));
        assert!(contains(&out.stderr, "refused"), "{}", text(&out.stderr));
        // No table, no row for the good camera.
        assert!(
            !contains(&out.stdout, "agentdvr-1"),
            "{}",
            text(&out.stdout)
        );
    }
    assert_eq!(
        site.disk_bytes(),
        before,
        "the refused import wrote something"
    );
}

#[test]
fn a_credential_parameter_value_of_a_skipped_entry_in_another_path_is_refused() {
    let secret = "Qv7synthetic-pw";
    let site = Site::new();
    site.init_key();
    let body = [
        cam_url(
            1,
            "Cam One",
            &format!("rtsp://192.0.2.1/live?user={USER}&password={secret}"),
        ),
        cam_url(
            2,
            "Cam Two",
            &format!("rtsp://192.0.2.2/live/{secret}/main"),
        ),
    ]
    .concat();
    let file = site.xml(&body);
    for extra in [&[][..], &["--dry-run"][..]] {
        let out = site.import(&file, extra);
        assert_no_leak(&site, &out, secret);
    }
}

#[test]
fn an_every_at_split_password_in_another_path_is_refused() {
    let secret = "Qv7/syn@thetic";
    let site = Site::new();
    site.init_key();
    let body = [
        cam_url(
            1,
            "Cam One",
            &format!("rtsp://{USER}:{secret}@192.0.2.1/a@b/c@d"),
        ),
        cam_url(
            2,
            "Cam Two",
            &format!("rtsp://192.0.2.2/live/{secret}/main"),
        ),
    ]
    .concat();
    let file = site.xml(&body);
    let out = site.import(&file, &["--dry-run"]);
    assert_no_leak(&site, &out, secret);
}
