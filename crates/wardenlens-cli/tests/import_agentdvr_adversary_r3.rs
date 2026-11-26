//! Round-3 adversary tests for `wardenlens import agentdvr` (#66, PR #162).
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

const PASSWORD: &str = "Qv7-synthetic-pw";
const USER: &str = "synthuser3";
const HOST: &str = "192.0.2.55";
const NAME: &str = "Synthetic Gate Cam";

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

fn cam(id: u32, name: &str, host: &str, path: &str, user: &str, pw: &str) -> String {
    format!(
        "<camera id=\"{id}\" name=\"{name}\"><settings>\
         <videosourcestring>rtsp://{host}:554{path}</videosourcestring>\
         <login>{user}</login><password>{pw}</password></settings></camera>"
    )
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
        "{needle:?} was printed: {}{}",
        text(&out.stdout),
        text(&out.stderr)
    );
}

/// The password is unique to camera 1, which the parser skips; camera 2's path repeats it
/// under an unlisted parameter name. The module docs promise any user or password *of the file*
/// is compared, so the password must not reach the registry or stdout.
fn skipped_holder_leaks(holder: &str) {
    let site = Site::new();
    site.init_key();
    let body = [
        holder.to_owned(),
        cam_url(
            2,
            "Cam Two",
            &format!("rtsp://192.0.2.2/live/ch0_zzq={PASSWORD}"),
        ),
    ]
    .concat();
    let file = site.xml(&body);
    // The real run first: it shows whether the password reaches the registry on disk.
    for extra in [&[][..], &["--dry-run"][..]] {
        let out = site.import(&file, extra);
        assert_no_leak(&site, &out, PASSWORD);
    }
}

#[test]
fn a_deleted_cameras_password_in_another_path_is_refused() {
    skipped_holder_leaks(&format!(
        "<camera id=\"1\" name=\"Cam One\" deleted=\"true\"><settings>\
         <videosourcestring>rtsp://192.0.2.1/s</videosourcestring>\
         <login>{USER}</login><password>{PASSWORD}</password></settings></camera>"
    ));
}

#[test]
fn an_http_cameras_password_in_another_path_is_refused() {
    skipped_holder_leaks(&format!(
        "<camera id=\"1\" name=\"Cam One\"><settings>\
         <videosourcestring>http://192.0.2.1/video.mjpg</videosourcestring>\
         <login>{USER}</login><password>{PASSWORD}</password></settings></camera>"
    ));
}

#[test]
fn a_password_without_user_in_another_path_is_refused() {
    skipped_holder_leaks(&format!(
        "<camera id=\"1\" name=\"Cam One\"><settings>\
         <videosourcestring>rtsp://192.0.2.1/s</videosourcestring>\
         <login></login><password>{PASSWORD}</password></settings></camera>"
    ));
}

#[test]
fn a_conflicting_cameras_password_in_another_path_is_refused() {
    skipped_holder_leaks(
        &cam_url(
            1,
            "Cam One",
            &format!("rtsp://{USER}:{PASSWORD}@192.0.2.1/s"),
        )
        .replace(
            "</videosourcestring>",
            &format!("</videosourcestring><login>{USER}</login><password>other-pw-9</password>"),
        ),
    );
}

// ---- checks that should hold (coverage) ----------------------------------------------------

/// Another camera's password, upper-cased in the path, under an unlisted name.
#[test]
fn another_cameras_password_in_other_case_is_refused() {
    let site = Site::new();
    site.init_key();
    let body = [
        cam(1, "Cam One", "192.0.2.1", "/stream1", USER, PASSWORD),
        cam_url(
            2,
            "Cam Two",
            &format!(
                "rtsp://192.0.2.2/live/ch0_zzq={}",
                PASSWORD.to_ascii_uppercase()
            ),
        ),
    ]
    .concat();
    let file = site.xml(&body);
    let out = site.import(&file, &[]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(text(&out.stdout).contains("path contains the login"));
    assert_no_leak(&site, &out, PASSWORD);
    assert_no_leak(&site, &out, &PASSWORD.to_ascii_uppercase());
}

/// Another camera's user in a third camera's path; the clean camera still imports.
#[test]
fn another_cameras_user_is_refused_and_clean_cameras_still_import() {
    let site = Site::new();
    site.init_key();
    let body = [
        cam(1, "Cam One", "192.0.2.1", "/stream1", USER, PASSWORD),
        cam_url(2, "Cam Two", &format!("rtsp://192.0.2.2/{USER}/main")),
        cam_url(3, "Cam Three", "rtsp://192.0.2.3/main"),
    ]
    .concat();
    let file = site.xml(&body);
    let out = site.import(&file, &[]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let s = text(&out.stdout);
    assert_eq!(s.matches("path contains the login").count(), 1, "{s}");
    assert!(s.contains("agentdvr-3"), "{s}");
    assert_no_leak(&site, &out, USER);
}

/// Every newly listed name, behind a camera-style prefix, is refused by the parser before it
/// reaches the import (skipped, value not printed or stored).
#[test]
fn newly_denied_names_are_skipped_without_leak() {
    for name in [
        "psw",
        "PSWD",
        "Passwort",
        "passphrase",
        "auth_code",
        "auth-token",
        "credential",
    ] {
        let site = Site::new();
        site.init_key();
        let file = site.xml(&cam_url(
            1,
            NAME,
            &format!("rtsp://{HOST}/live/ch0_{name}={PASSWORD}"),
        ));
        let out = site.import(&file, &[]);
        assert!(out.status.success(), "{name}: {}", text(&out.stderr));
        assert_no_leak(&site, &out, PASSWORD);
    }
}
