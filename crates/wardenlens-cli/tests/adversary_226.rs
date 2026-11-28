//! Adversary tests for #226 (PR #230): `import agentdvr` with hostile `objects.json` inputs, end
//! to end. Synthetic only: documentation-range hosts, invented logins, temporary directories, a
//! cleared environment, and every run is given its file (no install path is opened).

#![expect(
    clippy::unwrap_used,
    reason = "integration-test helpers outside #[test] fns"
)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use tempfile::TempDir;

const PASSWORD: &str = "Zx9-adv-pass-226";
const USER: &str = "advuser226";
/// The JSON `\\u` escape prefix, built so no tool decodes it in the source.
const U_ESC: &str = concat!("\\", "u");

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
    fn write(&self, name: &str, body: &str) -> PathBuf {
        let path = self.p(&format!("in/{name}"));
        fs::write(&path, body).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        path
    }
    /// Runs under coreutils `timeout`, so a hang fails the test instead of the suite.
    fn import(&self, file: &Path, extra: &[&str]) -> Output {
        Command::new("timeout")
            .arg("30")
            .arg(env!("CARGO_BIN_EXE_wardenlens"))
            .env_clear()
            .arg("--config")
            .arg(self.p("wardenlens.toml"))
            .args(["import", "agentdvr"])
            .arg(file)
            .args(extra)
            .stdin(Stdio::null())
            .output()
            .unwrap()
    }
    fn state_files(&self) -> usize {
        fs::read_dir(self.p("state")).unwrap().count()
    }
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

fn contains(hay: &[u8], needle: &str) -> bool {
    hay.windows(needle.len()).any(|w| w == needle.as_bytes())
}

fn no_secrets(out: &Output) {
    for stream in [&out.stdout, &out.stderr] {
        for needle in [PASSWORD, USER] {
            assert!(!contains(stream, needle), "output holds a login value");
        }
    }
}

/// Every character of `s` as a JSON `\uXXXX` escape (built at run time).
fn escaped(s: &str) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    for u in s.encode_utf16() {
        write!(out, "{U_ESC}{u:04x}").unwrap();
    }
    out
}

#[test]
fn a_fifo_named_objects_json_is_refused_without_hanging() {
    let site = Site::new();
    let fifo = site.p("in/objects.json");
    let st = Command::new("mkfifo").arg(&fifo).status().unwrap();
    assert!(st.success());
    let out = site.import(&fifo, &["--dry-run"]);
    assert_ne!(out.status.code(), Some(124), "timed out on a FIFO");
    assert!(!out.status.success());
}

#[test]
fn a_password_spelled_with_escapes_in_another_path_is_still_screened() {
    let site = Site::new();
    let leaky = escaped(&format!("/live/{PASSWORD}/main"));
    let body = format!(
        r#"{{"cameras":[
          {{"id":1,"name":"Main Cam","settings":{{"videosourcestring":"rtsp://192.0.2.10:554/s","login":"{USER}","password":"{}"}}}},
          {{"id":2,"name":"Leaky Cam","settings":{{"videosourcestring":"rtsp://192.0.2.11:554{leaky}"}}}}
        ]}}"#,
        escaped(PASSWORD)
    );
    let file = site.write("objects.json", &body);
    let out = site.import(&file, &["--dry-run"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let stdout = text(&out.stdout);
    let line = stdout.lines().find(|l| l.contains("agentdvr-2")).unwrap();
    assert!(line.contains("skipped"), "{stdout}");
    no_secrets(&out);
}

#[test]
fn a_terminal_escape_in_a_json_name_never_reaches_the_output() {
    let site = Site::new();
    let esc = format!("Cam\\{}001b]0;pwned\\{}0007", 'u', 'u');
    let body = format!(
        r#"{{"cameras":[{{"id":1,"name":"{esc}","settings":{{"videosourcestring":"rtsp://192.0.2.12/s"}}}}]}}"#
    );
    let file = site.write("objects.json", &body);
    let out = site.import(&file, &["--dry-run"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    for stream in [&out.stdout, &out.stderr] {
        assert!(!stream.contains(&0x1b), "ESC in output");
        assert!(!stream.contains(&0x07), "BEL in output");
        assert!(!contains(stream, "pwned"), "name text in output");
    }
}

#[test]
fn json_forced_as_xml_and_xml_forced_as_json_write_nothing_and_echo_nothing() {
    let site = Site::new();
    let json = site.write(
        "a.json",
        &format!(
            r#"{{"cameras":[{{"id":1,"name":"A","settings":{{"videosourcestring":"rtsp://{USER}:{PASSWORD}@192.0.2.13/s"}}}}]}}"#
        ),
    );
    let xml = site.write(
        "a.xml",
        &format!(
            "<objects><cameras><camera id=\"1\" name=\"A\"><settings>\
             <videosourcestring>rtsp://{USER}:{PASSWORD}@192.0.2.13/s</videosourcestring>\
             </settings></camera></cameras></objects>"
        ),
    );
    for (file, fmt) in [(&json, "xml"), (&xml, "json")] {
        let out = site.import(file, &["--format", fmt]);
        assert_eq!(out.status.code(), Some(1), "{}", text(&out.stderr));
        no_secrets(&out);
        assert_eq!(site.state_files(), 0);
    }
}

#[test]
fn every_parser_refusal_of_a_json_file_exits_1_without_echo() {
    let site = Site::new();
    let p = PASSWORD;
    let bodies = [
        // Duplicate key.
        format!(
            r#"{{"cameras":[{{"name":"A","settings":{{"password":"{p}","password":"{p}"}}}}]}}"#
        ),
        // Non-text credential.
        format!(r#"{{"cameras":[{{"name":"A","settings":{{"password":["{p}"]}}}}]}}"#),
        // Malformed.
        format!(r#"{{"cameras":[{{"name":"A","settings":{{"password":"{p}"#),
        // Not objects.
        format!(r#"{{"cameras":"{p}"}}"#),
        // Too deep.
        format!(
            r#"{{"cameras":[],"x":{}"{p}"{}}}"#,
            "[".repeat(40),
            "]".repeat(40)
        ),
    ];
    for (i, b) in bodies.iter().enumerate() {
        let file = site.write(&format!("r{i}.json"), b);
        let out = site.import(&file, &[]);
        assert_eq!(out.status.code(), Some(1), "row {i}: {}", text(&out.stderr));
        no_secrets(&out);
        assert_eq!(site.state_files(), 0, "row {i}");
    }
}

#[test]
fn an_unknown_format_value_is_a_usage_error() {
    let site = Site::new();
    let file = site.write("objects.json", r#"{"cameras":[]}"#);
    for v in ["JSON", "yaml", ""] {
        let out = site.import(&file, &["--format", v]);
        assert_eq!(out.status.code(), Some(2), "{v:?}");
    }
}
