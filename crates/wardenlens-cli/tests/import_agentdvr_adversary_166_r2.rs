//! Adversary tests for #166 round 2 (PR #167): the worst-case screen time of
//! `wardenlens import agentdvr --dry-run`.
//!
//! Synthetic data only: documentation-range hosts, invented names and passwords, temporary
//! directories, a cleared environment.

use std::fmt::Write as _;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Stdio};

/// 255 importable cameras whose paths are 511 `a`s, and one skipped carrier camera holding
/// 4096 distinct 255-byte passwords that are 252 `a`s and a three-character tail. No password
/// is in any path, so every window of every path is compared against every password.
fn screen_worst_case() -> String {
    let path = "a".repeat(511);
    let mut body = String::new();
    for i in 0..255 {
        let _ = write!(
            body,
            "<camera id=\"{}\" name=\"Cam {i}\"><settings><videosourcestring>\
             rtsp://192.0.2.1/{path}</videosourcestring></settings></camera>",
            i32::saturating_add(i, 1)
        );
    }
    let alphabet: Vec<char> = "bcdefghijklmnopqrstuvwxyz0123456789".chars().collect();
    let head = "a".repeat(252);
    let mut pws = String::new();
    'outer: for x in &alphabet {
        for y in &alphabet {
            for z in &alphabet {
                if pws.matches("<password>").count() >= 4096 {
                    break 'outer;
                }
                let _ = write!(pws, "<password>{head}{x}{y}{z}</password>");
            }
        }
    }
    let _ = write!(
        body,
        "<camera id=\"999\" name=\"Carrier\"><settings>\
         <videosourcestring>rtsp://192.0.2.9/s</videosourcestring>{pws}</settings></camera>"
    );
    format!("<objects><cameras>{body}</cameras></objects>")
}

#[test]
fn the_worst_case_screen_finishes_in_bounded_time() {
    let dir = tempfile::tempdir().unwrap();
    for d in ["state", "keys", "in"] {
        let p = dir.path().join(d);
        fs::create_dir(&p).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let t = dir.path().display();
    let config = dir.path().join("wardenlens.toml");
    fs::write(
        &config,
        format!(
            "[api]\nlisten = \"127.0.0.1:8080\"\n[storage]\nhot_root = \"{t}/hot\"\n\
             archive_root = \"{t}/archive\"\n[database]\npath = \"{t}/state/index.db\"\n\
             [secrets]\nkey_file = \"{t}/keys/secrets.key\"\n"
        ),
    )
    .unwrap();
    fs::set_permissions(&config, fs::Permissions::from_mode(0o600)).unwrap();
    let file = dir.path().join("in/objects.xml");
    let doc = screen_worst_case();
    assert!(doc.len() < wardenlens_agentdvr::MAX_INPUT_BYTES);
    fs::write(&file, doc).unwrap();
    fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_wardenlens"))
        .env_clear()
        .arg("--config")
        .arg(&config)
        .args(["import", "agentdvr", file.to_str().unwrap(), "--dry-run"])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "exit {:?}, stderr {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    // Every one of the 255 importable cameras was screened and none holds a login. The work is
    // bounded by `MAX_SCREEN_WORK` (a unit test in `import.rs` pins the count).
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(stdout.matches("would import").count(), 255, "{stdout}");
}
