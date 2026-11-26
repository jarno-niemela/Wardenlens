//! Adversary tests for #166 round 3 (PR #167): the screen's remaining worst case, where every
//! window's first and last bytes match so every window is compared whole.
//!
//! Synthetic data only: documentation-range hosts, invented passwords, temporary directories,
//! a cleared environment.

#![expect(
    clippy::unwrap_used,
    reason = "integration-test helpers outside #[test] fns; clippy.toml in-tests allowances do not reach them"
)]

use std::fmt::Write as _;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Stdio};

/// 255 importable cameras whose paths are 511 `a`s, and one skipped carrier camera holding
/// 4096 distinct 255-byte passwords `a…a XYZ a` (both ends `a`, three distinct bytes just before
/// the last). Every window of every path has matching first and last bytes, so it is compared
/// whole (about 252 bytes before the first difference).
fn ends_match_worst_case() -> String {
    let path = "a".repeat(511);
    let mut body = String::new();
    for i in 1..=255_u32 {
        let _ = write!(
            body,
            "<camera id=\"{i}\" name=\"Cam {i}\"><settings><videosourcestring>\
             rtsp://192.0.2.1/{path}</videosourcestring></settings></camera>"
        );
    }
    let alphabet: Vec<char> = "bcdefghijklmnopqrstuvwxyz0123456789".chars().collect();
    let head = "a".repeat(251);
    let mut pws = String::new();
    let mut n = 0_u32;
    'outer: for x in &alphabet {
        for y in &alphabet {
            for z in &alphabet {
                if n >= 4096 {
                    break 'outer;
                }
                let _ = write!(pws, "<password>{head}{x}{y}{z}a</password>");
                n = n.saturating_add(1);
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

fn run_dry(doc: &str) -> std::process::Output {
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
    assert!(doc.len() < wardenlens_agentdvr::MAX_INPUT_BYTES);
    fs::write(&file, doc).unwrap();
    fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
    Command::new(env!("CARGO_BIN_EXE_wardenlens"))
        .env_clear()
        .arg("--config")
        .arg(&config)
        .args(["import", "agentdvr", file.to_str().unwrap(), "--dry-run"])
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

#[test]
fn the_ends_match_screen_worst_case_finishes_in_bounded_time() {
    let doc = ends_match_worst_case();
    let out = run_dry(&doc);
    assert!(
        out.status.success(),
        "exit {:?}, stderr {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(stdout.matches("would import").count(), 255);
}
