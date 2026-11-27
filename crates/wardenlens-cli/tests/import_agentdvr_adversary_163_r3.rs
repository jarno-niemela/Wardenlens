//! Adversary tests for #163 round 3 (PR #213 at 2a101aa): the dry run over the read-only index
//! in the WAL states a crash leaves, against the real run.
//!
//! Synthetic only: documentation-range hosts, invented names, temporary directories, a cleared
//! environment.

#![expect(
    clippy::unwrap_used,
    reason = "integration-test helpers outside #[test] fns; clippy.toml in-tests allowances do not reach them"
)]

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;
use std::num::NonZeroU16;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use tempfile::TempDir;
use wardenlens_core::camera::{CameraId, ModelRef, RtspPath, StreamSet};
use wardenlens_core::time::UnixMs;
use wardenlens_index::{CameraRecord, Index};

fn models() -> Vec<String> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../cameras");
    let mut all = Vec::new();
    for v in fs::read_dir(&root).unwrap() {
        let v = v.unwrap().path();
        if v.is_dir() {
            for f in fs::read_dir(&v).unwrap() {
                let f = f.unwrap().path();
                if f.extension().and_then(|e| e.to_str()) == Some("toml") {
                    all.push(format!(
                        "{}/{}",
                        v.file_name().unwrap().to_str().unwrap(),
                        f.file_stem().unwrap().to_str().unwrap()
                    ));
                }
            }
        }
    }
    all.sort();
    all
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
        let out = site.run(&["secrets", "init"]);
        assert!(out.status.success(), "{}", text(&out.stderr));
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
    fn xml(&self, ids: &[u32]) -> PathBuf {
        let mut body = String::new();
        for id in ids {
            write!(
                body,
                "<camera id=\"{id}\" name=\"Fake Cam {id}\"><settings>\
                 <videosourcestring>rtsp://192.0.2.{id}:554/a</videosourcestring>\
                 </settings></camera>"
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
    fn state(&self) -> BTreeMap<String, Vec<u8>> {
        fs::read_dir(self.p("state"))
            .unwrap()
            .map(|e| {
                let e = e.unwrap();
                (
                    e.file_name().to_string_lossy().into_owned(),
                    fs::read(e.path()).unwrap(),
                )
            })
            .collect()
    }
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

fn line_of(out: &str, id: &str) -> String {
    out.lines()
        .find(|l| l.split_whitespace().next() == Some(id))
        .unwrap()
        .to_owned()
}

/// Leaves `state/` as a writer that crashed would: the row `agentdvr-1` under `model` exists only
/// in a non-empty `-wal`; `with_shm` keeps the `-shm` too.
fn crash_with_row_in_wal(site: &Site, model: &str, with_shm: bool) {
    let db = site.p("state/index.db");
    let (v, m) = model.split_once('/').unwrap();
    let mut idx = Index::open(&db).unwrap();
    idx.upsert_camera(
        &CameraRecord::new(
            CameraId::new("agentdvr-1").unwrap(),
            ModelRef::new(v, m).unwrap(),
            NonZeroU16::new(554).unwrap(),
            StreamSet::new(RtspPath::new("/a").unwrap(), None),
        ),
        &[],
        UnixMs::new(1_700_000_000_000).unwrap(),
    )
    .unwrap();
    let saved = tempfile::tempdir().unwrap();
    let names = ["index.db", "index.db-wal", "index.db-shm"];
    for n in names {
        fs::copy(site.p(&format!("state/{n}")), saved.path().join(n)).unwrap();
    }
    drop(idx);
    for n in names {
        let to = site.p(&format!("state/{n}"));
        if n == "index.db-shm" && !with_shm {
            let _ = fs::remove_file(&to);
            continue;
        }
        fs::copy(saved.path().join(n), &to).unwrap();
        fs::set_permissions(&to, fs::Permissions::from_mode(0o600)).unwrap();
    }
    assert!(fs::metadata(site.p("state/index.db-wal")).unwrap().len() > 0);
}

/// A crash with `-wal` and `-shm`: the dry run reads the row from the `-wal` and reports the
/// same skip the real run then makes; the main file and the `-wal` are untouched.
#[test]
fn a_dry_run_over_a_crashed_wal_with_shm_agrees_with_the_real_run() {
    let all = models();
    let (m1, m2) = (&all[0], &all[1]);
    let site = Site::new();
    let file = site.xml(&[1, 2]);
    assert!(site.import(&file, &["--model", m1]).status.success());
    crash_with_row_in_wal(&site, m2, true);
    let before = site.state();
    let dry = site.import(&file, &["--dry-run", "--model", m1]);
    assert!(dry.status.success(), "{}", text(&dry.stderr));
    let after = site.state();
    assert_eq!(
        before.keys().collect::<Vec<_>>(),
        after.keys().collect::<Vec<_>>()
    );
    for n in ["index.db", "index.db-wal", "vault.db"] {
        if before.contains_key(n) {
            assert_eq!(before[n], after[n], "{n} changed in a dry run");
        }
    }
    let dry_out = text(&dry.stdout);
    let real = site.import(&file, &["--model", m1]);
    assert!(real.status.success(), "{}", text(&real.stderr));
    let real_out = text(&real.stdout);
    let d1 = line_of(&dry_out, "agentdvr-1");
    let r1 = line_of(&real_out, "agentdvr-1");
    assert!(d1.contains("skipped"), "dry: {d1}");
    assert!(r1.contains("skipped"), "real: {r1}");
    assert!(!line_of(&dry_out, "agentdvr-2").contains("skipped"));
    assert!(!line_of(&real_out, "agentdvr-2").contains("skipped"));
}

/// With a crashed `-wal` + `-shm`, SQLite's `-shm` of a live `-wal` may be updated, as by any
/// reader (documented); everything else is byte-identical: the main file, the `-wal`, the vault
/// and the key.
#[test]
fn a_dry_run_over_a_crashed_wal_with_shm_leaves_all_but_the_shm_byte_identical() {
    let all = models();
    let site = Site::new();
    let file = site.xml(&[1]);
    assert!(site.import(&file, &["--model", &all[0]]).status.success());
    crash_with_row_in_wal(&site, &all[1], true);
    let before = site.state();
    let dry = site.import(&file, &["--dry-run", "--model", &all[0]]);
    assert!(dry.status.success(), "{}", text(&dry.stderr));
    let after = site.state();
    let changed: Vec<&String> = before
        .keys()
        .filter(|k| !k.ends_with("-shm") && after.get(*k) != before.get(*k))
        .collect();
    assert!(changed.is_empty(), "the dry run changed {changed:?}");
    assert_eq!(
        before.keys().collect::<Vec<_>>(),
        after.keys().collect::<Vec<_>>(),
        "a file was created or removed"
    );
}

/// A crash with no `-shm`: the dry run writes nothing at all, and says the real run recovers
/// first; the real run then skips the row the `-wal` held.
#[test]
fn a_dry_run_over_a_crashed_wal_without_shm_writes_nothing_and_says_so() {
    let all = models();
    let site = Site::new();
    let file = site.xml(&[1]);
    assert!(site.import(&file, &["--model", &all[0]]).status.success());
    crash_with_row_in_wal(&site, &all[1], false);
    let before = site.state();
    let dry = site.import(&file, &["--dry-run", "--model", &all[0]]);
    assert!(dry.status.success(), "{}", text(&dry.stderr));
    assert_eq!(site.state(), before);
    let d1 = line_of(&text(&dry.stdout), "agentdvr-1");
    assert!(d1.contains("recover"), "{d1}");
    let real = site.import(&file, &["--model", &all[0]]);
    assert!(real.status.success(), "{}", text(&real.stderr));
    assert_eq!(dry.status.code(), real.status.code());
    assert!(line_of(&text(&real.stdout), "agentdvr-1").contains("skipped"));
}

/// A dangling symlink at `database.path` is not "no index": the dry run refuses it as the real
/// run does, and nothing is created at the target.
#[test]
fn a_dry_run_refuses_a_dangling_symlinked_index_like_the_real_run() {
    let site = Site::new();
    let file = site.xml(&[1]);
    std::os::unix::fs::symlink(site.p("state/elsewhere.db"), site.p("state/index.db")).unwrap();
    let dry = site.import(&file, &["--dry-run"]);
    let real = site.import(&file, &[]);
    assert!(!site.p("state/elsewhere.db").exists());
    assert_eq!(
        dry.status.code(),
        real.status.code(),
        "{}",
        text(&dry.stderr)
    );
    assert_ne!(dry.status.code(), Some(0));
}
