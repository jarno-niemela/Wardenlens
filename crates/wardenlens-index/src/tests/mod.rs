//! Tests of the index. Helpers shared by the submodules.

mod adv_145_guard;
mod camera_tests;
mod cursor_tests;
mod guard_tests;
mod hygiene;
mod matrix_tests;
mod migrate_tests;
mod model;
mod open_tests;
mod ops_tests;
mod plan_tests;
mod registry_tests;
mod rows_tests;
mod schema_tests;
mod token_tests;

use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use wardenlens_core::camera::CameraId;
use wardenlens_core::recording::SegmentRecord;
use wardenlens_core::time::{Timestamp, UnixMs};

use crate::Index;

pub(crate) const BASE: i64 = 1_700_000_000_000;

pub(crate) fn cam(s: &str) -> CameraId {
    CameraId::new(s).unwrap()
}

pub(crate) fn rec(camera: &str, start: i64, dur: u64, bytes: u64, frames: u64) -> SegmentRecord {
    SegmentRecord::new(cam(camera), UnixMs::new(start).unwrap(), dur, bytes, frames)
}

pub(crate) fn ts(ms: i64) -> Timestamp {
    Timestamp::from_unix_millis(ms)
}

pub(crate) struct Fixture {
    pub(crate) dir: tempfile::TempDir,
    pub(crate) path: PathBuf,
}

/// A temporary directory nobody else can write (tempfile follows the umask).
pub(crate) fn private_tempdir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    chmod(dir.path(), 0o700);
    dir
}

pub(crate) fn fixture() -> Fixture {
    let dir = private_tempdir();
    let path = dir.path().join("index.db");
    Fixture { dir, path }
}

pub(crate) fn open_new() -> (Fixture, Index) {
    let f = fixture();
    let idx = Index::open(&f.path).unwrap();
    (f, idx)
}

pub(crate) fn chmod(p: &Path, mode: u32) {
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode)).unwrap();
}

/// Name and bytes of every entry of `dir` (directories and FIFOs by name only).
pub(crate) fn snapshot(dir: &Path) -> BTreeMap<String, Option<Vec<u8>>> {
    let mut out = BTreeMap::new();
    for e in std::fs::read_dir(dir).unwrap() {
        let e = e.unwrap();
        let name = e.file_name().to_string_lossy().into_owned();
        let ft = e.file_type().unwrap();
        let bytes = if ft.is_file() {
            Some(std::fs::read(e.path()).unwrap())
        } else {
            None
        };
        out.insert(name, bytes);
    }
    out
}

pub(crate) fn raw(path: &Path) -> rusqlite::Connection {
    rusqlite::Connection::open(path).unwrap()
}
