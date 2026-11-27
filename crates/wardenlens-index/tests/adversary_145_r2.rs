//! Adversarial tests for #145 round 2 (PR #147 at 0a01fcc): the hard-linked main file refusal in
//! every main state and through every name, links made while an index is open, and WAL headers
//! whose checksum is right but whose other fields SQLite rejects.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::as_conversions,
    reason = "adversary tests: a failed setup step is a test failure"
)]

use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use wardenlens_core::camera::CameraId;
use wardenlens_core::recording::SegmentRecord;
use wardenlens_core::storage::{SegmentIndex, Tier};
use wardenlens_core::time::{Timestamp, UnixMs};
use wardenlens_index::{Index, IndexError};

const BASE: i64 = 1_700_000_000_000;

fn private_tempdir() -> tempfile::TempDir {
    let d = tempfile::tempdir().unwrap();
    std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    d
}

fn cam(s: &str) -> CameraId {
    CameraId::new(s).unwrap()
}

fn rec(camera: &str, start: i64) -> SegmentRecord {
    SegmentRecord::new(cam(camera), UnixMs::new(start).unwrap(), 1000, 10, 1)
}

fn chmod(p: &Path, mode: u32) {
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode)).unwrap();
}

fn sidecar(p: &Path, suffix: &str) -> PathBuf {
    let mut n = p.as_os_str().to_owned();
    n.push(suffix);
    n.into()
}

fn snapshot(dir: &Path) -> BTreeMap<String, Option<Vec<u8>>> {
    std::fs::read_dir(dir)
        .unwrap()
        .map(|e| {
            let e = e.unwrap();
            let name = e.file_name().to_string_lossy().into_owned();
            let ft = e.file_type().unwrap();
            (name, ft.is_file().then(|| std::fs::read(e.path()).unwrap()))
        })
        .collect()
}

fn count(idx: &Index, camera: &str) -> usize {
    idx.list(
        &cam(camera),
        Timestamp::from_unix_millis(0),
        Timestamp::from_unix_millis(i64::MAX),
        1000,
        None,
    )
    .unwrap()
    .items
    .len()
}

/// A checkpointed index with `n` rows, then a live `-wal` with one more row.
fn main_and_live_wal(n: i64) -> (Vec<u8>, Vec<u8>) {
    let dir = private_tempdir();
    let path = dir.path().join("index.db");
    {
        let mut idx = Index::open(&path).unwrap();
        for k in 0..n {
            idx.insert(&rec("c", BASE + k * 10_000), Tier::Hot).unwrap();
        }
    }
    let mut idx = Index::open(&path).unwrap();
    idx.insert(&rec("c", BASE + 99 * 10_000), Tier::Hot)
        .unwrap();
    let main = std::fs::read(&path).unwrap();
    let wal = std::fs::read(sidecar(&path, "-wal")).unwrap();
    drop(idx);
    (main, wal)
}

fn write_private(p: &Path, bytes: &[u8]) {
    std::fs::write(p, bytes).unwrap();
    chmod(p, 0o600);
}

#[derive(Debug, Clone, Copy)]
enum MainState {
    Empty,
    ClosedIndex,
    LiveWal,
    LiveWalAndShm,
}

fn setup_main(state: MainState, path: &Path) {
    match state {
        MainState::Empty => write_private(path, b""),
        MainState::ClosedIndex => {
            let mut idx = Index::open(path).unwrap();
            idx.insert(&rec("c", BASE), Tier::Hot).unwrap();
        }
        MainState::LiveWal | MainState::LiveWalAndShm => {
            let (main, wal) = main_and_live_wal(2);
            write_private(path, &main);
            write_private(&sidecar(path, "-wal"), &wal);
            if matches!(state, MainState::LiveWalAndShm) {
                write_private(&sidecar(path, "-shm"), &vec![0u8; 32_768]);
            }
        }
    }
}

/// A main file with a second name, in every main state and opened through either name, is
/// refused with `HardLinkedIndex` and neither directory changes (an empty file is not "discarded"
/// either: this call did not create it).
#[test]
fn a_hard_linked_main_file_is_refused_untouched_in_every_state_and_through_either_name() {
    for state in [
        MainState::Empty,
        MainState::ClosedIndex,
        MainState::LiveWal,
        MainState::LiveWalAndShm,
    ] {
        for open_second in [false, true] {
            for same_dir in [false, true] {
                let da = private_tempdir();
                let db = private_tempdir();
                let pa = da.path().join("index.db");
                let pb = if same_dir {
                    da.path().join("other.db")
                } else {
                    db.path().join("index.db")
                };
                setup_main(state, &pa);
                if std::fs::hard_link(&pa, &pb).is_err() {
                    return; // different file systems
                }
                let before = (snapshot(da.path()), snapshot(db.path()));
                let target = if open_second { &pb } else { &pa };
                let r = Index::open(target);
                let what = format!("{state:?} second={open_second} same_dir={same_dir}");
                assert!(
                    matches!(r, Err(IndexError::HardLinkedIndex)),
                    "{what}: {r:?}"
                );
                assert!(
                    before == (snapshot(da.path()), snapshot(db.path())),
                    "{what}: the refusal changed a directory"
                );
            }
        }
    }
}

/// After the extra name is removed (the remedy the message names), the index opens with every
/// row.
#[test]
fn removing_the_extra_name_restores_the_index() {
    let d = private_tempdir();
    let pa = d.path().join("index.db");
    let pb = d.path().join("alias.db");
    setup_main(MainState::LiveWal, &pa);
    std::fs::hard_link(&pa, &pb).unwrap();
    assert!(matches!(Index::open(&pa), Err(IndexError::HardLinkedIndex)));
    std::fs::remove_file(&pb).unwrap();
    let idx = Index::open(&pa).unwrap();
    assert_eq!(count(&idx, "c"), 3);
}

/// A second name made while one index is open: every later open, through either name, is
/// refused untouched; the index already open keeps working and its rows survive.
#[test]
fn a_link_made_while_an_index_is_open_blocks_later_opens_without_harm() {
    let d = private_tempdir();
    let pa = d.path().join("index.db");
    let pb = d.path().join("alias.db");
    let mut ia = Index::open(&pa).unwrap();
    for k in 0..5 {
        ia.insert(&rec("c", BASE + k * 10_000), Tier::Hot).unwrap();
    }
    std::fs::hard_link(&pa, &pb).unwrap();
    let before = snapshot(d.path());
    // The same process has it open (#148): refused as such, through either name.
    assert!(matches!(
        Index::open(&pb),
        Err(IndexError::AlreadyOpenInProcess)
    ));
    assert!(matches!(
        Index::open(&pa),
        Err(IndexError::AlreadyOpenInProcess)
    ));
    assert!(before == snapshot(d.path()), "a refused open wrote");
    ia.insert(&rec("c", BASE + 50 * 10_000), Tier::Hot).unwrap();
    assert_eq!(count(&ia, "c"), 6);
    drop(ia);
    // Once closed, the extra name is what refuses.
    assert!(matches!(Index::open(&pb), Err(IndexError::HardLinkedIndex)));
    assert!(matches!(Index::open(&pa), Err(IndexError::HardLinkedIndex)));
    std::fs::remove_file(&pb).unwrap();
    let idx = Index::open(&pa).unwrap();
    assert_eq!(count(&idx, "c"), 6);
}

fn cksum(data: &[u8], big: bool) -> (u32, u32) {
    let w = |b: &[u8]| {
        let a: [u8; 4] = b.try_into().unwrap();
        if big {
            u32::from_be_bytes(a)
        } else {
            u32::from_le_bytes(a)
        }
    };
    let (mut s0, mut s1) = (0u32, 0u32);
    let (pairs, _) = data.as_chunks::<8>();
    for pair in pairs {
        s0 = s0.wrapping_add(w(&pair[..4])).wrapping_add(s1);
        s1 = s1.wrapping_add(w(&pair[4..])).wrapping_add(s0);
    }
    (s0, s1)
}

/// Sets bytes `at..at+4` of the WAL header to `value` and recomputes the header checksum, so only
/// the field differs (frame checksums chain from the header checksum, so the frames no longer
/// validate either: SQLite sees a header it may or may not accept and no valid frame).
fn patch_header(wal: &[u8], at: usize, value: u32) -> Vec<u8> {
    let mut w = wal.to_vec();
    w[at..at + 4].copy_from_slice(&value.to_be_bytes());
    let big = w[3] & 1 == 1;
    let (s0, s1) = cksum(&w[0..24], big);
    w[24..28].copy_from_slice(&s0.to_be_bytes());
    w[28..32].copy_from_slice(&s1.to_be_bytes());
    w
}

/// A WAL header with a correct checksum and page size but another format version: SQLite refuses
/// to use it (`SQLITE_CANTOPEN`). The open must be refused and leave the directory byte-identical
/// (in particular, never open it read-write, which could rewrite or delete it).
#[test]
fn a_wal_with_an_unknown_format_version_is_refused_and_kept() {
    let (main, wal) = main_and_live_wal(3);
    for version in [0u32, 3_007_001, 3_006_999, u32::MAX] {
        let d = private_tempdir();
        let path = d.path().join("index.db");
        write_private(&path, &main);
        write_private(&sidecar(&path, "-wal"), &patch_header(&wal, 4, version));
        let before = snapshot(d.path());
        let r = Index::open(&path);
        let opened = r.is_ok();
        let summary = format!("{r:?}");
        drop(r);
        assert!(
            before == snapshot(d.path()),
            "version {version}: opened={opened} ({summary}), the directory changed"
        );
        assert!(!opened, "version {version}: opened");
    }
}

/// The checkpoint sequence and salts are free fields to SQLite: a header with a recomputed
/// checksum but other salts has no valid frame. Whatever the verdict, the `-wal` (which may hold
/// frames whose salts are the old ones) and the main file must not change when the open is
/// refused, and an accepted open must keep every row the main file holds.
#[test]
fn a_wal_header_with_other_salts_never_loses_main_file_rows() {
    let (main, wal) = main_and_live_wal(3);
    for (at, value) in [(12usize, 7u32), (16, 0xdead_beef), (20, 0x0102_0304)] {
        let d = private_tempdir();
        let path = d.path().join("index.db");
        write_private(&path, &main);
        write_private(&sidecar(&path, "-wal"), &patch_header(&wal, at, value));
        let before = snapshot(d.path());
        match Index::open(&path) {
            Ok(idx) => assert!(count(&idx, "c") >= 3, "field {at}: rows lost"),
            Err(e) => assert!(
                before == snapshot(d.path()),
                "field {at}: refused with {e:?} but the directory changed"
            ),
        }
    }
}
