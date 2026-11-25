//! Adversarial tests for #145 (PR #147 at 45d6ee7): the WAL header checksum in both byte orders,
//! hard-linked main files and sidecars.
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

/// A checkpointed index with `n` rows, then a live `-wal` with one more row: returns the main
/// file bytes and the `-wal` bytes (written by SQLite on this host, so native byte order).
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

fn cksum(data: &[u8], big: bool, mut s0: u32, mut s1: u32) -> (u32, u32) {
    let w = |b: &[u8]| {
        let a: [u8; 4] = b.try_into().unwrap();
        if big {
            u32::from_be_bytes(a)
        } else {
            u32::from_le_bytes(a)
        }
    };
    let (pairs, _) = data.as_chunks::<8>();
    for pair in pairs {
        s0 = s0.wrapping_add(w(&pair[..4])).wrapping_add(s1);
        s1 = s1.wrapping_add(w(&pair[4..])).wrapping_add(s0);
    }
    (s0, s1)
}

/// Rewrites every checksum of `wal` (header and the frame chain) for the byte order `big`, and
/// sets the magic to match. Frames whose salts differ from the header's are left as they are.
fn reorder(wal: &[u8], big: bool) -> Vec<u8> {
    let mut w = wal.to_vec();
    w[0..4].copy_from_slice(&(0x377f_0682u32 | u32::from(big)).to_be_bytes());
    let (mut s0, mut s1) = cksum(&w[0..24], big, 0, 0);
    w[24..28].copy_from_slice(&s0.to_be_bytes());
    w[28..32].copy_from_slice(&s1.to_be_bytes());
    let page = u32::from_be_bytes(w[8..12].try_into().unwrap()) as usize;
    let mut at = 32;
    while at + 24 + page <= w.len() {
        if w[at + 8..at + 16] != w[16..24] {
            break;
        }
        let (a, b) = cksum(&w[at..at + 8], big, s0, s1);
        let (a, b) = cksum(&w[at + 24..at + 24 + page], big, a, b);
        w[at + 16..at + 20].copy_from_slice(&a.to_be_bytes());
        w[at + 20..at + 24].copy_from_slice(&b.to_be_bytes());
        (s0, s1) = (a, b);
        at += 24 + page;
    }
    w
}

fn place(main: &[u8], wal: &[u8]) -> (tempfile::TempDir, PathBuf) {
    let dir = private_tempdir();
    let path = dir.path().join("index.db");
    std::fs::write(&path, main).unwrap();
    chmod(&path, 0o600);
    let w = sidecar(&path, "-wal");
    std::fs::write(&w, wal).unwrap();
    chmod(&w, 0o600);
    (dir, path)
}

/// Sanity: re-checksumming a native `-wal` in its own byte order is the identity.
#[test]
fn the_test_checksum_matches_sqlite_on_this_host() {
    let (_main, wal) = main_and_live_wal(3);
    let big = wal[3] & 1 == 1;
    assert_eq!(reorder(&wal, big), wal);
}

/// A `-wal` written by a host of the other byte order (the other magic, checksums computed with
/// the other word order) is valid to SQLite: its committed row must be replayed, not refused.
#[test]
fn a_wal_in_the_other_byte_order_is_accepted_and_replayed() {
    let (main, wal) = main_and_live_wal(3);
    let native_big = wal[3] & 1 == 1;
    let other = reorder(&wal, !native_big);
    assert_ne!(other, wal);
    let (_d, path) = place(&main, &other);
    let idx =
        Index::open(&path).unwrap_or_else(|e| panic!("refused a valid foreign-order wal: {e:?}"));
    assert_eq!(count(&idx, "c"), 4);
}

/// The native `-wal` placed as-is next to its main file: accepted (control).
#[test]
fn a_native_wal_is_accepted_and_replayed() {
    let (main, wal) = main_and_live_wal(3);
    let (_d, path) = place(&main, &wal);
    let idx = Index::open(&path).unwrap();
    assert_eq!(count(&idx, "c"), 4);
}

/// The magic says one byte order, the checksum was computed with the other: SQLite rejects the
/// header (ignores every frame). It must be `InvalidWal` and kept byte-identical, in both
/// directions.
#[test]
fn a_header_checksummed_in_the_wrong_byte_order_is_refused_and_kept() {
    let (main, wal) = main_and_live_wal(3);
    for big in [false, true] {
        let mut w = reorder(&wal, big);
        // Flip only the magic's byte-order bit: the checksum no longer matches its order.
        w[3] ^= 1;
        let (d, path) = place(&main, &w);
        let before = snapshot(d.path());
        let err = Index::open(&path).unwrap_err();
        assert!(matches!(err, IndexError::InvalidWal), "big={big}: {err:?}");
        assert!(before == snapshot(d.path()), "big={big}: the refusal wrote");
    }
}

/// Every single-bit flip in the 24 checksummed header bytes or the 8 checksum bytes (other than
/// the page-size field, which has its own rule) is refused and leaves the directory untouched.
#[test]
fn every_header_bit_flip_is_refused_and_kept() {
    let (main, wal) = main_and_live_wal(2);
    for byte in (0..32).filter(|b| !(8..12).contains(b)) {
        for bit in 0..8 {
            let mut w = wal.clone();
            w[byte] ^= 1 << bit;
            let (d, path) = place(&main, &w);
            let before = snapshot(d.path());
            let r = Index::open(&path);
            let opened = r.is_ok();
            drop(r);
            assert!(
                before == snapshot(d.path()),
                "byte {byte} bit {bit}: opened={opened}, the -wal or main file changed"
            );
            assert!(!opened, "byte {byte} bit {bit}: opened");
        }
    }
}

/// Child half of the test below: run in its own process (SQLite shares locks per inode inside
/// one process, so only a second process shows the effect). Does nothing unless the parent set
/// the variable.
#[test]
fn hard_link_child() {
    let Some(p) = std::env::var_os("ADV145_CHILD_PATH") else {
        return;
    };
    let mut ib = Index::open(Path::new(&p)).unwrap();
    for k in 0..50 {
        ib.insert(&rec("d", BASE + k * 10_000), Tier::Hot).unwrap();
    }
    drop(ib); // last connection on this name: checkpoints into the shared main file
}

/// The main file is exempt from the link rule. Two names of one main file in two directories get
/// two separate `-wal`/`-shm` pairs, so SQLite's WAL locks do not see each other (a documented way
/// to corrupt a database), and `Index::open`'s `flock` is released after the open. Two processes
/// using one name each must not corrupt the index: the open of a hard-linked main file should
/// be refused, or the two must still be serialised.
#[test]
fn a_hard_linked_main_file_used_by_two_processes_is_not_corrupted() {
    let dir_a = private_tempdir();
    let dir_b = private_tempdir();
    let pa = dir_a.path().join("index.db");
    let pb = dir_b.path().join("index.db");
    {
        let mut idx = Index::open(&pa).unwrap();
        for k in 0..50 {
            idx.insert(&rec("c", BASE + k * 10_000), Tier::Hot).unwrap();
        }
    }
    if std::fs::hard_link(&pa, &pb).is_err() {
        return; // different file systems: nothing to test
    }
    // #145 round 2: the open of a hard-linked main file is refused (the first alternative of this
    // test's contract), for either name, and nothing is written. Otherwise the test goes on
    // and checks the serialised alternative.
    let before = (snapshot(dir_a.path()), snapshot(dir_b.path()));
    let mut ia = match Index::open(&pa) {
        Err(IndexError::HardLinkedIndex) => {
            assert!(matches!(Index::open(&pb), Err(IndexError::HardLinkedIndex)));
            assert_eq!(before, (snapshot(dir_a.path()), snapshot(dir_b.path())));
            return;
        }
        other => other.unwrap(),
    };
    ia.insert(&rec("c", BASE + 1000 * 10_000), Tier::Hot)
        .unwrap();
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "hard_link_child", "--test-threads=1"])
        .env("ADV145_CHILD_PATH", &pb)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .unwrap();
    let child_ok = status.success();
    let mut later_ok = true;
    for k in 0..50 {
        later_ok &= ia.insert(&rec("e", BASE + k * 10_000), Tier::Hot).is_ok();
    }
    drop(ia); // checkpoints a's -wal over the shared main file
    let r = Index::open(&pa);
    let summary = match &r {
        Ok(i) => format!(
            "c={} d={} e={}",
            count(i, "c"),
            count(i, "d"),
            count(i, "e")
        ),
        Err(e) => format!("{e:?}"),
    };
    let sound = match &r {
        Ok(i) => {
            count(i, "c") == 51
                && count(i, "d") == if child_ok { 50 } else { 0 }
                && count(i, "e") == if later_ok { 50 } else { 0 }
        }
        Err(_) => false,
    };
    assert!(
        sound,
        "child_ok={child_ok} later_ok={later_ok}: after writes through two names of one main file: {summary}"
    );
}

/// Main-file states for the hard-link matrix.
#[derive(Debug, Clone, Copy)]
enum MainState {
    Missing,
    Empty,
    ClosedIndex,
    LiveWal,
}

fn setup_main(state: MainState, dir: &Path) -> PathBuf {
    let path = dir.join("index.db");
    match state {
        MainState::Missing => {}
        MainState::Empty => {
            std::fs::write(&path, b"").unwrap();
            chmod(&path, 0o600);
        }
        MainState::ClosedIndex => {
            let mut idx = Index::open(&path).unwrap();
            idx.insert(&rec("c", BASE), Tier::Hot).unwrap();
        }
        MainState::LiveWal => {
            let (main, wal) = main_and_live_wal(2);
            std::fs::write(&path, main).unwrap();
            chmod(&path, 0o600);
            let w = sidecar(&path, "-wal");
            std::fs::write(&w, wal).unwrap();
            chmod(&w, 0o600);
        }
    }
    path
}

/// For every main state and every sidecar: a sidecar that is a second name of a file outside
/// the directory is refused, nothing in the directory changes, and the other name keeps its
/// bytes.
#[test]
fn a_hard_linked_sidecar_is_refused_untouched_in_every_main_state() {
    for state in [
        MainState::Missing,
        MainState::Empty,
        MainState::ClosedIndex,
        MainState::LiveWal,
    ] {
        for suffix in ["-wal", "-shm", "-journal"] {
            let dir = private_tempdir();
            let keep_dir = private_tempdir();
            let path = setup_main(state, dir.path());
            let s = sidecar(&path, suffix);
            let other = keep_dir.path().join("keep.bin");
            if s.exists() {
                std::fs::hard_link(&s, &other).unwrap();
            } else {
                std::fs::write(&other, vec![0x5au8; 40_000]).unwrap();
                chmod(&other, 0o600);
                if std::fs::hard_link(&other, &s).is_err() {
                    return; // tempdirs on different file systems
                }
            }
            let kept = std::fs::read(&other).unwrap();
            let before = snapshot(dir.path());
            let r = Index::open(&path);
            let ok = r.is_ok();
            let err = r.err();
            assert!(!ok, "{state:?} {suffix}: opened");
            assert!(
                matches!(err, Some(IndexError::InsecureSidecar { .. })),
                "{state:?} {suffix}: {err:?}"
            );
            assert!(
                before == snapshot(dir.path()),
                "{state:?} {suffix}: the refusal wrote"
            );
            assert_eq!(std::fs::read(&other).unwrap(), kept, "{state:?} {suffix}");
        }
    }
}
