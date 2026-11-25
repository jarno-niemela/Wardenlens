//! Adversarial tests for #49 round 5 (PR #140 at b272cd2): the generation bump as the tie
//! between a `-wal` and its main file, the torn-main rule, and sidecars that are not derived
//! state.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::as_conversions,
    reason = "adversary tests: a failed setup step is a test failure"
)]

use std::collections::{BTreeMap, BTreeSet};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use wardenlens_core::camera::CameraId;
use wardenlens_core::recording::SegmentRecord;
use wardenlens_core::storage::{SegmentId, SegmentIndex, Tier};
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

/// Every row of `camera` as `(start, tier is hot)`.
fn rows(idx: &Index, camera: &str) -> BTreeSet<(i64, bool)> {
    let mut out = BTreeSet::new();
    let mut cursor = None;
    loop {
        let page = idx
            .list(
                &cam(camera),
                Timestamp::from_unix_millis(0),
                Timestamp::from_unix_millis(i64::MAX),
                1000,
                cursor.as_ref(),
            )
            .unwrap();
        out.extend(
            page.items
                .iter()
                .map(|s| (s.record.started_at_ms.as_i64(), s.tier == Tier::Hot)),
        );
        match page.next {
            Some(c) => cursor = Some(c),
            None => return out,
        }
    }
}

fn copy_private(from: &Path, to: &Path) {
    std::fs::write(to, std::fs::read(from).unwrap()).unwrap();
    chmod(to, 0o600);
}

/// Valid frames of a `-wal` (salts equal to the header's), as `(pgno, page bytes)` in order.
fn frames(wal: &[u8]) -> (usize, Vec<(u32, Vec<u8>)>) {
    let page = u32::from_be_bytes(wal[8..12].try_into().unwrap()) as usize;
    let salts = &wal[16..24];
    let mut out = Vec::new();
    let mut at = 32;
    while at + 24 + page <= wal.len() {
        if &wal[at + 8..at + 16] != salts {
            break;
        }
        let n = u32::from_be_bytes(wal[at..at + 4].try_into().unwrap());
        out.push((n, wal[at + 24..at + 24 + page].to_vec()));
        at += 24 + page;
    }
    (page, out)
}

// ---------------------------------------------------------------------------------------------
// Torn main file: every page of the `-wal`, several sector boundaries, both tear directions,
// and a checkpoint that already wrote every earlier page (TEST-9: the space enumerated here).
// ---------------------------------------------------------------------------------------------

/// A crash image taken while a live index has uncheckpointed commits on top of a checkpointed
/// main file: returns (main bytes, wal bytes, expected rows of "c").
fn live_crash_image() -> (Vec<u8>, Vec<u8>, BTreeSet<(i64, bool)>) {
    let dir = private_tempdir();
    let path = dir.path().join("index.db");
    {
        let mut idx = Index::open(&path).unwrap();
        for k in 0..40 {
            idx.insert(&rec("c", BASE + k * 10_000), Tier::Hot).unwrap();
        }
    } // closed: checkpointed into the main file, `-wal` removed
    let mut idx = Index::open(&path).unwrap();
    for k in 40..700 {
        idx.insert(&rec("c", BASE + k * 10_000), Tier::Hot).unwrap();
    }
    for id in 1..=10 {
        idx.delete(SegmentId::new(id)).unwrap();
    }
    for id in 11..=20 {
        idx.set_tier(SegmentId::new(id), Tier::Archive).unwrap();
    }
    let want = rows(&idx, "c");
    let main = std::fs::read(&path).unwrap();
    let wal = std::fs::read(sidecar(&path, "-wal")).unwrap();
    drop(idx);
    assert!(wal.len() > 32);
    (main, wal, want)
}

#[derive(Debug, Clone, Copy)]
enum Tear {
    /// The first `k` bytes are the new page, the rest the old one.
    NewHead(usize),
    /// The first `k` bytes are the old page, the rest the new one.
    OldHead(usize),
    /// Only the first `k` bytes of a page that grew the file were written (short file).
    Short(usize),
}

fn torn_main(
    old: &[u8],
    newest: &BTreeMap<u32, Vec<u8>>,
    page: usize,
    pgno: u32,
    tear: Tear,
    earlier_done: bool,
) -> Vec<u8> {
    let mut main = old.to_vec();
    let put = |main: &mut Vec<u8>, at: usize, bytes: &[u8]| {
        if main.len() < at + bytes.len() {
            main.resize(at + bytes.len(), 0);
        }
        main[at..at + bytes.len()].copy_from_slice(bytes);
    };
    if earlier_done {
        for (&p, bytes) in newest.range(..pgno) {
            put(&mut main, (p as usize - 1) * page, bytes);
        }
    }
    let at = (pgno as usize - 1) * page;
    let new = &newest[&pgno];
    match tear {
        Tear::NewHead(k) => {
            if main.len() < at + page {
                main.resize(at + page, 0);
            }
            put(&mut main, at, &new[..k]);
        }
        Tear::OldHead(k) => {
            if main.len() < at + page {
                main.resize(at + page, 0);
            }
            put(&mut main, at + k, &new[k..]);
        }
        Tear::Short(k) => {
            if main.len() > at {
                return main; // not a growing page: covered by the other cases
            }
            main.resize(at, 0);
            put(&mut main, at, &new[..k]);
        }
    }
    main
}

/// A crash in the middle of a checkpoint leaves one page of the main file torn, anywhere and at
/// any sector boundary. The index's own `-wal` still holds every frame, so the replayed view is
/// sound: the open must succeed with every committed row and never call the own `-wal` foreign
/// (ADR 0005 section 5: "the replayed view decides").
#[test]
fn a_main_file_torn_at_any_page_and_sector_by_a_checkpoint_opens_with_every_row() {
    let (old, wal, want) = live_crash_image();
    let (page, fs) = frames(&wal);
    let newest: BTreeMap<u32, Vec<u8>> = fs.into_iter().collect();
    assert!(
        newest.contains_key(&1) && newest.contains_key(&2) && newest.keys().count() > 8,
        "{:?}",
        newest.keys()
    );

    // Control: the untouched image opens with every row.
    {
        let dir = private_tempdir();
        let path = dir.path().join("index.db");
        std::fs::write(&path, &old).unwrap();
        std::fs::write(sidecar(&path, "-wal"), &wal).unwrap();
        chmod(&path, 0o600);
        chmod(&sidecar(&path, "-wal"), 0o600);
        assert_eq!(rows(&Index::open(&path).unwrap(), "c"), want);
    }

    let mut cuts = vec![512, 1024, 2048];
    cuts.push(page - 512);
    let mut failures = Vec::new();
    let mut tried = 0;
    for &pgno in newest.keys() {
        for &k in &cuts {
            for tear in [Tear::NewHead(k), Tear::OldHead(k), Tear::Short(k)] {
                for earlier_done in [false, true] {
                    let main = torn_main(&old, &newest, page, pgno, tear, earlier_done);
                    let dir = private_tempdir();
                    let path = dir.path().join("index.db");
                    std::fs::write(&path, &main).unwrap();
                    std::fs::write(sidecar(&path, "-wal"), &wal).unwrap();
                    chmod(&path, 0o600);
                    chmod(&sidecar(&path, "-wal"), 0o600);
                    tried += 1;
                    match Index::open(&path) {
                        Ok(idx) => {
                            let got = rows(&idx, "c");
                            if got != want {
                                failures.push(format!(
                                    "page {pgno} {tear:?} earlier={earlier_done}: rows differ"
                                ));
                            }
                        }
                        Err(e) => failures.push(format!(
                            "page {pgno} {tear:?} earlier={earlier_done}: {e:?}"
                        )),
                    }
                }
            }
        }
    }
    assert!(tried > 20);
    assert!(
        failures.is_empty(),
        "{} of {tried} torn images refused:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

// ---------------------------------------------------------------------------------------------
// The bump: a foreign `-wal` holding a single small commit, after a checkpoint and a WAL restart
// ---------------------------------------------------------------------------------------------

fn closed_index_with(camera: &str, n: i64) -> (tempfile::TempDir, PathBuf) {
    let dir = private_tempdir();
    let path = dir.path().join("index.db");
    let mut idx = Index::open(&path).unwrap();
    for k in 0..n {
        idx.insert(&rec(camera, BASE + k * 10_000), Tier::Hot)
            .unwrap();
    }
    drop(idx);
    assert!(!sidecar(&path, "-wal").exists());
    (dir, path)
}

/// The `-wal` of another index after one operation `op` on a freshly reopened (checkpointed)
/// index: only the pages that operation touched.
fn single_commit_wal_of_other(op: &str) -> Vec<u8> {
    let (_d, path) = closed_index_with("c", 5);
    let mut idx = Index::open(&path).unwrap();
    match op {
        "set_tier" => idx.set_tier(SegmentId::new(3), Tier::Archive).unwrap(),
        "delete" => idx.delete(SegmentId::new(3)).unwrap(),
        "insert" => {
            idx.insert(&rec("c", BASE + 5 * 10_000), Tier::Hot).unwrap();
        }
        _ => unreachable!(),
    }
    let wal = std::fs::read(sidecar(&path, "-wal")).unwrap();
    drop(idx);
    wal
}

/// The same op on both sides, same row ids, same schema: the foreign `-wal` differs from what
/// this index would write only by the instance id. It must be `ForeignWal`, untouched.
#[test]
fn a_foreign_single_commit_wal_with_the_same_shape_is_refused_untouched() {
    for op in ["set_tier", "delete", "insert"] {
        let wal = single_commit_wal_of_other(op);
        let (_, fs) = frames(&wal);
        assert!(
            fs.iter().any(|(p, _)| *p == 2),
            "{op}: the commit holds no frame of page 2"
        );
        let (dir, path) = closed_index_with("c", 5);
        let w = sidecar(&path, "-wal");
        std::fs::write(&w, &wal).unwrap();
        chmod(&w, 0o600);
        let before = snapshot(dir.path());
        match Index::open(&path) {
            Err(IndexError::ForeignWal) => {}
            Ok(idx) => panic!("{op}: foreign -wal accepted, rows {:?}", rows(&idx, "c")),
            Err(e) => panic!("{op}: {e:?}"),
        }
        assert_eq!(before, snapshot(dir.path()), "{op}: directory changed");
    }
}

/// A long-lived index whose `-wal` was checkpointed and restarted (old frames with stale salts
/// remain behind the new ones) is still tied to its main file.
#[test]
fn a_restarted_foreign_wal_with_stale_frames_is_refused_and_an_own_one_recovers() {
    // Enough commits for automatic checkpoints (1000 pages) so the WAL restarts.
    let other = private_tempdir();
    let op = other.path().join("index.db");
    let mut b = Index::open(&op).unwrap();
    for k in 0..1500 {
        b.insert(&rec("t", BASE + k * 10_000), Tier::Hot).unwrap();
    }
    let wal = std::fs::read(sidecar(&op, "-wal")).unwrap();
    let main_b = std::fs::read(&op).unwrap();
    let want_b = rows(&b, "t");
    drop(b);
    let (page, fs) = frames(&wal);
    let total = (wal.len() - 32) / (24 + page);
    assert!(
        fs.len() < total,
        "the WAL did not restart ({} valid of {total} frames)",
        fs.len()
    );

    let (dir, path) = closed_index_with("t", 5);
    let w = sidecar(&path, "-wal");
    std::fs::write(&w, &wal).unwrap();
    chmod(&w, 0o600);
    let before = snapshot(dir.path());
    assert!(matches!(Index::open(&path), Err(IndexError::ForeignWal)));
    assert_eq!(before, snapshot(dir.path()));

    // Control: B's own crash image recovers every row.
    let image = private_tempdir();
    let ip = image.path().join("index.db");
    std::fs::write(&ip, &main_b).unwrap();
    chmod(&ip, 0o600);
    std::fs::write(sidecar(&ip, "-wal"), &wal).unwrap();
    chmod(&sidecar(&ip, "-wal"), 0o600);
    assert_eq!(rows(&Index::open(&ip).unwrap(), "t"), want_b);
}

/// A write that fails (duplicate, not found, already on tier) commits nothing, so it must leave
/// no frame at all; and every successful write adds page 2 (the frame parser, not the code,
/// decides).
#[test]
fn failed_writes_leave_no_frame_and_each_success_adds_page_two() {
    let (_d, path) = closed_index_with("c", 3);
    let mut idx = Index::open(&path).unwrap();
    let wal_path = sidecar(&path, "-wal");
    let len = || std::fs::metadata(&wal_path).map_or(0, |m| m.len());
    let start = len();
    assert!(idx.insert(&rec("c", BASE), Tier::Hot).is_err());
    assert!(idx.delete(SegmentId::new(99)).is_err());
    assert!(idx.set_tier(SegmentId::new(1), Tier::Hot).is_err());
    assert!(idx.set_tier(SegmentId::new(99), Tier::Archive).is_err());
    assert!(idx.delete(SegmentId::new(u64::MAX)).is_err());
    assert_eq!(len(), start, "a failed write appended frames");
    let mut last = 0usize;
    for step in 0..3 {
        match step {
            0 => drop(
                idx.insert(&rec("c", BASE + 99 * 10_000), Tier::Hot)
                    .unwrap(),
            ),
            1 => idx.set_tier(SegmentId::new(1), Tier::Archive).unwrap(),
            _ => idx.delete(SegmentId::new(2)).unwrap(),
        }
        let wal = std::fs::read(&wal_path).unwrap();
        let (_, fs) = frames(&wal);
        assert!(fs.len() > last, "step {step}: no frame");
        assert!(
            fs[last..].iter().any(|(p, _)| *p == 2),
            "step {step}: commit without a frame of page 2"
        );
        last = fs.len();
    }
}

// ---------------------------------------------------------------------------------------------
// Sidecars that are not derived state
// ---------------------------------------------------------------------------------------------

/// A `-shm` is accepted next to a WAL-mode index as derived state, and SQLite truncates and
/// rewrites it. A `-shm` that is a hard link to another file (here: a file of ours that holds
/// data) is not derived state: it must be refused, or at least the linked file left intact.
#[test]
#[ignore = "follow-up #145"]
fn a_hard_linked_shm_does_not_clobber_the_file_it_links_to() {
    let (dir, path) = closed_index_with("c", 3);
    let keep = dir.path().join("keep.bin");
    let precious = vec![0xA5u8; 40_000];
    std::fs::write(&keep, &precious).unwrap();
    chmod(&keep, 0o600);
    std::fs::hard_link(&keep, sidecar(&path, "-shm")).unwrap();
    let r = Index::open(&path);
    let after = std::fs::read(&keep).unwrap();
    drop(r);
    assert_eq!(
        after.len(),
        precious.len(),
        "the hard-linked file was truncated or grown"
    );
    assert!(after == precious, "the hard-linked file was rewritten");
}

/// The same for a `-wal` hard link: an own valid `-wal` linked from elsewhere is replayed and
/// then checkpointed and deleted; the other name must at least still hold its bytes.
#[test]
fn a_hard_linked_wal_is_not_rewritten_through_the_other_name() {
    let dir = private_tempdir();
    let path = dir.path().join("index.db");
    let mut idx = Index::open(&path).unwrap();
    idx.insert(&rec("c", BASE), Tier::Hot).unwrap();
    // Crash image of this index.
    let image = private_tempdir();
    let ip = image.path().join("index.db");
    copy_private(&path, &ip);
    copy_private(&sidecar(&path, "-wal"), &sidecar(&ip, "-wal"));
    drop(idx);
    let other_name = image.path().join("backup-of-wal");
    std::fs::hard_link(sidecar(&ip, "-wal"), &other_name).unwrap();
    let saved = std::fs::read(&other_name).unwrap();
    {
        let mut idx = Index::open(&ip).unwrap();
        idx.insert(&rec("c", BASE + 10_000), Tier::Hot).unwrap();
    }
    let after = std::fs::read(&other_name).unwrap();
    assert!(
        after.len() >= saved.len() && after[..32] == saved[..32],
        "the backup name of the -wal was rewritten"
    );
}

// ---------------------------------------------------------------------------------------------
// Messages (SEC-6): no path and no SQLite text for the round-5 variants
// ---------------------------------------------------------------------------------------------

#[test]
fn round_five_errors_carry_no_path() {
    let (dir, path) = closed_index_with("c", 1);
    let w = sidecar(&path, "-wal");
    std::fs::write(&w, single_commit_wal_of_other("insert")).unwrap();
    chmod(&w, 0o600);
    let e = Index::open(&path).unwrap_err();
    let text = format!("{e} {e:?}");
    let dir_text = dir.path().display().to_string();
    assert!(!text.contains(&dir_text), "{text}");
    assert!(!text.contains("index.db"), "{text}");
}

// ---------------------------------------------------------------------------------------------
// "Anything that is not a valid header is InvalidWal and is never opened read-write"
// ---------------------------------------------------------------------------------------------

/// A `-wal` whose header has the right magic and page size but a wrong header checksum is not
/// a valid header to SQLite: it ignores every frame. Our rule only checks magic and page size, so
/// the file is classed `Valid`, opened read-write, and on close SQLite deletes it, with the
/// committed rows it holds (recoverable by fixing 8 bytes). The documented rule says such a file
/// is `InvalidWal` and kept byte-identical.
#[test]
#[ignore = "follow-up #145"]
fn a_wal_with_a_bad_header_checksum_is_refused_and_kept() {
    let dir = private_tempdir();
    let path = dir.path().join("index.db");
    let (_d, src) = closed_index_with("c", 3);
    let mut idx = Index::open(&src).unwrap();
    idx.insert(&rec("c", BASE + 50 * 10_000), Tier::Hot)
        .unwrap();
    copy_private(&src, &path);
    let mut wal = std::fs::read(sidecar(&src, "-wal")).unwrap();
    drop(idx);
    wal[24] ^= 0x01; // header checksum, first word
    let w = sidecar(&path, "-wal");
    std::fs::write(&w, &wal).unwrap();
    chmod(&w, 0o600);
    let before = snapshot(dir.path());
    let r = Index::open(&path);
    let opened = r.is_ok();
    drop(r);
    let after = snapshot(dir.path());
    let kept = before.get("index.db-wal") == after.get("index.db-wal");
    let rows_now = rows(&Index::open(&path).unwrap(), "c").len();
    assert!(
        kept,
        "opened={opened}: the -wal holding a committed row was {} (rows now {rows_now} of 4)",
        if after.contains_key("index.db-wal") {
            "rewritten"
        } else {
            "deleted"
        }
    );
}
