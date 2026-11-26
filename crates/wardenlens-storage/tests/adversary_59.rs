//! Adversarial tests for #59 (PR #165): start-up reconciliation and the "archive returned" pass.
//! Public API only, real SQLite index, temporary directories only.
#![expect(
    clippy::unwrap_used,
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::too_many_lines,
    clippy::many_single_char_names,
    clippy::case_sensitive_file_extension_comparisons,
    reason = "test code: small bounded synthetic values"
)]

use std::collections::BTreeMap;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};

use wardenlens_core::camera::CameraId;
use wardenlens_core::recording::{RelPath, SegmentRecord};
use wardenlens_core::storage::{
    IndexedSegment, MinFreePercent, Policy, SegmentCursor, SegmentId, SegmentIndex, SegmentPage,
    StoredSegment, Tier, TierTotals, VolumeSpace,
};
use wardenlens_core::time::{DurationMs, Timestamp, UnixMs};
use wardenlens_fsutil::RootDir;
use wardenlens_index::{Index, IndexError};
use wardenlens_storage::{
    ARCHIVE_MARKER, ProbeError, RealFs, Storage, StorageConfig, StorageLoop, VolumeUsage,
};

const T0: i64 = 1_700_000_000_000;
const CAM: &str = "cam-1";

// ---- fixtures -------------------------------------------------------------------------------------

#[derive(Clone)]
struct Shared(Arc<Mutex<Index>>);

impl Shared {
    fn with<R>(&self, f: impl FnOnce(&mut Index) -> R) -> R {
        let mut g = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        f(&mut g)
    }
}

impl SegmentIndex for Shared {
    type Error = IndexError;
    fn insert(&mut self, r: &SegmentRecord, t: Tier) -> Result<SegmentId, IndexError> {
        self.with(|i| i.insert(r, t))
    }
    fn get(&self, id: SegmentId) -> Result<Option<IndexedSegment>, IndexError> {
        self.with(|i| i.get(id))
    }
    fn list(
        &self,
        c: &CameraId,
        f: Timestamp,
        t: Timestamp,
        l: usize,
        cur: Option<&SegmentCursor>,
    ) -> Result<SegmentPage, IndexError> {
        self.with(|i| i.list(c, f, t, l, cur))
    }
    fn set_tier(&mut self, id: SegmentId, t: Tier) -> Result<(), IndexError> {
        self.with(|i| i.set_tier(id, t))
    }
    fn delete(&mut self, id: SegmentId) -> Result<(), IndexError> {
        self.with(|i| i.delete(id))
    }
    fn oldest(
        &self,
        t: Tier,
        a: Option<(Timestamp, SegmentId)>,
        n: usize,
    ) -> Result<Vec<StoredSegment>, IndexError> {
        self.with(|i| i.oldest(t, a, n))
    }
    fn newest(&self, t: Tier) -> Result<Option<StoredSegment>, IndexError> {
        self.with(|i| i.newest(t))
    }
    fn bytes_by_tier(&self) -> Result<TierTotals, IndexError> {
        self.with(|i| i.bytes_by_tier())
    }
    fn latest_started_at(&self, c: &CameraId) -> Result<Option<UnixMs>, IndexError> {
        self.with(|i| i.latest_started_at(c))
    }
}

fn du(dir: &Path) -> u64 {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return 0;
    };
    rd.flatten()
        .map(|e| {
            let m = e.path().symlink_metadata().unwrap();
            if m.is_dir() { du(&e.path()) } else { m.len() }
        })
        .sum()
}

struct Fake {
    hot: PathBuf,
    arch: PathBuf,
}

impl VolumeUsage for Fake {
    fn space(&self, tier: Tier, _root: &RootDir) -> Result<VolumeSpace, ProbeError> {
        let cap = 10_000_000_000_u64;
        let dir = if tier == Tier::Hot {
            &self.hot
        } else {
            &self.arch
        };
        Ok(VolumeSpace {
            capacity_bytes: cap,
            free_bytes: cap.saturating_sub(du(dir)),
        })
    }
}

struct World {
    _tmp: tempfile::TempDir,
    hot: PathBuf,
    arch: PathBuf,
    index: Shared,
}

fn cam() -> CameraId {
    CAM.parse().unwrap()
}

fn key(n: i64) -> UnixMs {
    UnixMs::new(T0 + n * 60_000).unwrap()
}

fn rel(n: i64) -> String {
    RelPath::new(&cam(), key(n)).to_string()
}

impl World {
    fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let (hot, arch, idx) = (
            tmp.path().join("hot"),
            tmp.path().join("arch"),
            tmp.path().join("idx"),
        );
        for d in [&hot, &arch, &idx] {
            std::fs::DirBuilder::new().mode(0o700).create(d).unwrap();
        }
        std::fs::write(arch.join(ARCHIVE_MARKER), b"").unwrap();
        let index = Shared(Arc::new(Mutex::new(
            Index::open(&idx.join("index.db")).unwrap(),
        )));
        Self {
            _tmp: tmp,
            hot,
            arch,
            index,
        }
    }

    fn cfg(&self, hot_max_age_min: u64) -> StorageConfig {
        StorageConfig::new(
            self.hot.clone(),
            self.arch.clone(),
            Policy {
                hot_min_free: MinFreePercent::new(5).unwrap(),
                archive_min_free: MinFreePercent::new(5).unwrap(),
                hot_max_age: DurationMs::from_secs(hot_max_age_min * 60),
                emergency_reserve_bytes: 0,
            },
        )
        .with_allow_same_filesystem(true)
    }

    fn open(&self, cfg: StorageConfig) -> StorageLoop<Shared, RealFs, Fake> {
        let usage = Fake {
            hot: self.hot.clone(),
            arch: self.arch.clone(),
        };
        let (lp, _files) = Storage::open(cfg, self.index.clone(), usage).unwrap();
        lp
    }

    fn root(&self, tier: Tier) -> &Path {
        if tier == Tier::Hot {
            &self.hot
        } else {
            &self.arch
        }
    }

    fn put(&self, tier: Tier, n: i64, bytes: &[u8]) -> PathBuf {
        let p = self.root(tier).join(rel(n));
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, bytes).unwrap();
        p
    }

    fn row(&self, n: i64, tier: Tier, bytes: u64) -> SegmentId {
        let rec = SegmentRecord::new(cam(), key(n), 100, bytes, 3);
        self.index.clone().insert(&rec, tier).unwrap()
    }

    fn rows(&self) -> Vec<IndexedSegment> {
        let mut out = Vec::new();
        let mut cursor = None;
        loop {
            let page = self
                .index
                .list(
                    &cam(),
                    Timestamp::from_unix_millis(T0 - 10 * 86_400_000),
                    Timestamp::from_unix_millis(T0 + 10 * 86_400_000),
                    500,
                    cursor.as_ref(),
                )
                .unwrap();
            out.extend(page.items.clone());
            match page.next {
                Some(c) => cursor = Some(c),
                None => return out,
            }
        }
    }

    fn find(&self, n: i64) -> Option<IndexedSegment> {
        self.rows()
            .into_iter()
            .find(|r| r.record.started_at_ms == key(n))
    }

    fn unmount(&self) {
        let _ = std::fs::remove_file(self.arch.join(ARCHIVE_MARKER));
    }

    fn mount(&self) {
        std::fs::write(self.arch.join(ARCHIVE_MARKER), b"").unwrap();
    }
}

fn bx(fourcc: [u8; 4], payload: &[u8]) -> Vec<u8> {
    let size = u32::try_from(payload.len() + 8).unwrap();
    let mut v = size.to_be_bytes().to_vec();
    v.extend_from_slice(&fourcc);
    v.extend_from_slice(payload);
    v
}

fn moov_with_padding(pad: Option<usize>) -> Vec<u8> {
    let mut mdhd = vec![0_u8; 12];
    mdhd.extend_from_slice(&90_000_u32.to_be_bytes());
    mdhd.extend_from_slice(&[0; 4]);
    let mut payload = bx(*b"trak", &bx(*b"mdia", &bx(*b"mdhd", &mdhd)));
    if let Some(total) = pad {
        // `total` is the wanted moov payload length.
        let free_payload = total - payload.len() - 8;
        payload.extend_from_slice(&bx(*b"free", &vec![0_u8; free_payload]));
    }
    bx(*b"moov", &payload)
}

fn fragment(durations: &[u32], mdat_len: usize) -> Vec<u8> {
    let mut trun = 0x0000_0701_u32.to_be_bytes().to_vec();
    trun.extend_from_slice(&u32::try_from(durations.len()).unwrap().to_be_bytes());
    trun.extend_from_slice(&0_i32.to_be_bytes());
    for d in durations {
        trun.extend_from_slice(&d.to_be_bytes());
        trun.extend_from_slice(&100_u32.to_be_bytes());
        trun.extend_from_slice(&0x0101_0000_u32.to_be_bytes());
    }
    let mut tfhd = 0_u32.to_be_bytes().to_vec();
    tfhd.extend_from_slice(&1_u32.to_be_bytes());
    let traf = bx(
        *b"traf",
        &[bx(*b"tfhd", &tfhd), bx(*b"trun", &trun)].concat(),
    );
    let mut out = bx(*b"moof", &[bx(*b"mfhd", &[0; 8]), traf].concat());
    out.extend_from_slice(&bx(*b"mdat", &vec![0xAB; mdat_len]));
    out
}

fn mp4_with(moov: &[u8], fragments: usize, per: &[u32], mdat_len: usize) -> Vec<u8> {
    let mut out = bx(*b"ftyp", b"isom\0\0\0\0isom");
    out.extend_from_slice(moov);
    let frag = fragment(per, mdat_len);
    for _ in 0..fragments {
        out.extend_from_slice(&frag);
    }
    out
}

/// A good segment; `mdat_len` changes its size without changing its validity.
fn good(mdat_len: usize) -> Vec<u8> {
    mp4_with(&moov_with_padding(None), 1, &[3000, 3000, 3000], mdat_len)
}

fn garbage() -> Vec<u8> {
    b"not an mp4 at all, just bytes".to_vec()
}

/// Every regular file below `root` (relative path to bytes).
fn snapshot(root: &Path) -> BTreeMap<String, Vec<u8>> {
    fn walk(base: &Path, d: &Path, out: &mut BTreeMap<String, Vec<u8>>) {
        for e in std::fs::read_dir(d).unwrap().flatten() {
            let p = e.path();
            let r = p.strip_prefix(base).unwrap().to_string_lossy().into_owned();
            let ft = e.file_type().unwrap();
            if ft.is_dir() {
                walk(base, &p, out);
            } else if ft.is_file() {
                out.insert(r, std::fs::read(&p).unwrap());
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(root, root, &mut out);
    out
}

fn segment_files(root: &Path) -> BTreeMap<String, Vec<u8>> {
    snapshot(root)
        .into_iter()
        .filter(|(k, _)| !k.starts_with("_quarantine/") && k.ends_with(".mp4"))
        .collect()
}

fn quarantined(root: &Path) -> Vec<Vec<u8>> {
    snapshot(root)
        .into_iter()
        .filter(|(k, _)| k.starts_with("_quarantine/"))
        .map(|(_, v)| v)
        .collect()
}

// ---- 1. every cell in one directory, real index: post-condition and idempotence ---------------------

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum F {
    N,
    V,
    I,
}

#[test]
fn all_cells_in_one_directory_reach_the_post_condition_and_a_second_start_up_changes_nothing() {
    let w = World::new();
    let row_len = good(40).len() as u64;
    let mut n = 0_i64;
    let mut invalid_contents: Vec<Vec<u8>> = Vec::new();
    for row in [None, Some(Tier::Hot), Some(Tier::Archive)] {
        for h in [F::N, F::V, F::I] {
            for a in [F::N, F::V, F::I] {
                if row.is_none() && h == F::N && a == F::N {
                    continue;
                }
                n += 1;
                // Distinct contents per key so we can trace each invalid file.
                let tag = n as u8;
                for (tier, f) in [(Tier::Hot, h), (Tier::Archive, a)] {
                    match f {
                        F::N => {}
                        F::V => {
                            w.put(tier, n, &good(40));
                        }
                        F::I => {
                            let bytes = if row.is_some() {
                                // Parses, but the size differs from the row's.
                                let mut b = good(41);
                                b.push(tag);
                                b
                            } else {
                                let mut b = garbage();
                                b.push(tag);
                                b.push(tier as u8);
                                b
                            };
                            invalid_contents.push(bytes.clone());
                            w.put(tier, n, &bytes);
                        }
                    }
                }
                if let Some(t) = row {
                    w.row(n, t, row_len);
                }
            }
        }
    }
    // (none, valid, valid) with different sizes: H is quarantined.
    n += 1;
    w.put(Tier::Hot, n, &good(77));
    w.put(Tier::Archive, n, &good(40));
    let diff_h = good(77);
    // One `.part` per root.
    n += 1;
    for root in [&w.hot, &w.arch] {
        let p = root.join(format!("{}.part", rel(n)));
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, b"partial").unwrap();
    }

    let mut lp = w.open(w.cfg(100_000));
    let r = lp.reconcile_startup().unwrap().report;
    assert_eq!(r.unverified, 0, "{r:?}");
    assert_eq!(r.part_deleted, 2, "{r:?}");
    assert_eq!(r.missing, 2, "(hot|archive, none, none): {r:?}");
    assert_eq!(r.adopted, 6, "{r:?}");
    assert_eq!(r.rolled_forward, 3, "{r:?}");
    assert_eq!(r.rolled_back, 2, "{r:?}");
    assert_eq!(r.duplicates_deleted, 3, "{r:?}");
    assert_eq!(
        r.quarantined, 19,
        "18 invalid files (6 per row state) + the unequal hot twin: {r:?}"
    );
    assert_eq!(
        r.size_mismatch, 12,
        "the invalid files of keys with a row: {r:?}"
    );

    // Post-condition: every row has exactly one file, on its tier, and every .mp4 has a row.
    let rows = w.rows();
    let (hot_files, arch_files) = (segment_files(&w.hot), segment_files(&w.arch));
    for row in &rows {
        let p = RelPath::new(&row.record.camera, row.record.started_at_ms).to_string();
        let (own, other) = if row.tier == Tier::Hot {
            (&hot_files, &arch_files)
        } else {
            (&arch_files, &hot_files)
        };
        let f = own
            .get(&p)
            .unwrap_or_else(|| panic!("row {p} has no file on its tier"));
        assert_eq!(f.len() as u64, row.record.bytes, "{p}");
        assert!(!other.contains_key(&p), "{p} also on the other tier");
    }
    for p in hot_files.keys().chain(arch_files.keys()) {
        assert!(
            rows.iter()
                .any(|r| RelPath::new(&r.record.camera, r.record.started_at_ms).to_string() == *p),
            "{p} has no row"
        );
    }
    // No invalid file was destroyed: each one is in a quarantine.
    let mut q = quarantined(&w.hot);
    q.extend(quarantined(&w.arch));
    for c in &invalid_contents {
        assert!(q.contains(c), "an invalid file vanished");
    }
    assert!(q.contains(&diff_h));

    // A second start-up has nothing left to do.
    let mut lp = w.open(w.cfg(100_000));
    let r2 = lp.reconcile_startup().unwrap().report;
    assert_eq!(
        (
            r2.part_deleted,
            r2.rolled_forward,
            r2.rolled_back,
            r2.missing,
            r2.adopted,
            r2.quarantined,
            r2.size_mismatch,
            r2.duplicates_deleted,
            r2.unverified,
        ),
        (0, 0, 0, 0, 0, 0, 0, 0, 0),
        "{r2:?}"
    );
}

// ---- 2. names that are not UTF-8 are reported, not silently skipped ----------------------------------

#[test]
fn a_non_utf8_name_in_a_day_directory_is_reported_as_unknown_left() {
    let w = World::new();
    w.row(0, Tier::Hot, good(40).len() as u64);
    let p = w.put(Tier::Hot, 0, &good(40));
    let day = p.parent().unwrap();
    let odd = day.join(std::ffi::OsStr::from_bytes(b"\xff\xfe-not-utf8.mp4"));
    std::fs::write(&odd, b"owner's file").unwrap();
    let mut lp = w.open(w.cfg(100_000));
    let r = lp.reconcile_startup().unwrap().report;
    assert!(odd.exists(), "left in place");
    // ADR 0005 section 9: "Anything else is left in place and reported".
    assert_eq!(r.unknown_left, 1, "{r:?}");
}

#[test]
fn entries_with_non_utf8_names_count_against_the_walk_cap() {
    let w = World::new();
    // Three day directories, each with five entries whose names are not UTF-8.
    for d in 0..3_i64 {
        let p = w.put(Tier::Hot, d * 1440, &good(40));
        std::fs::remove_file(&p).unwrap();
        let day = p.parent().unwrap();
        for i in 0..5_u8 {
            std::fs::write(
                day.join(std::ffi::OsStr::from_bytes(&[0xff, b'a' + i])),
                b"x",
            )
            .unwrap();
        }
    }
    w.unmount();
    // Visible entries: 1 camera + 3 days = 4; with the 15 others the walk sees 19 entries.
    let mut lp = w.open(w.cfg(100_000).with_walk_max_entries(10));
    let r = lp.reconcile_startup().unwrap().report;
    assert!(
        r.walk_cap_exceeded,
        "19 entries were visited under a cap of 10: {r:?}"
    );
}

// ---- 3. a hot camera directory that can be traversed but not listed ------------------------------------

#[test]
fn an_unlistable_but_traversable_hot_camera_directory_adopts_nothing_and_drops_no_present_row() {
    let w = World::new();
    let len = good(40).len() as u64;
    let id_present = w.row(0, Tier::Hot, len);
    w.put(Tier::Hot, 0, &good(40));
    let orphan = w.put(Tier::Hot, 1, &good(40));
    // An archive twin of a hot row: both copies are observed directly, the cell applies.
    let id_twin = w.row(2, Tier::Hot, len);
    w.put(Tier::Hot, 2, &good(40));
    w.put(Tier::Archive, 2, &good(40));
    let cam_dir = w.hot.join(CAM);
    std::fs::set_permissions(&cam_dir, std::fs::Permissions::from_mode(0o300)).unwrap();
    let mut lp = w.open(w.cfg(100_000));
    let r = lp.reconcile_startup().unwrap().report;
    std::fs::set_permissions(&cam_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(r.hot_unverified, "{r:?}");
    assert!(
        orphan.exists(),
        "an unseen orphan is neither adopted nor deleted"
    );
    assert!(w.find(1).is_none());
    assert_eq!(w.index.get(id_present).unwrap().unwrap().tier, Tier::Hot);
    assert!(w.hot.join(rel(0)).exists());
    let twin = w.index.get(id_twin).unwrap().unwrap();
    assert_eq!(twin.tier, Tier::Archive, "rolled forward: {r:?}");
    assert!(w.arch.join(rel(2)).exists());
}

// ---- 4. the returned pass: scope ----------------------------------------------------------------------

#[test]
fn the_returned_pass_leaves_a_wrong_size_hot_file_of_a_hot_row_alone() {
    let w = World::new();
    let len = good(40).len() as u64;
    // Hot row whose hot file has the wrong size, no archive file anywhere for it.
    let id = w.row(0, Tier::Hot, len);
    w.put(Tier::Hot, 0, &good(99));
    // Another key in the same day in the archive, so the day is visited by the pass.
    let id_a = w.row(5, Tier::Archive, len);
    w.put(Tier::Archive, 5, &good(40));
    // Another hot row in a day the archive does not have, also wrong-size.
    let id_far = w.row(3 * 1440, Tier::Hot, len);
    w.put(Tier::Hot, 3 * 1440, &good(98));
    w.unmount();
    let mut lp = w.open(w.cfg(100_000));
    let s = lp.reconcile_startup().unwrap().report;
    assert!(s.archive_unavailable);
    // Start-up already quarantined the wrong-size hot files (hot, invalid) with the archive away;
    // put them back to model a hot file that changed after start-up.
    w.put(Tier::Hot, 0, &good(99));
    w.put(Tier::Hot, 3 * 1440, &good(98));
    let before = snapshot(&w.hot);
    w.mount();
    let r = lp.tick(Timestamp::from_unix_millis(T0 + 600_000)).unwrap();
    assert!(r.archive_returned, "{r:?}");
    let pass = r.returned.expect("the pass ran");
    assert_eq!(snapshot(&w.hot), before, "no hot file touched: {pass:?}");
    assert_eq!(w.index.get(id).unwrap().unwrap().tier, Tier::Hot);
    assert_eq!(w.index.get(id_far).unwrap().unwrap().tier, Tier::Hot);
    assert_eq!(w.index.get(id_a).unwrap().unwrap().tier, Tier::Archive);
}

#[test]
fn the_returned_pass_drops_hot_rows_whose_files_are_gone_in_visited_and_unvisited_days() {
    let w = World::new();
    let len = good(40).len() as u64;
    let near = w.row(0, Tier::Hot, len); // day with an archive directory
    let far = w.row(3 * 1440, Tier::Hot, len); // day without
    w.row(5, Tier::Archive, len);
    w.put(Tier::Archive, 5, &good(40));
    // Keep each hot day directory so only the files are missing.
    std::fs::create_dir_all(w.hot.join(rel(0)).parent().unwrap()).unwrap();
    std::fs::create_dir_all(w.hot.join(rel(3 * 1440)).parent().unwrap()).unwrap();
    w.unmount();
    let mut lp = w.open(w.cfg(100_000));
    let s = lp.reconcile_startup().unwrap().report;
    assert_eq!(
        s.missing, 0,
        "archive unavailable: hot rows without a file are unverified"
    );
    w.mount();
    let r = lp.tick(Timestamp::from_unix_millis(T0 + 600_000)).unwrap();
    let pass = r.returned.expect("the pass ran");
    assert_eq!(pass.missing, 2, "{pass:?}");
    assert!(w.index.get(near).unwrap().is_none());
    assert!(w.index.get(far).unwrap().is_none());
}

// ---- 5. multi-tick: a flapping archive while a recorder writes --------------------------------------

#[test]
fn a_flapping_archive_over_many_ticks_loses_no_row_and_no_file_and_never_touches_the_recorder() {
    let w = World::new();
    let len = good(40).len() as u64;
    // Archived history and some hot video.
    for n in 0..5 {
        w.row(n, Tier::Archive, len);
        w.put(Tier::Archive, n, &good(40));
    }
    for n in 10..13 {
        w.row(n, Tier::Hot, len);
        w.put(Tier::Hot, n, &good(40));
    }
    w.unmount();
    let mut lp = w.open(w.cfg(30));
    let s = lp.reconcile_startup().unwrap().report;
    assert!(s.archive_unavailable);
    let mut expected_rows = 8_usize;
    let mut mounted = false;
    let mut returns = 0;
    let mut moved = 0_u32;
    for t in 0..48_i64 {
        // Mount pattern: off, on, on, off, on, off, off, on ... (flaps, and multi-tick stays).
        let want = matches!(t % 7, 1 | 2 | 4) || t >= 40;
        if want != mounted {
            if want {
                w.mount();
            } else {
                w.unmount();
            }
        }
        let returning = want && !mounted;
        mounted = want;
        // The recorder: one finished segment (file then row), one mid-rename (file, no row yet),
        // and one mid-segment `.part`.
        let done = 100 + t;
        w.put(Tier::Hot, done, &good(40));
        w.row(done, Tier::Hot, len);
        expected_rows += 1;
        let mid = 2000 + t;
        let mid_path = w.put(Tier::Hot, mid, &good(41));
        let part = w.hot.join(format!("{}.part", rel(3000 + t)));
        std::fs::create_dir_all(part.parent().unwrap()).unwrap();
        std::fs::write(&part, b"writing").unwrap();
        let now = Timestamp::from_unix_millis(T0 + (200 + t) * 60_000);
        let r = lp.tick(now).unwrap();
        moved += r.moved;
        if returning {
            returns += 1;
            assert!(r.archive_returned, "tick {t}: {r:?}");
            assert!(r.returned.is_some(), "tick {t}: the pass ran");
            assert_eq!(r.moved, 0, "tick {t}: no move before the pass");
        } else {
            assert!(r.returned.is_none(), "tick {t}: {r:?}");
        }
        if let Some(p) = &r.returned {
            assert_eq!(
                (p.missing, p.quarantined, p.adopted, p.unverified),
                (0, 0, 0, 0),
                "tick {t}: {p:?}"
            );
        }
        // The recorder's files are untouched.
        assert_eq!(std::fs::read(&mid_path).unwrap(), good(41), "tick {t}");
        assert_eq!(std::fs::read(&part).unwrap(), b"writing", "tick {t}");
        // It finishes: the row of the renamed file, the `.part` renamed and indexed.
        w.row(mid, Tier::Hot, good(41).len() as u64);
        expected_rows += 1;
        let fin = w.hot.join(rel(3000 + t));
        std::fs::rename(&part, &fin).unwrap();
        w.row(3000 + t, Tier::Hot, 7);
        expected_rows += 1;

        // Invariants: no row lost, each row has its file on its tier (archive rows only checked
        // when the archive is mounted; it is never deleted from in this test).
        let rows = w.rows();
        assert_eq!(rows.len(), expected_rows, "tick {t}");
        for row in &rows {
            let p = RelPath::new(&row.record.camera, row.record.started_at_ms).to_string();
            let own = w.root(row.tier).join(&p);
            assert_eq!(
                std::fs::metadata(&own).map(|m| m.len()).ok(),
                Some(row.record.bytes),
                "tick {t}: {p} on {:?}",
                row.tier
            );
        }
    }
    assert!(
        returns >= 5,
        "the pattern returned the archive several times"
    );
    // In the end (mounted for the last ticks) everything old enough was moved.
    let r = lp
        .tick(Timestamp::from_unix_millis(T0 + 10_000 * 60_000))
        .unwrap();
    assert!(!r.archive_returned);
    moved += r.moved;
    assert!(moved > 0, "the flapping archive still received moves");
    assert!(quarantined(&w.hot).is_empty() && quarantined(&w.arch).is_empty());
}

// ---- 6. adoption bounds, end to end --------------------------------------------------------------------

#[test]
fn a_moov_of_exactly_one_mib_is_adopted_and_one_byte_more_is_quarantined() {
    let w = World::new();
    let ok = mp4_with(&moov_with_padding(Some(1024 * 1024)), 1, &[3000], 16);
    let big = mp4_with(&moov_with_padding(Some(1024 * 1024 + 1)), 1, &[3000], 16);
    w.put(Tier::Hot, 0, &ok);
    w.put(Tier::Hot, 1, &big);
    w.unmount();
    let mut lp = w.open(w.cfg(100_000));
    let r = lp.reconcile_startup().unwrap().report;
    assert_eq!((r.adopted, r.quarantined), (1, 1), "{r:?}");
    assert_eq!(w.find(0).unwrap().record.bytes, ok.len() as u64);
    assert!(w.find(1).is_none());
    assert_eq!(quarantined(&w.hot), vec![big]);
}

#[test]
fn one_hundred_thousand_fragments_are_adopted_and_one_more_is_quarantined() {
    let w = World::new();
    let ok = mp4_with(&moov_with_padding(None), 100_000, &[1], 0);
    let over = mp4_with(&moov_with_padding(None), 100_001, &[1], 0);
    w.put(Tier::Hot, 0, &ok);
    w.put(Tier::Hot, 1, &over);
    w.unmount();
    let mut lp = w.open(w.cfg(100_000));
    let r = lp.reconcile_startup().unwrap().report;
    assert_eq!((r.adopted, r.quarantined), (1, 1), "{r:?}");
    let row = w.find(0).unwrap();
    assert_eq!(row.record.frame_count, 100_000);
    // 100,000 ticks at 90 kHz = 1111.1 ms, rounded up.
    assert_eq!(row.record.duration_ms, 1112);
    assert!(w.find(1).is_none());
}

// ---- 7. FIFOs where directories are expected never block the walk ------------------------------------

fn mkfifo(p: &Path) {
    let st = std::process::Command::new("mkfifo")
        .arg(p)
        .status()
        .unwrap();
    assert!(st.success());
}

#[test]
fn fifos_in_place_of_camera_and_day_directories_and_parts_are_left_and_never_block() {
    let w = World::new();
    let len = good(40).len() as u64;
    // A row of a camera whose directory is a FIFO on the hot root.
    let fifo_cam = w.hot.join("cam-2");
    mkfifo(&fifo_cam);
    let rec = SegmentRecord::new("cam-2".parse().unwrap(), key(0), 100, len, 3);
    let id2 = w.index.clone().insert(&rec, Tier::Hot).unwrap();
    // A day directory that is a FIFO on the archive, with a hot row of that day.
    let id1 = w.row(0, Tier::Hot, len);
    w.put(Tier::Hot, 0, &good(40));
    let arch_day = w.arch.join(rel(0));
    let arch_day = arch_day.parent().unwrap();
    std::fs::create_dir_all(arch_day.parent().unwrap()).unwrap();
    mkfifo(arch_day);
    // A FIFO `.part` in the archive.
    let part = w.arch.join(format!("{}.part", rel(1440)));
    std::fs::create_dir_all(part.parent().unwrap()).unwrap();
    mkfifo(&part);
    let mut lp = w.open(w.cfg(100_000));
    let r = lp.reconcile_startup().unwrap().report;
    assert!(r.unknown_left >= 3, "{r:?}");
    assert!(fifo_cam.exists() && arch_day.exists() && part.exists());
    assert_eq!(
        w.index.get(id2).unwrap().map(|r| r.tier),
        Some(Tier::Hot),
        "no conclusion from a FIFO camera directory: {r:?}"
    );
    assert_eq!(
        w.index.get(id1).unwrap().map(|r| r.tier),
        Some(Tier::Hot),
        "{r:?}"
    );
    assert!(w.hot.join(rel(0)).exists());
}
