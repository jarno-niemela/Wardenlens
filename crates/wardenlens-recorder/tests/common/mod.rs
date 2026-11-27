//! Shared test support: synthetic frames, a fake clock, a fault-injecting index and store.
//! Synthetic data only; nothing here touches a camera or the owner's configuration.

#![expect(
    dead_code,
    unreachable_pub,
    clippy::unwrap_used,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    reason = "test support: each test file uses a subset; a panic is a test failure; small synthetic values"
)]

use std::cell::Cell;
use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use wardenlens_core::camera::CameraId;
use wardenlens_core::recording::SegmentRecord;
use wardenlens_core::storage::{
    IndexedSegment, SegmentCursor, SegmentId, SegmentIndex, SegmentPage, StoredSegment, Tier,
    TierTotals,
};
use wardenlens_core::time::{Clock, DurationMs, Timestamp, UnixMs};
use wardenlens_fsutil::RootDir;
use wardenlens_index::{Index, IndexError};
use wardenlens_ingest::{Frame, FrameMapper, RawParams, RawVideoFrame};
use wardenlens_mp4::DurationPatch;

pub mod rig;
use wardenlens_recorder::{HotStore, HotWriter, Sealed, SegmentStore, StoreError};

/// A 16x16 baseline SPS and its PPS.
pub const SPS_A: [u8; 7] = [0x67, 0x42, 0xc0, 0x0a, 0xf8, 0x41, 0xa2];
pub const PPS: [u8; 4] = [0x68, 0xce, 0x38, 0x80];
/// A different SPS (another level), so a parameter change is visible.
pub const SPS_B: [u8; 7] = [0x67, 0x42, 0xc0, 0x14, 0xf8, 0x41, 0xa2];

/// 2023-11-14T22:13:20.000Z, the directory day is 2023-11-14.
pub const T0: i64 = 1_700_000_000_000;
pub const DAY: &str = "2023-11-14";

/// A temporary directory nobody else can write (tempfile follows the umask, and the index
/// refuses a group-writable parent).
pub fn private_tempdir() -> tempfile::TempDir {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    dir
}

pub fn cam() -> CameraId {
    CameraId::new("cam1").unwrap()
}

pub fn params(sps: &[u8]) -> RawParams {
    RawParams {
        sps: sps.to_vec(),
        pps: PPS.to_vec(),
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Slice {
    Idr,
    P,
    B,
    /// A non-IDR slice NAL unit with this `slice_type` (H.264 table 7-6).
    Type(u32),
    /// An access unit with a P slice NAL unit and then a B slice NAL unit.
    PThenB,
    /// An IDR slice NAL unit cut off after its header byte (no slice header).
    Cut,
}

/// AVCC bytes of one slice NAL unit, `total` bytes long including the 4-byte length prefix.
pub fn avcc(slice: Slice, total: usize) -> Vec<u8> {
    let (header, first) = match slice {
        Slice::Idr => (0x65, 0x88), // slice_type 7 (I)
        Slice::P => (0x41, 0xe0),   // slice_type 0 (P)
        Slice::B => (0x41, 0xa8),   // slice_type 1 (B)
        Slice::Type(t) => {
            // first_mb_in_slice = ue(0) = '1', then ue(t), then padding bits.
            let x = u64::from(t) + 1;
            let len = 64 - x.leading_zeros();
            let mut bits = vec![true];
            bits.extend(std::iter::repeat_n(
                false,
                usize::try_from(len - 1).unwrap(),
            ));
            for i in (0..len).rev() {
                bits.push((x >> i) & 1 == 1);
            }
            while bits.len() % 8 != 0 {
                bits.push(false);
            }
            let mut v = vec![0, 0, 0, 0, 0x41];
            v.extend(
                bits.chunks(8)
                    .map(|b| b.iter().fold(0u8, |a, x| a << 1 | u8::from(*x))),
            );
            let n = u32::try_from(v.len() - 4).unwrap();
            v[..4].copy_from_slice(&n.to_be_bytes());
            return v;
        }
        Slice::PThenB => {
            let mut v = avcc(Slice::P, 8);
            v.extend(avcc(Slice::B, total.max(8) - 8));
            return v;
        }
        Slice::Cut => return vec![0, 0, 0, 1, 0x65],
    };
    let nal_len = total.max(6) - 4;
    let mut v = u32::try_from(nal_len).unwrap().to_be_bytes().to_vec();
    v.push(header);
    v.push(first);
    v.resize(4 + nal_len, 0xaa);
    v
}

/// The fake wall clock, in milliseconds.
pub struct FakeClock(Cell<i64>);

impl FakeClock {
    pub fn new(ms: i64) -> Self {
        Self(Cell::new(ms))
    }

    pub fn advance(&self, ms: i64) {
        self.0.set(self.0.get() + ms);
    }

    pub fn set(&self, ms: i64) {
        self.0.set(ms);
    }
}

impl Clock for FakeClock {
    fn now(&self) -> Timestamp {
        Timestamp::from_unix_millis(self.0.get())
    }
}

/// What a frame is made of; the defaults are an ordinary P frame.
#[derive(Clone)]
pub struct Spec {
    pub slice: Slice,
    pub size: usize,
    pub rtp: u32,
    pub loss: u16,
    pub params: Option<RawParams>,
}

impl Spec {
    pub fn key(rtp: u32) -> Self {
        Self {
            slice: Slice::Idr,
            size: 400,
            rtp,
            loss: 0,
            params: None,
        }
    }

    pub fn p(rtp: u32) -> Self {
        Self {
            slice: Slice::P,
            ..Self::key(rtp)
        }
    }

    pub fn with_slice(mut self, s: Slice) -> Self {
        self.slice = s;
        self
    }

    pub fn with_size(mut self, n: usize) -> Self {
        self.size = n;
        self
    }

    pub fn with_loss(mut self) -> Self {
        self.loss = 1;
        self
    }

    pub fn with_params(mut self, p: RawParams) -> Self {
        self.params = Some(p);
        self
    }
}

/// Builds `Frame`s the way ingest does (through `FrameMapper`), stamped by the fake clock.
pub struct Feeder {
    pub clock: FakeClock,
    mapper: FrameMapper,
}

impl Feeder {
    pub fn new() -> Self {
        Self {
            clock: FakeClock::new(T0),
            mapper: FrameMapper::new(),
        }
    }

    /// The first frame of a session carries the parameter sets and is a discontinuity.
    pub fn frame(&mut self, spec: &Spec) -> Frame {
        let raw = RawVideoFrame {
            data: avcc(spec.slice, spec.size),
            is_random_access_point: spec.slice == Slice::Idr,
            rtp_timestamp: i64::from(spec.rtp),
            clock_rate: 90_000,
            loss: spec.loss,
            params: spec.params.clone(),
        };
        self.mapper.map(raw, self.clock.now()).unwrap().unwrap()
    }

    /// A new session: the next frame is a discontinuity again.
    pub fn reconnect(&mut self) {
        self.mapper = FrameMapper::new();
    }
}

/// `fps` frames per second for `secs` seconds, a keyframe every `gop` frames, the first frame
/// carrying the parameters. The clock advances 1000/fps ms before each frame.
pub fn stream(feeder: &mut Feeder, secs: u32, fps: u32, gop: u32) -> Vec<Frame> {
    let mut out = Vec::new();
    for i in 0..secs * fps {
        feeder.clock.advance(i64::from(1000 / fps));
        let rtp = i * (90_000 / fps);
        let mut spec = if i % gop == 0 {
            Spec::key(rtp)
        } else {
            Spec::p(rtp)
        };
        if i == 0 {
            spec = spec.with_params(params(&SPS_A));
        }
        out.push(feeder.frame(&spec));
    }
    out
}

// ---- the index with scripted failures ----

#[derive(Default)]
pub struct IndexScript {
    /// Errors returned by the next inserts, in order, before the real insert runs.
    pub insert_errors: VecDeque<IndexError>,
    /// Every insert fails with this (after the scripted ones), until it is cleared.
    pub insert_forever: Option<fn() -> IndexError>,
    /// Insert attempts seen, failed or not.
    pub attempts: u32,
    /// `latest_started_at` fails with this once.
    pub seed_error: Option<IndexError>,
    /// The next inserts really commit the row and then fail with these (a checkpoint error
    /// inside `COMMIT`: the row is durable, the caller sees an error).
    pub commit_then_error: VecDeque<IndexError>,
    /// As `commit_then_error`, but the committed row is another segment's (one byte more).
    pub other_row_then_error: VecDeque<IndexError>,
    /// `list` fails this many times.
    pub list_errors: u32,
}

pub type SharedScript = Arc<Mutex<IndexScript>>;

/// A real `Index` whose `insert` can be made to fail.
pub struct TestIndex {
    pub inner: Index,
    pub script: SharedScript,
}

impl TestIndex {
    pub fn open(dir: &Path) -> (Self, SharedScript) {
        let inner = Index::open(&dir.join("index.db")).unwrap();
        let script = SharedScript::default();
        (
            Self {
                inner,
                script: script.clone(),
            },
            script,
        )
    }
}

impl SegmentIndex for TestIndex {
    type Error = IndexError;

    fn insert(&mut self, record: &SegmentRecord, tier: Tier) -> Result<SegmentId, IndexError> {
        {
            let mut s = self.script.lock().unwrap();
            s.attempts += 1;
            if let Some(e) = s.insert_errors.pop_front() {
                return Err(e);
            }
            if let Some(make) = s.insert_forever {
                return Err(make());
            }
            if let Some(e) = s.other_row_then_error.pop_front() {
                drop(s);
                let other = SegmentRecord::new(
                    record.camera.clone(),
                    record.started_at_ms,
                    record.duration_ms,
                    record.bytes + 1,
                    record.frame_count,
                );
                self.inner.insert(&other, tier)?;
                return Err(e);
            }
            if let Some(e) = s.commit_then_error.pop_front() {
                drop(s);
                self.inner.insert(record, tier)?;
                return Err(e);
            }
        }
        self.inner.insert(record, tier)
    }

    fn get(&self, id: SegmentId) -> Result<Option<IndexedSegment>, IndexError> {
        self.inner.get(id)
    }

    fn list(
        &self,
        camera: &CameraId,
        from: Timestamp,
        to: Timestamp,
        limit: usize,
        cursor: Option<&SegmentCursor>,
    ) -> Result<SegmentPage, IndexError> {
        {
            let mut s = self.script.lock().unwrap();
            if s.list_errors > 0 {
                s.list_errors -= 1;
                return Err(IndexError::Busy { op: "list" });
            }
        }
        self.inner.list(camera, from, to, limit, cursor)
    }

    fn set_tier(&mut self, id: SegmentId, tier: Tier) -> Result<(), IndexError> {
        self.inner.set_tier(id, tier)
    }

    fn delete(&mut self, id: SegmentId) -> Result<(), IndexError> {
        self.inner.delete(id)
    }

    fn oldest(
        &self,
        tier: Tier,
        after: Option<(Timestamp, SegmentId)>,
        n: usize,
    ) -> Result<Vec<StoredSegment>, IndexError> {
        self.inner.oldest(tier, after, n)
    }

    fn newest(&self, tier: Tier) -> Result<Option<StoredSegment>, IndexError> {
        self.inner.newest(tier)
    }

    fn bytes_by_tier(&self) -> Result<TierTotals, IndexError> {
        self.inner.bytes_by_tier()
    }

    fn latest_started_at(&self, camera: &CameraId) -> Result<Option<UnixMs>, IndexError> {
        if let Some(e) = self.script.lock().unwrap().seed_error.take() {
            return Err(e);
        }
        self.inner.latest_started_at(camera)
    }
}

/// All rows of the camera, oldest first.
pub fn rows(index: &TestIndex) -> Vec<IndexedSegment> {
    let mut out = Vec::new();
    let mut cursor = None;
    loop {
        let page = index
            .list(
                &cam(),
                Timestamp::from_unix_millis(0),
                Timestamp::from_unix_millis(i64::MAX / 2),
                1000,
                cursor.as_ref(),
            )
            .unwrap();
        out.extend(page.items);
        match page.next {
            Some(c) => cursor = Some(c),
            None => return out,
        }
    }
}

// ---- the store with scripted failures ----

#[derive(Default)]
pub struct StoreScript {
    /// `create` fails with this once (`NoSpace` unless set).
    pub create_error: Option<StoreError>,
    /// Appends that succeed before the next append fails with `append_error`.
    pub appends_until_error: Option<u32>,
    pub append_error: Option<StoreError>,
    /// `commit` fails with this once.
    pub commit_error: Option<StoreError>,
    /// `commit` reports the directory fsync as failed (the file is kept).
    pub not_durable: bool,
    /// Once `appends_until_error` reaches 0, every append fails with `NoSpace` (a volume that
    /// cannot be freed, or a quota that `statvfs` does not show).
    pub appends_always_full: bool,
    /// What `available_bytes` reports.
    pub available: Option<u64>,
    pub creates: u32,
    pub aborts: u32,
    pub max_open: u32,
    pub open_now: u32,
    pub queries_available: u32,
}

pub type SharedStore = Arc<Mutex<StoreScript>>;

/// A real `HotStore` with scripted failures and an open-writer counter.
pub struct TestStore {
    pub inner: HotStore,
    pub script: SharedStore,
}

pub fn hot_root(dir: &Path) -> PathBuf {
    let p = dir.join("hot");
    std::fs::create_dir_all(&p).unwrap();
    p
}

impl TestStore {
    pub fn new(root: &Path) -> (Self, SharedStore) {
        let script = SharedStore::default();
        (
            Self {
                inner: HotStore::new(RootDir::open(root).unwrap(), cam()),
                script: script.clone(),
            },
            script,
        )
    }
}

impl SegmentStore for TestStore {
    type Writer = HotWriter;

    fn key_taken(&mut self, key: UnixMs) -> Result<bool, StoreError> {
        self.inner.key_taken(key)
    }

    fn create(&mut self, key: UnixMs, head: &[u8]) -> Result<HotWriter, StoreError> {
        {
            let mut s = self.script.lock().unwrap();
            s.creates += 1;
            if let Some(e) = s.create_error.take() {
                return Err(e);
            }
            s.open_now += 1;
            s.max_open = s.max_open.max(s.open_now);
        }
        let r = self.inner.create(key, head);
        if r.is_err() {
            self.script.lock().unwrap().open_now -= 1;
        }
        r
    }

    fn append(&mut self, writer: &mut HotWriter, bytes: &[u8]) -> Result<(), StoreError> {
        {
            let mut s = self.script.lock().unwrap();
            match s.appends_until_error {
                Some(0) if s.appends_always_full => return Err(StoreError::NoSpace),
                Some(0) => {
                    s.appends_until_error = None;
                    if let Some(e) = s.append_error.take() {
                        return Err(e);
                    }
                }
                Some(n) => s.appends_until_error = Some(n - 1),
                None => {}
            }
        }
        self.inner.append(writer, bytes)
    }

    fn commit(
        &mut self,
        writer: HotWriter,
        patch: &DurationPatch,
        row_holds: &mut dyn FnMut(UnixMs) -> Option<bool>,
    ) -> Result<Sealed, StoreError> {
        let err = self.script.lock().unwrap().commit_error.take();
        self.script.lock().unwrap().open_now -= 1;
        if let Some(e) = err {
            self.inner.abort(writer);
            return Err(e);
        }
        let mut sealed = self.inner.commit(writer, patch, row_holds)?;
        if self.script.lock().unwrap().not_durable {
            sealed.durable = false;
        }
        Ok(sealed)
    }

    fn abort(&mut self, writer: HotWriter) {
        let mut s = self.script.lock().unwrap();
        s.aborts += 1;
        s.open_now -= 1;
        drop(s);
        self.inner.abort(writer);
    }

    fn quarantine(&mut self, key: UnixMs) -> Result<(), StoreError> {
        self.inner.quarantine(key)
    }

    fn available_bytes(&mut self) -> Result<u64, StoreError> {
        let mut s = self.script.lock().unwrap();
        s.queries_available += 1;
        if let Some(n) = s.available {
            Ok(n)
        } else {
            drop(s);
            self.inner.available_bytes()
        }
    }
}

// ---- looking at the disk ----

/// Every file below `root` as a path relative to it, sorted.
pub fn tree(root: &Path) -> Vec<String> {
    fn walk(dir: &Path, base: &Path, out: &mut Vec<String>) {
        for e in std::fs::read_dir(dir).unwrap() {
            let e = e.unwrap();
            let p = e.path();
            if e.file_type().unwrap().is_dir() {
                walk(&p, base, out);
            } else {
                out.push(p.strip_prefix(base).unwrap().to_string_lossy().into_owned());
            }
        }
    }
    let mut out = Vec::new();
    walk(root, root, &mut out);
    out.sort();
    out
}

pub fn part_files(root: &Path) -> Vec<String> {
    tree(root)
        .into_iter()
        .filter(|n| n.rsplit('.').next() == Some("part"))
        .collect()
}

/// Durations written in the file: `mvhd` (v0, 32 bit) and `mehd` (v1, 64 bit), in ticks.
pub fn header_durations(file: &[u8]) -> (u64, u64) {
    let at = |tag: &[u8; 4]| file.windows(4).position(|w| w == tag).unwrap();
    let m = at(b"mvhd");
    // fourcc, version/flags 4, creation 4, modification 4, timescale 4, duration 4
    let mvhd = u32::from_be_bytes(file[m + 4 + 4 + 4 + 4 + 4..][..4].try_into().unwrap());
    let h = at(b"mehd");
    let mehd_ticks = u64::from_be_bytes(file[h + 4 + 4..][..8].try_into().unwrap());
    (u64::from(mvhd), mehd_ticks)
}

pub fn ms(v: i64) -> UnixMs {
    UnixMs::new(v).unwrap()
}

pub fn dur(v: u64) -> DurationMs {
    DurationMs::from_millis(v)
}
