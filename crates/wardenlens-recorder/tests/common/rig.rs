//! A recorder over a real `HotStore` and a real `Index` in a temporary directory.

use std::path::{Path, PathBuf};
use std::time::Duration;

use tokio::sync::watch;
use wardenlens_core::recording::RelPath;
use wardenlens_recorder::{Recorder, RecorderConfig, RecorderHealth, RecorderState};

use super::*;

pub struct Rig {
    pub dir: tempfile::TempDir,
    pub root: PathBuf,
    pub rec: Recorder<TestStore, TestIndex>,
    pub health: watch::Receiver<RecorderHealth>,
    pub store: SharedStore,
    pub index: SharedScript,
    pub feeder: Feeder,
    pub i: u32,
}

pub fn fast() -> RecorderConfig {
    RecorderConfig::default().with_insert_retries(5, Duration::ZERO)
}

impl Rig {
    pub fn new() -> Self {
        Self::build(fast(), None, |_, _| {})
    }

    pub fn build(
        config: RecorderConfig,
        walk_max: Option<i64>,
        pre: impl FnOnce(&Path, &mut TestIndex),
    ) -> Self {
        let dir = private_tempdir();
        let root = hot_root(dir.path());
        let (mut index, index_script) = TestIndex::open(dir.path());
        pre(&root, &mut index);
        let (store, store_script) = TestStore::new(&root);
        let (rec, health) = Recorder::new(cam(), config, store, index, walk_max.map(ms)).unwrap();
        Self {
            dir,
            root,
            rec,
            health,
            store: store_script,
            index: index_script,
            feeder: Feeder::new(),
            i: 0,
        }
    }

    pub fn spec(&mut self, slice: Slice) -> Spec {
        let s = Spec::p(self.i * 9000).with_slice(slice);
        self.i += 1;
        s
    }

    /// The next frame, 100 ms after the previous one.
    pub fn feed(&mut self, slice: Slice) {
        let s = self.spec(slice);
        self.push(&s);
    }

    pub fn push(&mut self, spec: &Spec) {
        self.feeder.clock.advance(100);
        let f = self.feeder.frame(spec);
        self.rec.push_frame(f);
    }

    /// A first keyframe with the parameter sets.
    pub fn start(&mut self) {
        let s = self.spec(Slice::Idr).with_params(params(&SPS_A));
        self.push(&s);
    }

    pub fn gop(&mut self, n: u32) {
        self.feed(Slice::Idr);
        for _ in 1..n {
            self.feed(Slice::P);
        }
    }

    pub fn state(&self) -> RecorderState {
        self.health.borrow().state
    }

    pub fn health(&self) -> RecorderHealth {
        *self.health.borrow()
    }

    pub fn finish(self) -> Done {
        let end = self.rec.finish();
        let (index, _) = TestIndex::open(self.dir.path());
        Done {
            end,
            rows: rows(&index),
            root: self.root,
            _dir: self.dir,
        }
    }
}

pub struct Done {
    pub end: RecorderHealth,
    pub rows: Vec<wardenlens_core::storage::IndexedSegment>,
    pub root: PathBuf,
    pub _dir: tempfile::TempDir,
}

impl Done {
    pub fn frames(&self) -> Vec<u64> {
        self.rows.iter().map(|r| r.record.frame_count).collect()
    }

    pub fn durations(&self) -> Vec<u64> {
        self.rows.iter().map(|r| r.record.duration_ms).collect()
    }

    pub fn file(&self, i: usize) -> Vec<u8> {
        let r = &self.rows[i].record;
        std::fs::read(
            self.root
                .join(RelPath::new(&r.camera, r.started_at_ms).to_string()),
        )
        .unwrap()
    }
}

pub fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}
