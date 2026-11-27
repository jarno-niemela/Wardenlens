//! Per-camera passthrough recorder (ticket #57, ADR 0005 sections 2 and 3).
//!
//! A [`Recorder`] takes the frames of one camera from a [`FrameSource`], lets the core
//! `Segmenter` cut them into segments, writes each segment as a fragmented MP4 with
//! `wardenlens-mp4` through a [`SegmentStore`], and indexes it through the core `SegmentIndex`
//! port. The crate depends on core, mp4 and fsutil only (ADR 0005 section 11); the frame type and
//! the B-slice check are in `wardenlens_core::video`, and the index adapter is wired by the
//! caller. There is no decoding and no re-encoding.
//!
//! The logic is generic over the two ports ([`SegmentStore`], `SegmentIndex`), so it is tested
//! without a disk and without SQLite; [`HotStore`] and `wardenlens_index::Index` are the real
//! ones. The composition root (`serve`, #68) opens the hot root once, builds the store, the
//! index and the recorder, and runs the recorder on a blocking thread, feeding it
//! [`ChannelSource`] from the ingest supervisor.
//!
//! # Close sequence
//!
//! A segment is written to `<hot>/<camera>/<day>/<name>.mp4.part` (mode `0600`, directories
//! `0700`). It is closed by: last fragment, `pwrite` of the duration into `mvhd` and `mehd`,
//! fsync, `renameat2(RENAME_NOREPLACE)` to `.mp4`, fsync of the directory, and only then
//! `Index::insert`. A visible `.mp4` is therefore always complete, and a row always points at a
//! durable file. At most one `.part` per camera exists at any time.
//!
//! # What holds recording off
//!
//! See [`HoldReason`]. Every hold is visible in [`RecorderHealth`] through the watch channel
//! returned by [`Recorder::new`]; nothing in it names a path or a camera address.

mod close;
mod config;
mod health;
mod hot;
mod keys;
mod pending;
mod probe;
mod recorder;
mod source;
mod state;
mod store;
mod write;

pub use config::RecorderConfig;
pub use health::{HoldReason, RecorderHealth, RecorderState};
pub use hot::{HotStore, HotWriter};
pub use recorder::{Recorder, RecorderError};
pub use source::{ChannelSource, FrameSource};
pub use store::{Sealed, SegmentStore, StoreError};
