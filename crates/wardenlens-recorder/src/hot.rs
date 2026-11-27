//! [`HotStore`]: [`SegmentStore`] on the hot root, through one directory handle opened at
//! start-up. Every path is a `RelPath` of a validated camera id and a bounded time (SEC-4) and is
//! opened with `openat2` `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS` through that handle.

use std::fs::File;
use std::os::unix::fs::FileExt;

use wardenlens_core::camera::CameraId;
use wardenlens_core::recording::RelPath;
use wardenlens_core::time::UnixMs;
use wardenlens_fsutil::{FsError, RootDir, quarantine};
use wardenlens_mp4::DurationPatch;

use crate::store::{SegmentStore, StoreError};

const PART_SUFFIX: &str = ".part";

/// The three components of a segment's path below the hot root.
struct Names {
    camera: String,
    day: String,
    file: String,
}

impl Names {
    fn new(camera: &CameraId, key: UnixMs) -> Result<Self, StoreError> {
        let text = RelPath::new(camera, key).to_string();
        let mut parts = text.split('/');
        match (parts.next(), parts.next(), parts.next(), parts.next()) {
            (Some(c), Some(d), Some(f), None) => Ok(Self {
                camera: c.to_owned(),
                day: d.to_owned(),
                file: f.to_owned(),
            }),
            _ => Err(StoreError::Fs(FsError::InvalidComponent)),
        }
    }

    fn part(&self) -> String {
        format!("{}{PART_SUFFIX}", self.file)
    }
}

/// An open `.part` file and the directory it lives in.
#[derive(Debug)]
pub struct HotWriter {
    file: File,
    dir: RootDir,
    part: String,
    name: String,
}

/// The hot tier of one camera.
#[derive(Debug)]
pub struct HotStore {
    root: RootDir,
    camera: CameraId,
}

impl HotStore {
    /// A store for `camera` under `root`, the hot root handle opened once at start-up.
    #[must_use]
    pub fn new(root: RootDir, camera: CameraId) -> Self {
        Self { root, camera }
    }

    /// Opens `name` below `parent`, creating it (mode `0700`) and fsyncing `parent` when it is new.
    fn ensure_dir(parent: &RootDir, name: &str) -> Result<RootDir, StoreError> {
        match parent.open_dir(&[name]) {
            Ok(d) => return Ok(d),
            Err(e) if e.is_not_found() => {}
            Err(e) => return Err(StoreError::from_fs(e)),
        }
        match parent.mkdir(name) {
            Ok(()) => {}
            // Another creator won the race; the directory is there.
            Err(e) if e.errno() == Some(rustix::io::Errno::EXIST) => {}
            Err(e) => return Err(StoreError::from_fs(e)),
        }
        parent.sync().map_err(StoreError::from_fs)?;
        parent.open_dir(&[name]).map_err(StoreError::from_fs)
    }

    fn day_dir(&self, names: &Names) -> Result<RootDir, StoreError> {
        let cam = Self::ensure_dir(&self.root, &names.camera)?;
        Self::ensure_dir(&cam, &names.day)
    }

    /// The day directory if it exists, `None` on ENOENT.
    fn existing_day_dir(&self, names: &Names) -> Result<Option<RootDir>, StoreError> {
        match self.root.open_dir(&[&names.camera, &names.day]) {
            Ok(d) => Ok(Some(d)),
            Err(e) if e.is_not_found() => Ok(None),
            Err(e) => Err(StoreError::from_fs(e)),
        }
    }

    /// Whether `file` exists in `dir`. Anything that is there counts as taken, a symlink (which
    /// `RESOLVE_NO_SYMLINKS` refuses with `ELOOP`) or a FIFO included; any other error than
    /// ENOENT is an error (the key is never assumed free).
    fn exists(dir: &RootDir, file: &str) -> Result<bool, StoreError> {
        match dir.open_read(&[file]) {
            Ok(_) | Err(FsError::NotRegular) => Ok(true),
            Err(e) if e.errno() == Some(rustix::io::Errno::LOOP) => Ok(true),
            Err(e) if e.is_not_found() => Ok(false),
            Err(e) => Err(StoreError::from_fs(e)),
        }
    }
}

impl SegmentStore for HotStore {
    type Writer = HotWriter;

    fn key_taken(&mut self, key: UnixMs) -> Result<bool, StoreError> {
        let names = Names::new(&self.camera, key)?;
        let Some(dir) = self.existing_day_dir(&names)? else {
            return Ok(false);
        };
        Ok(Self::exists(&dir, &names.file)? || Self::exists(&dir, &names.part())?)
    }

    fn create(&mut self, key: UnixMs, head: &[u8]) -> Result<HotWriter, StoreError> {
        let names = Names::new(&self.camera, key)?;
        let dir = self.day_dir(&names)?;
        let part = names.part();
        let file = dir.create_new(&part).map_err(StoreError::from_fs)?;
        let mut writer = HotWriter {
            file,
            dir,
            part,
            name: names.file,
        };
        if let Err(e) = self.append(&mut writer, head) {
            self.abort(writer);
            return Err(e);
        }
        Ok(writer)
    }

    fn append(&mut self, writer: &mut HotWriter, bytes: &[u8]) -> Result<(), StoreError> {
        use std::io::Write;
        writer
            .file
            .write_all(bytes)
            .map_err(|e| StoreError::from_io("write", &e))
    }

    fn commit(&mut self, writer: HotWriter, patch: &DurationPatch) -> Result<u64, StoreError> {
        let result = seal(&writer, patch);
        if result.is_err() {
            self.abort(writer);
        }
        result
    }

    fn abort(&mut self, writer: HotWriter) {
        // Best effort: the caller already has the error that matters. A file that cannot be
        // removed is a `.part` that reconciliation deletes at the next start (ADR 0005 section 9).
        let HotWriter {
            file, dir, part, ..
        } = writer;
        drop(file);
        let _ = dir.unlink(&part);
    }

    fn quarantine(&mut self, key: UnixMs) -> Result<(), StoreError> {
        let names = Names::new(&self.camera, key)?;
        quarantine(&self.root, &[&names.camera, &names.day, &names.file])
            .map(|_| ())
            .map_err(StoreError::from_fs)
    }

    fn available_bytes(&mut self) -> Result<u64, StoreError> {
        let v = self.root.statvfs().map_err(StoreError::from_fs)?;
        Ok(v.blocks_available.saturating_mul(v.block_size))
    }
}

/// Steps 2 to 5 of the close sequence (ADR 0005 section 3), on the open `.part`.
fn seal(w: &HotWriter, patch: &DurationPatch) -> Result<u64, StoreError> {
    let io = |op| move |e: std::io::Error| StoreError::from_io(op, &e);
    w.file
        .write_all_at(&patch.mvhd_value, patch.mvhd_offset)
        .map_err(io("patch mvhd"))?;
    w.file
        .write_all_at(&patch.mehd_value, patch.mehd_offset)
        .map_err(io("patch mehd"))?;
    w.file.sync_all().map_err(io("fsync file"))?;
    let len = w.file.metadata().map_err(io("fstat"))?.len();
    w.dir
        .rename_noreplace(&w.part, &w.dir, &w.name)
        .map_err(StoreError::from_fs)?;
    if let Err(e) = w.dir.sync() {
        // Not durable, so not indexed: take the finished name away again (best effort).
        let _ = w.dir.unlink(&w.name);
        return Err(StoreError::from_fs(e));
    }
    Ok(len)
}
