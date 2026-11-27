//! [`HotStore`]: [`SegmentStore`] on the hot root, through one directory handle opened at
//! start-up. Every path is a `RelPath` of a validated camera id and a bounded time (SEC-4) and is
//! opened with `openat2` `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS` through that handle.

use std::fs::File;
use std::os::unix::fs::FileExt;

use wardenlens_core::camera::CameraId;
use wardenlens_core::recording::RelPath;
use wardenlens_core::time::UnixMs;
use wardenlens_fsutil::{FsError, QuarantineOutcome, RootDir, quarantine};
use wardenlens_mp4::DurationPatch;

use crate::store::{Sealed, SegmentStore, StoreError};

const PART_SUFFIX: &str = ".part";
/// How many keys `commit` tries when another file appeared at the final name.
const RENAME_TRIES: u32 = 8;

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
    key: UnixMs,
    /// The day directory name, to stay in it when the key is bumped.
    day: String,
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
}

impl HotStore {
    /// A sealed `.part` that found no free name: moved into `_quarantine` (the file is real
    /// video). When even that fails the `.part` is left where it is, never unlinked.
    fn keep_unnamed(&mut self, writer: HotWriter) -> Result<Sealed, StoreError> {
        let HotWriter {
            file,
            dir: _dir,
            part,
            day,
            ..
        } = writer;
        drop(file);
        match quarantine(
            &self.root,
            &[self.camera.as_str(), day.as_str(), part.as_str()],
        ) {
            Ok(QuarantineOutcome::Moved { .. }) => Err(StoreError::NoFreeName),
            Ok(_) => Err(StoreError::QuarantineExhausted),
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
        // `O_PATH`: a device node or FIFO planted at the name is never opened, and a file without
        // read permission is still found.
        Ok(dir.exists(&names.file).map_err(StoreError::from_fs)?
            || dir.exists(&names.part()).map_err(StoreError::from_fs)?)
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
            key,
            day: names.day,
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

    fn commit(
        &mut self,
        writer: HotWriter,
        patch: &DurationPatch,
        row_holds: &mut dyn FnMut(UnixMs) -> Option<bool>,
    ) -> Result<Sealed, StoreError> {
        let result = seal(&writer, &self.camera, patch, RootDir::sync, row_holds);
        match result {
            // The file is finished and fsynced but no key was free: keep it (#195).
            Err(StoreError::NameTaken) => self.keep_unnamed(writer),
            Err(e) => {
                self.abort(writer);
                Err(e)
            }
            ok => ok,
        }
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
        match quarantine(&self.root, &[&names.camera, &names.day, &names.file]) {
            Ok(QuarantineOutcome::Exhausted) => Err(StoreError::QuarantineExhausted),
            Ok(_) => Ok(()),
            Err(e) => Err(StoreError::from_fs(e)),
        }
    }

    fn available_bytes(&mut self) -> Result<u64, StoreError> {
        let v = self.root.statvfs().map_err(StoreError::from_fs)?;
        Ok(v.blocks_available.saturating_mul(v.block_size))
    }
}

/// Steps 2 to 5 of the close sequence (ADR 0005 section 3), on the open `.part`.
///
/// The rename never replaces: when a file appeared at the final name meanwhile, the next keys
/// are tried (within the same day directory, at most [`RENAME_TRIES`]). A bumped key that
/// `row_holds` says an index row holds is skipped without a rename: the file is never finished
/// under another segment's key (#195). A failed directory fsync keeps the finished file and says
/// so in [`Sealed::durable`]. `sync_dir` is a parameter so a test can make it fail.
fn seal(
    w: &HotWriter,
    camera: &CameraId,
    patch: &DurationPatch,
    sync_dir: fn(&RootDir) -> Result<(), FsError>,
    row_holds: &mut dyn FnMut(UnixMs) -> Option<bool>,
) -> Result<Sealed, StoreError> {
    let io = |op| move |e: std::io::Error| StoreError::from_io(op, &e);
    w.file
        .write_all_at(&patch.mvhd_value, patch.mvhd_offset)
        .map_err(io("patch mvhd"))?;
    w.file
        .write_all_at(&patch.mehd_value, patch.mehd_offset)
        .map_err(io("patch mehd"))?;
    w.file.sync_all().map_err(io("fsync file"))?;
    let len = w.file.metadata().map_err(io("fstat"))?.len();
    let mut key = w.key;
    let mut key_checked = true;
    for _ in 0..RENAME_TRIES {
        let names = Names::new(camera, key)?;
        if names.day != w.day {
            break; // the bumped key crossed midnight: another directory, not handled here
        }
        // The key chosen at `create` was probed against the index then; a bumped one was not.
        let held = if key == w.key {
            false
        } else {
            row_holds(key).unwrap_or_else(|| {
                key_checked = false;
                false
            })
        };
        if !held {
            match w.dir.rename_noreplace(&w.part, &w.dir, &names.file) {
                Ok(()) => {
                    let durable = sync_dir(&w.dir).is_ok();
                    return Ok(Sealed {
                        key,
                        len,
                        durable,
                        key_checked,
                    });
                }
                Err(e) if e.errno() == Some(rustix::io::Errno::EXIST) => {}
                Err(e) => return Err(StoreError::from_fs(e)),
            }
        }
        key = key
            .as_i64()
            .checked_add(1)
            .and_then(|ms| UnixMs::new(ms).ok())
            .ok_or(StoreError::NameTaken)?;
    }
    Err(StoreError::NameTaken)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: i64 = 1_700_000_000_000;

    fn camera() -> CameraId {
        CameraId::new("cam1").unwrap()
    }

    fn patch() -> DurationPatch {
        let init = wardenlens_mp4::init_segment(
            &wardenlens_mp4::H264Params::new(
                &[0x67, 0x42, 0xc0, 0x0a, 0xf8, 0x41, 0xa2],
                &[0x68, 0xce, 0x38, 0x80],
            )
            .unwrap(),
        )
        .unwrap();
        init.duration_patch(90_000).unwrap()
    }

    fn written(root: &std::path::Path, key: i64) -> (HotStore, HotWriter) {
        let mut store = HotStore::new(RootDir::open(root).unwrap(), camera());
        let init = wardenlens_mp4::init_segment(
            &wardenlens_mp4::H264Params::new(
                &[0x67, 0x42, 0xc0, 0x0a, 0xf8, 0x41, 0xa2],
                &[0x68, 0xce, 0x38, 0x80],
            )
            .unwrap(),
        )
        .unwrap();
        let w = store
            .create(UnixMs::new(key).unwrap(), init.bytes())
            .unwrap();
        (store, w)
    }

    fn files(root: &std::path::Path) -> Vec<String> {
        let day = root.join("cam1").join("2023-11-14");
        let mut v: Vec<String> = std::fs::read_dir(day)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        v.sort();
        v
    }

    #[test]
    fn a_failed_directory_fsync_keeps_the_finished_file_and_says_it_is_not_durable() {
        let d = tempfile::tempdir().unwrap();
        let (_store, w) = written(d.path(), KEY);
        let failing = |_: &RootDir| {
            Err(FsError::Io {
                op: "fsync dir",
                source: rustix::io::Errno::IO,
            })
        };
        let sealed = seal(&w, &camera(), &patch(), failing, &mut |_| Some(false)).unwrap();
        assert!(!sealed.durable);
        assert_eq!(sealed.key, UnixMs::new(KEY).unwrap());
        assert_eq!(files(d.path()), ["221320-000.mp4"]);
        assert_eq!(
            std::fs::metadata(d.path().join("cam1/2023-11-14/221320-000.mp4"))
                .unwrap()
                .len(),
            sealed.len
        );
    }

    #[test]
    fn a_synced_directory_is_durable() {
        let d = tempfile::tempdir().unwrap();
        let (_store, w) = written(d.path(), KEY);
        let sealed = seal(&w, &camera(), &patch(), RootDir::sync, &mut |_| Some(false)).unwrap();
        assert!(sealed.durable);
    }

    #[test]
    fn a_file_that_appeared_at_the_final_name_is_skipped_not_replaced() {
        let d = tempfile::tempdir().unwrap();
        let (_store, w) = written(d.path(), KEY);
        let day = d.path().join("cam1/2023-11-14");
        std::fs::write(day.join("221320-000.mp4"), b"foreign").unwrap();
        std::fs::write(day.join("221320-001.mp4"), b"foreign").unwrap();
        let sealed = seal(&w, &camera(), &patch(), RootDir::sync, &mut |_| Some(false)).unwrap();
        assert_eq!(sealed.key, UnixMs::new(KEY + 2).unwrap());
        assert_eq!(
            std::fs::read(day.join("221320-000.mp4")).unwrap(),
            b"foreign"
        );
        assert_eq!(
            std::fs::read(day.join("221320-001.mp4")).unwrap(),
            b"foreign"
        );
        assert_eq!(
            files(d.path()),
            ["221320-000.mp4", "221320-001.mp4", "221320-002.mp4"]
        );
    }

    #[test]
    fn running_out_of_free_names_keeps_the_finished_file_in_quarantine() {
        let d = tempfile::tempdir().unwrap();
        let (mut store, w) = written(d.path(), KEY);
        let day = d.path().join("cam1/2023-11-14");
        for n in 0..RENAME_TRIES {
            std::fs::write(day.join(format!("221320-{n:03}.mp4")), b"foreign").unwrap();
        }
        let e = store.commit(w, &patch(), &mut |_| Some(false)).unwrap_err();
        assert!(matches!(e, StoreError::NoFreeName));
        // The sealed recording is kept, not unlinked: it left the day directory for quarantine.
        assert!(files(d.path()).iter().all(|f| !f.contains(".part")));
        let q = d.path().join("_quarantine/cam1/2023-11-14");
        let kept: Vec<_> = std::fs::read_dir(q).unwrap().collect();
        assert_eq!(kept.len(), 1);
        let bytes = std::fs::read(kept[0].as_ref().unwrap().path()).unwrap();
        assert!(
            bytes.windows(4).any(|w| w == b"moov"),
            "the whole file, not a stub"
        );
    }

    /// A key the index cannot answer for is used, not skipped, and says it is unchecked.
    #[test]
    fn an_unanswered_key_is_used_and_reported_unchecked() {
        let d = tempfile::tempdir().unwrap();
        let (_store, w) = written(d.path(), KEY);
        std::fs::write(d.path().join("cam1/2023-11-14/221320-000.mp4"), b"foreign").unwrap();
        let sealed = seal(&w, &camera(), &patch(), RootDir::sync, &mut |_| None).unwrap();
        assert_eq!(sealed.key, UnixMs::new(KEY + 1).unwrap());
        assert!(!sealed.key_checked);
    }

    /// The index is asked for the bumped keys only (the first key was probed at `create`), a held
    /// key gets no rename, and the file lands on the first key that is free of file and row.
    #[test]
    fn a_bumped_key_a_row_holds_is_skipped_without_a_rename() {
        let d = tempfile::tempdir().unwrap();
        let (_store, w) = written(d.path(), KEY);
        let day = d.path().join("cam1/2023-11-14");
        std::fs::write(day.join("221320-000.mp4"), b"foreign").unwrap();
        let mut asked = Vec::new();
        let mut holds = |k: UnixMs| {
            asked.push(k.as_i64() - KEY);
            Some(k.as_i64() == KEY + 1 || k.as_i64() == KEY + 2)
        };
        let sealed = seal(&w, &camera(), &patch(), RootDir::sync, &mut holds).unwrap();
        assert_eq!(sealed.key, UnixMs::new(KEY + 3).unwrap());
        assert_eq!(
            asked,
            [1, 2, 3],
            "never asked about the key given at create"
        );
        assert_eq!(files(d.path()), ["221320-000.mp4", "221320-003.mp4"]);
    }

    #[test]
    fn a_free_first_key_never_asks_the_index() {
        let d = tempfile::tempdir().unwrap();
        let (_store, w) = written(d.path(), KEY);
        let mut holds = |_: UnixMs| -> Option<bool> { panic!("asked") };
        let sealed = seal(&w, &camera(), &patch(), RootDir::sync, &mut holds).unwrap();
        assert_eq!(sealed.key, UnixMs::new(KEY).unwrap());
    }

    #[test]
    fn a_bumped_key_never_leaves_the_day_directory() {
        let d = tempfile::tempdir().unwrap();
        // 23:59:59.999 UTC on 2023-11-14; the next key is in the next day.
        let key = 1_700_006_399_999;
        let (_store, w) = written(d.path(), key);
        std::fs::write(d.path().join("cam1/2023-11-14/235959-999.mp4"), b"foreign").unwrap();
        let e = seal(&w, &camera(), &patch(), RootDir::sync, &mut |_| Some(false)).unwrap_err();
        assert!(matches!(e, StoreError::NameTaken));
    }
}
