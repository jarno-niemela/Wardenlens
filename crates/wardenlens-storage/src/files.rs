//! The core [`SegmentFiles`] port, implemented with the handles of the storage loop
//! (ADR 0005 sections 7 and 11), and the `core::mp4box` byte source over a `Read + Seek` handle.

use std::fs::File;
use std::io::{ErrorKind, Read, Seek, SeekFrom};
use std::sync::Arc;

use wardenlens_core::mp4box::{ByteSource, SourceError};
use wardenlens_core::storage::{
    IndexedSegment, OpenedSegment, SegmentFiles, SegmentId, SegmentIndex, SegmentOpenError, Tier,
};
use wardenlens_fsutil::{FsError, RootDir};

use crate::fs::ArchiveSlot;
use crate::index::{Rel, SharedIndex};

/// Opens segment files for the API by id. It holds no path, and a caller of the port gets none:
/// the path is derived from the row, the hot file is opened through the hot root handle and the
/// archive file only through the archive handle of the latest successful probe.
#[derive(Debug)]
pub struct StorageFiles<I> {
    index: SharedIndex<I>,
    hot: Arc<RootDir>,
    archive: Arc<ArchiveSlot>,
}

impl<I> Clone for StorageFiles<I> {
    fn clone(&self) -> Self {
        Self {
            index: self.index.clone(),
            hot: Arc::clone(&self.hot),
            archive: Arc::clone(&self.archive),
        }
    }
}

fn io_kind(e: &FsError) -> SegmentOpenError {
    let kind = match e {
        FsError::NotRegular => ErrorKind::InvalidData,
        other => other.errno().map_or(ErrorKind::Other, |n| {
            std::io::Error::from_raw_os_error(n.raw_os_error()).kind()
        }),
    };
    SegmentOpenError::Io { kind }
}

impl<I: SegmentIndex> StorageFiles<I> {
    pub(crate) fn new(index: SharedIndex<I>, hot: Arc<RootDir>, archive: Arc<ArchiveSlot>) -> Self {
        Self {
            index,
            hot,
            archive,
        }
    }

    fn row(&self, id: SegmentId) -> Result<IndexedSegment, SegmentOpenError> {
        match self.index.get(id) {
            Ok(Some(row)) => Ok(row),
            Ok(None) => Err(SegmentOpenError::NotFound),
            Err(_) => Err(SegmentOpenError::Io {
                kind: ErrorKind::Other,
            }),
        }
    }

    /// Open the file of the tier the row names. A missing file is `NotFound` here; only
    /// [`open_segment`](SegmentFiles::open_segment) knows whether that is final.
    fn open_tier(&self, row: &IndexedSegment) -> Result<OpenedSegment<File>, SegmentOpenError> {
        let rel = Rel::of(row).ok_or(SegmentOpenError::Io {
            kind: ErrorKind::InvalidData,
        })?;
        let root = match row.tier {
            Tier::Hot => Arc::clone(&self.hot),
            Tier::Archive => self
                .archive
                .get()
                .ok_or(SegmentOpenError::ArchiveUnavailable)?,
            _ => {
                return Err(SegmentOpenError::Io {
                    kind: ErrorKind::Unsupported,
                });
            }
        };
        match root.open_read(&rel.comps()) {
            Ok(r) => OpenedSegment::from_handle(r.file, row.tier),
            Err(e) if e.is_not_found() => Err(SegmentOpenError::NotFound),
            Err(e) => Err(io_kind(&e)),
        }
    }
}

impl<I: SegmentIndex + Send> SegmentFiles for StorageFiles<I> {
    type Handle = File;

    fn open_segment(&self, id: SegmentId) -> Result<OpenedSegment<File>, SegmentOpenError> {
        let row = self.row(id)?;
        match self.open_tier(&row) {
            Err(SegmentOpenError::NotFound) => {}
            other => return other,
        }
        // ENOENT: the move may have finished between the row read and the open. Re-read the row
        // once; open the other tier only if it changed; never loop.
        let again = self.row(id)?;
        if again.tier == row.tier {
            return Err(SegmentOpenError::NotFound);
        }
        self.open_tier(&again)
    }
}

/// A [`ByteSource`] over any `Read + Seek` handle, for the `core::mp4box` walk. The length is
/// measured once from the handle itself and the walk reads header by header; nothing is read
/// into memory beyond what the walk asks for.
#[derive(Debug)]
pub struct ReadSeekSource<R> {
    inner: R,
    len: u64,
}

impl<R: Read + Seek> ReadSeekSource<R> {
    /// Wrap `inner`, measuring its length by seeking to the end.
    ///
    /// # Errors
    /// The seek failure.
    pub fn new(mut inner: R) -> std::io::Result<Self> {
        let len = inner.seek(SeekFrom::End(0))?;
        Ok(Self { inner, len })
    }
}

impl<R: Read + Seek> ByteSource for ReadSeekSource<R> {
    fn byte_len(&self) -> u64 {
        self.len
    }

    fn read_exact_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<(), SourceError> {
        let end = offset
            .checked_add(u64::try_from(buf.len()).map_err(|_| SourceError)?)
            .ok_or(SourceError)?;
        if end > self.len {
            return Err(SourceError);
        }
        self.inner
            .seek(SeekFrom::Start(offset))
            .map_err(|_| SourceError)?;
        self.inner.read_exact(buf).map_err(|_| SourceError)
    }
}
