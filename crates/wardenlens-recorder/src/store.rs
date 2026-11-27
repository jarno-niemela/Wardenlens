//! The file side of the recorder as a port, so the recorder logic is tested without a disk.

use rustix::io::Errno;
use wardenlens_core::time::UnixMs;
use wardenlens_fsutil::FsError;
use wardenlens_mp4::DurationPatch;

/// A failed file operation. No variant carries a path (paths name cameras and times).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StoreError {
    /// The volume is full (`ENOSPC`) or the quota is used up (`EDQUOT`).
    #[error("no space left on the hot volume")]
    NoSpace,
    /// A file with the segment's name already exists.
    #[error("a file with this name already exists")]
    NameTaken,
    /// Sealed (fsynced) but no free key: every key tried was taken by a file or an index row. The
    /// finished file was kept: moved into the hot quarantine, or renamed in place to
    /// `<name>.mp4.unsealed` when that failed. Never deleted (#195).
    #[error("no free name for the finished segment; it was kept")]
    NoFreeName,
    /// Every quarantine name is taken: the file was left where it is.
    #[error("every quarantine name is taken")]
    QuarantineExhausted,
    /// A path-confined file operation failed.
    #[error("file operation failed: {0}")]
    Fs(FsError),
    /// A plain I/O call on an open segment failed.
    #[error("{op} failed: {kind}")]
    Io {
        /// What was being done.
        op: &'static str,
        /// The error kind.
        kind: std::io::ErrorKind,
    },
}

impl StoreError {
    /// Classifies a raw errno: full volume, name taken, or neither.
    fn from_errno(errno: Errno) -> Option<Self> {
        match errno {
            Errno::NOSPC | Errno::DQUOT => Some(Self::NoSpace),
            Errno::EXIST => Some(Self::NameTaken),
            _ => None,
        }
    }

    /// Maps an `fsutil` error, recognising "volume full" and "name taken".
    #[must_use]
    pub fn from_fs(e: FsError) -> Self {
        e.errno().and_then(Self::from_errno).unwrap_or(Self::Fs(e))
    }

    /// Maps an `std::io::Error` from a call on an open file.
    #[must_use]
    pub fn from_io(op: &'static str, e: &std::io::Error) -> Self {
        e.raw_os_error()
            .and_then(|n| Self::from_errno(Errno::from_raw_os_error(n)))
            .unwrap_or(Self::Io { op, kind: e.kind() })
    }
}

/// A closed segment file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Sealed {
    /// The key the file was finished under: the key given at `create`, or a later one when
    /// another file appeared at the final name meanwhile.
    pub key: UnixMs,
    /// The length of the finished file.
    pub len: u64,
    /// Whether the directory fsync after the rename succeeded. A file that is not durable is
    /// complete and visible but may vanish in a crash, so it is not indexed.
    pub durable: bool,
    /// Whether the index answered for every bumped key tried (so none is a row's key). When it
    /// could not, the file is complete and visible but its key is unchecked: it is not indexed
    /// and reconciliation judges it (it never deletes a file that is not a byte-identical twin).
    pub key_checked: bool,
}

/// Reads and writes the segment files of one camera on the hot volume (ADR 0005 section 3).
///
/// At most one writer is open at a time (the caller's duty), so a crash leaves at most one
/// `.part` per camera.
pub trait SegmentStore {
    /// An open `.part` file.
    type Writer;

    /// Whether a file (finished or `.part`) with the name of `key` exists.
    ///
    /// # Errors
    /// Anything but "not found" that stops the answer (the key is then not assumed free).
    fn key_taken(&mut self, key: UnixMs) -> Result<bool, StoreError>;

    /// Creates the camera and day directories (mode `0700`, parents fsynced) and the `.part` file
    /// (mode `0600`, never an existing name) and writes `head` (`ftyp` + `moov`) to it.
    ///
    /// # Errors
    /// [`StoreError::NameTaken`] when the name exists, [`StoreError::NoSpace`], or another failure.
    /// No `.part` is left behind on failure.
    fn create(&mut self, key: UnixMs, head: &[u8]) -> Result<Self::Writer, StoreError>;

    /// Appends `bytes` to the file.
    ///
    /// # Errors
    /// [`StoreError::NoSpace`] or another write failure; the caller then aborts the segment.
    fn append(&mut self, writer: &mut Self::Writer, bytes: &[u8]) -> Result<(), StoreError>;

    /// Closes the segment: patches the duration in `mvhd` and `mehd` with `pwrite`, fsyncs the
    /// file, renames `.part` to `.mp4` with `RENAME_NOREPLACE` (at the next free key when another
    /// file appeared at the name), and fsyncs the directory.
    ///
    /// `row_holds` says whether an index row holds a key: `Some(true)` it does, `Some(false)` it
    /// does not, `None` the index could not answer. It is asked for every key after the one given
    /// at `create` (a bump), and a key a row holds is skipped: a finished file is never put under
    /// another segment's key. On `None` the key is used (the finished recording is never thrown
    /// away for a question that was not answered) and [`Sealed::key_checked`] is false.
    ///
    /// When no key is free the sealed file is moved to quarantine and
    /// [`StoreError::NoFreeName`] is returned: a finished recording is never deleted.
    ///
    /// A failed directory fsync is not an error: the finished file is kept (it is complete and
    /// is adopted by reconciliation, ADR 0005 section 9) and [`Sealed::durable`] is false.
    ///
    /// # Errors
    /// A step before the rename failing, or no free name. The `.part` is removed then (best
    /// effort); no `.mp4` was created.
    fn commit(
        &mut self,
        writer: Self::Writer,
        patch: &DurationPatch,
        row_holds: &mut dyn FnMut(UnixMs) -> Option<bool>,
    ) -> Result<Sealed, StoreError>;

    /// Throws the segment away: removes the `.part`. Best effort.
    fn abort(&mut self, writer: Self::Writer);

    /// Moves the finished file of `key` to quarantine (ADR 0005 section 9).
    ///
    /// # Errors
    /// The move failed or every quarantine name is taken
    /// ([`StoreError::QuarantineExhausted`]); the file stays where it is.
    fn quarantine(&mut self, key: UnixMs) -> Result<(), StoreError>;

    /// Bytes available to the recorder on the volume.
    ///
    /// # Errors
    /// The volume could not be queried.
    fn available_bytes(&mut self) -> Result<u64, StoreError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn io(errno: Errno) -> std::io::Error {
        std::io::Error::from_raw_os_error(errno.raw_os_error())
    }

    #[test]
    fn a_full_volume_and_a_quota_are_no_space_from_a_file_or_a_path_operation() {
        for e in [Errno::NOSPC, Errno::DQUOT] {
            assert!(matches!(
                StoreError::from_io("write", &io(e)),
                StoreError::NoSpace
            ));
            let fs = FsError::Io {
                op: "mkdir",
                source: e,
            };
            assert!(matches!(StoreError::from_fs(fs), StoreError::NoSpace));
        }
    }

    #[test]
    fn an_existing_name_is_name_taken() {
        assert!(matches!(
            StoreError::from_io("write", &io(Errno::EXIST)),
            StoreError::NameTaken
        ));
        let fs = FsError::Io {
            op: "create file",
            source: Errno::EXIST,
        };
        assert!(matches!(StoreError::from_fs(fs), StoreError::NameTaken));
    }

    #[test]
    fn other_failures_keep_their_kind_and_are_not_mistaken_for_a_full_volume() {
        for e in [
            Errno::IO,
            Errno::ACCESS,
            Errno::ROFS,
            Errno::FBIG,
            Errno::NOENT,
        ] {
            assert!(matches!(
                StoreError::from_io("write", &io(e)),
                StoreError::Io { .. }
            ));
            let fs = FsError::Io { op: "x", source: e };
            assert!(matches!(StoreError::from_fs(fs), StoreError::Fs(_)));
        }
        assert!(matches!(
            StoreError::from_fs(FsError::InvalidComponent),
            StoreError::Fs(FsError::InvalidComponent)
        ));
        let e = std::io::Error::other("no errno");
        assert!(matches!(
            StoreError::from_io("fsync", &e),
            StoreError::Io { op: "fsync", .. }
        ));
    }

    #[test]
    fn no_message_carries_a_path() {
        for e in [
            StoreError::NoSpace,
            StoreError::NameTaken,
            StoreError::Fs(FsError::NotRegular),
            StoreError::Io {
                op: "write",
                kind: std::io::ErrorKind::Other,
            },
        ] {
            assert!(!e.to_string().contains('/'), "{e}");
        }
    }
}
