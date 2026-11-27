//! The `SegmentFiles` port: how the recordings API reads a segment (ADR 0005
//! sections 7 and 11).
//!
//! The port opens a segment **by id** and returns a read-only handle, its
//! length and its tier. It exposes no path, no root and no writable handle, so
//! a consumer (#62) cannot derive any of them from what it receives. Core only
//! defines the contract; `storage` (#58) implements it and `cli` (#68) wires
//! it in as a generic.

use std::fmt;
use std::io::{self, Read, Seek, SeekFrom};

use super::types::{SegmentId, Tier};

/// Why a segment could not be opened.
///
/// The variants are the three cases the API maps to HTTP statuses (#62): not
/// found to 404, archive unavailable to 503, I/O to 500. No variant carries a
/// path, a root or any text from the input (SEC-6); `Io` keeps only the
/// [`io::ErrorKind`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SegmentOpenError {
    /// No such segment: no row, or no file on the tier the row names after
    /// the implementation's single re-read. (404)
    #[error("segment not found")]
    NotFound,
    /// The row names the archive tier and the archive is unavailable. (503)
    #[error("archive unavailable")]
    ArchiveUnavailable,
    /// Any other failure while opening or measuring the file. (500)
    ///
    /// An `io::ErrorKind::NotFound` here is still an I/O failure: only the
    /// implementation knows that the row exists, so it alone returns
    /// [`SegmentOpenError::NotFound`].
    #[error("segment i/o error")]
    Io {
        /// The kind of the underlying error; its message and path are dropped.
        kind: io::ErrorKind,
    },
}

impl SegmentOpenError {
    /// Builds an I/O error, keeping only the kind of `err`.
    #[must_use]
    pub fn io(err: &io::Error) -> Self {
        Self::Io { kind: err.kind() }
    }
}

/// An opened segment: a read-only handle positioned at byte 0, with its
/// length and tier.
///
/// The length is measured from the handle itself ([`OpenedSegment::from_handle`]),
/// so for a regular, unmodified file it equals what the handle yields. It is a
/// **snapshot taken at open**: a file that grows or shrinks afterwards makes the
/// handle yield more or fewer bytes than `len()`. A consumer therefore caps
/// every read at `len()` (for example `handle.take(len)`) and treats a short
/// read as a failure. The fields are private and there is no accessor for a
/// path or a writable view.
///
/// `Debug` prints the length and the tier only. It never prints the handle: a
/// `std::fs::File` prints its path, and the in-memory fake prints its bytes.
pub struct OpenedSegment<H> {
    handle: H,
    len: u64,
    tier: Tier,
}

impl<H> fmt::Debug for OpenedSegment<H> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OpenedSegment")
            .field("len", &self.len)
            .field("tier", &self.tier)
            .finish_non_exhaustive()
    }
}

impl<H: Read + Seek> OpenedSegment<H> {
    /// Wraps `handle`, measuring its length by seeking to the end and then
    /// rewinding to byte 0, whatever position it was in.
    ///
    /// # Errors
    ///
    /// [`SegmentOpenError::Io`] when seeking fails.
    pub fn from_handle(mut handle: H, tier: Tier) -> Result<Self, SegmentOpenError> {
        let len = handle
            .seek(SeekFrom::End(0))
            .map_err(|e| SegmentOpenError::io(&e))?;
        handle
            .seek(SeekFrom::Start(0))
            .map_err(|e| SegmentOpenError::io(&e))?;
        Ok(Self { handle, len, tier })
    }

    /// The length of the segment in bytes.
    #[must_use]
    pub const fn len(&self) -> u64 {
        self.len
    }

    /// Whether the segment has no bytes.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The tier the segment was opened from.
    #[must_use]
    pub const fn tier(&self) -> Tier {
        self.tier
    }

    /// Consumes the segment and returns the read-only handle.
    #[must_use]
    pub fn into_handle(self) -> H {
        self.handle
    }
}

/// Opens stored segments for reading, by id.
///
/// # Contract for implementations (storage, #58; ADR 0005 sections 7 and 8)
///
/// Core implements none of this; it is what `open_segment` must do:
///
/// - Read the index row, derive the path from it and open the file of the
///   row's tier through the root handle (`RootDir`). For the archive tier use
///   **only the handle of the latest successful probe**.
/// - Open with `O_RDONLY | O_NONBLOCK` and `O_NOFOLLOW` (through `openat2`
///   with `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS`) and `fstat` the descriptor;
///   the file must be **regular** (the length below is only meaningful for a
///   regular file). A write through the returned handle must fail with
///   `EBADF`; the implementation tests that.
/// - On `ENOENT` (a move finished between the row read and the open) **re-read
///   the row once**; if the tier changed, open the other tier, otherwise fail
///   with [`SegmentOpenError::NotFound`]. Never loop.
/// - Return [`SegmentOpenError::NotFound`] for no row or no file on the row's
///   tier after the re-read, [`SegmentOpenError::ArchiveUnavailable`] when the
///   row says archive and the archive state is unavailable, and
///   [`SegmentOpenError::Io`] for everything else. Errors carry no path.
/// - Build the result with [`OpenedSegment::from_handle`], so the length
///   matches the handle and the handle starts at byte 0. The reported tier is
///   the tier the file was actually opened from.
///
/// **Deviation from ADR 0005 section 3.** The ADR takes the length from
/// `fstat`; `from_handle` measures it by seeking to the end. For a regular file
/// the two are equal, which is why the implementation must still check that the
/// file is regular. Neither is a promise about later growth: the length is a
/// snapshot at open (see [`OpenedSegment`]).
///
/// # Blocking
///
/// `open_segment` blocks: it reads the index (SQLite) and opens the file
/// (`openat2`, and on the archive tier a possibly slow mount). A caller on an
/// async runtime runs it in `spawn_blocking` (ADR 0004 section 4). It must also
/// cap every read of the handle at [`OpenedSegment::len`] (`take(len)`), since
/// the file may change after the open.
///
/// # Handle bounds
///
/// `Handle` is `Read + Seek + Send + 'static`: `Read + Seek` serves
/// single-range requests, and `Send + 'static` lets the API move the handle
/// into a blocking task. A consumer that moves the port itself into
/// `spawn_blocking` additionally needs `F: Send + Sync + 'static`. There is no
/// `Write`, `AsRawFd` or `AsFd` bound, so a consumer holding only this port
/// cannot write or recover a path; the doctest below keeps it that way. A
/// download that holds the handle keeps reading through a later `unlink`
/// (POSIX semantics).
///
/// A generic consumer can read the handle:
///
/// ```
/// use std::io::Read;
/// use wardenlens_core::storage::{SegmentFiles, SegmentId};
///
/// fn consumer<F: SegmentFiles>(f: &F, id: SegmentId) {
///     if let Ok(seg) = f.open_segment(id) {
///         let mut handle = seg.into_handle();
///         let mut buf = Vec::new();
///         let _ = handle.read_to_end(&mut buf);
///     }
/// }
/// ```
///
/// but cannot write to it (the same code with `write_all` does not compile):
///
/// ```compile_fail,E0599
/// use std::io::Write;
/// use wardenlens_core::storage::{SegmentFiles, SegmentId};
///
/// fn consumer<F: SegmentFiles>(f: &F, id: SegmentId) {
///     if let Ok(seg) = f.open_segment(id) {
///         let mut handle = seg.into_handle();
///         let _ = handle.write_all(b"x");
///     }
/// }
/// ```
pub trait SegmentFiles {
    /// The read-only handle type.
    type Handle: Read + Seek + Send + 'static;

    /// Opens segment `id` for reading. Blocks; see the trait docs.
    ///
    /// # Errors
    ///
    /// See [`SegmentOpenError`] and the implementation contract above.
    fn open_segment(&self, id: SegmentId) -> Result<OpenedSegment<Self::Handle>, SegmentOpenError>;
}

#[cfg(any(test, feature = "test-support"))]
pub use fake::{MemoryHandle, MemorySegmentFiles};

/// In-memory fake. It is behind the `test-support` feature (and `cfg(test)`)
/// because the API crate's tests need it too (#62); production builds do not
/// compile it.
#[cfg(any(test, feature = "test-support"))]
mod fake {
    use std::collections::HashMap;
    use std::fmt;
    use std::io::{self, Cursor, Read, Seek, SeekFrom};
    use std::sync::{Arc, Mutex, PoisonError};

    use super::{OpenedSegment, SegmentFiles, SegmentId, SegmentOpenError, Tier};

    /// A read-only in-memory handle. It implements `Read` and `Seek` only, and
    /// owns a shared copy of the bytes, so it keeps working after the segment
    /// is moved or removed from the fake.
    ///
    /// `Debug` prints the length and position, never the bytes.
    pub struct MemoryHandle {
        cursor: Cursor<Arc<[u8]>>,
        fault: Option<ReadFault>,
    }

    impl fmt::Debug for MemoryHandle {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("MemoryHandle")
                .field("len", &self.cursor.get_ref().len())
                .field("position", &self.cursor.position())
                .finish_non_exhaustive()
        }
    }

    impl Read for MemoryHandle {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let Some(fault) = self.fault else {
                return self.cursor.read(buf);
            };
            let left = fault.after.saturating_sub(self.cursor.position());
            if left == 0 {
                return Err(io::Error::from(fault.kind));
            }
            // Never hand out more than the bytes left before the fault.
            let allowed = usize::try_from(left).map_or(buf.len(), |l| l.min(buf.len()));
            match buf.get_mut(..allowed) {
                Some(window) => self.cursor.read(window),
                None => self.cursor.read(buf),
            }
        }
    }

    impl Seek for MemoryHandle {
        fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
            self.cursor.seek(pos)
        }
    }

    /// Reads fail with `kind` once the handle's position reaches `after`.
    #[derive(Debug, Clone, Copy)]
    struct ReadFault {
        after: u64,
        kind: io::ErrorKind,
    }

    #[derive(Debug, Clone)]
    enum Entry {
        File {
            tier: Tier,
            bytes: Arc<[u8]>,
            fault: Option<ReadFault>,
        },
        Fail {
            tier: Tier,
            kind: io::ErrorKind,
        },
    }

    #[derive(Debug)]
    struct State {
        entries: HashMap<SegmentId, Entry>,
        archive_available: bool,
    }

    /// An in-memory [`SegmentFiles`] for tests of consumers.
    #[derive(Debug)]
    pub struct MemorySegmentFiles {
        state: Mutex<State>,
    }

    impl Default for MemorySegmentFiles {
        fn default() -> Self {
            Self::new()
        }
    }

    impl MemorySegmentFiles {
        /// An empty fake with the archive available.
        #[must_use]
        pub fn new() -> Self {
            Self {
                state: Mutex::new(State {
                    entries: HashMap::new(),
                    archive_available: true,
                }),
            }
        }

        fn with<R>(&self, f: impl FnOnce(&mut State) -> R) -> R {
            f(&mut self.state.lock().unwrap_or_else(PoisonError::into_inner))
        }

        /// Stores (or replaces) a segment.
        pub fn insert(&self, id: SegmentId, tier: Tier, bytes: &[u8]) {
            let bytes: Arc<[u8]> = Arc::from(bytes);
            self.with(|s| {
                s.entries.insert(
                    id,
                    Entry::File {
                        tier,
                        bytes,
                        fault: None,
                    },
                )
            });
        }

        /// Makes opening `id` fail with an I/O error of `kind`, as a row on
        /// `tier` would. On the archive tier an unavailable archive still wins
        /// and gives [`SegmentOpenError::ArchiveUnavailable`], as in the real
        /// implementation.
        pub fn fail_with(&self, id: SegmentId, tier: Tier, kind: io::ErrorKind) {
            self.with(|s| s.entries.insert(id, Entry::Fail { tier, kind }));
        }

        /// Makes reads of the stored segment `id` fail with `kind` once `after`
        /// bytes have been read (counted by position, so a seek past `after`
        /// fails at once). The open itself succeeds and `len()` is the full
        /// length, as for a file that errors mid-download. Applies to handles
        /// opened afterwards. Returns whether `id` was a stored file.
        pub fn fail_reads_after(&self, id: SegmentId, after: u64, kind: io::ErrorKind) -> bool {
            self.with(|s| match s.entries.get_mut(&id) {
                Some(Entry::File { fault, .. }) => {
                    *fault = Some(ReadFault { after, kind });
                    true
                }
                _ => false,
            })
        }

        /// Moves a stored segment to `tier`, as the mover would. Returns
        /// whether `id` was a stored file.
        pub fn move_to(&self, id: SegmentId, tier: Tier) -> bool {
            self.with(|s| match s.entries.get_mut(&id) {
                Some(Entry::File { tier: t, .. }) => {
                    *t = tier;
                    true
                }
                _ => false,
            })
        }

        /// Removes a segment (deletion by the mover). Handles already opened
        /// keep their bytes.
        pub fn remove(&self, id: SegmentId) {
            self.with(|s| s.entries.remove(&id));
        }

        /// Sets whether the archive tier is available.
        pub fn set_archive_available(&self, available: bool) {
            self.with(|s| s.archive_available = available);
        }
    }

    impl SegmentFiles for MemorySegmentFiles {
        type Handle = MemoryHandle;

        fn open_segment(
            &self,
            id: SegmentId,
        ) -> Result<OpenedSegment<Self::Handle>, SegmentOpenError> {
            let (tier, bytes, fault) = self.with(|s| {
                let archive_up = s.archive_available;
                match s.entries.get(&id) {
                    None => Err(SegmentOpenError::NotFound),
                    Some(Entry::Fail { tier, kind }) => {
                        if *tier == Tier::Archive && !archive_up {
                            Err(SegmentOpenError::ArchiveUnavailable)
                        } else {
                            Err(SegmentOpenError::Io { kind: *kind })
                        }
                    }
                    Some(Entry::File { tier, bytes, fault }) => {
                        if *tier == Tier::Archive && !archive_up {
                            Err(SegmentOpenError::ArchiveUnavailable)
                        } else {
                            Ok((*tier, Arc::clone(bytes), *fault))
                        }
                    }
                }
            })?;
            OpenedSegment::from_handle(
                MemoryHandle {
                    cursor: Cursor::new(bytes),
                    fault,
                },
                tier,
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Read, Seek, SeekFrom};

    use super::*;

    fn id(n: u64) -> SegmentId {
        SegmentId::new(n)
    }

    fn read_all<H: Read>(mut h: H) -> Vec<u8> {
        let mut v = Vec::new();
        h.read_to_end(&mut v).unwrap();
        v
    }

    // Misuse 1: wrong tier.
    #[test]
    fn reports_the_tier_the_segment_is_stored_on() {
        let fs = MemorySegmentFiles::new();
        fs.insert(id(1), Tier::Hot, b"h");
        fs.insert(id(2), Tier::Archive, b"a");
        assert_eq!(fs.open_segment(id(1)).unwrap().tier(), Tier::Hot);
        assert_eq!(fs.open_segment(id(2)).unwrap().tier(), Tier::Archive);
    }

    // Misuse 2: length disagrees with the handle.
    #[test]
    fn length_matches_the_bytes_the_handle_yields() {
        let fs = MemorySegmentFiles::new();
        fs.insert(id(1), Tier::Hot, b"0123456789");
        let seg = fs.open_segment(id(1)).unwrap();
        assert_eq!(seg.len(), 10);
        assert!(!seg.is_empty());
        assert_eq!(read_all(seg.into_handle()).len(), 10);
    }

    #[test]
    fn empty_segment_has_length_zero() {
        let fs = MemorySegmentFiles::new();
        fs.insert(id(1), Tier::Hot, b"");
        let seg = fs.open_segment(id(1)).unwrap();
        assert!(seg.is_empty());
        assert_eq!(seg.len(), 0);
    }

    // Misuse 3: handle not at byte 0 (the length measure must rewind).
    #[test]
    fn from_handle_rewinds_a_handle_that_was_mid_file() {
        let mut c = Cursor::new(b"abcdef".to_vec());
        c.set_position(4);
        let seg = OpenedSegment::from_handle(c, Tier::Hot).unwrap();
        assert_eq!(seg.len(), 6);
        assert_eq!(read_all(seg.into_handle()), b"abcdef");
    }

    // Misuse 4: a handle that cannot seek reports an I/O error, not a length.
    #[test]
    fn from_handle_seek_failure_is_io() {
        #[derive(Debug)]
        struct NoSeek;
        impl Read for NoSeek {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Ok(0)
            }
        }
        impl Seek for NoSeek {
            fn seek(&mut self, _: SeekFrom) -> std::io::Result<u64> {
                Err(std::io::Error::other("/secret/path"))
            }
        }
        let err = OpenedSegment::from_handle(NoSeek, Tier::Hot).unwrap_err();
        assert_eq!(
            err,
            SegmentOpenError::Io {
                kind: std::io::ErrorKind::Other
            }
        );
    }

    // Range requests: seeking works on the returned handle.
    #[test]
    fn handle_supports_range_reads() {
        let fs = MemorySegmentFiles::new();
        fs.insert(id(1), Tier::Hot, b"0123456789");
        let mut h = fs.open_segment(id(1)).unwrap().into_handle();
        h.seek(SeekFrom::Start(3)).unwrap();
        let mut b = [0u8; 4];
        h.read_exact(&mut b).unwrap();
        assert_eq!(&b, b"3456");
    }

    // Misuse 5: not-found vs I/O vs neighbouring id.
    #[test]
    fn unknown_id_is_not_found_and_neighbours_are_not_confused() {
        let fs = MemorySegmentFiles::new();
        fs.insert(id(5), Tier::Hot, b"x");
        assert_eq!(
            fs.open_segment(id(4)).unwrap_err(),
            SegmentOpenError::NotFound
        );
        assert_eq!(
            fs.open_segment(id(6)).unwrap_err(),
            SegmentOpenError::NotFound
        );
        assert!(fs.open_segment(id(5)).is_ok());
    }

    #[test]
    fn io_not_found_kind_stays_io() {
        let fs = MemorySegmentFiles::new();
        fs.fail_with(id(1), Tier::Hot, std::io::ErrorKind::NotFound);
        assert_eq!(
            fs.open_segment(id(1)).unwrap_err(),
            SegmentOpenError::Io {
                kind: std::io::ErrorKind::NotFound
            }
        );
    }

    // Misuse 6: archive unavailable only for archive rows, and recovers.
    #[test]
    fn archive_unavailable_affects_only_archive_segments() {
        let fs = MemorySegmentFiles::new();
        fs.insert(id(1), Tier::Hot, b"h");
        fs.insert(id(2), Tier::Archive, b"a");
        fs.set_archive_available(false);
        assert!(fs.open_segment(id(1)).is_ok());
        assert_eq!(
            fs.open_segment(id(2)).unwrap_err(),
            SegmentOpenError::ArchiveUnavailable
        );
        assert_eq!(
            fs.open_segment(id(3)).unwrap_err(),
            SegmentOpenError::NotFound
        );
        fs.set_archive_available(true);
        assert!(fs.open_segment(id(2)).is_ok());
    }

    // Misuse 7: a moved segment.
    #[test]
    fn move_changes_reported_tier_and_open_handle_keeps_reading() {
        let fs = MemorySegmentFiles::new();
        fs.insert(id(1), Tier::Hot, b"payload");
        let before = fs.open_segment(id(1)).unwrap();
        assert!(fs.move_to(id(1), Tier::Archive));
        assert_eq!(fs.open_segment(id(1)).unwrap().tier(), Tier::Archive);
        assert_eq!(before.tier(), Tier::Hot);
        assert_eq!(read_all(before.into_handle()), b"payload");
        assert!(!fs.move_to(id(9), Tier::Hot));
    }

    #[test]
    fn open_handle_survives_removal_and_new_open_is_not_found() {
        let fs = MemorySegmentFiles::new();
        fs.insert(id(1), Tier::Hot, b"payload");
        let h = fs.open_segment(id(1)).unwrap().into_handle();
        fs.remove(id(1));
        assert_eq!(
            fs.open_segment(id(1)).unwrap_err(),
            SegmentOpenError::NotFound
        );
        assert_eq!(read_all(h), b"payload");
    }

    #[test]
    fn each_open_is_independent() {
        let fs = MemorySegmentFiles::new();
        fs.insert(id(1), Tier::Hot, b"abc");
        let mut a = fs.open_segment(id(1)).unwrap().into_handle();
        let mut one = [0u8; 1];
        a.read_exact(&mut one).unwrap();
        assert_eq!(
            read_all(fs.open_segment(id(1)).unwrap().into_handle()),
            b"abc"
        );
    }

    // Misuse 8: errors leaking paths or input text (SEC-6).
    #[test]
    fn errors_carry_no_path_or_message() {
        let io = std::io::Error::other("/home/x/archive/cam/secret.mp4");
        let e = SegmentOpenError::io(&io);
        for err in [
            e,
            SegmentOpenError::NotFound,
            SegmentOpenError::ArchiveUnavailable,
        ] {
            let shown = format!("{err} {err:?}");
            assert!(
                !shown.contains("secret") && !shown.contains("home"),
                "{shown}"
            );
        }
    }

    // Debug prints the length and the tier, never the handle (a `File` prints
    // its path; the fake prints its bytes).
    #[test]
    fn opened_segment_debug_shows_len_and_tier_only() {
        struct Leaky(Cursor<Vec<u8>>);
        impl std::fmt::Debug for Leaky {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("Leaky(/secret/path)")
            }
        }
        impl Read for Leaky {
            fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
                self.0.read(b)
            }
        }
        impl Seek for Leaky {
            fn seek(&mut self, p: SeekFrom) -> std::io::Result<u64> {
                self.0.seek(p)
            }
        }
        let seg =
            OpenedSegment::from_handle(Leaky(Cursor::new(b"/secret/path".to_vec())), Tier::Archive)
                .unwrap();
        // Sanity: the handle itself would leak.
        assert!(format!("{:?}", Leaky(Cursor::new(Vec::new()))).contains("secret"));
        let shown = format!("{seg:?}");
        assert!(
            shown.contains("len: 12") && shown.contains("Archive"),
            "{shown}"
        );
        assert!(
            !shown.contains("secret") && !shown.contains("Leaky"),
            "{shown}"
        );
        // The fake's own handle does not dump bytes either.
        let fs = MemorySegmentFiles::new();
        fs.insert(id(1), Tier::Hot, b"PAYLOADBYTES");
        let h = fs.open_segment(id(1)).unwrap().into_handle();
        assert!(!format!("{h:?}").contains("PAYLOAD"));
    }

    fn drain(h: &mut impl Read) -> (Vec<u8>, Option<std::io::ErrorKind>) {
        let mut out = Vec::new();
        let mut buf = [0u8; 3];
        loop {
            match h.read(&mut buf) {
                Ok(0) => return (out, None),
                Ok(n) => out.extend_from_slice(&buf[..n]),
                Err(e) => return (out, Some(e.kind())),
            }
        }
    }

    // Mid-download failure: exactly `after` bytes arrive, then the chosen kind.
    #[test]
    fn reads_fail_after_n_bytes_with_the_chosen_kind() {
        use std::io::ErrorKind as K;
        let data = b"0123456789";
        for (after, kind) in [
            (0u64, K::PermissionDenied),
            (1, K::TimedOut),
            (4, K::BrokenPipe),
            (9, K::Other),
            (10, K::UnexpectedEof),
        ] {
            let fs = MemorySegmentFiles::new();
            fs.insert(id(1), Tier::Hot, data);
            assert!(fs.fail_reads_after(id(1), after, kind));
            let seg = fs.open_segment(id(1)).unwrap();
            assert_eq!(seg.len(), 10, "open succeeds with the full length");
            let (got, err) = drain(&mut seg.into_handle());
            let n = usize::try_from(after).unwrap();
            assert_eq!(got, &data[..n], "after={after}");
            assert_eq!(err, Some(kind), "after={after}");
        }
    }

    #[test]
    fn read_fault_follows_the_position_not_the_count() {
        let fs = MemorySegmentFiles::new();
        fs.insert(id(1), Tier::Hot, b"0123456789");
        fs.fail_reads_after(id(1), 5, std::io::ErrorKind::TimedOut);
        let mut h = fs.open_segment(id(1)).unwrap().into_handle();
        // A range starting past the fault fails at once.
        h.seek(SeekFrom::Start(7)).unwrap();
        assert_eq!(
            h.read(&mut [0u8; 2]).unwrap_err().kind(),
            std::io::ErrorKind::TimedOut
        );
        // A range below it reads, and reading may start before and stop at it.
        h.seek(SeekFrom::Start(2)).unwrap();
        let mut b = [0u8; 8];
        assert_eq!(h.read(&mut b).unwrap(), 3);
        assert_eq!(&b[..3], b"234");
        assert!(h.read(&mut b).is_err());
    }

    #[test]
    fn read_fault_is_per_segment_and_cleared_by_insert_and_kept_by_move() {
        let fs = MemorySegmentFiles::new();
        fs.insert(id(1), Tier::Hot, b"abcdef");
        fs.insert(id(2), Tier::Hot, b"abcdef");
        assert!(!fs.fail_reads_after(id(9), 1, std::io::ErrorKind::Other));
        assert!(fs.fail_reads_after(id(1), 2, std::io::ErrorKind::Other));
        let early = fs.open_segment(id(2)).unwrap();
        assert_eq!(drain(&mut early.into_handle()), (b"abcdef".to_vec(), None));
        assert!(fs.move_to(id(1), Tier::Archive));
        let (got, err) = drain(&mut fs.open_segment(id(1)).unwrap().into_handle());
        assert_eq!(
            (got.as_slice(), err),
            (&b"ab"[..], Some(std::io::ErrorKind::Other))
        );
        // Handles opened before the fault was set are unaffected.
        let before = fs.open_segment(id(2)).unwrap();
        fs.fail_reads_after(id(2), 0, std::io::ErrorKind::Other);
        assert_eq!(read_all(before.into_handle()), b"abcdef");
        // A fresh insert replaces the entry and its fault.
        fs.insert(id(1), Tier::Hot, b"abcdef");
        assert_eq!(
            read_all(fs.open_segment(id(1)).unwrap().into_handle()),
            b"abcdef"
        );
        // A failing-open entry is not a stored file.
        fs.fail_with(id(3), Tier::Hot, std::io::ErrorKind::Other);
        assert!(!fs.fail_reads_after(id(3), 1, std::io::ErrorKind::Other));
    }

    // fail_with names the tier: an archive-tier Io error, and the archive
    // being unavailable still wins on that tier only.
    #[test]
    fn fail_with_a_tier_gives_an_io_error_on_that_tier() {
        let kind = std::io::ErrorKind::PermissionDenied;
        let fs = MemorySegmentFiles::new();
        fs.fail_with(id(1), Tier::Archive, kind);
        fs.fail_with(id(2), Tier::Hot, kind);
        assert_eq!(
            fs.open_segment(id(1)).unwrap_err(),
            SegmentOpenError::Io { kind }
        );
        fs.set_archive_available(false);
        assert_eq!(
            fs.open_segment(id(1)).unwrap_err(),
            SegmentOpenError::ArchiveUnavailable
        );
        assert_eq!(
            fs.open_segment(id(2)).unwrap_err(),
            SegmentOpenError::Io { kind }
        );
    }

    // The port is usable generically with the documented bounds (Send for #62).
    #[test]
    fn handle_is_send_read_seek_through_the_trait() {
        fn assert_bounds<F: SegmentFiles>(f: &F, id: SegmentId) -> u64 {
            fn send<T: Send>(_: &T) {}
            let seg = f.open_segment(id).unwrap();
            let len = seg.len();
            let h = seg.into_handle();
            send(&h);
            len
        }
        let fs = MemorySegmentFiles::new();
        fs.insert(id(1), Tier::Hot, b"abcd");
        assert_eq!(assert_bounds(&fs, id(1)), 4);
    }
}
