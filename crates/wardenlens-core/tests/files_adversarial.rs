//! Adversarial tests for the `SegmentFiles` port (#85, PR #132).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::needless_borrow,
    reason = "adversarial tests; the needless borrow drives autoref trait probing"
)]

use std::fs::{self, File, OpenOptions};
use std::io::{self, Cursor, Read, Seek, SeekFrom, Write};
use std::path::PathBuf;

use wardenlens_core::storage::{OpenedSegment, SegmentOpenError, Tier};

/// A unique scratch file under the system temp dir, removed on drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str, bytes: &[u8]) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "wl-files-adv-{}-{tag}-secretdir",
            std::process::id()
        ));
        fs::create_dir_all(&dir).unwrap();
        let p = dir.join("cam-secret-2024-01-01.mp4");
        fs::write(&p, bytes).unwrap();
        Self(p)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
        if let Some(d) = self.0.parent() {
            let _ = fs::remove_dir(d);
        }
    }
}

// Claim: "It exposes no path ... so a consumer cannot derive any of them from
// what it receives" / "there is no accessor for a path". The natural storage
// handle is `std::fs::File`, whose `Debug` (Linux) prints the path through
// /proc/self/fd. `OpenedSegment` derives `Debug`, so `{:?}` (e.g. a tracing
// field) reveals the full path and root.
#[test]
#[ignore = "follow-up #133: OpenedSegment's derived Debug prints the handle (a File prints its path)"]
fn opened_segment_debug_does_not_reveal_the_file_path() {
    let s = Scratch::new("debug", b"payload");
    let seg = OpenedSegment::from_handle(File::open(&s.0).unwrap(), Tier::Hot).unwrap();
    let shown = format!("{seg:?}");
    assert!(
        !shown.contains("secret") && !shown.contains(&*s.0.to_string_lossy()),
        "Debug of an OpenedSegment leaks the path: {shown}"
    );
}

// The ADR says the length is the fstat size; the port measures by seeking.
// For a regular file they must agree.
#[test]
fn seek_measured_length_equals_fstat_size_for_a_regular_file() {
    let bytes: Vec<u8> = (0..=255u8).cycle().take(70_001).collect();
    let s = Scratch::new("fstat", &bytes);
    let f = File::open(&s.0).unwrap();
    let st = f.metadata().unwrap().len();
    let seg = OpenedSegment::from_handle(f, Tier::Archive).unwrap();
    assert_eq!(seg.len(), st);
    assert_eq!(seg.len(), 70_001);
    assert_eq!(seg.tier(), Tier::Archive);
    let mut out = Vec::new();
    seg.into_handle().read_to_end(&mut out).unwrap();
    assert_eq!(out, bytes);
}

#[test]
fn from_handle_rewinds_a_handle_positioned_past_the_end() {
    let mut c = Cursor::new(b"abc".to_vec());
    c.seek(SeekFrom::Start(1_000)).unwrap();
    let seg = OpenedSegment::from_handle(c, Tier::Hot).unwrap();
    assert_eq!(seg.len(), 3);
    let mut h = seg.into_handle();
    assert_eq!(h.stream_position().unwrap(), 0);
    let mut out = Vec::new();
    h.read_to_end(&mut out).unwrap();
    assert_eq!(out, b"abc");
}

#[test]
fn from_handle_rewind_failure_is_io_with_that_kind() {
    #[derive(Debug)]
    struct EndOnly;
    impl Read for EndOnly {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Ok(0)
        }
    }
    impl Seek for EndOnly {
        fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
            match pos {
                SeekFrom::End(_) => Ok(42),
                _ => Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "/root/archive/x.mp4",
                )),
            }
        }
    }
    let err = OpenedSegment::from_handle(EndOnly, Tier::Hot).unwrap_err();
    assert_eq!(
        err,
        SegmentOpenError::Io {
            kind: io::ErrorKind::PermissionDenied
        }
    );
    let shown = format!("{err} {err:?}");
    assert!(
        !shown.contains("root") && !shown.contains("x.mp4"),
        "{shown}"
    );
}

// A real handle keeps reading after unlink (POSIX), and the length stays
// what was measured at open.
#[test]
fn file_handle_survives_unlink_with_the_measured_length() {
    let s = Scratch::new("unlink", b"0123456789");
    let seg = OpenedSegment::from_handle(File::open(&s.0).unwrap(), Tier::Hot).unwrap();
    fs::remove_file(&s.0).unwrap();
    let len = seg.len();
    let mut h = seg.into_handle();
    h.seek(SeekFrom::Start(7)).unwrap();
    let mut out = Vec::new();
    h.read_to_end(&mut out).unwrap();
    assert_eq!(len, 10);
    assert_eq!(out, b"789");
}

// Observation for the doc claim "the length ... cannot disagree with what the
// handle yields": it is a snapshot. Documented here as a passing test of the
// snapshot semantics (len is fixed at open; consumers must bound reads by it).
#[test]
fn length_is_a_snapshot_taken_at_open() {
    let s = Scratch::new("grow", b"abc");
    let seg = OpenedSegment::from_handle(File::open(&s.0).unwrap(), Tier::Hot).unwrap();
    OpenOptions::new()
        .append(true)
        .open(&s.0)
        .unwrap()
        .write_all(b"def")
        .unwrap();
    assert_eq!(seg.len(), 3);
    let mut out = Vec::new();
    seg.into_handle().read_to_end(&mut out).unwrap();
    // The handle yields 6 bytes although len() says 3.
    assert_eq!(out.len(), 6);
}

#[cfg(feature = "test-support")]
mod fake {
    use std::io::{self, Read, Seek, SeekFrom, Write};
    use std::marker::PhantomData;
    use std::sync::{Arc, Barrier};

    use wardenlens_core::storage::{
        MemoryHandle, MemorySegmentFiles, SegmentFiles, SegmentId, SegmentOpenError, Tier,
    };

    struct Probe<T>(PhantomData<T>);
    trait IsWrite {
        fn is_write(&self) -> bool {
            true
        }
    }
    impl<T: Write> IsWrite for Probe<T> {}
    trait NotWrite {
        fn is_write(&self) -> bool {
            false
        }
    }
    impl<T> NotWrite for &Probe<T> {}

    #[test]
    fn memory_handle_does_not_implement_write() {
        assert!(!(&Probe::<MemoryHandle>(PhantomData)).is_write());
        // Sanity: the probe detects Write when it is there.
        assert!((&Probe::<Vec<u8>>(PhantomData)).is_write());
    }

    #[test]
    fn extreme_ids_are_distinct_keys() {
        let fs = MemorySegmentFiles::new();
        fs.insert(SegmentId::new(u64::MAX), Tier::Archive, b"max");
        fs.insert(SegmentId::new(0), Tier::Hot, b"zero");
        assert_eq!(fs.open_segment(SegmentId::new(u64::MAX)).unwrap().len(), 3);
        assert_eq!(fs.open_segment(SegmentId::new(0)).unwrap().len(), 4);
        assert_eq!(
            fs.open_segment(SegmentId::new(u64::MAX - 1)).unwrap_err(),
            SegmentOpenError::NotFound
        );
    }

    #[test]
    fn insert_replaces_failure_and_old_handle_keeps_old_bytes() {
        let fs = MemorySegmentFiles::new();
        let id = SegmentId::new(1);
        fs.fail_with(id, io::ErrorKind::PermissionDenied);
        assert!(!fs.move_to(id, Tier::Archive));
        assert_eq!(
            fs.open_segment(id).unwrap_err(),
            SegmentOpenError::Io {
                kind: io::ErrorKind::PermissionDenied
            }
        );
        fs.insert(id, Tier::Hot, b"old");
        let old = fs.open_segment(id).unwrap();
        fs.insert(id, Tier::Hot, b"newer");
        let mut out = Vec::new();
        old.into_handle().read_to_end(&mut out).unwrap();
        assert_eq!(out, b"old");
        assert_eq!(fs.open_segment(id).unwrap().len(), 5);
    }

    #[test]
    fn move_into_unavailable_archive_then_back_to_hot() {
        let fs = MemorySegmentFiles::new();
        let id = SegmentId::new(7);
        fs.insert(id, Tier::Hot, b"x");
        fs.set_archive_available(false);
        assert!(fs.move_to(id, Tier::Archive));
        assert_eq!(
            fs.open_segment(id).unwrap_err(),
            SegmentOpenError::ArchiveUnavailable
        );
        assert!(fs.move_to(id, Tier::Hot));
        assert_eq!(fs.open_segment(id).unwrap().tier(), Tier::Hot);
    }

    #[test]
    fn handle_seek_edges_do_not_panic() {
        let fs = MemorySegmentFiles::new();
        fs.insert(SegmentId::new(1), Tier::Hot, b"abc");
        let mut h = fs.open_segment(SegmentId::new(1)).unwrap().into_handle();
        assert!(h.seek(SeekFrom::Current(-1)).is_err());
        assert_eq!(h.seek(SeekFrom::Start(u64::MAX)).unwrap(), u64::MAX);
        let mut b = [0u8; 4];
        assert_eq!(h.read(&mut b).unwrap(), 0);
        assert_eq!(h.seek(SeekFrom::End(-3)).unwrap(), 0);
        h.read_exact(&mut b[..3]).unwrap();
        assert_eq!(&b[..3], b"abc");
    }

    #[test]
    fn concurrent_opens_from_threads_each_read_everything() {
        let fs = Arc::new(MemorySegmentFiles::new());
        fs.insert(SegmentId::new(1), Tier::Hot, b"shared-bytes");
        let n = 8;
        let barrier = Arc::new(Barrier::new(n));
        let joins: Vec<_> = (0..n)
            .map(|_| {
                let fs = Arc::clone(&fs);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    let mut h = fs.open_segment(SegmentId::new(1)).unwrap().into_handle();
                    let mut out = Vec::new();
                    h.read_to_end(&mut out).unwrap();
                    out
                })
            })
            .collect();
        for j in joins {
            assert_eq!(j.join().unwrap(), b"shared-bytes");
        }
    }
}
