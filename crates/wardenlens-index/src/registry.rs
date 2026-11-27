//! The process-wide registry of open index files (ADR 0005 section 5; ticket #148).
//!
//! POSIX record locks belong to the process, not to a descriptor: closing **any** descriptor of
//! a file drops every such lock the process holds on it, SQLite's included. A second `Index`
//! over the same file, in the same process, would therefore silently strip the first one of its
//! locks the moment the second (or a refused attempt) closed its own descriptor. The serving
//! process holds exactly one `Index`; a second open is a bug, so it is **refused** with
//! [`IndexError::AlreadyOpenInProcess`] rather than shared.
//!
//! The key is the (device, inode) of the main file, taken from the descriptor we opened
//! (`fstat`), so a symlinked directory or a hard link cannot dodge it. This set is the only
//! global mutable state of the crate.
//!
//! Order, all under the registry mutex so two threads cannot both pass:
//! 1. `stat` the path (following links): a registered identity is refused **before any
//!    descriptor of the file is opened**, because even closing a refused descriptor would drop
//!    the first handle's locks. A missing file or any other `stat` error falls through; the open
//!    below reports it. A `-shm`, `-wal` or `-journal` name of a registered base file is refused
//!    the same way, and so is any path with more than one hard link (`HardLinkedIndex`; a
//!    hard link of a live sidecar must not be opened either).
//! 2. open our own descriptor (creating the file when missing), `fstat` it and insert the key.
//!    A key that is present here means the path was swapped between 1 and 2 (an attacker) or a
//!    link appeared: refused, and that descriptor is **parked** (leaked), not closed, because
//!    closing it would drop the first handle's locks. A failed `fstat` parks it the same way,
//!    since it cannot be told apart from a registered file.
//!
//! The [`Registration`] is dropped after the descriptor it describes ([`Held`] field order), and
//! on every error path of the open, so the entry never outlives the file handle and never leaks.

use std::collections::HashSet;
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::sync::{Mutex, MutexGuard, OnceLock, PoisonError};

use wardenlens_fsutil::{PrivateFile, open_private_file};

use crate::IndexError;

type Key = (u64, u64);

fn registry() -> MutexGuard<'static, HashSet<Key>> {
    static OPEN: OnceLock<Mutex<HashSet<Key>>> = OnceLock::new();
    // A panic while holding the lock cannot leave the set inconsistent (single insert/remove),
    // so a poisoned lock is recovered, not propagated.
    OPEN.get_or_init(|| Mutex::new(HashSet::new()))
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
}

/// The entry of one open index file; removes it on drop.
#[derive(Debug)]
pub(crate) struct Registration {
    key: Key,
}

impl Drop for Registration {
    fn drop(&mut self) {
        registry().remove(&self.key);
    }
}

/// The index descriptor and its registration. Field order is the drop order: the descriptor
/// closes first, then the entry goes.
pub(crate) struct Held {
    pub(crate) file: PrivateFile,
    _registration: Registration,
}

impl Held {
    /// Test only: releases the registry entry and keeps the descriptor, so a test can stand in
    /// for another process holding the file.
    #[cfg(test)]
    pub(crate) fn into_file(self) -> PrivateFile {
        self.file
    }
}

/// Sidecar suffixes of an index file. Opening one of them as an index would close a descriptor
/// on the live `-shm`, `-wal` or `-journal` and drop the first handle's locks on it.
const SIDECAR_SUFFIXES: [&[u8]; 3] = [b"-shm", b"-wal", b"-journal"];

/// What the pre-open `stat` found.
enum Verdict {
    /// Nothing known against this path.
    Open,
    /// This process has the file (or the base file of this sidecar name) open.
    Registered,
    /// The path has more than one hard link.
    HardLinked,
}

/// Judges `path` from `stat`s only: no descriptor is opened. A registered file, or a sidecar
/// name whose base file (same directory, suffix stripped, compared on bytes so a non-UTF-8 name
/// cannot dodge it) is registered, is `Registered`; a path with several links is `HardLinked`.
fn judge(set: &HashSet<Key>, path: &Path) -> Verdict {
    let registered =
        |p: &Path| std::fs::metadata(p).is_ok_and(|m| set.contains(&(m.dev(), m.ino())));
    let meta = std::fs::metadata(path);
    if meta
        .as_ref()
        .is_ok_and(|m| set.contains(&(m.dev(), m.ino())))
    {
        return Verdict::Registered;
    }
    if let Some(name) = path.file_name().map(OsStr::as_bytes) {
        let sidecar_of_registered = SIDECAR_SUFFIXES.iter().any(|suffix| {
            name.strip_suffix(*suffix).is_some_and(|base| {
                !base.is_empty() && registered(&path.with_file_name(OsStr::from_bytes(base)))
            })
        });
        if sidecar_of_registered {
            return Verdict::Registered;
        }
    }
    if meta.is_ok_and(|m| m.is_file() && m.nlink() > 1) {
        return Verdict::HardLinked;
    }
    Verdict::Open
}

/// Opens `path` as a private file and registers its identity, or refuses when this process
/// already has that file open.
pub(crate) fn open_registered(path: &Path) -> Result<Held, IndexError> {
    // Held across the stat and the open by design: the open is one per process at a time, and
    // `open_private_file` uses `O_NONBLOCK` and refuses non-regular files, so a FIFO cannot hang
    // it while the mutex is held.
    let mut set = registry();
    match judge(&set, path) {
        Verdict::Open => {}
        Verdict::Registered => return Err(IndexError::AlreadyOpenInProcess),
        Verdict::HardLinked => return Err(IndexError::HardLinkedIndex),
    }
    let file = open_private_file(path)?;
    let Ok(meta) = file.file().metadata() else {
        // Cannot tell this file from a registered one: closing it might drop the first
        // handle's locks, so it is parked like the race below.
        let _parked = std::mem::ManuallyDrop::new(file);
        return Err(IndexError::Io {
            op: "inspecting index file",
            kind: std::io::ErrorKind::Other,
        });
    };
    let key = (meta.dev(), meta.ino());
    if !set.insert(key) {
        // The path was swapped to a registered file between the stat and the open. Closing this
        // descriptor would drop the first handle's POSIX locks, so it is parked (leaked): one
        // descriptor per attempt, needing a same-user attacker inside our private directory.
        let _parked = std::mem::ManuallyDrop::new(file);
        return Err(IndexError::AlreadyOpenInProcess);
    }
    Ok(Held {
        file,
        _registration: Registration { key },
    })
}

#[cfg(test)]
pub(crate) fn registry_for_test() -> MutexGuard<'static, HashSet<Key>> {
    registry()
}
