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
//!    below reports it.
//! 2. open our own descriptor (creating the file when missing), `fstat` it and insert the key.
//!    A key that is present here means the path was swapped between 1 and 2 (an attacker) or a
//!    link appeared: refused, at the price of closing that one descriptor.
//!
//! The [`Registration`] is dropped after the descriptor it describes ([`Held`] field order), and
//! on every error path of the open, so the entry never outlives the file handle and never leaks.

use std::collections::HashSet;
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

/// Opens `path` as a private file and registers its identity, or refuses when this process
/// already has that file open.
pub(crate) fn open_registered(path: &Path) -> Result<Held, IndexError> {
    let mut set = registry();
    if let Ok(meta) = std::fs::metadata(path)
        && set.contains(&(meta.dev(), meta.ino()))
    {
        return Err(IndexError::AlreadyOpenInProcess);
    }
    let file = open_private_file(path)?;
    let meta = file
        .file()
        .metadata()
        .map_err(IndexError::io("inspecting index file"))?;
    let key = (meta.dev(), meta.ino());
    if !set.insert(key) {
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
