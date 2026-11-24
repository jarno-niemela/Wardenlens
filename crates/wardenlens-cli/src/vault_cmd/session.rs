//! Opening the vault: read commands never touch key files; write commands take the lock and
//! recover an interrupted rekey first (ADR 0006 section 6).

use std::fs::File;
use std::os::fd::OwnedFd;
use std::path::Path;

use rustix::fs::{FlockOperation, Mode, OFlags};
use wardenlens_secrets::KeyFile;
use wardenlens_vault::{Vault, VaultError};

use super::warn;
use crate::env::Paths;
use crate::error::CliError;
use crate::terminal::Terminal;

/// An exclusive lock on the key directory. Released when dropped (the descriptor closes).
///
/// This is the "write lock" of ADR 0006 section 6 for key-file recovery: two processes cannot
/// rename or delete `<key>.next` at once. The SQLite write transaction still serialises the
/// database itself.
pub(super) struct DirLock {
    _fd: OwnedFd,
}

impl DirLock {
    pub(super) fn acquire(dir: &Path) -> Result<Self, CliError> {
        let fd = rustix::fs::open(
            dir,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| CliError::io("opening key directory")(e.into()))?;
        match rustix::fs::flock(&fd, FlockOperation::NonBlockingLockExclusive) {
            Ok(()) => Ok(Self { _fd: fd }),
            Err(e) if e == rustix::io::Errno::WOULDBLOCK => Err(CliError::Refused(
                "another vault write command is running; try again when it finishes",
            )),
            Err(e) => Err(CliError::io("locking key directory")(e.into())),
        }
    }
}

/// A vault opened for writing, with the lock held for as long as it lives.
pub(super) struct WriteSession {
    pub(super) vault: Vault,
    _lock: DirLock,
}

pub(super) fn key_dir(p: &Paths) -> Result<&Path, CliError> {
    p.key
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .ok_or(CliError::Refused("key path has no parent directory"))
}

pub(super) fn fsync_dir(dir: &Path) -> Result<(), CliError> {
    File::open(dir)
        .and_then(|d| d.sync_all())
        .map_err(CliError::io("syncing directory"))
}

fn open_with_key(p: &Paths, key_path: &Path) -> Result<Vault, CliError> {
    let key = KeyFile::load(key_path)?;
    Ok(Vault::open(&p.db, key)?)
}

/// Opens for reading. A key mismatch points at the write command that can recover; it never
/// renames or deletes a key file.
pub(super) fn open_read(p: &Paths) -> Result<Vault, CliError> {
    open_with_key(p, &p.key).map_err(|e| match e {
        CliError::Vault(VaultError::WrongKey)
            if p.next_key().symlink_metadata().is_ok() =>
        {
            CliError::KeyMismatch(
                "the key does not open the vault and a pending <key>.next exists: an interrupted rekey; run `wardenlens vault rekey` (or any write command) to recover",
            )
        }
        other => other,
    })
}

/// Takes the lock, recovers an interrupted rekey, then opens for writing.
pub(super) fn open_write(p: &Paths, term: &mut impl Terminal) -> Result<WriteSession, CliError> {
    let lock = DirLock::acquire(key_dir(p)?)?;
    recover(p, term)?;
    let vault = open_with_key(p, &p.key)?;
    Ok(WriteSession { vault, _lock: lock })
}

/// Finishes or discards an interrupted rekey. The caller holds the [`DirLock`].
///
/// If the vault opens with the current key, a leftover `<key>.next` is stale and is deleted. If
/// it does not, but opens with `<key>.next` (which must pass every `KeyFile::load` check), the
/// rename the crash interrupted is completed. If neither opens, nothing is touched.
pub(super) fn recover(p: &Paths, term: &mut impl Terminal) -> Result<(), CliError> {
    let next = p.next_key();
    match next.symlink_metadata() {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(CliError::io("inspecting pending key")(e)),
    }
    let dir = key_dir(p)?;
    let Err(current_err) = open_with_key(p, &p.key) else {
        std::fs::remove_file(&next).map_err(CliError::io("removing stale pending key"))?;
        fsync_dir(dir)?;
        return warn(
            term,
            "removed a stale pending key file left by a rekey that did not commit",
        );
    };
    // Same checks as any key: regular file, owner, mode, length, not a symlink, no work tree.
    open_with_key(p, &next).map_err(|_| current_err)?;
    std::fs::rename(&next, &p.key).map_err(CliError::io("completing key rename"))?;
    fsync_dir(dir)?;
    warn(
        term,
        "completed an interrupted rekey: the pending key is now the key",
    )
}
