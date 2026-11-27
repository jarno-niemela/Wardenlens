//! The exclusive lock inside the hot root (ADR 0005 section 8): two `serve` processes with
//! different state directories over one hot root would run two storage loops and two start-up
//! reconciliations on the same files. The lock is an `flock` on `.wardenlens.lock`, created mode
//! `0600` through the root handle (`openat2` beneath, no symlinks) and held until the file is
//! dropped. The reconciliation walk skips this one name.

use std::fs::File;

use rustix::fs::{FlockOperation, flock};
use rustix::io::Errno;
use wardenlens_fsutil::{FsError, RootDir};
use wardenlens_storage::HOT_LOCK_FILE;

use super::ServeError;

/// Why the lock file could not be used. No path.
#[derive(Debug, thiserror::Error)]
pub(crate) enum LockError {
    /// Creating or opening the file failed.
    #[error("the lock file cannot be created or opened")]
    File(#[source] FsError),
    /// `flock` failed for a reason other than "held by another instance".
    #[error("the lock cannot be taken: {0}")]
    Flock(#[source] Errno),
}

/// Takes the exclusive lock; [`ServeError::HotRootLocked`] when another instance holds it.
pub(crate) fn lock_hot_root(hot: &RootDir) -> Result<File, ServeError> {
    let file = match hot.create_new(HOT_LOCK_FILE) {
        Ok(f) => f,
        // An earlier run left it: it is the lock's name, not its content, that matters.
        Err(e) if e.errno() == Some(Errno::EXIST) => {
            hot.open_read(&[HOT_LOCK_FILE])
                .map_err(|e| ServeError::HotRootLock(LockError::File(e)))?
                .file
        }
        Err(e) => return Err(ServeError::HotRootLock(LockError::File(e))),
    };
    match flock(&file, FlockOperation::NonBlockingLockExclusive) {
        Ok(()) => Ok(file),
        Err(Errno::WOULDBLOCK) => Err(ServeError::HotRootLocked),
        Err(e) => Err(ServeError::HotRootLock(LockError::Flock(e))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_second_lock_is_refused_until_the_first_is_dropped_and_the_file_is_reused() {
        let dir = tempfile::tempdir().unwrap();
        let hot = RootDir::open(dir.path()).unwrap();
        let first = lock_hot_root(&hot).unwrap();
        assert!(matches!(
            lock_hot_root(&hot).unwrap_err(),
            ServeError::HotRootLocked
        ));
        // A second handle on the same directory is refused as well.
        let again = RootDir::open(dir.path()).unwrap();
        assert!(matches!(
            lock_hot_root(&again).unwrap_err(),
            ServeError::HotRootLocked
        ));
        drop(first);
        lock_hot_root(&hot).unwrap();
    }

    #[test]
    fn a_symlink_at_the_lock_name_is_refused_not_followed() {
        let dir = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink("/dev/null", dir.path().join(HOT_LOCK_FILE)).unwrap();
        let hot = RootDir::open(dir.path()).unwrap();
        assert!(matches!(
            lock_hot_root(&hot).unwrap_err(),
            ServeError::HotRootLock(LockError::File(_))
        ));
    }
}
