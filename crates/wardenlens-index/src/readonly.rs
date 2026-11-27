//! The read-only open of the index (#163): a reader that never writes.
//!
//! [`Index::open_read_only`] is for a caller that only wants to look (the dry run of `import`). It
//! runs **no migration, sets no pragma, creates no file, takes no `flock` and begins no write
//! transaction**, so the state directory is byte-identical before and after. It keeps the checks
//! of [`Index::open`]: the private parent, our own `O_NOFOLLOW` descriptor (never created), the
//! owner and mode of the file and of every sidecar, the sidecar table (`check_sidecars`), the
//! `-wal` header, the schema identity and `integrity_check`, and the registry of open files (a file
//! this process has open is refused with [`IndexError::AlreadyOpenInProcess`]). A refusal of the
//! read-write open that these checks make is the same refusal here.
//!
//! A missing file is [`IndexError::Fs`] (not found), or `StraySidecar` when a sidecar is there.
//!
//! What the read-write open would do first, and this one reports instead (typed, nothing written):
//! - [`IndexError::Uninitialised`]: a zero-length file, which the read-write open formats;
//! - [`IndexError::NeedsMigration`]: a schema older than this build's, which it migrates. (Reading
//!   the rows of an older schema would need a decoder per version; the simpler correct choice is to
//!   say that the real run migrates first.);
//! - [`IndexError::NeedsRecovery`]: a non-empty valid `-wal` with no `-shm`: opening it, even
//!   read-only, creates the `-shm`.
//!
//! Without a usable `-wal` the main file is read with `immutable=1` (a settled file, no locks at
//! all). With one (and its `-shm`, a live or crashed writer), a `SQLITE_OPEN_READ_ONLY`
//! connection replays it in memory with `NO_CKPT_ON_CLOSE`; SQLite then updates the existing
//! `-shm` (reader marks), which is state of the running writer, not of the index.
//!
//! **No lock is taken**, so a concurrent read-write open can change the file under the reader;
//! the reader sees SQLite's own consistent snapshot per statement. The dry run is advisory.

use std::path::Path;

use wardenlens_core::camera::CameraId;
use wardenlens_core::catalogue::CatalogueEntry;
use wardenlens_fsutil::check_parent;

use crate::Index;
use crate::cameras::{self, StoredCamera};
use crate::error::IndexError;
use crate::migrate;
use crate::open::{
    Sidecars, Step, check_sidecars, judge_view, open_immutable, open_wal_probe, read_header,
    wal_is_usable, wal_verdict,
};
use crate::registry::{Held, open_registered_existing};
use crate::sql::Db;

/// A read-only view of the index (see the module docs). Reads cameras only.
pub struct ReadOnlyIndex {
    // The connection closes first, then the descriptor and the registry entry.
    conn: Db,
    _held: Held,
}

impl std::fmt::Debug for ReadOnlyIndex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ReadOnlyIndex { .. }")
    }
}

impl ReadOnlyIndex {
    /// The camera with `id`, or `None`; as [`Index::get_camera`].
    ///
    /// # Errors
    /// The errors of [`Index::get_camera`].
    pub fn get_camera(
        &self,
        id: &CameraId,
        catalogue: &[CatalogueEntry],
    ) -> Result<Option<StoredCamera>, IndexError> {
        cameras::get_camera(&self.conn, id, catalogue)
    }

    /// Every camera, ordered by id; as [`Index::list_cameras`].
    ///
    /// # Errors
    /// The errors of [`Index::list_cameras`].
    pub fn list_cameras(
        &self,
        catalogue: &[CatalogueEntry],
    ) -> Result<Vec<StoredCamera>, IndexError> {
        cameras::list_cameras(&self.conn, catalogue)
    }
}

impl Index {
    /// Opens the index at `path` for reading only; see the `readonly` module docs for what it
    /// does not do and what it reports instead of doing.
    ///
    /// # Errors
    /// Every refusal of [`Index::open`] that its read-only checks make (symlink, owner, mode,
    /// sidecars, `-wal`, schema identity, damage, a schema too new), [`IndexError::Fs`] with a
    /// not-found error for a missing file (nothing is created), and
    /// [`IndexError::Uninitialised`], [`IndexError::NeedsMigration`],
    /// [`IndexError::NeedsRecovery`] for the states the read-write open would first change.
    pub fn open_read_only(path: &Path) -> Result<ReadOnlyIndex, IndexError> {
        open_read_only_with(path, migrate::MIGRATIONS)
    }
}

pub(crate) fn open_read_only_with(
    path: &Path,
    migrations: &[migrate::Migration],
) -> Result<ReadOnlyIndex, IndexError> {
    check_parent(crate::parent_of(path))?;
    let held = match open_registered_existing(path) {
        Ok(held) => held,
        // A missing main file with a sidecar: the read-write open would create the file and then
        // refuse the sidecar, so the refusal is the same here (and nothing is created).
        Err(IndexError::Fs(e)) if e.is_not_found() => {
            return Err(match Sidecars::read(path)?.first_present() {
                Some(suffix) => IndexError::StraySidecar { suffix },
                None => IndexError::Fs(e),
            });
        }
        Err(e) => return Err(e),
    };
    let file = held.file()?;
    if std::os::unix::fs::MetadataExt::nlink(
        &file
            .file()
            .metadata()
            .map_err(IndexError::io("inspecting index file"))?,
    ) > 1
    {
        return Err(IndexError::HardLinkedIndex);
    }
    // Sidecars change only when a writer closes; judge the state we read, retrying a few times
    // as `classify` does when they changed under the judgement.
    for _ in 0..crate::open::MAX_CLASSIFY_ATTEMPTS {
        let sc = Sidecars::read(path)?;
        match judge(sc, path, file, migrations) {
            Ok(conn) => {
                file.verify_path_unchanged(path)?;
                return Ok(ReadOnlyIndex { conn, _held: held });
            }
            Err(Step::Vanished) => {}
            Err(Step::Refused(e)) => {
                if same_presence(sc, Sidecars::read(path)?) {
                    return Err(e);
                }
            }
        }
    }
    Err(IndexError::SidecarsChanging)
}

fn same_presence(a: Sidecars, b: Sidecars) -> bool {
    a.wal.is_some() == b.wal.is_some()
        && a.shm.is_some() == b.shm.is_some()
        && a.journal.is_some() == b.journal.is_some()
}

fn judge(
    sc: Sidecars,
    path: &Path,
    file: &wardenlens_fsutil::PrivateFile,
    migrations: &[migrate::Migration],
) -> Result<Db, Step> {
    let len = file
        .file()
        .metadata()
        .map_err(IndexError::io("inspecting index file"))?
        .len();
    if len == 0 {
        return Err(match sc.first_present() {
            Some(suffix) => IndexError::StraySidecar { suffix },
            None => IndexError::Uninitialised,
        }
        .into());
    }
    let (head, wal_mode) = read_header(file.file())?;
    check_sidecars(wal_mode, sc)?;
    let conn = if wal_is_usable(sc, path, &head)? {
        if sc.shm.is_none() {
            return Err(IndexError::NeedsRecovery.into());
        }
        wal_verdict(path, file, migrations)?;
        open_wal_probe(path, file)?
    } else {
        let conn = open_immutable(path, file)?;
        judge_view(&conn, migrations)?;
        conn
    };
    if migrate::user_version(&conn)? < migrate::latest(migrations) {
        return Err(IndexError::NeedsMigration.into());
    }
    Ok(conn)
}
