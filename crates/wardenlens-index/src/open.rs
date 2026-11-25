//! The checked open of the index file (ADR 0005 section 5, defect pattern P3).
//!
//! **Invariant: no read-write SQLite connection is opened on the file until its identity and its
//! sidecars have been proven by means no sidecar can influence.** SQLite replays a hot
//! `-journal` and a `-wal` on the first read, and checkpoints (writes the main file) when the last
//! connection closes, so even a refused open through a read-write connection can modify the file.
//!
//! Order:
//! 1. `check_parent` (fsutil): the directory is ours and not writable by others.
//! 2. `open_private_file` (fsutil): `O_NOFOLLOW | O_NONBLOCK`, `fstat` regular file, owner, mode.
//! 3. Every sidecar (`-wal`, `-shm`, `-journal`) is `lstat`ed (`sidecar_len`): a symlink or
//!    non-regular file, another owner, or any group/other bit is refused. SQLite opens these
//!    itself, so they are checked here.
//! 4. The 100-byte header is read through our descriptor: magic, `application_id`, journal mode.
//!    With the sidecar state it selects the row of the table in `classify` (the matrix tested in
//!    `open_tests`); a sidecar that cannot belong to the file in that state is refused.
//! 5. The identity of the *settled* state is judged read-only: `application_id`, `user_version`
//!    (too new is refused here), every `sqlite_master` row against a reference built from the
//!    migrations, and `integrity_check`. Without a usable `-wal` this is an `immutable=1`
//!    read-only open. With a valid non-empty `-wal` it is a `SQLITE_OPEN_READ_ONLY` connection on
//!    the real files (no copy of the main file, so no size limit); see `probe_wal_readonly` for
//!    what that does and does not write, and ADR 0005 section 5 for the decision.
//! 6. Only then is the file opened read-write (`SQLITE_OPEN_NOFOLLOW`) and the device and inode
//!    compared again; pragmas are set and read back; migrations run.
//!
//! Residual trust: the `-wal` is judged by what its replay produces and by its instance id, so a
//! `-wal` copied from an older state of *this* index (same uid, mode `0600`, private directory) is accepted. That
//! needs the same privileges as editing the index itself.

use std::fs::File;
use std::os::unix::fs::FileExt;
use std::path::Path;
use std::time::Duration;

use rusqlite::{Connection, OpenFlags, TransactionBehavior};
use wardenlens_fsutil::{
    FileLock, FsError, PrivateFile, check_parent, immutable_uri, open_private_file, open_sidecar,
    sidecar_len,
};

use crate::error::IndexError;
use crate::migrate::{self, Migration};
use crate::sql;

/// `WLIX`, the `application_id` of an index file.
pub(crate) const APPLICATION_ID: u32 = 0x574C_4958;
/// How long a connection waits for a competing writer.
pub const BUSY_TIMEOUT: Duration = Duration::from_secs(5);
/// Largest the `-wal` file is kept at after a checkpoint, in bytes.
pub(crate) const JOURNAL_SIZE_LIMIT: i64 = 64 * 1024 * 1024;

const SQLITE_MAGIC: &[u8; 16] = b"SQLite format 3\0";
const HEADER_LEN: usize = 100;
const SUFFIXES: [&str; 3] = ["-wal", "-shm", "-journal"];
const WAL_MAGICS: [u32; 2] = [0x377f_0682, 0x377f_0683];
/// Most bytes of a `-wal` read to prove it entirely zero.
const MAX_ZERO_SCAN: u64 = wardenlens_fsutil::MAX_COPY_LEN;

/// Presence and length of each sidecar (`None` = absent), in the order of [`SUFFIXES`].
#[derive(Debug, Clone, Copy)]
struct Sidecars {
    wal: Option<u64>,
    shm: Option<u64>,
    journal: Option<u64>,
}

impl Sidecars {
    fn read(path: &Path) -> Result<Self, IndexError> {
        let mut out = [None; 3];
        for (slot, suffix) in out.iter_mut().zip(SUFFIXES) {
            *slot = sidecar_len(Path::new(&sidecar_path(path, suffix))).map_err(|e| match e {
                FsError::NotRegular => IndexError::BadSidecar { suffix },
                FsError::WrongOwner { .. }
                | FsError::InsecureMode { .. }
                | FsError::HardLinked { .. } => IndexError::InsecureSidecar { suffix },
                other => IndexError::Fs(other),
            })?;
        }
        let [wal, shm, journal] = out;
        Ok(Self { wal, shm, journal })
    }

    fn first_present(self) -> Option<&'static str> {
        [
            (self.wal, "-wal"),
            (self.shm, "-shm"),
            (self.journal, "-journal"),
        ]
        .into_iter()
        .find_map(|(len, suffix)| len.map(|_| suffix))
    }
}

/// What the file is, before anything is opened read-write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// Zero length, no sidecar.
    New,
    /// An index database whose settled state was proven read-only.
    Ours,
}

fn sidecar_path(path: &Path, suffix: &str) -> std::ffi::OsString {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    name
}

/// The journal-mode bytes and `application_id` of the header, or the refusal for a file that is
/// not an index. `Ok((is_wal, app_id))`.
fn read_header(file: &File) -> Result<([u8; HEADER_LEN], bool), IndexError> {
    let mut head = [0u8; HEADER_LEN];
    match file.read_exact_at(&mut head, 0) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
            return Err(IndexError::NotAnIndex);
        }
        Err(e) => return Err(IndexError::io("reading index header")(e)),
    }
    if head.get(..16) != Some(SQLITE_MAGIC.as_slice()) {
        return Err(IndexError::NotAnIndex);
    }
    let found = head
        .get(68..72)
        .and_then(|b| <[u8; 4]>::try_from(b).ok())
        .map(u32::from_be_bytes)
        .ok_or(IndexError::NotAnIndex)?;
    if found != APPLICATION_ID {
        return Err(IndexError::WrongApplicationId { found });
    }
    match (head.get(18), head.get(19)) {
        (Some(2), Some(2)) => Ok((head, true)),
        (Some(1), Some(1)) => Ok((head, false)),
        _ => Err(IndexError::NotAnIndex),
    }
}

/// The sidecar rule for a non-empty file with an index header. The table (tested cell by cell):
///
/// | sidecar | rollback header | WAL header |
/// |---|---|---|
/// | `-journal` non-empty | `PendingJournal` | `PendingJournal` (WAL never writes one) |
/// | `-journal` empty | `StraySidecar` | `StraySidecar` |
/// | `-wal`, `-shm` any | `StraySidecar` | allowed (judged by `probe`) |
fn check_sidecars(wal_mode: bool, sc: Sidecars) -> Result<(), IndexError> {
    match sc.journal {
        Some(0) => return Err(IndexError::StraySidecar { suffix: "-journal" }),
        Some(_) => return Err(IndexError::PendingJournal),
        None => {}
    }
    if !wal_mode {
        if sc.wal.is_some() {
            return Err(IndexError::StraySidecar { suffix: "-wal" });
        }
        if sc.shm.is_some() {
            return Err(IndexError::StraySidecar { suffix: "-shm" });
        }
    }
    Ok(())
}

/// What the start of a `-wal` says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WalHeader {
    /// What a crash before the first frame leaves: a file that is entirely zero, or a file
    /// shorter than a header that is a prefix of a valid one. SQLite treats it as an empty WAL
    /// (and rewrites it), and so do we.
    Torn,
    /// A WAL header with the page size of the main file.
    Valid,
}

/// The WAL format version SQLite writes, in bytes 4..8 of the header (3007000).
const WAL_FORMAT_VERSION: u32 = 3_007_000;

/// True if every byte of `wal` (`len` long) is zero. Reads at most [`MAX_ZERO_SCAN`] bytes; a
/// longer file is never proven zero.
fn all_zero(wal: &File, len: u64) -> Result<bool, IndexError> {
    if len > MAX_ZERO_SCAN {
        return Ok(false);
    }
    let mut buf = vec![0u8; 64 * 1024];
    let mut at = 0u64;
    while at < len {
        let want = usize::try_from(len.saturating_sub(at)).map_or(buf.len(), |r| r.min(buf.len()));
        let window = buf.get_mut(..want).ok_or(IndexError::InvalidWal)?;
        wal.read_exact_at(window, at)
            .map_err(IndexError::io("reading wal"))?;
        if window.iter().any(|b| *b != 0) {
            return Ok(false);
        }
        at = at.saturating_add(u64::try_from(want).unwrap_or(u64::MAX));
    }
    Ok(true)
}

/// Classifies the `-wal` against the main file's page size. Only a file SQLite could have
/// written is `Torn`: **entirely** zero, or shorter than a header and a prefix of one (a WAL
/// magic followed by the format version, then the page size if it is present). Anything else
/// that is not a valid header is [`IndexError::InvalidWal`] and is never opened read-write, so it
/// is never deleted or rewritten.
fn check_wal_header(wal: &File, main_header: &[u8; HEADER_LEN]) -> Result<WalHeader, IndexError> {
    let len = wal
        .metadata()
        .map_err(IndexError::io("inspecting wal"))?
        .len();
    if all_zero(wal, len)? {
        return Ok(WalHeader::Torn);
    }
    let mut head = [0u8; 32];
    let want = usize::try_from(len.min(32)).unwrap_or(32);
    let got = head.get_mut(..want).ok_or(IndexError::InvalidWal)?;
    wal.read_exact_at(got, 0)
        .map_err(IndexError::io("reading wal header"))?;
    let be = |b: &[u8], at: usize| {
        b.get(at..at.saturating_add(4))
            .and_then(|s| <[u8; 4]>::try_from(s).ok())
            .map(u32::from_be_bytes)
    };
    // The main file stores the page size as two bytes at 16, where 1 means 65536.
    let main_page = main_header
        .get(16..18)
        .and_then(|s| <[u8; 2]>::try_from(s).ok())
        .map(u16::from_be_bytes)
        .map(|p| if p == 1 { 65_536_u32 } else { u32::from(p) });
    if want < 32 {
        // A header write cut short: the bytes present must be a prefix of magic + version
        // (+ page size). Magic alone, or any other bytes, is not.
        let seen = head.get(..want).ok_or(IndexError::InvalidWal)?;
        let prefix = WAL_MAGICS.iter().any(|m| {
            let mut full = [0u8; 12];
            full[..4].copy_from_slice(&m.to_be_bytes());
            full[4..8].copy_from_slice(&WAL_FORMAT_VERSION.to_be_bytes());
            full[8..12].copy_from_slice(&main_page.unwrap_or(0).to_be_bytes());
            let n = want.min(12);
            want >= 8 && seen.get(..n) == full.get(..n)
        });
        return if prefix {
            Ok(WalHeader::Torn)
        } else {
            Err(IndexError::InvalidWal)
        };
    }
    if !be(&head, 0).is_some_and(|m| WAL_MAGICS.contains(&m)) {
        return Err(IndexError::InvalidWal);
    }
    if be(&head, 8) == main_page {
        Ok(WalHeader::Valid)
    } else {
        Err(IndexError::ForeignWal)
    }
}

/// What the read-only probes check, on the settled view `conn`: `application_id`, then
/// `user_version` (too new or negative is refused), then **every `sqlite_master` row**
/// (`type, name, tbl_name, sql`) against a reference built from the compiled-in migrations up to
/// that version, then `integrity_check` (which, unlike `quick_check`, compares every index with
/// its table, so a `-wal` from a diverged copy of this index is caught). The integrity check reads
/// the whole file once at start-up; its cost grows linearly with the index, a few seconds per
/// hundred megabytes.
fn judge_view(conn: &Connection, migrations: &[Migration]) -> Result<InstanceId, IndexError> {
    let found = app_id(conn)?;
    if found != APPLICATION_ID {
        return Err(IndexError::WrongApplicationId { found });
    }
    let version = migrate::user_version(conn)?;
    migrate::check_not_newer(version, migrations)?;
    let seen = migrate::schema_rows(conn).map_err(corruption_or("inspect schema"))?;
    let want = migrate::reference_schema(migrations, version)?;
    if seen != want {
        return Err(IndexError::UnexpectedSchema);
    }
    let verdict: String = sql::query_row(conn, sql::INTEGRITY_CHECK, [], |r| r.get(0))
        .map_err(corruption_or("integrity check"))?;
    if verdict != "ok" {
        return Err(IndexError::Damaged);
    }
    instance_id(conn)
}

/// The random per-index id created with the file (`index_meta`, ADR 0005 section 5). It ties a
/// `-wal` to its main file: a `-wal` replayed onto another index's main file changes it.
type InstanceId = Vec<u8>;

fn instance_id(conn: &Connection) -> Result<InstanceId, IndexError> {
    let id: Vec<u8> = sql::query_row(conn, sql::INSTANCE_ID, [], |r| r.get(0))
        .map_err(corruption_or("read instance id"))?;
    if id.len() == 16 {
        Ok(id)
    } else {
        Err(IndexError::Damaged)
    }
}

/// A SQLite failure while reading a file we do not yet trust: corruption codes mean the file is
/// damaged (or not a database), anything else is passed on.
pub(crate) fn corruption_or(op: &'static str) -> impl FnOnce(rusqlite::Error) -> IndexError {
    move |e| match (&e, e.sqlite_error_code()) {
        (_, Some(rusqlite::ErrorCode::DatabaseCorrupt | rusqlite::ErrorCode::NotADatabase))
        | (rusqlite::Error::InvalidColumnType(..), _) => IndexError::Damaged,
        _ => IndexError::sqlite(op)(e),
    }
}

/// Opens the main file alone, read-only, ignoring any `-wal` and writing nothing: `immutable=1`.
fn open_immutable(path: &Path, file: &PrivateFile) -> Result<Connection, IndexError> {
    let conn = Connection::open_with_flags(
        immutable_uri(path)?,
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_URI
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(corruption_or("open"))?;
    file.verify_path_unchanged(path)?;
    Ok(conn)
}

/// Read-only identification of a file with no usable `-wal`.
fn probe_immutable(
    path: &Path,
    file: &PrivateFile,
    migrations: &[Migration],
) -> Result<(), IndexError> {
    judge_view(&open_immutable(path, file)?, migrations).map(|_| ())
}

/// The connection of the `-wal` probe: `SQLITE_OPEN_READ_ONLY` on the real files with
/// `NO_CKPT_ON_CLOSE`. These are the guards that keep the probe from writing the main file or the
/// `-wal` (pinned by `probe_connection_is_read_only_and_never_checkpoints`):
/// - **no checkpoint and no `-wal` delete on close** (`NO_CKPT_ON_CLOSE`): a checkpoint is the
///   only thing that writes the main file from the `-wal`, and the last-connection close would
///   otherwise run one and unlink the `-wal`;
/// - **a read-only pager** (`SQLITE_OPEN_READ_ONLY`): no write transaction can begin, so no frame
///   is appended to the `-wal` and no page is written to the main file;
/// - our own main-file descriptor is `O_RDONLY` (checked by fsutil's tests), and the connection
///   opens the main file read-only.
///
/// (`SQLITE_READONLY` from a checkpoint is *not* a guard here: the `-wal` itself is opened
/// read-write by SQLite.) The connection does create or update the `-shm`.
pub(crate) fn open_wal_probe(path: &Path, file: &PrivateFile) -> Result<Connection, IndexError> {
    let conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(corruption_or("open"))?;
    conn.set_db_config(
        rusqlite::config::DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE,
        true,
    )
    .map_err(IndexError::sqlite("db config"))?;
    file.verify_path_unchanged(path)?;
    conn.busy_timeout(BUSY_TIMEOUT)
        .map_err(IndexError::sqlite("busy timeout"))?;
    Ok(conn)
}

/// Identification of a file with a valid non-empty `-wal`, with **no copy of the main file**:
/// 1. the main file alone (`immutable=1`, `-wal` ignored) must be a sound index of ours: this is
///    the verdict for a damaged or foreign main file, so such a file is never blamed on the
///    `-wal`; its instance id is read;
/// 2. the real files are opened with [`open_wal_probe`] so SQLite replays the `-wal` into its
///    in-memory view, and the view is judged like any index;
/// 3. the view's instance id must equal the main file's: a `-wal` of another index (same
///    application id, schema and a clean integrity check) is `ForeignWal`. This works because
///    every commit of this crate rewrites the page that holds the id (`sql::write_tx`), so every
///    non-empty `-wal` carries it. If the main file's id cannot be read (a page torn by a crash in
///    the middle of a checkpoint) the replayed view decides; `ForeignWal` needs both ids readable
///    and different. A torn main page plus a foreign `-wal` with our header cannot be told apart
///    (it needs the privileges to edit the index).
///
/// The probe never writes the main file or the `-wal` (guards on [`open_wal_probe`]). It does
/// create or update the `-shm` (the wal-index every first connection rebuilds from the `-wal`).
/// **On refusal** a `-shm` that did not exist is removed again so the directory is byte-identical;
/// **after success it is never removed**, because the read-write open uses it. Both are safe
/// because `Index::open` holds an exclusive `flock` on the verified main descriptor from
/// `classify` until the read-write open is established, so no other `Index::open` can be
/// attached to a `-shm` we created, and a `-shm` that existed before the probe is never touched
/// by removal.
pub(crate) fn probe_wal_readonly(
    path: &Path,
    file: &PrivateFile,
    migrations: &[Migration],
) -> Result<(), IndexError> {
    let shm = std::path::PathBuf::from(sidecar_path(path, "-shm"));
    let shm_existed = sidecar_len(&shm)?.is_some();
    let verdict = wal_verdict(path, file, migrations);
    if verdict.is_err() && !shm_existed {
        // ERR-4: best effort; the `-shm` is derived state and the next open rebuilds it.
        let _ = std::fs::remove_file(&shm);
    }
    verdict
}

fn wal_verdict(
    path: &Path,
    file: &PrivateFile,
    migrations: &[Migration],
) -> Result<(), IndexError> {
    let main_view = open_immutable(path, file)?;
    // The id of the main file alone. If the main file cannot answer because it is damaged or torn
    // (a crash in the middle of a checkpoint leaves a page half new), it has no readable id and
    // the replayed view decides; any other failure (I/O, busy) is the real error.
    let main_id = match instance_id(&main_view) {
        Ok(id) => Some(id),
        Err(e) if main_unreadable(&e) => None,
        Err(e) => return Err(e),
    };
    let main_verdict = judge_view(&main_view, migrations);
    drop(main_view);
    let conn = open_wal_probe(path, file)?;
    match judge_view(&conn, migrations) {
        // The replay is an index of ours: it must be this index's, unless the main file's id is
        // unreadable. Residual: a torn main page plus a foreign `-wal` with our header cannot be
        // told apart; that needs the privileges to edit the index.
        Ok(view_id) => match main_id {
            Some(id) if id != view_id => Err(IndexError::ForeignWal),
            _ => Ok(()),
        },
        Err(
            IndexError::WrongApplicationId { .. }
            | IndexError::UnexpectedSchema
            | IndexError::Damaged,
        ) => match main_verdict {
            // The main file is itself not a sound index of ours: that is the cause.
            Err(own) => Err(own),
            // The main file is sound and the replay is not ours: the `-wal` is.
            Ok(_) => Err(IndexError::ForeignWal),
        },
        Err(other) => Err(other),
    }
}

/// True if a failed read of the main file alone means "this file cannot say" (damaged, torn,
/// schema unreadable), as opposed to a real error (I/O, busy, permissions) that must be reported.
fn main_unreadable(e: &IndexError) -> bool {
    use rusqlite::ErrorCode::{
        CannotOpen, DiskFull, NoLargeFileSupport, OutOfMemory, PermissionDenied, ReadOnly,
        SystemIoFailure,
    };
    match e {
        IndexError::Damaged | IndexError::UnexpectedSchema => true,
        IndexError::Sqlite { code, .. } => !matches!(
            code,
            Some(
                SystemIoFailure
                    | CannotOpen
                    | DiskFull
                    | OutOfMemory
                    | PermissionDenied
                    | ReadOnly
                    | NoLargeFileSupport
            )
        ),
        _ => false,
    }
}

/// Judges the file without any read-write connection.
fn classify(path: &Path, file: &PrivateFile, migrations: &[Migration]) -> Result<Kind, IndexError> {
    let sc = Sidecars::read(path)?;
    let len = file
        .file()
        .metadata()
        .map_err(IndexError::io("inspecting index file"))?
        .len();
    if len == 0 {
        // SQLite deletes or replays a sidecar next to a zero-page database on first open.
        return match sc.first_present() {
            Some(suffix) => Err(IndexError::StraySidecar { suffix }),
            None => Ok(Kind::New),
        };
    }
    let (head, wal_mode) = read_header(file.file())?;
    check_sidecars(wal_mode, sc)?;
    let usable_wal = match sc.wal {
        Some(n) if n > 0 => {
            let wal = open_sidecar(Path::new(&sidecar_path(path, "-wal")))?;
            if !wal
                .metadata()
                .map_err(IndexError::io("inspecting wal"))?
                .is_file()
            {
                return Err(IndexError::BadSidecar { suffix: "-wal" });
            }
            check_wal_header(&wal, &head)? == WalHeader::Valid
        }
        _ => false,
    };
    if usable_wal {
        probe_wal_readonly(path, file, migrations)?;
    } else {
        probe_immutable(path, file, migrations)?;
    }
    Ok(Kind::Ours)
}

fn app_id(conn: &Connection) -> Result<u32, IndexError> {
    let raw: i64 = sql::query_row(conn, sql::GET_APP_ID, [], |r| r.get(0))
        .map_err(corruption_or("read application id"))?;
    // SQLite stores it as a signed 32-bit value; keep the bits.
    i32::try_from(raw)
        .map(i32::cast_unsigned)
        .map_err(|_| IndexError::NotAnIndex)
}

/// Claims a file that was empty: under `BEGIN IMMEDIATE`, set the `application_id` if nothing
/// else (another process, a file that grew) got there first.
fn claim_new(conn: &mut Connection) -> Result<(), IndexError> {
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(IndexError::sqlite("begin claim"))?;
    let found = app_id(&tx)?;
    if found == APPLICATION_ID {
        return Ok(()); // another process of ours created it a moment ago
    }
    let objects: i64 = sql::query_row(&tx, sql::OBJECT_COUNT, [], |r| r.get(0))
        .map_err(IndexError::sqlite("inspect schema"))?;
    if found != 0 || objects != 0 || migrate::user_version(&tx)? != 0 {
        return Err(IndexError::NotAnIndex);
    }
    sql::execute_unversioned(&tx, sql::BOOTSTRAP).map_err(IndexError::sqlite("bootstrap"))?;
    tx.commit().map_err(IndexError::sqlite("commit claim"))
}

fn pragma_i64(conn: &Connection, stmt: &'static str, op: &'static str) -> Result<i64, IndexError> {
    sql::query_row(conn, stmt, [], |r| r.get(0)).map_err(IndexError::sqlite(op))
}

/// Sets the connection pragmas and reads each back.
fn apply_pragmas(conn: &Connection) -> Result<(), IndexError> {
    conn.busy_timeout(BUSY_TIMEOUT)
        .map_err(IndexError::sqlite("busy timeout"))?;
    let mode: String = sql::query_row_unversioned(conn, sql::SET_WAL, |r| r.get(0))
        .map_err(IndexError::sqlite("journal mode"))?;
    if !mode.eq_ignore_ascii_case("wal") {
        return Err(IndexError::PragmaRefused {
            pragma: "journal_mode",
        });
    }
    sql::execute_unversioned(conn, sql::SET_SYNC).map_err(IndexError::sqlite("synchronous"))?;
    sql::execute_unversioned(conn, sql::SET_FK).map_err(IndexError::sqlite("foreign keys"))?;
    // `journal_size_limit` returns a row; SQLite reports it read-only (a connection setting).
    let _: i64 = pragma_i64(conn, sql::SET_JOURNAL_LIMIT, "journal size limit")?;
    let checks = [
        (sql::GET_SYNC, 2, "synchronous"),
        (sql::GET_FK, 1, "foreign_keys"),
        (
            sql::GET_JOURNAL_LIMIT,
            JOURNAL_SIZE_LIMIT,
            "journal_size_limit",
        ),
        (
            sql::GET_BUSY,
            i64::try_from(BUSY_TIMEOUT.as_millis()).unwrap_or(i64::MAX),
            "busy_timeout",
        ),
    ];
    for (query, want, pragma) in checks {
        if pragma_i64(conn, query, pragma)? != want {
            return Err(IndexError::PragmaRefused { pragma });
        }
    }
    Ok(())
}

/// Takes the exclusive `flock` on the verified descriptor, waiting at most `wait`. `flock` is
/// independent of SQLite's own POSIX locks on the file: it never blocks SQLite and SQLite never
/// blocks it, so it serialises only openers of this crate.
fn lock_file(file: &PrivateFile, wait: Duration) -> Result<FileLock, IndexError> {
    let start = std::time::Instant::now();
    loop {
        if let Some(lock) = file.try_lock_exclusive()? {
            return Ok(lock);
        }
        if start.elapsed() >= wait {
            return Err(IndexError::Busy {
                op: "lock index file",
            });
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// An open connection and the descriptor whose identity was checked.
pub(crate) struct Opened {
    pub(crate) conn: Connection,
    /// Unlocked, but its descriptor stays open for the life of the connection.
    pub(crate) lock: FileLock,
    pub(crate) file: PrivateFile,
}

/// The whole checked open. `between` runs after our own checks and before SQLite opens the path
/// (the window a swap needs); tests use it.
pub(crate) fn open(
    path: &Path,
    migrations: &[Migration],
    between: impl FnOnce(),
    lock_wait: Duration,
) -> Result<Opened, IndexError> {
    check_parent(crate::parent_of(path))?;
    let file = open_private_file(path)?;
    // Excludes every other `Index::open` on this file from here to the end of this function: the
    // probes and the read-write open must not interleave with another opener's (a `-shm` one of
    // us created must not be attached to by another process, and two first creators must not
    // both claim the file). Unlocked after migrations; the descriptor then lives on in `Opened`.
    let lock = lock_file(&file, lock_wait)?;
    let kind = match classify(path, &file, migrations) {
        Ok(kind) => kind,
        Err(e) => {
            discard_if_created(path, &file);
            return Err(e);
        }
    };
    between();
    let mut conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(IndexError::sqlite("open"))?;
    file.verify_path_unchanged(path)?;
    conn.busy_timeout(BUSY_TIMEOUT)
        .map_err(IndexError::sqlite("busy timeout"))?;
    match kind {
        Kind::New => {
            if let Err(e) = claim_new(&mut conn) {
                drop(conn);
                discard_if_created(path, &file);
                return Err(e);
            }
        }
        Kind::Ours => {
            // The probe judged the settled state; this is the same check on the real connection.
            let found = app_id(&conn)?;
            if found != APPLICATION_ID {
                return Err(IndexError::WrongApplicationId { found });
            }
            migrate::check_not_newer(migrate::user_version(&conn)?, migrations)?;
        }
    }
    apply_pragmas(&conn)?;
    migrate::run(&mut conn, migrations)?;
    lock.unlock();
    Ok(Opened { conn, lock, file })
}

/// Removes the empty file this call created when the open is refused before anything was
/// written, so a refusal leaves no litter. Only if the path still names our file.
fn discard_if_created(path: &Path, file: &PrivateFile) {
    if file.created() && file.verify_path_unchanged(path).is_ok() {
        // ERR-4: best effort; an empty file left behind is harmless and is refused or adopted
        // by the next open the same way.
        let _ = std::fs::remove_file(path);
    }
}
