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
//!    (too new is refused here), exactly the schema objects of that version, and `quick_check`.
//!    Without a `-wal` this is an `immutable=1` read-only open of the file. With a non-empty
//!    `-wal` it is a read-write open of a **private copy** of the main file and the `-wal` in a
//!    `0700` scratch directory, so SQLite replays the copy, never the original.
//! 6. Only then is the file opened read-write (`SQLITE_OPEN_NOFOLLOW`) and the device and inode
//!    compared again; pragmas are set and read back; migrations run.
//!
//! Residual trust: the `-wal` is judged by what its replay produces, so a `-wal` copied from
//! another copy of *this* index (same uid, mode `0600`, private directory) is accepted. That
//! needs the same privileges as editing the index itself.

use std::fs::File;
use std::os::unix::fs::{FileExt, MetadataExt};
use std::path::Path;
use std::time::Duration;

use rusqlite::{Connection, OpenFlags, TransactionBehavior};
use wardenlens_fsutil::{
    FsError, PrivateFile, Scratch, check_parent, copy_bounded, immutable_uri, open_private_file,
    open_sidecar, sidecar_len,
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
/// How often a copy that raced a writer is repeated before the open reports `Busy`.
const PROBE_ATTEMPTS: u32 = 4;
const WAL_MAGICS: [u32; 2] = [0x377f_0682, 0x377f_0683];

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
                FsError::WrongOwner { .. } | FsError::InsecureMode { .. } => {
                    IndexError::InsecureSidecar { suffix }
                }
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

/// The `-wal` header must be a WAL header of the page size of the main file.
fn check_wal_header(wal: &File, main_header: &[u8; HEADER_LEN]) -> Result<(), IndexError> {
    let mut head = [0u8; 32];
    match wal.read_exact_at(&mut head, 0) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
            return Err(IndexError::ForeignWal);
        }
        Err(e) => return Err(IndexError::io("reading wal header")(e)),
    }
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
    match (be(&head, 0), be(&head, 8)) {
        (Some(magic), Some(page)) if WAL_MAGICS.contains(&magic) && Some(page) == main_page => {
            Ok(())
        }
        _ => Err(IndexError::ForeignWal),
    }
}

/// What the read-only probes check, on the settled view `conn`: `application_id`, then
/// `user_version` (too new or negative is refused), then exactly the schema objects of that
/// version, then `quick_check`.
fn judge_view(conn: &Connection, migrations: &[Migration]) -> Result<(), IndexError> {
    let found = app_id(conn)?;
    if found != APPLICATION_ID {
        return Err(IndexError::WrongApplicationId { found });
    }
    let version = migrate::user_version(conn)?;
    migrate::check_not_newer(version, migrations)?;
    let mut stmt =
        sql::prepare(conn, sql::SCHEMA_OBJECTS).map_err(corruption_or("inspect schema"))?;
    let mut rows = stmt.query([]).map_err(corruption_or("inspect schema"))?;
    let mut seen: Vec<(String, String)> = Vec::new();
    while let Some(row) = rows.next().map_err(corruption_or("inspect schema"))? {
        let pair = (
            row.get::<_, String>(0)
                .map_err(corruption_or("inspect schema"))?,
            row.get::<_, String>(1)
                .map_err(corruption_or("inspect schema"))?,
        );
        seen.push(pair);
        if seen.len() > 64 {
            return Err(IndexError::UnexpectedSchema);
        }
    }
    let mut want: Vec<(String, String)> = Vec::new();
    for m in migrations.iter().filter(|m| m.version <= version) {
        for (kind, name) in m.objects {
            want.push(((*kind).to_owned(), (*name).to_owned()));
        }
    }
    if version > 0 {
        want.push(("table".to_owned(), "sqlite_sequence".to_owned()));
    }
    seen.sort();
    want.sort();
    if seen != want {
        return Err(IndexError::UnexpectedSchema);
    }
    let verdict: String = sql::query_row(conn, sql::QUICK_CHECK, [], |r| r.get(0))
        .map_err(corruption_or("integrity check"))?;
    if verdict != "ok" {
        return Err(IndexError::Damaged);
    }
    Ok(())
}

/// A SQLite failure while reading a file we do not yet trust: corruption codes mean the file is
/// damaged (or not a database), anything else is passed on.
fn corruption_or(op: &'static str) -> impl FnOnce(rusqlite::Error) -> IndexError {
    move |e| match (&e, e.sqlite_error_code()) {
        (_, Some(rusqlite::ErrorCode::DatabaseCorrupt | rusqlite::ErrorCode::NotADatabase))
        | (rusqlite::Error::InvalidColumnType(..), _) => IndexError::Damaged,
        _ => IndexError::sqlite(op)(e),
    }
}

/// Read-only identification of a file with no `-wal`: `immutable=1` never writes a journal,
/// `-wal` or `-shm` and ignores any present.
fn probe_immutable(
    path: &Path,
    file: &PrivateFile,
    migrations: &[Migration],
) -> Result<(), IndexError> {
    let conn = Connection::open_with_flags(
        immutable_uri(path)?,
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_URI
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(corruption_or("open"))?;
    file.verify_path_unchanged(path)?;
    judge_view(&conn, migrations)
}

type Stamp = (u64, i64, i64, u64);

fn stamp(m: &std::fs::Metadata) -> Stamp {
    (m.ino(), m.mtime(), m.mtime_nsec(), m.len())
}

/// Identification of a file with a non-empty `-wal`: the main file and the `-wal` are copied
/// (through verified descriptors, bounded) into a private scratch directory and the **copy** is
/// opened read-write, so SQLite replays the copy and the originals are only read. A copy that
/// raced a writer (the stamps of the originals moved) is repeated.
fn probe_wal_copy(
    path: &Path,
    file: &PrivateFile,
    head: &[u8; HEADER_LEN],
    migrations: &[Migration],
) -> Result<(), IndexError> {
    let parent = crate::parent_of(path);
    let wal_path = sidecar_path(path, "-wal");
    for _ in 0..PROBE_ATTEMPTS {
        // O_NONBLOCK: a FIFO in place of the `-wal` must not block (it was refused by `lstat`
        // already; this covers a swap).
        let wal = open_sidecar(Path::new(&wal_path))?;
        let wal_meta = wal.metadata().map_err(IndexError::io("inspecting wal"))?;
        if !wal_meta.is_file() {
            return Err(IndexError::BadSidecar { suffix: "-wal" });
        }
        check_wal_header(&wal, head)?;
        let main_before = stamp(
            &file
                .file()
                .metadata()
                .map_err(IndexError::io("inspecting index"))?,
        );
        let wal_before = stamp(&wal_meta);
        let scratch = Scratch::new(parent)?;
        let copy = scratch.path().join("index.db");
        let copy_wal = scratch.path().join("index.db-wal");
        let copied = copy_bounded(file.file(), &copy)? && copy_bounded(&wal, &copy_wal)?;
        if !copied {
            return Err(IndexError::TooLargeToProbe);
        }
        let main_after = stamp(
            &file
                .file()
                .metadata()
                .map_err(IndexError::io("inspecting index"))?,
        );
        let wal_after = std::fs::symlink_metadata(&wal_path)
            .map(|m| stamp(&m))
            .map_err(IndexError::io("inspecting wal"))?;
        if main_after != main_before || wal_after != wal_before {
            continue; // a writer was active: the copy may be torn
        }
        file.verify_path_unchanged(path)?;
        let conn = Connection::open_with_flags(
            &copy,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .map_err(corruption_or("open copy"))?;
        return match judge_view(&conn, migrations) {
            // The replay gave something that is not our index: the `-wal` is not ours.
            Err(
                IndexError::WrongApplicationId { .. }
                | IndexError::UnexpectedSchema
                | IndexError::Damaged,
            ) => Err(IndexError::ForeignWal),
            other => other,
        };
    }
    Err(IndexError::Busy {
        op: "identify index",
    })
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
    if sc.wal.is_some_and(|n| n > 0) {
        probe_wal_copy(path, file, &head, migrations)?;
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
    sql::execute_batch(&tx, sql::SET_APP_ID).map_err(IndexError::sqlite("set application id"))?;
    tx.commit().map_err(IndexError::sqlite("commit claim"))
}

fn pragma_i64(conn: &Connection, stmt: &'static str, op: &'static str) -> Result<i64, IndexError> {
    sql::query_row(conn, stmt, [], |r| r.get(0)).map_err(IndexError::sqlite(op))
}

/// Sets the connection pragmas and reads each back.
fn apply_pragmas(conn: &Connection) -> Result<(), IndexError> {
    conn.busy_timeout(BUSY_TIMEOUT)
        .map_err(IndexError::sqlite("busy timeout"))?;
    let mode: String = sql::query_row(conn, sql::SET_WAL, [], |r| r.get(0))
        .map_err(IndexError::sqlite("journal mode"))?;
    if !mode.eq_ignore_ascii_case("wal") {
        return Err(IndexError::PragmaRefused {
            pragma: "journal_mode",
        });
    }
    sql::execute_batch(conn, sql::SET_SYNC).map_err(IndexError::sqlite("synchronous"))?;
    sql::execute_batch(conn, sql::SET_FK).map_err(IndexError::sqlite("foreign keys"))?;
    // `journal_size_limit` returns a row, so it goes through `query_row`.
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

/// An open connection and the descriptor whose identity was checked.
pub(crate) struct Opened {
    pub(crate) conn: Connection,
    pub(crate) file: PrivateFile,
}

/// The whole checked open. `between` runs after our own checks and before SQLite opens the path
/// (the window a swap needs); tests use it.
pub(crate) fn open(
    path: &Path,
    migrations: &[Migration],
    between: impl FnOnce(),
) -> Result<Opened, IndexError> {
    check_parent(crate::parent_of(path))?;
    let file = open_private_file(path)?;
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
    Ok(Opened { conn, file })
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
