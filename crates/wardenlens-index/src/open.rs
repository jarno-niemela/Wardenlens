//! The checked open of the index file (ADR 0005 section 5, defect pattern P3).
//!
//! Order, and why:
//! 1. `open_private_file` (fsutil): `O_NOFOLLOW | O_NONBLOCK`, `fstat` regular file, owner, mode.
//! 2. Sidecars (`-wal`, `-shm`, `-journal`) are looked at with `lstat`: a symlink or a non-regular
//!    file is refused, because SQLite would open it itself.
//! 3. **Identity is proven from the 100-byte header read through our own descriptor, before any
//!    SQLite call**: magic, `application_id`, journal mode. A foreign database, a text file, a
//!    stray sidecar and an interrupted rollback journal are all refused here, so the file is never
//!    written. (`application_id` is set once, in rollback mode, before WAL is switched on, so the
//!    main file's header holds it even while a `-wal` holds newer pages.)
//! 4. Only then SQLite opens the path (`SQLITE_OPEN_NOFOLLOW`) and the device and inode are
//!    compared again.
//! 5. A new file is claimed under `BEGIN IMMEDIATE`; an existing one has its `user_version`
//!    checked **before** any pragma that could write, so a too-new file is left untouched.
//! 6. Pragmas, each verified by reading it back; then migrations.

use std::fs::File;
use std::os::unix::fs::FileExt;
use std::path::Path;
use std::time::Duration;

use rusqlite::{Connection, OpenFlags, TransactionBehavior};
use wardenlens_fsutil::{PrivateFile, open_private_file};

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
const SIDECARS: [&str; 3] = ["-wal", "-shm", "-journal"];

/// What `lstat` says about a sidecar.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Sidecar {
    Absent,
    /// A regular file of length zero (SQLite ignores a zero-length `-journal`).
    Empty,
    Present,
}

/// What the file is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// Zero length: nothing there yet.
    New,
    /// An index database: right `application_id`, journal mode consistent with its sidecars.
    Ours,
}

fn sidecar_path(path: &Path, suffix: &str) -> std::ffi::OsString {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    name
}

fn sidecar_state(path: &Path, suffix: &'static str) -> Result<Sidecar, IndexError> {
    match Path::new(&sidecar_path(path, suffix)).symlink_metadata() {
        Ok(m) if m.is_file() => Ok(if m.len() == 0 {
            Sidecar::Empty
        } else {
            Sidecar::Present
        }),
        Ok(_) => Err(IndexError::BadSidecar { suffix }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Sidecar::Absent),
        Err(e) => Err(IndexError::io("inspecting sidecar")(e)),
    }
}

fn sidecar_states(path: &Path) -> Result<[Sidecar; 3], IndexError> {
    let mut out = [Sidecar::Absent; 3];
    for (slot, suffix) in out.iter_mut().zip(SIDECARS) {
        *slot = sidecar_state(path, suffix)?;
    }
    Ok(out)
}

/// Judges the file from its header and sidecars alone: no SQLite call, no write.
fn classify(path: &Path, file: &File) -> Result<Kind, IndexError> {
    let states = sidecar_states(path)?;
    let len = file
        .metadata()
        .map_err(IndexError::io("inspecting index file"))?
        .len();
    if len == 0 {
        // SQLite deletes or replays a sidecar next to a zero-page database on first open.
        return match SIDECARS
            .iter()
            .zip(states)
            .find(|(_, s)| *s != Sidecar::Absent)
        {
            Some((suffix, _)) => Err(IndexError::StraySidecar { suffix }),
            None => Ok(Kind::New),
        };
    }
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
    let [wal, _, journal] = states;
    match (head.get(18), head.get(19)) {
        // WAL: a `-journal` is not consulted by SQLite.
        (Some(2), Some(2)) => Ok(Kind::Ours),
        (Some(1), Some(1)) => {
            if journal == Sidecar::Present {
                Err(IndexError::PendingJournal)
            } else if wal == Sidecar::Present {
                // Switching this file to WAL would make SQLite replay a `-wal` that is not ours.
                Err(IndexError::StraySidecar { suffix: "-wal" })
            } else {
                Ok(Kind::Ours)
            }
        }
        _ => Err(IndexError::NotAnIndex),
    }
}

fn app_id(conn: &Connection) -> Result<i64, IndexError> {
    conn.query_row(sql::GET_APP_ID, [], |r| r.get(0))
        .map_err(IndexError::sqlite("read application id"))
}

/// Claims a file that was empty: under `BEGIN IMMEDIATE`, set the `application_id` if nothing
/// else (another process, a file that grew) got there first.
fn claim_new(conn: &mut Connection) -> Result<(), IndexError> {
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(IndexError::sqlite("begin claim"))?;
    let found = app_id(&tx)?;
    if found == i64::from(APPLICATION_ID) {
        return Ok(()); // another process of ours created it a moment ago
    }
    let objects: i64 = tx
        .query_row(sql::OBJECT_COUNT, [], |r| r.get(0))
        .map_err(IndexError::sqlite("inspect schema"))?;
    if found != 0 || objects != 0 || migrate::user_version(&tx)? != 0 {
        return Err(IndexError::NotAnIndex);
    }
    tx.execute_batch(sql::SET_APP_ID)
        .map_err(IndexError::sqlite("set application id"))?;
    tx.commit().map_err(IndexError::sqlite("commit claim"))
}

fn pragma_i64(conn: &Connection, sql: &'static str, op: &'static str) -> Result<i64, IndexError> {
    conn.query_row(sql, [], |r| r.get(0))
        .map_err(IndexError::sqlite(op))
}

/// Sets the connection pragmas and reads each back.
fn apply_pragmas(conn: &Connection) -> Result<(), IndexError> {
    conn.busy_timeout(BUSY_TIMEOUT)
        .map_err(IndexError::sqlite("busy timeout"))?;
    let mode: String = conn
        .query_row(sql::SET_WAL, [], |r| r.get(0))
        .map_err(IndexError::sqlite("journal mode"))?;
    if !mode.eq_ignore_ascii_case("wal") {
        return Err(IndexError::PragmaRefused {
            pragma: "journal_mode",
        });
    }
    conn.execute_batch(sql::SET_SYNC)
        .map_err(IndexError::sqlite("synchronous"))?;
    conn.execute_batch(sql::SET_FK)
        .map_err(IndexError::sqlite("foreign keys"))?;
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
    let file = open_private_file(path)?;
    let kind = match classify(path, file.file()) {
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
            // Reads only: a file from a newer build must stay untouched.
            let found = app_id(&conn)?;
            if found != i64::from(APPLICATION_ID) {
                return Err(IndexError::WrongApplicationId {
                    found: u32::try_from(found).unwrap_or(u32::MAX),
                });
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
