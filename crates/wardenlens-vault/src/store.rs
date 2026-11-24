//! The SQLite store: checked open, entries, rekey (ADR 0006 sections 3 and 4).

use std::fmt;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, params};
use secrecy::{ExposeSecret, SecretString};
use wardenlens_core::entry::{EntryId, EntryKind};
use wardenlens_fsutil::{PrivateFile, open_private_file};
use wardenlens_secrets::{
    Credentials, KeyFile, MAX_RECORD_LEN, RecordKind, SecretsError, open, open_credentials, seal,
    seal_credentials,
};

use crate::error::VaultError;
use crate::validate::{check_credential, is_unscannable, normalize_text};

/// How `set` decides whether the leak scan can use a value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Scan {
    /// Mark the entry unscannable only when the value is too short.
    Normal,
    /// Only valid for the credential and secret kinds. The value is a credential or secret that already appears in tracked files (ADR 0006
    /// section 4): it would match its own public occurrences, so it is always unscannable.
    PublicOccurrence,
}

/// Whether the leak scan can use a stored value.
///
/// The flag does not yet apply the ADR 0006 section 7 squeeze table (zero-width characters,
/// soft hyphens): a value made only of those is flagged `Scannable` here. #75 recomputes the
/// flag for all kinds when it builds the matcher.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Scannability {
    /// The scan can use every needle of the value.
    Scannable,
    /// The value is too short or already public; the scan warns instead.
    Unscannable,
}

impl Scannability {
    /// True for [`Scannability::Unscannable`].
    #[must_use]
    pub fn is_unscannable(self) -> bool {
        self == Self::Unscannable
    }
}

/// Longest value (and each credential field) in bytes.
pub const MAX_VALUE_LEN: usize = wardenlens_secrets::MAX_VALUE_LEN;
/// Most entries a store may hold.
pub const MAX_ENTRIES: usize = 10_000;
/// How long a connection waits for a competing writer.
pub const BUSY_TIMEOUT: Duration = Duration::from_secs(5);

const SCHEMA_VERSION: i64 = 1;
const INVALID_ID: &str = "(invalid id)";
const KEYCHECK_ID: &str = "meta:keycheck";
const KEYCHECK_PLAINTEXT: &[u8] = b"wardenlens-vault-keycheck-v1";

/// A value as stored or returned. `Debug` redacts every field.
#[derive(Debug)]
#[non_exhaustive]
pub enum Value {
    /// For [`EntryKind::Credential`].
    Credential(Credentials),
    /// For every other kind.
    Text(SecretString),
}

/// A decrypted entry.
#[derive(Debug)]
#[non_exhaustive]
pub struct Entry {
    /// The entry kind.
    pub kind: EntryKind,
    /// The decrypted value.
    pub value: Value,
    /// True if the leak scan cannot use this value.
    pub unscannable: bool,
}

/// What `list` shows: never a value.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct EntryInfo {
    /// The entry id.
    pub id: EntryId,
    /// The entry kind.
    pub kind: EntryKind,
    /// True if the leak scan cannot use this value.
    pub unscannable: bool,
}

/// An open vault. Holds the checked file descriptor and the key for its lifetime.
pub struct Vault {
    conn: Connection,
    key: KeyFile,
    // Kept open so the inode (and the identity we compared) cannot be recycled.
    _file: PrivateFile,
}

impl fmt::Debug for Vault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Vault { .. }")
    }
}

/// Maps a core kind to its record kind. `EntryKind` is `#[non_exhaustive]`: a kind this build
/// does not know is refused rather than guessed.
fn record_kind(kind: EntryKind) -> Result<RecordKind, VaultError> {
    Ok(match kind {
        EntryKind::Credential => RecordKind::Credential,
        EntryKind::Secret => RecordKind::Secret,
        EntryKind::Host => RecordKind::Host,
        EntryKind::Mac => RecordKind::Mac,
        EntryKind::Serial => RecordKind::Serial,
        EntryKind::DisplayName => RecordKind::DisplayName,
        EntryKind::Other => RecordKind::Other,
        _ => return Err(VaultError::ValueKindMismatch { kind }),
    })
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_secs()).ok())
        .unwrap_or(0)
}

/// Refuses a path inside a git work tree (a `.git` entry in any ancestor of the parent).
fn refuse_work_tree(parent: &Path) -> Result<(), VaultError> {
    let canonical = parent
        .canonicalize()
        .map_err(VaultError::io("resolving directory"))?;
    if canonical
        .ancestors()
        .any(|dir| dir.join(".git").symlink_metadata().is_ok())
    {
        return Err(VaultError::InWorkTree);
    }
    Ok(())
}

/// The parent must be ours and not writable by group or others, or another user could swap the
/// file between our checks.
fn check_parent(parent: &Path) -> Result<(), VaultError> {
    let meta = std::fs::metadata(parent).map_err(VaultError::io("inspecting directory"))?;
    if meta.uid() != rustix::process::geteuid().as_raw() {
        return Err(VaultError::ParentWrongOwner);
    }
    if meta.mode() & 0o022 != 0 {
        return Err(VaultError::ParentWritable);
    }
    Ok(())
}

fn parent_of(path: &Path) -> Result<&Path, VaultError> {
    match path.parent() {
        Some(p) if p.as_os_str().is_empty() => Ok(Path::new(".")),
        Some(p) => Ok(p),
        None => Err(VaultError::NoParent),
    }
}

/// The open sequence of ADR 0006 section 4. `between` runs after our own descriptor is checked
/// and before SQLite opens the path (the window a swap attack needs); tests use it.
fn connect(
    path: &Path,
    key: &KeyFile,
    must_exist: bool,
    between: impl FnOnce(),
) -> Result<(Connection, PrivateFile), VaultError> {
    let parent = parent_of(path)?;
    refuse_work_tree(parent)?;
    check_parent(parent)?;
    if must_exist {
        match path.symlink_metadata() {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(VaultError::NotFound),
            Err(e) => return Err(VaultError::io("inspecting vault file")(e)),
        }
    }
    let file = open_private_file(path)?;
    if must_exist && file.created() {
        // Lost a race with a deletion: `open` never creates a file.
        let _ = std::fs::remove_file(path);
        return Err(VaultError::NotFound);
    }
    let len = file_len(&file)?;
    if len > 0 && !has_sqlite_header(file.file())? {
        // Somebody's data: never initialise over it, and refuse before SQLite touches it.
        return Err(if must_exist {
            VaultError::NotInitialized
        } else {
            VaultError::NotEmpty
        });
    }
    between();
    if len > 0 {
        // Read-only probe before ANY pragma: a foreign database must stay byte-for-byte intact.
        let is_vault = probe_existing(path, &file, must_exist.then_some(key))?;
        if !must_exist {
            return Err(if is_vault {
                VaultError::AlreadyInitialized
            } else {
                VaultError::NotEmpty
            });
        }
        if !is_vault {
            return Err(VaultError::NotInitialized);
        }
    } else if must_exist {
        return Err(VaultError::NotInitialized);
    } else if wal_present(path)? || journal_present(path)? {
        // SQLite deletes a sidecar next to a zero-page database on first open: never let it.
        return Err(VaultError::NotEmpty);
    }
    if !must_exist && file_len(&file)? > 0 {
        // The file grew since the probe found it empty.
        return Err(VaultError::NotEmpty);
    }
    let conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(VaultError::sqlite("open"))?;
    file.verify_path_unchanged(path)?;
    conn.busy_timeout(BUSY_TIMEOUT)
        .map_err(VaultError::sqlite("busy timeout"))?;
    // Invariant: a pragma that writes (journal_mode) only runs on a file that is empty (`create`)
    // or that the read-only probe above showed to be a vault (`open`).
    conn.execute_batch(
        "PRAGMA journal_mode = DELETE; PRAGMA synchronous = FULL; PRAGMA secure_delete = ON;",
    )
    .map_err(VaultError::sqlite("pragma"))?;
    Ok((conn, file))
}

fn file_len(file: &PrivateFile) -> Result<u64, VaultError> {
    Ok(file
        .file()
        .metadata()
        .map_err(VaultError::io("inspecting vault file"))?
        .len())
}

/// How often a pending `-journal` is re-checked while waiting for it to go away.
const JOURNAL_POLL: Duration = Duration::from_millis(50);

fn sidecar(path: &Path, suffix: &str) -> std::ffi::OsString {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    name
}

/// True if a `-wal` sidecar of any kind exists (a vault never uses WAL).
fn wal_present(path: &Path) -> Result<bool, VaultError> {
    match Path::new(&sidecar(path, "-wal")).symlink_metadata() {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(VaultError::io("inspecting sidecar")(e)),
        Ok(_) => Ok(true),
    }
}

/// True if a `-journal` exists that SQLite would not ignore. A zero-length regular file is
/// ignored, as SQLite does; anything else (including a non-regular file) counts.
fn journal_present(path: &Path) -> Result<bool, VaultError> {
    match Path::new(&sidecar(path, "-journal")).symlink_metadata() {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(VaultError::io("inspecting sidecar")(e)),
        Ok(m) => Ok(!(m.is_file() && m.len() == 0)),
    }
}

/// True if the header says rollback mode (bytes 18 and 19 are both 1). Only a short file means
/// "no"; any other read failure is passed on.
fn rollback_header(file: &PrivateFile) -> Result<bool, VaultError> {
    use std::os::unix::fs::FileExt;
    let mut mode = [0u8; 2];
    match file.file().read_exact_at(&mut mode, 18) {
        Ok(()) => Ok(mode == [1, 1]),
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Ok(false),
        Err(e) => Err(VaultError::io("reading vault header")(e)),
    }
}

/// Identifies the non-empty file as a vault or not before any read-write open. The probe itself
/// is entirely read-only (`immutable=1`): no pragma, lock, journal, `-wal` or `-shm` file is
/// ever written, so a foreign database stays byte-for-byte intact. A vault is:
/// - in rollback mode (header bytes 18 and 19 are both 1);
/// - without a `-wal` sidecar (a vault never uses WAL);
/// - exactly the vault schema (`meta(key, value)` and `entries`, no other table, index, trigger
///   or view);
/// - on `open` (`key` is `Some`): `schema_version = 1` and a keycheck row that decrypts under `key`.
///
/// A zero-length `-journal` is ignored, as SQLite does. A non-empty one means a writer is active
/// (or crashed), and an immutable read would ignore its contents, so the probe waits up to
/// [`BUSY_TIMEOUT`] for it to disappear (ADR 0006 section 3: a scan during a write waits). If it
/// stays: on `open`, a file that passes the full probe (exact schema and keycheck under the
/// supplied key) is proven to be the owner's vault and may be opened read-write, so SQLite rolls
/// back its own hot journal; in every other case (and on `create`) the result is
/// [`VaultError::PendingJournal`], never a "not a vault" verdict, and nothing is modified.
///
/// Returns `Ok(false)` for anything that is not a vault. Only "not a database" and schema errors
/// mean that; every other SQLite error (corruption, I/O and so on) is passed on.
///
/// # Errors
/// [`VaultError::UnsupportedSchema`], [`VaultError::NotInitialized`] (no keycheck row) and
/// [`VaultError::WrongKey`] for a file that has the vault schema but fails the `open` checks;
/// [`VaultError::PendingJournal`] as above.
fn probe_existing(
    path: &Path,
    file: &PrivateFile,
    key: Option<&KeyFile>,
) -> Result<bool, VaultError> {
    if !rollback_header(file)? || wal_present(path)? {
        return Ok(false);
    }
    let start = std::time::Instant::now();
    while journal_present(path)? {
        if start.elapsed() >= BUSY_TIMEOUT {
            let Some(key) = key else {
                return Err(VaultError::PendingJournal);
            };
            return match immutable_probe(path, file, Some(key)) {
                Ok(true) => Ok(true),
                Err(e @ VaultError::Fs(_)) => Err(e),
                Ok(false) | Err(_) => Err(VaultError::PendingJournal),
            };
        }
        std::thread::sleep(JOURNAL_POLL);
    }
    immutable_probe(path, file, key)
}

fn immutable_probe(
    path: &Path,
    file: &PrivateFile,
    key: Option<&KeyFile>,
) -> Result<bool, VaultError> {
    use std::ffi::OsString;
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
    let abs = std::path::absolute(path).map_err(VaultError::io("resolving vault path"))?;
    // `file://` + empty authority + the encoded absolute path, so a leading `//` stays path.
    let mut uri = b"file://".to_vec();
    for &b in abs.as_os_str().as_bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'/' | b'-' | b'_' | b'.' | b'~') {
            uri.push(b);
        } else {
            uri.extend_from_slice(format!("%{b:02X}").as_bytes());
        }
    }
    uri.extend_from_slice(b"?immutable=1");
    let conn = Connection::open_with_flags(
        OsString::from_vec(uri),
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_URI
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(VaultError::sqlite("open"))?;
    file.verify_path_unchanged(path)?;
    let rows = match read_identity(&conn) {
        Ok(Some(rows)) => rows,
        Ok(None) => return Ok(false),
        Err(e) if is_not_a_vault(&e) => return Ok(false),
        Err(e) => return Err(VaultError::sqlite("inspect schema")(e)),
    };
    let Some(key) = key else {
        return Ok(true);
    };
    if rows.version.as_deref() != Some(SCHEMA_VERSION.to_string().as_bytes()) {
        return Err(VaultError::UnsupportedSchema);
    }
    let record = rows.keycheck.ok_or(VaultError::NotInitialized)?;
    check_keycheck(key, &record)?;
    Ok(true)
}

/// The `meta` rows the probe reads.
struct MetaRows {
    version: Option<Vec<u8>>,
    keycheck: Option<Vec<u8>>,
}

/// A `meta` value as bytes. A missing row or a value that is not a blob is `None`: it counts as
/// a mismatch or a missing record, never as a conversion error.
fn meta_blob(conn: &Connection, key: &str) -> rusqlite::Result<Option<Vec<u8>>> {
    use rusqlite::types::ValueRef;
    conn.query_row("SELECT value FROM meta WHERE key = ?1", [key], |r| {
        Ok(match r.get_ref(0)? {
            ValueRef::Blob(b) => Some(b.to_vec()),
            _ => None,
        })
    })
    .optional()
    .map(Option::flatten)
}

/// `None` unless the schema is exactly the vault's two tables (and nothing else: no index,
/// trigger or view; the automatic indexes of the primary keys are not listed).
fn read_identity(conn: &Connection) -> rusqlite::Result<Option<MetaRows>> {
    let mut stmt = conn.prepare(
        "SELECT type, name FROM sqlite_master
         WHERE substr(name, 1, 17) != 'sqlite_autoindex_' ORDER BY type, name",
    )?;
    let objects = stmt
        .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let table = |n: &str| ("table".to_owned(), n.to_owned());
    if objects != [table("entries"), table("meta")] {
        return Ok(None);
    }
    let columns = |table: &str| -> rusqlite::Result<Vec<(String, String, bool, i64)>> {
        conn.prepare(&format!("PRAGMA table_info({table})"))?
            .query_map([], |r| Ok((r.get(1)?, r.get(2)?, r.get(3)?, r.get(5)?)))?
            .collect()
    };
    let col = |n: &str, t: &str, nn: bool, pk: i64| (n.to_owned(), t.to_owned(), nn, pk);
    if columns("meta")? != [col("key", "TEXT", false, 1), col("value", "BLOB", true, 0)]
        || columns("entries")?
            != [
                col("id", "TEXT", false, 1),
                col("kind", "INTEGER", true, 0),
                col("record", "BLOB", true, 0),
                col("unscannable", "INTEGER", true, 0),
                col("created_at", "INTEGER", true, 0),
                col("updated_at", "INTEGER", true, 0),
            ]
    {
        return Ok(None);
    }
    Ok(Some(MetaRows {
        version: meta_blob(conn, "schema_version")?,
        keycheck: meta_blob(conn, "keycheck")?,
    }))
}

/// SQLite errors that mean "this file is not a vault" rather than "reading it failed". A
/// corrupt database is not among them: it is passed on as an error.
fn is_not_a_vault(e: &rusqlite::Error) -> bool {
    matches!(
        e.sqlite_error_code(),
        Some(rusqlite::ErrorCode::NotADatabase | rusqlite::ErrorCode::SchemaChanged)
    )
}

/// True if the file starts with the SQLite header. Only such a non-empty file is handed to SQLite
/// (the read-only probe, never a read-write open, until [`probe_existing`] identifies a vault);
/// `create` then tells a vault (`AlreadyInitialized`) from another database (`NotEmpty`).
fn has_sqlite_header(file: &std::fs::File) -> Result<bool, VaultError> {
    use std::os::unix::fs::FileExt;
    let mut head = [0u8; 16];
    match file.read_exact_at(&mut head, 0) {
        Ok(()) => Ok(&head == b"SQLite format 3\0"),
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Ok(false),
        Err(e) => Err(VaultError::io("reading vault header")(e)),
    }
}

fn seal_keycheck(key: &KeyFile) -> Result<Vec<u8>, VaultError> {
    Ok(seal(
        key,
        RecordKind::Keycheck,
        KEYCHECK_ID,
        KEYCHECK_PLAINTEXT,
    )?)
}

impl Vault {
    /// Creates and initialises a new vault file (mode 0600) sealed under `key`.
    ///
    /// # Errors
    /// [`VaultError::AlreadyInitialized`] if the file already holds a vault, [`VaultError::NotEmpty`] if it
    /// holds anything else (including an empty file with a `-wal` or non-empty `-journal` next to
    /// it), [`VaultError::PendingJournal`] if the vault has an unfinished transaction; the open-sequence
    /// refusals (symlink, wrong owner or mode, identity mismatch, unsafe parent, work tree).
    pub fn create(path: &Path, key: KeyFile) -> Result<Self, VaultError> {
        Self::create_with(path, key, || {})
    }

    pub(crate) fn create_with(
        path: &Path,
        key: KeyFile,
        between: impl FnOnce(),
    ) -> Result<Self, VaultError> {
        let (mut conn, file) = connect(path, &key, false, between)?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(VaultError::sqlite("begin"))?;
        if has_meta(&tx)? {
            return Err(VaultError::AlreadyInitialized);
        }
        let len = file
            .file()
            .metadata()
            .map_err(VaultError::io("inspecting vault file"))?
            .len();
        if len > 0 {
            // Some other SQLite database: never add vault tables to it.
            return Err(VaultError::NotEmpty);
        }
        tx.execute_batch(
            "CREATE TABLE meta(key TEXT PRIMARY KEY, value BLOB NOT NULL);
             CREATE TABLE entries(
                 id TEXT PRIMARY KEY,
                 kind INTEGER NOT NULL,
                 record BLOB NOT NULL,
                 unscannable INTEGER NOT NULL DEFAULT 0,
                 created_at INTEGER NOT NULL,
                 updated_at INTEGER NOT NULL);",
        )
        .map_err(VaultError::sqlite("create schema"))?;
        tx.execute(
            "INSERT INTO meta(key, value) VALUES ('schema_version', ?1), ('keycheck', ?2)",
            params![
                SCHEMA_VERSION.to_string().into_bytes(),
                seal_keycheck(&key)?
            ],
        )
        .map_err(VaultError::sqlite("write meta"))?;
        tx.commit().map_err(VaultError::sqlite("commit"))?;
        Ok(Self {
            conn,
            key,
            _file: file,
        })
    }

    /// Opens an existing vault and checks `key` against `meta:keycheck`.
    ///
    /// # Errors
    /// [`VaultError::NotFound`], [`VaultError::NotInitialized`], [`VaultError::WrongKey`],
    /// [`VaultError::TooManyEntries`], [`VaultError::PendingJournal`], and the open-sequence
    /// refusals.
    pub fn open(path: &Path, key: KeyFile) -> Result<Self, VaultError> {
        Self::open_with(path, key, || {})
    }

    pub(crate) fn open_with(
        path: &Path,
        key: KeyFile,
        between: impl FnOnce(),
    ) -> Result<Self, VaultError> {
        let (conn, file) = connect(path, &key, true, between)?;
        if !has_meta(&conn)? {
            return Err(VaultError::NotInitialized);
        }
        let version = meta_blob(&conn, "schema_version")
            .map_err(VaultError::sqlite("read schema version"))?;
        if version.as_deref() != Some(SCHEMA_VERSION.to_string().as_bytes()) {
            return Err(VaultError::UnsupportedSchema);
        }
        let record = meta_blob(&conn, "keycheck")
            .map_err(VaultError::sqlite("read keycheck"))?
            .ok_or(VaultError::NotInitialized)?;
        check_keycheck(&key, &record)?;
        let vault = Self {
            conn,
            key,
            _file: file,
        };
        if vault.count()? > MAX_ENTRIES {
            return Err(VaultError::TooManyEntries);
        }
        vault.check_rows()?;
        Ok(vault)
    }

    /// Structural check of every row (ADR 0006 section 1): a valid id, a known kind and a
    /// record within the size bound. Nothing is decrypted.
    fn check_rows(&self) -> Result<(), VaultError> {
        let mut stmt = self
            .conn
            .prepare("SELECT id, kind, length(record) FROM entries")
            .map_err(VaultError::sqlite("check rows"))?;
        let rows = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, i64>(2)?,
                ))
            })
            .map_err(VaultError::sqlite("check rows"))?;
        for row in rows {
            let (id, code, len) = row.map_err(VaultError::sqlite("check rows"))?;
            if EntryId::new(&id).is_err() {
                return Err(VaultError::corrupt(INVALID_ID));
            }
            let too_big = usize::try_from(len).map_or(true, |l| l > MAX_RECORD_LEN);
            if kind_from_column(code).is_none() || too_big {
                return Err(VaultError::corrupt(&id));
            }
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn raw(&self) -> &Connection {
        &self.conn
    }

    fn count(&self) -> Result<usize, VaultError> {
        let n: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM entries", [], |r| r.get(0))
            .map_err(VaultError::sqlite("count"))?;
        Ok(usize::try_from(n).unwrap_or(usize::MAX))
    }

    /// Stores `value` under `id`, replacing an existing entry. Returns whether the entry is
    /// marked unscannable (too short for the scan, or [`Scan::PublicOccurrence`]).
    ///
    /// The `unscannable` column is not covered by the record's AAD (a deviation from the
    /// strictest reading of ADR 0006). That is acceptable: anyone who can edit the column can
    /// equally delete the row or the file, which already defeats the scan for that value, and
    /// the flag only ever makes the scan warn, never hide a hit. The display-name rule here
    /// checks the collapsed form and the slug without spaces; the squeeze table belongs to the
    /// scanner (#75), which recomputes the flag from the squeezed needles.
    ///
    /// # Errors
    /// [`VaultError::InvalidValue`], [`VaultError::ValueTooLarge`],
    /// [`VaultError::ValueKindMismatch`], [`VaultError::TooManyEntries`],
    /// [`VaultError::PublicOccurrenceKind`] (`Scan::PublicOccurrence` for a kind other than
    /// credential or secret), or a store failure.
    pub fn set(
        &mut self,
        id: &EntryId,
        kind: EntryKind,
        value: &Value,
        scan: Scan,
    ) -> Result<Scannability, VaultError> {
        if scan == Scan::PublicOccurrence
            && !matches!(kind, EntryKind::Credential | EntryKind::Secret)
        {
            return Err(VaultError::PublicOccurrenceKind { kind });
        }
        let (record, short) = match (kind, value) {
            (EntryKind::Credential, Value::Credential(c)) => {
                check_credential(&c.username, c.password.expose_secret())?;
                let short = is_unscannable(kind, c.password.expose_secret());
                (seal_credentials(&self.key, id.as_str(), c)?, short)
            }
            (EntryKind::Credential, _) | (_, Value::Credential(_)) => {
                return Err(VaultError::ValueKindMismatch { kind });
            }
            (_, Value::Text(text)) => {
                let normalized = normalize_text(kind, text.expose_secret())?;
                let plain: &str = &normalized;
                let short = is_unscannable(kind, plain);
                let record = seal(&self.key, record_kind(kind)?, id.as_str(), plain.as_bytes())?;
                (record, short)
            }
        };
        let unscannable = short || scan == Scan::PublicOccurrence;
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(VaultError::sqlite("begin"))?;
        let exists: bool = tx
            .query_row("SELECT 1 FROM entries WHERE id = ?1", [id.as_str()], |_| {
                Ok(true)
            })
            .optional()
            .map_err(VaultError::sqlite("lookup"))?
            .is_some();
        if !exists {
            let n: i64 = tx
                .query_row("SELECT COUNT(*) FROM entries", [], |r| r.get(0))
                .map_err(VaultError::sqlite("count"))?;
            if usize::try_from(n).unwrap_or(usize::MAX) >= MAX_ENTRIES {
                return Err(VaultError::TooManyEntries);
            }
        }
        let ts = now();
        tx.execute(
            "INSERT INTO entries(id, kind, record, unscannable, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?5)
             ON CONFLICT(id) DO UPDATE SET kind = ?2, record = ?3, unscannable = ?4, updated_at = ?5",
            params![id.as_str(), kind.code(), record, unscannable, ts],
        )
        .map_err(VaultError::sqlite("write entry"))?;
        tx.commit().map_err(VaultError::sqlite("commit"))?;
        Ok(if unscannable {
            Scannability::Unscannable
        } else {
            Scannability::Scannable
        })
    }

    /// Reads and decrypts one entry.
    ///
    /// # Errors
    /// [`VaultError::CorruptEntry`] if the row does not authenticate under the key and its own
    /// id and kind, or the stored kind column disagrees with the authenticated kind.
    pub fn get(&self, id: &EntryId) -> Result<Option<Entry>, VaultError> {
        let row: Option<(i64, Vec<u8>, bool)> = self
            .conn
            .query_row(
                "SELECT kind, record, unscannable FROM entries WHERE id = ?1",
                [id.as_str()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()
            .map_err(VaultError::sqlite("read entry"))?;
        let Some((code, record, unscannable)) = row else {
            return Ok(None);
        };
        let kind = kind_from_column(code).ok_or_else(|| VaultError::corrupt(id.as_str()))?;
        if record.len() > MAX_RECORD_LEN {
            return Err(VaultError::corrupt(id.as_str()));
        }
        let corrupt = |_: SecretsError| VaultError::corrupt(id.as_str());
        let value = if kind == EntryKind::Credential {
            Value::Credential(open_credentials(&self.key, id.as_str(), &record).map_err(corrupt)?)
        } else {
            let plain =
                open(&self.key, record_kind(kind)?, id.as_str(), &record).map_err(corrupt)?;
            let text = std::str::from_utf8(&plain)
                .map_err(|_| VaultError::corrupt(id.as_str()))?
                .to_owned();
            Value::Text(SecretString::from(text))
        };
        Ok(Some(Entry {
            kind,
            value,
            unscannable,
        }))
    }

    /// Lists ids, kinds and the `unscannable` flag, ordered by id. No value is decrypted.
    ///
    /// # Errors
    /// [`VaultError::CorruptEntry`] for a row with an invalid id or kind.
    pub fn list(&self) -> Result<Vec<EntryInfo>, VaultError> {
        let mut stmt = self
            .conn
            .prepare("SELECT id, kind, unscannable FROM entries ORDER BY id LIMIT ?1")
            .map_err(VaultError::sqlite("list"))?;
        let limit = i64::try_from(MAX_ENTRIES.saturating_add(1)).unwrap_or(i64::MAX);
        let rows = stmt
            .query_map([limit], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, bool>(2)?,
                ))
            })
            .map_err(VaultError::sqlite("list"))?;
        let mut out = Vec::new();
        for row in rows {
            let (id, code, unscannable) = row.map_err(VaultError::sqlite("list"))?;
            let parsed = EntryId::new(&id).map_err(|_| VaultError::corrupt(INVALID_ID))?;
            let kind = kind_from_column(code).ok_or_else(|| VaultError::corrupt(&id))?;
            out.push(EntryInfo {
                id: parsed,
                kind,
                unscannable,
            });
        }
        Ok(out)
    }

    /// Removes an entry; returns whether it existed.
    ///
    /// # Errors
    /// A store failure.
    pub fn rm(&mut self, id: &EntryId) -> Result<bool, VaultError> {
        let n = self
            .conn
            .execute("DELETE FROM entries WHERE id = ?1", [id.as_str()])
            .map_err(VaultError::sqlite("delete"))?;
        Ok(n > 0)
    }

    /// Re-seals every entry and the keycheck under `new_key` in one transaction (fresh nonce
    /// each), then adopts `new_key`. On any failure the transaction rolls back and the vault is
    /// unchanged: the old key still opens it.
    ///
    /// Key files (`<key>.next`, the rename, the directory fsync) are the caller's concern (#94).
    ///
    /// # Errors
    /// [`VaultError::CorruptEntry`] if any entry does not open under the current key.
    pub fn rekey(&mut self, new_key: KeyFile) -> Result<(), VaultError> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(VaultError::sqlite("begin"))?;
        let ids: Vec<String> = {
            let mut stmt = tx
                .prepare("SELECT id FROM entries ORDER BY id LIMIT ?1")
                .map_err(VaultError::sqlite("rekey list"))?;
            let limit = i64::try_from(MAX_ENTRIES.saturating_add(1)).unwrap_or(i64::MAX);
            stmt.query_map([limit], |r| r.get(0))
                .map_err(VaultError::sqlite("rekey list"))?
                .collect::<Result<_, _>>()
                .map_err(VaultError::sqlite("rekey list"))?
        };
        if ids.len() > MAX_ENTRIES {
            return Err(VaultError::TooManyEntries);
        }
        for id in &ids {
            if EntryId::new(id).is_err() {
                return Err(VaultError::corrupt(INVALID_ID));
            }
            let (code, record): (i64, Vec<u8>) = tx
                .query_row(
                    "SELECT kind, record FROM entries WHERE id = ?1",
                    [id],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .map_err(VaultError::sqlite("rekey read"))?;
            let kind = kind_from_column(code).ok_or_else(|| VaultError::corrupt(id))?;
            let rk = record_kind(kind)?;
            let plain = open(&self.key, rk, id, &record).map_err(|_| VaultError::corrupt(id))?;
            let resealed = seal(&new_key, rk, id, &plain)?;
            tx.execute(
                "UPDATE entries SET record = ?2, updated_at = ?3 WHERE id = ?1",
                params![id, resealed, now()],
            )
            .map_err(VaultError::sqlite("rekey write"))?;
        }
        tx.execute(
            "UPDATE meta SET value = ?1 WHERE key = 'keycheck'",
            [seal_keycheck(&new_key)?],
        )
        .map_err(VaultError::sqlite("rekey keycheck"))?;
        tx.commit().map_err(VaultError::sqlite("commit"))?;
        self.key = new_key;
        Ok(())
    }
}

fn kind_from_column(code: i64) -> Option<EntryKind> {
    u8::try_from(code).ok().and_then(EntryKind::from_code)
}

fn has_meta(conn: &Connection) -> Result<bool, VaultError> {
    conn.query_row(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'meta'",
        [],
        |_| Ok(true),
    )
    .optional()
    .map(|o| o.is_some())
    .map_err(VaultError::sqlite("inspect schema"))
}

fn check_keycheck(key: &KeyFile, record: &[u8]) -> Result<(), VaultError> {
    match open(key, RecordKind::Keycheck, KEYCHECK_ID, record) {
        Ok(plain) if plain.as_slice() == KEYCHECK_PLAINTEXT => Ok(()),
        Ok(_) | Err(SecretsError::Authentication) => Err(VaultError::WrongKey),
        Err(e) => Err(VaultError::Secrets(e)),
    }
}
