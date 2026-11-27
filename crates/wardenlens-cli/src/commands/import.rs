//! `wardenlens import agentdvr <objects.xml> [--dry-run]` (#66).
//!
//! Wires the parser ([`wardenlens_agentdvr`]), the key file ([`wardenlens_secrets`]), the vault and
//! the camera registry. Where each part of a camera goes (ADR 0006):
//!
//! | part | where | how |
//! |---|---|---|
//! | host, display name, login | the service vault `cam:<id>:host`, `:name`, `:credential` | sealed with the key file of `secrets.key_file` |
//! | id, model, port, main path | the `cameras` table of the index at `database.path` | plain, no site data |
//!
//! **The service vault path is not in the config** (the config has `database.path` and
//! `secrets.key_file` only). It is `vault.db` in the directory of `database.path`, which matches
//! ADR 0006 section 4 (`/var/lib/wardenlens/vault.db`, a separate file next to the recording index).
//!
//! # Behaviour
//! * The input is opened with `O_NOFOLLOW` as a regular file, refused when its size (`fstat`) is
//!   over 8 MiB, and read through `take(limit + 1)` so a file that grows is bounded too. A file
//!   readable by others draws a warning on stderr; the file is never changed. The buffer is
//!   zeroised on drop.
//! * `--dry-run` parses and prints, and touches no file: not the index, not the vault, not the key
//!   (their statuses are `would import`; whether a camera is new is only known by opening the
//!   index, which creates files).
//! * A real run needs the key file. A missing file points at `wardenlens secrets init`.
//! * Per camera, in this order: remove the vault login of an earlier run, write the vault host and
//!   name, write the new vault login last (none when the file has no login), then the registry
//!   row. A failure midway thus never pairs an old login with a new host. The two stores
//!   cannot share a transaction, so a run that fails midway is repaired by running it again
//!   (every write is an upsert). The registry row is last so a listed camera always has its
//!   vault entries.
//! * The registry stores model `agentdvr/imported`, which is in no catalogue, so a path with a query
//!   string is skipped (`path has a query string`): the registry accepts a query only for a model
//!   whose catalogue entry lists it (SEC-10). The check runs in a dry run too, so both agree.
//! * A path that contains any user or password the parser read (any camera's, since sites share
//!   passwords, and the logins of skipped entries too; ASCII-case-insensitive) is skipped and its path is not
//!   shown, so a login hidden in a path never reaches the registry or the output. A very short
//!   login (one character) matches many paths and over-refuses; that is fail-safe.
//! * The parser bounds the logins it collects (distinct values and bytes); a file with more is
//!   refused whole (`the objects file was refused`), so the screen's cost is bounded.
//! * Only the path is screened. The host is not: it is a site identifier the table prints by design,
//!   and a host that equals a login is not a leak path into the registry (which stores no host).
//! * Output (stdout) is a table of id, host, path and status. The host identifies the site: the
//!   owner runs this locally and never pastes the output. No login, password or source URL is
//!   ever printed, and no error carries input text.

use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use aho_corasick::AhoCorasick;
use secrecy::SecretString;
use wardenlens_agentdvr::{CameraDraft, Logins, MAX_INPUT_BYTES, SkipReason, Skipped};
use wardenlens_core::camera::{CameraError, MAX_PATH_LEN, ModelRef, RtspPath, StreamSet};
use wardenlens_core::catalogue::query_allowed;
use wardenlens_core::config::Config;
use wardenlens_core::entry::EntryKind;
use wardenlens_core::time::UnixMs;
use wardenlens_fsutil::{FsError, is_symlink_refusal, open_regular_nofollow};
use wardenlens_index::{CameraRecord, Index, IndexError};
use wardenlens_secrets::{Credentials, KeyFile, SecretsError};
use wardenlens_vault::{Scan, Value, Vault, VaultError};
use zeroize::Zeroizing;

use super::{Context, report_error};
use crate::args::ImportCommand;
use crate::config_file::{ConfigFileError, load, resolve_path};

/// The vault file next to the index.
const VAULT_FILE_NAME: &str = "vault.db";

/// The registry model of an imported camera: in no catalogue (see the module docs).
const MODEL: (&str, &str) = ("agentdvr", "imported");

/// Why the import failed.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ImportError {
    /// The config could not be used.
    #[error(transparent)]
    Config(#[from] ConfigFileError),
    /// The input file does not exist.
    #[error("input file {path:?} not found")]
    NotFound { path: PathBuf },
    /// The input path is a symbolic link.
    #[error("input file {path:?} is a symbolic link; give its real path")]
    Symlink { path: PathBuf },
    /// The input path is not a regular file.
    #[error("input path {path:?} is not a regular file")]
    NotRegular { path: PathBuf },
    /// The input could not be opened.
    #[error("input file {path:?} cannot be opened")]
    Open {
        path: PathBuf,
        #[source]
        source: FsError,
    },
    /// The input is over the limit.
    #[error("input file {path:?} is larger than {MAX_INPUT_BYTES} bytes (8 MiB)")]
    TooLarge { path: PathBuf },
    /// Reading the input failed.
    #[error("input file {path:?} cannot be read")]
    Read {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    /// The parser refused the document. Its message never holds input text.
    #[error("the objects file was refused")]
    Parse(#[source] wardenlens_agentdvr::ImportError),
    /// The key file does not exist.
    #[error("key file {path:?} does not exist; run `wardenlens secrets init` to create it")]
    KeyMissing { path: PathBuf },
    /// The key file was refused.
    #[error("the key file cannot be used")]
    Key(#[source] SecretsError),
    /// The vault refused.
    #[error("the vault cannot be used")]
    Vault(#[source] VaultError),
    /// The index refused.
    #[error("the camera registry cannot be used")]
    Index(#[source] IndexError),
    /// A built-in camera constant or entry id was refused (cannot happen today).
    #[error("internal camera value refused")]
    Camera(#[source] CameraError),
    /// The built-in camera catalogue is invalid (cannot happen; a test pins it).
    #[error("the built-in camera catalogue is invalid")]
    Catalogue(#[source] wardenlens_core::catalogue::CatalogueError),
    /// The vault file would be the index file.
    #[error("the vault file and the index file are the same path; rename `database.path`")]
    SameFile,
    /// The clock is outside 2000 to 2099.
    #[error("the system clock is outside the supported range")]
    Clock,
    /// The login screen could not be built, so no path can be vetted: nothing is written.
    #[error("the login screen could not be built; nothing was imported")]
    Screen,
    /// Writing the table failed.
    #[error("cannot write to stdout")]
    Output(#[source] io::Error),
}

impl ImportError {
    fn exit_code(&self) -> u8 {
        match self {
            Self::Config(e) => e.exit_code(),
            Self::Parse(_) | Self::TooLarge { .. } => 1,
            _ => 2,
        }
    }

    fn open(path: &Path, e: FsError) -> Self {
        let path = path.to_path_buf();
        if is_symlink_refusal(&e) {
            Self::Symlink { path }
        } else if e.is_not_found() {
            Self::NotFound { path }
        } else if matches!(e, FsError::NotRegular) {
            Self::NotRegular { path }
        } else {
            Self::Open { path, source: e }
        }
    }
}

/// What happened to one camera.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Status {
    WouldImport,
    Imported,
    Updated,
    Skipped(String),
}

impl Status {
    fn text(&self) -> String {
        match self {
            Self::WouldImport => "would import".to_owned(),
            Self::Imported => "imported".to_owned(),
            Self::Updated => "updated".to_owned(),
            Self::Skipped(reason) => format!("skipped: {reason}"),
        }
    }
}

/// One output line. Only ids, hosts, paths and fixed text; never a login.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Row {
    id: String,
    host: String,
    path: String,
    status: Status,
}

pub(crate) fn execute(cmd: &ImportCommand, ctx: &Context<'_>) -> ExitCode {
    let result = match cmd {
        ImportCommand::Agentdvr { file, dry_run } => agentdvr(ctx, file, *dry_run),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            report_error(&e, ctx.log_format);
            ExitCode::from(e.exit_code())
        }
    }
}

fn agentdvr(ctx: &Context<'_>, file: &Path, dry_run: bool) -> Result<(), ImportError> {
    let config = load(&resolve_path(ctx.config_flag, ctx.env)?)?;
    if vault_path(&config) == config.database_path() {
        return Err(ImportError::SameFile);
    }
    let bytes = read_input(file)?;
    let parsed = wardenlens_agentdvr::parse(&bytes).map_err(ImportError::Parse)?;
    drop(bytes);
    let model = ModelRef::new(MODEL.0, MODEL.1).map_err(ImportError::Camera)?;
    let (ready, mut rows) = screen(parsed.cameras, &parsed.logins, &model)?;
    rows.extend(parsed.skipped.iter().map(skipped_row));
    if dry_run {
        rows.extend(ready.iter().map(|d| row(d, Status::WouldImport)));
    } else {
        let key = load_key(config.key_file())?;
        let written = write_all(&config, key, &ready, &model)?;
        rows.extend(written);
    }
    print_table(&rows, &mut io::stdout().lock()).map_err(ImportError::Output)
}

/// Opens, bounds and reads the input; see the module docs.
fn read_input(path: &Path) -> Result<Zeroizing<Vec<u8>>, ImportError> {
    let (file, stat) = open_regular_nofollow(path).map_err(|e| ImportError::open(path, e))?;
    let too_large = || ImportError::TooLarge {
        path: path.to_path_buf(),
    };
    let limit = u64::try_from(MAX_INPUT_BYTES).map_err(|_| too_large())?;
    if stat.size > limit {
        return Err(too_large());
    }
    if stat.mode & 0o004 != 0 {
        // Not `tracing`: a `RUST_LOG` filter must not be able to hide it.
        // Escaped, so a control character in a path cannot forge a line.
        let shown = path.to_string_lossy().escape_debug().to_string();
        let _ = writeln!(
            io::stderr(),
            "warning: input file \"{shown}\" is readable by everyone and holds plaintext credentials; \
             it was not changed"
        );
    }
    // Capacity for the whole bounded read, so the buffer never reallocates and leaves copies.
    let capacity = usize::try_from(stat.size.saturating_add(1)).map_err(|_| too_large())?;
    let mut buf = Zeroizing::new(Vec::with_capacity(capacity));
    file.take(limit.saturating_add(1))
        .read_to_end(&mut buf)
        .map_err(|source| ImportError::Read {
            path: path.to_path_buf(),
            source,
        })?;
    if u64::try_from(buf.len()).map_or(true, |n| n > limit) {
        return Err(too_large());
    }
    Ok(buf)
}

/// Splits the drafts into those that can be written and the rows of those that cannot.
///
/// A draft is refused when its path contains any login of the file (any user or password the
/// parser read, skipped entries included, compared ASCII-case-insensitively with the path as
/// written and, defensively, percent-decoded): the registry would hold it in plaintext. Such a row
/// shows `-` for the path, and a query path that is skipped shows only the
/// part before `?`, so no refused path ever reaches the output.
///
/// # Errors
/// [`ImportError::Screen`] when the search cannot be built: never "no match".
fn screen(
    drafts: Vec<CameraDraft>,
    logins: &Logins,
    model: &ModelRef,
) -> Result<(Vec<CameraDraft>, Vec<Row>), ImportError> {
    let (ready, rows, _) = screen_with(drafts, logins, model, build_matcher)?;
    Ok((ready, rows))
}

/// The matcher over `patterns` (already ASCII-lowercased, none empty): ASCII-case-insensitive,
/// one automaton for all of them.
fn build_matcher(patterns: &[Zeroizing<Vec<u8>>]) -> Result<AhoCorasick, ImportError> {
    AhoCorasick::builder()
        .ascii_case_insensitive(true)
        .build(patterns.iter().map(|p| p.as_slice()))
        .map_err(|_| ImportError::Screen)
}

/// [`screen`] with the matcher builder given, also returning the path bytes scanned (see
/// `MAX_SCREEN_WORK`). A builder that fails fails the whole screen.
fn screen_with(
    drafts: Vec<CameraDraft>,
    logins: &Logins,
    model: &ModelRef,
    build: impl FnOnce(&[Zeroizing<Vec<u8>>]) -> Result<AhoCorasick, ImportError>,
) -> Result<(Vec<CameraDraft>, Vec<Row>, u64), ImportError> {
    let mut work = 0_u64;
    let mut ready = Vec::new();
    let mut rows = Vec::new();
    let logins = lowered_logins(logins);
    // One automaton over every login, built once (cost linear in the login bytes, at most
    // `MAX_LOGIN_BYTES`); no login at all needs none.
    let matcher = if logins.is_empty() {
        None
    } else {
        Some(build(&logins)?)
    };
    for d in drafts {
        if path_holds_login(&d.path, matcher.as_ref(), &mut work) {
            let mut r = row(
                &d,
                Status::Skipped("path contains the login (path not shown)".to_owned()),
            );
            "-".clone_into(&mut r.path);
            rows.push(r);
        } else if query_allowed(&[], model, &d.path) {
            ready.push(d);
        } else {
            // The registry vets the same thing on write; checking here keeps a dry run honest.
            let mut r = row(
                &d,
                Status::Skipped("path has a query string (no catalogue model lists it)".to_owned()),
            );
            let head = before_query(&r.path).to_owned();
            r.path = head;
            rows.push(r);
        }
    }
    Ok((ready, rows, work))
}

/// The part of a path before its query string.
fn before_query(path: &str) -> &str {
    path.split_once('?').map_or(path, |(head, _)| head)
}

/// Percent-decoding for the comparison only; a `%` not followed by two hex digits stays literal.
fn percent_decode(s: &str) -> Zeroizing<Vec<u8>> {
    let bytes = s.as_bytes();
    let mut out = Zeroizing::new(Vec::with_capacity(bytes.len()));
    let mut i = 0_usize;
    while let Some(&b) = bytes.get(i) {
        let hex = |off: usize| {
            bytes
                .get(i.saturating_add(off))
                .and_then(|c| char::from(*c).to_digit(16))
        };
        if let (b'%', Some(h), Some(l)) = (b, hex(1), hex(2)) {
            out.push(u8::try_from(h.saturating_mul(16).saturating_add(l)).unwrap_or(b));
            i = i.saturating_add(3);
        } else {
            out.push(b);
            i = i.saturating_add(1);
        }
    }
    out
}

/// The most path bytes the screen scans: at most 256 paths of at most `MAX_PATH_LEN` bytes, each
/// scanned as written and (only when it differs) percent-decoded. One search per path, so the
/// cost is the path length whatever the number or length of the logins; building the automaton
/// is separate and linear in the login bytes (at most `MAX_LOGIN_BYTES`).
#[cfg(test)]
const MAX_SCREEN_WORK: u64 = 256 * 2 * 512;

/// Every non-empty user and password the parser read (skipped entries included), ASCII-lowercased
/// for the comparison, zeroised on drop.
fn lowered_logins(logins: &Logins) -> Vec<Zeroizing<Vec<u8>>> {
    // A value longer than any path cannot be inside one, so it never costs a comparison.
    logins
        .iter()
        .filter(|l| l.len() <= MAX_PATH_LEN)
        .map(|l| Zeroizing::new(l.to_ascii_lowercase().into_bytes()))
        .collect()
}

/// True if the path holds any login (`matcher` is built over them), compared
/// ASCII-case-insensitively, as written or percent-decoded. Every byte fed to the search is one
/// unit of `work`. (Core refuses `%` in a path, so the decoded text equals the written one and is
/// skipped; the check stays for a path type that ever allows it.)
fn path_holds_login(path: &RtspPath, matcher: Option<&AhoCorasick>, work: &mut u64) -> bool {
    let Some(matcher) = matcher else { return false };
    let written = path.as_str().as_bytes();
    let decoded = percent_decode(path.as_str());
    let mut scan = |hay: &[u8]| {
        *work = work.saturating_add(u64::try_from(hay.len()).unwrap_or(u64::MAX));
        matcher.is_match(hay)
    };
    scan(written) || (decoded.as_slice() != written && scan(&decoded))
}

fn row(d: &CameraDraft, status: Status) -> Row {
    Row {
        id: d.id.to_string(),
        host: d.host.expose(),
        path: d.path.as_str().to_owned(),
        status,
    }
}

fn skipped_row(s: &Skipped) -> Row {
    let reason: SkipReason = s.reason;
    Row {
        id: "-".to_owned(),
        host: "-".to_owned(),
        path: "-".to_owned(),
        status: Status::Skipped(format!("{reason} (entry {})", s.position)),
    }
}

/// The key file, or a message that points at `secrets init` when it is missing.
fn load_key(path: &Path) -> Result<KeyFile, ImportError> {
    if std::fs::symlink_metadata(path).is_err_and(|e| e.kind() == io::ErrorKind::NotFound) {
        return Err(ImportError::KeyMissing {
            path: path.to_path_buf(),
        });
    }
    KeyFile::load(path).map_err(ImportError::Key)
}

/// `vault.db` next to the index.
pub(crate) fn vault_path(config: &Config) -> PathBuf {
    let dir = match config.database_path().parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    dir.join(VAULT_FILE_NAME)
}

pub(crate) fn open_vault(path: &Path, key: KeyFile) -> Result<Vault, VaultError> {
    if std::fs::symlink_metadata(path).is_err_and(|e| e.kind() == io::ErrorKind::NotFound) {
        Vault::create(path, key)
    } else {
        Vault::open(path, key)
    }
}

fn now() -> Result<UnixMs, ImportError> {
    let ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_millis()).ok())
        .ok_or(ImportError::Clock)?;
    UnixMs::new(ms).map_err(|_| ImportError::Clock)
}

pub(super) fn write_all(
    config: &Config,
    key: KeyFile,
    drafts: &[CameraDraft],
    model: &ModelRef,
) -> Result<Vec<Row>, ImportError> {
    let mut vault = open_vault(&vault_path(config), key).map_err(ImportError::Vault)?;
    let mut index = Index::open(config.database_path()).map_err(ImportError::Index)?;
    // The registry may hold cameras whose paths carry a query that the catalogue lists
    // (`camera add`); reading or writing a row with no catalogue would refuse them.
    let catalogue = super::camera::catalogue().map_err(ImportError::Catalogue)?;
    let mut rows = Vec::with_capacity(drafts.len());
    for d in drafts {
        let existed = index
            .get_camera(&d.id, &catalogue)
            .map_err(ImportError::Index)?
            .is_some();
        write_vault(&mut vault, d)?;
        let record = CameraRecord::new(
            d.id.clone(),
            model.clone(),
            d.port,
            StreamSet::new(d.path.clone(), None),
        );
        index
            .upsert_camera(&record, &catalogue, now()?)
            .map_err(ImportError::Index)?;
        rows.push(row(
            d,
            if existed {
                Status::Updated
            } else {
                Status::Imported
            },
        ));
    }
    Ok(rows)
}

/// Writes one camera's vault entries. The order matters: the old login goes first and the new one
/// last, so a failure in between never leaves an old login next to a new host.
fn write_vault(vault: &mut Vault, d: &CameraDraft) -> Result<(), ImportError> {
    let id_for = |kind| d.id.entry_id(kind).map_err(ImportError::Camera);
    let text = |s: &str| Value::Text(SecretString::from(s.to_owned()));
    let credential_id = id_for(EntryKind::Credential)?;
    vault.rm(&credential_id).map_err(ImportError::Vault)?;
    vault
        .set(
            &id_for(EntryKind::Host)?,
            EntryKind::Host,
            &text(&d.host.expose()),
            Scan::Normal,
        )
        .map_err(ImportError::Vault)?;
    vault
        .set(
            &id_for(EntryKind::DisplayName)?,
            EntryKind::DisplayName,
            &text(d.name.expose()),
            Scan::Normal,
        )
        .map_err(ImportError::Vault)?;
    if let Some(c) = &d.credential {
        let value = Value::Credential(Credentials {
            username: c.user.clone(),
            password: c.password.clone(),
        });
        vault
            .set(&credential_id, EntryKind::Credential, &value, Scan::Normal)
            .map_err(ImportError::Vault)?;
    }
    Ok(())
}

fn print_table(rows: &[Row], out: &mut impl Write) -> io::Result<()> {
    let status: Vec<String> = rows.iter().map(|r| r.status.text()).collect();
    let width = |head: &str, f: fn(&Row) -> &str| {
        rows.iter()
            .map(|r| f(r).chars().count())
            .chain([head.len()])
            .max()
            .unwrap_or(0)
    };
    let (wi, wh, wp) = (
        width("id", |r| &r.id),
        width("host", |r| &r.host),
        width("path", |r| &r.path),
    );
    writeln!(out, "{:wi$}  {:wh$}  {:wp$}  status", "id", "host", "path")?;
    for (r, s) in rows.iter().zip(&status) {
        writeln!(out, "{:wi$}  {:wh$}  {:wp$}  {s}", r.id, r.host, r.path)?;
    }
    out.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_lists_columns_and_never_more() {
        let rows = vec![
            Row {
                id: "agentdvr-1".into(),
                host: "192.0.2.10".into(),
                path: "/s".into(),
                status: Status::Imported,
            },
            Row {
                id: "-".into(),
                host: "-".into(),
                path: "-".into(),
                status: Status::Skipped("x".into()),
            },
        ];
        let mut out = Vec::new();
        print_table(&rows, &mut out).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert_eq!(text.lines().count(), 3);
        assert!(text.contains("agentdvr-1  192.0.2.10"));
        assert!(text.contains("skipped: x"));
    }

    #[test]
    fn the_reader_refuses_over_the_limit_itself_and_accepts_the_limit() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f.xml");
        let limit = u64::try_from(MAX_INPUT_BYTES).unwrap();
        // Sparse: nothing is written. The parser is never reached, so this is the reader's own
        // refusal (the size from `fstat`).
        std::fs::File::create(&path)
            .unwrap()
            .set_len(limit + 1)
            .unwrap();
        assert!(matches!(
            read_input(&path),
            Err(ImportError::TooLarge { .. })
        ));
        std::fs::File::create(&path)
            .unwrap()
            .set_len(limit)
            .unwrap();
        assert_eq!(read_input(&path).unwrap().len(), MAX_INPUT_BYTES);
    }

    fn drafts(path: &str, user: &str, password: &str) -> wardenlens_agentdvr::Import {
        let xml = format!(
            "<objects><cameras><camera id=\"1\" name=\"A\"><settings>\
             <videosourcestring>rtsp://192.0.2.5{path}</videosourcestring>\
             <login>{user}</login><password>{password}</password></settings></camera>\
             </cameras></objects>"
        );
        wardenlens_agentdvr::parse(xml.as_bytes()).unwrap()
    }

    fn screen_all(i: wardenlens_agentdvr::Import, m: &ModelRef) -> (Vec<CameraDraft>, Vec<Row>) {
        screen(i.cameras, &i.logins, m).unwrap()
    }

    /// The ends-match shape: 255 paths of 512 bytes, and 4096 distinct 255-byte logins that are
    /// held by a skipped carrier camera, start and end with `a`, and are in no path. It was the
    /// worst case of the per-login window scan; the multi-pattern search does not care.
    fn ends_match_import() -> wardenlens_agentdvr::Import {
        let path = "a".repeat(511);
        let head = "a".repeat(251);
        let cams: Vec<String> = (1..=255_u32)
            .map(|i| {
                format!(
                    "<camera id=\"{i}\" name=\"Cam {i}\"><settings><videosourcestring>\
                     rtsp://192.0.2.1/{path}</videosourcestring></settings></camera>"
                )
            })
            .collect();
        let alphabet: Vec<char> = "bcdefghijklmnopqrstuvwxyz0123456789".chars().collect();
        let pws: Vec<String> = (0..4096_usize)
            .map(|n| {
                let (x, y, z) = (
                    alphabet[n / 1225 % 35],
                    alphabet[n / 35 % 35],
                    alphabet[n % 35],
                );
                format!("<password>{head}{x}{y}{z}a</password>")
            })
            .collect();
        let xml = format!(
            "<objects><cameras>{}<camera id=\"999\" name=\"Carrier\"><settings>\
             <videosourcestring>rtsp://192.0.2.9/s</videosourcestring>{}</settings></camera>\
             </cameras></objects>",
            cams.concat(),
            pws.concat()
        );
        wardenlens_agentdvr::parse(xml.as_bytes()).unwrap()
    }

    #[test]
    fn the_screen_work_is_the_path_bytes_scanned_in_the_ends_match_worst_case() {
        let model = ModelRef::new(MODEL.0, MODEL.1).unwrap();
        let parsed = ends_match_import();
        assert_eq!(parsed.logins.len(), 4096);
        let (ready, _, work) =
            screen_with(parsed.cameras, &parsed.logins, &model, build_matcher).unwrap();
        assert_eq!(ready.len(), 255);
        // One pass over each 512-byte path (the decoded text equals the written one, so it is
        // not scanned again); independent of the 4096 logins.
        assert_eq!(work, 255 * 512);
        assert!(work <= MAX_SCREEN_WORK);
    }

    #[test]
    fn a_matcher_that_cannot_be_built_fails_the_screen_closed() {
        let model = ModelRef::new(MODEL.0, MODEL.1).unwrap();
        let i = drafts("/live/Fake-pw-1/main", "u-fake", "Fake-pw-1");
        let r = screen_with(i.cameras, &i.logins, &model, |_| Err(ImportError::Screen));
        assert!(matches!(r, Err(ImportError::Screen)));
        // With no login there is nothing to build, so a failing builder is never asked.
        let i = drafts("/live/main", "", "");
        let (ready, _, _) =
            screen_with(i.cameras, &i.logins, &model, |_| Err(ImportError::Screen)).unwrap();
        assert_eq!(ready.len(), 1);
    }

    #[test]
    fn a_path_holding_the_login_is_refused_and_never_shown() {
        let model = ModelRef::new(MODEL.0, MODEL.1).unwrap();
        // (path, user, password): every one holds the password or the user.
        for (path, user, pw) in [
            ("/live/Fake-pw-1/main", "u-fake", "Fake-pw-1"),
            ("/a/u-fake/b", "u-fake", "Fake-pw-1"),
            ("/x_zzq=Fake-pw-1", "u-fake", "Fake-pw-1"),
        ] {
            let (ready, rows) = screen_all(drafts(path, user, pw), &model);
            assert!(ready.is_empty(), "{path}");
            assert_eq!(rows.len(), 1);
            let shown = format!("{:?}", rows[0]);
            assert!(!shown.contains(pw) && !shown.contains(user), "{shown}");
            assert_eq!(rows[0].path, "-");
        }
        // An empty password matches nothing; a path without the login passes.
        let (ready, _) = screen_all(drafts("/live/main", "u-fake", ""), &model);
        assert_eq!(ready.len(), 1);
        let (ready, _) = screen_all(drafts("/live/main", "u-fake", "Fake-pw-1"), &model);
        assert_eq!(ready.len(), 1);
    }

    #[test]
    fn another_cameras_login_and_other_case_are_refused() {
        let model = ModelRef::new(MODEL.0, MODEL.1).unwrap();
        let xml = "<objects><cameras>\
            <camera id=\"1\" name=\"A\"><settings><videosourcestring>rtsp://192.0.2.5/s\
            </videosourcestring><login>u-fake</login><password>Fake-pw-1</password></settings></camera>\
            <camera id=\"2\" name=\"B\"><settings><videosourcestring>rtsp://192.0.2.6/x/FAKE-PW-1/y\
            </videosourcestring></settings></camera>\
            <camera id=\"3\" name=\"C\"><settings><videosourcestring>rtsp://192.0.2.7/ok\
            </videosourcestring></settings></camera></cameras></objects>";
        let (ready, rows) = screen_all(wardenlens_agentdvr::parse(xml.as_bytes()).unwrap(), &model);
        let ids: Vec<_> = ready.iter().map(|d| d.id.to_string()).collect();
        assert_eq!(ids, ["agentdvr-1", "agentdvr-3"]);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].path, "-");
        assert!(!format!("{rows:?}").to_lowercase().contains("fake-pw-1"));
    }

    #[test]
    fn the_comparison_also_sees_a_percent_encoded_login() {
        // Core's path type refuses `%`, so a draft cannot carry one today; the helper is the
        // guard if that rule changes, and is tested directly.
        assert_eq!(&**percent_decode("/a%41b%zz%4"), b"/aAb%zz%4");
        // A path that were to carry the encoded login is caught through the decoded scan.
        let m = build_matcher(&[Zeroizing::new(b"pass".to_vec())]).unwrap();
        assert!(m.is_match(&**percent_decode("/p%61ss")));
        assert!(m.is_match(b"/PASS"));
    }

    #[test]
    fn a_skipped_query_path_shows_only_the_part_before_the_query() {
        let model = ModelRef::new(MODEL.0, MODEL.1).unwrap();
        let (ready, rows) = screen_all(drafts("/s?pin=7731", "u-fake", "Fake-pw-1"), &model);
        assert!(ready.is_empty());
        assert_eq!(rows[0].path, "/s");
        assert_eq!(before_query("/a"), "/a");
    }

    #[test]
    fn the_same_file_for_vault_and_index_is_refused() {
        let toml = r#"
[api]
listen = "127.0.0.1:8080"
[storage]
hot_root = "/srv/wl/hot"
archive_root = "/srv/wl/archive"
[database]
path = "/srv/wl/state/vault.db"
[secrets]
key_file = "/srv/wl/keys/secrets.key"
"#;
        let c = Config::from_toml_str(toml).unwrap();
        assert_eq!(vault_path(&c), c.database_path());
        assert_eq!(ImportError::SameFile.exit_code(), 2);
    }

    #[test]
    fn vault_sits_next_to_the_index() {
        let toml = r#"
[api]
listen = "127.0.0.1:8080"
[storage]
hot_root = "/srv/wl/hot"
archive_root = "/srv/wl/archive"
[database]
path = "/srv/wl/state/index.db"
[secrets]
key_file = "/srv/wl/keys/secrets.key"
"#;
        let c = Config::from_toml_str(toml).unwrap();
        assert_eq!(vault_path(&c), Path::new("/srv/wl/state/vault.db"));
    }
}
