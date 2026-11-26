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
//! * Per camera, in this order: vault host, vault name, vault login (an entry left by an earlier
//!   run is removed when the file no longer has a login), then the registry row. The two stores
//!   cannot share a transaction, so a run that fails midway is repaired by running it again
//!   (every write is an upsert). The registry row is last so a listed camera always has its
//!   vault entries.
//! * The registry stores model `agentdvr/imported`, which is in no catalogue, so a path with a query
//!   string is skipped (`path has a query string`): the registry accepts a query only for a model
//!   whose catalogue entry lists it (SEC-10). The check runs in a dry run too, so both agree.
//! * Output (stdout) is a table of id, host, path and status. The host identifies the site: the
//!   owner runs this locally and never pastes the output. No login, password or source URL is
//!   ever printed, and no error carries input text.

use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use secrecy::SecretString;
use wardenlens_agentdvr::{CameraDraft, MAX_INPUT_BYTES, SkipReason, Skipped};
use wardenlens_core::camera::{CameraError, ModelRef, StreamSet};
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
    /// The clock is outside 2000 to 2099.
    #[error("the system clock is outside the supported range")]
    Clock,
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
enum Status {
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
struct Row {
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
    let bytes = read_input(file)?;
    let parsed = wardenlens_agentdvr::parse(&bytes).map_err(ImportError::Parse)?;
    drop(bytes);
    let model = ModelRef::new(MODEL.0, MODEL.1).map_err(ImportError::Camera)?;
    let (ready, mut rows) = screen(parsed.cameras, &model);
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
fn screen(drafts: Vec<CameraDraft>, model: &ModelRef) -> (Vec<CameraDraft>, Vec<Row>) {
    let mut ready = Vec::new();
    let mut rows = Vec::new();
    for d in drafts {
        // The registry vets the same thing on write; checking here keeps a dry run honest.
        if query_allowed(&[], model, &d.path) {
            ready.push(d);
        } else {
            rows.push(row(
                &d,
                Status::Skipped("path has a query string (no catalogue model lists it)".to_owned()),
            ));
        }
    }
    (ready, rows)
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
fn vault_path(config: &Config) -> PathBuf {
    let dir = match config.database_path().parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    dir.join(VAULT_FILE_NAME)
}

fn open_vault(path: &Path, key: KeyFile) -> Result<Vault, VaultError> {
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

fn write_all(
    config: &Config,
    key: KeyFile,
    drafts: &[CameraDraft],
    model: &ModelRef,
) -> Result<Vec<Row>, ImportError> {
    let mut vault = open_vault(&vault_path(config), key).map_err(ImportError::Vault)?;
    let mut index = Index::open(config.database_path()).map_err(ImportError::Index)?;
    let mut rows = Vec::with_capacity(drafts.len());
    for d in drafts {
        let existed = index
            .get_camera(&d.id, &[])
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
            .upsert_camera(&record, &[], now()?)
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

fn write_vault(vault: &mut Vault, d: &CameraDraft) -> Result<(), ImportError> {
    let id_for = |kind| d.id.entry_id(kind).map_err(ImportError::Camera);
    let text = |s: &str| Value::Text(SecretString::from(s.to_owned()));
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
    let credential_id = id_for(EntryKind::Credential)?;
    match &d.credential {
        Some(c) => {
            let value = Value::Credential(Credentials {
                username: c.user.clone(),
                password: c.password.clone(),
            });
            vault
                .set(&credential_id, EntryKind::Credential, &value, Scan::Normal)
                .map_err(ImportError::Vault)?;
        }
        // The file no longer has a login: an entry from an earlier run must not outlive it.
        None => {
            vault.rm(&credential_id).map_err(ImportError::Vault)?;
        }
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
