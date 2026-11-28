//! `wardenlens import agentdvr [<objects.json|objects.xml>] [--format F] [--dry-run] [--model M] [--camera-model ID=M]` (#66,
//! #163).
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
//! * **Formats (#226).** `objects.json` (current `AgentDVR`) and `objects.xml` are both read; the
//!   format is detected from the content (first byte `{` is JSON) or forced with `--format`. The
//!   JSON is parsed by the same crate into the same drafts, so the screen, the model match, the
//!   vault writes and every refusal below are shared. With no file, the first of
//!   `DEFAULT_INPUTS` that exists is read (never a `.bak`). The JSON layout is an assumption (see
//!   the parser crate's `json` module).
//! * The input is opened with `O_NOFOLLOW` as a regular file, refused when its size (`fstat`) is
//!   over 8 MiB, and read through `take(limit + 1)` so a file that grows is bounded too (two
//!   guards, each tested alone). Exit codes follow `ConfigFileError`: a document refused for its
//!   content or a bad option is 1; a file that cannot be used, or any other failure, is 2. A file
//!   readable by others draws a warning on stderr; the file is never changed. The buffer is
//!   zeroised on drop.
//! * `--dry-run` parses and prints, and writes nothing: not the vault, not the key, and not the
//!   index (no migration, no pragma, no file created; the main file and the `-wal` stay
//!   byte-identical, and SQLite may update the `-shm` of a live `-wal`, as for any reader). It
//!   reads an existing index with `Index::open_read_only` (no lock, so the answer is advisory), so it applies the same row guard as the real run and reports the same
//!   skips; it keeps the real open's refusals (a stray sidecar, a damaged file). A missing or empty
//!   index counts as no rows. An index that the real run would first migrate (older schema) or
//!   recover (a `-wal` with no `-shm`) is not entered: every camera is reported as `would import
//!   (the real run would first migrate the index ...)` and no row is compared. **The dry run does
//!   not check the registry capacity** (`MAX_CAMERAS`): a real run that would exceed it fails on
//!   the row that does.
//! * A real run needs the key file. A missing file points at `wardenlens secrets init`.
//! * Per camera, in this order: remove the vault login of an earlier run, write the vault host and
//!   name, write the new vault login last (none when the file has no login), then the registry
//!   row. A failure midway thus never pairs an old login with a new host. The two stores
//!   cannot share a transaction, so a run that fails midway is repaired by running it again
//!   (every write is an upsert). The registry row is last so a listed camera always has its
//!   vault entries.
//! * **A run that fails midway leaves orphans.** If the registry write fails after the vault
//!   writes of that camera (the registry refuses the row, the disk is full), the vault holds
//!   `cam:<id>:host` and `:name` (and the login) for an id that no registry row lists. Nothing
//!   reads them, `camera list` does not show them, and running the import again completes the
//!   camera. The cameras before the failing one are complete.
//! * **Cameras removed from the file are not pruned.** The import only adds and updates; a camera
//!   that is no longer in `objects.xml` keeps its registry row and vault entries until
//!   `wardenlens camera remove <id>` removes them. (A prune would delete a camera the owner may
//!   have added by hand under the same id scheme.)
//! * **The model of a camera** (catalogue data only; no vendor or model is named in this code).
//!   In this order: its `--camera-model <id>=<vendor>/<model>`, then `--model <vendor>/<model>`
//!   for the whole file, then, only for a source path **with a query string**, the one catalogue
//!   model that lists exactly that path (path and query) among its RTSP paths. More than one such
//!   model is an ambiguity: the camera is skipped, naming the model ids, never guessed. A path
//!   with no query string and no option keeps `agentdvr/imported`. An option model must be in the
//!   catalogue, and a `--camera-model` id must be in the file, or nothing is written (exit 1).
//!   The `AgentDVR` file has no vendor field that the importer reads, so the vendor is not a
//!   matching input; the path shape is.
//! * **SEC-10 holds whatever picked the model:** the registry accepts a query only for a model
//!   whose catalogue entry lists exactly that query, so an unlisted query is skipped (`path has a
//!   query string`) even under a chosen model, and no other model is substituted. The check runs
//!   in a dry run too, so both agree.
//! * **Rows of `camera add`.** `camera add` refuses ids starting with `agentdvr-` (`ReservedId`),
//!   which are this command's, so an import never meets a hand-added row. Every `agentdvr-*` row
//!   is updated by a re-import (host, name, login and main path are replaced). As defence in
//!   depth a row under a catalogue model (vendor not `agentdvr`) that differs from the model
//!   chosen now is left as it is, with the vault untouched: an earlier `--model` import is not
//!   re-mapped by accident. A dry run opens an existing index (never creates one) so that its
//!   statuses agree with the real run. A pre-reservation hand-added `agentdvr-*` row cannot be
//!   told from an imported one (the registry has no provenance); see [`RESERVED_ID_PREFIX`].
//! * A path that contains any user or password the parser read (any camera's, since sites share
//!   passwords, and the logins of skipped entries too; ASCII-case-insensitive) is skipped and its path is not
//!   shown, so a login hidden in a path never reaches the registry or the output. A very short
//!   login (one character) matches many paths and over-refuses; that is fail-safe.
//! * The parser bounds the logins it collects (distinct values and bytes); a file with more is
//!   refused whole (`the objects file was refused`), so the screen's cost is bounded.
//! * Only the path is screened. The host is not: it is a site identifier the table prints by design,
//!   and a host that equals a login is not a leak path into the registry (which stores no host).
//! * Output (stdout) is a table of id, host, path, model (`-` for the default) and status. The host identifies the site: the
//!   owner runs this locally and never pastes the output. No login, password or source URL is
//!   ever printed, and no error carries input text.

use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use aho_corasick::AhoCorasick;
use secrecy::SecretString;
use wardenlens_agentdvr::{CameraDraft, Logins, MAX_INPUT_BYTES, SkipReason, Skipped};
use wardenlens_core::camera::{CameraError, CameraId, MAX_PATH_LEN, ModelRef, RtspPath, StreamSet};
use wardenlens_core::catalogue::{CatalogueEntry, ProtocolKind, query_allowed};
use wardenlens_core::config::Config;
use wardenlens_core::entry::EntryKind;
use wardenlens_core::time::UnixMs;
use wardenlens_fsutil::{FsError, is_symlink_refusal, open_regular_nofollow};
use wardenlens_index::{CameraRecord, Index, IndexError, ReadOnlyIndex, StoredCamera};
use wardenlens_secrets::{Credentials, KeyFile, SecretsError};
use wardenlens_vault::{Scan, Value, Vault, VaultError};
use zeroize::Zeroizing;

use super::{Context, report_error};
use crate::args::{FormatArg, ImportCommand};
use crate::config_file::{ConfigFileError, load, resolve_path};

/// The vault file next to the index.
const VAULT_FILE_NAME: &str = "vault.db";

/// The registry model of an imported camera that no catalogue model was chosen for or matched:
/// in no catalogue, so a path with a query string is not imported under it (see the module docs).
const MODEL: (&str, &str) = ("agentdvr", "imported");

/// The id prefix of every camera this command writes (the parser makes `agentdvr-<n>`). `camera
/// add` refuses it (`ReservedId`), so no hand-added row can share an id with an import and the
/// import's read-then-write of a row cannot race with a `camera add` of the same id.
///
/// A row under this prefix that was hand-added before the reservation (an existing install) cannot
/// be told from an imported one: the registry has no provenance. A re-import replaces its vault
/// host, name and login and its main path. Rename or remove such a camera before importing.
pub(crate) const RESERVED_ID_PREFIX: &str = "agentdvr-";

/// The vendor slug of the models this command itself assigns. A registry row of any other vendor
/// was mapped to a catalogue model by an earlier import.
const OWN_VENDOR: &str = "agentdvr";

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
    /// No file was given and none of the usual install paths exists.
    #[error(
        "no input file given and none of the usual paths exists \
         (/opt/AgentDVR/Media/XML/objects.json, .../objects.xml); give the file"
    )]
    NoDefaultInput,
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
    /// A `--model` or `--camera-model` value is not `<vendor>/<model>` (or `<id>=<vendor>/<model>`).
    #[error(
        "a model option is malformed; use `--model <vendor>/<model>` and `--camera-model <id>=<vendor>/<model>`"
    )]
    ModelArg,
    /// A model given on the command line is in no catalogue entry.
    #[error(
        "a model option names no catalogue entry; use `<vendor>/<model>` as in cameras/README.md"
    )]
    UnknownModel,
    /// `--camera-model` names one camera twice.
    #[error("`--camera-model` names the same camera twice")]
    DuplicateCamera,
    /// `--camera-model` names a camera that is not in the file.
    #[error("`--camera-model` names a camera id that is not in the file")]
    UnknownCamera,
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
            // Like `ConfigFileError`: a document that is refused for its content is 1; a file
            // that cannot be used (missing, too large, not regular, unreadable) is 2.
            Self::Parse(_)
            | Self::ModelArg
            | Self::DuplicateCamera
            | Self::UnknownModel
            | Self::UnknownCamera => 1,
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
    /// A dry run over an index that the real run would first change.
    WouldImportAfter(Prelude),
    Imported,
    Updated,
    Skipped(SkipWhy),
}

/// Why a camera was not imported. The text holds ids and model ids only, never a host, a name or
/// a login.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum SkipWhy {
    /// The parser skipped the entry.
    Parser { reason: SkipReason, position: usize },
    /// The path holds a login of the file.
    LoginInPath,
    /// The path has a query string that the model (the matched or chosen one, if any) does not
    /// list.
    QueryNotListed(Option<ModelRef>),
    /// The path is listed by several catalogue models; none is guessed.
    Ambiguous(Vec<ModelRef>),
    /// The registry holds this id under a catalogue model other than the one chosen now (an
    /// earlier import mapped it): a changed model is never applied silently.
    ExistingModel(ModelRef),
}

impl SkipWhy {
    fn text(&self) -> String {
        match self {
            Self::Parser { reason, position } => format!("{reason} (entry {position})"),
            Self::LoginInPath => "path contains the login (path not shown)".to_owned(),
            Self::QueryNotListed(None) => {
                "path has a query string (no catalogue model lists it; choose one with \
                 --model or --camera-model)"
                    .to_owned()
            }
            Self::QueryNotListed(Some(m)) => {
                format!("path has a query string that model {m} does not list")
            }
            Self::Ambiguous(models) => {
                let list: Vec<String> = models.iter().map(ToString::to_string).collect();
                format!(
                    "ambiguous: the path is listed by models {}; choose one with --camera-model",
                    list.join(", ")
                )
            }
            Self::ExistingModel(m) => format!(
                "the registry holds this id under model {m}, which differs from the model chosen \
                 now; the row is left as it is (pass {m} with --model or --camera-model to update it)"
            ),
        }
    }
}

impl Status {
    fn text(&self) -> String {
        match self {
            Self::WouldImport => "would import".to_owned(),
            Self::WouldImportAfter(Prelude::Migrate) => {
                "would import (the real run would first migrate the index; existing rows not compared)"
                    .to_owned()
            }
            Self::WouldImportAfter(Prelude::Recover) => {
                "would import (the real run would first recover the index; existing rows not compared)"
                    .to_owned()
            }
            Self::Imported => "imported".to_owned(),
            Self::Updated => "updated".to_owned(),
            Self::Skipped(why) => format!("skipped: {}", why.text()),
        }
    }
}

/// One output line. Only ids, hosts, paths and fixed text; never a login.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Row {
    id: String,
    host: String,
    path: String,
    /// The catalogue model the camera is registered under; none for the default or a skipped one.
    model: Option<ModelRef>,
    status: Status,
}

pub(crate) fn execute(cmd: &ImportCommand, ctx: &Context<'_>) -> ExitCode {
    let result = match cmd {
        ImportCommand::Agentdvr {
            file,
            format,
            model,
            camera_model,
            dry_run,
        } => agentdvr(
            ctx,
            file.as_deref(),
            *format,
            model.as_deref(),
            camera_model,
            *dry_run,
        ),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            report_error(&e, ctx.log_format);
            ExitCode::from(e.exit_code())
        }
    }
}

/// The models the user chose on the command line, checked against the catalogue.
#[derive(Debug, Default)]
struct Choice {
    /// `--model`: every camera without an entry of its own.
    all: Option<ModelRef>,
    /// `--camera-model`: one camera each.
    each: Vec<(CameraId, ModelRef)>,
}

impl Choice {
    /// Parses the options. Refuses a malformed value, a model that is in no catalogue entry and a
    /// camera named twice (which of the two would be a guess).
    ///
    /// No error echoes the option text.
    fn parse(
        all: Option<&str>,
        each: &[String],
        catalogue: &[CatalogueEntry],
    ) -> Result<Self, ImportError> {
        let known = |text: &str| -> Result<ModelRef, ImportError> {
            let m = super::camera::parse_model(text).map_err(|_| ImportError::ModelArg)?;
            if catalogue
                .iter()
                .any(|e| ModelRef::from_entry(e).is_ok_and(|x| x == m))
            {
                Ok(m)
            } else {
                Err(ImportError::UnknownModel)
            }
        };
        let all = all.map(known).transpose()?;
        let mut pairs: Vec<(CameraId, ModelRef)> = Vec::with_capacity(each.len());
        for text in each {
            let (id, model) = text.split_once('=').ok_or(ImportError::ModelArg)?;
            let id = CameraId::new(id).map_err(|_| ImportError::ModelArg)?;
            if pairs.iter().any(|(seen, _)| *seen == id) {
                return Err(ImportError::DuplicateCamera);
            }
            pairs.push((id, known(model)?));
        }
        Ok(Self { all, each: pairs })
    }

    fn for_camera(&self, id: &CameraId) -> Option<&ModelRef> {
        self.each
            .iter()
            .find(|(c, _)| c == id)
            .map(|(_, m)| m)
            .or(self.all.as_ref())
    }
}

fn agentdvr(
    ctx: &Context<'_>,
    file: Option<&Path>,
    format: FormatArg,
    model: Option<&str>,
    camera_model: &[String],
    dry_run: bool,
) -> Result<(), ImportError> {
    let config = load(&resolve_path(ctx.config_flag, ctx.env)?)?;
    if vault_path(&config) == config.database_path() {
        return Err(ImportError::SameFile);
    }
    let catalogue = super::camera::catalogue().map_err(ImportError::Catalogue)?;
    let choice = Choice::parse(model, camera_model, &catalogue)?;
    let file = input_path(file, DEFAULT_INPUTS)?;
    let bytes = read_input(&file)?;
    let parsed = wardenlens_agentdvr::parse_as(format_of(format, &bytes), &bytes)
        .map_err(ImportError::Parse)?;
    drop(bytes);
    if choice
        .each
        .iter()
        .any(|(id, _)| !parsed.cameras.iter().any(|d| d.id == *id))
    {
        return Err(ImportError::UnknownCamera);
    }
    let (ready, mut rows) = screen(parsed.cameras, &parsed.logins, &catalogue, &choice)?;
    rows.extend(parsed.skipped.iter().map(skipped_row));
    if dry_run {
        let registry = open_for_dry_run(&config)?;
        for r in &ready {
            let existing = match &registry {
                Registry::Reader(i) => i
                    .get_camera(&r.draft.id, &catalogue)
                    .map_err(ImportError::Index)?,
                Registry::None | Registry::Changes(_) => None,
            };
            rows.push(match (&registry, conflict(existing.as_ref(), r)) {
                (_, Some(why)) => row_of(&r.draft, None, Status::Skipped(why)),
                (Registry::Changes(p), None) => row(r, Status::WouldImportAfter(*p)),
                _ => row(r, Status::WouldImport),
            });
        }
    } else {
        let key = load_key(config.key_file())?;
        let written = write_all(&config, key, &ready, &catalogue)?;
        rows.extend(written);
    }
    print_table(&rows, &mut io::stdout().lock()).map_err(ImportError::Output)
}

/// Where an install keeps its configuration, in the order tried when no file is given: the
/// current `objects.json`, then the older `objects.xml`. The numbered `.bak` copies are never read.
const DEFAULT_INPUTS: &[&str] = &[
    "/opt/AgentDVR/Media/XML/objects.json",
    "/opt/AgentDVR/Media/XML/objects.xml",
];

/// The file to read: the given one, else the first of `defaults` that is not missing. A candidate
/// is skipped only when `lstat` says `NotFound`; any other error (permission denied, a file in the
/// way) returns that path, so opening it reports the real cause instead of "no file". A symbolic
/// link counts as present (opening it later refuses it). Nothing is opened or read to choose.
fn input_path(given: Option<&Path>, defaults: &[&str]) -> Result<PathBuf, ImportError> {
    if let Some(p) = given {
        return Ok(p.to_path_buf());
    }
    for candidate in defaults.iter().map(Path::new) {
        match std::fs::symlink_metadata(candidate) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            _ => return Ok(candidate.to_path_buf()),
        }
    }
    Err(ImportError::NoDefaultInput)
}

/// The format to parse as: the forced one, else the one the content shows.
fn format_of(arg: FormatArg, bytes: &[u8]) -> wardenlens_agentdvr::Format {
    match arg {
        FormatArg::Xml => wardenlens_agentdvr::Format::Xml,
        FormatArg::Json => wardenlens_agentdvr::Format::Json,
        FormatArg::Auto => wardenlens_agentdvr::detect(bytes),
    }
}

/// What the dry run knows of the registry (see [`open_for_dry_run`]).
enum Registry {
    /// No index yet (a missing or zero-length file): the real run creates it.
    None,
    /// The index, opened read-only.
    Reader(ReadOnlyIndex),
    /// The real run would first change the index, so no row is compared.
    Changes(Prelude),
}

/// What the real run does to the index before it writes a row, which a read-only dry run only
/// reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Prelude {
    /// An older schema: migrated first.
    Migrate,
    /// An unrecovered `-wal`: recovered first.
    Recover,
}

/// Opens the registry for the dry run with [`Index::open_read_only`]: it writes no byte of the
/// main file, the `-wal` or any other file (no migration, no pragma, no file created, no lock).
/// The one thing SQLite may update is the `-shm` of a live `-wal`, as for any reader. It keeps the
/// real open's refusals (a stray sidecar, a bad owner or mode, a damaged file, a missing parent
/// directory), which are errors here as in the real run. States the real run would change first
/// are reported, not entered. The answer is advisory (see the index crate's `readonly` docs).
fn open_for_dry_run(config: &Config) -> Result<Registry, ImportError> {
    let path = config.database_path();
    let parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    registry_of(Index::open_read_only(path), parent.is_dir())
}

/// The registry state a dry run reports for the result of the read-only open. Pure, so every
/// input is unit-tested.
///
/// A missing file is "no index" only when its parent directory exists: with no parent the real run
/// refuses (the vault cannot be created either), so the dry run refuses too.
fn registry_of(
    opened: Result<ReadOnlyIndex, IndexError>,
    parent_exists: bool,
) -> Result<Registry, ImportError> {
    match opened {
        Ok(r) => Ok(Registry::Reader(r)),
        Err(IndexError::Fs(e)) if e.is_not_found() && parent_exists => Ok(Registry::None),
        Err(IndexError::Uninitialised) => Ok(Registry::None),
        Err(IndexError::NeedsMigration) => Ok(Registry::Changes(Prelude::Migrate)),
        Err(IndexError::NeedsRecovery) => Ok(Registry::Changes(Prelude::Recover)),
        Err(e) => Err(ImportError::Index(e)),
    }
}

/// Why the row that the registry holds must be left alone, if so (see the module docs): it is
/// under a catalogue model that differs from the one chosen now. Shared by the dry run and the
/// real run, so they agree.
fn conflict(existing: Option<&StoredCamera>, r: &Ready) -> Option<SkipWhy> {
    let have = existing?.record().model();
    (have.vendor() != OWN_VENDOR && *have != r.model).then(|| SkipWhy::ExistingModel(have.clone()))
}

/// A camera that passed the screen, with the model it is registered under.
#[derive(Debug, Clone)]
pub(super) struct Ready {
    pub(super) draft: CameraDraft,
    pub(super) model: ModelRef,
}

/// The default model: in no catalogue.
fn default_model() -> Result<ModelRef, ImportError> {
    ModelRef::new(MODEL.0, MODEL.1).map_err(ImportError::Camera)
}

/// The catalogue models that list exactly this path (head and query) among their RTSP paths, each
/// once. Only catalogue data is read.
fn models_listing(catalogue: &[CatalogueEntry], path: &RtspPath) -> Vec<ModelRef> {
    let mut found: Vec<ModelRef> = Vec::new();
    for entry in catalogue {
        let lists = entry
            .protocols
            .iter()
            .filter(|p| p.kind == ProtocolKind::Rtsp)
            .flat_map(|p| &p.paths)
            .any(|listed| listed == path.as_str());
        if let (true, Ok(m)) = (lists, ModelRef::from_entry(entry))
            && !found.contains(&m)
        {
            found.push(m);
        }
    }
    found
}

/// The model one camera is registered under, or why it is not imported.
///
/// In this order: its `--camera-model`, `--model`, then, only for a path with a query string (the
/// one case where a model is needed to import it), the one catalogue model that lists the path
/// exactly. Several such models are never guessed. A path with no query and no choice keeps the
/// default model. Whatever the source, a query string must be listed for the resulting model
/// (SEC-10): a chosen model does not make an unlisted query acceptable.
fn resolve(
    d: &CameraDraft,
    catalogue: &[CatalogueEntry],
    choice: &Choice,
    default: &ModelRef,
) -> Result<ModelRef, SkipWhy> {
    if let Some(m) = choice.for_camera(&d.id) {
        return if query_allowed(catalogue, m, &d.path) {
            Ok(m.clone())
        } else {
            Err(SkipWhy::QueryNotListed(Some(m.clone())))
        };
    }
    if d.path.query().is_none() {
        return Ok(default.clone());
    }
    let mut found = models_listing(catalogue, &d.path);
    match found.len() {
        0 => Err(SkipWhy::QueryNotListed(None)),
        1 => found.pop().ok_or(SkipWhy::QueryNotListed(None)),
        _ => Err(SkipWhy::Ambiguous(found)),
    }
}

/// The size limit as a `u64`.
fn size_limit(path: &Path) -> Result<u64, ImportError> {
    u64::try_from(MAX_INPUT_BYTES).map_err(|_| too_large(path))
}

fn too_large(path: &Path) -> ImportError {
    ImportError::TooLarge {
        path: path.to_path_buf(),
    }
}

/// Guard 1: the size from `fstat` of the opened file is over the limit.
fn check_declared_size(size: u64, path: &Path) -> Result<(), ImportError> {
    if size > size_limit(path)? {
        return Err(too_large(path));
    }
    Ok(())
}

/// Guard 2: reads at most the limit plus one byte of `src` and refuses when more than the limit
/// came, whatever size `declared` (from `fstat`) said: a file that grew after it was opened is
/// bounded too.
fn read_bounded(
    src: impl Read,
    declared: u64,
    path: &Path,
) -> Result<Zeroizing<Vec<u8>>, ImportError> {
    let limit = size_limit(path)?;
    // Capacity for the whole bounded read, so the buffer never reallocates and leaves copies.
    let capacity =
        usize::try_from(declared.min(limit).saturating_add(1)).map_err(|_| too_large(path))?;
    let mut buf = Zeroizing::new(Vec::with_capacity(capacity));
    src.take(limit.saturating_add(1))
        .read_to_end(&mut buf)
        .map_err(|source| ImportError::Read {
            path: path.to_path_buf(),
            source,
        })?;
    if u64::try_from(buf.len()).map_or(true, |n| n > limit) {
        return Err(too_large(path));
    }
    Ok(buf)
}

/// Opens, bounds and reads the input; see the module docs.
fn read_input(path: &Path) -> Result<Zeroizing<Vec<u8>>, ImportError> {
    let (file, stat) = open_regular_nofollow(path).map_err(|e| ImportError::open(path, e))?;
    check_declared_size(stat.size, path)?;
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
    read_bounded(file, stat.size, path)
}

/// Splits the drafts into those that can be written (with their model) and the rows of those that
/// cannot.
///
/// A draft is refused when its path contains any login of the file (any user or password the
/// parser read, skipped entries included, compared ASCII-case-insensitively with the path as
/// written and, defensively, percent-decoded): the registry would hold it in plaintext. Such a row
/// shows `-` for the path, and a query path that is skipped shows only the
/// part before `?`, so no refused path ever reaches the output. Then [`resolve`] picks the model.
///
/// # Errors
/// [`ImportError::Screen`] when the search cannot be built: never "no match".
fn screen(
    drafts: Vec<CameraDraft>,
    logins: &Logins,
    catalogue: &[CatalogueEntry],
    choice: &Choice,
) -> Result<(Vec<Ready>, Vec<Row>), ImportError> {
    let (ready, rows, _) = screen_with(drafts, logins, catalogue, choice, build_matcher)?;
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
    catalogue: &[CatalogueEntry],
    choice: &Choice,
    build: impl FnOnce(&[Zeroizing<Vec<u8>>]) -> Result<AhoCorasick, ImportError>,
) -> Result<(Vec<Ready>, Vec<Row>, u64), ImportError> {
    let mut work = 0_u64;
    let mut ready = Vec::new();
    let mut rows = Vec::new();
    let default = default_model()?;
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
            let mut r = row_of(&d, None, Status::Skipped(SkipWhy::LoginInPath));
            "-".clone_into(&mut r.path);
            rows.push(r);
            continue;
        }
        match resolve(&d, catalogue, choice, &default) {
            Ok(model) => ready.push(Ready { draft: d, model }),
            Err(why) => {
                // The registry vets the same thing on write; checking here keeps a dry run honest.
                let mut r = row_of(&d, None, Status::Skipped(why));
                let head = before_query(&r.path).to_owned();
                r.path = head;
                rows.push(r);
            }
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

/// A row for a camera that passed the screen. The default model is not shown.
fn row(r: &Ready, status: Status) -> Row {
    let shown = (r.model.vendor() != OWN_VENDOR).then(|| r.model.clone());
    row_of(&r.draft, shown, status)
}

fn row_of(d: &CameraDraft, model: Option<ModelRef>, status: Status) -> Row {
    Row {
        id: d.id.to_string(),
        host: d.host.expose(),
        path: d.path.as_str().to_owned(),
        model,
        status,
    }
}

fn skipped_row(s: &Skipped) -> Row {
    Row {
        id: "-".to_owned(),
        host: "-".to_owned(),
        path: "-".to_owned(),
        model: None,
        status: Status::Skipped(SkipWhy::Parser {
            reason: s.reason,
            position: s.position,
        }),
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

/// Writes the cameras: the vault entries, then the registry row.
///
/// A row that the registry already holds under a catalogue model (vendor other than `agentdvr`)
/// that differs from the one chosen now is left as it is and its vault entries are not touched; the
/// camera is reported skipped. Ids are always `agentdvr-<n>`, which `camera add` refuses, so no
/// `camera add` can create or change a row between the read and the write below.
///
/// # Errors
/// Vault, index and clock errors. A failure midway leaves the vault entries of the camera it
/// stopped at without a registry row (nothing lists them; running again repairs them).
pub(super) fn write_all(
    config: &Config,
    key: KeyFile,
    ready: &[Ready],
    catalogue: &[CatalogueEntry],
) -> Result<Vec<Row>, ImportError> {
    let mut vault = open_vault(&vault_path(config), key).map_err(ImportError::Vault)?;
    let mut index = Index::open(config.database_path()).map_err(ImportError::Index)?;
    // The registry may hold cameras whose paths carry a query that the catalogue lists
    // (`camera add`); reading or writing a row with no catalogue would refuse them.
    let mut rows = Vec::with_capacity(ready.len());
    for r in ready {
        let d = &r.draft;
        let existing = index
            .get_camera(&d.id, catalogue)
            .map_err(ImportError::Index)?;
        if let Some(why) = conflict(existing.as_ref(), r) {
            rows.push(row_of(d, None, Status::Skipped(why)));
            continue;
        }
        write_vault(&mut vault, d)?;
        let record = CameraRecord::new(
            d.id.clone(),
            r.model.clone(),
            d.port,
            StreamSet::new(d.path.clone(), None),
        );
        index
            .upsert_camera(&record, catalogue, now()?)
            .map_err(ImportError::Index)?;
        rows.push(row(
            r,
            if existing.is_some() {
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
    let model: Vec<String> = rows
        .iter()
        .map(|r| {
            r.model
                .as_ref()
                .map_or_else(|| "-".to_owned(), ToString::to_string)
        })
        .collect();
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
    let wm = model
        .iter()
        .map(|m| m.chars().count())
        .chain(["model".len()])
        .max()
        .unwrap_or(0);
    writeln!(
        out,
        "{:wi$}  {:wh$}  {:wp$}  {:wm$}  status",
        "id", "host", "path", "model"
    )?;
    for ((r, s), m) in rows.iter().zip(&status).zip(&model) {
        writeln!(
            out,
            "{:wi$}  {:wh$}  {:wp$}  {m:wm$}  {s}",
            r.id, r.host, r.path
        )?;
    }
    out.flush()
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret as _;

    #[test]
    fn the_default_input_is_the_first_existing_candidate_and_a_given_file_wins() {
        let dir = tempfile::tempdir().unwrap();
        let json = dir.path().join("objects.json");
        let xml = dir.path().join("objects.xml");
        let (j, x) = (json.to_str().unwrap(), xml.to_str().unwrap());
        let defaults = [j, x];
        // None exists.
        assert!(matches!(
            input_path(None, &defaults),
            Err(ImportError::NoDefaultInput)
        ));
        // Only the later one exists.
        std::fs::write(&xml, "<objects/>").unwrap();
        assert_eq!(input_path(None, &defaults).unwrap(), xml);
        // Both exist: the first wins.
        std::fs::write(&json, "{}").unwrap();
        assert_eq!(input_path(None, &defaults).unwrap(), json);
        // A given file is used as it is, existing or not (opening it reports the error).
        let given = dir.path().join("elsewhere");
        assert_eq!(input_path(Some(&given), &defaults).unwrap(), given);
        // A dangling link counts as present, so opening it refuses it by name.
        std::fs::remove_file(&json).unwrap();
        std::os::unix::fs::symlink(dir.path().join("nowhere"), &json).unwrap();
        assert_eq!(input_path(None, &defaults).unwrap(), json);
    }

    #[test]
    fn a_candidate_that_cannot_be_examined_is_returned_not_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let locked = dir.path().join("locked");
        std::fs::create_dir(&locked).unwrap();
        let hidden = locked.join("objects.json");
        let next = dir.path().join("objects.xml");
        std::fs::write(&next, "<objects/>").unwrap();
        std::fs::set_permissions(&locked, std::os::unix::fs::PermissionsExt::from_mode(0o000))
            .unwrap();
        let defaults = [hidden.to_str().unwrap(), next.to_str().unwrap()];
        let got = input_path(None, &defaults);
        let opened = read_input(&hidden);
        std::fs::set_permissions(&locked, std::os::unix::fs::PermissionsExt::from_mode(0o700))
            .unwrap();
        // As root the directory stays readable and the candidate is simply missing.
        if std::fs::symlink_metadata(&hidden).is_ok() || got.as_ref().is_ok_and(|p| *p == next) {
            return;
        }
        assert_eq!(got.unwrap(), hidden);
        assert!(matches!(opened, Err(ImportError::Open { .. })));
    }

    #[test]
    fn no_default_input_exits_2() {
        assert_eq!(ImportError::NoDefaultInput.exit_code(), 2);
    }

    #[test]
    fn the_built_in_defaults_name_the_json_first_and_never_a_backup() {
        assert_eq!(
            DEFAULT_INPUTS,
            [
                "/opt/AgentDVR/Media/XML/objects.json",
                "/opt/AgentDVR/Media/XML/objects.xml"
            ]
        );
    }

    #[test]
    fn format_of_forces_or_detects() {
        use wardenlens_agentdvr::Format;
        let rows: [(FormatArg, &[u8], Format); 6] = [
            (FormatArg::Auto, b"{}", Format::Json),
            (FormatArg::Auto, b"<objects/>", Format::Xml),
            (FormatArg::Xml, b"{}", Format::Xml),
            (FormatArg::Json, b"<objects/>", Format::Json),
            (FormatArg::Json, b"", Format::Json),
            (FormatArg::Auto, b"", Format::Xml),
        ];
        for (arg, bytes, want) in rows {
            assert_eq!(format_of(arg, bytes), want);
        }
    }

    #[test]
    fn table_lists_columns_and_never_more() {
        let rows = vec![
            Row {
                id: "agentdvr-1".into(),
                host: "192.0.2.10".into(),
                path: "/s".into(),
                model: None,
                status: Status::Imported,
            },
            Row {
                id: "-".into(),
                host: "-".into(),
                path: "-".into(),
                model: None,
                status: Status::Skipped(SkipWhy::LoginInPath),
            },
        ];
        let mut out = Vec::new();
        print_table(&rows, &mut out).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert_eq!(text.lines().count(), 3);
        assert!(text.contains("agentdvr-1  192.0.2.10"));
        assert!(text.contains("skipped: path contains the login"));
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

    fn screen_all(i: wardenlens_agentdvr::Import) -> (Vec<Ready>, Vec<Row>) {
        screen(i.cameras, &i.logins, &[], &Choice::default()).unwrap()
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
        let parsed = ends_match_import();
        assert_eq!(parsed.logins.len(), 4096);
        let (ready, _, work) = screen_with(
            parsed.cameras,
            &parsed.logins,
            &[],
            &Choice::default(),
            build_matcher,
        )
        .unwrap();
        assert_eq!(ready.len(), 255);
        // One pass over each 512-byte path (the decoded text equals the written one, so it is
        // not scanned again); independent of the 4096 logins.
        assert_eq!(work, 255 * 512);
        assert!(work <= MAX_SCREEN_WORK);
    }

    #[test]
    fn a_matcher_that_cannot_be_built_fails_the_screen_closed() {
        let i = drafts("/live/Fake-pw-1/main", "u-fake", "Fake-pw-1");
        let r = screen_with(i.cameras, &i.logins, &[], &Choice::default(), |_| {
            Err(ImportError::Screen)
        });
        assert!(matches!(r, Err(ImportError::Screen)));
        // With no login there is nothing to build, so a failing builder is never asked.
        let i = drafts("/live/main", "", "");
        let (ready, _, _) = screen_with(i.cameras, &i.logins, &[], &Choice::default(), |_| {
            Err(ImportError::Screen)
        })
        .unwrap();
        assert_eq!(ready.len(), 1);
    }

    #[test]
    fn a_path_holding_the_login_is_refused_and_never_shown() {
        // (path, user, password): every one holds the password or the user.
        for (path, user, pw) in [
            ("/live/Fake-pw-1/main", "u-fake", "Fake-pw-1"),
            ("/a/u-fake/b", "u-fake", "Fake-pw-1"),
            ("/x_zzq=Fake-pw-1", "u-fake", "Fake-pw-1"),
        ] {
            let (ready, rows) = screen_all(drafts(path, user, pw));
            assert!(ready.is_empty(), "{path}");
            assert_eq!(rows.len(), 1);
            let shown = format!("{:?}", rows[0]);
            assert!(!shown.contains(pw) && !shown.contains(user), "{shown}");
            assert_eq!(rows[0].path, "-");
        }
        // An empty password matches nothing; a path without the login passes.
        let (ready, _) = screen_all(drafts("/live/main", "u-fake", ""));
        assert_eq!(ready.len(), 1);
        let (ready, _) = screen_all(drafts("/live/main", "u-fake", "Fake-pw-1"));
        assert_eq!(ready.len(), 1);
    }

    #[test]
    fn another_cameras_login_and_other_case_are_refused() {
        let xml = "<objects><cameras>\
            <camera id=\"1\" name=\"A\"><settings><videosourcestring>rtsp://192.0.2.5/s\
            </videosourcestring><login>u-fake</login><password>Fake-pw-1</password></settings></camera>\
            <camera id=\"2\" name=\"B\"><settings><videosourcestring>rtsp://192.0.2.6/x/FAKE-PW-1/y\
            </videosourcestring></settings></camera>\
            <camera id=\"3\" name=\"C\"><settings><videosourcestring>rtsp://192.0.2.7/ok\
            </videosourcestring></settings></camera></cameras></objects>";
        let (ready, rows) = screen_all(wardenlens_agentdvr::parse(xml.as_bytes()).unwrap());
        let ids: Vec<_> = ready.iter().map(|r| r.draft.id.to_string()).collect();
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
        let (ready, rows) = screen_all(drafts("/s?pin=7731", "u-fake", "Fake-pw-1"));
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

    // ---- #163: catalogue models ---------------------------------------------------------------

    /// A synthetic catalogue entry with one RTSP protocol listing `paths`.
    fn entry(vendor: &str, model: &str, paths: &[&str]) -> CatalogueEntry {
        let list: Vec<String> = paths.iter().map(|p| format!("\"{p}\"")).collect();
        CatalogueEntry::from_toml_str(&format!(
            "vendor = \"{vendor}\"\nmodel = \"{model}\"\nsupport = \"community\"\n\
             [[protocols]]\nkind = \"rtsp\"\npaths = [{}]\n\
             [[evidence]]\nreference = \"docs/adr/0002-camera-integration.md\"\n",
            list.join(", ")
        ))
        .unwrap()
    }

    fn model(v: &str, m: &str) -> ModelRef {
        ModelRef::new(v, m).unwrap()
    }

    /// Two models with a distinct listed query path, and two that list the same one.
    fn catalogue() -> Vec<CatalogueEntry> {
        vec![
            entry("acme", "c1", &["/cam?channel=1&subtype=0", "/plain1"]),
            entry("acme", "c2", &["/other?x=1"]),
            entry("acme", "d1", &["/dual?z=1"]),
            entry("beta", "d2", &["/dual?z=1"]),
        ]
    }

    fn one_draft(path: &str) -> CameraDraft {
        drafts(path, "", "").cameras.remove(0)
    }

    #[test]
    fn the_model_of_a_camera_is_decided_by_this_table() {
        let cat = catalogue();
        let default = default_model().unwrap();
        let c1 = model("acme", "c1");
        let c2 = model("acme", "c2");
        let none = Choice::default();
        let all_c1 = Choice {
            all: Some(c1.clone()),
            each: Vec::new(),
        };
        let each_c2 = Choice {
            all: Some(c1.clone()),
            each: vec![(CameraId::new("agentdvr-1").unwrap(), c2.clone())],
        };
        let other_id = Choice {
            all: None,
            each: vec![(CameraId::new("agentdvr-9").unwrap(), c2.clone())],
        };
        let amp = "?channel=1&amp;subtype=0";
        let cam = format!("/cam{amp}");
        // (choice, path, expected)
        let cases: Vec<(&Choice, &str, Result<ModelRef, SkipWhy>)> = vec![
            // matched from the catalogue by the path shape
            (&none, &cam, Ok(c1.clone())),
            (&none, "/other?x=1", Ok(c2.clone())),
            // no query and no choice: the default model
            (&none, "/stream1", Ok(default.clone())),
            // even a path that a model lists, without a query: still the default
            (&none, "/plain1", Ok(default.clone())),
            // the query is listed by no model, or only for another path head
            (
                &none,
                "/cam?channel=2&amp;subtype=0",
                Err(SkipWhy::QueryNotListed(None)),
            ),
            (&none, "/elsewhere?x=1", Err(SkipWhy::QueryNotListed(None))),
            (
                &none,
                "/cam?channel=1&amp;subtype=0&amp;extra=1",
                Err(SkipWhy::QueryNotListed(None)),
            ),
            // two models list it: never a guess
            (
                &none,
                "/dual?z=1",
                Err(SkipWhy::Ambiguous(vec![
                    model("acme", "d1"),
                    model("beta", "d2"),
                ])),
            ),
            // a chosen model
            (&all_c1, "/stream1", Ok(c1.clone())),
            (&all_c1, &cam, Ok(c1.clone())),
            // `query_allowed` compares the query only: a chosen model that lists this query
            // accepts it on another path head (unlike the auto-match, which needs the exact
            // listed path). The choice is the user's; the credential rules still apply.
            (
                &all_c1,
                "/elsewhere?channel=1&amp;subtype=0",
                Ok(c1.clone()),
            ),
            (&each_c2, "/other?x=1", Ok(c2.clone())),
            (&each_c2, "/stream1", Ok(c2.clone())),
            (&other_id, "/stream1", Ok(default.clone())),
            // SEC-10: a chosen model does not make an unlisted query acceptable, and another
            // model that lists it is not substituted
            (
                &all_c1,
                "/other?x=1",
                Err(SkipWhy::QueryNotListed(Some(c1.clone()))),
            ),
            (
                &all_c1,
                "/dual?z=1",
                Err(SkipWhy::QueryNotListed(Some(c1.clone()))),
            ),
            (
                &each_c2,
                &cam,
                Err(SkipWhy::QueryNotListed(Some(c2.clone()))),
            ),
        ];
        for (choice, path, want) in cases {
            let d = one_draft(path);
            assert_eq!(
                resolve(&d, &cat, choice, &default),
                want,
                "{path} with {choice:?}"
            );
        }
    }

    /// #218: a Dahua ONVIF-form path matches the Dahua model by the same listed-query rule.
    #[test]
    fn a_dahua_onvif_form_path_auto_matches_the_dahua_model() {
        let dahua = model("dahua", "ipc-hfw4431r-z");
        let cat = vec![entry(
            "dahua",
            "ipc-hfw4431r-z",
            &[
                "/cam/realmonitor?channel=1&subtype=0",
                "/cam/realmonitor?channel=1&subtype=0&unicast=true&proto=Onvif",
            ],
        )];
        let default = default_model().unwrap();
        let none = Choice::default();
        let amp = "?channel=1&amp;subtype=0&amp;unicast=true&amp;proto=Onvif";
        let d = one_draft(&format!("/cam/realmonitor{amp}"));
        assert_eq!(resolve(&d, &cat, &none, &default), Ok(dahua));
        let d = one_draft("/cam/realmonitor?proto=Onvif&amp;unicast=true");
        assert_eq!(
            resolve(&d, &cat, &none, &default),
            Err(SkipWhy::QueryNotListed(None))
        );
    }

    #[test]
    fn a_listed_query_path_is_ready_and_an_unlisted_one_is_skipped_by_the_screen() {
        let cat = catalogue();
        let xml = "<objects><cameras>\
            <camera id=\"1\" name=\"A\"><settings><videosourcestring>\
            rtsp://192.0.2.5/cam?channel=1&amp;subtype=0</videosourcestring></settings></camera>\
            <camera id=\"2\" name=\"B\"><settings><videosourcestring>\
            rtsp://192.0.2.6/cam?channel=7&amp;subtype=0</videosourcestring></settings></camera>\
            <camera id=\"3\" name=\"C\"><settings><videosourcestring>\
            rtsp://192.0.2.7/dual?z=1</videosourcestring></settings></camera>\
            </cameras></objects>";
        let i = wardenlens_agentdvr::parse(xml.as_bytes()).unwrap();
        let (ready, rows) = screen(i.cameras, &i.logins, &cat, &Choice::default()).unwrap();
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0].model, model("acme", "c1"));
        assert_eq!(ready[0].draft.path.as_str(), "/cam?channel=1&subtype=0");
        assert_eq!(rows.len(), 2);
        // Neither refused row shows the query.
        assert!(rows.iter().all(|r| !r.path.contains('?')), "{rows:?}");
        let text: Vec<String> = rows.iter().map(|r| r.status.text()).collect();
        assert!(text[0].contains("query"), "{text:?}");
        // The ambiguity names model ids only: no host, no name, no path.
        assert_eq!(
            text[1],
            "skipped: ambiguous: the path is listed by models acme/d1, beta/d2; \
             choose one with --camera-model"
        );
        for t in &text {
            assert!(!t.contains("192.0.2") && !t.contains("dual"), "{t}");
        }
    }

    #[test]
    fn the_model_options_are_checked_against_the_catalogue() {
        let cat = catalogue();
        let ok = |all: Option<&str>, each: &[&str]| {
            let each: Vec<String> = each.iter().map(|s| (*s).to_owned()).collect();
            Choice::parse(all, &each, &cat)
        };
        let c = ok(Some("acme/c1"), &["agentdvr-2=acme/c2"]).unwrap();
        assert_eq!(c.all, Some(model("acme", "c1")));
        assert_eq!(c.each.len(), 1);
        assert!(ok(None, &[]).unwrap().all.is_none());
        for bad in ["", "acme", "acme/", "/c1", "Acme/C1", "a/b/c"] {
            assert!(
                matches!(ok(Some(bad), &[]), Err(ImportError::ModelArg)),
                "{bad:?}"
            );
        }
        // Well formed but in no catalogue entry (the default model is in none either).
        for unknown in ["acme/zz", "other/c1", "agentdvr/imported"] {
            assert!(
                matches!(ok(Some(unknown), &[]), Err(ImportError::UnknownModel)),
                "{unknown}"
            );
        }
        for bad in [
            "agentdvr-2",
            "=acme/c1",
            "agentdvr-2=",
            "Bad Id=acme/c1",
            "agentdvr-2=acme/zz",
        ] {
            assert!(ok(None, &[bad]).is_err(), "{bad:?}");
        }
        // A camera named twice is refused, even for the same model, with its own error.
        for pair in [
            ["agentdvr-2=acme/c1", "agentdvr-2=acme/c1"],
            ["agentdvr-2=acme/c1", "agentdvr-2=acme/c2"],
        ] {
            let e = ok(None, &pair).unwrap_err();
            assert!(matches!(e, ImportError::DuplicateCamera), "{e:?}");
            assert!(!e.to_string().contains("agentdvr-2"), "{e}");
        }
        // No error echoes the option.
        let e = ok(Some("secretword/x"), &[]).unwrap_err().to_string();
        assert!(!e.contains("secretword"), "{e}");
    }

    #[test]
    fn exit_codes_line_up_with_the_config_file_errors() {
        let p = || PathBuf::from("/srv/x");
        let parse = wardenlens_agentdvr::parse(b"<nope").unwrap_err();
        // A document refused for its content: 1 (as `ConfigFileError::Invalid`).
        assert_eq!(ImportError::Parse(parse).exit_code(), 1);
        // A file that cannot be used: 2 (as `NotFound`, `TooLarge`, `NotRegular`, `Symlink`).
        assert_eq!(ImportError::TooLarge { path: p() }.exit_code(), 2);
        assert_eq!(ImportError::NotFound { path: p() }.exit_code(), 2);
        assert_eq!(ImportError::NotRegular { path: p() }.exit_code(), 2);
        assert_eq!(ImportError::Symlink { path: p() }.exit_code(), 2);
        for usage in [
            ImportError::ModelArg,
            ImportError::DuplicateCamera,
            ImportError::UnknownModel,
            ImportError::UnknownCamera,
        ] {
            assert_eq!(usage.exit_code(), 1);
        }
    }

    #[test]
    fn a_path_that_is_not_a_regular_file_is_its_own_error() {
        let e = ImportError::open(Path::new("/srv/x"), FsError::NotRegular);
        assert!(matches!(e, ImportError::NotRegular { .. }), "{e:?}");
        let dir = tempfile::tempdir().unwrap();
        assert!(matches!(
            read_input(dir.path()),
            Err(ImportError::NotRegular { .. })
        ));
    }

    /// Guard 1 alone: the size from `fstat`.
    #[test]
    fn the_declared_size_guard_refuses_on_its_own() {
        let p = Path::new("/srv/x");
        let limit = u64::try_from(MAX_INPUT_BYTES).unwrap();
        assert!(check_declared_size(limit, p).is_ok());
        assert!(matches!(
            check_declared_size(limit + 1, p),
            Err(ImportError::TooLarge { .. })
        ));
    }

    /// Guard 2 alone: the file said it was small and then grew; the declared size is not asked.
    #[test]
    fn the_read_bound_refuses_a_file_that_grew_after_it_was_opened() {
        let p = Path::new("/srv/x");
        let limit = MAX_INPUT_BYTES;
        let at = vec![b' '; limit];
        assert_eq!(read_bounded(&at[..], 0, p).unwrap().len(), limit);
        let over = vec![b' '; limit + 1];
        assert!(matches!(
            read_bounded(&over[..], 0, p),
            Err(ImportError::TooLarge { .. })
        ));
        // An endless source is bounded too, not read to the end.
        assert!(matches!(
            read_bounded(io::repeat(b' '), 10, p),
            Err(ImportError::TooLarge { .. })
        ));
    }

    /// The private directories the vault and the key file need.
    fn make_dirs(dir: &Path) {
        use std::os::unix::fs::PermissionsExt;
        for d in ["state", "keys"] {
            let p = dir.join(d);
            std::fs::create_dir(&p).unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
    }

    /// A synthetic config in `dir`.
    fn site_config(dir: &Path) -> Config {
        let t = dir.display();
        Config::from_toml_str(&format!(
            "[api]\nlisten = \"127.0.0.1:8080\"\n[storage]\nhot_root = \"{t}/hot\"\n\
             archive_root = \"{t}/archive\"\n[database]\npath = \"{t}/state/index.db\"\n\
             [secrets]\nkey_file = \"{t}/keys/secrets.key\"\n"
        ))
        .unwrap()
    }

    /// A run that fails at the registry after the vault writes leaves vault entries with no
    /// registry row (documented in the module docs); running again completes it.
    #[test]
    fn a_failed_index_write_after_the_vault_writes_is_repaired_by_a_rerun() {
        let dir = tempfile::tempdir().unwrap();
        make_dirs(dir.path());
        let config = site_config(dir.path());
        let key = KeyFile::generate(config.key_file()).unwrap();
        let cat = catalogue();
        let d = one_draft("/cam?channel=1&amp;subtype=0");
        let host_id = d.id.entry_id(EntryKind::Host).unwrap();
        // The query is listed by `acme/c1` and not by the default model: the registry refuses the
        // row after the vault entries were written.
        let bad = [Ready {
            draft: d.clone(),
            model: default_model().unwrap(),
        }];
        let err = write_all(&config, key, &bad, &cat).unwrap_err();
        assert!(matches!(err, ImportError::Index(_)), "{err:?}");
        let key = KeyFile::load(config.key_file()).unwrap();
        let vault = Vault::open(&vault_path(&config), key).unwrap();
        assert!(
            vault.get(&host_id).is_ok(),
            "the vault entries were written"
        );
        drop(vault);
        let index = Index::open(config.database_path()).unwrap();
        assert!(index.get_camera(&d.id, &cat).unwrap().is_none(), "no row");
        drop(index);
        // The run again, with the model that lists the path.
        let good = [Ready {
            draft: d.clone(),
            model: model("acme", "c1"),
        }];
        let key = KeyFile::load(config.key_file()).unwrap();
        let rows = write_all(&config, key, &good, &cat).unwrap();
        assert_eq!(rows[0].status, Status::Imported);
        let index = Index::open(config.database_path()).unwrap();
        let got = index.get_camera(&d.id, &cat).unwrap().unwrap();
        assert_eq!(got.record().model(), &model("acme", "c1"));
        assert_eq!(
            got.record().streams().main.as_str(),
            "/cam?channel=1&subtype=0"
        );
    }

    /// A row under a catalogue model that differs from the one chosen now is left as it is.
    #[test]
    fn a_row_with_another_vendors_model_is_not_overwritten() {
        let dir = tempfile::tempdir().unwrap();
        make_dirs(dir.path());
        let config = site_config(dir.path());
        let cat = catalogue();
        let d = one_draft("/stream1");
        let mk = |m: ModelRef| {
            [Ready {
                draft: d.clone(),
                model: m,
            }]
        };
        // Registered by something else (here: an earlier import under `acme/c1`).
        let key = KeyFile::generate(config.key_file()).unwrap();
        write_all(&config, key, &mk(model("acme", "c1")), &cat).unwrap();
        let key = KeyFile::load(config.key_file()).unwrap();
        // The default model and another catalogue model are both refused.
        for m in [default_model().unwrap(), model("acme", "c2")] {
            let rows = write_all(
                &config,
                KeyFile::load(config.key_file()).unwrap(),
                &mk(m),
                &cat,
            )
            .unwrap();
            assert_eq!(
                rows[0].status,
                Status::Skipped(SkipWhy::ExistingModel(model("acme", "c1")))
            );
        }
        drop(key);
        let index = Index::open(config.database_path()).unwrap();
        let got = index.get_camera(&d.id, &cat).unwrap().unwrap();
        assert_eq!(got.record().model(), &model("acme", "c1"));
        drop(index);
        // The same model updates; an `agentdvr/*` row is updated by any model.
        let key = KeyFile::load(config.key_file()).unwrap();
        let rows = write_all(&config, key, &mk(model("acme", "c1")), &cat).unwrap();
        assert_eq!(rows[0].status, Status::Updated);
    }

    /// Every vault value of one camera, for a byte comparison.
    fn vault_values(config: &Config, id: &CameraId) -> Vec<Option<String>> {
        let vault = Vault::open(
            &vault_path(config),
            KeyFile::load(config.key_file()).unwrap(),
        )
        .unwrap();
        [
            EntryKind::Host,
            EntryKind::DisplayName,
            EntryKind::Credential,
        ]
        .into_iter()
        .map(|k| {
            vault
                .get(&id.entry_id(k).unwrap())
                .unwrap()
                .map(|e| match e.value {
                    Value::Text(t) => t.expose_secret().to_owned(),
                    Value::Credential(c) => {
                        format!("{}:{}", c.username, c.password.expose_secret())
                    }
                    other => format!("{other:?}"),
                })
        })
        .collect()
    }

    /// A skipped row leaves the vault byte-identical: the second import has another host, name and
    /// login for the same id. (Mutation check: moving `write_vault` above the guard fails this.)
    #[test]
    fn a_skipped_row_leaves_its_vault_entries_untouched() {
        let dir = tempfile::tempdir().unwrap();
        make_dirs(dir.path());
        let config = site_config(dir.path());
        let cat = catalogue();
        let camera = |host: &str, name: &str, user: &str, pw: &str| {
            let xml = format!(
                "<objects><cameras><camera id=\"1\" name=\"{name}\"><settings>\
                 <videosourcestring>rtsp://{host}/stream1</videosourcestring>\
                 <login>{user}</login><password>{pw}</password></settings></camera>\
                 </cameras></objects>"
            );
            wardenlens_agentdvr::parse(xml.as_bytes())
                .unwrap()
                .cameras
                .remove(0)
        };
        let first = camera("192.0.2.5", "First", "user-one", "pass-one-1");
        let second = camera("198.51.100.8", "Second", "user-two", "pass-two-2");
        assert_eq!(first.id, second.id);
        let key = KeyFile::generate(config.key_file()).unwrap();
        let mapped = [Ready {
            draft: first.clone(),
            model: model("acme", "c1"),
        }];
        write_all(&config, key, &mapped, &cat).unwrap();
        let before = vault_values(&config, &first.id);
        assert!(before.iter().all(Option::is_some));
        for m in [default_model().unwrap(), model("acme", "c2")] {
            let other = [Ready {
                draft: second.clone(),
                model: m,
            }];
            let key = KeyFile::load(config.key_file()).unwrap();
            let rows = write_all(&config, key, &other, &cat).unwrap();
            assert!(matches!(
                rows[0].status,
                Status::Skipped(SkipWhy::ExistingModel(_))
            ));
            assert_eq!(
                vault_values(&config, &first.id),
                before,
                "the vault changed"
            );
        }
    }

    /// The dry run reads an existing index read-only and reports the same skip as the real run;
    /// with no index, or an empty file, it creates and changes nothing.
    #[test]
    fn a_dry_run_reads_an_existing_index_without_writing() {
        let dir = tempfile::tempdir().unwrap();
        make_dirs(dir.path());
        let config = site_config(dir.path());
        assert!(matches!(open_for_dry_run(&config), Ok(Registry::None)));
        assert!(!config.database_path().exists());
        let cat = catalogue();
        let d = one_draft("/stream1");
        let mk = |m: ModelRef| Ready {
            draft: d.clone(),
            model: m,
        };
        let key = KeyFile::generate(config.key_file()).unwrap();
        write_all(&config, key, &[mk(model("acme", "c1"))], &cat).unwrap();
        let before = dir_bytes(dir.path());
        let Ok(Registry::Reader(index)) = open_for_dry_run(&config) else {
            panic!("not a reader");
        };
        let existing = index.get_camera(&d.id, &cat).unwrap();
        assert!(conflict(existing.as_ref(), &mk(model("acme", "c2"))).is_some());
        assert!(conflict(existing.as_ref(), &mk(default_model().unwrap())).is_some());
        assert!(conflict(existing.as_ref(), &mk(model("acme", "c1"))).is_none());
        assert!(conflict(None, &mk(model("acme", "c1"))).is_none());
        drop(index);
        assert_eq!(dir_bytes(dir.path()), before);
    }

    /// Name and bytes of every file under `dir`, recursively.
    fn dir_bytes(dir: &Path) -> Vec<(PathBuf, Vec<u8>)> {
        let mut out = Vec::new();
        for e in std::fs::read_dir(dir).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                out.extend(dir_bytes(&p));
            } else {
                let b = std::fs::read(&p).unwrap();
                out.push((p, b));
            }
        }
        out.sort();
        out
    }

    #[test]
    fn an_import_model_row_is_updated_by_a_catalogue_model() {
        let dir = tempfile::tempdir().unwrap();
        make_dirs(dir.path());
        let config = site_config(dir.path());
        let cat = catalogue();
        let d = one_draft("/stream1");
        let mk = |m: ModelRef| {
            [Ready {
                draft: d.clone(),
                model: m,
            }]
        };
        let key = KeyFile::generate(config.key_file()).unwrap();
        write_all(&config, key, &mk(default_model().unwrap()), &cat).unwrap();
        let key = KeyFile::load(config.key_file()).unwrap();
        let rows = write_all(&config, key, &mk(model("acme", "c1")), &cat).unwrap();
        assert_eq!(rows[0].status, Status::Updated);
        let index = Index::open(config.database_path()).unwrap();
        let got = index.get_camera(&d.id, &cat).unwrap().unwrap();
        assert_eq!(got.record().model(), &model("acme", "c1"));
    }

    #[test]
    fn every_skip_reason_has_its_own_text_without_site_data() {
        let m = model("acme", "c1");
        let texts = [
            SkipWhy::Parser {
                reason: SkipReason::Deleted,
                position: 3,
            }
            .text(),
            SkipWhy::LoginInPath.text(),
            SkipWhy::QueryNotListed(None).text(),
            SkipWhy::QueryNotListed(Some(m.clone())).text(),
            SkipWhy::Ambiguous(vec![m.clone(), model("beta", "d2")]).text(),
            SkipWhy::ExistingModel(m).text(),
        ];
        let mut sorted = texts.to_vec();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), texts.len(), "{texts:?}");
        assert!(texts[0].contains("entry 3"));
        assert!(texts[3].contains("acme/c1") && texts[5].contains("acme/c1"));
    }

    /// Every id the parser produces starts with the prefix that `camera add` refuses, whatever
    /// the entry's `id` attribute is (numeric, duplicate, missing, not a number, hostile).
    #[test]
    fn every_parser_id_has_the_reserved_prefix() {
        let cam = |attrs: &str, n: u32| {
            format!(
                "<camera {attrs} name=\"Cam {n}\"><settings><videosourcestring>\
                 rtsp://192.0.2.{n}/s</videosourcestring></settings></camera>"
            )
        };
        let xml = format!(
            "<objects><cameras>{}</cameras></objects>",
            [
                cam("id=\"1\"", 1),
                cam("id=\"1\"", 2),
                cam("", 3),
                cam("id=\"x\"", 4),
                cam("id=\"-5\"", 5),
                cam("id=\"99999999999999\"", 6),
                cam("id=\"../etc\"", 7),
                cam("id=\"\"", 8),
            ]
            .concat()
        );
        let parsed = wardenlens_agentdvr::parse(xml.as_bytes()).unwrap();
        assert!(parsed.cameras.len() >= 4, "{}", parsed.cameras.len());
        for d in &parsed.cameras {
            assert!(
                d.id.as_str().starts_with(RESERVED_ID_PREFIX),
                "{} does not start with the reserved prefix",
                d.id
            );
        }
    }

    #[test]
    fn a_dry_run_over_an_index_the_real_run_changes_first_says_so() {
        for (p, word) in [(Prelude::Migrate, "migrate"), (Prelude::Recover, "recover")] {
            let t = Status::WouldImportAfter(p).text();
            assert!(t.starts_with("would import") && t.contains(word), "{t}");
        }
    }

    /// Every input of the dry run's mapping from the read-only open to the registry state.
    #[test]
    fn registry_of_maps_every_open_result() {
        let dir = tempfile::tempdir().unwrap();
        let not_found = || {
            let e = wardenlens_fsutil::open_existing_private_file(&dir.path().join("missing"))
                .unwrap_err();
            assert!(e.is_not_found());
            IndexError::Fs(e)
        };
        let is_none = |r: Result<Registry, ImportError>| matches!(r, Ok(Registry::None));
        // A missing file: no index when the parent exists, the refusal when it does not.
        assert!(is_none(registry_of(Err(not_found()), true)));
        assert!(matches!(
            registry_of(Err(not_found()), false),
            Err(ImportError::Index(IndexError::Fs(_)))
        ));
        assert!(is_none(registry_of(Err(IndexError::Uninitialised), true)));
        assert!(matches!(
            registry_of(Err(IndexError::NeedsMigration), true),
            Ok(Registry::Changes(Prelude::Migrate))
        ));
        assert!(matches!(
            registry_of(Err(IndexError::NeedsRecovery), true),
            Ok(Registry::Changes(Prelude::Recover))
        ));
        // Anything else is the refusal, with the same error as the real run.
        for other in [
            IndexError::StraySidecar { suffix: "-wal" },
            IndexError::ForeignWal,
            IndexError::Damaged,
            IndexError::NotAnIndex,
            IndexError::AlreadyOpenInProcess,
        ] {
            let text = other.to_string();
            match registry_of(Err(other), true) {
                Err(ImportError::Index(e)) => assert_eq!(e.to_string(), text),
                _ => panic!("{text} was not refused"),
            }
        }
        // A real reader is a reader.
        let config = site_config(dir.path());
        make_dirs(dir.path());
        let key = KeyFile::generate(config.key_file()).unwrap();
        write_all(
            &config,
            key,
            &[Ready {
                draft: one_draft("/stream1"),
                model: default_model().unwrap(),
            }],
            &[],
        )
        .unwrap();
        assert!(matches!(
            registry_of(Index::open_read_only(config.database_path()), true),
            Ok(Registry::Reader(_))
        ));
    }

    /// A missing parent directory is refused by the dry run, as the real run refuses it.
    #[test]
    fn a_dry_run_with_a_missing_state_directory_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let config = site_config(dir.path());
        assert!(!dir.path().join("state").exists());
        assert!(matches!(
            open_for_dry_run(&config),
            Err(ImportError::Index(_))
        ));
        assert!(!dir.path().join("state").exists());
    }
}
