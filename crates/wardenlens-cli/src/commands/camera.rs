//! `wardenlens camera discover|add|list|remove` (#67): the ONVIF driver wired into the registry.
//!
//! | command | what it does |
//! |---|---|
//! | `discover` | one WS-Discovery probe; lists what answered, **suggestions only** ([`discover`]) |
//! | `add` | probes a camera over ONVIF (catalogue paths if it is unreachable), stores it ([`add`]) |
//! | `list` | id, model and host of every registered camera; never a login |
//! | `remove` | the registry row first, then the camera's vault entries; recordings are kept |
//!
//! A camera is stored exactly as `import agentdvr` stores one (ADR 0006): host, display name and
//! login sealed in the service vault `vault.db` next to the index under `cam:<id>:host`, `:name`
//! and `:credential`, the rest in the `cameras` table. `serve` reads them back with the same ids;
//! a test adds a camera here and reads it with `serve`'s own loader.
//!
//! The password never comes from argv: see [`password`]. Where `add` may connect is decided by
//! [`guard`]. The catalogue is the one compiled in (the `catalogue` module).
//!
//! Exit codes: 0 done; 1 the request was refused (bad value, refused address, wrong login, a full
//! registry, a taken id,
//! unknown or duplicate id); 2 the system could not do it (config, key file, vault, registry, I/O)
//! and, as for the other commands, an invalid config is 1.

mod add;
mod catalogue;
mod discover;
mod guard;
mod password;
#[cfg(test)]
mod tests;

use std::collections::HashMap;
use std::io::{self, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use secrecy::ExposeSecret as _;
use wardenlens_core::camera::{CameraError, CameraId, CredentialRule, Host};
use wardenlens_core::catalogue::CatalogueError;
use wardenlens_core::config::Config;
use wardenlens_core::entry::EntryKind;
use wardenlens_core::time::UnixMs;
use wardenlens_index::{Index, IndexError};
use wardenlens_onvif::OnvifError;
use wardenlens_onvif::discovery::DiscoveryError;
use wardenlens_secrets::{KeyFile, SecretsError};
use wardenlens_vault::{Value, Vault, VaultError};

use self::add::Services;
use self::discover::{Found, Registered};
use self::guard::{GuardError, SystemNetwork};
use self::password::PasswordError;
use super::import::{open_vault, vault_path};
use super::{Context, error_chain, report_error};
use crate::args::CameraCommand;
use crate::config_file::{ConfigFileError, load, resolve_path};
use crate::terminal::{StdTerminal, Terminal};

/// Why a `camera` command failed. No value of a camera, no host and no login is in a message.
#[derive(Debug, thiserror::Error)]
pub(crate) enum CameraCmdError {
    /// The config could not be used.
    #[error(transparent)]
    Config(#[from] ConfigFileError),
    /// A camera value was refused; the rule is named.
    #[error("{0}")]
    Camera(#[source] CameraError),
    /// A stream path was refused.
    #[error("a stream path was refused: {0}")]
    Path(#[source] CameraError),
    /// The embedded catalogue is invalid (cannot happen; a test pins it).
    #[error("the built-in camera catalogue is invalid")]
    Catalogue(#[source] CatalogueError),
    /// The id starts with the prefix that `import agentdvr` owns.
    #[error(
        "camera ids starting with `agentdvr-` are reserved for `wardenlens import agentdvr`; choose another id"
    )]
    ReservedId,
    /// The model is not in the catalogue.
    #[error("no catalogue entry for that model; use `<vendor>/<model>` as in cameras/README.md")]
    UnknownModel,
    /// The address is refused or does not resolve.
    #[error(transparent)]
    Guard(GuardError),
    /// The password could not be read.
    #[error(transparent)]
    Password(PasswordError),
    /// The login cannot be stored.
    #[error("the login is refused: {0}")]
    Credential(CredentialRule),
    /// The id is registered already.
    #[error("that id is already registered; `camera remove` it first")]
    AlreadyRegistered,
    /// Nothing is registered under that id.
    #[error("no camera with that id")]
    NotFound,
    /// The camera answered ONVIF, but not usably (the fallback is for an unreachable camera only).
    #[error("the camera's ONVIF answer was not usable")]
    Onvif(#[source] OnvifError),
    /// ONVIF was unreachable and the catalogue entry lists no RTSP path.
    #[error("the camera is unreachable over ONVIF and the catalogue lists no RTSP path for it")]
    NoCataloguePaths,
    /// A path has a query the catalogue does not list for the model.
    #[error("a stream path has a query string that the catalogue does not list for this model")]
    PathQuery,
    /// As [`Self::PathQuery`], but the catalogue lists a path with the same head.
    #[error(
        "a stream path has a query string that the catalogue does not list for this model; the catalogue lists {listed} for this stream (the catalogue's paths are used when the camera does not answer ONVIF)"
    )]
    PathQueryListed { listed: String },
    /// The key file does not exist.
    #[error("key file {path:?} does not exist; run `wardenlens secrets init` to create it")]
    KeyMissing { path: PathBuf },
    /// The key file was refused.
    #[error("the key file cannot be used")]
    Key(#[source] SecretsError),
    /// The vault refused.
    #[error("the vault cannot be used")]
    Vault(#[from] VaultError),
    /// The index refused.
    #[error("the camera registry cannot be used")]
    Index(#[source] IndexError),
    /// The discovery socket failed.
    #[error("discovery failed")]
    Discovery(#[source] DiscoveryError),
    /// The async runtime could not start.
    #[error("the async runtime could not start")]
    Runtime(#[source] io::Error),
    /// The clock is outside 2000 to 2099.
    #[error("the system clock is outside the supported range")]
    Clock,
    /// Writing to stdout or stderr failed.
    #[error("cannot write the result")]
    Output(#[source] io::Error),
}

impl CameraCmdError {
    fn exit_code(&self) -> u8 {
        match self {
            Self::Config(e) => e.exit_code(),
            // A full registry or a taken id is a refusal of the request, not a system failure.
            Self::Index(IndexError::TooManyCameras { .. } | IndexError::CameraExists)
            | Self::Camera(_)
            | Self::Path(_)
            | Self::UnknownModel
            | Self::ReservedId
            | Self::Guard(_)
            | Self::Password(_)
            | Self::Credential(_)
            | Self::AlreadyRegistered
            | Self::NotFound
            | Self::Onvif(_)
            | Self::NoCataloguePaths
            | Self::PathQuery
            | Self::PathQueryListed { .. } => 1,
            Self::Catalogue(_)
            | Self::KeyMissing { .. }
            | Self::Key(_)
            | Self::Vault(_)
            | Self::Index(_)
            | Self::Discovery(_)
            | Self::Runtime(_)
            | Self::Clock
            | Self::Output(_) => 2,
        }
    }
}

pub(crate) fn execute(cmd: &CameraCommand, ctx: &Context<'_>) -> ExitCode {
    let mut term = StdTerminal::new();
    match run(cmd, ctx, &mut term) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            report_error(&e, ctx.log_format);
            ExitCode::from(e.exit_code())
        }
    }
}

fn run(
    cmd: &CameraCommand,
    ctx: &Context<'_>,
    term: &mut impl Terminal,
) -> Result<(), CameraCmdError> {
    if let CameraCommand::Discover(args) = cmd {
        // Discovery needs no config; the registry is only consulted to mark known addresses.
        return discover_cmd(ctx, args, term);
    }
    let config = load(&resolve_path(ctx.config_flag, ctx.env)?)?;
    match cmd {
        CameraCommand::Discover(_) => Ok(()),
        CameraCommand::Add(args) => {
            let services = Services {
                network: &SystemNetwork,
                client: wardenlens_onvif::ClientConfig::default(),
                clock: now,
            };
            add::add(&config, args, term, &services)
        }
        CameraCommand::List => list(&config, term),
        CameraCommand::Remove { id } => remove(&config, id, term),
    }
}

/// The built-in catalogue, for the registry's query check (also used by `serve`).
///
/// # Errors
/// [`CatalogueError`] when an embedded file is invalid (a test pins that none is).
pub(crate) fn catalogue() -> Result<Vec<wardenlens_core::catalogue::CatalogueEntry>, CatalogueError>
{
    catalogue::load()
}

/// `vendor/model` as a `ModelRef` (for `import agentdvr --model`).
///
/// # Errors
/// [`CameraError::ModelSlug`] when `text` has no `/` or a part is not a slug.
pub(crate) fn parse_model(text: &str) -> Result<wardenlens_core::camera::ModelRef, CameraError> {
    catalogue::parse_model(text)
}

/// The key file, or a message that points at `secrets init` when it is missing.
fn load_key(path: &Path) -> Result<KeyFile, CameraCmdError> {
    if std::fs::symlink_metadata(path).is_err_and(|e| e.kind() == io::ErrorKind::NotFound) {
        return Err(CameraCmdError::KeyMissing {
            path: path.to_path_buf(),
        });
    }
    KeyFile::load(path).map_err(CameraCmdError::Key)
}

fn now() -> Result<UnixMs, CameraCmdError> {
    let ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_millis()).ok())
        .ok_or(CameraCmdError::Clock)?;
    UnixMs::new(ms).map_err(|_| CameraCmdError::Clock)
}

/// The host in `cam:<id>:host`, if it is there and valid.
fn read_host(vault: &Vault, id: &CameraId) -> Option<Host> {
    let entry_id = id.entry_id(EntryKind::Host).ok()?;
    match vault.get(&entry_id).ok()??.value {
        Value::Text(t) => Host::new(t.expose_secret()).ok(),
        _ => None,
    }
}

/// The index at `database.path`, or `None` when the file does not exist (nothing is created).
fn open_existing_index(config: &Config) -> Result<Option<Index>, CameraCmdError> {
    if std::fs::symlink_metadata(config.database_path())
        .is_err_and(|e| e.kind() == io::ErrorKind::NotFound)
    {
        return Ok(None);
    }
    Index::open(config.database_path())
        .map(Some)
        .map_err(CameraCmdError::Index)
}

fn list(config: &Config, term: &mut impl Terminal) -> Result<(), CameraCmdError> {
    let stored = match open_existing_index(config)? {
        Some(index) => index
            .list_cameras(&catalogue().map_err(CameraCmdError::Catalogue)?)
            .map_err(CameraCmdError::Index)?,
        None => Vec::new(),
    };
    if stored.is_empty() {
        return writeln!(term.out(), "no cameras are registered").map_err(CameraCmdError::Output);
    }
    // Hosts live in the vault. If it cannot be opened the ids and models are still shown.
    let vault = load_key(config.key_file())
        .and_then(|key| Vault::open(&vault_path(config), key).map_err(CameraCmdError::Vault));
    if let Err(e) = &vault {
        writeln!(term.err(), "note: hosts not shown: {}", error_chain(e))
            .map_err(CameraCmdError::Output)?;
    }
    let rows: Vec<[String; 3]> = stored
        .iter()
        .map(|s| {
            let id = s.record().id();
            let host = vault.as_ref().ok().map_or("-".to_owned(), |v| {
                read_host(v, id).map_or("?".to_owned(), |h| h.expose())
            });
            [id.to_string(), s.record().model().to_string(), host]
        })
        .collect();
    let out = term.out();
    let width = |col: usize, head: &str| {
        rows.iter()
            .filter_map(|r| r.get(col))
            .map(|c| c.chars().count())
            .chain(std::iter::once(head.chars().count()))
            .max()
            .unwrap_or(0)
    };
    let (w_id, w_model) = (width(0, "ID"), width(1, "MODEL"));
    let line = |out: &mut dyn Write, a: &str, b: &str, c: &str| {
        writeln!(out, "{a:<w_id$}  {b:<w_model$}  {c}")
    };
    line(out, "ID", "MODEL", "HOST").map_err(CameraCmdError::Output)?;
    for [id, model, host] in &rows {
        line(out, id, model, host).map_err(CameraCmdError::Output)?;
    }
    Ok(())
}

fn remove(config: &Config, id: &str, term: &mut impl Terminal) -> Result<(), CameraCmdError> {
    let id = CameraId::new(id).map_err(CameraCmdError::Camera)?;
    // The row goes first: a listed camera then always has its vault entries.
    let had_row = match open_existing_index(config)? {
        Some(mut index) => index.remove_camera(&id).map_err(CameraCmdError::Index)?,
        None => false,
    };
    let mut had_entries = false;
    if std::fs::symlink_metadata(vault_path(config)).is_ok() {
        let key = load_key(config.key_file())?;
        let mut vault = Vault::open(&vault_path(config), key)?;
        for kind in [
            EntryKind::Credential,
            EntryKind::Host,
            EntryKind::DisplayName,
        ] {
            let entry_id = id.entry_id(kind).map_err(CameraCmdError::Camera)?;
            had_entries |= vault.rm(&entry_id)?;
        }
    }
    if !had_row && !had_entries {
        return Err(CameraCmdError::NotFound);
    }
    writeln!(term.out(), "removed {id}; its recordings were not deleted")
        .map_err(CameraCmdError::Output)
}

/// Registered camera ids by host address; only IP hosts can match a discovered address.
fn registered_hosts(config: &Config) -> Result<Registered, CameraCmdError> {
    let mut map = Registered::new();
    let Some(index) = open_existing_index(config)? else {
        return Ok(map);
    };
    let stored = index
        .list_cameras(&catalogue().map_err(CameraCmdError::Catalogue)?)
        .map_err(CameraCmdError::Index)?;
    if stored.is_empty() {
        return Ok(map);
    }
    let vault = Vault::open(&vault_path(config), load_key(config.key_file())?)?;
    for s in &stored {
        let id = s.record().id();
        if let Some(ip) = read_host(&vault, id).and_then(|h| h.expose().parse::<IpAddr>().ok()) {
            map.entry(ip).or_default().push(id.to_string());
        }
    }
    Ok(map)
}

fn discover_cmd(
    ctx: &Context<'_>,
    args: &crate::args::DiscoverArgs,
    term: &mut impl Terminal,
) -> Result<(), CameraCmdError> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(CameraCmdError::Runtime)?;
    let devices = runtime
        .block_on(wardenlens_onvif::discovery::discover(
            args.timeout,
            args.interface,
        ))
        .map_err(CameraCmdError::Discovery)?;
    let found: Vec<Found> = devices.iter().map(Found::from).collect();
    let registered = resolve_path(ctx.config_flag, ctx.env)
        .map_err(CameraCmdError::from)
        .and_then(|p| load(&p).map_err(CameraCmdError::from))
        .and_then(|c| registered_hosts(&c))
        .unwrap_or_else(|e| {
            // Best effort: discovery works before anything is set up.
            let _ = writeln!(
                term.err(),
                "note: registered cameras were not consulted: {}",
                error_chain(&e)
            );
            HashMap::new()
        });
    discover::render(
        &found,
        &registered,
        &SystemNetwork,
        args.timeout,
        term.out(),
    )
    .map_err(CameraCmdError::Output)
}
