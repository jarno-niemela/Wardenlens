//! `wardenlens camera add` (#67): one camera into the registry and the vault.
//!
//! # Steps, in this order
//! 1. Validate the arguments (id, host, user name, catalogue model, name) and look the model up
//!    in the catalogue. Nothing is read or written yet.
//! 2. Vet the host ([`super::guard::vet_host`]): this machine's own addresses and the cloud metadata
//!    addresses are refused **before any request**, and the probe connects to the vetted address.
//! 3. Load the key file and refuse an id that is registered already (`remove` it first: `add`
//!    never overwrites). Only then read the password (stdin or a no-echo prompt, never argv), so
//!    nobody is asked for a password that is not going to be used.
//! 4. Ask the camera over ONVIF for its profiles (the one with the most pixels is the main
//!    stream, the one with the fewest the sub stream) and their stream paths. **Only** when the
//!    camera never answered, that is `GetProfiles` was unreachable within the client's retry
//!    budget ([`OnvifError::Unreachable`]), are the catalogue paths used instead. Any other
//!    failure (wrong login, a fault, a malformed reply, or an unreachable later call after the
//!    camera had answered) stops the command: guessing paths for a camera that answered would
//!    hide a mistake.
//! 5. Insert the registry row first (insert-only, in one transaction: a second concurrent `add`
//!    of the id is refused and writes nothing), then the vault entries, host and name before the
//!    login. If a vault write fails, this run removes its own entries and row. See [`add`].
//!
//! The stored port is the RTSP port (from the ONVIF stream URI, else the catalogue, else 554);
//! the ONVIF port is used for the probe only. A sub stream on another port than the main stream
//! cannot be stored (the registry has one port) and is left out, with a notice.

use std::net::IpAddr;
use std::num::NonZeroU16;

use secrecy::{ExposeSecret as _, SecretString};
use wardenlens_core::camera::{
    CameraId, Credential, DisplayName, Host, ModelRef, RtspPath, StreamSet,
};
use wardenlens_core::catalogue::{CatalogueEntry, query_allowed};
use wardenlens_core::config::Config;
use wardenlens_core::entry::{EntryId, EntryKind};
use wardenlens_core::time::UnixMs;
use wardenlens_index::{CameraRecord, Index, IndexError};
use wardenlens_onvif::{ClientConfig, OnvifClient, OnvifError, pick_streams};
use wardenlens_secrets::Credentials;
use wardenlens_vault::{Scan, Value, Vault, VaultError};

use super::guard::{Network, vet_host};
use super::{CameraCmdError, catalogue, open_vault, password};
use crate::args::AddArgs;
use crate::commands::import::vault_path;
use crate::terminal::Terminal;

/// What the probe decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Source {
    /// The camera answered ONVIF.
    Onvif,
    /// ONVIF was unreachable; the catalogue paths were used.
    Catalogue,
}

/// The streams to store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Streams {
    pub(super) main: RtspPath,
    pub(super) sub: Option<RtspPath>,
    pub(super) port: NonZeroU16,
    pub(super) source: Source,
    /// Why a stream was left out; shown to the operator.
    pub(super) notes: Vec<&'static str>,
}

/// Asks the camera for its streams over ONVIF. `Ok(None)` means the camera never answered (the
/// first call, `GetProfiles`, was unreachable within the retry budget): only then may the caller
/// use the catalogue. Once the camera has answered, every later failure is an error, including an
/// unreachable `GetStreamUri`.
async fn ask_onvif(client: &OnvifClient) -> Result<Option<Streams>, OnvifError> {
    let profiles = match client.get_profiles().await {
        Ok(p) => p,
        Err(OnvifError::Unreachable { .. }) => return Ok(None),
        Err(e) => return Err(e),
    };
    let choice = pick_streams(&profiles).ok_or(OnvifError::MissingElement {
        element: "Profiles",
    })?;
    let main = client.get_stream_uri(&choice.main.token).await?;
    let mut notes = Vec::new();
    let sub = match choice.sub {
        Some(p) => {
            let sub = client.get_stream_uri(&p.token).await?;
            if sub.port == main.port {
                Some(sub.path)
            } else {
                notes.push(
                    "the sub stream is on another port than the main stream and was left out",
                );
                None
            }
        }
        None => None,
    };
    Ok(Some(Streams {
        main: main.path,
        sub,
        port: main.port,
        source: Source::Onvif,
        notes,
    }))
}

/// The catalogue's streams for `entry`.
fn catalogue_streams(entry: &CatalogueEntry) -> Result<Streams, CameraCmdError> {
    let (main, sub) = catalogue::rtsp_paths(entry);
    let main = main.ok_or(CameraCmdError::NoCataloguePaths)?;
    Ok(Streams {
        main: RtspPath::new(main).map_err(CameraCmdError::Path)?,
        sub: sub
            .map(RtspPath::new)
            .transpose()
            .map_err(CameraCmdError::Path)?,
        port: catalogue::rtsp_port(entry),
        source: Source::Catalogue,
        notes: Vec::new(),
    })
}

/// The streams of the camera at `ip:onvif_port`: from ONVIF, or from the catalogue when the camera
/// never answered ONVIF.
pub(super) fn find_streams(
    ip: IpAddr,
    onvif_port: NonZeroU16,
    credential: Credential,
    config: ClientConfig,
    entry: &CatalogueEntry,
) -> Result<Streams, CameraCmdError> {
    let host = Host::new(&ip.to_string()).map_err(CameraCmdError::Camera)?;
    let client = OnvifClient::new(host, onvif_port, Some(credential)).with_config(config);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(CameraCmdError::Runtime)?;
    match runtime.block_on(ask_onvif(&client)) {
        Ok(Some(streams)) => Ok(streams),
        Ok(None) => catalogue_streams(entry),
        Err(e) => Err(CameraCmdError::Onvif(e)),
    }
}

/// The checked arguments.
pub(super) struct Request {
    id: CameraId,
    host: Host,
    model: ModelRef,
    name: DisplayName,
    user: String,
}

fn request(args: &AddArgs) -> Result<Request, CameraCmdError> {
    let id = CameraId::new(&args.id).map_err(CameraCmdError::Camera)?;
    // Before anything else (no prompt, no connection, no write): `import agentdvr` owns this
    // prefix and overwrites the rows under it, so a hand-added row there would be lost.
    if id
        .as_str()
        .starts_with(crate::commands::import::RESERVED_ID_PREFIX)
    {
        return Err(CameraCmdError::ReservedId);
    }
    let name = DisplayName::new(args.name.as_deref().unwrap_or(id.as_str()))
        .map_err(CameraCmdError::Camera)?;
    Ok(Request {
        host: Host::new(&args.host).map_err(CameraCmdError::Camera)?,
        model: catalogue::parse_model(&args.model).map_err(CameraCmdError::Camera)?,
        user: args.username.clone(),
        name,
        id,
    })
}

/// Everything `add` needs from the outside, so tests can use loopback and short timeouts.
pub(super) struct Services<'a> {
    pub(super) network: &'a dyn Network,
    pub(super) client: ClientConfig,
    /// The wall clock; read before the first write.
    pub(super) clock: fn() -> Result<UnixMs, CameraCmdError>,
}

/// The vault operations `add` needs, so a test can make one fail part way.
pub(super) trait VaultOps {
    fn set(&mut self, id: &EntryId, kind: EntryKind, value: &Value) -> Result<(), VaultError>;
    fn rm(&mut self, id: &EntryId) -> Result<bool, VaultError>;
}

impl VaultOps for Vault {
    fn set(&mut self, id: &EntryId, kind: EntryKind, value: &Value) -> Result<(), VaultError> {
        Vault::set(self, id, kind, value, Scan::Normal).map(drop)
    }
    fn rm(&mut self, id: &EntryId) -> Result<bool, VaultError> {
        Vault::rm(self, id)
    }
}

/// Runs `camera add`; prints one line on success.
///
/// Concurrent runs for one id are safe: the registry row is inserted **first** with
/// [`Index::insert_camera`] (check and write in one transaction), so exactly one run wins and the
/// others stop with [`CameraCmdError::AlreadyRegistered`] before they write anything to the vault.
/// Only the winner writes the vault entries, and only the winner rolls back (it removes its own
/// row and entries), so no run ever deletes or overwrites another run's camera. The price is a
/// short window in which the row exists and the vault entries do not; `serve` skips such a camera
/// by id and logs it.
pub(super) fn add(
    config: &Config,
    args: &AddArgs,
    term: &mut impl Terminal,
    svc: &Services<'_>,
) -> Result<(), CameraCmdError> {
    let req = request(args)?;
    // The user name is checked now; the password (not read yet) is checked when it is.
    Credential::check(&req.user, "").map_err(CameraCmdError::Credential)?;
    let entries = catalogue::load().map_err(CameraCmdError::Catalogue)?;
    let entry = catalogue::find(&entries, &req.model).ok_or(CameraCmdError::UnknownModel)?;
    let ip = vet_host(&req.host, svc.network).map_err(CameraCmdError::Guard)?;
    let key = super::load_key(config.key_file())?;
    // A quick refusal before the operator is asked for anything. The authoritative check is the
    // insert below; this one creates no file.
    let taken = match super::open_existing_index(config)? {
        Some(index) => index
            .get_camera(&req.id, &entries)
            .map_err(CameraCmdError::Index)?
            .is_some(),
        None => false,
    };
    if taken {
        return Err(CameraCmdError::AlreadyRegistered);
    }
    let password = password::read(term, "password").map_err(CameraCmdError::Password)?;
    Credential::check(&req.user, password.expose_secret()).map_err(CameraCmdError::Credential)?;
    let credential = Credential::new(req.user.clone(), password.clone());
    let onvif_port = args
        .onvif_port
        .unwrap_or_else(|| catalogue::onvif_port(entry));
    let streams = find_streams(ip, onvif_port, credential, svc.client, entry)?;
    // The registry vets the query of a path too; check it first so a refusal leaves no vault
    // entries behind.
    for path in std::iter::once(&streams.main).chain(streams.sub.iter()) {
        if !query_allowed(&entries, &req.model, path) {
            return Err(CameraCmdError::PathQuery);
        }
    }
    // Everything that can fail without side effects comes before the first write.
    let stamp = (svc.clock)()?;
    let record = CameraRecord::new(
        req.id.clone(),
        req.model.clone(),
        streams.port,
        StreamSet::new(streams.main.clone(), streams.sub.clone()),
    );
    let mut vault = open_vault(&vault_path(config), key).map_err(CameraCmdError::Vault)?;
    let mut index = Index::open(config.database_path()).map_err(CameraCmdError::Index)?;
    commit(
        &mut index, &mut vault, &record, &entries, stamp, &req, password,
    )?;
    // The camera is stored: a failure to print must not turn into an error exit.
    let _ = print(&req, &streams, term);
    Ok(())
}

/// A request for tests that call [`commit`] directly.
#[cfg(test)]
pub(super) fn test_request(id: &str) -> Request {
    Request {
        id: CameraId::new(id).unwrap_or_else(|_| unreachable!()),
        host: Host::new("192.0.2.10").unwrap_or_else(|_| unreachable!()),
        model: ModelRef::new("reolink", "rlc-520a").unwrap_or_else(|_| unreachable!()),
        name: DisplayName::new(id).unwrap_or_else(|_| unreachable!()),
        user: "u".to_owned(),
    }
}

/// The row first, then the vault entries; a failure after the row removes what this run wrote.
pub(super) fn commit(
    index: &mut Index,
    vault: &mut impl VaultOps,
    record: &CameraRecord,
    entries: &[CatalogueEntry],
    stamp: UnixMs,
    req: &Request,
    password: SecretString,
) -> Result<(), CameraCmdError> {
    index
        .insert_camera(record, entries, stamp)
        .map_err(|e| match e {
            IndexError::CameraExists => CameraCmdError::AlreadyRegistered,
            e => CameraCmdError::Index(e),
        })?;
    if let Err(e) = write_vault(vault, req, password) {
        rollback(vault, &req.id);
        // The row is this run's own (the insert succeeded), so removing it is safe.
        let _ = index.remove_camera(&req.id);
        return Err(e);
    }
    Ok(())
}

/// Writes the three vault entries in the order of `import`: host and name, then the login last.
fn write_vault(
    vault: &mut impl VaultOps,
    req: &Request,
    password: SecretString,
) -> Result<(), CameraCmdError> {
    let id_for = |kind| req.id.entry_id(kind).map_err(CameraCmdError::Camera);
    let text = |s: &str| Value::Text(SecretString::from(s.to_owned()));
    vault.set(
        &id_for(EntryKind::Host)?,
        EntryKind::Host,
        &text(&req.host.expose()),
    )?;
    vault.set(
        &id_for(EntryKind::DisplayName)?,
        EntryKind::DisplayName,
        &text(req.name.expose()),
    )?;
    let login = Value::Credential(Credentials {
        username: req.user.clone(),
        password,
    });
    vault.set(
        &id_for(EntryKind::Credential)?,
        EntryKind::Credential,
        &login,
    )?;
    Ok(())
}

/// Removes the entries of `id` after a failed add; errors are ignored, the add already failed.
fn rollback(vault: &mut impl VaultOps, id: &CameraId) {
    for kind in [
        EntryKind::Credential,
        EntryKind::Host,
        EntryKind::DisplayName,
    ] {
        if let Ok(entry_id) = id.entry_id(kind) {
            let _ = vault.rm(&entry_id);
        }
    }
}

fn print(req: &Request, streams: &Streams, term: &mut impl Terminal) -> Result<(), CameraCmdError> {
    let source = match streams.source {
        Source::Onvif => "ONVIF",
        Source::Catalogue => "catalogue",
    };
    if streams.source == Source::Catalogue {
        writeln!(
            term.err(),
            "note: the camera did not answer ONVIF; the catalogue's paths were used"
        )
        .map_err(CameraCmdError::Output)?;
    }
    for note in &streams.notes {
        writeln!(term.err(), "note: {note}").map_err(CameraCmdError::Output)?;
    }
    let sub = streams
        .sub
        .as_ref()
        .map_or_else(|| "none".to_owned(), RtspPath::redacted_for_display);
    writeln!(
        term.out(),
        "added {id}: model {model}, port {port}, main {main}, sub {sub} (streams from {source})",
        id = req.id,
        model = req.model,
        port = streams.port,
        main = streams.main.redacted_for_display(),
    )
    .map_err(CameraCmdError::Output)
}
