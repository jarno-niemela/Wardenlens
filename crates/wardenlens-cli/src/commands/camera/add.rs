//! `wardenlens camera add` (#67): one camera into the registry and the vault.
//!
//! # Steps, in this order
//! 1. Validate the arguments (id, host, catalogue model, name) and look the model up in the
//!    catalogue. Nothing is read or written yet.
//! 2. Vet the host ([`guard::vet_host`]): this machine's own addresses and the cloud metadata
//!    address are refused **before any request**, and the probe connects to the vetted address.
//! 3. Read the password (stdin or a no-echo prompt, never argv) and check the login.
//! 4. Refuse an id that is registered already (`remove` it first: `add` never overwrites).
//! 5. Ask the camera over ONVIF for its profiles (the one with the most pixels is the main
//!    stream, the one with the fewest the sub stream) and their stream paths. **Only** when the
//!    camera is unreachable within the client's retry budget ([`OnvifError::Unreachable`]) are
//!    the catalogue paths used instead. Any other failure (wrong login, a fault, a malformed
//!    reply) stops the command: guessing paths for a camera that answered would hide a mistake.
//! 6. Write, as `import` does: host and name, then the login, in the vault; the registry row
//!    last, so a listed camera always has its vault entries. If the registry refuses the row the
//!    vault entries just written are removed again.
//!
//! The stored port is the RTSP port (from the ONVIF stream URI, else the catalogue, else 554);
//! the ONVIF port is used for the probe only. A sub stream on another port than the main stream
//! cannot be stored (the registry has one port) and is left out, with a notice.

use std::net::IpAddr;
use std::num::NonZeroU16;

use secrecy::SecretString;
use wardenlens_core::camera::{
    CameraId, Credential, DisplayName, Host, ModelRef, RtspPath, StreamSet,
};
use wardenlens_core::catalogue::{CatalogueEntry, query_allowed};
use wardenlens_core::config::Config;
use wardenlens_core::entry::EntryKind;
use wardenlens_index::{CameraRecord, Index};
use wardenlens_onvif::{ClientConfig, OnvifClient, OnvifError, pick_streams};
use wardenlens_secrets::Credentials;
use wardenlens_vault::{Scan, Value, Vault};

use super::guard::{Network, vet_host};
use super::{CameraCmdError, catalogue, now, open_vault, password};
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

/// Asks the camera for its streams over ONVIF.
async fn ask_onvif(client: &OnvifClient) -> Result<Streams, OnvifError> {
    let profiles = client.get_profiles().await?;
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
    Ok(Streams {
        main: main.path,
        sub,
        port: main.port,
        source: Source::Onvif,
        notes,
    })
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

/// The streams of the camera at `ip:onvif_port`: from ONVIF, or from the catalogue when ONVIF is
/// unreachable.
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
        Ok(streams) => Ok(streams),
        Err(OnvifError::Unreachable { .. }) => catalogue_streams(entry),
        Err(e) => Err(CameraCmdError::Onvif(e)),
    }
}

/// The checked arguments.
struct Request {
    id: CameraId,
    host: Host,
    model: ModelRef,
    name: DisplayName,
    user: String,
}

fn request(args: &AddArgs) -> Result<Request, CameraCmdError> {
    let id = CameraId::new(&args.id).map_err(CameraCmdError::Camera)?;
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
}

/// Runs `camera add`; prints one line on success.
pub(super) fn add(
    config: &Config,
    args: &AddArgs,
    term: &mut impl Terminal,
    svc: &Services<'_>,
) -> Result<(), CameraCmdError> {
    let req = request(args)?;
    let entries = catalogue::load().map_err(CameraCmdError::Catalogue)?;
    let entry = catalogue::find(&entries, &req.model).ok_or(CameraCmdError::UnknownModel)?;
    let ip = vet_host(&req.host, svc.network).map_err(CameraCmdError::Guard)?;
    let password = password::read(term, "password").map_err(CameraCmdError::Password)?;
    Credential::check(&req.user, secrecy::ExposeSecret::expose_secret(&password))
        .map_err(CameraCmdError::Credential)?;
    let key = super::load_key(config.key_file())?;
    let mut index = Index::open(config.database_path()).map_err(CameraCmdError::Index)?;
    if index
        .get_camera(&req.id, &entries)
        .map_err(CameraCmdError::Index)?
        .is_some()
    {
        return Err(CameraCmdError::AlreadyRegistered);
    }
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
    let record = CameraRecord::new(
        req.id.clone(),
        req.model.clone(),
        streams.port,
        StreamSet::new(streams.main.clone(), streams.sub.clone()),
    );
    let mut vault = open_vault(&vault_path(config), key).map_err(CameraCmdError::Vault)?;
    write_vault(&mut vault, &req, password)?;
    if let Err(e) = index.upsert_camera(&record, &entries, now()?) {
        rollback(&mut vault, &req.id);
        return Err(CameraCmdError::Index(e));
    }
    print(&req, &streams, term)
}

/// Writes the three vault entries in the order of `import`: host and name, then the login last.
fn write_vault(
    vault: &mut Vault,
    req: &Request,
    password: SecretString,
) -> Result<(), CameraCmdError> {
    let id_for = |kind| req.id.entry_id(kind).map_err(CameraCmdError::Camera);
    let text = |s: &str| Value::Text(SecretString::from(s.to_owned()));
    let result = (|| {
        vault.set(
            &id_for(EntryKind::Host)?,
            EntryKind::Host,
            &text(&req.host.expose()),
            Scan::Normal,
        )?;
        vault.set(
            &id_for(EntryKind::DisplayName)?,
            EntryKind::DisplayName,
            &text(req.name.expose()),
            Scan::Normal,
        )?;
        let login = Value::Credential(Credentials {
            username: req.user.clone(),
            password,
        });
        vault.set(
            &id_for(EntryKind::Credential)?,
            EntryKind::Credential,
            &login,
            Scan::Normal,
        )?;
        Ok(())
    })();
    if result.is_err() {
        rollback(vault, &req.id);
    }
    result
}

/// Removes the entries of `id` after a failed add; errors are ignored, the add already failed.
fn rollback(vault: &mut Vault, id: &CameraId) {
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
