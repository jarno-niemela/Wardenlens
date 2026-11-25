//! Parses an `AgentDVR` `objects.xml` into camera drafts. Pure: bytes in, drafts out; no network,
//! no storage, no clock (ADR 0004 crate table; ARCH-1). Writing the drafts to the registry and
//! the vault is the CLI import task (#66).
//!
//! # The format
//!
//! `AgentDVR` descends from iSpy and keeps its camera list in the same `objects.xml` layout. The
//! element and attribute names below come from iSpy's public schema
//! (`XML/objects.cs`, class `objects`, `objectsCamera` and `objectsCameraSettings` in
//! <https://github.com/ispysoftware/iSpy>, generated from `XML/objects.xsd`):
//!
//! ```text
//! <objects>
//!   <cameras>
//!     <camera id="1" name="Porch" deleted="false">     attributes: id, name, deleted
//!       <settings>
//!         <videosourcestring>rtsp://host/path</videosourcestring>
//!         <login>user</login>
//!         <password>secret</password>
//!       </settings>
//!     </camera>
//!   </cameras>
//! </objects>
//! ```
//!
//! Everything else in the file (`microphones`, `floorplans`, recording and motion settings, the
//! `onvif` block, ...) is ignored. Names are matched exactly and case-sensitively at exactly
//! these paths.
//!
//! **Not confirmed from public sources, for the owner to check against a real file locally**
//! (the real file is never copied into the repo):
//!
//! 1. That `AgentDVR`'s `objects.xml` uses this iSpy layout (`settings/videosourcestring`,
//!    `settings/login`, `settings/password`, `name` as an attribute of `camera`). The iSpy
//!    schema is public; `AgentDVR`'s own format is not documented separately.
//! 2. That `login` and `password` hold plaintext. iSpy could store an encrypted password in some
//!    versions; an encrypted value would be imported as if it were the password.
//! 3. Which source wins when the URL has userinfo and the login fields differ (decided below).
//! 4. That a source of kind "local device" or "ONVIF only" has no `rtsp://` URL in
//!    `videosourcestring` (such entries are skipped, see [`SkipReason`]).
//!
//! # What an import gives
//!
//! [`parse`] returns an [`Import`]: [`CameraDraft`]s (built only from core's camera types:
//! [`CameraId`], [`DisplayName`], [`Host`], port, [`RtspPath`], [`Credential`]) and the
//! [`Skipped`] entries with a typed [`SkipReason`]. A malformed document or one over a limit
//! fails the whole import with an [`ImportError`].
//!
//! ## Rules
//!
//! - **Source URL.** Only `rtsp://` (scheme case-insensitive). `[userinfo@]host[:port][path][?query]`.
//!   The userinfo is everything before the **last** `@` of the authority, which ends at the first
//!   `/` or `?`; it is split at the first `:` and percent-decoded (a `%` not followed by two hex
//!   digits stays literal). The host is bracketed IPv6, IPv4 or a DNS name, validated by core's
//!   [`Host`]; the port is 1 to 65535, default 554 (also when written `host:`); the path and
//!   query are passed unchanged to core's [`RtspPath`], which refuses `%`, `@`, `#`, dot
//!   segments, any character outside its pass-list and credential parameters. A source with a
//!   control character is skipped before anything else.
//! - **Credentials.** If `login` or `password` is non-empty, they are the credential and the URL
//!   userinfo is ignored (the explicit fields win over the URL when both are present and differ;
//!   no mixing of the two). Otherwise the URL userinfo is used when its user or password is
//!   non-empty (`rtsp://:@host` has none). An empty password is kept as empty. A user or password
//!   with a control character is skipped ([`SkipReason::InvalidCredential`]): such a value could
//!   inject RTSP headers.
//! - **Credentials in the path** (the Xiongmai `/user=..&password=..` form): the camera is
//!   skipped with [`SkipReason::CredentialInPath`]; the path is never imported, because moving
//!   the credential out of it would be a heuristic.
//! - **Identity.** The name is normalised exactly as the vault normalises a display name (every
//!   white-space char becomes one space, runs collapse, invisible characters are dropped, ends
//!   trimmed) and then validated by [`DisplayName::new`]. Two imported cameras whose normalised
//!   names are equal (case-sensitive, as in the vault's legacy import) fail the import with
//!   [`ImportError::DuplicateName`]; they are never merged. The [`CameraId`] slug is the ASCII
//!   lower-case alphanumerics of the name with other runs as one `-`, prefixed `cam-` when it
//!   does not start with a letter and `cam` when empty, at most 28 bytes; a slug already used
//!   gets `-2`, `-3`, ... in document order among imported cameras (skipped entries take no id).
//!
//! # Limits and hostile input
//!
//! At most [`MAX_INPUT_BYTES`] (8 MiB), [`MAX_CAMERAS`] `camera` elements (counting skipped
//! ones), [`MAX_DEPTH`] nested elements, and [`MAX_FIELD_BYTES`] per source or login field.
//! DOCTYPE is refused, so no entity is ever defined: only the five predefined entities and
//! numeric character references are expanded, one level, with no recursion. UTF-8 only (one leading BOM is
//! accepted; the reader skips it). Comments, processing instructions and CDATA are accepted. No input is echoed in
//! any error, `Debug` or `Display` output (SEC-6).
//!
//! [`CameraId`]: wardenlens_core::camera::CameraId
//! [`DisplayName`]: wardenlens_core::camera::DisplayName
//! [`DisplayName::new`]: wardenlens_core::camera::DisplayName::new
//! [`Host`]: wardenlens_core::camera::Host
//! [`RtspPath`]: wardenlens_core::camera::RtspPath
//! [`Credential`]: wardenlens_core::camera::Credential

mod document;
mod error;
mod identity;
mod source;

#[cfg(test)]
mod tests;

use std::collections::BTreeSet;
use std::num::NonZeroU16;

use secrecy::{ExposeSecret, SecretString};
use wardenlens_core::camera::{CameraId, Credential, DisplayName, Host, RtspPath};

pub use error::{ImportError, SkipReason};

/// Longest input accepted, in bytes.
pub const MAX_INPUT_BYTES: usize = 8 * 1024 * 1024;
/// Most `camera` elements accepted (skipped ones count).
pub const MAX_CAMERAS: usize = 256;
/// Deepest element nesting accepted (the root is depth 1).
pub const MAX_DEPTH: usize = 32;
/// Longest source URL, login or password text accepted, in bytes.
pub const MAX_FIELD_BYTES: usize = 4096;

/// One importable camera. Built from core's validated types; `Debug` shows only the id and the
/// port, because the name, host, path and credential redact themselves. The credential is meant
/// for the vault, not the database (ADR 0006); the source URL is never kept.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct CameraDraft {
    /// The slug id (deduplicated).
    pub id: CameraId,
    /// The display name, normalised.
    pub name: DisplayName,
    /// The camera host.
    pub host: Host,
    /// The RTSP port (554 when the source names none).
    pub port: NonZeroU16,
    /// The stream path and query, never with a credential.
    pub path: RtspPath,
    /// The login, if the entry has one.
    pub credential: Option<Credential>,
}

/// A camera entry that was not imported, and why.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Skipped {
    /// Zero-based position among the `camera` elements of the document.
    pub position: usize,
    /// The numeric `id` attribute of the entry, if it has one that is a number.
    pub agent_id: Option<u32>,
    /// Why.
    pub reason: SkipReason,
}

/// The result of a successful parse: every `camera` element is in exactly one of the two lists.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct Import {
    /// The importable cameras, in document order.
    pub cameras: Vec<CameraDraft>,
    /// The entries that were not importable, in document order.
    pub skipped: Vec<Skipped>,
}

/// Parses an `AgentDVR` `objects.xml`.
///
/// # Errors
/// An [`ImportError`] when the document is over a limit, is not UTF-8, has a DOCTYPE, is not
/// well-formed, is not an objects file, or has two cameras with the same normalised name. The
/// error never contains input text.
pub fn parse(input: &[u8]) -> Result<Import, ImportError> {
    if input.len() > MAX_INPUT_BYTES {
        return Err(ImportError::TooLarge);
    }
    let text = std::str::from_utf8(input).map_err(|_| ImportError::NotUtf8)?;
    let raws = document::read(text)?;
    let mut import = Import::default();
    let mut ids = identity::IdAllocator::default();
    let mut names = BTreeSet::new();
    for raw in raws {
        let (position, agent_id) = (raw.position, raw.agent_id);
        match build(raw) {
            Ok(p) => {
                // One name, one camera: never merged, never first-wins (#43, ADR 0006).
                if !names.insert(p.name.expose().to_owned()) {
                    return Err(ImportError::DuplicateName);
                }
                match ids.allocate(p.name.expose()) {
                    Ok(id) => import.cameras.push(CameraDraft {
                        id,
                        name: p.name,
                        host: p.host,
                        port: p.port,
                        path: p.path,
                        credential: p.credential,
                    }),
                    Err(_) => import.skipped.push(Skipped {
                        position,
                        agent_id,
                        reason: SkipReason::NameRefused,
                    }),
                }
            }
            Err(reason) => import.skipped.push(Skipped {
                position,
                agent_id,
                reason,
            }),
        }
    }
    Ok(import)
}

/// A validated entry that has no id yet: the id depends on every earlier imported camera.
struct Pending {
    name: DisplayName,
    host: Host,
    port: NonZeroU16,
    path: RtspPath,
    credential: Option<Credential>,
}

/// One raw entry to a validated entry, or the reason it is skipped.
fn build(mut raw: document::RawCamera) -> Result<Pending, SkipReason> {
    if raw.deleted {
        return Err(SkipReason::Deleted);
    }
    let slots = [&raw.source, &raw.login, &raw.password];
    if raw.settings_count > 1 || slots.iter().any(|s| s.count > 1) {
        return Err(SkipReason::RepeatedElement);
    }
    if slots.iter().any(|s| s.too_long) {
        return Err(SkipReason::FieldTooLong);
    }
    let name = raw.name.take().ok_or(SkipReason::MissingName)?;
    let normalised = identity::normalise_name(&name);
    let name = DisplayName::new(&normalised).map_err(|_| SkipReason::NameRefused)?;
    let source = raw.source.text.take().unwrap_or_default();
    let parts = source::split(&source)?;
    let credential = credential_of(&mut raw, parts.userinfo)?;
    Ok(Pending {
        name,
        host: parts.host,
        port: parts.port,
        path: parts.path,
        credential,
    })
}

/// The login fields win when either is non-empty; otherwise the URL userinfo. Never mixed.
fn credential_of(
    raw: &mut document::RawCamera,
    userinfo: Option<(String, SecretString)>,
) -> Result<Option<Credential>, SkipReason> {
    let login = raw.login.text.take().unwrap_or_default();
    let password = raw.take_password();
    let password_empty = password
        .as_ref()
        .is_none_or(|p| p.expose_secret().is_empty());
    if login.is_empty() && password_empty {
        return Ok(userinfo.map(|(user, password)| Credential::new(user, password)));
    }
    let password = password.unwrap_or_else(|| SecretString::from(String::new()));
    if login.chars().any(char::is_control) || password.expose_secret().chars().any(char::is_control)
    {
        return Err(SkipReason::InvalidCredential);
    }
    Ok(Some(Credential::new(login, password)))
}
