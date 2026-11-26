//! Camera domain model: validated identity, address and stream paths, plus credential ports.
//!
//! Pure: no I/O (ARCH-1). Every type is parse-don't-validate (TYPE-2) and the exact accepted and
//! rejected forms are tabulated in each submodule ([`CameraId`], [`Host`], [`RtspPath`],
//! [`DisplayName`]). Sensitive values (host, display name, credential) have redacting `Debug` and
//! `Display`; errors name the rule and never echo the input (SEC-6).
//!
//! A [`Camera`] holds its id, display name, catalogue [`ModelRef`], host, port and a [`StreamSet`]
//! (main path, optional sub path). It holds no credential: that comes from a
//! [`CredentialSource`] by camera id (ADR 0006). [`StreamRole`] is the catalogue's enum.
//!
//! Paths are redacting too: [`RtspPath`] prints `<redacted-path>`, so formatting a camera never
//! shows a host, a name or a path.
//!
//! [`Camera::rtsp_url`] never contains credentials: it is `rtsp://<host>:<port><path>`, port always
//! present, IPv6 hosts bracketed. The URL type redacts itself when formatted.

mod credential;
mod directory;
mod error;
mod host;
mod id;
mod model;
mod modelref;
mod name;
mod path;

pub use crate::catalogue::StreamRole;
pub use credential::{Credential, CredentialRule, CredentialSource, MAX_CREDENTIAL_PART_LEN};
pub use directory::{CameraDirectory, CameraStatus, DirectoryError, LinkState, LinkStatus};
pub use error::CameraError;
pub use host::{Host, MAX_HOST_LEN};
pub use id::{CameraId, MAX_CAMERA_ID_LEN};
pub use model::{Camera, DEFAULT_RTSP_PORT, RtspUrl, StreamSet};
pub use modelref::{MAX_SLUG_LEN, ModelRef};
pub use name::{DisplayName, MAX_NAME_LEN};
pub use path::{MAX_PATH_LEN, RtspPath};
