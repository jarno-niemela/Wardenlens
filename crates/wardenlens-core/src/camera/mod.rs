//! Camera domain model: validated identity, address and stream paths, plus credential ports.
//!
//! Pure: no I/O (ARCH-1). Every type is parse-don't-validate (TYPE-2) and the exact accepted and
//! rejected forms are tabulated in each submodule ([`CameraId`], [`Host`], [`RtspPath`],
//! [`DisplayName`]). Sensitive values (host, display name, credential) have redacting `Debug` and
//! `Display`; errors name the rule and never echo the input (SEC-6).
//!
//! [`Camera::rtsp_url`] never contains credentials: it is `rtsp://<host>:<port><path>`, port always
//! present, IPv6 hosts bracketed. The URL type redacts itself when formatted.

mod credential;
mod error;
mod host;
mod id;
mod model;
mod name;
mod path;

pub use credential::{Credential, CredentialSource};
pub use error::CameraError;
pub use host::{Host, MAX_HOST_LEN};
pub use id::{CameraId, MAX_CAMERA_ID_LEN};
pub use model::{Camera, DEFAULT_RTSP_PORT, RtspUrl, StreamRole};
pub use name::{DisplayName, MAX_NAME_LEN};
pub use path::{MAX_PATH_LEN, RtspPath};
