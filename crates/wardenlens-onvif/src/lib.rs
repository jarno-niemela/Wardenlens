//! A hand-rolled ONVIF device client over plain HTTP (ADR 0004 section 7).
//!
//! [`discovery`] finds devices on the LAN with WS-Discovery; the client below talks to one.
//!
//! Three read-only calls: [`OnvifClient::get_device_information`], [`OnvifClient::get_profiles`]
//! and [`OnvifClient::get_stream_uri`]. Everything a camera sends is untrusted network input
//! (SEC-2): the reply is read through a 1 MiB limit on the socket read itself, parsed with
//! quick-xml with DOCTYPE and entities refused, and bounded in depth and element count; every
//! value that leaves the crate went through a validator (core's [`wardenlens_core::camera::RtspPath`]
//! for the stream path, [`ProfileToken`] for tokens, bounded text for the rest).
//!
//! # Layers
//!
//! - [`parse_device_information`], [`parse_profiles`], [`parse_stream_uri`] and
//!   [`reduce_stream_uri`] are pure functions, tested on synthetic envelopes.
//! - The WS-Security `UsernameToken` digest uses a 16-byte nonce from the OS RNG, a UTC
//!   `Created`, and `Base64(SHA1(nonce + created + password))`. SHA-1 is what the ONVIF profile
//!   requires; it only answers the camera's challenge.
//! - The transport opens one plain-TCP connection per call (see "Retry contract").
//!
//! # Retry contract
//!
//! Up to [`MAX_ATTEMPTS`] (6) attempts per call. An attempt fails *retryably* when it gets no HTTP
//! response head: the connect is refused or times out
//! ([`ClientConfig::connect_timeout`], default 3 s), the camera closes the connection before
//! answering, it sends a head that hyper refuses (malformed, over 64 KiB, conflicting lengths; this
//! too ends as `Unreachable`, not as a transport error), or it stays silent for
//! [`ClientConfig::request_timeout`]. Every attempt builds its own request, with a fresh
//! WS-Security nonce and `Created`. Between attempts the wait
//! comes from core's `Backoff` ([`ClientConfig::backoff`]). After the last failure the result is
//! [`OnvifError::Unreachable`]. Once a head has arrived nothing is retried: the body is read once
//! and a failure there is final (a `Content-Length` over the cap is refused at once, the body as
//! a whole has [`ClientConfig::body_timeout`]). The calls are read-only queries, so repeating them is safe.
//!
//! # Credentials
//!
//! The password goes into exactly one place, the digest input buffer, which is wiped on return.
//! It is never formatted: not in `Debug`, not in errors, not in any log. The only events this
//! crate logs are [`discovery`]'s, at `debug` level, each a fixed text plus the probe id and
//! never reply text: a reason for every dropped entry or ignored datagram, a datagram over 64
//! KiB, and a receive error (as its `ErrorKind`).
//!
//! # The camera does not choose where the recorder connects
//!
//! A stream URI is reduced to a path and a port; the host in it is discarded and any userinfo the
//! camera echoes is dropped (see [`stream_uri`]).
//!
//! # Clock skew
//!
//! `Created` is the local UTC time. A camera whose clock is far off may refuse the token as
//! `NotAuthorized`; reading its clock with `GetSystemDateAndTime` is not part of this crate yet.

mod client;
pub mod discovery;
mod error;
mod model;
mod parse;
mod soap;
pub mod stream_uri;
mod transport;
mod wsse;

#[cfg(test)]
mod tests;

pub use client::{DEFAULT_SERVICE_PATH, OnvifClient};
pub use error::OnvifError;
pub use model::{
    DeviceInformation, MAX_DIMENSION, MAX_FIELD_LEN, MAX_TOKEN_LEN, Profile, ProfileToken,
    StreamChoice, VideoEncoding, pick_streams,
};
pub use parse::{parse_device_information, parse_profiles, parse_stream_uri};
pub use stream_uri::{MAX_STREAM_URI_LEN, StreamEndpoint, reduce_stream_uri};
pub use transport::ClientConfig;

/// Largest reply body that is read or parsed: 1 MiB.
pub const MAX_BODY_BYTES: usize = 1024 * 1024;
/// Deepest element nesting that is accepted (ADR 0004 section 7).
pub const MAX_DEPTH: usize = 64;
/// Most elements a reply may have.
pub const MAX_ELEMENTS: usize = 4096;
/// Most profiles a reply may list.
pub const MAX_PROFILES: usize = 32;
/// Most attempts one call makes before it gives up with [`OnvifError::Unreachable`].
pub const MAX_ATTEMPTS: u8 = 6;
/// Longest service path in bytes.
pub const MAX_SERVICE_PATH_LEN: usize = 256;
