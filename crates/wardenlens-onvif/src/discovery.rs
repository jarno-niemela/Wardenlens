//! WS-Discovery: one `Probe` to `239.255.255.250:3702`, then the `ProbeMatches` that echo it
//! (ADR 0004 section 7, ticket #53).
//!
//! Anyone on the LAN can answer, so every result is a **suggestion** for the operator to
//! confirm, never a trusted fact. What the module guarantees:
//!
//! - A datagram counts only if its `RelatesTo` equals the `MessageID` of the probe sent (a fresh
//!   128-bit random value per call). A datagram larger than [`MAX_DATAGRAM`] is ignored.
//! - The wait is [`DEFAULT_WINDOW`] (4 s) when the caller passes that, and never more than
//!   [`MAX_WINDOW`] (10 s), measured on the monotonic clock. Collection stops at
//!   [`MAX_REPLIES`] (64) accepted replies and keeps at most [`MAX_DEVICES`] (64) devices.
//! - Entries with one endpoint reference are merged (their `XAddrs` and scopes are unioned, up
//!   to [`MAX_XADDRS`] and [`MAX_SCOPES`]).
//! - Every `XAddr` goes through one pass-list: plain `http://` on a private or
//!   link-local IP literal only, rebuilt in canonical form. Each drop is logged at `debug` level
//!   with its reason and the probe id, never with the offending text (it is attacker controlled).
//! - Replies are accepted from any source address; the pass-list on the `XAddrs` is the check,
//!   not the sender.
//!
//! IPv4 only, as the ADR says. Multicast does not cross Docker's default bridge network. No
//! multicast group is joined: replies are unicast to the probe's source port.

mod matches;
mod xaddr;

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::time::Instant;

#[cfg(test)]
pub(crate) use matches::Collector;
pub use matches::{ProbeReply, ProbeReplyError, parse_probe_matches};
pub use xaddr::XAddrDrop;
#[cfg(test)]
pub(crate) use xaddr::validate as xaddr_validate;

/// The WS-Discovery multicast group.
pub const MULTICAST_GROUP: Ipv4Addr = Ipv4Addr::new(239, 255, 255, 250);
/// The WS-Discovery port.
pub const DISCOVERY_PORT: u16 = 3702;
/// The window a caller should use when it has no better idea.
pub const DEFAULT_WINDOW: Duration = Duration::from_secs(4);
/// The longest window that is honoured; a larger one is cut to this.
pub const MAX_WINDOW: Duration = Duration::from_secs(10);
/// Most accepted replies before collection stops.
pub const MAX_REPLIES: usize = 64;
/// Most devices returned.
pub const MAX_DEVICES: usize = 64;
/// Most `XAddrs` kept per device.
pub const MAX_XADDRS: usize = 8;
/// Most scopes kept per device.
pub const MAX_SCOPES: usize = 32;
/// Largest datagram that is parsed, in bytes (64 KiB).
pub const MAX_DATAGRAM: usize = 64 * 1024;

/// One device that answered, after validation and merging.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredDevice {
    /// Canonical `http://` service URLs on private or link-local IP literals, at most
    /// [`MAX_XADDRS`], never empty.
    pub xaddrs: Vec<String>,
    /// ONVIF scope URIs (at most [`MAX_SCOPES`]). Attacker-controlled text: display with care.
    pub scopes: Vec<String>,
    /// The endpoint reference the device gave (usually `urn:uuid:...`). Not authenticated: two
    /// devices may claim one.
    pub endpoint_ref: String,
}

/// Why something was dropped, for the log and for tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DropReason {
    /// One `XAddr` was refused, for the inner reason.
    XAddrs(XAddrDrop),
    /// More than [`MAX_XADDRS`] were listed or merged.
    TooManyXAddrs,
    /// An entry had no `XAddr` left after validation.
    NoUsableXAddr,
    /// The endpoint reference is missing, empty, too long or has control characters.
    BadEndpointReference,
    /// A scope was too long, had a control character, or the whole element was too long.
    ScopeTooLong,
    /// More than [`MAX_SCOPES`] scopes.
    TooManyScopes,
    /// A reply had more than 16 `ProbeMatch` entries.
    TooManyMatches,
    /// A new endpoint arrived with [`MAX_DEVICES`] devices already held.
    TooManyDevices,
}

impl std::fmt::Display for DropReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::XAddrs(r) => r.fmt(f),
            Self::TooManyXAddrs => f.write_str("more xaddrs than the limit"),
            Self::NoUsableXAddr => f.write_str("entry has no usable xaddr"),
            Self::BadEndpointReference => f.write_str("endpoint reference is missing or invalid"),
            Self::ScopeTooLong => f.write_str("a scope is too long or invalid"),
            Self::TooManyScopes => f.write_str("more scopes than the limit"),
            Self::TooManyMatches => f.write_str("more probe matches than the limit"),
            Self::TooManyDevices => f.write_str("more devices than the limit"),
        }
    }
}

/// Why a discovery run failed. Never carries reply text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum DiscoveryError {
    /// The OS random source failed, so no `MessageID` could be made.
    #[error("the operating system random source failed")]
    Random,
    /// The socket could not be created, bound to the interface address, or sent on.
    #[error("the discovery socket failed to open or send: {0:?}")]
    Socket(std::io::ErrorKind),
    /// Receiving failed (not a timeout).
    #[error("receiving discovery replies failed: {0:?}")]
    Receive(std::io::ErrorKind),
}

/// The window actually used for a requested `timeout`: at most [`MAX_WINDOW`].
#[must_use]
pub fn effective_window(timeout: Duration) -> Duration {
    timeout.min(MAX_WINDOW)
}

/// Builds the `Probe` envelope for `message_id` (pure).
#[must_use]
pub fn build_probe(message_id: &str) -> String {
    format!(
        concat!(
            r#"<?xml version="1.0" encoding="UTF-8"?>"#,
            r#"<e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope" "#,
            r#"xmlns:w="http://schemas.xmlsoap.org/ws/2004/08/addressing" "#,
            r#"xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery" "#,
            r#"xmlns:dn="http://www.onvif.org/ver10/network/wsdl">"#,
            r#"<e:Header><w:MessageID>{id}</w:MessageID>"#,
            r#"<w:To e:mustUnderstand="true">urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To>"#,
            r#"<w:Action e:mustUnderstand="true">"#,
            r#"http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action></e:Header>"#,
            r#"<e:Body><d:Probe><d:Types>dn:NetworkVideoTransmitter</d:Types></d:Probe></e:Body>"#,
            r#"</e:Envelope>"#
        ),
        id = message_id
    )
}

pub(crate) fn new_message_id() -> Result<String, DiscoveryError> {
    let mut b = [0_u8; 16];
    getrandom::fill(&mut b).map_err(|_| DiscoveryError::Random)?;
    let mut id = String::from("uuid:");
    for byte in b {
        for nibble in [byte >> 4, byte & 0x0f] {
            id.push(char::from_digit(u32::from(nibble), 16).unwrap_or('0'));
        }
    }
    Ok(id)
}

/// Sends one probe out of the interface with address `iface` (`0.0.0.0` lets the OS choose) and
/// collects replies for `timeout` (cut to [`MAX_WINDOW`]).
///
/// # Errors
/// [`DiscoveryError`] when the socket cannot be set up or used. Hostile or malformed replies are
/// skipped, not errors.
pub async fn discover(
    timeout: Duration,
    iface: Ipv4Addr,
) -> Result<Vec<DiscoveredDevice>, DiscoveryError> {
    let target = SocketAddr::V4(SocketAddrV4::new(MULTICAST_GROUP, DISCOVERY_PORT));
    run(target, iface, timeout, MAX_REPLIES, &new_message_id()?).await
}

fn open(iface: Ipv4Addr) -> std::io::Result<UdpSocket> {
    use socket2::{Domain, Protocol, SockAddr, Socket, Type};
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_multicast_if_v4(&iface)?;
    socket.set_multicast_ttl_v4(1)?;
    socket.bind(&SockAddr::from(SocketAddrV4::new(iface, 0)))?;
    socket.set_nonblocking(true)?;
    UdpSocket::from_std(socket.into())
}

/// Whether a received datagram of `n` bytes is parsed (the buffer holds one byte more than the
/// limit, so a longer one is seen as longer).
pub(crate) fn datagram_within_limit(n: usize) -> bool {
    n <= MAX_DATAGRAM
}

/// The socket path with the target and caps as parameters, so tests can use loopback.
pub(crate) async fn run(
    target: SocketAddr,
    iface: Ipv4Addr,
    timeout: Duration,
    max_replies: usize,
    message_id: &str,
) -> Result<Vec<DiscoveredDevice>, DiscoveryError> {
    let socket = open(iface).map_err(|e| DiscoveryError::Socket(e.kind()))?;
    let now = Instant::now();
    // The window is at most 10 s, so the sum cannot overflow; `now` is the safe fallback.
    let deadline = now.checked_add(effective_window(timeout)).unwrap_or(now);
    socket
        .send_to(build_probe(message_id).as_bytes(), target)
        .await
        .map_err(|e| DiscoveryError::Socket(e.kind()))?;
    // One byte more than the limit, so a datagram over the limit is seen as such.
    let mut buf = vec![0_u8; MAX_DATAGRAM + 1];
    let mut collector = matches::Collector::default();
    let mut accepted = 0_usize;
    while accepted < max_replies {
        let received = tokio::time::timeout_at(deadline, socket.recv_from(&mut buf)).await;
        let n = match received {
            Err(_elapsed) => break,
            Ok(Err(e)) => return Err(DiscoveryError::Receive(e.kind())),
            Ok(Ok((n, _from))) => n,
        };
        if !datagram_within_limit(n) {
            tracing::debug!(probe = message_id, "discovery datagram over 64 KiB ignored");
            continue;
        }
        let Some(datagram) = buf.get(..n) else {
            continue;
        };
        let reply = match parse_probe_matches(datagram, message_id) {
            Ok(r) => r,
            Err(e) => {
                tracing::debug!(probe = message_id, reason = %e, "discovery datagram ignored");
                continue;
            }
        };
        accepted = accepted.saturating_add(1);
        let mut drops = reply.drops;
        for device in reply.devices {
            collector.add(device, &mut drops);
        }
        for reason in drops {
            tracing::debug!(probe = message_id, %reason, "discovery entry dropped");
        }
    }
    Ok(collector.into_devices())
}
