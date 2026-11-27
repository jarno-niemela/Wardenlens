//! The pure `ProbeMatches` parser and the merge of what it finds. No I/O, no clock, no
//! randomness. The XML is read with the crate's bounded reader (1 MiB, depth 64, 4096 elements,
//! DOCTYPE refused), so a hostile datagram can only fail, never blow up.

use super::xaddr::{XAddrDrop, validate};
use super::{DiscoveredDevice, DropReason, MAX_DEVICES, MAX_SCOPES, MAX_XADDRS};
use crate::OnvifError;
use crate::soap::Doc;

/// Most `ProbeMatch` entries read from one reply; the rest are dropped.
pub(crate) const MAX_MATCHES_PER_REPLY: usize = 16;
/// Longest endpoint reference, in bytes.
pub(crate) const MAX_ENDPOINT_REF_LEN: usize = 256;
/// Longest scope, in bytes.
pub(crate) const MAX_SCOPE_LEN: usize = 256;

/// Why a datagram is not a usable answer to our probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ProbeReplyError {
    /// The datagram is not a bounded, well-formed `ProbeMatches` envelope (or is a SOAP fault).
    #[error("the datagram is not a usable ProbeMatches reply: {0}")]
    Xml(OnvifError),
    /// `RelatesTo` is missing or does not echo the `MessageID` of our probe: a stray or spoofed
    /// datagram.
    #[error("the datagram does not echo our MessageID")]
    NotOurs,
}

/// What one datagram yielded.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProbeReply {
    /// The usable entries, in document order. Two entries may name one endpoint; the collector
    /// merges them.
    pub devices: Vec<DiscoveredDevice>,
    /// Everything that was dropped, one reason each (bounded: at most a few dozen per reply).
    pub drops: Vec<DropReason>,
}

fn text(doc: &Doc, idx: usize) -> Option<(&str, bool)> {
    doc.elem(idx).map(|e| (e.text.trim(), e.text_too_long))
}

/// Parses one datagram as the answer to the probe whose `MessageID` is `message_id` (the full
/// value, for example `uuid:...`; `RelatesTo` must equal it exactly).
///
/// # Errors
/// [`ProbeReplyError::NotOurs`] unless `RelatesTo` echoes `message_id`;
/// [`ProbeReplyError::Xml`] for a datagram that is not a bounded, well-formed, non-fault
/// `ProbeMatches` envelope.
pub fn parse_probe_matches(
    datagram: &[u8],
    message_id: &str,
) -> Result<ProbeReply, ProbeReplyError> {
    let doc = Doc::parse(datagram).map_err(ProbeReplyError::Xml)?;
    let relates = doc
        .path(0, &["Header", "RelatesTo"])
        .and_then(|i| text(&doc, i));
    if !relates.is_some_and(|(t, too_long)| !too_long && t == message_id) {
        return Err(ProbeReplyError::NotOurs);
    }
    let root = doc.response("ProbeMatches").map_err(ProbeReplyError::Xml)?;
    let mut reply = ProbeReply::default();
    let entries = doc
        .children(root)
        .filter(|i| doc.elem(*i).is_some_and(|e| e.name == "ProbeMatch"));
    for (n, idx) in entries.enumerate() {
        if n >= MAX_MATCHES_PER_REPLY {
            reply.drops.push(DropReason::TooManyMatches);
            break;
        }
        match entry(&doc, idx, &mut reply.drops) {
            Ok(device) => reply.devices.push(device),
            Err(reason) => reply.drops.push(reason),
        }
    }
    Ok(reply)
}

fn entry(
    doc: &Doc,
    idx: usize,
    drops: &mut Vec<DropReason>,
) -> Result<DiscoveredDevice, DropReason> {
    let endpoint_ref = doc
        .path(idx, &["EndpointReference", "Address"])
        .and_then(|i| text(doc, i))
        .filter(|(t, too_long)| {
            !too_long
                && !t.is_empty()
                && t.len() <= MAX_ENDPOINT_REF_LEN
                && !t.chars().any(char::is_control)
        })
        .map(|(t, _)| t.to_owned())
        .ok_or(DropReason::BadEndpointReference)?;
    let xaddrs = match doc.child(idx, "XAddrs").and_then(|i| text(doc, i)) {
        Some((_, true)) => return Err(DropReason::XAddrs(XAddrDrop::TooLong)),
        Some((t, false)) => xaddrs(t, drops),
        None => Vec::new(),
    };
    if xaddrs.is_empty() {
        return Err(DropReason::NoUsableXAddr);
    }
    let scopes = match doc.child(idx, "Scopes").and_then(|i| text(doc, i)) {
        Some((_, true)) => {
            drops.push(DropReason::ScopeTooLong);
            Vec::new()
        }
        Some((t, false)) => scopes(t, drops),
        None => Vec::new(),
    };
    Ok(DiscoveredDevice {
        xaddrs,
        scopes,
        endpoint_ref,
    })
}

/// Validates the space-separated list. At most [`MAX_XADDRS`] are kept and a few more looked at,
/// so the drop list stays small however long the text is.
fn xaddrs(list: &str, drops: &mut Vec<DropReason>) -> Vec<String> {
    let mut kept: Vec<String> = Vec::new();
    for (n, raw) in list.split_whitespace().enumerate() {
        if n >= MAX_XADDRS {
            drops.push(DropReason::TooManyXAddrs);
            break;
        }
        match validate(raw) {
            Ok(u) if kept.contains(&u) => {}
            Ok(u) => kept.push(u),
            Err(reason) => drops.push(DropReason::XAddrs(reason)),
        }
    }
    kept
}

fn scopes(list: &str, drops: &mut Vec<DropReason>) -> Vec<String> {
    let mut kept: Vec<String> = Vec::new();
    for (n, s) in list.split_whitespace().enumerate() {
        if n >= MAX_SCOPES {
            drops.push(DropReason::TooManyScopes);
            break;
        }
        if s.len() > MAX_SCOPE_LEN || s.chars().any(char::is_control) {
            drops.push(DropReason::ScopeTooLong);
        } else if !kept.iter().any(|k| k == s) {
            kept.push(s.to_owned());
        }
    }
    kept
}

/// Merges entries that name one endpoint reference and caps the number of devices.
#[derive(Debug, Default)]
pub(crate) struct Collector {
    devices: Vec<DiscoveredDevice>,
}

impl Collector {
    /// Adds `device`, merging into the entry with the same endpoint reference. Pushes onto `drops`
    /// whatever the merge or a cap refused.
    pub(crate) fn add(&mut self, device: DiscoveredDevice, drops: &mut Vec<DropReason>) {
        let Some(known) = self
            .devices
            .iter_mut()
            .find(|d| d.endpoint_ref == device.endpoint_ref)
        else {
            if self.devices.len() >= MAX_DEVICES {
                drops.push(DropReason::TooManyDevices);
            } else {
                self.devices.push(device);
            }
            return;
        };
        for x in device.xaddrs {
            if known.xaddrs.contains(&x) {
                continue;
            }
            if known.xaddrs.len() >= MAX_XADDRS {
                drops.push(DropReason::TooManyXAddrs);
            } else {
                known.xaddrs.push(x);
            }
        }
        for s in device.scopes {
            if known.scopes.contains(&s) {
                continue;
            }
            if known.scopes.len() >= MAX_SCOPES {
                drops.push(DropReason::TooManyScopes);
            } else {
                known.scopes.push(s);
            }
        }
    }

    pub(crate) fn into_devices(self) -> Vec<DiscoveredDevice> {
        self.devices
    }
}
