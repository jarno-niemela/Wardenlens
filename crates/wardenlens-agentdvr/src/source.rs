//! The source URL split: `rtsp://[userinfo@]host[:port][/path][?query]` into core's [`Host`],
//! port, [`RtspPath`] and the userinfo, which the caller turns into a credential.
//!
//! Hand-written on purpose: core's types validate the parts but do not parse a URL, and a
//! general URL parser would rewrite the path (dot segments, percent-encoding) and silently drop
//! tabs and newlines. Here nothing is rewritten: the path and query reach [`RtspPath`] exactly as
//! written, and every part is checked by core's validator (one choke point, SEC-10).
//!
//! The userinfo is returned undecoded. The only input-dependent error is a [`SkipReason`], which
//! carries no text.

use std::num::NonZeroU16;

use secrecy::zeroize::Zeroizing;
use wardenlens_core::camera::{CameraError, DEFAULT_RTSP_PORT, Host, RtspPath};

use crate::SkipReason;

/// The parts of one accepted source.
pub(crate) struct Parts {
    pub host: Host,
    pub port: NonZeroU16,
    pub path: RtspPath,
    /// The URL userinfo, still percent-encoded, when its user or password is non-empty. It is
    /// decoded only when it is the credential that will be used (or must be compared).
    pub userinfo: Option<RawUserinfo>,
}

/// The userinfo as written: user and password, percent-encoded.
pub(crate) struct RawUserinfo {
    user: Zeroizing<String>,
    password: Zeroizing<String>,
}

impl RawUserinfo {
    /// The decoded `(user, password)`. Invalid UTF-8 after decoding is refused.
    pub(crate) fn decode(&self) -> Result<(Zeroizing<String>, Zeroizing<String>), SkipReason> {
        Ok((decode(&self.user)?, decode(&self.password)?))
    }
}

/// Splits `raw`, or says why the camera cannot be imported.
pub(crate) fn split(raw: &str) -> Result<Parts, SkipReason> {
    let s = raw.trim_matches(|c: char| c.is_ascii_whitespace());
    if s.is_empty() {
        return Err(SkipReason::NoSource);
    }
    // Before anything else: a control character anywhere (tab, newline, NUL, DEL, C1).
    if s.chars().any(char::is_control) {
        return Err(SkipReason::InvalidUrl);
    }
    let (scheme, rest) = s.split_once("://").ok_or(SkipReason::NotAUrl)?;
    if !scheme.eq_ignore_ascii_case("rtsp") {
        return Err(SkipReason::UnsupportedScheme);
    }
    // The authority ends at the first `/` or `?`; the userinfo ends at the last `@` before that.
    let end = rest.find(['/', '?']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at_checked(end).unwrap_or((rest, ""));
    let (userinfo, host_port) = match authority.rfind('@') {
        Some(at) => {
            let (ui, hp) = authority.split_at_checked(at).unwrap_or((authority, ""));
            (ui, hp.strip_prefix('@').unwrap_or(hp))
        }
        None => ("", authority),
    };
    let (host, port) = host_port_of(host_port)?;
    let path = path_of(tail)?;
    let userinfo = userinfo_of(userinfo);
    Ok(Parts {
        host,
        port,
        path,
        userinfo,
    })
}

/// `host`, `host:port`, `[v6]`, `[v6]:port`; an empty port (`host:`) is the default.
fn host_port_of(hp: &str) -> Result<(Host, NonZeroU16), SkipReason> {
    let (host_text, port_text) = if hp.starts_with('[') {
        let close = hp.find(']').ok_or(SkipReason::InvalidHost)?;
        let (h, after) = hp
            .split_at_checked(close.saturating_add(1))
            .ok_or(SkipReason::InvalidHost)?;
        match after.strip_prefix(':') {
            Some(p) => (h, p),
            None if after.is_empty() => (h, ""),
            None => return Err(SkipReason::InvalidHost),
        }
    } else {
        match hp.split_once(':') {
            // A second colon: an unbracketed IPv6 address or junk. Refused, never guessed at.
            Some((_, p)) if p.contains(':') => return Err(SkipReason::InvalidHost),
            Some((h, p)) => (h, p),
            None => (hp, ""),
        }
    };
    let host = Host::new(host_text).map_err(|_| SkipReason::InvalidHost)?;
    Ok((host, port_of(port_text)?))
}

fn port_of(text: &str) -> Result<NonZeroU16, SkipReason> {
    if text.is_empty() {
        return Ok(DEFAULT_RTSP_PORT);
    }
    if !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err(SkipReason::InvalidPort);
    }
    text.parse::<u16>()
        .ok()
        .and_then(NonZeroU16::new)
        .ok_or(SkipReason::InvalidPort)
}

/// The path and query exactly as written. An absent path is `/`; a bare query gets a `/`.
fn path_of(tail: &str) -> Result<RtspPath, SkipReason> {
    let text = if tail.is_empty() {
        "/".to_owned()
    } else if tail.starts_with('?') {
        format!("/{tail}")
    } else {
        tail.to_owned()
    };
    RtspPath::new(&text).map_err(|e| match e {
        CameraError::PathCredentialParam => SkipReason::CredentialInPath,
        _ => SkipReason::InvalidPath,
    })
}

/// `user[:password]`, kept encoded; none when both are empty.
fn userinfo_of(ui: &str) -> Option<RawUserinfo> {
    let (user, password) = ui.split_once(':').unwrap_or((ui, ""));
    if user.is_empty() && password.is_empty() {
        return None;
    }
    Some(RawUserinfo {
        user: Zeroizing::new(user.to_owned()),
        password: Zeroizing::new(password.to_owned()),
    })
}

/// Lenient login candidates of a source text, with or without a scheme (see `Logins`): the part
/// before the LAST `@` of everything after `://` (or of the whole text), not cut at a `/` or `?`,
/// split at the first `:` into user and password; each part raw, and percent-decoded when that is
/// valid UTF-8. Also the same for the authority-bounded userinfo, which is the true split of a
/// well-formed URL that has a `@` further on.
pub(crate) fn userinfo_candidates(raw: &str) -> Vec<Zeroizing<String>> {
    let s = raw.trim_matches(|c: char| c.is_ascii_whitespace());
    let rest = s.split_once("://").map_or(s, |(_, r)| r);
    let end = rest.find(['/', '?']).unwrap_or(rest.len());
    let authority = rest.split_at_checked(end).map_or(rest, |(a, _)| a);
    let mut out = Vec::new();
    for scope in [rest, authority] {
        let Some(at) = scope.rfind('@') else { continue };
        let userinfo = scope.split_at_checked(at).map_or("", |(u, _)| u);
        let (user, password) = userinfo.split_once(':').unwrap_or((userinfo, ""));
        for part in [user, password] {
            out.push(Zeroizing::new(part.to_owned()));
            if let Ok(decoded) = decode(part) {
                out.push(decoded);
            }
        }
    }
    out
}

/// Percent-decoding; a `%` not followed by two hex digits stays literal. Invalid UTF-8 is
/// refused. Every buffer is zeroised on drop.
fn decode(s: &str) -> Result<Zeroizing<String>, SkipReason> {
    let bytes = s.as_bytes();
    let mut out = Zeroizing::new(Vec::with_capacity(bytes.len()));
    let mut i = 0_usize;
    while let Some(&b) = bytes.get(i) {
        let escaped = if b == b'%' {
            let hi = bytes.get(i.saturating_add(1)).copied().and_then(hex);
            let lo = bytes.get(i.saturating_add(2)).copied().and_then(hex);
            hi.zip(lo).map(|(h, l)| (h << 4) | l)
        } else {
            None
        };
        if let Some(byte) = escaped {
            out.push(byte);
            i = i.saturating_add(3);
        } else {
            out.push(b);
            i = i.saturating_add(1);
        }
    }
    let text = std::str::from_utf8(&out).map_err(|_| SkipReason::InvalidCredential)?;
    Ok(Zeroizing::new(text.to_owned()))
}

fn hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => b.checked_sub(b'0'),
        b'a'..=b'f' => b.checked_sub(b'a').map(|d| d.saturating_add(10)),
        b'A'..=b'F' => b.checked_sub(b'A').map(|d| d.saturating_add(10)),
        _ => None,
    }
}
