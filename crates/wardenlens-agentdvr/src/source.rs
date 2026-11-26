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
use wardenlens_core::camera::{
    CameraError, DEFAULT_RTSP_PORT, Host, RtspPath, ends_with_credential_param_name,
};

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

/// Calls `emit` with every lenient login candidate of a source text, with or without a scheme
/// (see `Logins`), each raw and percent-decoded when that is valid UTF-8:
///
/// * for **every** `@` of everything after `://` (or of the whole text), not cut at a `/` or
///   `?`: the userinfo before it, split at its first `:` into user and password. A real `@` may
///   be anywhere after an unencoded `/` or `@` in the password, so no split is guessed;
/// * the value of every credential-named `name=value` parameter anywhere in the text (core's
///   list), up to the next `&` and up to the next of `& / ? # @ ;`.
///
/// The first error of `emit` stops the walk and is returned. The scans here are a constant
/// number of passes over `raw` (the delimiter search is one forward pass); what is not bounded by
/// that is the candidates, and the caller bounds those: every candidate is passed to `emit`, so an
/// `emit` that charges the bytes it is offered (as `Logins` does, duplicates included) and
/// refuses past a budget ends the walk after work linear in the input.
pub(crate) fn for_each_candidate<E>(
    raw: &str,
    emit: &mut impl FnMut(&str) -> Result<(), E>,
) -> Result<(), E> {
    let s = raw.trim_matches(|c: char| c.is_ascii_whitespace());
    let rest = s.split_once("://").map_or(s, |(_, r)| r);
    emit_both(rest_user(rest), emit)?;
    let colon = rest.find(':');
    for (at, _) in rest.match_indices('@') {
        let userinfo = rest.get(..at).unwrap_or_default();
        match colon {
            // The first `:` is inside the userinfo: the user is fixed (emitted once above).
            Some(c) if c < at => {
                let password = rest.get(c.saturating_add(1)..at).unwrap_or_default();
                emit_both(password, emit)?;
            }
            // No `:` before this `@`: the whole userinfo is the user, with an empty password.
            _ => emit_both(userinfo, emit)?,
        }
    }
    // One forward pass: the next `&` and the next other delimiter at or after each `=` are
    // cached, and a cache that is still ahead of the `=` is reused, so every byte is scanned at
    // most once per kind whatever the number of `=`.
    let (mut next_amp, mut next_delim) = (0_usize, 0_usize);
    for (eq, _) in s.match_indices('=') {
        if !ends_with_credential_param_name(s.get(..eq).unwrap_or_default()) {
            continue;
        }
        let from = eq.saturating_add(1);
        let tail = s.get(from..).unwrap_or_default();
        if next_amp < from {
            next_amp = tail.find('&').map_or(s.len(), |i| from.saturating_add(i));
        }
        if next_delim < from {
            next_delim = tail
                .find(['&', '/', '?', '#', '@', ';'])
                .map_or(s.len(), |i| from.saturating_add(i));
        }
        let to_amp = s.get(from..next_amp).unwrap_or_default();
        let to_delim = s.get(from..next_delim).unwrap_or_default();
        emit_both(to_amp, emit)?;
        emit_both(to_delim, emit)?;
    }
    Ok(())
}

/// The user of `rest`: the text before its first `:`, when a `@` follows that colon. (A `:` with
/// no `@` after it is not a userinfo; the per-`@` loop covers every `@` before the colon.)
fn rest_user(rest: &str) -> &str {
    match rest.split_once(':') {
        Some((user, after)) if after.contains('@') => user,
        _ => "",
    }
}

/// `part` as written, then percent-decoded when that differs and is valid UTF-8.
fn emit_both<E>(part: &str, emit: &mut impl FnMut(&str) -> Result<(), E>) -> Result<(), E> {
    emit(part)?;
    if part.contains('%')
        && let Ok(decoded) = decode(part)
    {
        emit(&decoded)?;
    }
    Ok(())
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
