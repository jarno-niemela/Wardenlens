//! The `XAddrs` pass-list: one choke point that turns a hostile URL string into a canonical
//! `http://` URL on a private or link-local address, or into the reason it was dropped (SEC-10).
//!
//! Nothing is kept as given. The string is split into scheme, authority, port and path, each part
//! is checked against what is known to be good, and the URL is rebuilt from the parsed parts, so a
//! spelling the parser accepts but a client might read differently (userinfo, a host name, a
//! decimal or octal host, a zone id, a fragment) never reaches the caller.

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

/// Longest `XAddr` that is looked at, in bytes.
pub(crate) const MAX_XADDR_LEN: usize = 512;

/// Why one `XAddr` was dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum XAddrDrop {
    /// Longer than 512 bytes.
    TooLong,
    /// Has a space, a control character or a non-ASCII character.
    BadCharacters,
    /// No `scheme://` part.
    NoScheme,
    /// `https://` (this client has no TLS, ADR 0004 section 7).
    Https,
    /// A scheme other than `http`.
    OtherScheme,
    /// Has `user@` or `user:password@` before the host.
    Userinfo,
    /// The host is not a plain IPv4 or bracketed IPv6 literal (a name, a number spelled in a
    /// non-standard way, a zone id, a malformed bracket).
    NotIpLiteral,
    /// The port is empty, not decimal digits, 0 or above 65535.
    BadPort,
    /// A well-formed address that is not private (RFC 1918, `fc00::/7`) or link-local
    /// (`169.254.0.0/16`, `fe80::/10`).
    OutsideLan,
    /// The path or query has a character outside the allowed set, a `%`, a `?` or a `#`.
    BadPath,
}

impl fmt::Display for XAddrDrop {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::TooLong => "xaddr is longer than 512 bytes",
            Self::BadCharacters => "xaddr has a space, control or non-ASCII character",
            Self::NoScheme => "xaddr has no scheme",
            Self::Https => "xaddr is https, which this client cannot speak",
            Self::OtherScheme => "xaddr scheme is not http",
            Self::Userinfo => "xaddr has userinfo",
            Self::NotIpLiteral => "xaddr host is not a plain IP address",
            Self::BadPort => "xaddr port is invalid",
            Self::OutsideLan => "xaddr address is not private or link-local",
            Self::BadPath => "xaddr path has a character outside the allowed set",
        })
    }
}

fn lan_v4(a: Ipv4Addr) -> bool {
    a.is_private() || a.is_link_local()
}

/// `fc00::/7` (unique local) or `fe80::/10` (link-local). An IPv4-mapped address is neither.
fn lan_v6(a: Ipv6Addr) -> bool {
    let first = a.segments()[0];
    (first & 0xfe00) == 0xfc00 || (first & 0xffc0) == 0xfe80
}

fn path_byte_ok(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"-._~!$&'()*+,;=:@/".contains(&b)
}

/// Checks `raw` and returns the canonical form `http://host[:port]/path`.
///
/// # Errors
/// The [`XAddrDrop`] reason when `raw` is not a plain-HTTP URL on a private or link-local IP
/// literal.
pub(crate) fn validate(raw: &str) -> Result<String, XAddrDrop> {
    if raw.len() > MAX_XADDR_LEN {
        return Err(XAddrDrop::TooLong);
    }
    if !raw.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
        return Err(XAddrDrop::BadCharacters);
    }
    let (scheme, rest) = raw.split_once("://").ok_or(XAddrDrop::NoScheme)?;
    if scheme.eq_ignore_ascii_case("https") {
        return Err(XAddrDrop::Https);
    }
    if !scheme.eq_ignore_ascii_case("http") {
        return Err(XAddrDrop::OtherScheme);
    }
    // Everything is ASCII here, so byte offsets are char boundaries.
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = rest.get(..end).unwrap_or_default();
    let path = rest.get(end..).unwrap_or_default();
    if authority.contains('@') {
        return Err(XAddrDrop::Userinfo);
    }
    let (host, port) = split_authority(authority)?;
    let host = canonical_host(host)?;
    let port = match port {
        None => String::new(),
        Some(p) => format!(":{}", parse_port(p)?),
    };
    if !path.bytes().all(path_byte_ok) || !(path.is_empty() || path.starts_with('/')) {
        return Err(XAddrDrop::BadPath);
    }
    let path = if path.is_empty() { "/" } else { path };
    Ok(format!("http://{host}{port}{path}"))
}

/// Splits `host[:port]` or `[v6][:port]` into the host text (with its brackets) and the port text.
fn split_authority(authority: &str) -> Result<(&str, Option<&str>), XAddrDrop> {
    if authority.starts_with('[') {
        let close = authority.find(']').ok_or(XAddrDrop::NotIpLiteral)?;
        let host = authority.get(..=close).ok_or(XAddrDrop::NotIpLiteral)?;
        let after = authority.get(close.saturating_add(1)..).unwrap_or_default();
        return match after {
            "" => Ok((host, None)),
            _ => match after.strip_prefix(':') {
                Some(p) => Ok((host, Some(p))),
                None => Err(XAddrDrop::NotIpLiteral),
            },
        };
    }
    match authority.split_once(':') {
        Some((h, p)) => Ok((h, Some(p))),
        None => Ok((authority, None)),
    }
}

fn canonical_host(host: &str) -> Result<String, XAddrDrop> {
    if let Some(inner) = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
        let a = Ipv6Addr::from_str(inner).map_err(|_| XAddrDrop::NotIpLiteral)?;
        return if lan_v6(a) {
            Ok(format!("[{a}]"))
        } else {
            Err(XAddrDrop::OutsideLan)
        };
    }
    let a = Ipv4Addr::from_str(host).map_err(|_| XAddrDrop::NotIpLiteral)?;
    if lan_v4(a) {
        Ok(a.to_string())
    } else {
        Err(XAddrDrop::OutsideLan)
    }
}

fn parse_port(p: &str) -> Result<u16, XAddrDrop> {
    if p.is_empty() || p.len() > 5 || !p.bytes().all(|b| b.is_ascii_digit()) {
        return Err(XAddrDrop::BadPort);
    }
    match p.parse::<u16>() {
        Ok(v) if v != 0 => Ok(v),
        _ => Err(XAddrDrop::BadPort),
    }
}
