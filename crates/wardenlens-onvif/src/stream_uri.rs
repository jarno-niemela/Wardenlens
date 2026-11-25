//! Reducing the stream URI a camera reports to what the recorder may use: a validated
//! [`RtspPath`] and a port.
//!
//! **The host in the reply is never used.** A camera reports the address it believes it has
//! (often its internal one behind NAT or a bridge), and a hostile or confused camera could name any
//! other machine. The recorder keeps connecting to the host the operator configured, so a reply
//! cannot redirect it. The host part is therefore discarded unread; only its shape is checked
//! enough to find the port. **Userinfo** (`user:password@`) that a camera echoes is dropped too:
//! it is never stored, never returned and never part of an error. Credentials come from the
//! vault, nowhere else.
//!
//! | input | result |
//! |---|---|
//! | `rtsp://h/p`, `RTSP://h/p`, `rtsp://h:8554/p?q=1` | path `/p`, port 554 / 554 / 8554 |
//! | `rtsp://h` , `rtsp://h?x=1` | path `/` , `/?x=1` |
//! | `rtsp://u:pw@h:554/p` (userinfo, also with several `@`) | userinfo dropped, as without it |
//! | `rtsp://[2001:db8::1]:8554/p` | port 8554 |
//! | `rtsp://h:/p` | port 554 |
//! | `http://h/p`, `rtsps://h/p`, no scheme | `StreamUriScheme` |
//! | space or control char or non-ASCII in the authority, empty host, `h:1:2`, `[::1`, `[::1]x` | `StreamUriAuthority` |
//! | port `0`, `65536`, `abc`, `-1`, `+1`, more than 5 digits | `StreamUriPort` |
//! | path or query refused by `RtspPath` (`%`, `@`, `#`, dot segment, credential parameter, over 512 bytes) | `StreamUriPath` |
//! | a URI over 2048 bytes | `InvalidField` |

use std::num::NonZeroU16;

use wardenlens_core::camera::{DEFAULT_RTSP_PORT, RtspPath};

use crate::OnvifError;

/// Longest stream URI that is looked at, in bytes.
pub const MAX_STREAM_URI_LEN: usize = 2048;

/// Where a stream lives on the camera the caller configured.
///
/// There is deliberately no host: see the module documentation.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct StreamEndpoint {
    /// The RTSP path and query (`Debug` redacts it, see [`RtspPath`]).
    pub path: RtspPath,
    /// The RTSP port: the one in the URI, else 554.
    pub port: NonZeroU16,
}

/// Reduces a camera's stream URI to a [`StreamEndpoint`].
///
/// # Errors
/// The `StreamUri*` variants of [`OnvifError`], or `InvalidField` for an over-long URI.
pub fn reduce_stream_uri(uri: &str) -> Result<StreamEndpoint, OnvifError> {
    let uri = uri.trim();
    if uri.len() > MAX_STREAM_URI_LEN {
        return Err(OnvifError::InvalidField { field: "Uri" });
    }
    let rest = match uri.get(..7) {
        Some(head) if head.eq_ignore_ascii_case("rtsp://") => uri.get(7..).unwrap_or_default(),
        _ => return Err(OnvifError::StreamUriScheme),
    };
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at_checked(authority_end).unwrap_or((rest, ""));
    if !authority.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(OnvifError::StreamUriAuthority);
    }
    // Everything up to the last `@` is userinfo: dropped unread.
    let host_port = authority
        .rsplit_once('@')
        .map_or(authority, |(_userinfo, hp)| hp);
    let port = port_of(host_port)?;
    let path = match tail {
        "" => "/".to_owned(),
        t if t.starts_with('?') => format!("/{t}"),
        t => t.to_owned(),
    };
    let path = RtspPath::new(&path).map_err(OnvifError::StreamUriPath)?;
    Ok(StreamEndpoint { path, port })
}

/// The port of `host[:port]` or `[v6][:port]`; 554 when there is none.
fn port_of(host_port: &str) -> Result<NonZeroU16, OnvifError> {
    let port_text = if let Some(inner) = host_port.strip_prefix('[') {
        let (host, after) = inner
            .split_once(']')
            .ok_or(OnvifError::StreamUriAuthority)?;
        if host.is_empty() {
            return Err(OnvifError::StreamUriAuthority);
        }
        match after {
            "" => None,
            a => Some(a.strip_prefix(':').ok_or(OnvifError::StreamUriAuthority)?),
        }
    } else {
        let (host, port) = match host_port.split_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (host_port, None),
        };
        if host.is_empty() || port.is_some_and(|p| p.contains(':')) {
            return Err(OnvifError::StreamUriAuthority);
        }
        port
    };
    match port_text {
        None | Some("") => Ok(DEFAULT_RTSP_PORT),
        Some(p) => {
            if p.len() > 5 || !p.bytes().all(|b| b.is_ascii_digit()) {
                return Err(OnvifError::StreamUriPort);
            }
            p.parse::<u16>()
                .ok()
                .and_then(NonZeroU16::new)
                .ok_or(OnvifError::StreamUriPort)
        }
    }
}
