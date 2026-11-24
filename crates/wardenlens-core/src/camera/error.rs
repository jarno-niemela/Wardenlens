//! Errors of the camera model. None of them carries the rejected input (SEC-6).

/// Why a camera value was refused. The message names the rule, never the input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum CameraError {
    /// The camera id is empty.
    #[error("camera id is empty")]
    IdEmpty,
    /// The camera id is longer than 32 bytes.
    #[error("camera id is longer than 32 bytes")]
    IdTooLong,
    /// The camera id does not match `[a-z][a-z0-9-]*`.
    #[error("camera id must match [a-z][a-z0-9-]*")]
    IdCharset,
    /// The host is empty.
    #[error("host is empty")]
    HostEmpty,
    /// The host is longer than 253 bytes.
    #[error("host is longer than 253 bytes")]
    HostTooLong,
    /// The host is not an IPv4 address, an IPv6 address or an ASCII DNS name.
    #[error("host is not an IPv4 address, an IPv6 address or a plain ASCII DNS name")]
    HostSyntax,
    /// A DNS label is empty or longer than 63 bytes.
    #[error("host has an empty or over-long DNS label")]
    HostLabel,
    /// The path is empty or does not start with a single `/`.
    #[error("RTSP path must start with a single '/'")]
    PathStart,
    /// The path is longer than 512 bytes.
    #[error("RTSP path is longer than 512 bytes")]
    PathTooLong,
    /// The path has a character outside the allowed printable ASCII set.
    #[error("RTSP path has a disallowed character")]
    PathCharset,
    /// The path has a `.` or `..` segment.
    #[error("RTSP path has a dot segment")]
    PathDotSegment,
    /// The query string has a parameter that can carry a credential.
    #[error("RTSP path has a credential-bearing query parameter")]
    PathCredentialParam,
    /// The display name is empty or longer than 128 bytes.
    #[error("display name must be 1 to 128 bytes")]
    NameLength,
    /// The display name has a control, invisible or non-space whitespace character, or edge spaces.
    #[error("display name has a disallowed character")]
    NameCharset,
    /// The camera has no stream for the requested role.
    #[error("camera has no stream for that role")]
    NoSuchStream,
}
