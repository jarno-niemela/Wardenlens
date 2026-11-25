//! Config errors. A message names the key (a `'static` string of this crate) and the reason. It
//! never contains the rejected value, an unknown key name or any other input text, and toml's own
//! messages are never forwarded because they quote the input (SEC-6).

use super::bind::BindError;

/// Why a listen address was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ListenProblem {
    /// Not an `ip:port` socket address (a hostname, a missing port, a named scope id, ...).
    NotSocketAddr,
    /// A well-formed address the LAN-only rule refuses.
    Bind(BindError),
}

/// Why a path was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PathProblem {
    /// Does not start with `/`.
    NotAbsolute,
    /// Empty or longer than 4096 bytes.
    BadLength,
    /// Contains a control character (including NUL).
    ControlChar,
    /// Contains a `.` or `..` component.
    DotComponent,
    /// Contains an empty component (`//`) or ends in `/`.
    NotCanonical,
    /// Is `/` itself.
    Root,
}

/// Which relation between two paths was violated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConflictKind {
    /// The two paths are equal.
    Same,
    /// The first path lies inside the second (or the other way round for the two roots).
    Nested,
}

/// Why a config was rejected.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ConfigError {
    /// The input exceeds the size cap.
    #[error("config is {len} bytes, more than the {max} byte limit")]
    TooLarge {
        /// Size of the input in bytes.
        len: usize,
        /// Maximum accepted size in bytes.
        max: usize,
    },
    /// Not valid TOML. Only the line is reported.
    #[error("config is not valid toml (line {})", line.map_or_else(|| "unknown".to_owned(), |l| l.to_string()))]
    Syntax {
        /// 1-based line, when known.
        line: Option<usize>,
    },
    /// A key this version does not know. The name is not echoed; the section is.
    #[error("unknown key in section [{section}]")]
    UnknownKey {
        /// The section holding it, `<root>` for the top level.
        section: &'static str,
    },
    /// A required key is absent.
    #[error("missing required key {key}")]
    Missing {
        /// Dotted key.
        key: &'static str,
    },
    /// The value has the wrong toml type.
    #[error("key {key} has the wrong type")]
    WrongType {
        /// Dotted key.
        key: &'static str,
    },
    /// An integer outside its range.
    #[error("key {key} is outside the range {min} to {max}")]
    OutOfRange {
        /// Dotted key.
        key: &'static str,
        /// Smallest accepted value.
        min: i64,
        /// Largest accepted value.
        max: i64,
    },
    /// `api.listen` is not acceptable.
    #[error("key api.listen rejected: {}", match reason {
        ListenProblem::NotSocketAddr => "not an ip:port socket address",
        ListenProblem::Bind(BindError::NotLan) => "not a loopback, private or link-local address",
        ListenProblem::Bind(BindError::UnspecifiedNotAllowed) => "unspecified address needs api.allow_unspecified_bind",
        ListenProblem::Bind(BindError::CgnatNotAllowed) => "100.64.0.0/10 needs api.allow_cgnat_bind",
        ListenProblem::Bind(BindError::PortZero) => "port 0 is not allowed",
    })]
    Listen {
        /// The reason.
        reason: ListenProblem,
    },
    /// A path key is not acceptable.
    #[error("key {key} rejected: {}", match reason {
        PathProblem::NotAbsolute => "path is not absolute",
        PathProblem::BadLength => "path is empty or too long",
        PathProblem::ControlChar => "path contains a control character",
        PathProblem::DotComponent => "path contains a . or .. component",
        PathProblem::NotCanonical => "path has an empty component or a trailing slash",
        PathProblem::Root => "path is the filesystem root",
    })]
    Path {
        /// Dotted key.
        key: &'static str,
        /// The reason.
        reason: PathProblem,
    },
    /// Two path keys collide.
    #[error("keys {key} and {other} {}", match reason {
        ConflictKind::Same => "must differ",
        ConflictKind::Nested => "must not lie inside one another",
    })]
    Conflict {
        /// Dotted key.
        key: &'static str,
        /// The other dotted key.
        other: &'static str,
        /// The reason.
        reason: ConflictKind,
    },
}
