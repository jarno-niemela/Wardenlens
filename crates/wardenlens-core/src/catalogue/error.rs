//! Catalogue errors. Messages never echo the offending value, so a rejected line of site data
//! is not copied into CI logs (ERR-5).

use std::fmt;

/// The kind of site-specific data found in a catalogue string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SiteDataKind {
    /// A dotted-quad IPv4 address (private or public).
    Ipv4,
    /// An IPv6 address.
    Ipv6,
    /// A MAC address: six hex pairs with separators, or three dotted hex quads.
    Mac,
    /// A serial-number-like token.
    Serial,
    /// A URL or `user:pass@host` string carrying credentials.
    Credentials,
    /// An email address.
    Email,
    /// A private-network hostname such as `*.lan`.
    Hostname,
    /// A character outside the allow-list (ASCII without controls, plus alphabetic letters), such
    /// as invisible, fullwidth or non-ASCII digit characters that can disguise other site data.
    Encoding,
}

impl SiteDataKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Ipv4 => "ipv4 address",
            Self::Ipv6 => "ipv6 address",
            Self::Mac => "mac address",
            Self::Serial => "serial-like value",
            Self::Credentials => "credentials in a url",
            Self::Email => "email address",
            Self::Hostname => "private hostname",
            Self::Encoding => "disguising character encoding",
        }
    }
}

/// Why a catalogue entry was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CatalogueError {
    /// The input exceeds the size cap.
    TooLarge {
        /// Size of the input in bytes.
        len: usize,
        /// Maximum accepted size in bytes.
        max: usize,
    },
    /// The input is not valid TOML or does not match the entry schema. Only the line is
    /// reported: the parser's own message can quote the rejected value.
    Parse {
        /// 1-based line of the problem, when known.
        line: Option<usize>,
    },
    /// A required field is empty or an evidence list is missing.
    Missing(&'static str),
    /// A field has the wrong shape.
    Malformed(&'static str),
    /// A numeric field is outside its accepted range.
    OutOfRange(&'static str),
    /// A string field contains site-specific data.
    SiteData {
        /// Which field held it, e.g. `quirks[2]`.
        field: String,
        /// What it looked like.
        kind: SiteDataKind,
    },
}

impl fmt::Display for CatalogueError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge { len, max } => {
                write!(f, "catalogue entry is {len} bytes, the limit is {max}")
            }
            Self::Parse { line: Some(line) } => write!(f, "invalid catalogue entry at line {line}"),
            Self::Parse { line: None } => write!(f, "invalid catalogue entry"),
            Self::Malformed(what) => write!(f, "catalogue field {what} is malformed"),
            Self::Missing(what) => write!(f, "catalogue entry is missing {what}"),
            Self::OutOfRange(what) => write!(f, "catalogue field {what} is out of range"),
            Self::SiteData { field, kind } => {
                write!(f, "site data ({}) in field {field}", kind.as_str())
            }
        }
    }
}

impl std::error::Error for CatalogueError {}
