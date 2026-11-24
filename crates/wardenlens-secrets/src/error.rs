//! The crate error type. Messages name the rule that failed and never carry secret material.

use crate::record::RecordKind;

/// Every failure this crate can report.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SecretsError {
    /// The key file path is a symbolic link.
    #[error("key file is a symbolic link")]
    KeyFileSymlink,
    /// The key file is not a regular file.
    #[error("key file is not a regular file")]
    KeyFileNotRegular,
    /// The key file is owned by another user.
    #[error("key file is not owned by the current user")]
    KeyFileWrongOwner,
    /// The key file grants access to group or others.
    #[error("key file is accessible by group or others (mode must have no 0o077 bits)")]
    KeyFilePermissions,
    /// The key file is not exactly 32 bytes.
    #[error("key file is not exactly 32 bytes")]
    KeyFileWrongLength,
    /// The key file lives inside a git work tree.
    #[error("key file is inside a git work tree")]
    KeyFileInWorkTree,
    /// The key file already exists and is never overwritten.
    #[error("key file already exists")]
    KeyFileExists,
    /// The key file path has no usable parent directory.
    #[error("key file path has no parent directory")]
    KeyFileNoParent,
    /// A filesystem operation failed.
    #[error("key file i/o failed during {operation}")]
    Io {
        /// Which step failed.
        operation: &'static str,
        /// The underlying error (carries no key material).
        #[source]
        source: std::io::Error,
    },
    /// The operating-system random number generator failed.
    #[error("operating-system random number generator failed")]
    Random,
    /// The text form of a key is not valid base64 of exactly 32 bytes.
    #[error("key text is not base64 of exactly 32 bytes")]
    InvalidKeyEncoding,
    /// The entry id is empty, too long or has characters outside `[a-z0-9:_.-]`.
    #[error("entry id is invalid")]
    InvalidId,
    /// A value or record exceeds the size limits.
    #[error("value exceeds the size limit")]
    TooLarge,
    /// The cipher failed to encrypt (not expected for inputs within the size limits).
    #[error("encryption failed")]
    Encrypt,
    /// The record is shorter than version, nonce and tag.
    #[error("record is truncated")]
    Truncated,
    /// The record carries a version this build does not know.
    #[error("unsupported record version {0}")]
    UnsupportedVersion(u8),
    /// Authentication failed: tampering, wrong key, or wrong kind or entry id.
    #[error("authentication failed (tampered record, wrong key, kind or entry id)")]
    Authentication,
    /// The decrypted plaintext does not have the layout of the requested kind.
    #[error("decrypted value is malformed for kind {0:?}")]
    MalformedPlaintext(RecordKind),
}
