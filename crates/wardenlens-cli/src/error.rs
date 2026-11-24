//! The CLI error type. Messages carry ids, kinds and rule names only, never values (SEC-6).

use wardenlens_secrets::SecretsError;
use wardenlens_vault::VaultError;
use wardenlens_vault::legacy::LegacyError;

/// Why a command failed.
#[derive(Debug, thiserror::Error)]
pub(crate) enum CliError {
    /// A rule of ADR 0006 refused the request; the text names the rule.
    #[error("{0}")]
    Refused(&'static str),
    /// The key does not open the vault and a rekey may be pending (exit 2).
    #[error("{0}")]
    KeyMismatch(&'static str),
    /// A refusal that names an id or a path (never a value).
    #[error("{0}")]
    RefusedWith(String),
    /// No entry has this id.
    #[error("no entry with id {0}")]
    NoEntry(String),
    /// The vault library refused.
    #[error(transparent)]
    Vault(#[from] VaultError),
    /// The key file was refused.
    #[error("key file: {0}")]
    Key(#[from] SecretsError),
    /// A legacy file could not be mapped.
    #[error("legacy import: {0}")]
    Legacy(#[from] LegacyError),
    /// An I/O failure; `op` names the step, never a value.
    #[error("i/o failed during {op}: {source}")]
    Io {
        op: &'static str,
        #[source]
        source: std::io::Error,
    },
}

impl CliError {
    pub(crate) fn io(op: &'static str) -> impl FnOnce(std::io::Error) -> Self {
        move |source| Self::Io { op, source }
    }

    /// Exit code: 2 when the vault or its key cannot be used (ADR 0006 section 8), else 1.
    pub(crate) fn exit_code(&self) -> u8 {
        match self {
            Self::Key(_)
            | Self::KeyMismatch(_)
            | Self::Vault(
                VaultError::WrongKey
                | VaultError::NotFound
                | VaultError::NotInitialized
                | VaultError::CorruptEntry { .. },
            ) => 2,
            _ => 1,
        }
    }
}
