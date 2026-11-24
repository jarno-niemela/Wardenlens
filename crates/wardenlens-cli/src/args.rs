//! Command-line grammar (clap 4 derive, ADR 0004 section 4).
//!
//! No value is ever an argument: `set` and `key import` read from stdin or a no-echo prompt
//! (ADR 0006 section 10).

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};
use wardenlens_core::entry::EntryKind;

/// Wardenlens command line.
#[derive(Debug, Parser)]
#[command(name = "wardenlens", version = wardenlens_core::VERSION, about)]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub(crate) command: Option<Command>,
}

/// Top-level commands.
#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    /// Manage the sensitive-data vault.
    #[command(subcommand)]
    Vault(VaultCommand),
}

/// `wardenlens vault ...`
#[derive(Debug, Subcommand)]
pub(crate) enum VaultCommand {
    /// Create the developer vault and its key at the fixed paths.
    Init,
    /// Store a value read from stdin or a no-echo prompt (never from arguments).
    ///
    /// On a terminal each field is a no-echo prompt. On a pipe the value is the whole of stdin
    /// minus its end: one trailing line ending (LF or CRLF) and, if that was present, one
    /// further blank line. A credential is exactly two lines, username then password (a
    /// username line alone is refused; an empty second line is an empty password); a third
    /// line is refused. Other line breaks inside a value are kept.
    Set(SetArgs),
    /// Write one value to stdout with no trailing text (pipe or terminal only).
    Get(GetArgs),
    /// List ids, kinds and the unscannable flag. Never values.
    List,
    /// Remove an entry.
    Rm {
        /// The entry id.
        id: String,
    },
    /// Rotate the key: re-seal every entry, then export the new key (terminal required).
    Rekey,
    /// Check a key file against the key rules without printing it.
    CheckKey {
        /// The key file; defaults to the configured key path.
        path: Option<PathBuf>,
    },
    /// Export or import the key as base64 (terminal required).
    #[command(subcommand)]
    Key(KeyCommand),
    /// Import the legacy `AgentDVR` secret file and camera inventory.
    ImportLegacy(LegacyArgs),
}

/// `wardenlens vault key ...`
#[derive(Debug, Subcommand)]
pub(crate) enum KeyCommand {
    /// Print the key as base64 for a password manager.
    Export,
    /// Read a base64 key from a no-echo prompt and create the key file.
    Import,
}

/// Arguments of `set`.
#[derive(Debug, Args)]
pub(crate) struct SetArgs {
    /// The entry id, for example `cam:reolink-1:host`.
    pub(crate) id: String,
    /// What the value is.
    #[arg(long, value_enum)]
    pub(crate) kind: KindArg,
}

/// Arguments of `get`.
#[derive(Debug, Args)]
pub(crate) struct GetArgs {
    /// The entry id.
    pub(crate) id: String,
    /// Which field of a credential entry to write.
    #[arg(long, value_enum)]
    pub(crate) field: Option<FieldArg>,
}

/// Arguments of `import-legacy`.
#[derive(Debug, Args)]
pub(crate) struct LegacyArgs {
    /// The `AgentDVR` secret JSON; defaults to `agentdvr-cameras.secret.json` in the config directory.
    #[arg(long)]
    pub(crate) secret_json: Option<PathBuf>,
    /// The camera inventory; defaults to `cameras.local.toml` in the config directory.
    #[arg(long)]
    pub(crate) inventory: Option<PathBuf>,
}

/// The `--kind` choices.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub(crate) enum KindArg {
    Credential,
    Secret,
    Host,
    Mac,
    Serial,
    DisplayName,
    Other,
}

impl From<KindArg> for EntryKind {
    fn from(k: KindArg) -> Self {
        match k {
            KindArg::Credential => Self::Credential,
            KindArg::Secret => Self::Secret,
            KindArg::Host => Self::Host,
            KindArg::Mac => Self::Mac,
            KindArg::Serial => Self::Serial,
            KindArg::DisplayName => Self::DisplayName,
            KindArg::Other => Self::Other,
        }
    }
}

/// The `--field` choices.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum FieldArg {
    Username,
    Password,
}
