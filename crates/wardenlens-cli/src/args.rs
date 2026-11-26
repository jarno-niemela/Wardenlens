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
    /// The service config file. Precedence: this flag, then `WARDENLENS_CONFIG` (ignored if
    /// empty), then `/etc/wardenlens/wardenlens.toml`. Not used by `vault`.
    #[arg(long, global = true, value_name = "PATH")]
    pub(crate) config: Option<PathBuf>,
    /// Log format on stderr, `text` by default. The level comes from `RUST_LOG` (default `info`). Not used by `vault`.
    #[arg(long, global = true, value_enum)]
    pub(crate) log_format: Option<LogFormat>,
    #[command(subcommand)]
    pub(crate) command: Option<Command>,
}

/// The `--log-format` choices.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum LogFormat {
    /// Human-readable lines.
    Text,
    /// One JSON object per line.
    Json,
}

/// Top-level commands.
#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    /// Manage the sensitive-data vault.
    #[command(subcommand)]
    Vault(VaultCommand),
    /// Inspect the service config file.
    #[command(subcommand)]
    Config(ConfigCommand),
    /// Import cameras from another system into the registry and the service vault.
    #[command(subcommand)]
    Import(ImportCommand),
    /// Manage the service key file named by `secrets.key_file` in the config.
    #[command(subcommand)]
    Secrets(SecretsCommand),
    /// Manage the API tokens in the index named by `database.path`.
    #[command(subcommand)]
    Token(TokenCommand),
}

/// `wardenlens token ...`
#[derive(Debug, Subcommand)]
pub(crate) enum TokenCommand {
    /// Create a token and print it once on stdout (`wl_<id>_<secret>`).
    ///
    /// Only its id, a SHA-256 of the secret, the name and the creation time are stored; the secret
    /// cannot be shown again. Never logged.
    Create {
        /// A label, 1 to 64 bytes, no control characters.
        #[arg(long)]
        name: String,
    },
    /// List the tokens: id, name, created, last used, revoked. Never a secret or a hash.
    List,
    /// Revoke a token by id. The row stays (the id is never reused); the token stops working.
    /// Exits 1 for an unknown id.
    Revoke {
        /// The 8-character token id (shown by `create` and `list`).
        id: String,
    },
}

/// `wardenlens import ...`
#[derive(Debug, Subcommand)]
pub(crate) enum ImportCommand {
    /// Import the cameras of an `AgentDVR` `objects.xml`.
    ///
    /// Each camera is registered in the index named by `database.path`; its host, display name
    /// and login are sealed into the vault next to it with the key file `secrets.key_file`. Prints
    /// id, host, path and status per camera, never a login. Re-running updates the same ids.
    /// Refuses a file over 8 MiB and warns if it is world-readable (the file is never changed).
    Agentdvr {
        /// The `objects.xml` to read.
        file: PathBuf,
        /// Parse and print what would be done; write nothing (the key file is not read).
        #[arg(long)]
        dry_run: bool,
    },
}

/// `wardenlens secrets ...`
#[derive(Debug, Subcommand)]
pub(crate) enum SecretsCommand {
    /// Create the key file named by `secrets.key_file` from the OS random generator, mode 0600.
    /// An existing file is never overwritten.
    Init,
}

/// `wardenlens config ...`
#[derive(Debug, Subcommand)]
pub(crate) enum ConfigCommand {
    /// Read and validate the config file, then print what it sets (paths and floors, never the
    /// contents of the key file). Exits 0 if valid, 1 if the config is invalid, 2 if the file cannot be read, stdout cannot be written or the arguments are wrong.
    Check,
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
    /// Scan files, directories, the staged changes or a pushed range for any vault value. Exits 1 on a hit, 2 if the scan could not run.
    ///
    /// A hit is printed as `entry-id kind path:line`; the value, the matching text and the line
    /// are never printed, and a path that contains a hit is replaced by `<redacted-path:N>`.
    /// Binary files are skipped with a notice; a file over 8 MiB, an unreadable file and a
    /// vault or key that cannot be used all make the scan fail (exit 2).
    Scan(ScanArgs),
}

/// Arguments of `scan`: files and directories, or one git source.
#[derive(Debug, Default, Args)]
pub(crate) struct ScanArgs {
    /// Files and directories to scan; a directory is walked, symlinks inside it are skipped.
    #[arg(
        value_name = "PATH",
        required_unless_present_any = ["staged", "range"],
        conflicts_with_all = ["staged", "range"]
    )]
    pub(crate) paths: Vec<PathBuf>,
    /// Scan what the next commit would hold: the staged blobs (read from the index, not the
    /// working tree), their paths included. Binary blobs are scanned too.
    #[arg(long, conflicts_with = "range")]
    pub(crate) staged: bool,
    /// Scan what pushing `B` over `A` would publish: the blobs and commits that are new, every
    /// path of the new commits and the raw commit and tag objects. `A` may be empty or all zeros
    /// (a new branch).
    #[arg(long, value_name = "A..B")]
    pub(crate) range: Option<String>,
    /// With `--range`: also treat what this remote's tracking refs hold as already published.
    #[arg(long, value_name = "REMOTE", requires = "range", conflicts_with_all = ["staged", "paths"])]
    pub(crate) remote: Option<String>,
    /// With `--range`: a ref name that the push publishes; the name is scanned and reported
    /// as `ref:<index>` (its position among the `--ref` options). May be repeated.
    #[arg(long = "ref", value_name = "NAME", requires = "range", conflicts_with_all = ["staged", "paths"])]
    pub(crate) refs: Vec<String>,
    /// Use the fixed default vault and key paths and ignore `WARDENLENS_VAULT` and
    /// `WARDENLENS_VAULT_KEY_FILE` (the git hooks pass this).
    #[arg(long)]
    pub(crate) default_paths: bool,
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
