//! Command-line grammar (clap 4 derive, ADR 0004 section 4).
//!
//! No value is ever an argument: `set` and `key import` read from stdin or a no-echo prompt
//! (ADR 0006 section 10).

use std::net::Ipv4Addr;
use std::num::NonZeroU16;
use std::path::PathBuf;
use std::time::Duration;

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
    /// Run the service: record every registered camera, run the storage loop and serve the API
    /// on `api.listen`. Stops on SIGTERM or SIGINT after flushing the open segments (exit 0).
    ///
    /// Refuses to start (exit 2) when the config, the key file, the index or the hot root cannot
    /// be used, or when another instance holds the process lock (`wardenlens.lock` next to the index) or the lock inside the hot root. A missing, read-only or same-filesystem
    /// archive is not a refusal: the service starts in `archive_unavailable` mode.
    Serve,
    /// Probe a running service: `GET /api/v1/health` on the `api.listen` address of the config
    /// (an unspecified address is probed on loopback), 3 s timeout. Exits 0 when the service answers
    /// 200, 1 otherwise. For the container healthcheck; needs no token and prints nothing on success.
    Health,
    /// Find, add, list and remove cameras.
    #[command(subcommand)]
    Camera(CameraCommand),
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
    /// Import the cameras of an `AgentDVR` `objects.json` or `objects.xml`.
    ///
    /// The format is detected from the content (a file that starts with `{` is JSON), or forced
    /// with `--format`. Both formats map the same fields and share every rule. Without a file,
    /// the first of `/opt/AgentDVR/Media/XML/objects.json` and `.../objects.xml` that exists is
    /// read (the numbered `.bak` copies are never used).
    ///
    /// The JSON layout (a `cameras` array with nested `settings`, mirroring the XML) is an
    /// assumption not checked against a real file: a camera that does not fit is skipped and
    /// said so, never guessed.
    ///
    /// Each camera is registered in the index named by `database.path`; its host, display name
    /// and login are sealed into the vault next to it with the key file `secrets.key_file`. Prints
    /// id, host, path and status per camera, never a login. Re-running updates the same ids.
    /// Refuses a file over 8 MiB and warns if it is world-readable (the file is never changed).
    ///
    /// A camera is registered under the catalogue model that lists its path: a source path with a
    /// query string is imported only when the catalogue lists exactly that path for the model
    /// (`--camera-model`, `--model`, or the one catalogue model that lists the path); any other
    /// query is skipped. A path that several models list is skipped, never guessed. Cameras
    /// removed from the file are not removed from the registry or the vault (use
    /// `wardenlens camera remove`).
    ///
    /// The `agentdvr-` id prefix is reserved for this command (`camera add` refuses it). An install that
    /// hand-added `agentdvr-*` cameras before this release should remove or rename them before
    /// importing: the registry cannot tell them from imported ones, and a re-import replaces their
    /// host, name, login and main path.
    Agentdvr {
        /// The `objects.json` or `objects.xml` to read (default: the first of the usual install
        /// paths that exists).
        file: Option<PathBuf>,
        /// The file format; `auto` detects it from the content.
        #[arg(long, value_enum, default_value_t = FormatArg::Auto)]
        format: FormatArg,
        /// Register every camera of the file under this catalogue model (`<vendor>/<model>`, as in
        /// cameras/README.md). A camera named by `--camera-model` keeps its own model.
        #[arg(long, value_name = "VENDOR/MODEL")]
        model: Option<String>,
        /// Register one camera under a catalogue model: `<camera id>=<vendor>/<model>`, for
        /// example `agentdvr-3=vendor/model`. Repeatable.
        #[arg(long, value_name = "ID=VENDOR/MODEL")]
        camera_model: Vec<String>,
        /// Parse and print what would be done; write nothing (the key file is not read, the index is
        /// only read).
        #[arg(long)]
        dry_run: bool,
    },
}

/// The `--format` choices of `import agentdvr`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum FormatArg {
    /// Detect from the content.
    Auto,
    /// `objects.xml`.
    Xml,
    /// `objects.json`.
    Json,
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
    /// Rename a camera: move every `cam:<from>:*` entry to `cam:<to>:*` in one transaction.
    ///
    /// Refuses if the source has no entry or any target entry exists; nothing is overwritten.
    /// Use it to turn `import-json-N` into an inventory id. Prints ids, never values.
    Mv {
        /// The camera id to move from, for example `import-json-1`.
        from: String,
        /// The camera id to move to, for example an inventory id.
        to: String,
    },
    /// Scan files, directories, the staged changes or a pushed range for any vault value. Exits 1 on a hit, 2 if the scan could not run.
    ///
    /// A hit is printed as `entry-id kind path:line`; the value, the matching text and the line
    /// are never printed, and a path that contains a hit is replaced by `<redacted-path:N>`.
    /// Binary files are skipped with a notice; a file over 8 MiB, an unreadable file and a
    /// vault or key that cannot be used all make the scan fail (exit 2).
    Scan(ScanArgs),
    /// Copy stdin to stdout, replacing every vault value with `[REDACTED]` (a filter for logs).
    ///
    /// Exact match against the values in the vault: a credential's password and its
    /// `user:password@` URL prefix, hosts, MAC addresses, secrets and so on, in the raw, percent,
    /// base64, hex and XML renderings the leak scan knows. An IPv4, IPv6 or MAC address is found
    /// in any spelling the scan recognises (zero-padded, dashed, compressed, mapped, unpadded).
    /// Matching ignores ASCII case only. The input is not squeezed (zero-width and fullwidth
    /// characters and runs of white space are not normalised) and the decoded, JSON-unescaped and
    /// line-split views are not replaced; `vault scan` finds all of these. Streams in bounded
    /// chunks and finds a value split across two reads. Overlapping or touching matches become
    /// one marker, which reveals no length. Other bytes, binary included, are copied unchanged.
    /// An entry that is too short to match safely is listed on stderr and its value is not
    /// replaced. Fails closed: if the vault or key cannot be used nothing is written and the exit
    /// code is 2; an input or output error exits 1 (bytes already written were redacted). Like
    /// `scan`, it tells whoever feeds it text whether a guess occurs in the vault.
    Redact,
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
    /// Joins a JSON camera to an inventory id by hand: `--map <json-index>=<id>`, repeatable. Indexes count from 1 (the N of `import-json-N`).
    ///
    /// Without it each camera is matched by its display name against the inventory id, vendor and
    /// model (case-insensitive, whole words); a camera with no match or several equal matches is
    /// refused, never guessed.
    #[arg(long = "map", value_name = "INDEX=ID")]
    pub(crate) map: Vec<String>,
    /// Show which inventory id each JSON camera maps to and what would be imported, and write nothing.
    #[arg(long)]
    pub(crate) dry_run: bool,
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

/// `wardenlens camera ...`
#[derive(Debug, Subcommand)]
pub(crate) enum CameraCommand {
    /// Probe the LAN with WS-Discovery (multicast) and list the ONVIF devices that answer.
    ///
    /// Everything shown is an unauthenticated suggestion from the network: every address of a
    /// device is listed, a device whose addresses name different hosts is flagged, nothing is
    /// ever picked for you, and nothing is fetched. Addresses already registered, this machine's
    /// own addresses and text from the network are marked or escaped.
    Discover(DiscoverArgs),
    /// Register a camera: ask it over ONVIF for its main and sub stream paths (falling back to
    /// the catalogue paths when ONVIF is unreachable) and store it with sealed credentials.
    ///
    /// The password is read from stdin (one line) or a no-echo prompt, never from an argument.
    /// Refuses this machine's own addresses and 169.254.169.254 before any request is made.
    Add(AddArgs),
    /// List the registered cameras: id, model and host. Never a login.
    List,
    /// Remove a camera from the registry and its entries from the vault. Recordings are kept.
    Remove {
        /// The camera id.
        id: String,
    },
}

/// Arguments of `camera discover`.
#[derive(Debug, Args)]
pub(crate) struct DiscoverArgs {
    /// How long to listen for answers (`3s`, `1500ms`, or plain seconds); at most 10 s are used.
    #[arg(long, default_value = "3s", value_parser = parse_timeout, value_name = "DURATION")]
    pub(crate) timeout: Duration,
    /// The IPv4 address of the interface to probe from; the default lets the OS choose.
    #[arg(long, default_value = "0.0.0.0", value_name = "IPV4")]
    pub(crate) interface: Ipv4Addr,
}

/// Arguments of `camera add`.
#[derive(Debug, Args)]
pub(crate) struct AddArgs {
    /// The camera id: a lowercase slug, at most 32 bytes (`front-door`).
    #[arg(long)]
    pub(crate) id: String,
    /// The camera's IP address or DNS name. Never taken from a discovery result for you.
    #[arg(long)]
    pub(crate) host: String,
    /// The catalogue entry, `<vendor>/<model>` as slugs (see `cameras/README.md`).
    #[arg(long, value_name = "VENDOR/MODEL")]
    pub(crate) model: String,
    /// The camera login's user name. The password is read from stdin or a prompt.
    #[arg(long)]
    pub(crate) username: String,
    /// The ONVIF HTTP port; defaults to the catalogue's, else 80.
    #[arg(long, value_name = "PORT")]
    pub(crate) onvif_port: Option<NonZeroU16>,
    /// A display name; defaults to the id.
    #[arg(long)]
    pub(crate) name: Option<String>,
}

/// Parses `3s`, `1500ms` or `3` (seconds): a positive duration.
fn parse_timeout(text: &str) -> Result<Duration, String> {
    let (digits, unit_ms) = match text.strip_suffix("ms") {
        Some(d) => (d, 1_u64),
        None => (text.strip_suffix('s').unwrap_or(text), 1000),
    };
    if digits.is_empty() || digits.len() > 9 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err("not a duration".to_owned());
    }
    let n: u64 = digits.parse().map_err(|_| "not a duration".to_owned())?;
    if n == 0 {
        return Err("must be above zero".to_owned());
    }
    Ok(Duration::from_millis(n.saturating_mul(unit_ms)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timeouts_parse_by_the_table() {
        let ok = [
            ("3s", 3000),
            ("3", 3000),
            ("1500ms", 1500),
            ("1ms", 1),
            ("10s", 10_000),
        ];
        for (text, ms) in ok {
            assert_eq!(parse_timeout(text), Ok(Duration::from_millis(ms)), "{text}");
        }
        for bad in [
            "",
            "s",
            "ms",
            "0",
            "0s",
            "0ms",
            "-1s",
            "+1s",
            "1.5s",
            " 1s",
            "1 s",
            "1m",
            "1S",
            "1e3",
            "9999999999s",
            "\u{0663}s",
        ] {
            assert!(parse_timeout(bad).is_err(), "{bad:?}");
        }
    }
}
