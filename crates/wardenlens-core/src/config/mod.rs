//! The static service config (`wardenlens.toml`), parsed from a string and validated (#47).
//!
//! Parsing is pure: reading the file is the CLI's job. The parser walks a generic toml table
//! instead of deriving `Deserialize`, because serde's and toml's error messages quote the input,
//! and a config can sit next to secrets (SEC-6). Every error is a [`ConfigError`] built from
//! `'static` key names and reason codes only.
//!
//! # Keys
//! | key | default | rule |
//! |---|---|---|
//! | `api.listen` | required | LAN-only, see [`bind`] |
//! | `api.allow_unspecified_bind` | `false` | permits `0.0.0.0`, `::`, `::ffff:0.0.0.0` |
//! | `api.allow_cgnat_bind` | `false` | permits `100.64.0.0/10` |
//! | `storage.hot_root`, `storage.archive_root` | required | absolute, canonical, not nested |
//! | `storage.hot_min_free_percent`, `storage.archive_min_free_percent` | 25 | 0-90 |
//! | `storage.hot_max_age` | 43200 | seconds, 60-604800 |
//! | `storage.max_actions_per_tick` | 64 | 1-1024 |
//! | `recording.segment_target_secs` | 60 | 10-290 |
//! | `database.path`, `secrets.key_file` | required | absolute, canonical, outside both roots |
//!
//! # Docker
//! On Docker's default bridge network the process must listen on all container interfaces, so the
//! container config sets `api.listen = "0.0.0.0:<port>"` together with
//! `api.allow_unspecified_bind = true`, and the compose file publishes the port to one host LAN
//! address. With `network_mode: host` use a specific LAN address and leave the flag `false`.
//!
//! # Paths
//! A path is accepted only in one canonical lexical form: it starts with `/`, has no empty
//! component (`//`), no trailing slash, no `.` or `..` component, no control or invisible character (`char::is_control` or [`crate::text::is_invisible`], the
//! one rule shared with the vault and the display names; so a printed path cannot be spoofed
//! with a bidi override or a separator) and is at
//! most 4096 bytes. Refusing instead of normalising means the nesting check below cannot be
//! fooled by `/srv/a/../b`. The comparison is lexical (core does no I/O), so symlinks and bind
//! mounts are not resolved here; the storage adapter must check the real volumes at startup.
//! `database.path` and `secrets.key_file` must not equal or lie inside either recording root,
//! because the planner moves and deletes files under the roots and a database or key there would
//! be exposed to that.

pub mod bind;
mod error;
mod paths;

#[cfg(test)]
mod tests;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use toml::{Table, Value};

use crate::recording::SegmentConfig;
use crate::storage::{MinFreePercent, Policy};
use crate::time::DurationMs;

pub use bind::{BindClass, BindError};
pub use error::{ConfigError, ConflictKind, ListenProblem, PathProblem};

/// Largest accepted config, bytes (SEC-2). Checked before parsing.
pub const MAX_CONFIG_BYTES: usize = 64 * 1024;

/// Smallest `storage.hot_max_age`, seconds.
pub const MIN_HOT_MAX_AGE_SECS: i64 = 60;
/// Largest `storage.hot_max_age`, seconds (7 days).
pub const MAX_HOT_MAX_AGE_SECS: i64 = 7 * 24 * 3600;
/// Default `storage.hot_max_age`, seconds (12 h, ADR 0005).
pub const DEFAULT_HOT_MAX_AGE_SECS: i64 = 12 * 3600;
/// Smallest `storage.max_actions_per_tick`.
pub const MIN_ACTIONS_PER_TICK: i64 = 1;
/// Largest `storage.max_actions_per_tick`.
pub const MAX_ACTIONS_PER_TICK: i64 = 1024;
/// Default `storage.max_actions_per_tick` (ADR 0005).
pub const DEFAULT_ACTIONS_PER_TICK: u32 = 64;
/// Default `recording.segment_target_secs` (ADR 0005).
pub const DEFAULT_SEGMENT_TARGET_SECS: u32 = 60;

/// A validated service config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    listen: SocketAddr,
    allow_unspecified_bind: bool,
    allow_cgnat_bind: bool,
    hot_root: PathBuf,
    archive_root: PathBuf,
    hot_min_free: MinFreePercent,
    archive_min_free: MinFreePercent,
    hot_max_age_secs: u32,
    max_actions_per_tick: u32,
    segment_target_secs: u32,
    database_path: PathBuf,
    key_file: PathBuf,
}

impl Config {
    /// Parses and validates a config.
    ///
    /// # Errors
    /// [`ConfigError`]; see its variants. Nothing in the error repeats input text.
    pub fn from_toml_str(text: &str) -> Result<Self, ConfigError> {
        if text.len() > MAX_CONFIG_BYTES {
            return Err(ConfigError::TooLarge {
                len: text.len(),
                max: MAX_CONFIG_BYTES,
            });
        }
        let root = parse_table(text)?;
        let [api, storage, recording, database, secrets] = sections(&root)?;
        let allow_unspecified_bind =
            boolean(api, "allow_unspecified_bind", "api.allow_unspecified_bind")?;
        let allow_cgnat_bind = boolean(api, "allow_cgnat_bind", "api.allow_cgnat_bind")?;
        let listen = listen(api, allow_unspecified_bind, allow_cgnat_bind)?;

        let hot_root = path(storage, "hot_root", "storage.hot_root")?;
        let archive_root = path(storage, "archive_root", "storage.archive_root")?;
        let database_path = path(database, "path", "database.path")?;
        let key_file = path(secrets, "key_file", "secrets.key_file")?;
        check_layout(&hot_root, &archive_root, &database_path, &key_file)?;

        let hot_min_free = min_free(
            storage,
            "hot_min_free_percent",
            "storage.hot_min_free_percent",
        )?;
        let archive_min_free = min_free(
            storage,
            "archive_min_free_percent",
            "storage.archive_min_free_percent",
        )?;
        let hot_max_age_secs = ranged(
            storage,
            "hot_max_age",
            "storage.hot_max_age",
            MIN_HOT_MAX_AGE_SECS,
            MAX_HOT_MAX_AGE_SECS,
            DEFAULT_HOT_MAX_AGE_SECS,
        )?;
        let max_actions_per_tick = ranged(
            storage,
            "max_actions_per_tick",
            "storage.max_actions_per_tick",
            MIN_ACTIONS_PER_TICK,
            MAX_ACTIONS_PER_TICK,
            i64::from(DEFAULT_ACTIONS_PER_TICK),
        )?;
        let segment_target_secs = ranged(
            recording,
            "segment_target_secs",
            "recording.segment_target_secs",
            i64::from(SegmentConfig::MIN_TARGET_SECS),
            i64::from(SegmentConfig::MAX_TARGET_SECS),
            i64::from(DEFAULT_SEGMENT_TARGET_SECS),
        )?;

        Ok(Self {
            listen,
            allow_unspecified_bind,
            allow_cgnat_bind,
            hot_root,
            archive_root,
            hot_min_free,
            archive_min_free,
            hot_max_age_secs,
            max_actions_per_tick,
            segment_target_secs,
            database_path,
            key_file,
        })
    }

    /// The address the API listens on; already checked by [`bind::check_bind`].
    #[must_use]
    pub const fn listen(&self) -> SocketAddr {
        self.listen
    }

    /// Whether `api.allow_unspecified_bind` is set.
    #[must_use]
    pub const fn allow_unspecified_bind(&self) -> bool {
        self.allow_unspecified_bind
    }

    /// Whether `api.allow_cgnat_bind` is set.
    #[must_use]
    pub const fn allow_cgnat_bind(&self) -> bool {
        self.allow_cgnat_bind
    }

    /// Root of the hot volume.
    #[must_use]
    pub fn hot_root(&self) -> &Path {
        &self.hot_root
    }

    /// Root of the archive volume.
    #[must_use]
    pub fn archive_root(&self) -> &Path {
        &self.archive_root
    }

    /// Path of the index database.
    #[must_use]
    pub fn database_path(&self) -> &Path {
        &self.database_path
    }

    /// Path of the secrets key file.
    #[must_use]
    pub fn key_file(&self) -> &Path {
        &self.key_file
    }

    /// Segment target, seconds, within the segmenter's accepted range.
    #[must_use]
    pub const fn segment_target_secs(&self) -> u32 {
        self.segment_target_secs
    }

    /// At most this many actions run per storage tick.
    #[must_use]
    pub const fn max_actions_per_tick(&self) -> u32 {
        self.max_actions_per_tick
    }

    /// The planner policy: both floors and the hot max age; the emergency reserve keeps its
    /// default.
    #[must_use]
    pub fn storage_policy(&self) -> Policy {
        Policy {
            hot_min_free: self.hot_min_free,
            archive_min_free: self.archive_min_free,
            hot_max_age: DurationMs::from_secs(u64::from(self.hot_max_age_secs)),
            ..Policy::default()
        }
    }
}

fn reject_unknown(table: &Table, known: &[&str], section: &'static str) -> Result<(), ConfigError> {
    if table.keys().all(|k| known.contains(&k.as_str())) {
        Ok(())
    } else {
        Err(ConfigError::UnknownKey { section })
    }
}

fn parse_table(text: &str) -> Result<Table, ConfigError> {
    text.parse().map_err(|e: toml::de::Error| {
        let line = e.span().map(|span| {
            let upto = text.get(..span.start).unwrap_or_default();
            upto.bytes()
                .filter(|b| *b == b'\n')
                .count()
                .saturating_add(1)
        });
        ConfigError::Syntax { line }
    })
}

/// The five sections, after refusing unknown keys at the top level and inside each section.
fn sections(root: &Table) -> Result<[&Table; 5], ConfigError> {
    reject_unknown(
        root,
        &["api", "storage", "recording", "database", "secrets"],
        "<root>",
    )?;
    let api = section(root, "api")?;
    let storage = section(root, "storage")?;
    let recording = section(root, "recording")?;
    let database = section(root, "database")?;
    let secrets = section(root, "secrets")?;
    reject_unknown(
        api,
        &["listen", "allow_unspecified_bind", "allow_cgnat_bind"],
        "api",
    )?;
    reject_unknown(
        storage,
        &[
            "hot_root",
            "archive_root",
            "hot_min_free_percent",
            "archive_min_free_percent",
            "hot_max_age",
            "max_actions_per_tick",
        ],
        "storage",
    )?;
    reject_unknown(recording, &["segment_target_secs"], "recording")?;
    reject_unknown(database, &["path"], "database")?;
    reject_unknown(secrets, &["key_file"], "secrets")?;
    Ok([api, storage, recording, database, secrets])
}

/// A section table; an absent section is empty so its own missing keys are reported by name.
fn section<'a>(parent: &'a Table, name: &'static str) -> Result<&'a Table, ConfigError> {
    static EMPTY: std::sync::LazyLock<Table> = std::sync::LazyLock::new(Table::new);
    match parent.get(name) {
        None => Ok(&EMPTY),
        Some(Value::Table(t)) => Ok(t),
        Some(_) => Err(ConfigError::WrongType { key: name }),
    }
}

fn boolean(t: &Table, name: &str, key: &'static str) -> Result<bool, ConfigError> {
    match t.get(name) {
        None => Ok(false),
        Some(Value::Boolean(b)) => Ok(*b),
        Some(_) => Err(ConfigError::WrongType { key }),
    }
}

fn required_str<'a>(t: &'a Table, name: &str, key: &'static str) -> Result<&'a str, ConfigError> {
    match t.get(name) {
        None => Err(ConfigError::Missing { key }),
        Some(Value::String(s)) => Ok(s),
        Some(_) => Err(ConfigError::WrongType { key }),
    }
}

fn listen(t: &Table, unspec: bool, cgnat: bool) -> Result<SocketAddr, ConfigError> {
    let text = required_str(t, "listen", "api.listen")?;
    let addr: SocketAddr = text.parse().map_err(|_| ConfigError::Listen {
        reason: ListenProblem::NotSocketAddr,
    })?;
    bind::check_bind(addr, unspec, cgnat).map_err(|e| ConfigError::Listen {
        reason: ListenProblem::Bind(e),
    })?;
    Ok(addr)
}

fn path(t: &Table, name: &str, key: &'static str) -> Result<PathBuf, ConfigError> {
    let text = required_str(t, name, key)?;
    paths::validate(text).map_err(|reason| ConfigError::Path { key, reason })?;
    Ok(PathBuf::from(text))
}

/// Integer in `min..=max`, or `default` when absent. The result is within `u32` because every
/// caller's range is.
fn ranged(
    t: &Table,
    name: &str,
    key: &'static str,
    min: i64,
    max: i64,
    default: i64,
) -> Result<u32, ConfigError> {
    let value = match t.get(name) {
        None => default,
        Some(Value::Integer(i)) => *i,
        Some(_) => return Err(ConfigError::WrongType { key }),
    };
    if !(min..=max).contains(&value) {
        return Err(ConfigError::OutOfRange { key, min, max });
    }
    u32::try_from(value).map_err(|_| ConfigError::OutOfRange { key, min, max })
}

fn min_free(t: &Table, name: &str, key: &'static str) -> Result<MinFreePercent, ConfigError> {
    let max = i64::from(MinFreePercent::MAX);
    let default = i64::from(MinFreePercent::default().get());
    let value = ranged(t, name, key, 0, max, default)?;
    u8::try_from(value)
        .ok()
        .and_then(|v| MinFreePercent::new(v).ok())
        .ok_or(ConfigError::OutOfRange { key, min: 0, max })
}

fn relation(a: &Path, b: &Path) -> Option<ConflictKind> {
    if a == b {
        Some(ConflictKind::Same)
    } else if a.starts_with(b) || b.starts_with(a) {
        Some(ConflictKind::Nested)
    } else {
        None
    }
}

/// The roots must not collide; a file path must not collide with a root or with the other file.
fn check_layout(hot: &Path, archive: &Path, db: &Path, key_file: &Path) -> Result<(), ConfigError> {
    let conflict = |key, other, reason| Err(ConfigError::Conflict { key, other, reason });
    if let Some(reason) = relation(hot, archive) {
        return conflict("storage.hot_root", "storage.archive_root", reason);
    }
    let files = [("database.path", db), ("secrets.key_file", key_file)];
    let roots = [("storage.hot_root", hot), ("storage.archive_root", archive)];
    for (key, file) in files {
        for (other, root) in roots {
            if let Some(reason) = relation(file, root) {
                return conflict(key, other, reason);
            }
        }
    }
    if db == key_file {
        return conflict("secrets.key_file", "database.path", ConflictKind::Same);
    }
    Ok(())
}
