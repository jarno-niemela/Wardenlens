//! Locating and reading the service config file (#64). The path is untrusted input (SEC-2).
//!
//! # Path precedence
//! `--config <path>`, then `WARDENLENS_CONFIG`, then [`DEFAULT_CONFIG_PATH`]. An empty
//! `WARDENLENS_CONFIG` counts as unset (a compose file's `${VAR:-}` yields an empty value); an
//! empty `--config` is a usage error, because silently falling back would read a different file
//! than the one the operator named.
//!
//! # Reading
//! * The last path component is opened with `O_NOFOLLOW`: a symlink is refused, dangling or not.
//!   A config managed through a symlink (some orchestrators project secrets that way) must be
//!   given by its real path.
//! * The open is `O_NONBLOCK` and the descriptor is `fstat`ed: a directory, FIFO, device or
//!   socket is refused without blocking.
//! * A file writable by everyone (mode `& 0o002`) is refused: the listen address and the paths
//!   decide where the service binds and what it deletes. A group-writable file is accepted
//!   (many distributions default to umask 0002). A world-writable parent directory without the
//!   sticky bit only draws a warning; the check is advisory and the directory could change
//!   between check and read.
//! * At most `MAX_CONFIG_BYTES + 1` bytes are read, and a larger file is refused before parsing
//!   (core repeats the check); the bytes must be UTF-8.
//! * Errors name the path (escaped, so a control character cannot forge a log line) and a
//!   reason, never file contents.
//!
//! # Exit codes
//! 1 only for a config that was read but is invalid; 2 for everything else that stops the command
//! doing its job: a config that could not be read, stdout that could not be written (a closed
//! pipe, a full disk) and a usage error (as for the vault commands, 2 means the resource the
//! command needs cannot be used).

use std::io::Read;
use std::path::{Path, PathBuf};

use wardenlens_core::config::{Config, ConfigError, MAX_CONFIG_BYTES};
use wardenlens_fsutil::{FsError, is_symlink_refusal, open_regular_nofollow};

use crate::env::Env;

/// Where the config lives when neither the flag nor the variable names it.
pub(crate) const DEFAULT_CONFIG_PATH: &str = "/etc/wardenlens/wardenlens.toml";

/// Why the config could not be used.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ConfigFileError {
    /// The arguments are unusable (exit 2).
    #[error("{0}")]
    Usage(&'static str),
    /// There is no such file.
    #[error("config file {path:?} not found")]
    NotFound { path: PathBuf },
    /// The path is a symbolic link.
    #[error("config file {path:?} is a symbolic link; give its real path")]
    Symlink { path: PathBuf },
    /// The path is a directory, FIFO, device or socket.
    #[error("config path {path:?} is not a regular file")]
    NotRegular { path: PathBuf },
    /// Any other failure to open the file.
    #[error("config file {path:?} cannot be opened")]
    Open {
        path: PathBuf,
        #[source]
        source: FsError,
    },
    /// The file is writable by everyone.
    #[error("config file {path:?} is writable by everyone; refusing to use it")]
    WorldWritable { path: PathBuf },
    /// The file is larger than the cap.
    #[error("config file {path:?} is larger than {MAX_CONFIG_BYTES} bytes")]
    TooLarge { path: PathBuf },
    /// The file is not UTF-8.
    #[error("config file {path:?} is not valid UTF-8")]
    NotUtf8 { path: PathBuf },
    /// Reading failed.
    #[error("config file {path:?} cannot be read")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    /// The file was read but is not a valid config. The source never repeats input text.
    #[error("invalid config")]
    Invalid(#[source] ConfigError),
    /// Writing the result to stdout failed.
    #[error("cannot write to stdout")]
    Output(#[source] std::io::Error),
}

impl ConfigFileError {
    pub(crate) fn exit_code(&self) -> u8 {
        match self {
            Self::Invalid(_) => 1,
            _ => 2,
        }
    }

    fn open(path: &Path, e: FsError) -> Self {
        let path = path.to_path_buf();
        if is_symlink_refusal(&e) {
            Self::Symlink { path }
        } else if e.is_not_found() {
            Self::NotFound { path }
        } else if matches!(e, FsError::NotRegular) {
            Self::NotRegular { path }
        } else {
            Self::Open { path, source: e }
        }
    }
}

/// The config path: flag, then environment, then the default.
///
/// # Errors
/// [`ConfigFileError::Usage`] for an empty `--config`.
pub(crate) fn resolve_path(flag: Option<&Path>, env: &Env) -> Result<PathBuf, ConfigFileError> {
    if let Some(p) = flag {
        if p.as_os_str().is_empty() {
            return Err(ConfigFileError::Usage("--config must not be empty"));
        }
        return Ok(p.to_path_buf());
    }
    match env.config.as_ref().filter(|v| !v.is_empty()) {
        Some(v) => Ok(PathBuf::from(v)),
        None => Ok(PathBuf::from(DEFAULT_CONFIG_PATH)),
    }
}

/// Reads and validates the config at `path`; see the module documentation.
///
/// # Errors
/// [`ConfigFileError`].
pub(crate) fn load(path: &Path) -> Result<Config, ConfigFileError> {
    let (file, stat) = open_regular_nofollow(path).map_err(|e| ConfigFileError::open(path, e))?;
    if stat.mode & 0o002 != 0 {
        return Err(ConfigFileError::WorldWritable {
            path: path.to_path_buf(),
        });
    }
    warn_if_parent_is_open(path);
    let cap = u64::try_from(MAX_CONFIG_BYTES).map_or(u64::MAX, |m| m.saturating_add(1));
    let mut bytes = Vec::new();
    file.take(cap)
        .read_to_end(&mut bytes)
        .map_err(|source| ConfigFileError::Read {
            path: path.to_path_buf(),
            source,
        })?;
    if bytes.len() > MAX_CONFIG_BYTES {
        return Err(ConfigFileError::TooLarge {
            path: path.to_path_buf(),
        });
    }
    tracing::debug!(bytes = bytes.len(), "config file read");
    // `FromUtf8Error` holds the bytes; it is dropped, not forwarded.
    let text = String::from_utf8(bytes).map_err(|_| ConfigFileError::NotUtf8 {
        path: path.to_path_buf(),
    })?;
    Config::from_toml_str(&text).map_err(ConfigFileError::Invalid)
}

/// Advisory: a directory that anyone may write to (and that has no sticky bit) lets another
/// user replace the file between runs.
fn warn_if_parent_is_open(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    if let Ok(meta) = std::fs::metadata(parent) {
        let mode = meta.permissions().mode();
        if mode & 0o002 != 0 && mode & 0o1000 == 0 {
            tracing::warn!("the directory holding the config file is writable by everyone");
        }
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;

    use super::*;

    fn env(config: Option<&str>) -> Env {
        Env {
            config: config.map(OsString::from),
            ..Env::default()
        }
    }

    #[test]
    fn flag_beats_env_beats_default() {
        let flag = Some(Path::new("/srv/flag.toml"));
        assert_eq!(
            resolve_path(flag, &env(Some("/srv/env.toml"))).unwrap(),
            Path::new("/srv/flag.toml")
        );
        assert_eq!(
            resolve_path(None, &env(Some("/srv/env.toml"))).unwrap(),
            Path::new("/srv/env.toml")
        );
        assert_eq!(
            resolve_path(None, &env(None)).unwrap(),
            Path::new(DEFAULT_CONFIG_PATH)
        );
    }

    #[test]
    fn empty_env_counts_as_unset_and_empty_flag_is_refused() {
        assert_eq!(
            resolve_path(None, &env(Some(""))).unwrap(),
            Path::new(DEFAULT_CONFIG_PATH)
        );
        // An empty variable does not override a flag either.
        assert_eq!(
            resolve_path(Some(Path::new("/srv/f")), &env(Some(""))).unwrap(),
            Path::new("/srv/f")
        );
        let e = resolve_path(Some(Path::new("")), &env(Some("/srv/env.toml"))).unwrap_err();
        assert_eq!(e.exit_code(), 2);
    }

    #[test]
    fn the_default_path_is_the_documented_one() {
        assert_eq!(DEFAULT_CONFIG_PATH, "/etc/wardenlens/wardenlens.toml");
    }

    #[test]
    fn exit_codes() {
        let p = || PathBuf::from("/srv/x");
        assert_eq!(ConfigFileError::NotFound { path: p() }.exit_code(), 2);
        assert_eq!(ConfigFileError::TooLarge { path: p() }.exit_code(), 2);
        assert_eq!(
            ConfigFileError::Invalid(ConfigError::Missing { key: "k" }).exit_code(),
            1
        );
        assert_eq!(
            ConfigFileError::Output(std::io::Error::other("x")).exit_code(),
            2
        );
    }
}
