//! Paths and the environment, read once at startup and injectable in tests (ADR 0006 sections
//! 4 and 6). The binary reads exactly the variables named there and no others for the vault.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use crate::error::CliError;

const DATA_REL: &str = ".local/share/wardenlens";
const CONFIG_REL: &str = ".config/wardenlens";
const DB_NAME: &str = "dev-vault.db";
const KEY_NAME: &str = "dev-vault.key";
/// Default legacy file names in the config directory.
pub(crate) const LEGACY_JSON_NAME: &str = "agentdvr-cameras.secret.json";
pub(crate) const LEGACY_TOML_NAME: &str = "cameras.local.toml";

/// The variables the vault commands read.
#[derive(Debug, Clone, Default)]
pub(crate) struct Env {
    pub(crate) home: Option<OsString>,
    pub(crate) xdg_data_home: Option<OsString>,
    pub(crate) xdg_config_home: Option<OsString>,
    /// `WARDENLENS_VAULT`
    pub(crate) vault: Option<OsString>,
    /// `WARDENLENS_VAULT_KEY_FILE`
    pub(crate) key_file: Option<OsString>,
    /// True if `WARDENLENS_VAULT_KEY` is set (always an error; its value is never read).
    pub(crate) key_var_set: bool,
}

impl Env {
    pub(crate) fn from_process() -> Self {
        let get = |k| std::env::var_os(k);
        Self {
            home: get("HOME"),
            xdg_data_home: get("XDG_DATA_HOME"),
            xdg_config_home: get("XDG_CONFIG_HOME"),
            vault: get("WARDENLENS_VAULT"),
            key_file: get("WARDENLENS_VAULT_KEY_FILE"),
            key_var_set: std::env::var_os("WARDENLENS_VAULT_KEY").is_some(),
        }
    }

    fn home(&self) -> Result<PathBuf, CliError> {
        match &self.home {
            Some(h) if Path::new(h).is_absolute() => Ok(PathBuf::from(h)),
            _ => Err(CliError::Refused("HOME must be set to an absolute path")),
        }
    }

    /// The directory holding the legacy files and the dev key.
    pub(crate) fn config_dir(&self) -> Result<PathBuf, CliError> {
        Ok(self.home()?.join(CONFIG_REL))
    }

    fn require_absolute(p: &OsString) -> Result<PathBuf, CliError> {
        let p = PathBuf::from(p);
        if p.is_absolute() {
            Ok(p)
        } else {
            Err(CliError::Refused(
                "WARDENLENS_VAULT and WARDENLENS_VAULT_KEY_FILE must be absolute paths",
            ))
        }
    }

    /// Refuses when `WARDENLENS_VAULT_KEY` is set (its value is never read).
    ///
    /// # Errors
    /// [`CliError::Refused`].
    pub(crate) fn refuse_key_variable(&self) -> Result<(), CliError> {
        if self.key_var_set {
            return Err(CliError::Refused(
                "WARDENLENS_VAULT_KEY is set: the key is read from a file, never from the environment; unset it",
            ));
        }
        Ok(())
    }

    /// The vault and key paths for a command. `WARDENLENS_VAULT_KEY` is always refused: the key
    /// is a file, never an environment variable.
    ///
    /// # Errors
    /// `HOME` unusable, a relative override, or `WARDENLENS_VAULT_KEY` set.
    pub(crate) fn paths(&self) -> Result<Paths, CliError> {
        self.refuse_key_variable()?;
        let db = match &self.vault {
            Some(v) => Self::require_absolute(v)?,
            None => self.home()?.join(DATA_REL).join(DB_NAME),
        };
        let key = match &self.key_file {
            Some(v) => Self::require_absolute(v)?,
            None => self.home()?.join(CONFIG_REL).join(KEY_NAME),
        };
        Ok(Paths { db, key })
    }

    /// Refuses when `XDG_DATA_HOME` or `XDG_CONFIG_HOME` would place the default dev vault or
    /// key anywhere but the fixed path the git hooks use (ADR 0006 section 4). A variable set
    /// to the default location is accepted.
    ///
    /// # Errors
    /// [`CliError::Refused`].
    pub(crate) fn check_xdg(&self) -> Result<(), CliError> {
        let home = self.home()?;
        let moved = |var: &Option<OsString>, default: &str| {
            var.as_ref()
                .filter(|v| !v.is_empty())
                .is_some_and(|v| Path::new(v) != home.join(default))
        };
        // XDG_DATA_HOME defaults to ~/.local/share, XDG_CONFIG_HOME to ~/.config.
        if moved(&self.xdg_data_home, ".local/share") || moved(&self.xdg_config_home, ".config") {
            return Err(CliError::Refused(
                "XDG_DATA_HOME or XDG_CONFIG_HOME would place the vault or key away from the fixed path the git hooks use; unset them",
            ));
        }
        Ok(())
    }

    /// The same environment without `WARDENLENS_VAULT`, `WARDENLENS_VAULT_KEY_FILE` and the
    /// `XDG_*` variables, so the paths are the fixed defaults (the git hooks use this).
    pub(crate) fn without_overrides(&self) -> Self {
        Self {
            vault: None,
            key_file: None,
            xdg_data_home: None,
            xdg_config_home: None,
            ..self.clone()
        }
    }

    /// True if either path comes from an override variable rather than the fixed default.
    pub(crate) fn has_override(&self) -> bool {
        self.vault.is_some() || self.key_file.is_some()
    }
}

/// Where the vault database and its key live.
#[derive(Debug, Clone)]
pub(crate) struct Paths {
    pub(crate) db: PathBuf,
    pub(crate) key: PathBuf,
}

impl Paths {
    /// `<key>.next`, the new key of a rotation in progress.
    pub(crate) fn next_key(&self) -> PathBuf {
        let mut name = self.key.clone().into_os_string();
        name.push(".next");
        PathBuf::from(name)
    }
}
