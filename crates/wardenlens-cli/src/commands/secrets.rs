//! `wardenlens secrets init`: creates the key file that `secrets.key_file` names.
//!
//! The key comes from the OS random generator and is written with mode 0600 by
//! [`KeyFile::generate`], which uses `O_CREAT | O_EXCL | O_NOFOLLOW`: an existing file (or a
//! symlink at the path) is refused and never overwritten, whatever the process umask. The parent
//! directory is not created. The key is never printed.

use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use wardenlens_secrets::{KeyFile, SecretsError};

use super::{Context, report_error};
use crate::args::SecretsCommand;
use crate::config_file::{ConfigFileError, load, resolve_path};

/// Why `secrets init` failed.
#[derive(Debug, thiserror::Error)]
pub(crate) enum SecretsInitError {
    /// The config could not be used.
    #[error(transparent)]
    Config(#[from] ConfigFileError),
    /// The file exists: it is never overwritten (its contents are not read).
    #[error("key file {path:?} already exists; it was left untouched")]
    Exists { path: PathBuf },
    /// The key file could not be created.
    #[error("key file {path:?} cannot be created")]
    Create {
        path: PathBuf,
        #[source]
        source: SecretsError,
    },
    /// Writing the result to stdout failed.
    #[error("cannot write to stdout")]
    Output(#[source] io::Error),
}

impl SecretsInitError {
    fn exit_code(&self) -> u8 {
        match self {
            Self::Config(e) => e.exit_code(),
            Self::Exists { .. } => 1,
            Self::Create { .. } | Self::Output(_) => 2,
        }
    }
}

pub(crate) fn execute(cmd: &SecretsCommand, ctx: &Context<'_>) -> ExitCode {
    let result = match cmd {
        SecretsCommand::Init => init(ctx),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            report_error(&e, ctx.log_format);
            ExitCode::from(e.exit_code())
        }
    }
}

fn init(ctx: &Context<'_>) -> Result<(), SecretsInitError> {
    let config = load(&resolve_path(ctx.config_flag, ctx.env)?)?;
    create(config.key_file(), &mut io::stdout().lock())
}

fn create(path: &Path, out: &mut impl Write) -> Result<(), SecretsInitError> {
    // The returned key is dropped (and zeroised) at once: the file is the only copy.
    KeyFile::generate(path).map_err(|source| match source {
        SecretsError::KeyFileExists => SecretsInitError::Exists {
            path: path.to_path_buf(),
        },
        source => SecretsInitError::Create {
            path: path.to_path_buf(),
            source,
        },
    })?;
    // Escaped, so a control character in a path cannot forge a line.
    let shown = path.to_string_lossy().escape_debug().to_string();
    writeln!(
        out,
        "created key file \"{shown}\" (mode 0600). Back it up outside this machine: \
         without it the sealed credentials cannot be read."
    )
    .and_then(|()| out.flush())
    .map_err(SecretsInitError::Output)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    #[test]
    fn creates_a_private_32_byte_file_and_never_overwrites() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("k.key");
        let mut out = Vec::new();
        create(&path, &mut out).unwrap();
        let bytes = std::fs::read(&path).unwrap();
        assert_eq!(bytes.len(), 32);
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        // The printed text never holds the key.
        assert!(!out.windows(32).any(|w| w == bytes.as_slice()));
        let err = create(&path, &mut Vec::new()).unwrap_err();
        assert!(matches!(err, SecretsInitError::Exists { .. }));
        assert_eq!(err.exit_code(), 1);
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
    }

    #[test]
    fn a_missing_directory_is_an_error_not_created() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nope").join("k.key");
        let err = create(&path, &mut Vec::new()).unwrap_err();
        assert!(matches!(err, SecretsInitError::Create { .. }));
        assert_eq!(err.exit_code(), 2);
        assert!(!dir.path().join("nope").exists());
    }
}
