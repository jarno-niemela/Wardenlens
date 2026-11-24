//! Directory and work-tree rules for the files `init` and `key import` create.

use std::fs::DirBuilder;
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::Path;

use crate::error::CliError;

/// Refuses a path whose nearest existing ancestor (or any ancestor above it) holds a `.git`
/// entry. Works for a directory that does not exist yet.
pub(super) fn refuse_work_tree(file: &Path) -> Result<(), CliError> {
    let parent = file
        .parent()
        .ok_or(CliError::Refused("path has no parent directory"))?;
    let existing = parent
        .ancestors()
        .find(|a| a.symlink_metadata().is_ok())
        .ok_or(CliError::Refused("path has no existing ancestor"))?;
    let canonical = existing
        .canonicalize()
        .map_err(CliError::io("resolving directory"))?;
    if canonical
        .ancestors()
        .any(|d| d.join(".git").symlink_metadata().is_ok())
    {
        return Err(CliError::Refused(
            "refusing a path inside a git work tree: the vault and key live outside every repository",
        ));
    }
    Ok(())
}

/// Makes the directory of `file` (mode 0700) or checks an existing one: a real directory owned
/// by the current user with no group or other access.
pub(super) fn ensure_private_dir(file: &Path) -> Result<(), CliError> {
    let dir = file
        .parent()
        .ok_or(CliError::Refused("path has no parent directory"))?;
    match dir.symlink_metadata() {
        Ok(meta) => {
            if !meta.is_dir() {
                return Err(CliError::Refused("directory path is not a directory"));
            }
            if meta.uid() != rustix::process::geteuid().as_raw() {
                return Err(CliError::Refused(
                    "directory is not owned by the current user",
                ));
            }
            if meta.mode() & 0o077 != 0 {
                return Err(CliError::Refused(
                    "directory must be mode 0700 (no group or other access); run chmod 700 on it",
                ));
            }
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .map_err(CliError::io("creating directory")),
        Err(e) => Err(CliError::io("inspecting directory")(e)),
    }
}
