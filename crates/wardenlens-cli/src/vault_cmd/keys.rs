//! Key commands: `rekey`, `key export`, `key import` and `check-key` (ADR 0006 section 6).

use std::path::Path;

use wardenlens_secrets::KeyFile;
use wardenlens_vault::Vault;

use super::session::{DirLock, fsync_dir, key_dir, recover};
use super::{paths, say, warn};
use crate::env::{Env, Paths};
use crate::error::CliError;
use crate::terminal::{StdoutKind, Terminal};

const NEEDS_TTY_OUT: &str = "this command needs a terminal on stdout: the key is shown only to the owner, never to a pipe or file";

/// `vault key export`: the key as base64, to a terminal only.
pub(super) fn export<T: Terminal>(p: &Paths, term: &mut T) -> Result<(), CliError> {
    if term.stdout_kind() != StdoutKind::Tty {
        return Err(CliError::Refused(NEEDS_TTY_OUT));
    }
    let key = KeyFile::load(&p.key)?;
    let text = key.to_base64();
    say(term, &text)
}

/// `vault key import`: a base64 key from a no-echo prompt, written as a new key file.
pub(super) fn import<T: Terminal>(env: &Env, term: &mut T) -> Result<(), CliError> {
    if !term.stdin_is_tty() {
        return Err(CliError::Refused(
            "key import needs a terminal on stdin: the key is read from a no-echo prompt, never from a pipe or argv",
        ));
    }
    if env.key_file.is_none() {
        env.check_xdg()?;
    }
    let p = env.paths()?;
    paths::refuse_work_tree(&p.key)?;
    if env.key_file.is_none() {
        paths::ensure_private_dir(&p.key)?;
    }
    let line = term
        .prompt_secret("key (base64)")
        .map_err(|_| CliError::Refused("could not read the key"))?;
    let text = std::str::from_utf8(&line)
        .map_err(|_| CliError::Refused("key text is not base64 of exactly 32 bytes"))?;
    KeyFile::import(&p.key, text)?;
    say(term, "key file created")
}

/// `vault check-key [path]`: the key rules, never the contents.
pub(super) fn check_key<T: Terminal>(
    path: Option<&Path>,
    env: &Env,
    term: &mut T,
) -> Result<(), CliError> {
    let target = match path {
        Some(p) => p.to_owned(),
        None => env.paths()?.key,
    };
    KeyFile::load(&target)?;
    say(term, "key file ok")
}

/// `vault rekey`: new key as `<key>.next`, one transaction, rename, then export.
pub(super) fn rekey<T: Terminal>(p: &Paths, term: &mut T) -> Result<(), CliError> {
    // Before anything changes: the closing export needs a terminal, and a rotation that cannot
    // finish its export would strand the owner with an old password-manager copy.
    if term.stdout_kind() != StdoutKind::Tty {
        return Err(CliError::Refused(
            "rekey needs a terminal on stdout: it ends by exporting the new key; nothing was changed",
        ));
    }
    let dir = key_dir(p)?;
    let _lock = DirLock::acquire(dir)?;
    recover(p, term)?;
    let mut vault = Vault::open(&p.db, KeyFile::load(&p.key)?)?;
    let next = p.next_key();
    // Created O_EXCL with mode 0600 and fsynced; the directory is fsynced again here so a crash
    // cannot lose the only copy of the new key before the transaction starts.
    let new_key = KeyFile::generate(&next)?;
    fsync_dir(dir)?;
    // On any error the vault is unchanged or the outcome is unknown; `<key>.next` is left in
    // place and the next write command's recovery decides which key is current.
    vault.rekey(new_key)?;
    std::fs::rename(&next, &p.key).map_err(|e| CliError::Io {
        op: "renaming the new key into place (the next write command completes it)",
        source: e,
    })?;
    fsync_dir(dir)?;
    warn(
        term,
        "re-export the key now: the previous password-manager copy no longer opens the vault",
    )?;
    export(p, term)
}
