//! `wardenlens vault ...` (ADR 0006 sections 4, 6 and 10).
//!
//! Values are written to stdout only by `get`. Everything else prints ids, kinds and counts.

mod keys;
mod legacy;
mod paths;
mod session;
mod value;

use wardenlens_core::entry::EntryId;
use wardenlens_secrets::{KeyFile, SecretsError};
use wardenlens_vault::{Scan, Scannability, Value, Vault, VaultError};

use self::session::{open_read, open_write};
use crate::args::{FieldArg, GetArgs, SetArgs, VaultCommand};
use crate::env::{Env, Paths};
use crate::error::CliError;
use crate::terminal::{StdoutKind, Terminal};

/// Runs one vault command.
///
/// # Errors
/// Any [`CliError`]; the caller prints it and maps it to an exit code.
pub(crate) fn run<T: Terminal>(cmd: VaultCommand, env: &Env, term: &mut T) -> Result<(), CliError> {
    match cmd {
        VaultCommand::Init => init(env, term),
        VaultCommand::Set(a) => set(&a, &env.paths()?, term),
        VaultCommand::Get(a) => get(&a, &env.paths()?, term),
        VaultCommand::List => list(&env.paths()?, term),
        VaultCommand::Rm { id } => rm(&id, &env.paths()?, term),
        VaultCommand::Rekey => keys::rekey(&env.paths()?, term),
        VaultCommand::CheckKey { path } => keys::check_key(path.as_deref(), env, term),
        VaultCommand::Key(crate::args::KeyCommand::Export) => keys::export(&env.paths()?, term),
        VaultCommand::Key(crate::args::KeyCommand::Import) => keys::import(env, term),
        VaultCommand::ImportLegacy(a) => legacy::import(&a, env, term),
    }
}

fn parse_id(text: &str) -> Result<EntryId, CliError> {
    EntryId::new(text).map_err(|e| CliError::Vault(VaultError::InvalidId(e)))
}

fn say(term: &mut impl Terminal, text: &str) -> Result<(), CliError> {
    writeln!(term.out(), "{text}").map_err(CliError::io("writing output"))
}

fn warn(term: &mut impl Terminal, text: &str) -> Result<(), CliError> {
    writeln!(term.err(), "{text}").map_err(CliError::io("writing output"))
}

fn init<T: Terminal>(env: &Env, term: &mut T) -> Result<(), CliError> {
    if env.has_override() {
        return Err(CliError::Refused(
            "init creates the developer vault at the fixed path only; unset WARDENLENS_VAULT and WARDENLENS_VAULT_KEY_FILE",
        ));
    }
    env.check_xdg()?;
    let p = env.paths()?;
    paths::refuse_work_tree(&p.db)?;
    paths::refuse_work_tree(&p.key)?;
    paths::ensure_private_dir(&p.db)?;
    paths::ensure_private_dir(&p.key)?;
    let (key, created) = match KeyFile::generate(&p.key) {
        Ok(k) => (k, true),
        // A key put there by `key import`: reuse it, never overwrite it.
        Err(SecretsError::KeyFileExists) => (KeyFile::load(&p.key)?, false),
        Err(e) => return Err(e.into()),
    };
    if let Err(e) = Vault::create(&p.db, key) {
        if created {
            // The key was created a moment ago by this command and protects nothing yet.
            let _ = std::fs::remove_file(&p.key);
        }
        return Err(e.into());
    }
    say(term, "created the developer vault and its key")?;
    warn(
        term,
        "next: run `wardenlens vault key export` and keep the result in your password manager; exclude the key path from backups",
    )
}

fn set<T: Terminal>(args: &SetArgs, p: &Paths, term: &mut T) -> Result<(), CliError> {
    let id = parse_id(&args.id)?;
    let kind = args.kind.into();
    let value = value::read(kind, term)?;
    let mut session = open_write(p, term)?;
    let how = session.vault.set(&id, kind, &value, Scan::Normal)?;
    say(term, &format!("stored {id} ({kind})"))?;
    if how == Scannability::Unscannable {
        warn(
            term,
            "warning: stored as unscannable (too short for the leak scan to match safely); `list` shows the mark",
        )?;
    }
    Ok(())
}

fn get<T: Terminal>(args: &GetArgs, p: &Paths, term: &mut T) -> Result<(), CliError> {
    let id = parse_id(&args.id)?;
    if term.stdout_kind() == StdoutKind::Other {
        return Err(CliError::Refused(
            "stdout must be a pipe or a terminal: a value is never written to a file or socket",
        ));
    }
    let vault = open_read(p)?;
    let entry = vault
        .get(&id)?
        .ok_or_else(|| CliError::NoEntry(id.to_string()))?;
    let out = term.out();
    let written = match (&entry.value, args.field) {
        (Value::Credential(c), Some(FieldArg::Username)) => out.write_all(c.username.as_bytes()),
        (Value::Credential(c), Some(FieldArg::Password)) => {
            use secrecy::ExposeSecret;
            out.write_all(c.password.expose_secret().as_bytes())
        }
        (Value::Credential(_), None) => {
            return Err(CliError::Refused(
                "credential entries need --field username or --field password",
            ));
        }
        (Value::Text(t), None) => {
            use secrecy::ExposeSecret;
            out.write_all(t.expose_secret().as_bytes())
        }
        _ => {
            return Err(CliError::Refused(
                "--field applies to credential entries only",
            ));
        }
    };
    written
        .and_then(|()| out.flush())
        .map_err(CliError::io("writing value"))
}

fn list<T: Terminal>(p: &Paths, term: &mut T) -> Result<(), CliError> {
    let vault = open_read(p)?;
    for e in vault.list()? {
        let flag = if e.unscannable {
            "unscannable"
        } else {
            "scannable"
        };
        say(term, &format!("{}\t{}\t{flag}", e.id, e.kind))?;
    }
    Ok(())
}

fn rm<T: Terminal>(id: &str, p: &Paths, term: &mut T) -> Result<(), CliError> {
    let id = parse_id(id)?;
    let mut session = open_write(p, term)?;
    if !session.vault.rm(&id)? {
        return Err(CliError::NoEntry(id.to_string()));
    }
    say(term, &format!("removed {id}"))
}

#[cfg(test)]
mod tests;
