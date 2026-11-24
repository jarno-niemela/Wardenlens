//! `vault import-legacy`: the `AgentDVR` secret JSON and the camera inventory (ADR 0006 section 4).
//!
//! Imports through `legacy::map_legacy` only, which refuses ids two files would share. Prints
//! counts, ids and key names, never values.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use rustix::fs::{Mode, OFlags};
use wardenlens_vault::legacy::{LegacyImport as Mapped, MAX_REPORTED_KEYS, map_legacy};
use wardenlens_vault::{Scan, Scannability};
use zeroize::Zeroizing;

use super::session::open_write;
use super::{say, warn};
use crate::args::LegacyArgs;
use crate::env::{Env, LEGACY_JSON_NAME, LEGACY_TOML_NAME};
use crate::error::CliError;
use crate::terminal::Terminal;

/// Largest legacy file read (SEC-2).
const MAX_LEGACY_BYTES: u64 = 1024 * 1024;

/// Reads one legacy file. A missing default file is `None`; a missing explicit one is an error.
fn read_file(path: &Path, explicit: bool) -> Result<Option<Zeroizing<String>>, CliError> {
    // Non-blocking and no controlling terminal: opening a FIFO must not wait for a writer.
    let flags = OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::CLOEXEC;
    let file = match rustix::fs::open(path, flags, Mode::empty()) {
        Ok(fd) => File::from(fd),
        Err(e) if e == rustix::io::Errno::NOENT && !explicit => return Ok(None),
        Err(e) => return Err(CliError::io("opening legacy file")(e.into())),
    };
    let meta = file
        .metadata()
        .map_err(CliError::io("inspecting legacy file"))?;
    if !meta.is_file() {
        return Err(CliError::Refused("legacy path is not a regular file"));
    }
    let mut text = Zeroizing::new(String::new());
    file.take(MAX_LEGACY_BYTES.saturating_add(1))
        .read_to_string(&mut text)
        .map_err(|_| CliError::Refused("legacy file is not readable UTF-8 text"))?;
    if u64::try_from(text.len()).unwrap_or(u64::MAX) > MAX_LEGACY_BYTES {
        return Err(CliError::Refused("legacy file is larger than 1 MiB"));
    }
    Ok(Some(text))
}

/// Camera display name to inventory id, from the inventory's `name` (or `display_name`).
fn names_to_ids(table: &toml::Table) -> Result<BTreeMap<String, String>, CliError> {
    let mut map = BTreeMap::new();
    let Some(cameras) = table.get("cameras").and_then(toml::Value::as_table) else {
        return Ok(map);
    };
    for (id, camera) in cameras {
        let name = camera
            .as_table()
            .and_then(|c| c.get("name").or_else(|| c.get("display_name")))
            .and_then(toml::Value::as_str);
        if let Some(name) = name
            && map.insert(name.to_owned(), id.clone()).is_some()
        {
            return Err(CliError::Refused(
                "two inventory cameras share a display name; the secret file cannot be mapped",
            ));
        }
    }
    Ok(map)
}

pub(super) fn import<T: Terminal>(
    args: &LegacyArgs,
    env: &Env,
    term: &mut T,
) -> Result<(), CliError> {
    let paths = env.paths()?;
    let config = env.config_dir()?;
    let pick = |given: &Option<PathBuf>, name: &str| match given {
        Some(p) => (p.clone(), true),
        None => (config.join(name), false),
    };
    let (json_path, json_explicit) = pick(&args.secret_json, LEGACY_JSON_NAME);
    let (toml_path, toml_explicit) = pick(&args.inventory, LEGACY_TOML_NAME);
    let json_text = read_file(&json_path, json_explicit)?;
    let toml_text = read_file(&toml_path, toml_explicit)?;
    if json_text.is_none() && toml_text.is_none() {
        return Err(CliError::Refused(
            "no legacy file found: pass --secret-json and --inventory, or place them in the config directory",
        ));
    }
    let json = json_text
        .map(|t| {
            serde_json::from_str::<serde_json::Value>(&t)
                .map_err(|_| CliError::Refused("the secret file is not valid JSON"))
        })
        .transpose()?;
    let table = toml_text
        .map(|t| {
            toml::from_str::<toml::Table>(&t)
                .map_err(|_| CliError::Refused("the inventory is not valid TOML"))
        })
        .transpose()?;
    let names = table
        .as_ref()
        .map(names_to_ids)
        .transpose()?
        .unwrap_or_default();
    let mapped = map_legacy(json.as_ref(), &names, table.as_ref())?;

    let mut session = open_write(&paths, term)?;
    let mut unscannable = Vec::new();
    let total = mapped.entries.len();
    let mut done = 0_usize;
    let mut failure = None;
    for e in &mapped.entries {
        match session.vault.set(&e.id, e.kind, &e.value, Scan::Normal) {
            Ok(how) => {
                if how == Scannability::Unscannable {
                    unscannable.push(e.id.to_string());
                }
                done = done.saturating_add(1);
                say(term, &format!("imported {} ({})", e.id, e.kind))?;
            }
            Err(err) => {
                failure = Some((e.id.to_string(), err));
                break;
            }
        }
    }
    if failure.is_none() {
        say(term, &format!("imported {total} entries"))?;
    }
    for id in &unscannable {
        warn(
            term,
            &format!("warning: {id} stored as unscannable (too short for the leak scan)"),
        )?;
    }
    report_unknown(&mapped, term)?;
    if let Some((id, err)) = failure {
        // The typed error keeps its exit code; the id and the progress are the context.
        warn(
            term,
            &format!(
                "stopped at entry {id}: {done} of {total} imported before the failure; re-run is safe"
            ),
        )?;
        return Err(err.into());
    }
    warn(
        term,
        "the legacy files are still plaintext: after `wardenlens vault key export` is safe in your password manager, delete them yourself",
    )
}

fn report_unknown(mapped: &Mapped, term: &mut impl Terminal) -> Result<(), CliError> {
    if !mapped.unknown_keys.is_empty() {
        say(
            term,
            "not imported (classify each with `wardenlens vault set`):",
        )?;
        for key in &mapped.unknown_keys {
            say(term, &format!("  {key}"))?;
        }
    }
    if mapped.keys_truncated {
        say(
            term,
            &format!("  (list cut at {MAX_REPORTED_KEYS} keys; more were not imported)"),
        )?;
    }
    Ok(())
}
