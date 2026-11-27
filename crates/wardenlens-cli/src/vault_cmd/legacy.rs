//! `vault import-legacy`: the `AgentDVR` secret JSON and the camera inventory (ADR 0006 section 4).
//!
//! Joins each JSON camera to an inventory id (`legacy::resolve_ids`), then imports through
//! `legacy::map_legacy_with_ids` only, which refuses ids two files would share. Prints counts,
//! ids, camera indexes and key names, never values.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use rustix::fs::{Mode, OFlags};
use wardenlens_vault::legacy::{
    Basis, LegacyError, LegacyImport as Mapped, MAX_REPORTED_KEYS, Resolution, Row,
    check_inventory_names, map_legacy_with_ids, resolve_ids,
};
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

/// Shown when two cameras share a display name, whichever check finds it.
const DUPLICATE_NAME: CliError =
    CliError::Refused("two cameras share a display name; the secret file cannot be mapped");

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
        // Only the exact spelling is checked here, because the map is keyed by it and a second
        // camera would replace the first. Names that differ only in white space or invisible
        // characters are refused by `map_legacy` (one check: the vault's stored form).
        if let Some(name) = name
            && map.insert(name.to_owned(), id.clone()).is_some()
        {
            return Err(DUPLICATE_NAME);
        }
    }
    Ok(map)
}

/// Parses `--map <json-index>=<id>`. The text is never echoed: it is user input, but a typo
/// must not put anything but a fixed message into an error.
fn parse_map(text: &str) -> Result<(usize, String), CliError> {
    const BAD: CliError =
        CliError::Refused("--map needs <json-index>=<id>, for example --map 1=reolink-1");
    let (index, id) = text.split_once('=').ok_or(BAD)?;
    let index = index.parse::<usize>().map_err(|_| BAD)?;
    if id.is_empty() {
        return Err(BAD);
    }
    Ok((index, id.to_owned()))
}

fn say_mapping(resolution: &Resolution, term: &mut impl Terminal) -> Result<(), CliError> {
    for (i, row) in resolution.rows().iter().enumerate() {
        let index = i.saturating_add(1);
        let line = match row {
            Row::Mapped { id, basis } => {
                let how = match basis {
                    Basis::Explicit => "mapped by --map",
                    Basis::Exact => "exact match",
                    _ => "word match",
                };
                format!("camera index {index} -> {id} ({how})")
            }
            Row::NoMatch => format!(
                "camera index {index} -> unmapped: no inventory id, vendor or model matches"
            ),
            Row::Ambiguous(ids) => {
                format!(
                    "camera index {index} -> unmapped: ambiguous between {} ids",
                    ids.len()
                )
            }
            _ => format!("camera index {index} -> unmapped"),
        };
        say(term, &line)?;
    }
    Ok(())
}

/// Reads both files, joins every JSON camera to an inventory id (printing the mapping) and maps
/// the fields. Writes nothing.
fn map_files(args: &LegacyArgs, env: &Env, term: &mut impl Terminal) -> Result<Mapped, CliError> {
    let explicit = args
        .map
        .iter()
        .map(|m| parse_map(m))
        .collect::<Result<Vec<_>, _>>()?;
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
    if json.is_none() && !explicit.is_empty() {
        return Err(CliError::Refused(
            "--map needs the secret file, and none was found",
        ));
    }
    check_inventory_names(&names).map_err(|_| DUPLICATE_NAME)?;
    let resolution = json
        .as_ref()
        .map(|j| resolve_ids(j, table.as_ref(), &explicit))
        .transpose()?;
    if let Some(r) = &resolution {
        say_mapping(r, term)?;
    }
    let ids = match resolution {
        Some(r) => r.into_ids()?,
        None => Vec::new(),
    };
    map_legacy_with_ids(json.as_ref(), &ids, &names, table.as_ref()).map_err(|e| match e {
        LegacyError::DuplicateName => DUPLICATE_NAME,
        other => CliError::from(other),
    })
}

pub(super) fn import<T: Terminal>(
    args: &LegacyArgs,
    env: &Env,
    term: &mut T,
) -> Result<(), CliError> {
    let mapped = map_files(args, env, term)?;
    if args.dry_run {
        for e in &mapped.entries {
            say(term, &format!("would import {} ({})", e.id, e.kind))?;
        }
        say(
            term,
            &format!(
                "would import {} entries; nothing was written",
                mapped.entries.len()
            ),
        )?;
        return report_unknown(&mapped, term);
    }

    let paths = env.paths()?;
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

/// One line per unused field name with the number of cameras it was found in.
fn report_unknown(mapped: &Mapped, term: &mut impl Terminal) -> Result<(), CliError> {
    if !mapped.unused_fields.is_empty() {
        say(
            term,
            "not imported, field name and number of cameras (classify each with `wardenlens vault set`):",
        )?;
        for (name, count) in &mapped.unused_fields {
            say(term, &format!("  {name}: {count}"))?;
        }
    }
    if mapped.keys_truncated {
        say(
            term,
            &format!("  (list cut at {MAX_REPORTED_KEYS} fields; more were not imported)"),
        )?;
    }
    Ok(())
}
