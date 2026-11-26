//! `wardenlens vault redact`: a stdin-to-stdout filter that replaces every vault value with a
//! fixed marker (ADR 0006 amendment, #76).
//!
//! The filter is built before a byte is read, so a missing vault, a wrong key or a refused key
//! variable writes nothing (fail closed, exit 2). Stderr names entry ids and kinds that cannot be
//! matched, never a value.

use wardenlens_vault::Redactor;

use super::session::open_read;
use super::warn;
use crate::env::Env;
use crate::error::CliError;
use crate::terminal::Terminal;

pub(super) fn run<T: Terminal>(env: &Env, term: &mut T) -> Result<(), CliError> {
    let could_not = |e: CliError| CliError::CouldNotRedact(Box::new(e));
    let paths = env.paths().map_err(could_not)?;
    let vault = open_read(&paths).map_err(could_not)?;
    let redactor = Redactor::from_vault(&vault).map_err(|e| could_not(e.into()))?;
    drop(vault);
    for u in redactor.unredactable() {
        warn(
            term,
            &format!(
                "warning: entry {} ({}) is unredactable (too short, or already public) and is not replaced",
                u.id, u.kind
            ),
        )?;
    }
    let (input, output) = term.stream();
    redactor.filter(input, output)?;
    Ok(())
}
