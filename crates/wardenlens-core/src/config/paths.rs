//! Lexical validation of a configured path (no I/O).

use super::error::PathProblem;

/// Longest accepted path, bytes (Linux `PATH_MAX`).
const MAX_PATH_BYTES: usize = 4096;

/// Accepts only the canonical absolute form described in the module docs of [`super`].
pub(super) fn validate(text: &str) -> Result<(), PathProblem> {
    if text.is_empty() || text.len() > MAX_PATH_BYTES {
        return Err(PathProblem::BadLength);
    }
    if text
        .chars()
        .any(|c| c.is_control() || crate::text::is_invisible(c))
    {
        return Err(PathProblem::ControlChar);
    }
    let Some(rest) = text.strip_prefix('/') else {
        return Err(PathProblem::NotAbsolute);
    };
    if rest.is_empty() {
        return Err(PathProblem::Root);
    }
    let mut dot = false;
    let mut empty = false;
    for component in rest.split('/') {
        match component {
            "" => empty = true,
            "." | ".." => dot = true,
            _ => {}
        }
    }
    if dot {
        Err(PathProblem::DotComponent)
    } else if empty {
        Err(PathProblem::NotCanonical)
    } else {
        Ok(())
    }
}
