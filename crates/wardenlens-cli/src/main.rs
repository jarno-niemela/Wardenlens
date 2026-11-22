//! Wardenlens command-line entry point.
//!
//! Keep this file thin: parse arguments, call into `wardenlens-core`,
//! map errors to exit codes.

use std::io::{self, Write};
use std::process::ExitCode;

fn main() -> ExitCode {
    let mut out = io::stdout().lock();
    match writeln!(out, "wardenlens {}", wardenlens_core::VERSION) {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => ExitCode::FAILURE,
    }
}
