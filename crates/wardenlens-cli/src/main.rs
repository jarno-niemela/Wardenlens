//! Wardenlens command-line entry point.
//!
//! Keep this file thin: parse arguments, call into the libraries, map errors to exit codes.

mod args;
mod env;
mod error;
mod terminal;
mod vault_cmd;

use std::error::Error;
use std::io::{self, Write};
use std::process::ExitCode;

use clap::Parser;
use clap::error::ErrorKind;
use rustix::process::{Resource, Rlimit, setrlimit};

use crate::args::{Cli, Command};
use crate::env::Env;
use crate::terminal::{StdTerminal, Terminal};

fn main() -> ExitCode {
    // No core dump may hold keys or values (ADR 0006 section 6). Lowering a limit is always allowed.
    let zero = Rlimit {
        current: Some(0),
        maximum: Some(0),
    };
    if setrlimit(Resource::Core, zero).is_err() {
        return fail("error: could not disable core dumps", 1);
    }
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(e) => return usage_error(&e),
    };
    match cli.command {
        None => version(),
        Some(Command::Vault(cmd)) => {
            let mut term = StdTerminal::new();
            match vault_cmd::run(cmd, &Env::from_process(), &mut term) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    report(&e, &mut term);
                    ExitCode::from(e.exit_code())
                }
            }
        }
    }
}

/// Clap echoes the offending text for these kinds, and a value put on argv by mistake must not
/// reach a terminal log, so a fixed message replaces it. Help, version and the rest print as is.
fn usage_error(e: &clap::Error) -> ExitCode {
    match e.kind() {
        ErrorKind::UnknownArgument | ErrorKind::InvalidValue => fail(
            "error: invalid arguments; values are never arguments (run `wardenlens vault --help`)",
            2,
        ),
        _ => e.exit(),
    }
}

fn version() -> ExitCode {
    let mut out = io::stdout().lock();
    match writeln!(out, "wardenlens {}", wardenlens_core::VERSION) {
        Ok(()) => ExitCode::SUCCESS,
        // The only failure is that stdout is gone (e.g. a closed pipe); the exit code carries it.
        Err(_) => ExitCode::FAILURE,
    }
}

fn fail(message: &str, code: u8) -> ExitCode {
    // If stderr is gone there is nowhere left to report; the exit code carries the signal.
    let _ = writeln!(io::stderr(), "{message}");
    ExitCode::from(code)
}

/// Prints the error and its sources. Messages hold ids, kinds and rule names only.
fn report(e: &error::CliError, term: &mut impl Terminal) {
    let mut line = format!("error: {e}");
    let mut source = e.source();
    while let Some(s) = source {
        line.push_str(": ");
        line.push_str(&s.to_string());
        source = s.source();
    }
    // As in `fail`: nothing more can be done if stderr is closed.
    let _ = writeln!(term.err(), "{line}");
}
