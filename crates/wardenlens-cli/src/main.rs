//! Wardenlens command-line entry point.
//!
//! Keep this file thin: parse arguments, call into the libraries, map errors to exit codes.

mod args;
mod commands;
mod config_file;
mod env;
mod error;
mod logging;
mod terminal;
mod vault_cmd;
mod wiring;

use std::error::Error;
use std::io::{self, Write};
use std::process::ExitCode;

use clap::Parser;
use clap::error::ErrorKind;
use rustix::process::{Resource, Rlimit, setrlimit};

use crate::args::{Cli, Command, LogFormat};
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
        Err(e) => return usage_error(&e, json_requested(std::env::args_os())),
    };
    let env = Env::from_process();
    let format = cli.log_format.unwrap_or(LogFormat::Text);
    let ctx = commands::Context {
        env: &env,
        config_flag: cli.config.as_deref(),
        log_format: format,
    };
    match cli.command {
        None => {
            if cli.config.is_some() {
                return commands::usage_failure(
                    "--config needs a subcommand (try `config check`)",
                    format,
                );
            }
            logging::init(format, &env);
            version()
        }
        Some(Command::Config(cmd)) => {
            logging::init(format, &env);
            commands::config::execute(&cmd, &ctx)
        }
        Some(Command::Import(cmd)) => {
            logging::init(format, &env);
            commands::import::execute(&cmd, &ctx)
        }
        Some(Command::Secrets(cmd)) => {
            logging::init(format, &env);
            commands::secrets::execute(&cmd, &ctx)
        }
        Some(Command::Token(cmd)) => {
            logging::init(format, &env);
            commands::token::execute(&cmd, &ctx)
        }
        Some(Command::Serve) => {
            logging::init(format, &env);
            commands::serve::execute(&ctx)
        }
        Some(Command::Vault(cmd)) => {
            // `--config` and `--log-format` are global for the grammar, but the vault has fixed
            // paths (ADR 0006) and does not log: a flag that would be ignored is refused, as it
            // was before the flags existed. No logging is set up, so `RUST_LOG` cannot change
            // the vault's output.
            if cli.config.is_some() || cli.log_format.is_some() {
                return commands::usage_failure(
                    "--config and --log-format do not apply to the vault commands",
                    format,
                );
            }
            let mut term = StdTerminal::new();
            match vault_cmd::run(cmd, &env, &mut term) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    report(&e, &mut term);
                    ExitCode::from(e.exit_code())
                }
            }
        }
    }
}

/// Clap echoes the offending text in most error kinds, and a value put on argv by mistake must not
/// reach a terminal log. Only kinds known to echo nothing pass through; every other kind (and any
/// kind added later) gets a fixed message.
///
/// Clap fails before the log format is known, so argv is pre-scanned for exactly `--log-format
/// json` or `--log-format=json` (nothing else is read from it) and, under it, a usage error is one
/// fixed JSON line. Help and version output are not errors and stay as clap prints them.
fn usage_error(e: &clap::Error, json: bool) -> ExitCode {
    match e.kind() {
        ErrorKind::DisplayHelp | ErrorKind::DisplayVersion => e.exit(),
        _ if json => commands::usage_failure("invalid arguments", LogFormat::Json),
        ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand
        | ErrorKind::MissingRequiredArgument
        | ErrorKind::MissingSubcommand => e.exit(),
        _ => fail(
            "error: invalid arguments; values are never arguments (run `wardenlens --help`)",
            2,
        ),
    }
}

/// True if argv holds exactly `--log-format json` or `--log-format=json`.
fn json_requested(args: impl Iterator<Item = std::ffi::OsString>) -> bool {
    let args: Vec<_> = args.collect();
    args.iter().any(|a| a == "--log-format=json")
        || args
            .windows(2)
            .any(|w| matches!(w, [f, v] if f == "--log-format" && v == "json"))
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
        let text = s.to_string();
        // Some variants embed their source in their own message; do not print it twice.
        if !line.ends_with(&text) {
            line.push_str(": ");
            line.push_str(&text);
        }
        source = s.source();
    }
    // As in `fail`: nothing more can be done if stderr is closed.
    let _ = writeln!(term.err(), "{line}");
}
