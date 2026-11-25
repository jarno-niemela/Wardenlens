//! `wardenlens config check`.
//!
//! Prints the listen address, both roots with their free-space floors, the segment target and
//! the database and key-file paths. The key file is never opened. Interface scope ids such as
//! `%eth0` are not resolved: core refuses a named scope in `api.listen` and so does this
//! command (exit 1).

use std::io::{self, Write};
use std::process::ExitCode;

use wardenlens_core::config::Config;

use super::{Context, report_error};
use crate::args::ConfigCommand;
use crate::config_file::{ConfigFileError, load, resolve_path};

pub(crate) fn execute(cmd: &ConfigCommand, ctx: &Context<'_>) -> ExitCode {
    let result = match cmd {
        ConfigCommand::Check => check(ctx),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            report_error(&e, ctx.log_format);
            ExitCode::from(e.exit_code())
        }
    }
}

fn check(ctx: &Context<'_>) -> Result<(), ConfigFileError> {
    let path = resolve_path(ctx.config_flag, ctx.env)?;
    let config = load(&path)?;
    summary(&config, &mut io::stdout().lock()).map_err(ConfigFileError::Output)
}

fn summary(c: &Config, out: &mut impl Write) -> io::Result<()> {
    let policy = c.storage_policy();
    writeln!(out, "listen: {}", c.listen())?;
    writeln!(
        out,
        "hot_root: {} (min free {}%)",
        c.hot_root().display(),
        policy.hot_min_free.get()
    )?;
    writeln!(
        out,
        "archive_root: {} (min free {}%)",
        c.archive_root().display(),
        policy.archive_min_free.get()
    )?;
    writeln!(out, "segment_target_secs: {}", c.segment_target_secs())?;
    writeln!(out, "database: {}", c.database_path().display())?;
    writeln!(out, "key_file: {}", c.key_file().display())?;
    out.flush()
}
