//! Subcommands of the service config and later service commands (#64).
//!
//! Convention for a new command: add `src/commands/<name>.rs` exposing
//! `execute(cmd, &Context) -> ExitCode`, add its clap grammar to `args.rs` and one match arm in
//! `main.rs`. Errors are typed (`thiserror`), carry an `exit_code()` and are printed through
//! [`report_error`], which honours `--log-format`. The older `vault_cmd` module predates this
//! layout and keeps its own error type and terminal handling.

pub(crate) mod config;
pub(crate) mod health;
pub(crate) mod import;
pub(crate) mod secrets;
pub(crate) mod serve;
pub(crate) mod token;

use std::error::Error;
use std::io::{self, Write};

use crate::args::LogFormat;

/// What every command receives.
pub(crate) struct Context<'a> {
    pub(crate) env: &'a crate::env::Env,
    pub(crate) config_flag: Option<&'a std::path::Path>,
    pub(crate) log_format: LogFormat,
}

/// The error and its sources on one line. Some variants embed their source in their own message;
/// it is not printed twice.
pub(crate) fn error_chain(e: &dyn Error) -> String {
    let mut line = e.to_string();
    let mut source = e.source();
    while let Some(s) = source {
        let text = s.to_string();
        if !line.ends_with(&text) {
            line.push_str(": ");
            line.push_str(&text);
        }
        source = s.source();
    }
    line
}

/// Writes the failure to stderr regardless of `RUST_LOG`: `error: <chain>` as text, or one JSON
/// object per line under `--log-format json` (`level`, `fields.message`, `target`; unlike the
/// subscriber's lines it has no timestamp).
pub(crate) fn report_error(e: &dyn Error, format: LogFormat) {
    let chain = error_chain(e);
    let line = match format {
        LogFormat::Text => format!("error: {chain}"),
        LogFormat::Json => serde_json::json!({
            "level": "ERROR",
            "fields": { "message": chain },
            "target": "wardenlens",
        })
        .to_string(),
    };
    // If stderr is gone there is nowhere left to report; the exit code carries the signal.
    let _ = writeln!(io::stderr(), "{line}");
}

/// A refused combination of arguments: reported like any error, exit 2.
pub(crate) fn usage_failure(message: &'static str, format: LogFormat) -> std::process::ExitCode {
    #[derive(Debug, thiserror::Error)]
    #[error("{0}")]
    struct Usage(&'static str);
    report_error(&Usage(message), format);
    std::process::ExitCode::from(2)
}
