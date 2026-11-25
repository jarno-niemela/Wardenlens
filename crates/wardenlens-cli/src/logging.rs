//! Logging to stderr through tracing-subscriber (ADR 0004 section 5). stdout is for command
//! output only. The level comes from `RUST_LOG` (default `info`); a value that does not parse is
//! not echoed, the default is used and a warning says so. No event carries a config value.

use std::io;

use tracing_subscriber::EnvFilter;

use crate::args::LogFormat;
use crate::env::Env;

/// Installs the global subscriber. A second call (or a subscriber installed elsewhere) is
/// ignored.
pub(crate) fn init(format: LogFormat, env: &Env) {
    let (filter, bad_directive) = match env.rust_log.as_deref() {
        None => (EnvFilter::new("info"), false),
        Some(v) => match v.to_str().map(EnvFilter::try_new) {
            Some(Ok(f)) => (f, false),
            _ => (EnvFilter::new("info"), true),
        },
    };
    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(io::stderr);
    let installed = match format {
        LogFormat::Text => builder.try_init(),
        LogFormat::Json => builder.json().try_init(),
    };
    if installed.is_ok() && bad_directive {
        tracing::warn!("RUST_LOG is not a valid filter; using the default level info");
    }
}
