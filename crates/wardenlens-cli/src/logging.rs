//! Logging to stderr through tracing-subscriber (ADR 0004 section 5). stdout is for command
//! output only. The level comes from `RUST_LOG` (default `info`); a value that does not parse is
//! not echoed, the default is used and a warning says so. No event carries a config value.
//!
//! Records of the `retina` target never pass below `error`, whatever `RUST_LOG` says: its `warn`
//! records carry peer addresses and URLs (ADR 0002 section 13, #155). No `log` bridge is
//! installed today, so nothing from retina is printed at all; the cap holds the day one is added
//! (the `tracing-log` feature of tracing-subscriber and a `LogTracer`).

use std::ffi::OsStr;
use std::io;

use tracing_subscriber::EnvFilter;

use crate::args::LogFormat;
use crate::env::Env;

/// The only level at which the `retina` target may log.
const RETINA_DIRECTIVE: &str = "retina=error";

/// Whether one `RUST_LOG` directive names the `retina` target (or a module of it). The target is
/// what precedes `=` or `[`; a bare level (`debug`) is not a target.
fn names_retina(directive: &str) -> bool {
    let target = directive
        .split(['=', '['])
        .next()
        .unwrap_or_default()
        .trim();
    target == "retina" || target.starts_with("retina::")
}

/// The filter for a `RUST_LOG` value, and whether it was invalid. Directives for `retina` are
/// removed from what the user wrote (a more specific one such as `retina::client=trace` would
/// beat the cap), then the cap is added.
fn build_filter(rust_log: Option<&OsStr>) -> (EnvFilter, bool) {
    let default = || EnvFilter::new(format!("info,{RETINA_DIRECTIVE}"));
    let Some(v) = rust_log else {
        return (default(), false);
    };
    let Some(text) = v.to_str() else {
        return (default(), true);
    };
    let kept: Vec<&str> = text.split(',').filter(|d| !names_retina(d)).collect();
    match EnvFilter::try_new(format!("{},{RETINA_DIRECTIVE}", kept.join(","))) {
        Ok(f) => (f, false),
        Err(_) => (default(), true),
    }
}

/// Installs the global subscriber. A second call (or a subscriber installed elsewhere) is
/// ignored.
pub(crate) fn init(format: LogFormat, env: &Env) {
    let (filter, bad_directive) = build_filter(env.rust_log.as_deref());
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

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use tracing_subscriber::fmt::MakeWriter;

    use super::*;

    #[derive(Clone, Default)]
    struct Capture(Arc<Mutex<Vec<u8>>>);

    impl io::Write for Capture {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            if let Ok(mut v) = self.0.lock() {
                v.extend_from_slice(buf);
            }
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl MakeWriter<'_> for Capture {
        type Writer = Capture;
        fn make_writer(&self) -> Capture {
            self.clone()
        }
    }

    /// Emits one record per (target, level) through the filter built for `rust_log` and returns
    /// what was printed.
    fn printed(rust_log: Option<&str>) -> String {
        let (filter, _) = build_filter(rust_log.map(OsStr::new));
        let cap = Capture::default();
        let sub = tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_writer(cap.clone())
            .finish();
        tracing::subscriber::with_default(sub, || {
            tracing::error!(target: "retina", "r-error");
            tracing::warn!(target: "retina", "r-warn 192.0.2.7");
            tracing::info!(target: "retina::client", "r-info");
            tracing::debug!(target: "retina::client::rtp", "r-debug");
            tracing::trace!(target: "retina", "r-trace");
            tracing::error!(target: "retina::client", "rc-error");
            tracing::warn!(target: "other", "o-warn");
            tracing::info!(target: "other", "o-info");
            tracing::debug!(target: "other", "o-debug");
        });
        let bytes = cap.0.lock().map_or_else(|_| Vec::new(), |v| v.clone());
        String::from_utf8_lossy(&bytes).into_owned()
    }

    /// Whichever `RUST_LOG` the user sets, retina prints `error` records and nothing quieter.
    #[test]
    fn the_retina_target_is_filtered_below_error() {
        let rows = [
            None,
            Some(""),
            Some("info"),
            Some("debug"),
            Some("trace"),
            Some("warn"),
            Some("retina=trace"),
            Some("retina=debug,other=debug"),
            Some("retina::client=trace"),
            Some("retina::client::rtp=trace,retina=info"),
            Some("debug,retina"),
            Some("retina[span]=trace"),
            Some(" retina = trace "),
            Some("trace,retina=trace,retina::client=trace"),
            // Invalid: the fallback applies, and it caps retina too.
            Some("retina=bogus"),
            Some("other=bogus,retina=trace"),
            Some("=="),
        ];
        for rust_log in rows {
            let out = printed(rust_log);
            for quiet in ["r-warn", "r-info", "r-debug", "r-trace", "192.0.2.7"] {
                assert!(!out.contains(quiet), "{rust_log:?}: {quiet} in {out}");
            }
            assert!(out.contains("r-error"), "{rust_log:?}: {out}");
            assert!(out.contains("rc-error"), "{rust_log:?}: {out}");
        }
    }

    /// The cap does not silence the other targets, and `RUST_LOG` still sets their level.
    #[test]
    fn other_targets_keep_the_requested_level() {
        let out = printed(None);
        assert!(out.contains("o-warn") && out.contains("o-info") && !out.contains("o-debug"));
        let out = printed(Some("debug"));
        assert!(out.contains("o-debug"), "{out}");
        let out = printed(Some("warn"));
        assert!(out.contains("o-warn") && !out.contains("o-info"), "{out}");
        let out = printed(Some("retina=trace,other=debug"));
        assert!(out.contains("o-debug"), "{out}");
    }

    #[test]
    fn only_the_retina_target_is_recognised() {
        for yes in [
            "retina",
            " retina=trace",
            "retina::client=debug",
            "retina[x]=info",
        ] {
            assert!(names_retina(yes), "{yes}");
        }
        for no in [
            "",
            "debug",
            "retinal=debug",
            "other::retina=debug",
            "info",
            "x=retina",
        ] {
            assert!(!names_retina(no), "{no}");
        }
    }

    #[test]
    fn an_invalid_value_is_reported_and_still_capped() {
        assert!(build_filter(Some(OsStr::new("other=bogus"))).1);
        assert!(build_filter(Some(OsStr::new("retina=trace,other=bogus"))).1);
        assert!(!build_filter(Some(OsStr::new("debug"))).1);
        assert!(!build_filter(None).1);
    }
}
