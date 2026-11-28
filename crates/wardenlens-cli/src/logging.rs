//! Logging to stderr through tracing-subscriber (ADR 0004 section 5). stdout is for command
//! output only. The level comes from `RUST_LOG` (default `info`); a value that does not parse is
//! not echoed, the default is used and a warning says so. No event carries a config value.
//!
//! Records of the `retina` target never pass below `error`, whatever `RUST_LOG` says: its `warn`
//! records carry peer addresses and URLs (ADR 0002 section 14, #155). The cap is a separate
//! `Targets` filter on the fmt layer, AND-ed with the `RUST_LOG` filter. No `log` bridge is
//! installed today, so nothing from retina is printed at all; the cap holds the day one is added
//! (the `tracing-log` feature of tracing-subscriber and a `LogTracer`).

use std::ffi::OsStr;
use std::io;

use tracing::Subscriber;
use tracing_subscriber::filter::{FilterExt, LevelFilter, Targets};
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::{EnvFilter, Layer};

use crate::args::LogFormat;
use crate::env::Env;

/// The cap on the `retina` target: a filter of its own, AND-ed with the `RUST_LOG` filter, so no
/// spelling of a directive (prefix forms, span scopes, a more specific module) can loosen it.
fn retina_cap() -> Targets {
    Targets::new()
        .with_default(LevelFilter::TRACE)
        .with_target("retina", LevelFilter::ERROR)
}

/// The `RUST_LOG` filter, and whether the value was invalid (then the default `info` is used).
fn build_filter(rust_log: Option<&OsStr>) -> (EnvFilter, bool) {
    let Some(v) = rust_log else {
        return (EnvFilter::new("info"), false);
    };
    // An empty or blank value would mean "nothing but errors"; it is the same as no value.
    if v.to_str().is_some_and(|t| t.trim().is_empty()) {
        return (EnvFilter::new("info"), false);
    }
    match v.to_str().map(EnvFilter::try_new) {
        Some(Ok(f)) => (f, false),
        _ => (EnvFilter::new("info"), true),
    }
}

/// The subscriber: one fmt layer whose filter is the `RUST_LOG` filter and the retina cap.
fn subscriber<W>(
    format: LogFormat,
    env_filter: EnvFilter,
    writer: W,
) -> impl Subscriber + Send + Sync
where
    W: for<'w> MakeWriter<'w> + Send + Sync + 'static,
{
    let filter = env_filter.and(retina_cap());
    let layer: Box<dyn Layer<_> + Send + Sync> = match format {
        LogFormat::Text => tracing_subscriber::fmt::layer()
            .with_writer(writer)
            .with_filter(filter)
            .boxed(),
        LogFormat::Json => tracing_subscriber::fmt::layer()
            .json()
            .with_writer(writer)
            .with_filter(filter)
            .boxed(),
    };
    tracing_subscriber::registry().with(layer)
}

/// Installs the global subscriber. A second call (or a subscriber installed elsewhere) is
/// ignored.
pub(crate) fn init(format: LogFormat, env: &Env) {
    let (filter, bad_directive) = build_filter(env.rust_log.as_deref());
    let installed = tracing::subscriber::set_global_default(subscriber(format, filter, io::stderr));
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
        let sub = subscriber(LogFormat::Text, filter, cap.clone());
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

    /// Rows of the table below whose filter does not enable the bare `retina` target.
    const SUB_TARGET_OR_SPAN_ONLY: [Option<&str>; 4] = [
        Some("retina::client=trace"),
        Some("retina[span]=trace"),
        Some("retina:=trace"),
        Some("[sp]=trace"),
    ];

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
            Some("retina:=trace"),
            Some("[sp]=trace"),
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
            // Errors still get through wherever the filter enables retina at error. A directive
            // that names only other targets, or only spans (`retina::client=trace`, `[sp]=trace`),
            // leaves the unnamed ones off, as for any target; the sub-target still prints its error.
            if !SUB_TARGET_OR_SPAN_ONLY.contains(&rust_log) {
                assert!(out.contains("r-error"), "{rust_log:?}: {out}");
            }
            if rust_log == Some("retina::client=trace")
                || !SUB_TARGET_OR_SPAN_ONLY.contains(&rust_log)
            {
                assert!(out.contains("rc-error"), "{rust_log:?}: {out}");
            }
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

    /// The JSON layer carries the same cap.
    #[test]
    fn the_json_format_is_capped_too() {
        let (filter, _) = build_filter(Some(OsStr::new("trace")));
        let cap = Capture::default();
        let sub = subscriber(LogFormat::Json, filter, cap.clone());
        tracing::subscriber::with_default(sub, || {
            tracing::warn!(target: "retina", "r-warn");
            tracing::warn!(target: "other", "o-warn");
        });
        let bytes = cap.0.lock().map_or_else(|_| Vec::new(), |v| v.clone());
        let out = String::from_utf8_lossy(&bytes).into_owned();
        assert!(out.contains("o-warn") && !out.contains("r-warn"), "{out}");
    }

    #[test]
    fn an_invalid_value_is_reported_and_still_capped() {
        assert!(build_filter(Some(OsStr::new("other=bogus"))).1);
        assert!(build_filter(Some(OsStr::new("retina=trace,other=bogus"))).1);
        assert!(build_filter(Some(OsStr::new("retina=bogus"))).1);
        assert!(!build_filter(Some(OsStr::new("debug"))).1);
        assert!(!build_filter(None).1);
    }

    /// Adversary #155: directive spellings that tracing-subscriber matches against the `retina`
    /// target in unexpected ways (prefix matching, span scopes), with the events inside a span.
    fn printed_in_span(rust_log: &str) -> String {
        let (filter, _) = build_filter(Some(OsStr::new(rust_log)));
        let cap = Capture::default();
        let sub = subscriber(LogFormat::Text, filter, cap.clone());
        tracing::subscriber::with_default(sub, || {
            let span = tracing::error_span!("camera");
            let _g = span.enter();
            tracing::warn!(target: "retina::client", "r-warn 192.0.2.7");
            tracing::debug!(target: "retina", "r-debug");
        });
        let bytes = cap.0.lock().map_or_else(|_| Vec::new(), |v| v.clone());
        String::from_utf8_lossy(&bytes).into_owned()
    }

    #[test]
    fn adv_retina_cap_holds_for_prefix_and_span_directives() {
        let mut leaks = Vec::new();
        for rust_log in [
            "retina:=trace",
            "retina:=warn",
            "[camera]=trace",
            "[camera]=warn",
            "[]=trace",
            "[{x}]=trace",
            "retina::=trace",
            "retina=trace,retina:=trace",
        ] {
            let out = printed_in_span(rust_log);
            if out.contains("r-warn") || out.contains("r-debug") {
                leaks.push(format!("in span {rust_log:?}: {out}"));
            }
            let out = printed(Some(rust_log));
            if ["r-warn", "r-info", "r-debug", "r-trace"]
                .iter()
                .any(|q| out.contains(q))
            {
                leaks.push(format!("{rust_log:?}: {out}"));
            }
        }
        assert!(
            leaks.is_empty(),
            "retina records below error printed:\n{}",
            leaks.join("\n")
        );
    }

    /// Emits through `subscriber` with `rust_log` and `format`, returns what was printed.
    fn capture_with(rust_log: &str, format: LogFormat, f: impl FnOnce()) -> String {
        let (filter, _) = build_filter(Some(OsStr::new(rust_log)));
        let cap = Capture::default();
        let sub = subscriber(format, filter, cap.clone());
        tracing::subscriber::with_default(sub, f);
        let bytes = cap.0.lock().map_or_else(|_| Vec::new(), |v| v.clone());
        String::from_utf8_lossy(&bytes).into_owned()
    }

    /// Adversary #155 r2: span-scoped directives still work for other targets through the `And`
    /// combinator (span enter/exit must reach the `EnvFilter`).
    #[test]
    fn adv_r2_span_scoped_directive_still_enables_other_targets() {
        for format in [LogFormat::Text, LogFormat::Json] {
            let out = capture_with("warn,[camera]=debug", format, || {
                tracing::debug!(target: "other", "outside-debug");
                let span = tracing::info_span!("camera", id = 1);
                let _g = span.enter();
                tracing::debug!(target: "other", "inside-debug");
                tracing::debug!(target: "retina::client", "r-inside-debug");
            });
            assert!(out.contains("inside-debug"), "{out}");
            assert!(!out.contains("outside-debug"), "{out}");
            assert!(!out.contains("r-inside-debug"), "{out}");
        }
    }

    /// Adversary #155 r2: span field-value directives (dynamic filtering) still work.
    #[test]
    fn adv_r2_field_value_span_directive_still_works() {
        let out = capture_with("warn,[camera{id=7}]=debug", LogFormat::Text, || {
            let a = tracing::info_span!("camera", id = 7);
            a.in_scope(|| tracing::debug!(target: "other", "seven-debug"));
            let b = tracing::info_span!("camera", id = 8);
            b.in_scope(|| tracing::debug!(target: "other", "eight-debug"));
            a.in_scope(|| tracing::debug!(target: "retina", "r-seven-debug"));
        });
        assert!(out.contains("seven-debug"), "{out}");
        assert!(!out.contains("eight-debug"), "{out}");
        assert!(!out.contains("r-seven-debug"), "{out}");
    }

    /// Adversary #155 r2: retina records in JSON at every level, with `retina` in a span name or
    /// field, and an event whose fields name retina, never pass below error.
    #[test]
    fn adv_r2_json_cap_matrix() {
        for rust_log in [
            "trace",
            "retina=trace",
            "retina::client=trace",
            "[retina]=trace",
            "retina:=trace",
            "  ",
        ] {
            let out = capture_with(rust_log, LogFormat::Json, || {
                let span = tracing::error_span!(target: "retina", "retina", peer = "192.0.2.9");
                let _g = span.enter();
                tracing::warn!(target: "retina", peer = "192.0.2.7", "r-warn");
                tracing::info!(target: "retina::client::rtp", "r-info");
                tracing::trace!(target: "retina", "r-trace");
            });
            for q in ["r-warn", "r-info", "r-trace", "192.0.2.7"] {
                assert!(!out.contains(q), "{rust_log:?}: {q} in {out}");
            }
        }
    }

    /// Adversary #155 r2: a whitespace-only value is treated like an empty one (the default info).
    #[test]
    fn adv_r2_whitespace_only_rust_log_means_the_default() {
        let out = capture_with("  ", LogFormat::Text, || {
            tracing::info!(target: "other", "o-info");
        });
        assert!(out.contains("o-info"), "{out:?}");
    }
}
