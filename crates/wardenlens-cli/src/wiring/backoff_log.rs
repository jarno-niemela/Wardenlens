//! Why a camera is backing off: one rate-limited `warn` line per failure, and the failure record
//! the API serves (`connection.last_failure`, `connection.attempts`).
//!
//! A log line carries the camera id (a slug), the failure kind, the attempt number and the retry
//! delay, and nothing else: never a host, URL, path, query or credential, and never error text
//! (the supervisor only knows a [`FailureKind`]). A dead camera retries every few seconds, so
//! repeated failures of one kind are logged the first time and then at most once per
//! [`REPEAT_INTERVAL`], with a count of the lines held back. The interval runs on the monotonic
//! clock the supervisor stamps notices with, which tests set by hand.

use wardenlens_core::camera::CameraId;
use wardenlens_core::connection::FailureKind;
use wardenlens_core::time::{DurationMs, MonoMs, Timestamp};
use wardenlens_ingest::{ConnectionNotice, FailureNote};

use super::status::Links;

/// The least time between two log lines for the same failure kind of one camera.
pub(crate) const REPEAT_INTERVAL: DurationMs = DurationMs::from_secs(60);

/// Decides which failures are logged. One value per camera; it holds at most one entry per
/// failure kind, so its size is bounded by the kinds that exist.
#[derive(Debug, Default)]
pub(crate) struct LogGate {
    /// Per kind: when it was last logged and how many failures were held back since.
    kinds: Vec<(FailureKind, MonoMs, u32)>,
}

impl LogGate {
    /// `Some(held_back)` when a failure of `kind` at `now` is to be logged: the number of
    /// failures of that kind held back since its last line. `None` when it is held back.
    pub(crate) fn admit(&mut self, kind: FailureKind, now: MonoMs) -> Option<u32> {
        let Some((_, last, held)) = self.kinds.iter_mut().find(|(k, ..)| *k == kind) else {
            self.kinds.push((kind, now, 0));
            return Some(0);
        };
        if now >= *last && now.saturating_duration_since(*last) < REPEAT_INTERVAL {
            *held = held.saturating_add(1);
            return None;
        }
        *last = now;
        Some(std::mem::take(held))
    }

    /// The outage is over: the next failure is logged again.
    pub(crate) fn reset(&mut self) {
        self.kinds.clear();
    }
}

/// The fixed name of a failure kind, as the API spells it.
fn kind_name(kind: FailureKind) -> &'static str {
    match kind {
        FailureKind::Timeout => "timeout",
        FailureKind::Refused => "refused",
        FailureKind::Auth => "auth",
        FailureKind::Protocol => "protocol",
        // `FailureKind` is non-exhaustive: a kind added later is named `other`.
        _ => "other",
    }
}

fn log_failure(camera: &CameraId, note: &FailureNote, held_back: u32) {
    if note.degraded {
        tracing::warn!(
            camera = %camera,
            kind = kind_name(note.kind),
            attempt = note.attempt,
            retry_in_ms = note.retry_in.as_millis(),
            held_back,
            "camera is degraded: the retry budget is spent, retrying in the background"
        );
    } else {
        tracing::warn!(
            camera = %camera,
            kind = kind_name(note.kind),
            attempt = note.attempt,
            retry_in_ms = note.retry_in.as_millis(),
            held_back,
            "camera connection failed, backing off"
        );
    }
}

/// The supervisor observer of `camera`: records every failure for the API and logs the ones the
/// gate admits. `wall` stamps the record with wall-clock time.
pub(crate) fn observer(
    camera: CameraId,
    links: Links,
    wall: impl Fn() -> Timestamp + Send + 'static,
) -> impl FnMut(ConnectionNotice) + Send + 'static {
    let mut gate = LogGate::default();
    move |notice| match notice {
        ConnectionNotice::Failed(note) => {
            links.record_failure(&camera, note.kind, wall(), note.attempt);
            if let Some(held_back) = gate.admit(note.kind, note.at) {
                log_failure(&camera, &note, held_back);
            }
        }
        ConnectionNotice::Recovered => {
            links.record_recovery(&camera);
            gate.reset();
        }
        // A notice added later is not logged until it is handled here.
        _ => {}
    }
}

#[cfg(test)]
mod tests;
