use std::future::{Future, ready};
use std::io;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use wardenlens_core::camera::{CameraId, CameraStatus, LinkState};
use wardenlens_core::connection::{Backoff, FailureKind};
use wardenlens_core::time::{DurationMs, MonoMs};
use wardenlens_ingest::{
    CancelToken, FrameSource, IngestError, InstantClock, SplitMixJitter, StreamSource, Supervisor,
    SupervisorConfig,
};

use super::super::status::{Links, track_link};
use super::super::wall_now;
use super::*;

fn at(ms: u64) -> MonoMs {
    MonoMs::from_millis(ms)
}

#[test]
fn the_first_failure_is_logged_and_identical_ones_are_held_back_for_a_minute() {
    let mut gate = LogGate::default();
    assert_eq!(gate.admit(FailureKind::Auth, at(1_000)), Some(0));
    // Every few seconds for 59 s: nothing.
    for k in 1..=19 {
        assert_eq!(gate.admit(FailureKind::Auth, at(1_000 + k * 3_000)), None);
    }
    // 59_000 ms after the first line is still inside the interval, 60_000 ms is not.
    assert_eq!(gate.admit(FailureKind::Auth, at(1_000 + 59_999)), None);
    // The 20 held back above are counted on the next line.
    assert_eq!(gate.admit(FailureKind::Auth, at(1_000 + 60_000)), Some(20));
    // The interval restarts at that line.
    assert_eq!(gate.admit(FailureKind::Auth, at(1_000 + 60_001)), None);
    assert_eq!(gate.admit(FailureKind::Auth, at(1_000 + 119_999)), None);
    assert_eq!(gate.admit(FailureKind::Auth, at(1_000 + 120_000)), Some(2));
}

#[test]
fn another_kind_is_logged_at_once_but_each_kind_has_its_own_interval() {
    let mut gate = LogGate::default();
    assert_eq!(gate.admit(FailureKind::Auth, at(0)), Some(0));
    assert_eq!(gate.admit(FailureKind::Timeout, at(2_000)), Some(0));
    // Alternating kinds cannot beat the limit: at most one line per kind per interval.
    for k in 2..40 {
        let kind = if k % 2 == 0 {
            FailureKind::Auth
        } else {
            FailureKind::Timeout
        };
        assert_eq!(gate.admit(kind, at(k * 1_000)), None, "{k}");
    }
    assert_eq!(gate.admit(FailureKind::Auth, at(60_000)), Some(19));
}

#[test]
fn a_recovery_makes_the_next_failure_loggable_and_a_backwards_clock_does_not_panic() {
    let mut gate = LogGate::default();
    assert_eq!(gate.admit(FailureKind::Refused, at(10_000)), Some(0));
    assert_eq!(gate.admit(FailureKind::Refused, at(12_000)), None);
    gate.reset();
    assert_eq!(gate.admit(FailureKind::Refused, at(13_000)), Some(0));
    // A `now` before the stored time is a contract violation: handled, never a panic.
    assert!(gate.admit(FailureKind::Refused, at(1)).is_some());
}

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

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Capture {
    type Writer = Capture;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// A process-wide capturing subscriber (a thread-local one loses to callsite interest cached by
/// parallel tests). Each test filters on a camera id of its own.
fn captured() -> String {
    static CAPTURE: OnceLock<Capture> = OnceLock::new();
    let capture = CAPTURE.get_or_init(|| {
        let capture = Capture::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(capture.clone())
            .with_max_level(tracing::Level::TRACE)
            .finish();
        let _ = tracing::subscriber::set_global_default(subscriber);
        capture
    });
    String::from_utf8_lossy(&capture.0.lock().unwrap()).into_owned()
}

/// A source that holds a synthetic host and credential, as a real one does, and always fails.
struct Failing {
    host: String,
    password: String,
}

struct Never;

impl FrameSource for Never {
    fn next_frame(
        &mut self,
    ) -> impl Future<Output = Result<Option<wardenlens_core::video::Frame>, IngestError>> + Send
    {
        ready(Ok(None))
    }
}

impl StreamSource for Failing {
    type Stream = Never;
    fn open(&mut self, _idle: Duration) -> impl Future<Output = Result<Never, IngestError>> + Send {
        // The source knows these; nothing of them may reach a log line or the status.
        let _ = (&self.host, &self.password);
        ready(Err(IngestError::AuthRejected))
    }
}

#[tokio::test]
async fn a_failing_session_logs_one_line_without_host_or_credential_and_feeds_the_status() {
    let host = "cam-host-6f1e.invalid.example";
    let password = "pw-Zk9-synthetic-secret";
    let id = CameraId::new("bo-log-a").unwrap();
    let links = Links::default();
    let cancel = CancelToken::new();
    let (frames, state, _dropped, task) = Supervisor::spawn_observed(
        Failing {
            host: host.to_owned(),
            password: password.to_owned(),
        },
        InstantClock::new(),
        Backoff::new(DurationMs::from_millis(1), DurationMs::from_millis(1)),
        SplitMixJitter::new(7),
        SupervisorConfig::default(),
        cancel.clone(),
        observer(id.clone(), links.clone(), wall_now),
    );
    tokio::spawn(track_link(id.clone(), state, links.clone(), wall_now));
    let _ = captured();
    // The supervisor floors the pause between attempts at 100 ms: wait for four failures.
    let status = loop {
        if let Some(s) = links.status(&id).await
            && s.attempts >= 4
        {
            break s;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    assert_eq!(status.last_failure.map(|f| f.kind), Some(FailureKind::Auth));
    assert!(status.attempts >= 4);
    assert!(matches!(
        status.state,
        LinkState::Backoff | LinkState::Connecting
    ));
    cancel.cancel();
    drop(frames);
    let _ = task.await;

    let out = captured();
    let ours: Vec<&str> = out.lines().filter(|l| l.contains("bo-log-a")).collect();
    // Four failures inside the interval: the first is logged, the rest are held back.
    assert_eq!(ours.len(), 1, "{ours:?}");
    let line = ours[0];
    assert!(line.contains("WARN"), "{line}");
    assert!(
        line.contains("kind=\"auth\"") || line.contains("kind=auth"),
        "{line}"
    );
    assert!(line.contains("attempt=1"), "{line}");
    assert!(line.contains("retry_in_ms="), "{line}");
    assert!(
        !out.contains(host) && !out.contains(password),
        "host or credential in the log"
    );
    assert!(!out.contains("invalid.example") && !out.contains("synthetic-secret"));
    let shown = format!("{status:?}");
    assert!(!shown.contains(host) && !shown.contains(password));
}
