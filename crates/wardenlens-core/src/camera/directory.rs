//! Read ports the API uses to serve cameras: [`CameraDirectory`] (what is configured) and
//! [`CameraStatus`] (what each connection is doing now).
//!
//! The composition root implements both: the directory over the registry plus the vault (host and
//! display name are sealed, ADR 0006), the status over the ingest `watch` channels. The API holds
//! neither a vault handle nor a credential, and a [`Camera`] carries none, so nothing that crosses
//! these ports can leak one.

use std::fmt;
use std::future::Future;

use super::{Camera, CameraId};
use crate::connection::{ConnectionState, FailureKind};
use crate::time::Timestamp;

/// A port failed; the cause is deliberately not carried to callers (it may name a path or a
/// vault entry).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DirectoryError;

impl fmt::Display for DirectoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("camera directory unavailable")
    }
}

impl std::error::Error for DirectoryError {}

/// Read access to the configured cameras.
pub trait CameraDirectory {
    /// Every camera, ordered by id.
    ///
    /// # Errors
    /// [`DirectoryError`] when the backing store fails.
    fn list(&self) -> impl Future<Output = Result<Vec<Camera>, DirectoryError>> + Send;

    /// One camera; `Ok(None)` when the id is unknown.
    ///
    /// # Errors
    /// [`DirectoryError`] when the backing store fails.
    fn get(
        &self,
        id: &CameraId,
    ) -> impl Future<Output = Result<Option<Camera>, DirectoryError>> + Send;
}

/// The coarse connection state exposed to clients. `Degraded` carries the most recent failure
/// kind, so a failure kind next to any other state cannot be represented.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LinkState {
    /// Connected and receiving.
    Streaming,
    /// An attempt is in flight.
    Connecting,
    /// Waiting to retry after a failure.
    Backoff,
    /// The retry budget is spent; the kind of the most recent failure.
    Degraded(FailureKind),
}

/// The live state of one camera connection, with a wall-clock `since`.
///
/// Only a failure *kind* is ever kept, never remote error text.
///
/// # The `since` rule
/// `since` is the wall-clock time at which the adapter saw the coarse [`LinkState`] begin (the
/// state machine's own clock is monotonic and cannot be shown to clients). The adapter must keep
/// it unchanged while the coarse state stays the same, for example across repeated failures in
/// `Degraded`.
///
/// A background retry while degraded is `ConnectionState::Connecting` carrying an outage with
/// `degraded_since`, and the failure kind is no longer in that value. [`LinkStatus::from_state`]
/// therefore reports `Connecting` for it, as it is, and the adapter records a new `since`. A
/// client sees `degraded`, `connecting`, `degraded` over a retry cycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkStatus {
    /// Where the connection is.
    pub state: LinkState,
    /// When it entered `state`, in wall-clock time.
    pub since: Timestamp,
}

impl LinkStatus {
    /// The status for a state machine value; `since` is the wall-clock time the adapter
    /// recorded when the coarse state was entered. This is the only mapping.
    #[must_use]
    pub fn from_state(state: &ConnectionState, since: Timestamp) -> Self {
        let state = match state {
            ConnectionState::Connecting { .. } => LinkState::Connecting,
            ConnectionState::Streaming { .. } => LinkState::Streaming,
            ConnectionState::Backoff { .. } => LinkState::Backoff,
            ConnectionState::Degraded {
                last_error_kind, ..
            } => LinkState::Degraded(*last_error_kind),
        };
        Self { state, since }
    }
}

/// Read access to live connection state.
pub trait CameraStatus {
    /// The status of `id`; `None` when no connection is supervised for it yet.
    fn status(&self, id: &CameraId) -> impl Future<Output = Option<LinkStatus>> + Send;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connection::Outage;
    use crate::time::MonoMs;

    fn outage() -> Outage {
        Outage {
            attempt: 1,
            start: MonoMs::from_millis(1),
            degraded_since: None,
        }
    }

    #[test]
    fn maps_every_connection_state() {
        let t = Timestamp::from_unix_millis(7);
        let retry = Outage {
            degraded_since: Some(MonoMs::from_millis(1)),
            ..outage()
        };
        let cases = [
            (ConnectionState::INITIAL, LinkState::Connecting),
            (
                ConnectionState::Streaming {
                    since: MonoMs::from_millis(1),
                    prior: None,
                },
                LinkState::Streaming,
            ),
            (
                ConnectionState::Backoff {
                    outage: outage(),
                    until: MonoMs::from_millis(9),
                },
                LinkState::Backoff,
            ),
            (
                ConnectionState::Degraded {
                    since: MonoMs::from_millis(1),
                    last_error_kind: FailureKind::Auth,
                    next_retry: MonoMs::from_millis(9),
                },
                LinkState::Degraded(FailureKind::Auth),
            ),
            // The kind is gone from a degraded retry: documented, reported as connecting.
            (
                ConnectionState::Connecting {
                    outage: Some(retry),
                    attempt_started: None,
                },
                LinkState::Connecting,
            ),
        ];
        for (state, want) in cases {
            let s = LinkStatus::from_state(&state, t);
            assert_eq!((s.state, s.since), (want, t));
        }
    }
}
