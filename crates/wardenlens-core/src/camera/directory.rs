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

/// The coarse connection state exposed to clients.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LinkState {
    /// Connected and receiving.
    Streaming,
    /// An attempt is in flight.
    Connecting,
    /// Waiting to retry after a failure.
    Backoff,
    /// The retry budget is spent.
    Degraded,
}

/// The live state of one camera connection, with a wall-clock `since`.
///
/// Only a failure *kind* is kept, never remote error text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkStatus {
    /// Where the connection is.
    pub state: LinkState,
    /// When it entered `state` (wall clock; the state machine's own clock is monotonic).
    pub since: Timestamp,
    /// The most recent failure kind, known only while degraded.
    pub error_kind: Option<FailureKind>,
}

impl LinkStatus {
    /// The status for a state machine value; `since` is the wall-clock time the adapter
    /// recorded when the state was entered.
    #[must_use]
    pub fn from_state(state: &ConnectionState, since: Timestamp) -> Self {
        let (state, error_kind) = match state {
            ConnectionState::Connecting { .. } => (LinkState::Connecting, None),
            ConnectionState::Streaming { .. } => (LinkState::Streaming, None),
            ConnectionState::Backoff { .. } => (LinkState::Backoff, None),
            ConnectionState::Degraded {
                last_error_kind, ..
            } => (LinkState::Degraded, Some(*last_error_kind)),
        };
        Self {
            state,
            since,
            error_kind,
        }
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
        let cases = [
            (ConnectionState::INITIAL, LinkState::Connecting, None),
            (
                ConnectionState::Streaming {
                    since: MonoMs::from_millis(1),
                    prior: None,
                },
                LinkState::Streaming,
                None,
            ),
            (
                ConnectionState::Backoff {
                    outage: outage(),
                    until: MonoMs::from_millis(9),
                },
                LinkState::Backoff,
                None,
            ),
            (
                ConnectionState::Degraded {
                    since: MonoMs::from_millis(1),
                    last_error_kind: FailureKind::Auth,
                    next_retry: MonoMs::from_millis(9),
                },
                LinkState::Degraded,
                Some(FailureKind::Auth),
            ),
        ];
        for (state, want, kind) in cases {
            let s = LinkStatus::from_state(&state, t);
            assert_eq!((s.state, s.error_kind, s.since), (want, kind, t));
        }
    }
}
