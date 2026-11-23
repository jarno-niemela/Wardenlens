//! Reconnect backoff and per-camera connection state.
//!
//! Everything here is pure: time and randomness are injected, so adapters own
//! the real clock, the sockets and the timers (ARCH-1, ARCH-3). The retry
//! contract comes from ADR 0002 (hdipc): quick retries with a 2-5 s backoff,
//! then a total budget of at least three minutes before the camera is marked
//! degraded; retries continue in the background after that. Time types live in
//! [`crate::time`].

mod backoff;
mod state;

pub use backoff::{Backoff, JitterSource};
pub use state::{ConnectionPolicy, ConnectionState, Event, FailureKind, Outage, transition};
