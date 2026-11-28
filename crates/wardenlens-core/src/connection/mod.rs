//! Reconnect backoff and per-camera connection state.
//!
//! Everything here is pure: time and randomness are injected, so adapters own
//! the real clock, the sockets and the timers (ARCH-1, ARCH-3). The retry
//! contract is general camera behaviour measured in ADR 0002, not tuning for
//! one installation: quick retries with a 2-5 s backoff, then a total budget
//! of at least three minutes before the camera is marked degraded; retries
//! continue in the background after that. The defaults are generic and the
//! policy is configurable by type (`ConnectionPolicy`). Time types live in
//! [`crate::time`].

mod backoff;
mod state;

pub use backoff::{Backoff, JitterSource};
pub use state::{ConnectionPolicy, ConnectionState, Event, FailureKind, Outage, transition};
