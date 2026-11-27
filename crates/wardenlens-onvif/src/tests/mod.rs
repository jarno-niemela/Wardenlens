//! Tests. Each module enumerates one input space (TEST-9) and says which.
#![expect(
    clippy::arithmetic_side_effects,
    reason = "test code: small bounded counters and readable string building"
)]

mod client;
mod discovery;
mod discovery_adv;
mod discovery_adversary;
mod fixtures;
mod leaks;
mod limits;
mod parse;
mod props;
mod server;
mod stream_uri;
