//! Core domain logic for Wardenlens.
//!
//! This crate is pure: it performs no I/O, reads no environment and spawns no
//! threads. Adapters (CLI, network, storage) live in their own crates and
//! depend on this one, never the other way round.

/// Crate version, taken from `Cargo.toml` at compile time.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use super::VERSION;

    #[test]
    fn version_is_semver_like() {
        assert_eq!(VERSION.split('.').count(), 3);
    }
}
