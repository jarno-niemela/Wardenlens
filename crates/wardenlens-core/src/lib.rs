//! Core domain logic for Wardenlens.
//!
//! This crate is pure: it performs no I/O, reads no environment and spawns no
//! threads. Adapters (CLI, network, storage) live in their own crates and
//! depend on this one, never the other way round.

pub mod mp4box;

/// Crate version, taken from `Cargo.toml` at compile time.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use super::VERSION;

    #[test]
    fn version_is_semver_like() {
        assert_eq!(VERSION.split('.').count(), 3);
    }

    // Adversarial: every component must be a number (the existing test accepts "a.b.c"),
    // and unwrap/indexing in tests must be accepted by the lint config (clippy.toml claims so).
    #[test]
    fn version_components_are_numeric() {
        let parts: Vec<u64> = VERSION.split('.').map(|p| p.parse().unwrap()).collect();
        assert_eq!(parts.len(), 3);
        assert!(parts[0] < 1000);
    }
}
