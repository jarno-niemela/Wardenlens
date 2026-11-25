//! Tests. Each module enumerates one input space (TEST-9) and states which.
#![expect(
    clippy::arithmetic_side_effects,
    clippy::format_push_string,
    reason = "test code: small bounded counters and readable string building"
)]

mod document;
mod fields;
mod fixtures;
mod identity;
mod leaks;
mod props;
mod source;

use crate::SkipReason;

/// Every skip reason. Adding a variant is a compile error in `index` until it is listed here, and
/// the tests that loop over this list then need a row for it.
pub(crate) const ALL_SKIPS: [SkipReason; 17] = [
    SkipReason::Deleted,
    SkipReason::RepeatedElement,
    SkipReason::FieldTooLong,
    SkipReason::MissingName,
    SkipReason::NameRefused,
    SkipReason::NoSource,
    SkipReason::NotAUrl,
    SkipReason::UnsupportedScheme,
    SkipReason::InvalidUrl,
    SkipReason::InvalidHost,
    SkipReason::InvalidPort,
    SkipReason::InvalidPath,
    SkipReason::CredentialInPath,
    SkipReason::InvalidCredential,
    SkipReason::CredentialWithoutUser,
    SkipReason::ConflictingCredential,
    SkipReason::IdRefused,
];

#[test]
fn all_skips_is_complete_and_unique() {
    fn index(r: SkipReason) -> usize {
        match r {
            SkipReason::Deleted => 0,
            SkipReason::RepeatedElement => 1,
            SkipReason::FieldTooLong => 2,
            SkipReason::MissingName => 3,
            SkipReason::NameRefused => 4,
            SkipReason::NoSource => 5,
            SkipReason::NotAUrl => 6,
            SkipReason::UnsupportedScheme => 7,
            SkipReason::InvalidUrl => 8,
            SkipReason::InvalidHost => 9,
            SkipReason::InvalidPort => 10,
            SkipReason::InvalidPath => 11,
            SkipReason::CredentialInPath => 12,
            SkipReason::InvalidCredential => 13,
            SkipReason::CredentialWithoutUser => 14,
            SkipReason::ConflictingCredential => 15,
            SkipReason::IdRefused => 16,
        }
    }
    let seen: std::collections::BTreeSet<usize> = ALL_SKIPS.iter().map(|r| index(*r)).collect();
    assert_eq!(seen.len(), ALL_SKIPS.len());
    assert_eq!(seen.last().copied(), Some(ALL_SKIPS.len() - 1));
}
