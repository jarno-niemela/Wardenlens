//! The H.264 profiles whose SPS carries the chroma and bit-depth syntax ("High family").
//!
//! One list, used by the SPS parsers of `wardenlens-ingest` and `wardenlens-mp4` and by the `avcC`
//! writer of `wardenlens-mp4`. In #54 the writer knew profile 144 and the parser did not; two
//! copies of an enumeration drift (defect pattern P4).

/// `profile_idc` values whose SPS has `chroma_format_idc`, the bit depths and the scaling list
/// syntax after `seq_parameter_set_id` (H.264 7.3.2.1.1), plus 144, the withdrawn High 4:4:4
/// profile, which ffmpeg and the JM decoder still read the same way.
pub const HIGH_FAMILY_PROFILES: [u8; 14] = [
    100, 110, 122, 244, 44, 83, 86, 118, 128, 138, 139, 134, 135, 144,
];

/// Whether an SPS with this `profile_idc` carries the High family syntax.
#[must_use]
pub fn is_high_family(profile_idc: u8) -> bool {
    HIGH_FAMILY_PROFILES.contains(&profile_idc)
}

/// Whether the `avcC` record of this profile carries the chroma and bit-depth extension bytes
/// (ISO 14496-15 section 5.3.3.1.2: 100, 110, 122 and 144). A subset of the High family.
#[must_use]
pub fn avcc_has_chroma_extension(profile_idc: u8) -> bool {
    matches!(profile_idc, 100 | 110 | 122 | 144)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_profile_value_is_classified_by_the_table() {
        for p in 0..=u8::MAX {
            let listed = HIGH_FAMILY_PROFILES
                .iter()
                .copied()
                .filter(|&x| x == p)
                .count();
            assert!(listed <= 1, "{p} listed twice");
            assert_eq!(is_high_family(p), listed == 1, "profile {p}");
            // The avcC extension is only ever for a profile whose SPS has the fields.
            if avcc_has_chroma_extension(p) {
                assert!(is_high_family(p), "avcC extension for non-High {p}");
            }
        }
    }

    #[test]
    fn the_known_profiles_are_in_and_the_others_out() {
        for p in [
            100, 110, 122, 244, 44, 83, 86, 118, 128, 138, 139, 134, 135, 144,
        ] {
            assert!(is_high_family(p), "{p}");
        }
        // Baseline, Main, Extended, constrained variants share these idc values.
        for p in [0, 66, 77, 88, 99, 101, 143, 145, 255] {
            assert!(!is_high_family(p), "{p}");
        }
        for p in [100, 110, 122, 144] {
            assert!(avcc_has_chroma_extension(p), "{p}");
        }
        for p in [244, 44, 83, 66, 77] {
            assert!(!avcc_has_chroma_extension(p), "{p}");
        }
    }
}
