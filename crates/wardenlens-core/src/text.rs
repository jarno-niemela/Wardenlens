//! Shared text predicates.

/// True for a character that is not a graphic, visible one and so must never be printed as it
/// is: every Unicode `Cf` (format) character, the soft hyphen, the bidirectional controls, the
/// variation selectors and the other invisible fillers, the line and paragraph separators, and
/// every character the squeeze table deletes. `Cc` (control) characters are not listed here:
/// `char::is_control` covers them. This is the one definition: the vault scanner, the report
/// printing and the camera `DisplayName` all use it.
#[must_use]
pub fn is_invisible(c: char) -> bool {
    matches!(
        u32::from(c),
        0x00AD
            | 0x034F
            | 0x0600..=0x0605
            | 0x061C
            | 0x06DD
            | 0x070F
            | 0x0890..=0x0891
            | 0x08E2
            | 0x115F..=0x1160
            | 0x17B4..=0x17B5
            | 0x180B..=0x180F
            | 0x200B..=0x200F
            | 0x2028..=0x202E
            | 0x2060..=0x206F
            | 0x3164
            | 0xFE00..=0xFE0F
            | 0xFEFF
            | 0xFFA0
            | 0xFFF9..=0xFFFB
            | 0x110BD
            | 0x110CD
            | 0x13430..=0x1343F
            | 0x1BCA0..=0x1BCA3
            | 0x1D173..=0x1D17A
            | 0xE0001
            | 0xE0020..=0xE007F
            | 0xE0100..=0xE01EF
    )
}

#[cfg(test)]
mod tests {
    use super::is_invisible;

    /// Every `Cf` (format) range of Unicode 16, from `DerivedGeneralCategory.txt`.
    const CF_RANGES: [(u32, u32); 21] = [
        (0x00AD, 0x00AD),
        (0x0600, 0x0605),
        (0x061C, 0x061C),
        (0x06DD, 0x06DD),
        (0x070F, 0x070F),
        (0x0890, 0x0891),
        (0x08E2, 0x08E2),
        (0x180E, 0x180E),
        (0x200B, 0x200F),
        (0x202A, 0x202E),
        (0x2060, 0x2064),
        (0x2066, 0x206F),
        (0xFEFF, 0xFEFF),
        (0xFFF9, 0xFFFB),
        (0x110BD, 0x110BD),
        (0x110CD, 0x110CD),
        (0x13430, 0x1343F),
        (0x1BCA0, 0x1BCA3),
        (0x1D173, 0x1D17A),
        (0xE0001, 0xE0001),
        (0xE0020, 0xE007F),
    ];

    #[test]
    fn every_cf_character_is_invisible() {
        for (lo, hi) in CF_RANGES {
            for n in lo..=hi {
                let c = char::from_u32(n).unwrap();
                assert!(is_invisible(c), "U+{n:04X}");
            }
        }
    }

    #[test]
    fn ordinary_text_is_not_invisible() {
        for c in [
            'a',
            'Z',
            '0',
            ' ',
            '-',
            '\u{e9}',
            '\u{4e2d}',
            '\u{1F600}',
            '\u{a0}',
        ] {
            assert!(!is_invisible(c), "{c:?}");
        }
    }
}
