//! Shared text predicates.

/// True for a character that is not a graphic, visible one and so must never be printed as it
/// is: every Unicode `Cf` (format) character, the soft hyphen, the bidirectional controls, the
/// variation selectors and the other invisible fillers, the line and paragraph separators, and
/// every character the squeeze table deletes. `Cc` (control) characters are not listed here:
/// `char::is_control` covers them. This is the one definition: the vault scanner, the report printing and the camera `DisplayName` all use it.
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
