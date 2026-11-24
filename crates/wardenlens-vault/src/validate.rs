//! Per-kind validation and normalisation (ADR 0006 section 1) and the `unscannable` rule.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use secrecy::zeroize::Zeroizing;
use wardenlens_core::entry::EntryKind;

use crate::error::VaultError;
use crate::store::MAX_VALUE_LEN;

/// Shortest value (and needle) the leak scan can use; shorter values are stored `unscannable`.
pub const MIN_SCANNABLE_LEN: usize = 7;
/// Single-label hosts below this length are `unscannable`.
const MIN_SINGLE_LABEL_HOST_LEN: usize = 8;
const MAX_HOSTNAME_LEN: usize = 253;
const MAX_LABEL_LEN: usize = 63;

fn invalid(kind: EntryKind, rule: &'static str) -> VaultError {
    VaultError::InvalidValue { kind, rule }
}

pub(crate) fn check_len(kind: EntryKind, text: &str) -> Result<(), VaultError> {
    if text.len() > MAX_VALUE_LEN {
        return Err(VaultError::ValueTooLarge { kind });
    }
    Ok(())
}

/// Validates a credential pair (lengths and NUL only; the password is never inspected further).
pub(crate) fn check_credential(username: &str, password: &str) -> Result<(), VaultError> {
    let kind = EntryKind::Credential;
    check_len(kind, username)?;
    check_len(kind, password)?;
    if username.is_empty() {
        return Err(invalid(kind, "username is empty"));
    }
    if username.contains('\0') || password.contains('\0') {
        return Err(invalid(kind, "contains a NUL character"));
    }
    Ok(())
}

/// Validates a text value for `kind` and returns the normalised form to store. Every
/// intermediate copy of the value is zeroised on drop.
pub(crate) fn normalize_text(kind: EntryKind, raw: &str) -> Result<Zeroizing<String>, VaultError> {
    check_len(kind, raw)?;
    if raw.contains('\0') {
        return Err(invalid(kind, "contains a NUL character"));
    }
    match kind {
        EntryKind::Host => normalize_host(raw),
        EntryKind::Mac => normalize_mac(raw),
        EntryKind::Secret => non_empty(kind, raw).map(|t| Zeroizing::new(t.to_owned())),
        EntryKind::Serial | EntryKind::DisplayName => {
            let t = non_empty(kind, raw.trim())?;
            if t.chars().any(char::is_control) {
                return Err(invalid(kind, "contains a control character"));
            }
            Ok(Zeroizing::new(t.to_owned()))
        }
        EntryKind::Other => non_empty(kind, raw.trim()).map(|t| Zeroizing::new(t.to_owned())),
        // `Credential` is validated through `check_credential`; reaching here is a caller bug.
        _ => Err(VaultError::ValueKindMismatch { kind }),
    }
}

fn non_empty(kind: EntryKind, text: &str) -> Result<&str, VaultError> {
    if text.is_empty() {
        Err(invalid(kind, "value is empty"))
    } else {
        Ok(text)
    }
}

fn normalize_host(raw: &str) -> Result<Zeroizing<String>, VaultError> {
    let kind = EntryKind::Host;
    let lower = Zeroizing::new(raw.to_ascii_lowercase());
    let name = lower.strip_suffix('.').unwrap_or(&lower);
    if name.is_empty() {
        return Err(invalid(kind, "host is empty"));
    }
    if name.contains(':') {
        return name
            .parse::<Ipv6Addr>()
            .map(|a| Zeroizing::new(a.to_string()))
            .map_err(|_| invalid(kind, "not a valid IPv6 address"));
    }
    if name.bytes().all(|b| b.is_ascii_digit() || b == b'.') {
        return name
            .parse::<Ipv4Addr>()
            .map(|a| Zeroizing::new(a.to_string()))
            .map_err(|_| invalid(kind, "not a valid IPv4 address"));
    }
    if name.len() > MAX_HOSTNAME_LEN {
        return Err(invalid(kind, "hostname is longer than 253 bytes"));
    }
    for label in name.split('.') {
        let ok_chars = label
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'_'));
        if label.is_empty()
            || label.len() > MAX_LABEL_LEN
            || !ok_chars
            || label.starts_with('-')
            || label.ends_with('-')
        {
            return Err(invalid(kind, "hostname label is invalid"));
        }
    }
    Ok(Zeroizing::new(name.to_owned()))
}

/// Reduces any separator layout to 12 hex digits and re-renders them as `aa:bb:cc:dd:ee:ff`
/// (ADR 0006 section 1: "reduces to 12 hex digits").
fn normalize_mac(raw: &str) -> Result<Zeroizing<String>, VaultError> {
    let kind = EntryKind::Mac;
    let mut digits = Zeroizing::new(String::with_capacity(13));
    for c in raw.chars() {
        if c.is_ascii_hexdigit() {
            digits.push(c.to_ascii_lowercase());
        } else if !matches!(c, ':' | '-' | '.' | ' ' | '_') {
            return Err(invalid(kind, "not a MAC address"));
        }
        if digits.len() > 12 {
            break;
        }
    }
    if digits.len() != 12 {
        return Err(invalid(kind, "MAC must have exactly 12 hex digits"));
    }
    let mut out = Zeroizing::new(String::with_capacity(17));
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && i % 2 == 0 {
            out.push(':');
        }
        out.push(c);
    }
    Ok(out)
}

/// Whitespace-collapsed (any run becomes one space), then lowercased with the full mapping
/// (`char::to_lowercase`, ADR 0006 section 7).
fn collapsed_fold(text: &str) -> Zeroizing<String> {
    let collapsed = Zeroizing::new(text.split_whitespace().collect::<Vec<_>>().join(" "));
    Zeroizing::new(collapsed.chars().flat_map(char::to_lowercase).collect())
}

/// True when a (normalised) value is too short for the scan (ADR 0006 section 7).
///
/// The credential rule looks at the password only (usernames are not scanned).
pub(crate) fn is_unscannable(kind: EntryKind, normalized: &str) -> bool {
    match kind {
        EntryKind::Mac => false,
        EntryKind::Host => {
            if normalized.parse::<IpAddr>().is_ok() {
                false
            } else if normalized.contains('.') {
                normalized.len() < MIN_SCANNABLE_LEN
            } else {
                normalized.len() < MIN_SINGLE_LABEL_HOST_LEN
            }
        }
        EntryKind::Serial => {
            // Needles are matched in the fold, so the compact form is measured after it.
            let folded = Zeroizing::new(
                normalized
                    .chars()
                    .flat_map(char::to_lowercase)
                    .collect::<String>(),
            );
            folded
                .bytes()
                .filter(|b| !matches!(b, b'-' | b'_' | b'.' | b' '))
                .count()
                < MIN_SCANNABLE_LEN
        }
        EntryKind::Other => collapsed_fold(normalized).len() < MIN_SCANNABLE_LEN,
        EntryKind::DisplayName => {
            // Per-needle rule: the collapsed form and the slug with its spaces removed must
            // both reach the minimum. The scan matcher recomputes the rule from the squeezed
            // needles when it is built.
            let collapsed = collapsed_fold(normalized);
            let joined: Zeroizing<String> = Zeroizing::new(collapsed.replace(' ', ""));
            collapsed.len() < MIN_SCANNABLE_LEN || joined.len() < MIN_SCANNABLE_LEN
        }
        _ => normalized.len() < MIN_SCANNABLE_LEN,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n(kind: EntryKind, s: &str) -> Result<String, VaultError> {
        normalize_text(kind, s).map(|z| (*z).clone())
    }

    #[test]
    fn host_ipv4_is_strict() {
        assert_eq!(n(EntryKind::Host, "192.0.2.10").unwrap(), "192.0.2.10");
        for bad in [
            "192.0.2",
            "192.0.2.256",
            "192.000.2.10",
            "1.2.3.4.5",
            "01.2.3.4",
        ] {
            assert!(n(EntryKind::Host, bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn host_ipv6_is_canonicalised() {
        assert_eq!(
            n(EntryKind::Host, "2001:DB8:0:0:0:0:0:1").unwrap(),
            "2001:db8::1"
        );
        assert!(n(EntryKind::Host, "[2001:db8::1]").is_err());
        assert!(n(EntryKind::Host, "fe80::1%eth0").is_err());
    }

    #[test]
    fn host_name_is_lowercased_without_trailing_dot() {
        assert_eq!(
            n(EntryKind::Host, "NVR-1.Example.INVALID.").unwrap(),
            "nvr-1.example.invalid"
        );
        assert_eq!(
            n(EntryKind::Host, "_sip._tcp.example.invalid").unwrap(),
            "_sip._tcp.example.invalid"
        );
    }

    #[test]
    fn host_name_rules() {
        for bad in [
            "",
            ".",
            "a..b",
            "-a.example",
            "a-.example",
            "a b",
            "a/b",
            "caf\u{e9}.example",
            "a@b",
        ] {
            assert!(n(EntryKind::Host, bad).is_err(), "{bad:?}");
        }
        let label63 = "a".repeat(63);
        assert!(n(EntryKind::Host, &label63).is_ok());
        assert!(n(EntryKind::Host, &"a".repeat(64)).is_err());
        let long = [label63.as_str(); 4].join(".");
        assert_eq!(long.len(), 255);
        assert!(n(EntryKind::Host, &long).is_err());
        let ok253 = format!("{0}.{0}.{0}.{1}", label63, "a".repeat(61));
        assert_eq!(ok253.len(), 253);
        assert!(n(EntryKind::Host, &ok253).is_ok());
    }

    #[test]
    fn mac_reduces_to_colon_form() {
        for s in [
            "02:00:5E:00:53:AF",
            "02-00-5e-00-53-af",
            "0200.5e00.53af",
            "02005e0053af",
        ] {
            assert_eq!(n(EntryKind::Mac, s).unwrap(), "02:00:5e:00:53:af", "{s}");
        }
        for bad in [
            "",
            "02:00:5e:00:53",
            "02:00:5e:00:53:af:11",
            "02:00:5e:00:53:ag",
            "02/00/5e/00/53/af",
        ] {
            assert!(n(EntryKind::Mac, bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn text_kinds_reject_empty_nul_and_oversize() {
        for kind in [
            EntryKind::Secret,
            EntryKind::Serial,
            EntryKind::DisplayName,
            EntryKind::Other,
        ] {
            assert!(n(kind, "").is_err());
            assert!(n(kind, "ab\0cd").is_err());
            assert!(n(kind, &"x".repeat(4096)).is_ok());
            assert!(matches!(
                n(kind, &"x".repeat(4097)),
                Err(VaultError::ValueTooLarge { .. })
            ));
        }
        assert!(n(EntryKind::Serial, "   ").is_err());
    }

    #[test]
    fn serial_and_display_name_refuse_control_characters() {
        assert!(n(EntryKind::Serial, "SN\n1").is_err());
        assert!(n(EntryKind::DisplayName, "a\tb").is_err());
        assert!(n(EntryKind::Other, "a\nb").is_ok());
    }

    #[test]
    fn size_limit_counts_bytes_not_chars() {
        // 1366 three-byte chars = 4098 bytes.
        assert!(n(EntryKind::Other, &"\u{20ac}".repeat(1366)).is_err());
        assert!(n(EntryKind::Other, &"\u{20ac}".repeat(1365)).is_ok());
    }

    #[test]
    fn credential_rules() {
        assert!(check_credential("svc-reader", "Tr0ub4dor-x9").is_ok());
        assert!(check_credential("", "pw").is_err());
        assert!(check_credential("u", "").is_ok());
        assert!(check_credential("u\0", "p").is_err());
        assert!(check_credential(&"u".repeat(4097), "p").is_err());
        assert!(check_credential("u", &"p".repeat(4097)).is_err());
        assert!(check_credential(&"u".repeat(4096), &"p".repeat(4096)).is_ok());
    }

    #[test]
    fn unscannable_by_minimum_length() {
        assert!(is_unscannable(EntryKind::Secret, "123456"));
        assert!(!is_unscannable(EntryKind::Secret, "1234567"));
        assert!(is_unscannable(EntryKind::Credential, "abc"));
        assert!(!is_unscannable(EntryKind::DisplayName, "Back Door"));
        assert!(is_unscannable(EntryKind::DisplayName, "Door"));
        assert!(is_unscannable(EntryKind::Serial, "A-B-C-D-E-F"));
        assert!(!is_unscannable(EntryKind::Serial, "SN-0042-ZQ"));
        assert!(is_unscannable(EntryKind::Other, "a  b  c"));
    }

    #[test]
    fn display_name_needles_are_each_checked() {
        // Collapsed form is 7 bytes, but the slug without spaces is 6.
        assert!(is_unscannable(EntryKind::DisplayName, "Door 12"));
        assert!(is_unscannable(EntryKind::DisplayName, "Door     12"));
        assert!(is_unscannable(EntryKind::DisplayName, "a b c d"));
        assert!(!is_unscannable(EntryKind::DisplayName, "Door 123"));
        assert!(!is_unscannable(EntryKind::DisplayName, "Back   Door"));
        assert!(is_unscannable(EntryKind::DisplayName, "Tor  1"));
        // Lowercasing can change the length: U+0130 lowercases to two chars (3 bytes).
        assert!(!is_unscannable(
            EntryKind::DisplayName,
            "\u{130}\u{130}\u{130}"
        ));
    }

    #[test]
    fn unscannable_host_rules() {
        assert!(is_unscannable(EntryKind::Host, "nvr-1"));
        assert!(is_unscannable(EntryKind::Host, "nvr-123"));
        assert!(!is_unscannable(EntryKind::Host, "nvr-1234"));
        assert!(!is_unscannable(EntryKind::Host, "a.b.cde"));
        assert!(is_unscannable(EntryKind::Host, "a.b.cd"));
        // Fixed-format values are exempt however short.
        assert!(!is_unscannable(EntryKind::Host, "1.1.1.1"));
        assert!(!is_unscannable(EntryKind::Host, "::1"));
        assert!(!is_unscannable(EntryKind::Mac, "02:00:5e:00:53:af"));
    }

    proptest::proptest! {
        #[test]
        fn mac_normalisation_is_idempotent(raw in "[0-9a-fA-F:._ -]{0,40}") {
            if let Ok(once) = n(EntryKind::Mac, &raw) {
                proptest::prop_assert_eq!(n(EntryKind::Mac, &once).unwrap(), once);
            }
        }

        #[test]
        fn host_normalisation_is_idempotent(raw in "[0-9a-fA-F:._ -]{0,40}|[A-Za-z0-9._-]{0,80}") {
            if let Ok(once) = n(EntryKind::Host, &raw) {
                proptest::prop_assert_eq!(n(EntryKind::Host, &once).unwrap(), once);
            }
        }
    }
}
