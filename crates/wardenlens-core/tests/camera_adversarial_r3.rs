//! Round-3 adversarial tests for the camera domain model (#43). Synthetic data only.

use proptest::prelude::*;
use wardenlens_core::camera::{CameraError, DisplayName, MAX_NAME_LEN, RtspPath};

/// The module table says a name with "a leading combining mark" is refused. Combining marks
/// outside the listed blocks (Hebrew points after U+05BD, Arabic U+0670, Bengali, Thai, Tibetan,
/// Myanmar) still start a name.
#[test]
fn display_name_refuses_every_leading_combining_mark() {
    for n in [
        "\u{05C1}abc", // HEBREW POINT SHIN DOT (Mn)
        "\u{0670}abc", // ARABIC LETTER SUPERSCRIPT ALEF (Mn)
        "\u{0981}abc", // BENGALI SIGN CANDRABINDU (Mn)
        "\u{0E31}abc", // THAI CHARACTER MAI HAN-AKAT (Mn)
        "\u{0F71}abc", // TIBETAN VOWEL SIGN AA (Mn)
        "\u{102D}abc", // MYANMAR VOWEL SIGN I (Mn)
        "\u{20DD}abc", // COMBINING ENCLOSING CIRCLE (Me), listed block: control row
    ] {
        assert_eq!(
            DisplayName::new(n),
            Err(CameraError::NameCharset),
            "U+{:04X}",
            u32::from(n.chars().next().unwrap())
        );
    }
}

/// A name that is a single combining mark renders as nothing (or a dotted circle) even when the
/// mark is `Alphabetic`; "renders blank" is refused by the contract.
#[test]
fn display_name_refuses_a_lone_alphabetic_combining_mark() {
    for n in ["\u{0E31}", "\u{05C1}", "\u{0670}"] {
        assert_eq!(DisplayName::new(n), Err(CameraError::NameCharset), "{n:?}");
    }
}

/// Every boundary of the blank-glyph ranges: the edge code points are refused, their visible
/// neighbours pass.
#[test]
fn display_name_blank_glyph_range_edges() {
    for c in [
        '\u{E000}',
        '\u{F8FF}',
        '\u{FDD0}',
        '\u{FDEF}',
        '\u{FFFE}',
        '\u{FFFF}',
        '\u{2FFFE}',
        '\u{10FFFF}',
        '\u{F0000}',
        '\u{FFFFD}',
        '\u{100000}',
        '\u{10FFFD}',
        '\u{2800}',
        '\u{FFFC}',
    ] {
        let n = format!("a{c}b");
        assert_eq!(DisplayName::new(&n), Err(CameraError::NameCharset), "{n:?}");
    }
    for c in [
        '\u{D7FF}', '\u{F900}', '\u{FDCF}', '\u{FDF0}', '\u{FFFD}', '\u{27FF}', '\u{2801}',
    ] {
        let n = format!("a{c}b");
        assert!(DisplayName::new(&n).is_ok(), "U+{:04X}", u32::from(c));
    }
}

/// Length boundaries with multibyte characters: exactly 128 bytes accepted, 129 refused.
#[test]
fn display_name_length_boundary_with_multibyte() {
    let at = format!("{}a", "\u{e9}".repeat((MAX_NAME_LEN - 1) / 2)); // 126 + 1 = 127
    let exact = format!("{at}b");
    assert_eq!(exact.len(), MAX_NAME_LEN);
    assert!(DisplayName::new(&exact).is_ok());
    let over = format!("{exact}c");
    assert_eq!(DisplayName::new(&over), Err(CameraError::NameLength));
}

/// The module says the tail check makes the credential refusal hold "whatever separator
/// precedes the name". The list's own multi-word names (`user_name`, `user-name`, `user_id`)
/// have a separator inside, so their alphanumeric tail is `name` or `id` and a prefixed form
/// slips through.
#[test]
fn rtsp_path_refuses_prefixed_multi_word_credential_names() {
    for p in [
        "/a?x_user_name=admin",
        "/a?0_user-name=admin",
        "/a?+user_id=admin",
        "/a?(user_name=admin",
    ] {
        assert_eq!(
            RtspPath::new(p),
            Err(CameraError::PathCredentialParam),
            "{p}"
        );
    }
}

/// Credential names hidden after a `=` inside a value, behind every separator the splitter
/// uses, are refused; plain vendor parameters with `=` in the value are accepted.
#[test]
fn rtsp_path_credential_names_in_chained_values() {
    for p in [
        "/a?x=password=1",
        "/a?x=y=user=1",
        "/a;password=1",
        "/a,pwd=1",
        "/a/b?c&PASSWORD=1",
        "/a?x=1&&pw=2",
    ] {
        assert_eq!(
            RtspPath::new(p),
            Err(CameraError::PathCredentialParam),
            "{p}"
        );
    }
    for p in [
        "/a?x==1",
        "/a?=1",
        "/a?x=1=2",
        "/Streaming/Channels/101?transportmode=unicast&profile=Profile_1",
        "/axis-media/media.amp?videocodec=h264&resolution=640x480",
        "/cam/realmonitor?channel=1&subtype=1&unicast=true&proto=Onvif",
    ] {
        assert!(RtspPath::new(p).is_ok(), "{p}");
    }
}

proptest! {
    /// Any name on the list, in any case, behind any allowed non-alphanumeric prefix, before
    /// `=`, in the path or the query, is refused.
    #[test]
    fn rtsp_path_single_word_credential_names_behind_any_prefix(
        name in prop::sample::select(vec![
            "pass", "passw", "passwd", "password", "passcode", "pw", "pwd", "p", "user", "usr",
            "u", "username", "userid", "login", "loginuse", "loginpas", "token", "auth", "key",
            "apikey", "secret", "pword", "account",
        ]),
        prefix in "[a-z0-9]{0,4}[-._~!$'()*+:]",
        upper in any::<bool>(),
        in_query in any::<bool>(),
    ) {
        let name = if upper { name.to_ascii_uppercase() } else { name.to_owned() };
        let p = if in_query {
            format!("/s?a=1&{prefix}{name}=v")
        } else {
            format!("/s/{prefix}{name}=v")
        };
        prop_assert_eq!(RtspPath::new(&p), Err(CameraError::PathCredentialParam), "{}", p);
    }

    /// Never panics and never refuses with anything but a typed error on arbitrary text.
    #[test]
    fn rtsp_path_never_panics(s in "\\PC{0,40}") {
        let _ = RtspPath::new(&s);
        let _ = RtspPath::new(&format!("/{s}"));
        let _ = DisplayName::new(&s);
    }
}
