//! Adversary tests for #43 round 4: the combining-mark table and the multi-word credential
//! parameter check of `RtspPath`. Synthetic values only.

use wardenlens_core::camera::{CameraError, DisplayName, RtspPath};

/// The table claims to list combining marks (`Mn`, `Mc`, `Me`). Its ranges also cover the
/// avagraha letters U+09BD (Bengali), U+0ABD (Gujarati) and U+0B3D (Oriya), which are `Lo`
/// (alphanumeric letters), so a name made of or starting with one is refused as a leading mark.
#[test]
fn letters_inside_the_mark_ranges_are_not_treated_as_marks() {
    for n in [
        "\u{09BD}",
        "\u{0ABD}",
        "\u{0B3D}",
        "\u{09BD}x",
        "\u{0B3D}\u{0B15}",
    ] {
        assert!(n.chars().next().is_some_and(char::is_alphanumeric));
        assert!(DisplayName::new(n).is_ok(), "{n:?}");
    }
}

/// Marks in the listed blocks are refused at the start and do not count as content.
#[test]
fn listed_marks_are_refused_at_the_start_and_as_sole_content() {
    for n in [
        "\u{0E31}a",
        "\u{0F71}a",
        "\u{102B}a",
        "\u{17B6}a",
        "\u{0D3E}a",
        "\u{0BBE}a",
        "\u{0E31}\u{0E34}",
        "\u{093E}",
        "- \u{0E31}",
    ] {
        assert_eq!(DisplayName::new(n), Err(CameraError::NameCharset), "{n:?}");
    }
    for n in ["a\u{0E31}", "\u{0E01}\u{0E31}", "Caf\u{0065}\u{0301}"] {
        assert!(DisplayName::new(n).is_ok(), "{n:?}");
    }
}

/// Multi-word credential names behind any separator and prefix, mixed case, a trailing
/// separator and repeated separators are refused.
#[test]
fn multi_word_credential_names_in_every_join_are_refused() {
    for p in [
        "/a?X_USER_NAME=1",
        "/a?a_b_c_user_id=1",
        "/a?x--api--key=1",
        "/a?password_=1",
        "/a?_-_password=1",
        "/a?x_access-token=1",
        "/a?x=1&y_login_use=2",
        "/a;x-pass-word=1",
        "/a/x_user=admin_password=1",
    ] {
        assert_eq!(
            RtspPath::new(p),
            Err(CameraError::PathCredentialParam),
            "{p}"
        );
    }
}

/// Single-piece names that merely end in a listed word stay accepted, as documented.
#[test]
fn single_piece_names_ending_in_a_listed_word_stay_accepted() {
    for p in [
        "/a?monkey=1",
        "/a?accounting=1",
        "/a?apikeys=1",
        "/a?subtype=0&channel=1",
    ] {
        assert!(RtspPath::new(p).is_ok(), "{p}");
    }
}
