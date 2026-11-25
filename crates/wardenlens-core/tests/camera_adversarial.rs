//! Adversarial tests for the camera domain model (#43). Synthetic data only.
#![expect(clippy::unwrap_used, reason = "test code")]

use std::num::NonZeroU16;

use wardenlens_core::camera::{
    Camera, CameraError, CameraId, DisplayName, Host, MAX_CAMERA_ID_LEN, MAX_HOST_LEN,
    MAX_NAME_LEN, MAX_PATH_LEN, ModelRef, RtspPath, StreamRole, StreamSet,
};

fn camera_with_path(path: &str) -> Camera {
    Camera::new(
        CameraId::new("cam1").unwrap(),
        DisplayName::new("Back Door North").unwrap(),
        ModelRef::new("reolink", "rlc-520a").unwrap(),
        Host::new("192.0.2.10").unwrap(),
        NonZeroU16::new(554).unwrap(),
        StreamSet::new(RtspPath::new(path).unwrap(), None),
    )
}

// ---- Credential parameters spelled outside the `?query` ----

/// Xiongmai/XMEye cameras put the login in the path itself:
/// `rtsp://<host>:554/user=admin&password=<pw>&channel=1&stream=0.sdp`.
/// The credential-parameter rule only looks after the first `?`, so this is accepted.
#[test]
fn path_rejects_credential_params_in_the_path_part() {
    for p in [
        "/user=admin&password=Tr0ub4dor-x9&channel=1&stream=0.sdp",
        "/user=admin_password=Tr0ub4dor-x9_channel=1_stream=0.sdp",
        "/live;user=admin;password=Tr0ub4dor-x9",
        "/password=Tr0ub4dor-x9",
    ] {
        assert!(
            RtspPath::new(p).is_err(),
            "{p:?} accepted although it carries a password"
        );
    }
}

/// Consequence of the above: `Camera`'s derived `Debug` prints paths verbatim, so a password in
/// the path reaches any log line that formats the camera.
#[test]
fn camera_debug_never_prints_a_password_carried_in_the_path() {
    let p = "/user=admin&password=Tr0ub4dor-x9&channel=1&stream=0.sdp";
    let Ok(_) = RtspPath::new(p) else {
        return; // refused: nothing can leak
    };
    let shown = format!("{:?}", camera_with_path(p));
    assert!(!shown.contains("Tr0ub4dor-x9"), "{shown}");
}

/// Real vendor spellings of credential query names not on the denylist.
#[test]
fn query_rejects_common_vendor_credential_names() {
    for q in [
        "loginuse=admin&loginpas=x", // VStarcam / hipcam CGI
        "pw=x",
        "passw=x",
        "user_name=x",
        "user-name=x",
        "userid=x",
        "access_token=x",
        "apikey=x",
        "api_key=x",
        "u=admin&p=x",
    ] {
        let p = format!("/videostream.cgi?{q}");
        assert_eq!(
            RtspPath::new(&p),
            Err(CameraError::PathCredentialParam),
            "{p}"
        );
    }
}

// ---- DisplayName bidi controls ----

/// U+061C ARABIC LETTER MARK has `Bidi_Control=Yes`, like U+200E/U+200F which are refused.
#[test]
fn display_name_rejects_every_bidi_control() {
    for c in [
        '\u{61c}', '\u{200e}', '\u{200f}', '\u{202a}', '\u{202b}', '\u{202c}', '\u{202d}',
        '\u{202e}', '\u{2066}', '\u{2067}', '\u{2068}', '\u{2069}',
    ] {
        let n = format!("a{c}b");
        assert_eq!(
            DisplayName::new(&n),
            Err(CameraError::NameCharset),
            "U+{:04X}",
            u32::from(c)
        );
    }
}

// ---- Boundaries and hostile components (these pass; kept as coverage) ----

#[test]
fn camera_id_exact_boundaries() {
    let max = format!("a{}", "-".repeat(MAX_CAMERA_ID_LEN - 1));
    assert!(CameraId::new(&max).is_ok());
    let over = format!("a{}", "0".repeat(MAX_CAMERA_ID_LEN));
    assert_eq!(CameraId::new(&over), Err(CameraError::IdTooLong));
    // 32 bytes but multibyte: refused on charset, never panics.
    let multi = format!("a{}", "\u{e9}".repeat(15));
    assert!(multi.len() <= MAX_CAMERA_ID_LEN + 1);
    assert!(CameraId::new(&multi).is_err());
}

#[test]
fn multibyte_char_in_every_position_never_panics_and_is_refused() {
    let base = "reolink-1.example.invalid";
    for i in 0..=base.len() {
        let (a, b) = base.split_at(i);
        for c in ['\u{e9}', '\u{ff0e}', '\u{1f600}', '\u{301}'] {
            let s = format!("{a}{c}{b}");
            assert!(CameraId::new(&s).is_err());
            assert_eq!(Host::new(&s), Err(CameraError::HostSyntax), "{s:?}");
            let p = format!("/{s}");
            assert_eq!(RtspPath::new(&p), Err(CameraError::PathCharset), "{p:?}");
        }
    }
}

#[test]
fn truncation_sweeps_never_panic() {
    let host = "[2001:db8:0:0:0:0:0:1]";
    for i in 0..=host.len() {
        let _ = Host::new(&host[..i]);
    }
    let path = "/cam/realmonitor?channel=1&subtype=0&pass=x";
    for i in 0..=path.len() {
        let _ = RtspPath::new(&path[..i]);
    }
    let name = "Garage \u{2013} Side \u{4e2d}";
    for (i, _) in name.char_indices() {
        let _ = DisplayName::new(&name[..i]);
    }
}

#[test]
fn length_caps_are_exact() {
    let host_max = format!("{0}.{0}.{0}.{1}", "a".repeat(63), "b".repeat(61));
    assert_eq!(host_max.len(), MAX_HOST_LEN);
    assert!(Host::new(&host_max).is_ok());
    assert_eq!(
        Host::new(&format!("{host_max}b")),
        Err(CameraError::HostTooLong)
    );

    let path_max = format!("/{}", "a".repeat(MAX_PATH_LEN - 1));
    assert!(RtspPath::new(&path_max).is_ok());
    assert_eq!(
        RtspPath::new(&format!("{path_max}a")),
        Err(CameraError::PathTooLong)
    );

    let name_max = "\u{e9}".repeat(MAX_NAME_LEN / 2);
    assert!(DisplayName::new(&name_max).is_ok());
    assert_eq!(
        DisplayName::new(&format!("{name_max}a")),
        Err(CameraError::NameLength)
    );
}

#[test]
fn url_authority_cannot_be_altered_by_any_accepted_path() {
    for p in ["/", "/?", "/:x", "/a//b", "/a?x=//h", "/;x", "/a?x=1?y=2"] {
        let c = camera_with_path(p);
        let url = c.rtsp_url(StreamRole::Main).unwrap();
        assert_eq!(url.as_str(), format!("rtsp://192.0.2.10:554{p}"));
        assert!(!url.as_str().contains('@'));
    }
}

#[test]
fn every_error_variant_message_is_input_free() {
    let cases: [(Result<(), CameraError>, &str); 6] = [
        (CameraId::new("Zsecretz").map(drop), "secret"),
        (Host::new("secret.invalid.").map(drop), "secret"),
        (Host::new("secret x.invalid").map(drop), "secret"),
        (RtspPath::new("/a?secret=1").map(drop), "secret"),
        (RtspPath::new("/secret/../x").map(drop), "secret"),
        (DisplayName::new("secret\u{202e}").map(drop), "secret"),
    ];
    for (r, word) in cases {
        let e = r.unwrap_err();
        assert!(!e.to_string().contains(word), "{e}");
        assert!(!format!("{e:?}").contains(word), "{e:?}");
    }
}
