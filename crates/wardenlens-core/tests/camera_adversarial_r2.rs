//! Round-2 adversarial tests for the camera domain model (#43). Synthetic data only.
#![expect(clippy::unwrap_used, reason = "test code")]

use std::num::NonZeroU16;

use wardenlens_core::camera::{
    Camera, CameraError, CameraId, DisplayName, Host, ModelRef, RtspPath, StreamRole, StreamSet,
};
use wardenlens_core::entry::EntryKind;

const SECRETISH: [&str; 6] = [
    "nvr-7",
    "example",
    "Garage",
    "Side",
    "Tr0ub4dor",
    "2001:db8",
];

fn camera(host: &str, main: &str, sub: Option<&str>) -> Camera {
    Camera::new(
        CameraId::new("cam-7").unwrap(),
        DisplayName::new("Garage Side").unwrap(),
        ModelRef::new("reolink", "rlc-520a").unwrap(),
        Host::new(host).unwrap(),
        NonZeroU16::new(8554).unwrap(),
        StreamSet::new(
            RtspPath::new(main).unwrap(),
            sub.map(|s| RtspPath::new(s).unwrap()),
        ),
    )
}

/// `Debug` of a camera (compact and pretty, nested in containers) shows no host, name or path,
/// for a DNS host, an IPv6 host and with a sub stream present.
#[test]
fn camera_debug_never_shows_host_name_or_paths() {
    for cam in [
        camera(
            "nvr-7.example.invalid",
            "/cam?pin=Tr0ub4dor",
            Some("/sub?pin=Tr0ub4dor"),
        ),
        camera("2001:db8::77", "/Tr0ub4dor", None),
    ] {
        for shown in [
            format!("{cam:?}"),
            format!("{cam:#?}"),
            format!("{:?}", vec![cam.clone()]),
            format!("{:?}", cam.streams()),
            format!("{:?}", cam.rtsp_url(StreamRole::Main).unwrap()),
            format!("{}", cam.rtsp_url(StreamRole::Main).unwrap()),
        ] {
            for s in SECRETISH {
                assert!(!shown.contains(s), "{s} in {shown}");
            }
        }
        // The id and the model are not sensitive and do show.
        let d = format!("{cam:?}");
        assert!(d.contains("cam-7") && d.contains("rlc-520a"), "{d}");
    }
}

#[test]
fn rtsp_url_brackets_ipv6_keeps_the_port_and_refuses_a_missing_sub_stream() {
    let c = camera("2001:DB8::77", "/live?channel=1", None);
    assert_eq!(
        c.rtsp_url(StreamRole::Main).unwrap().as_str(),
        "rtsp://[2001:db8::77]:8554/live?channel=1"
    );
    assert_eq!(
        c.rtsp_url(StreamRole::Sub).unwrap_err(),
        CameraError::NoSuchStream
    );
    let c = camera("NVR-7.Example.INVALID", "/", Some("/s"));
    assert_eq!(
        c.rtsp_url(StreamRole::Sub).unwrap().as_str(),
        "rtsp://nvr-7.example.invalid:8554/s"
    );
}

/// Every vault entry id a camera builds is accepted and has the documented form, for the
/// longest id.
#[test]
fn entry_ids_for_the_longest_camera_id() {
    let id = CameraId::new(&format!("a{}", "-".repeat(31))).unwrap();
    for (kind, suffix) in [
        (EntryKind::Credential, "credential"),
        (EntryKind::Host, "host"),
        (EntryKind::DisplayName, "name"),
    ] {
        assert_eq!(
            id.entry_id(kind).unwrap().as_str(),
            format!("cam:{}:{suffix}", id.as_str())
        );
    }
    for kind in [
        EntryKind::Secret,
        EntryKind::Serial,
        EntryKind::Mac,
        EntryKind::Other,
    ] {
        assert_eq!(id.entry_id(kind), Err(CameraError::EntryKindNotOwned));
    }
}

/// A credential-named parameter glued to the path with a character that is allowed but is not
/// one of the split characters (`/ ? & ; ,`), or a vendor name the list misses, passes the
/// credential rule. Each of these carries a password in clear text.
#[test]
fn credential_parameters_behind_other_allowed_separators_are_refused() {
    let accepted: Vec<&str> = [
        // `_` separated XMEye form with the fields reordered
        "/channel=1_stream=0_user=admin_password=Tr0ub4dor.sdp",
        // `:`, `+`, `!`, `$`, `*`, `'`, `(` as glue
        "/live:user=admin:password=Tr0ub4dor",
        "/a?x=1+password=Tr0ub4dor",
        "/a?x=1!password=Tr0ub4dor",
        "/a?$password=Tr0ub4dor",
        "/a?*password=Tr0ub4dor",
        "/a?'password=Tr0ub4dor",
        "/a?(password=Tr0ub4dor)",
        // vendor names missing from the list
        "/a?user=admin&psw=Tr0ub4dor",
        "/a?account=admin&pword=Tr0ub4dor",
    ]
    .into_iter()
    .filter(|p| RtspPath::new(p).is_ok())
    .collect();
    assert!(accepted.is_empty(), "accepted: {accepted:#?}");
}

/// The bare-name rule for the query also holds after a second `?` and after `;`.
#[test]
fn bare_credential_names_anywhere_in_the_query_are_refused() {
    for p in ["/a?x=1?password", "/a?x=1;token", "/a?x=1,secret", "/?PASS"] {
        assert_eq!(
            RtspPath::new(p),
            Err(CameraError::PathCredentialParam),
            "{p}"
        );
    }
}

/// A display name that renders as nothing visible.
#[test]
fn display_names_that_render_blank_are_refused() {
    let accepted: Vec<String> = [
        "\u{2800}", // braille pattern blank (So)
        "\u{2800}\u{2800}",
        "\u{301}",  // a lone combining acute accent
        "\u{FFFC}", // object replacement
        "\u{E000}", // private use
        "\u{FFFF}", // noncharacter
    ]
    .into_iter()
    .filter(|n| DisplayName::new(n).is_ok())
    .map(|n| format!("{:?}", n.escape_unicode().to_string()))
    .collect();
    assert!(accepted.is_empty(), "accepted: {accepted:?}");
}

/// The byte cap counts bytes, not characters, and never splits a character.
#[test]
fn display_name_cap_is_in_bytes_for_multibyte_text() {
    let ok = "\u{4e2d}".repeat(42); // 126 bytes
    assert!(DisplayName::new(&ok).is_ok());
    let ok = format!("{ok}ab"); // 128
    assert!(DisplayName::new(&ok).is_ok());
    let bad = "\u{4e2d}".repeat(43); // 129
    assert_eq!(DisplayName::new(&bad), Err(CameraError::NameLength));
    let bad = format!("{}\u{1F600}", "a".repeat(125)); // 129
    assert_eq!(DisplayName::new(&bad), Err(CameraError::NameLength));
}

/// Hosts that are not usable unicast camera addresses.
#[test]
fn ip_hosts_have_one_value_whatever_the_spelling() {
    // IPv4-compatible and plain spellings of the same IPv6 address are one host.
    assert_eq!(
        Host::new("::192.0.2.1").unwrap(),
        Host::new("::c000:201").unwrap()
    );
    assert_eq!(
        Host::new("::192.0.2.1").unwrap().expose(),
        Host::new("::c000:201").unwrap().expose()
    );
}
