//! Every cap, at -1, exact and +1 (TEST-8): body size, depth, element count, text size.

use super::fixtures::*;
use crate::soap::Doc;
use crate::{
    MAX_BODY_BYTES, MAX_DEPTH, MAX_ELEMENTS, OnvifError, parse_device_information, parse_profiles,
    parse_stream_uri,
};

fn nested(depth: usize) -> String {
    format!("{}{}", "<a>".repeat(depth), "</a>".repeat(depth))
}

fn parsed(doc: &str) -> Result<(), OnvifError> {
    Doc::parse(doc.as_bytes()).map(|_| ())
}

#[test]
fn depth_boundary() {
    assert_eq!(MAX_DEPTH, 64);
    assert_eq!(parsed(&nested(MAX_DEPTH - 1)), Ok(()));
    assert_eq!(parsed(&nested(MAX_DEPTH)), Ok(()));
    assert_eq!(parsed(&nested(MAX_DEPTH + 1)), Err(OnvifError::TooDeep));
    assert_eq!(parsed(&nested(10_000)), Err(OnvifError::TooDeep));
    // Siblings do not add depth.
    let flat = format!("<r>{}</r>", "<a/>".repeat(100));
    assert_eq!(parsed(&flat), Ok(()));
}

#[test]
fn depth_limit_applies_inside_a_real_envelope_for_every_parser() {
    // Envelope and Body take two levels; the response and everything under it the rest.
    let deep = |n: usize| env(&format!("{}{}", "<x>".repeat(n), "</x>".repeat(n)));
    for parse in [
        |b: &[u8]| parse_device_information(b).map(|_| ()),
        |b: &[u8]| parse_profiles(b).map(|_| ()),
        |b: &[u8]| parse_stream_uri(b).map(|_| ()),
    ] {
        assert_eq!(
            parse(deep(MAX_DEPTH - 2).as_bytes())
                .err()
                .map(|e| e == OnvifError::TooDeep),
            Some(false)
        );
        assert_eq!(
            parse(deep(MAX_DEPTH - 1).as_bytes()),
            Err(OnvifError::TooDeep)
        );
    }
}

#[test]
fn element_count_boundary() {
    let flat = |n: usize| format!("<r>{}</r>", "<a/>".repeat(n - 1));
    assert_eq!(MAX_ELEMENTS, 4096);
    assert_eq!(parsed(&flat(MAX_ELEMENTS - 1)), Ok(()));
    assert_eq!(parsed(&flat(MAX_ELEMENTS)), Ok(()));
    assert_eq!(
        parsed(&flat(MAX_ELEMENTS + 1)),
        Err(OnvifError::TooManyElements)
    );
    // Empty-element tags and start/end pairs count alike.
    let pairs = format!("<r>{}</r>", "<a></a>".repeat(MAX_ELEMENTS));
    assert_eq!(parsed(&pairs), Err(OnvifError::TooManyElements));
}

fn padded(total: usize) -> Vec<u8> {
    let mut doc = good_device_info().into_bytes();
    assert!(doc.len() <= total);
    doc.resize(total, b' ');
    doc
}

#[test]
fn body_size_boundary_in_every_parser() {
    assert_eq!(MAX_BODY_BYTES, 1024 * 1024);
    assert!(parse_device_information(&padded(MAX_BODY_BYTES - 1)).is_ok());
    assert!(parse_device_information(&padded(MAX_BODY_BYTES)).is_ok());
    assert_eq!(
        parse_device_information(&padded(MAX_BODY_BYTES + 1)).err(),
        Some(OnvifError::BodyTooLarge)
    );
    assert_eq!(
        parse_profiles(&padded(MAX_BODY_BYTES + 1)).err(),
        Some(OnvifError::BodyTooLarge)
    );
    assert_eq!(
        parse_stream_uri(&padded(MAX_BODY_BYTES + 1)).err(),
        Some(OnvifError::BodyTooLarge)
    );
    // Not UTF-8 and too large: the size is checked first, nothing is decoded.
    let mut big = vec![0xFF_u8; MAX_BODY_BYTES + 1];
    assert_eq!(
        parse_device_information(&big).err(),
        Some(OnvifError::BodyTooLarge)
    );
    big.truncate(MAX_BODY_BYTES);
    assert_eq!(
        parse_device_information(&big).err(),
        Some(OnvifError::NotUtf8)
    );
}

#[test]
fn big_text_is_kept_bounded() {
    // 1 MiB of text in an element nobody reads is fine, and is not copied in full.
    let text = "t".repeat(MAX_BODY_BYTES - 2000);
    let doc = format!(
        "<env:Envelope {NS}><env:Body><tds:GetDeviceInformationResponse><tds:Junk>{text}</tds:Junk>\
         <tds:Manufacturer>m</tds:Manufacturer><tds:Model>m</tds:Model><tds:FirmwareVersion>m</tds:FirmwareVersion>\
         <tds:SerialNumber>m</tds:SerialNumber><tds:HardwareId>m</tds:HardwareId>\
         </tds:GetDeviceInformationResponse></env:Body></env:Envelope>"
    );
    assert!(parse_device_information(doc.as_bytes()).is_ok());
    let d = Doc::parse(doc.as_bytes()).expect("doc");
    let junk = d.elem(3).expect("junk");
    assert_eq!(junk.name, "Junk");
    assert!(junk.text.len() <= 4096);
    assert!(junk.text_too_long);
}

#[test]
fn text_limit_boundary() {
    // 4096 bytes are kept; the 256-byte field rule then refuses it, so probe the keep limit
    // through the arena directly.
    let kept = |n: usize| {
        let doc = Doc::parse(format!("<a>{}</a>", "x".repeat(n)).as_bytes()).expect("doc");
        let e = doc.elem(0).expect("root");
        (e.text.len(), e.text_too_long)
    };
    assert_eq!(kept(4095), (4095, false));
    assert_eq!(kept(4096), (4096, false));
    assert_eq!(kept(4097), (0, true));
}
