//! The pure parsers: reply bytes in, typed results out. No I/O, no clock, no randomness.
//!
//! Every parser applies the limits of [`crate::soap`] (1 MiB, depth 64, 4096 elements) and maps
//! the three reply failures the camera can cause to typed errors: an empty reply
//! ([`OnvifError::EmptyReply`]), a SOAP fault ([`OnvifError::SoapFault`], or
//! [`OnvifError::NotAuthorized`] for the credentials fault) and malformed XML
//! ([`OnvifError::Malformed`]). No error carries reply text.

use crate::model::{
    DeviceInformation, MAX_DIMENSION, MAX_FIELD_LEN, Profile, ProfileToken, VideoEncoding,
};
use crate::soap::Doc;
use crate::stream_uri::{StreamEndpoint, reduce_stream_uri};
use crate::{MAX_PROFILES, OnvifError};

/// The trimmed text of `idx`, checked as a display field (bounded, no control character and no invisible one: core's
/// `is_invisible`, which covers Unicode Cf and U+2028/U+2029).
fn field(doc: &Doc, idx: usize, name: &'static str) -> Result<String, OnvifError> {
    let e = doc
        .elem(idx)
        .ok_or(OnvifError::InvalidField { field: name })?;
    let text = e.text.trim();
    if e.text_too_long
        || text.len() > MAX_FIELD_LEN
        || text
            .chars()
            .any(|c| c.is_control() || wardenlens_core::text::is_invisible(c))
    {
        return Err(OnvifError::InvalidField { field: name });
    }
    Ok(text.to_owned())
}

/// A required child of `parent` as a display field.
fn required(doc: &Doc, parent: usize, name: &'static str) -> Result<String, OnvifError> {
    let idx = doc
        .child(parent, name)
        .ok_or(OnvifError::MissingElement { element: name })?;
    field(doc, idx, name)
}

/// Parses a `GetDeviceInformationResponse`.
///
/// # Errors
/// An [`OnvifError`] for an empty, oversized, malformed or fault reply, or a missing or invalid
/// field.
pub fn parse_device_information(reply: &[u8]) -> Result<DeviceInformation, OnvifError> {
    let doc = Doc::parse(reply)?;
    let r = doc.response("GetDeviceInformationResponse")?;
    Ok(DeviceInformation {
        manufacturer: required(&doc, r, "Manufacturer")?,
        model: required(&doc, r, "Model")?,
        firmware_version: required(&doc, r, "FirmwareVersion")?,
        serial_number: required(&doc, r, "SerialNumber")?,
        hardware_id: required(&doc, r, "HardwareId")?,
    })
}

fn dimension(doc: &Doc, parent: usize, name: &'static str) -> Result<u32, OnvifError> {
    let idx = doc
        .child(parent, name)
        .ok_or(OnvifError::MissingElement { element: name })?;
    let text = field(doc, idx, name)?;
    // Digits only: `+5`, `-5`, `5.0` and `0x5` are refused rather than guessed at.
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err(OnvifError::InvalidField { field: name });
    }
    match text.parse::<u32>() {
        Ok(v) if (1..=MAX_DIMENSION).contains(&v) => Ok(v),
        _ => Err(OnvifError::InvalidField { field: name }),
    }
}

fn encoding(doc: &Doc, config: usize) -> Result<VideoEncoding, OnvifError> {
    let Some(idx) = doc.child(config, "Encoding") else {
        return Ok(VideoEncoding::Other);
    };
    let text = field(doc, idx, "Encoding")?;
    Ok(match text.to_ascii_uppercase().as_str() {
        "H264" => VideoEncoding::H264,
        "H265" => VideoEncoding::H265,
        "JPEG" => VideoEncoding::Jpeg,
        "MPEG4" => VideoEncoding::Mpeg4,
        _ => VideoEncoding::Other,
    })
}

/// Parses a `GetProfilesResponse`. A profile without a `VideoEncoderConfiguration` (audio-only,
/// metadata-only) is left out *before* its token is looked at, so an odd token on such a profile
/// never matters. A video profile whose token is missing or outside the pass-list (checked
/// untrimmed: the token is sent back exactly as received) is refused, not skipped: a camera
/// whose main stream silently vanished is worse than a loud error. Two profiles with one token
/// are refused, since a token must name one profile.
///
/// # Errors
/// An [`OnvifError`] for an empty, oversized, malformed or fault reply, more than
/// [`MAX_PROFILES`] profiles, or a missing or invalid field.
pub fn parse_profiles(reply: &[u8]) -> Result<Vec<Profile>, OnvifError> {
    let doc = Doc::parse(reply)?;
    let r = doc.response("GetProfilesResponse")?;
    let entries: Vec<usize> = doc
        .children(r)
        .filter(|i| doc.elem(*i).is_some_and(|e| e.name == "Profiles"))
        .collect();
    if entries.len() > MAX_PROFILES {
        return Err(OnvifError::TooManyProfiles);
    }
    let mut profiles: Vec<Profile> = Vec::with_capacity(entries.len());
    for idx in entries {
        let e = doc
            .elem(idx)
            .ok_or(OnvifError::InvalidField { field: "token" })?;
        let Some(config) = doc.child(idx, "VideoEncoderConfiguration") else {
            continue;
        };
        let token = match (&e.token, e.token_too_long) {
            (Some(t), false) => {
                ProfileToken::new(t).map_err(|_| OnvifError::InvalidField { field: "token" })?
            }
            _ => return Err(OnvifError::InvalidField { field: "token" }),
        };
        let name = match doc.child(idx, "Name") {
            Some(n) => Some(field(&doc, n, "Name")?),
            None => None,
        };
        let resolution = doc
            .child(config, "Resolution")
            .ok_or(OnvifError::MissingElement {
                element: "Resolution",
            })?;
        let width = dimension(&doc, resolution, "Width")?;
        let height = dimension(&doc, resolution, "Height")?;
        if profiles.iter().any(|p| p.token == token) {
            return Err(OnvifError::InvalidField { field: "token" });
        }
        profiles.push(Profile {
            token,
            name,
            width,
            height,
            encoding: encoding(&doc, config)?,
        });
    }
    Ok(profiles)
}

/// Parses a `GetStreamUriResponse` and reduces its `Uri` with [`reduce_stream_uri`].
///
/// # Errors
/// An [`OnvifError`] for an empty, oversized, malformed or fault reply, a missing `Uri`, or a URI
/// that cannot be reduced.
pub fn parse_stream_uri(reply: &[u8]) -> Result<StreamEndpoint, OnvifError> {
    let doc = Doc::parse(reply)?;
    let r = doc.response("GetStreamUriResponse")?;
    let uri = doc
        .path(r, &["MediaUri", "Uri"])
        .ok_or(OnvifError::MissingElement { element: "Uri" })?;
    let e = doc
        .elem(uri)
        .ok_or(OnvifError::MissingElement { element: "Uri" })?;
    if e.text_too_long {
        return Err(OnvifError::InvalidField { field: "Uri" });
    }
    reduce_stream_uri(&e.text)
}
