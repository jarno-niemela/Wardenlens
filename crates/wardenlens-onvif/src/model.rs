//! The typed results of the three calls, and the main/sub choice.

use std::fmt;

use crate::OnvifError;

/// Longest profile token in bytes.
pub const MAX_TOKEN_LEN: usize = 64;
/// Longest text field (manufacturer, model, name, ...) in bytes.
pub const MAX_FIELD_LEN: usize = 256;
/// Largest picture side in pixels that is accepted.
pub const MAX_DIMENSION: u32 = 65_535;

/// A media profile token. Pass-list: 1 to 64 bytes of `[A-Za-z0-9._:-]`. It is sent back to the
/// camera in `GetStreamUri`, so a token outside the list (a camera that uses spaces or `<`) is
/// refused instead of escaped: there is one spelling, and nothing in it can alter the request.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct ProfileToken(String);

impl ProfileToken {
    /// Validates `text` as a profile token.
    ///
    /// # Errors
    /// [`OnvifError::InvalidToken`].
    pub fn new(text: &str) -> Result<Self, OnvifError> {
        let ok = !text.is_empty()
            && text.len() <= MAX_TOKEN_LEN
            && text
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'));
        if ok {
            Ok(Self(text.to_owned()))
        } else {
            Err(OnvifError::InvalidToken)
        }
    }

    /// The token text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ProfileToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ProfileToken").field(&self.0).finish()
    }
}

/// The answer of `GetDeviceInformation`. All five fields are mandatory in the ONVIF schema; each
/// is trimmed, at most [`MAX_FIELD_LEN`] bytes and free of control characters.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct DeviceInformation {
    /// The manufacturer.
    pub manufacturer: String,
    /// The model.
    pub model: String,
    /// The firmware version.
    pub firmware_version: String,
    /// The serial number.
    pub serial_number: String,
    /// The hardware id.
    pub hardware_id: String,
}

/// The video codec a profile reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum VideoEncoding {
    /// `H264`.
    H264,
    /// `H265`.
    H265,
    /// `JPEG`.
    Jpeg,
    /// `MPEG4`.
    Mpeg4,
    /// Any other spelling, or none.
    Other,
}

/// A media profile with a video encoder: what `GetProfiles` lists, minus audio-only entries.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Profile {
    /// The token to pass to `get_stream_uri`.
    pub token: ProfileToken,
    /// The profile's name, when the camera sent one.
    pub name: Option<String>,
    /// Picture width in pixels, 1 to [`MAX_DIMENSION`].
    pub width: u32,
    /// Picture height in pixels, 1 to [`MAX_DIMENSION`].
    pub height: u32,
    /// The codec.
    pub encoding: VideoEncoding,
}

impl Profile {
    /// Width times height. Never overflows: both are at most [`MAX_DIMENSION`].
    #[must_use]
    pub fn pixels(&self) -> u64 {
        u64::from(self.width).saturating_mul(u64::from(self.height))
    }
}

/// The main and sub profile among a camera's profiles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct StreamChoice<'a> {
    /// The profile with the most pixels.
    pub main: &'a Profile,
    /// The profile with the fewest pixels, when that is strictly fewer than `main`'s.
    pub sub: Option<&'a Profile>,
}

/// Picks the main and sub profile by resolution (pixel count). Ties go to the profile listed
/// first. `None` when `profiles` is empty. Codec and name play no part: a camera with one
/// resolution has a main stream and no sub stream.
#[must_use]
pub fn pick_streams(profiles: &[Profile]) -> Option<StreamChoice<'_>> {
    let mut main: Option<&Profile> = None;
    for p in profiles {
        if main.is_none_or(|m| p.pixels() > m.pixels()) {
            main = Some(p);
        }
    }
    let main = main?;
    let mut sub: Option<&Profile> = None;
    for p in profiles {
        if p.pixels() < main.pixels() && sub.is_none_or(|s| p.pixels() < s.pixels()) {
            sub = Some(p);
        }
    }
    Some(StreamChoice { main, sub })
}
