//! The typed catalogue entry and its TOML boundary parser.

use serde::Deserialize;
use serde::de::{self, Deserializer};

use super::error::CatalogueError;

/// Largest accepted entry, in bytes. Real entries are about 2 KiB; the cap bounds parser work (SEC-2).
const MAX_ENTRY_BYTES: usize = 64 * 1024;

/// How well a camera model is supported.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum SupportLevel {
    /// Everything listed was exercised against a real camera.
    Verified,
    /// Works, but some listed capabilities are unconfirmed or have known gaps.
    Partial,
    /// Reported by users; not exercised by the maintainers.
    Community,
    /// Known not to work.
    Unsupported,
}

impl SupportLevel {
    /// Stable lowercase name, as used in the TOML files.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Verified => "verified",
            Self::Partial => "partial",
            Self::Community => "community",
            Self::Unsupported => "unsupported",
        }
    }
}

/// A firmware family, `major.minor` only: patch levels and builds can identify a unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct FirmwareFamily {
    /// Major version.
    pub major: u16,
    /// Minor version.
    pub minor: u16,
}

impl FirmwareFamily {
    /// Parses `"<major>.<minor>"`: exactly two decimal numbers of up to four digits.
    ///
    /// # Errors
    /// Returns a message when the text is not in that form.
    pub fn parse(text: &str) -> Result<Self, String> {
        let number = |part: &str| -> Result<u16, String> {
            if part.is_empty() || part.len() > 4 || !part.bytes().all(|b| b.is_ascii_digit()) {
                return Err("firmware family must be major.minor, digits only".to_owned());
            }
            part.parse::<u16>().map_err(|e| e.to_string())
        };
        match text.split_once('.') {
            Some((major, minor)) => Ok(Self {
                major: number(major)?,
                minor: number(minor)?,
            }),
            None => Err("firmware family must be major.minor, digits only".to_owned()),
        }
    }
}

impl std::fmt::Display for FirmwareFamily {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)
    }
}

impl<'de> Deserialize<'de> for FirmwareFamily {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let text = String::deserialize(d)?;
        Self::parse(&text).map_err(de::Error::custom)
    }
}

/// Video codec of a stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Codec {
    /// H.264 / AVC.
    H264,
    /// H.265 / HEVC.
    H265,
}

impl Codec {
    /// Display name, e.g. `H.264`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::H264 => "H.264",
            Self::H265 => "H.265",
        }
    }
}

/// Which stream of the camera is described.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum StreamRole {
    /// The full-resolution stream.
    Main,
    /// The low-resolution stream.
    Sub,
}

/// Observed parameters of one stream.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct Stream {
    /// Main or sub stream.
    pub role: StreamRole,
    /// Video codec.
    pub codec: Codec,
    /// Width in pixels.
    pub width: u32,
    /// Height in pixels.
    pub height: u32,
    /// Measured frames per second, when known.
    pub fps: Option<f32>,
    /// Keyframe interval in frames, when known.
    pub gop: Option<u32>,
}

/// A way of talking to the camera.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ProtocolKind {
    /// RTSP video.
    Rtsp,
    /// ONVIF services.
    Onvif,
    /// Reolink Baichuan (port 9000 by default).
    Baichuan,
    /// Dahua CGI HTTP API.
    DahuaCgi,
    /// Tapo local HTTPS API.
    TapoHttps,
}

impl ProtocolKind {
    /// Stable lowercase name, as used in the TOML files.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Rtsp => "rtsp",
            Self::Onvif => "onvif",
            Self::Baichuan => "baichuan",
            Self::DahuaCgi => "dahua_cgi",
            Self::TapoHttps => "tapo_https",
        }
    }
}

/// One protocol the model speaks, with its usual port and (for RTSP) stream paths.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct Protocol {
    /// Which protocol.
    pub kind: ProtocolKind,
    /// TCP port, when known.
    pub port: Option<u16>,
    /// URL paths (RTSP stream paths), never full URLs.
    #[serde(default)]
    pub paths: Vec<String>,
}

/// What an event is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum EventKind {
    /// Generic motion.
    Motion,
    /// A person was detected.
    Person,
    /// A vehicle was detected.
    Vehicle,
    /// Intrusion rule fired.
    Intrusion,
    /// Line-crossing rule fired.
    LineCross,
    /// Camera tampering.
    Tamper,
    /// Vendor-defined smart event without a finer classification.
    SmartEvent,
    /// Another client's RTSP session ended (a client-presence signal).
    ClientDisconnect,
}

impl EventKind {
    /// Stable lowercase name, as used in the TOML files.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Motion => "motion",
            Self::Person => "person",
            Self::Vehicle => "vehicle",
            Self::Intrusion => "intrusion",
            Self::LineCross => "line_cross",
            Self::Tamper => "tamper",
            Self::SmartEvent => "smart_event",
            Self::ClientDisconnect => "client_disconnect",
        }
    }
}

/// Channel an event arrives on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum EventSource {
    /// ONVIF events (`PullPoint`).
    Onvif,
    /// Reolink Baichuan push.
    Baichuan,
    /// Vendor CGI long-poll.
    Cgi,
}

/// How firmly an event is known to work.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum EventStatus {
    /// Seen on the wire from a real camera.
    Observed,
    /// Advertised or documented, not yet seen live.
    Advertised,
}

/// An event the camera can emit.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct Event {
    /// What the event means.
    pub kind: EventKind,
    /// Where it arrives.
    pub source: EventSource,
    /// Observed live, or only advertised.
    pub status: EventStatus,
}

/// A setting the optimizer may change on this model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ConfigFeature {
    /// Which network services (HTTP, RTSP, ONVIF) are enabled and on which port.
    ServicePorts,
}

/// A pointer to the evidence behind an entry.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct Evidence {
    /// Repository path, issue or PR reference, e.g. `docs/adr/0002-camera-integration.md`.
    pub reference: String,
    /// Section or detail within the reference.
    pub section: Option<String>,
}

/// One camera model and what is known about it.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct CatalogueEntry {
    /// Vendor name, e.g. `Reolink`.
    pub vendor: String,
    /// Model name, e.g. `RLC-520A`.
    pub model: String,
    /// Other names the model is sold under (OEM names).
    #[serde(default)]
    pub aliases: Vec<String>,
    /// Support level.
    pub support: SupportLevel,
    /// Firmware families the entry was tested on.
    #[serde(default)]
    pub firmware: Vec<FirmwareFamily>,
    /// Stream parameters.
    #[serde(default)]
    pub streams: Vec<Stream>,
    /// Protocols spoken.
    #[serde(default)]
    pub protocols: Vec<Protocol>,
    /// Events the camera emits.
    #[serde(default)]
    pub events: Vec<Event>,
    /// Settings the optimizer may change.
    #[serde(default)]
    pub configurable: Vec<ConfigFeature>,
    /// Known quirks, in prose.
    #[serde(default)]
    pub quirks: Vec<String>,
    /// Evidence links; at least one is required by [`validate`](super::validate).
    #[serde(default)]
    pub evidence: Vec<Evidence>,
}

impl CatalogueEntry {
    /// Parses one entry from TOML text. Unknown fields are rejected. This does not run
    /// [`validate`](super::validate); call it too.
    ///
    /// # Errors
    /// [`CatalogueError::TooLarge`] above 64 KiB, [`CatalogueError::Parse`] for bad TOML,
    /// unknown fields, unknown enum values or a malformed firmware family.
    pub fn from_toml_str(text: &str) -> Result<Self, CatalogueError> {
        if text.len() > MAX_ENTRY_BYTES {
            return Err(CatalogueError::TooLarge {
                len: text.len(),
                max: MAX_ENTRY_BYTES,
            });
        }
        toml::from_str(text).map_err(|e| CatalogueError::Parse(e.message().to_owned()))
    }

    /// Lowercase, hyphen-separated form of the vendor, used as the directory name.
    #[must_use]
    pub fn vendor_slug(&self) -> String {
        slug(&self.vendor)
    }

    /// Lowercase, hyphen-separated form of the model, used as the file stem.
    #[must_use]
    pub fn model_slug(&self) -> String {
        slug(&self.model)
    }
}

/// Lowercases, maps every run of non-alphanumeric characters to one `-`, trims `-` at the ends.
fn slug(text: &str) -> String {
    let mut out = String::new();
    let mut pending_dash = false;
    for c in text.chars() {
        if c.is_ascii_alphanumeric() {
            if pending_dash && !out.is_empty() {
                out.push('-');
            }
            pending_dash = false;
            out.push(c.to_ascii_lowercase());
        } else {
            pending_dash = true;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL: &str = r#"
vendor = "Acme"
model = "Cam 1"
support = "community"
"#;

    #[test]
    fn parses_minimal_entry() {
        let e = CatalogueEntry::from_toml_str(MINIMAL).unwrap();
        assert_eq!(e.support, SupportLevel::Community);
        assert_eq!(e.evidence.len(), 0);
    }

    #[test]
    fn rejects_unknown_top_level_field() {
        let err = CatalogueEntry::from_toml_str(&format!("{MINIMAL}ip = \"x\"\n")).unwrap_err();
        assert!(matches!(err, CatalogueError::Parse(_)), "{err}");
    }

    #[test]
    fn rejects_unknown_nested_field() {
        let text = format!(
            "{MINIMAL}[[events]]\nkind=\"motion\"\nsource=\"cgi\"\nstatus=\"observed\"\nextra=1\n"
        );
        assert!(CatalogueEntry::from_toml_str(&text).is_err());
    }

    #[test]
    fn rejects_unknown_enum_values() {
        let head = "vendor=\"A\"\nmodel=\"B\"\n";
        for bad in [
            "support = \"great\"\n",
            "support=\"verified\"\nstreams = [{role=\"main\", codec=\"vp9\", width=1, height=1}]\n",
            "support=\"verified\"\nprotocols = [{kind=\"telnet\"}]\n",
            "support=\"verified\"\nevents = [{kind=\"ghost\", source=\"cgi\", status=\"observed\"}]\n",
            "support=\"verified\"\nevents = [{kind=\"motion\", source=\"pigeon\", status=\"observed\"}]\n",
        ] {
            assert!(
                CatalogueEntry::from_toml_str(&format!("{head}{bad}")).is_err(),
                "{bad}"
            );
        }
    }

    #[test]
    fn rejects_oversized_input() {
        let text = format!("{MINIMAL}# {}\n", "x".repeat(MAX_ENTRY_BYTES));
        assert!(matches!(
            CatalogueEntry::from_toml_str(&text),
            Err(CatalogueError::TooLarge { .. })
        ));
    }

    #[test]
    fn accepts_input_at_the_size_cap() {
        let pad = MAX_ENTRY_BYTES - MINIMAL.len() - 3;
        let text = format!("{MINIMAL}# {}\n", "x".repeat(pad));
        assert_eq!(text.len(), MAX_ENTRY_BYTES);
        assert!(CatalogueEntry::from_toml_str(&text).is_ok());
    }

    #[test]
    fn firmware_is_major_minor_only() {
        assert_eq!(
            FirmwareFamily::parse("3.0"),
            Ok(FirmwareFamily { major: 3, minor: 0 })
        );
        for bad in [
            "3", "3.0.1", "v3.0", "3.", ".0", "", "3.x", "12345.0", "-1.0", "3.0 ",
        ] {
            assert!(FirmwareFamily::parse(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn firmware_with_build_number_is_a_parse_error() {
        let text = format!("{MINIMAL}firmware = [\"3.0.0.12\"]\n");
        assert!(matches!(
            CatalogueEntry::from_toml_str(&text),
            Err(CatalogueError::Parse(_))
        ));
    }

    #[test]
    fn rejects_garbage_and_empty_input() {
        assert!(CatalogueEntry::from_toml_str("\u{0}\u{1}[[[").is_err());
        assert!(CatalogueEntry::from_toml_str("").is_err());
    }

    #[test]
    fn slugs_are_lowercase_hyphenated() {
        let e = CatalogueEntry::from_toml_str(
            "vendor=\"TP-Link\"\nmodel=\"Tapo C110\"\nsupport=\"partial\"\n",
        )
        .unwrap();
        assert_eq!(e.vendor_slug(), "tp-link");
        assert_eq!(e.model_slug(), "tapo-c110");
        assert_eq!(slug("  --A__B!! "), "a-b");
        assert_eq!(slug("Ünï"), "n");
    }
}
