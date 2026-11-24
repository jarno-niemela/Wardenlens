//! Validated camera ids and the derived segment path.

use std::fmt;
use std::str::FromStr;

use crate::time::UnixMs;

/// Errors from the recording module's validated types and the segmenter config.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RecordingError {
    /// The camera id is not `[a-z][a-z0-9-]{0,31}`.
    InvalidCameraId,
    /// The path is not the canonical `<camera>/<YYYY-MM-DD>/<HHMMSS>-<mmm>.mp4`.
    InvalidRelPath,
    /// The target segment duration is outside 10-290 s.
    TargetOutOfRange,
    /// The byte cap is zero.
    ZeroByteCap,
}

impl fmt::Display for RecordingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidCameraId => "camera id must match [a-z][a-z0-9-]{0,31}",
            Self::InvalidRelPath => "not a canonical segment path",
            Self::TargetOutOfRange => "target segment duration must be 10-290 seconds",
            Self::ZeroByteCap => "segment byte cap must be positive",
        })
    }
}

impl std::error::Error for RecordingError {}

/// A validated camera slug, `[a-z][a-z0-9-]{0,31}`; also a path component.
///
/// Minimal local definition: the camera model (#43) owns the shared type and
/// this is unified with it when both land.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CameraId(String);

impl CameraId {
    /// The id as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for CameraId {
    type Err = RecordingError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut bytes = s.bytes();
        let first_ok = bytes.next().is_some_and(|b| b.is_ascii_lowercase());
        let rest_ok = bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
        if first_ok && rest_ok && s.len() <= 32 {
            Ok(Self(s.to_owned()))
        } else {
            Err(RecordingError::InvalidCameraId)
        }
    }
}

impl fmt::Display for CameraId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

const MS_PER_DAY: i64 = 86_400_000;

/// Days since 1970-01-01 to (year, month, day). Hinnant's `civil_from_days`.
#[expect(
    clippy::arithmetic_side_effects,
    reason = "inputs are bounded to years 2000-2099, so no intermediate can overflow i64"
)]
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

/// (year, month, day) to days since 1970-01-01. Hinnant's `days_from_civil`.
#[expect(
    clippy::arithmetic_side_effects,
    reason = "callers pass year 2000-2099 and month/day below 100, so nothing can overflow i64"
)]
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = year - i64::from(month <= 2);
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = if month > 2 { month - 3 } else { month + 9 };
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The canonical relative path of a segment file, identical on both tiers.
///
/// Derived from a validated camera id and a bounded time, so it can contain
/// no `..`, separator or other character than the pattern allows (SEC-4).
/// Never taken from a camera or stored in the index.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RelPath {
    camera: CameraId,
    started_at: UnixMs,
}

impl RelPath {
    /// Builds the path of the segment of `camera` that started at `started_at`.
    #[must_use]
    pub fn new(camera: &CameraId, started_at: UnixMs) -> Self {
        Self {
            camera: camera.clone(),
            started_at,
        }
    }

    /// The camera component.
    #[must_use]
    pub fn camera(&self) -> &CameraId {
        &self.camera
    }

    /// The segment start time.
    #[must_use]
    pub fn started_at(&self) -> UnixMs {
        self.started_at
    }
}

impl fmt::Display for RelPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ms = self.started_at.as_i64();
        let (year, month, day) = civil_from_days(ms.div_euclid(MS_PER_DAY));
        let in_day = ms.rem_euclid(MS_PER_DAY);
        let (hour, minute, second, milli) = (
            in_day / 3_600_000,
            in_day / 60_000 % 60,
            in_day / 1000 % 60,
            in_day % 1000,
        );
        write!(
            f,
            "{}/{year:04}-{month:02}-{day:02}/{hour:02}{minute:02}{second:02}-{milli:03}.mp4",
            self.camera
        )
    }
}

/// Parses exactly `width` ASCII digits (no sign, no whitespace).
fn digits(s: &str, width: usize) -> Result<i64, RecordingError> {
    if s.len() == width && s.bytes().all(|b| b.is_ascii_digit()) {
        s.parse().map_err(|_| RecordingError::InvalidRelPath)
    } else {
        Err(RecordingError::InvalidRelPath)
    }
}

impl FromStr for RelPath {
    type Err = RecordingError;

    /// Strict parse: the text must be canonical, i.e. round-trip through
    /// [`RelPath::new`] (so `996099-000.mp4` or `2023-02-30` are rejected).
    #[expect(
        clippy::arithmetic_side_effects,
        reason = "every component is a fixed-width digit string (at most 4 digits), so the sums are tiny"
    )]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bad = RecordingError::InvalidRelPath;
        let mut parts = s.split('/');
        let (Some(cam), Some(day), Some(file), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(bad);
        };
        let camera: CameraId = cam.parse().map_err(|_| RecordingError::InvalidRelPath)?;
        let mut d = day.split('-');
        let (Some(y), Some(mo), Some(da), None) = (d.next(), d.next(), d.next(), d.next()) else {
            return Err(bad);
        };
        let stem = file
            .strip_suffix(".mp4")
            .ok_or(RecordingError::InvalidRelPath)?;
        let (clock, milli) = stem.split_once('-').ok_or(RecordingError::InvalidRelPath)?;
        // `get` returns None on a multibyte boundary, so no slice can panic.
        let (Some(h), Some(mi), Some(sec), 6) = (
            clock.get(0..2),
            clock.get(2..4),
            clock.get(4..6),
            clock.len(),
        ) else {
            return Err(bad);
        };
        let (year, month, dom) = (digits(y, 4)?, digits(mo, 2)?, digits(da, 2)?);
        let (h, mi, sec, milli) = (
            digits(h, 2)?,
            digits(mi, 2)?,
            digits(sec, 2)?,
            digits(milli, 3)?,
        );
        if !(2000..=2099).contains(&year) || !(1..=12).contains(&month) || !(1..=31).contains(&dom)
        {
            return Err(bad);
        }
        let ms = days_from_civil(year, month, dom) * MS_PER_DAY
            + h * 3_600_000
            + mi * 60_000
            + sec * 1000
            + milli;
        let started_at = UnixMs::new(ms).map_err(|_| RecordingError::InvalidRelPath)?;
        let path = Self::new(&camera, started_at);
        // Canonical form only: rejects hour 24+, minute 60+, 31 February and the like.
        if path.to_string() == s {
            Ok(path)
        } else {
            Err(bad)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIN_MS: i64 = 946_684_800_000;
    const MAX_MS: i64 = 4_102_444_799_999;

    fn cam(s: &str) -> CameraId {
        s.parse().unwrap()
    }

    #[test]
    fn formats_the_documented_layout() {
        // 2024-02-29T13:45:07.042Z
        let p = RelPath::new(&cam("hdipc"), UnixMs::new(1_709_214_307_042).unwrap());
        assert_eq!(p.to_string(), "hdipc/2024-02-29/134507-042.mp4");
    }

    #[test]
    fn formats_the_range_boundaries() {
        let first = RelPath::new(&cam("a"), UnixMs::new(MIN_MS).unwrap());
        assert_eq!(first.to_string(), "a/2000-01-01/000000-000.mp4");
        let last = RelPath::new(&cam("a"), UnixMs::new(MAX_MS).unwrap());
        assert_eq!(last.to_string(), "a/2099-12-31/235959-999.mp4");
    }

    #[test]
    fn rejects_times_outside_2000_2099() {
        assert!(UnixMs::new(MIN_MS - 1).is_err());
        assert!(UnixMs::new(MAX_MS + 1).is_err());
        assert!(UnixMs::new(0).is_err());
        assert!(UnixMs::new(i64::MAX).is_err());
        assert!(UnixMs::new(-1).is_err());
    }

    #[test]
    fn rejects_bad_camera_ids() {
        for bad in [
            "",
            "1cam",
            "-cam",
            "Cam",
            "ca_m",
            "a/b",
            "..",
            "a.b",
            "é",
            &"a".repeat(33),
        ] {
            assert!(bad.parse::<CameraId>().is_err(), "{bad:?}");
        }
        assert!("a".repeat(32).parse::<CameraId>().is_ok());
        assert!("a-1".parse::<CameraId>().is_ok());
    }

    #[test]
    fn rejects_noncanonical_paths() {
        for bad in [
            "",
            "hdipc/2024-02-29/134507-042.mp4.part",
            "hdipc/2024-02-29/996099-000.mp4",
            "hdipc/2024-02-29/240000-000.mp4",
            "hdipc/2024-02-30/000000-000.mp4",
            "hdipc/2023-02-29/000000-000.mp4",
            "hdipc/2024-2-29/134507-042.mp4",
            "hdipc/2024-02-29/134507-42.mp4",
            "hdipc/2024-02-29/+34507-042.mp4",
            "hdipc/1999-12-31/235959-999.mp4",
            "hdipc/2100-01-01/000000-000.mp4",
            "../2024-02-29/134507-042.mp4",
            "/hdipc/2024-02-29/134507-042.mp4",
            "hdipc/2024-02-29/134507-042.mp4/",
            "hdipc/x/2024-02-29/134507-042.mp4",
            "_quarantine/2024-02-29/134507-042.mp4",
        ] {
            assert!(bad.parse::<RelPath>().is_err(), "{bad:?}");
        }
    }

    #[test]
    fn parses_a_canonical_path() {
        let p: RelPath = "hdipc/2024-02-29/134507-042.mp4".parse().unwrap();
        assert_eq!(p.started_at().as_i64(), 1_709_214_307_042);
        assert_eq!(p.camera().as_str(), "hdipc");
    }

    proptest::proptest! {
        #[test]
        fn path_round_trips(ms in MIN_MS..=MAX_MS, id in "[a-z][a-z0-9-]{0,31}") {
            let p = RelPath::new(&id.parse().unwrap(), UnixMs::new(ms).unwrap());
            let back: RelPath = p.to_string().parse().unwrap();
            proptest::prop_assert_eq!(back, p);
        }

        #[test]
        fn well_formed_shape_with_arbitrary_characters_never_panics(
            cam in ".{0,6}", y in ".{0,5}", mo in ".{0,3}", da in ".{0,3}",
            h in ".{0,3}", mi in ".{0,3}", sec in ".{0,3}", ms in ".{0,4}",
        ) {
            let s = format!("{cam}/{y}-{mo}-{da}/{h}{mi}{sec}-{ms}.mp4");
            let _ = s.parse::<RelPath>();
        }

        #[test]
        fn arbitrary_text_never_panics(s in ".*") {
            let _ = s.parse::<RelPath>();
        }
    }
}
