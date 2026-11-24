//! [`RtspPath`]: the path and optional query of a camera's RTSP URL, never a full URL.
//!
//! Input forms:
//!
//! | input | result |
//! |---|---|
//! | `/`, `/stream1`, `/h264Preview_01_main`, `/11` | accepted |
//! | `/cam/realmonitor?channel=1&subtype=0` (Dahua), any `?query` of printable ASCII | accepted |
//! | `/a?b?c`, `/?`, `/a?x=1;y=2` | accepted (a later `?` is plain query text) |
//! | `/a:b`, `/a=b`, `/a,b`, `/a~b`, `/a//b` (inner `//`) | accepted |
//! | empty, no leading `/`, `?q` alone, `rtsp://h/p`, `h/p` | `PathStart` |
//! | `//x`, `//` (would parse as an authority) | `PathStart` |
//! | more than 512 bytes | `PathTooLong` |
//! | space, tab, newline, NUL, any control char incl. DEL, any non-ASCII | `PathCharset` |
//! | `@` anywhere (userinfo), `\`, `#` (fragment), `%` (no percent-encoding: one spelling) | `PathCharset` |
//! | a `.` or `..` segment in the path part (`/..`, `/a/./b`, `/a/..`) | `PathDotSegment` |
//! | a query parameter named (case-insensitive) `pass`, `password`, `pwd`, `user`, `usr`, `username`, `token`, `auth`, `key`, `secret`, `login`, `passwd` | `PathCredentialParam` |
//!
//! Query parameters are split on `&` and `;`; the name is the text before the first `=`.
//! A name is checked after trimming nothing: spaces and `%` are already refused, so there is
//! no way to spell a denied name differently.

use std::fmt;
use std::str::FromStr;

use super::CameraError;

/// Longest path (with query) in bytes.
pub const MAX_PATH_LEN: usize = 512;

const DENIED_PARAMS: [&str; 12] = [
    "pass", "password", "passwd", "pwd", "user", "usr", "username", "login", "token", "auth",
    "key", "secret",
];

/// A validated RTSP path. Not site-identifying (vendor stream templates), so `Debug` and `Display`
/// print it as is.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RtspPath(String);

impl RtspPath {
    /// Validates `text` as an RTSP path (see the module table).
    ///
    /// # Errors
    /// [`CameraError`] naming the failed rule, never echoing `text`.
    pub fn new(text: &str) -> Result<Self, CameraError> {
        if !text.starts_with('/') || text.starts_with("//") {
            return Err(CameraError::PathStart);
        }
        if text.len() > MAX_PATH_LEN {
            return Err(CameraError::PathTooLong);
        }
        if !text
            .bytes()
            .all(|b| (0x21..=0x7e).contains(&b) && !matches!(b, b'@' | b'\\' | b'#' | b'%'))
        {
            return Err(CameraError::PathCharset);
        }
        let (path, query) = match text.split_once('?') {
            Some((p, q)) => (p, Some(q)),
            None => (text, None),
        };
        if path.split('/').any(|seg| seg == "." || seg == "..") {
            return Err(CameraError::PathDotSegment);
        }
        if let Some(q) = query {
            let denied = q.split(['&', ';']).any(|param| {
                let name = param.split_once('=').map_or(param, |(n, _)| n);
                DENIED_PARAMS.iter().any(|d| name.eq_ignore_ascii_case(d))
            });
            if denied {
                return Err(CameraError::PathCredentialParam);
            }
        }
        Ok(Self(text.to_owned()))
    }

    /// The path text, starting with `/`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RtspPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for RtspPath {
    type Err = CameraError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_vendor_paths() {
        for p in [
            "/",
            "/stream1",
            "/h264Preview_01_main",
            "/11",
            "/cam/realmonitor?channel=1&subtype=0",
            "/a?b?c",
            "/?",
            "/a?x=1;y=2",
            "/a:b",
            "/a=b",
            "/a,b",
            "/a~b",
            "/a/b//c",
            "/a.b",
            "/.hidden",
            "/a/b.",
            "/a?keyframe=1",
            "/a?passage=2",
            "/a?users=3",
            "/a?tokens=1",
        ] {
            assert_eq!(RtspPath::new(p).unwrap().as_str(), p);
        }
        assert!(RtspPath::new(&format!("/{}", "a".repeat(511))).is_ok());
    }

    #[test]
    fn rejects_bad_start() {
        for p in [
            "",
            "a",
            "?q",
            "rtsp://h.invalid/p",
            "h/p",
            "//x",
            "//",
            "///a",
            " /a",
            "\\a",
        ] {
            assert_eq!(RtspPath::new(p), Err(CameraError::PathStart), "{p:?}");
        }
    }

    #[test]
    fn rejects_too_long() {
        assert_eq!(
            RtspPath::new(&format!("/{}", "a".repeat(512))),
            Err(CameraError::PathTooLong)
        );
    }

    #[test]
    fn rejects_bad_characters() {
        for p in [
            "/a b",
            "/a\tb",
            "/a\nb",
            "/a\rb",
            "/a\0b",
            "/a\x7f",
            "/a\x1b",
            "/ ",
            "/a ",
            "/a\u{a0}",
            "/a\u{3000}",
            "/\u{e9}",
            "/\u{ff0f}",
            "/a\u{200b}",
            "/a@b",
            "/@",
            "/a?x=1@h",
            "/a\\b",
            "/a#f",
            "/#",
            "/a?x=1#f",
            "/a%2f",
            "/%41",
            "/a%",
            "/a?x=%41",
            "/a?x=1 &y=2",
            "/a\u{85}",
        ] {
            assert_eq!(RtspPath::new(p), Err(CameraError::PathCharset), "{p:?}");
        }
    }

    #[test]
    fn rejects_dot_segments_in_the_path_only() {
        for p in [
            "/..", "/.", "/a/..", "/a/./b", "/../a", "/a/../b", "/a/.?x=1", "/..?x=1",
        ] {
            assert_eq!(RtspPath::new(p), Err(CameraError::PathDotSegment), "{p:?}");
        }
        assert!(RtspPath::new("/a?x=../b").is_ok());
    }

    #[test]
    fn rejects_credential_query_parameters() {
        for q in [
            "pass=x",
            "password=x",
            "PASSWORD=x",
            "Pwd=x",
            "user=x",
            "usr=x",
            "username=x",
            "token=x",
            "auth=x",
            "key=x",
            "secret=x",
            "login=x",
            "passwd=x",
            "pass",
            "user=",
            "a=1&pass=x",
            "a=1;user=x",
            "a=1&b=2&Token=x",
            "&auth=1",
            "x=1&&key=2",
        ] {
            let p = format!("/a?{q}");
            assert_eq!(
                RtspPath::new(&p),
                Err(CameraError::PathCredentialParam),
                "{p}"
            );
        }
        assert!(RtspPath::new("/a?channel=1&subtype=0").is_ok());
        assert!(RtspPath::new("/a?x=pass").is_ok());
    }

    #[test]
    fn errors_never_echo_input() {
        for p in ["/secret@x", "/a?password=hunter2", "/secret path", "secret"] {
            let msg = RtspPath::new(p).unwrap_err().to_string();
            assert!(!msg.contains("secret") && !msg.contains("hunter2"), "{msg}");
        }
    }

    proptest::proptest! {
        #[test]
        fn arbitrary_input_never_panics_and_accepted_is_clean(s in "\\PC{0,600}") {
            if let Ok(p) = RtspPath::new(&s) {
                let t = p.as_str();
                proptest::prop_assert!(t.starts_with('/') && !t.starts_with("//"));
                proptest::prop_assert!(t.len() <= 512);
                proptest::prop_assert!(t.bytes().all(|b| (0x21..=0x7e).contains(&b)));
                proptest::prop_assert!(!t.contains(['@', '\\', '#', '%']));
            }
        }

        #[test]
        fn plain_paths_round_trip(s in "/[a-zA-Z0-9_/=&?;:,~-][a-zA-Z0-9_/=&?;:,~-]{0,100}") {
            match RtspPath::new(&s) {
                Ok(p) => proptest::prop_assert_eq!(p.to_string().parse::<RtspPath>().unwrap(), p),
                Err(e) if s.starts_with("//") => proptest::prop_assert_eq!(e, CameraError::PathStart),
                Err(e) => proptest::prop_assert_eq!(e, CameraError::PathCredentialParam),
            }
        }
    }
}
