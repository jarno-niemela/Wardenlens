//! [`RtspPath`]: the path and optional query of a camera's RTSP URL, never a full URL.
//!
//! Input forms:
//!
//! Allowed characters are RFC 3986 `pchar` (unreserved, sub-delims, `:`) plus `/` and `?`, minus
//! `@` and `%`, so a URL parser never re-encodes the text and there is one spelling.
//!
//! | input | result |
//! |---|---|
//! | `/`, `/stream1`, `/h264Preview_01_main`, `/11` | accepted |
//! | `/cam/realmonitor?channel=1&subtype=0` (Dahua), any `?query` of allowed characters | accepted |
//! | `/a?b?c`, `/?`, `/a?x=1;y=2` | accepted (a later `?` is plain query text) |
//! | `/a:b`, `/a=b`, `/a,b`, `/a~b`, `/a(b)`, `/a!$'*+`, `/a//b` (inner `//`) | accepted |
//! | empty, no leading `/`, `?q` alone, `rtsp://h/p`, `h/p` | `PathStart` |
//! | `//x`, `//` (would parse as an authority) | `PathStart` |
//! | more than 512 bytes | `PathTooLong` |
//! | space, tab, newline, NUL, any control char incl. DEL, any non-ASCII | `PathCharset` |
//! | `@` (userinfo), `\`, `#` (fragment), `%` (no percent-encoding), `"`, `<`, `>`, `[`, `]`, `^`, `` ` ``, `{`, `}`, the pipe | `PathCharset` |
//! | a `.` or `..` segment in the path part (`/..`, `/a/./b`, `/a/..`) | `PathDotSegment` |
//! | a `name=value` pair whose name is on the credential list, **anywhere** (path or query) | `PathCredentialParam` |
//! | a bare query parameter without `=` whose name is on the list (`/a?pass`) | `PathCredentialParam` |
//!
//! Credential check: the whole text is split on every one of `/ ? & ; ,`; each piece is a
//! parameter, its name is the text before the first `=` (the whole piece when it has no `=` and
//! lies in the query). A name is compared case-insensitively with this list: `pass`, `passw`,
//! `passwd`, `password`, `passcode`, `pw`, `pwd`, `p`, `user`, `usr`, `u`, `username`,
//! `user_name`, `user-name`, `userid`, `user_id`, `login`, `loginuse`, `loginpas`, `token`,
//! `access_token`, `auth`, `key`, `apikey`, `api_key`, `api-key`, `secret`, `pword`, `account`, `psw`, `pswd`, `passwort`, `passphrase`, `authcode`, `authtoken`, `credential`. Also, for every `=`, the run of ASCII
//! alphanumerics, `_` and `-` right before it is split on `_` and `-` and every trailing join of
//! its pieces is compared with the list (separators removed), so `x_user_name=`, `+user_id=`, `_password=`, `0_user=`,
//! `+password=`, `(password=` and `:password=` are refused. This covers the
//! Xiongmai/XMEye form `/user=admin&password=x&channel=1&stream=0.sdp`, `;` path parameters and
//! a second `?`. The list can never be complete, so the second layer is that `Debug` and
//! `Display` of [`RtspPath`] print `<redacted-path>`: a credential name the list misses is still
//! never logged. Only [`RtspPath::as_str`] returns the text, for the RTSP client.

use std::fmt;
use std::str::FromStr;

use super::CameraError;

/// Longest path (with query) in bytes.
pub const MAX_PATH_LEN: usize = 512;

const DENIED_PARAMS: [&str; 36] = [
    "pass",
    "passw",
    "passwd",
    "password",
    "passcode",
    "pw",
    "pwd",
    "p",
    "user",
    "usr",
    "u",
    "username",
    "user_name",
    "user-name",
    "userid",
    "user_id",
    "login",
    "loginuse",
    "loginpas",
    "token",
    "access_token",
    "auth",
    "key",
    "apikey",
    "api_key",
    "api-key",
    "secret",
    "pword",
    "account",
    "psw",
    "pswd",
    "passwort",
    "passphrase",
    "authcode",
    "authtoken",
    "credential",
];

/// What [`RtspPath::redacted_for_display`] puts in place of every value.
pub const REDACTED_VALUE: &str = "***";

/// What `Debug` and `Display` print.
const REDACTED_PATH: &str = "<redacted-path>";

fn is_denied(name: &str) -> bool {
    DENIED_PARAMS.iter().any(|d| name.eq_ignore_ascii_case(d))
}

/// A list name or a candidate with `_` and `-` removed, lowercased, for the multi-word compare.
fn squashed(name: &str) -> String {
    name.chars()
        .filter(|c| !matches!(c, '_' | '-'))
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

/// True when the run of `[A-Za-z0-9_-]` at the end of `before_eq` (the text in front of one `=`),
/// split on `_` and `-`, has a trailing join of pieces on the list (separators removed on both
/// sides): `name`, `user_name` and `x_user_name` are all tried. So `_password=`, `0_user=`,
/// `+user_id=`, `x_user_name=` and `(password=` are caught whatever precedes the name, while a
/// name that merely ends in a listed word inside one piece (`monkey=`, `accounting=`) is not.
fn tail_denied(before_eq: &str) -> bool {
    let start = before_eq
        .bytes()
        .rposition(|b| !(b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-')))
        .map_or(0, |i| i.saturating_add(1));
    let run = before_eq.get(start..).unwrap_or_default();
    let pieces: Vec<&str> = run.split(['_', '-']).collect();
    (0..pieces.len()).any(|from| {
        let joined: String = pieces.get(from..).unwrap_or_default().concat();
        DENIED_PARAMS
            .iter()
            .any(|d| squashed(d) == squashed(&joined))
    })
}

/// RFC 3986 `pchar` plus `/` and `?`, without `@` and `%`.
fn allowed(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'-' | b'.'
                | b'_'
                | b'~'
                | b'!'
                | b'$'
                | b'&'
                | b'\''
                | b'('
                | b')'
                | b'*'
                | b'+'
                | b','
                | b';'
                | b'='
                | b':'
                | b'/'
                | b'?'
        )
}

/// A validated RTSP path. `Debug` and `Display` print `<redacted-path>` (a path can carry a
/// credential in a spelling the list misses); use [`RtspPath::as_str`] for the RTSP client.
#[derive(Clone, PartialEq, Eq, Hash)]
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
        if !text.bytes().all(allowed) {
            return Err(CameraError::PathCharset);
        }
        let (path, query) = match text.split_once('?') {
            Some((p, q)) => (p, Some(q)),
            None => (text, None),
        };
        if path.split('/').any(|seg| seg == "." || seg == "..") {
            return Err(CameraError::PathDotSegment);
        }
        let query_start = text.len().saturating_sub(query.map_or(0, str::len));
        let mut offset = 0_usize;
        for piece in text.split(['/', '?', '&', ';', ',']) {
            let name = match piece.split_once('=') {
                Some((n, _)) => Some(n),
                // A bare name counts only in the query: `/user` is just a path segment.
                None if offset >= query_start => Some(piece),
                None => None,
            };
            if name.is_some_and(is_denied) || piece.split('=').rev().skip(1).any(tail_denied) {
                return Err(CameraError::PathCredentialParam);
            }
            offset = offset.saturating_add(piece.len()).saturating_add(1);
        }
        Ok(Self(text.to_owned()))
    }

    /// The path text, starting with `/`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The path with every `name=value` value replaced by [`REDACTED_VALUE`], for showing to
    /// people and API clients. The text is split on `/`, `?`, `&` and `;`; in each piece
    /// containing `=`, everything after the first `=` becomes `***` (also an empty value, so
    /// neither length nor emptiness shows). Pieces without `=` and all separators are kept.
    ///
    /// This is structural: it does not depend on the credential name list, which can never be
    /// complete, so a credential in any `key=value` spelling is never shown. A secret carried in
    /// a bare segment (no `=`) is not detectable and is kept.
    #[must_use]
    pub fn redacted_for_display(&self) -> String {
        let mut out = String::with_capacity(self.0.len());
        let mut piece = String::new();
        let flush = |piece: &mut String, out: &mut String| {
            match piece.split_once('=') {
                Some((key, _)) => {
                    out.push_str(key);
                    out.push('=');
                    out.push_str(REDACTED_VALUE);
                }
                None => out.push_str(piece),
            }
            piece.clear();
        };
        for c in self.0.chars() {
            if matches!(c, '/' | '?' | '&' | ';') {
                flush(&mut piece, &mut out);
                out.push(c);
            } else {
                piece.push(c);
            }
        }
        flush(&mut piece, &mut out);
        out
    }

    /// The query string: the text after the first `?`, `None` when there is no `?`. `/a?` has
    /// the empty query `Some("")`, which is a query string like any other.
    #[must_use]
    pub fn query(&self) -> Option<&str> {
        self.0.split_once('?').map(|(_, q)| q)
    }
}

impl fmt::Debug for RtspPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED_PATH)
    }
}

impl fmt::Display for RtspPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED_PATH)
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
    fn query_is_the_text_after_the_first_question_mark() {
        for (p, q) in [
            ("/a", None),
            ("/a?", Some("")),
            ("/a?b=1", Some("b=1")),
            ("/a?b?c", Some("b?c")),
            ("/?x=1", Some("x=1")),
        ] {
            assert_eq!(RtspPath::new(p).unwrap().query(), q, "{p}");
        }
    }

    #[test]
    fn newly_listed_credential_names_are_refused_in_path_and_query() {
        for name in [
            "psw",
            "PSW",
            "pswd",
            "passwort",
            "passphrase",
            "authcode",
            "auth_code",
            "authtoken",
            "auth-token",
            "credential",
        ] {
            for p in [
                format!("/live/ch0_{name}=x"),
                format!("/a?{name}=x"),
                format!("/{name}=x"),
            ] {
                assert_eq!(
                    RtspPath::new(&p),
                    Err(CameraError::PathCredentialParam),
                    "{p}"
                );
            }
        }
    }

    #[test]
    fn credential_names_behind_any_separator_are_refused() {
        for p in [
            "/a?x=1&_password=2",
            "/a?0_user=1",
            "/a?+password=1",
            "/a?(password=1",
            "/a?:password=1",
            "/a?$password=1",
            "/a?pword=1",
            "/a?account=1",
            "/a?Account=1",
            "/x_pword=1",
        ] {
            assert_eq!(
                RtspPath::new(p),
                Err(CameraError::PathCredentialParam),
                "{p}"
            );
        }
        for p in [
            "/cam/realmonitor?channel=1&subtype=0",
            "/a?accounting=1",
            "/a?monkey=1",
            "/a?apikeys=1",
        ] {
            assert!(RtspPath::new(p).is_ok(), "{p}");
        }
    }

    #[test]
    fn multi_word_credential_names_are_refused_behind_any_prefix_but_not_inside_a_word() {
        for p in [
            "/a?x_user_name=1",
            "/a?0_user-name=1",
            "/a?+user_id=1",
            "/a?(user_name=1",
            "/a?x-api_key=1",
        ] {
            assert_eq!(
                RtspPath::new(p),
                Err(CameraError::PathCredentialParam),
                "{p}"
            );
        }
        for p in [
            "/a?monkey=1",
            "/a?accounting=1",
            "/a?apikeys=1",
            "/a?my_users=1",
            "/a?x_name=1",
        ] {
            assert!(RtspPath::new(p).is_ok(), "{p}");
        }
    }

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
            "/a(b)!$'*+",
            "/live/user",
            "/p/u",
            "/stream=0.sdp",
            "/a?x=1&stream=0",
            "/user_x=1",
            "/a?puser=1",
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
            "/a\"b",
            "/a<b>",
            "/a[0]",
            "/a^b",
            "/a`b",
            "/a{b}",
            "/a|b",
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
    fn rejects_credential_parameters_anywhere_in_the_text() {
        for p in [
            // Xiongmai/XMEye: the login rides in the path itself.
            "/user=admin&password=Tr0ub4dor-x9&channel=1&stream=0.sdp",
            "/user=admin_password=Tr0ub4dor-x9_channel=1_stream=0.sdp",
            "/live;user=admin;password=Tr0ub4dor-x9",
            "/live,user=admin,password=x",
            "/password=x",
            "/a/pass=x/b",
            "/a/PWD=x",
            // path parameters and a second `?`
            "/a;pw=x",
            "/a?x=1?password=y",
            "/a?x=1?y=2&token=z",
            "/a?x=1/user=y",
            // vendor names and the short ones
            "/videostream.cgi?loginuse=admin&loginpas=x",
            "/a?passw=x",
            "/a?passcode=x",
            "/a?user_name=x",
            "/a?user-name=x",
            "/a?userid=x",
            "/a?user_id=x",
            "/a?access_token=x",
            "/a?apikey=x",
            "/a?api_key=x",
            "/a?api-key=x",
            "/a?u=admin&p=x",
            "/a?P=x",
            "/u=admin&p=x",
            "/a?x=1;p=2",
        ] {
            assert_eq!(
                RtspPath::new(p),
                Err(CameraError::PathCredentialParam),
                "{p}"
            );
        }
    }

    #[test]
    fn bare_names_count_only_in_the_query() {
        assert!(RtspPath::new("/pass").is_ok());
        assert!(RtspPath::new("/user/token").is_ok());
        assert!(RtspPath::new("/a?pass").is_err());
        assert!(RtspPath::new("/a?x=1&token").is_err());
        assert!(RtspPath::new("/a/user?x=1").is_ok());
    }

    #[test]
    fn debug_and_display_are_redacted_everywhere() {
        // A name the list misses must still never be printed.
        let p = RtspPath::new("/cam?pin=Tr0ub4dor-x9&who=svc-reader").unwrap();
        for shown in [
            format!("{p}"),
            format!("{p:?}"),
            format!("{p:#?}"),
            format!("{p:>40}"),
            format!("{:?}", Some(&p)),
            format!("{:#?}", vec![p.clone()]),
            p.to_string(),
        ] {
            assert!(
                !shown.contains("Tr0ub4dor")
                    && !shown.contains("svc-reader")
                    && !shown.contains("pin"),
                "{shown}"
            );
            assert!(shown.contains("redacted"), "{shown}");
        }
        assert_eq!(p.as_str(), "/cam?pin=Tr0ub4dor-x9&who=svc-reader");
    }

    #[test]
    fn errors_never_echo_input() {
        for p in ["/secret@x", "/a?password=hunter2", "/secret path", "secret"] {
            let msg = RtspPath::new(p).unwrap_err().to_string();
            assert!(!msg.contains("secret") && !msg.contains("hunter2"), "{msg}");
        }
    }

    #[test]
    fn redaction_replaces_every_value_and_keeps_the_rest() {
        for (input, want) in [
            ("/", "/"),
            ("/main", "/main"),
            ("/live?pin=abc", "/live?pin=***"),
            ("/live?pin=", "/live?pin=***"),
            ("/live?a=1&b=2;c=3", "/live?a=***&b=***;c=***"),
            (
                "/cam/realmonitor?channel=1&subtype=0",
                "/cam/realmonitor?channel=***&subtype=***",
            ),
            (
                "/k1=a&k2=b&channel=1&stream=0.sdp",
                "/k1=***&k2=***&channel=***&stream=***",
            ),
            ("/a;k=v/b", "/a;k=***/b"),
            ("/a?x=1=2&y", "/a?x=***&y"),
            ("/a?b?c=d", "/a?b?c=***"),
            ("/a?q=x,y=z", "/a?q=***"),
        ] {
            assert_eq!(
                RtspPath::new(input).unwrap().redacted_for_display(),
                want,
                "{input}"
            );
        }
    }

    proptest::proptest! {
        /// Values drawn from an alphabet the rest of the path never uses cannot survive.
        #[test]
        fn redaction_leaves_no_value_bytes(
            segs in proptest::collection::vec(("zz[a-z0-9]{0,4}", "[A-Z]{1,8}", 0_u8..4), 1..6)
        ) {
            let mut text = String::from("/zzbase");
            for (k, v, sep) in &segs {
                text.push([ '/', '?', '&', ';' ][usize::from(*sep)]);
                text.push_str(k);
                text.push('=');
                text.push_str(v);
            }
            if let Ok(p) = RtspPath::new(&text) {
                let shown = p.redacted_for_display();
                proptest::prop_assert!(!shown.bytes().any(|b| b.is_ascii_uppercase()), "{shown}");
                proptest::prop_assert!(shown.matches("=***").count() >= segs.len());
            }
        }

        /// Over any accepted path: same pieces, every `=` piece becomes `key=***`, others stay.
        #[test]
        fn redaction_is_structural_for_any_accepted_path(s in "/[a-z0-9=&;?/,.:_-]{0,80}") {
            if let Ok(p) = RtspPath::new(&s) {
                let shown = p.redacted_for_display();
                let seps = ['/', '?', '&', ';'];
                let orig: Vec<&str> = s.split(seps).collect();
                let out: Vec<&str> = shown.split(seps).collect();
                proptest::prop_assert_eq!(orig.len(), out.len());
                for (o, r) in orig.iter().zip(&out) {
                    if let Some((k, _)) = o.split_once('=') {
                        proptest::prop_assert_eq!(*r, format!("{k}=***"));
                    } else {
                        proptest::prop_assert_eq!(o, r);
                    }
                }
            }
        }
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
                Ok(p) => proptest::prop_assert_eq!(p.as_str().parse::<RtspPath>().unwrap(), p),
                Err(e) if s.starts_with("//") => proptest::prop_assert_eq!(e, CameraError::PathStart),
                Err(e) => proptest::prop_assert_eq!(e, CameraError::PathCredentialParam),
            }
        }
    }
}
