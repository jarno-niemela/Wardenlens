//! `reduce_stream_uri`: one row per form in the module table of `stream_uri.rs` (TEST-9).

use std::num::NonZeroU16;

use crate::{OnvifError, StreamEndpoint, reduce_stream_uri};
use wardenlens_core::camera::CameraError;

fn ok(uri: &str) -> (String, u16) {
    let e: StreamEndpoint = reduce_stream_uri(uri).unwrap_or_else(|e| panic!("{uri}: {e:?}"));
    (e.path.as_str().to_owned(), e.port.get())
}

#[test]
fn accepted_forms() {
    let rows: [(&str, &str, u16); 22] = [
        ("rtsp://192.0.2.10/p", "/p", 554),
        ("RTSP://192.0.2.10/p", "/p", 554),
        ("RtSp://192.0.2.10:8554/p?q=1", "/p?q=1", 8554),
        ("rtsp://192.0.2.10", "/", 554),
        ("rtsp://192.0.2.10?x=1", "/?x=1", 554),
        ("rtsp://192.0.2.10/", "/", 554),
        ("rtsp://192.0.2.10:/p", "/p", 554),
        ("rtsp://192.0.2.10:1/p", "/p", 1),
        ("rtsp://192.0.2.10:65535/p", "/p", 65535),
        ("rtsp://192.0.2.10:00554/p", "/p", 554),
        ("rtsp://[2001:db8::1]/p", "/p", 554),
        ("rtsp://[2001:db8::1]:8554/p", "/p", 8554),
        ("rtsp://[2001:db8::1]:/p", "/p", 554),
        (
            "rtsp://cam.invalid:8554/h264Preview_01_main",
            "/h264Preview_01_main",
            8554,
        ),
        (
            "rtsp://192.0.2.10:554/cam/realmonitor?channel=1&subtype=0",
            "/cam/realmonitor?channel=1&subtype=0",
            554,
        ),
        ("rtsp://192.0.2.10/11", "/11", 554),
        ("rtsp://192.0.2.10/stream2", "/stream2", 554),
        ("  rtsp://192.0.2.10/p\n", "/p", 554),
        // The host is ignored whatever it is.
        ("rtsp://198.51.100.99/p", "/p", 554),
        ("rtsp://other.invalid/p", "/p", 554),
        ("rtsp://999.999.999.999/p", "/p", 554),
        ("rtsp://h/a//b", "/a//b", 554),
    ];
    for (uri, path, port) in rows {
        assert_eq!(ok(uri), (path.to_owned(), port), "{uri}");
    }
}

#[test]
fn userinfo_is_dropped_in_every_spelling() {
    let rows = [
        "rtsp://admin:USERINFO-SENTINEL@192.0.2.10:8554/stream1",
        "rtsp://USERINFO-SENTINEL@192.0.2.10:8554/stream1",
        "rtsp://:USERINFO-SENTINEL@192.0.2.10:8554/stream1",
        "rtsp://a@b:USERINFO-SENTINEL@192.0.2.10:8554/stream1",
        "rtsp://a:b@c@192.0.2.10:8554/stream1",
        "rtsp://@192.0.2.10:8554/stream1",
        "rtsp://us%40er:USERINFO-SENTINEL@192.0.2.10:8554/stream1",
        "rtsp://us:er:USERINFO-SENTINEL@192.0.2.10:8554/stream1",
    ];
    for uri in rows {
        let e = reduce_stream_uri(uri).unwrap_or_else(|e| panic!("{uri}: {e:?}"));
        assert_eq!((e.path.as_str(), e.port.get()), ("/stream1", 8554), "{uri}");
        let shown = format!("{e:?}");
        assert!(
            !shown.contains("SENTINEL") && !shown.contains("admin"),
            "{uri}"
        );
    }
    // A `@` after the authority is path text, and RtspPath refuses it: never userinfo.
    assert_eq!(
        reduce_stream_uri("rtsp://192.0.2.10/p@q").err(),
        Some(OnvifError::StreamUriPath(CameraError::PathCharset))
    );
    // Userinfo is dropped even when the rest is refused: the error carries no text.
    let e =
        reduce_stream_uri("rtsp://admin:USERINFO-SENTINEL@192.0.2.10/p%41").expect_err("refused");
    assert!(!format!("{e} {e:?}").contains("SENTINEL"));
}

#[test]
fn refused_forms() {
    let rows: [(&str, OnvifError); 28] = [
        ("", OnvifError::StreamUriScheme),
        ("rtsp:/h/p", OnvifError::StreamUriScheme),
        ("rtsp:", OnvifError::StreamUriScheme),
        ("http://192.0.2.10/p", OnvifError::StreamUriScheme),
        ("rtsps://192.0.2.10/p", OnvifError::StreamUriScheme),
        ("192.0.2.10/p", OnvifError::StreamUriScheme),
        ("\u{e9}tsp://192.0.2.10/p", OnvifError::StreamUriScheme),
        ("rts\u{e9}://192.0.2.10/p", OnvifError::StreamUriScheme),
        ("rtsp://", OnvifError::StreamUriAuthority),
        ("rtsp:///p", OnvifError::StreamUriAuthority),
        ("rtsp://:554/p", OnvifError::StreamUriAuthority),
        ("rtsp://h:1:2/p", OnvifError::StreamUriAuthority),
        ("rtsp://[::1/p", OnvifError::StreamUriAuthority),
        ("rtsp://[::1]x/p", OnvifError::StreamUriAuthority),
        ("rtsp://[]/p", OnvifError::StreamUriAuthority),
        ("rtsp://[::1]:1:2/p", OnvifError::StreamUriPort),
        ("rtsp://a b/p", OnvifError::StreamUriAuthority),
        ("rtsp://a\tb/p", OnvifError::StreamUriAuthority),
        ("rtsp://caf\u{e9}/p", OnvifError::StreamUriAuthority),
        ("rtsp://h:0/p", OnvifError::StreamUriPort),
        ("rtsp://h:65536/p", OnvifError::StreamUriPort),
        ("rtsp://h:abc/p", OnvifError::StreamUriPort),
        ("rtsp://h:-1/p", OnvifError::StreamUriPort),
        ("rtsp://h:+1/p", OnvifError::StreamUriPort),
        ("rtsp://h:123456/p", OnvifError::StreamUriPort),
        ("rtsp://h:000000/p", OnvifError::StreamUriPort),
        ("rtsp://h:5 4/p", OnvifError::StreamUriAuthority),
        (
            "rtsp://h#frag",
            OnvifError::StreamUriPath(CameraError::PathStart),
        ),
    ];
    for (uri, want) in rows {
        assert_eq!(reduce_stream_uri(uri), Err(want), "{uri:?}");
    }
}

#[test]
fn path_refusals_come_from_the_core_validator() {
    let rows: [(&str, CameraError); 9] = [
        ("rtsp://h/a%20b", CameraError::PathCharset),
        ("rtsp://h/a#b", CameraError::PathCharset),
        ("rtsp://h/a b", CameraError::PathCharset),
        ("rtsp://h/../x", CameraError::PathDotSegment),
        ("rtsp://h/a/./b", CameraError::PathDotSegment),
        ("rtsp://h//x", CameraError::PathStart),
        // A camera that echoes credentials in the query: refused, never forwarded.
        (
            "rtsp://h/live?user=a&password=PATH-SENTINEL",
            CameraError::PathCredentialParam,
        ),
        (
            "rtsp://h/user=admin&password=PATH-SENTINEL&channel=1&stream=0.sdp",
            CameraError::PathCredentialParam,
        ),
        (
            "rtsp://h/live?token=PATH-SENTINEL",
            CameraError::PathCredentialParam,
        ),
    ];
    for (uri, rule) in rows {
        let e = reduce_stream_uri(uri).expect_err(uri);
        assert_eq!(e, OnvifError::StreamUriPath(rule), "{uri}");
        assert!(!format!("{e} {e:?}").contains("SENTINEL"), "{uri}");
    }
    // 512 bytes of path is the core limit.
    let exact = format!("rtsp://h/{}", "a".repeat(511));
    assert!(reduce_stream_uri(&exact).is_ok());
    let over = format!("rtsp://h/{}", "a".repeat(512));
    assert_eq!(
        reduce_stream_uri(&over).err(),
        Some(OnvifError::StreamUriPath(CameraError::PathTooLong))
    );
}

#[test]
fn uri_length_boundary() {
    let uri = |total: usize| {
        let base = "rtsp://h/";
        format!("{base}{}", "a".repeat(total - base.len()))
    };
    // 2048 passes the length check (then fails core's 512-byte path limit, a different error).
    assert_eq!(
        reduce_stream_uri(&uri(2048)).err(),
        Some(OnvifError::StreamUriPath(CameraError::PathTooLong))
    );
    assert_eq!(
        reduce_stream_uri(&uri(2049)).err(),
        Some(OnvifError::InvalidField { field: "Uri" })
    );
}

#[test]
fn the_host_in_the_reply_cannot_change_the_result() {
    let a = reduce_stream_uri("rtsp://192.0.2.10:8554/s?x=1").expect("a");
    for host in [
        "198.51.100.7",
        "other.invalid",
        "[2001:db8::9]",
        "u:p@203.0.113.5",
        "evil@x",
    ] {
        let b = reduce_stream_uri(&format!("rtsp://{host}:8554/s?x=1")).expect("b");
        assert_eq!(a, b, "{host}");
    }
    assert_eq!(a.port, NonZeroU16::new(8554).expect("nz"));
}
