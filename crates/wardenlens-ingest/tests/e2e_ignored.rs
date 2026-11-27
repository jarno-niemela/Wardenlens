//! Manual end-to-end run against a real RTSP server, for example a local mediamtx.
//!
//! ```text
//! WARDENLENS_TEST_RTSP_URL=rtsp://127.0.0.1:8554/stream \
//!   cargo test -p wardenlens-ingest --test e2e_ignored -- --ignored --nocapture
//! ```
//!
//! The URL is read from the environment only and is never printed. It must not carry a user name
//! or password: the test opens the stream anonymously. The report it prints names no host, path
//! or credential, so it can be pasted into a PR. Per stream it gives the codec parameters, the
//! SPS reorder verdict and whether any B slice was seen in the first frames (ADR 0005 open
//! risk 1); the owner runs it on their own streams.
#![expect(
    clippy::print_stdout,
    reason = "the manual report is the output of this ignored test"
)]

use std::num::NonZeroU16;

use url::Url;
use wardenlens_core::camera::{Host, RtspPath};
use wardenlens_core::catalogue::StreamRole;
use wardenlens_core::time::{Clock, Timestamp};
use wardenlens_ingest::{H264ParamsExt, ReorderVerdict, contains_b_slice, open_stream, parse_sps};

const FRAMES_TO_OBSERVE: usize = 300;

struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Timestamp {
        let ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX));
        Timestamp::from_unix_millis(ms)
    }
}

#[tokio::test]
#[ignore = "needs WARDENLENS_TEST_RTSP_URL pointing at a reachable RTSP server"]
async fn reports_frames_and_reordering_for_one_stream() {
    let raw = std::env::var("WARDENLENS_TEST_RTSP_URL")
        .expect("set WARDENLENS_TEST_RTSP_URL (see the module docs)");
    let url = Url::parse(&raw).expect("WARDENLENS_TEST_RTSP_URL is not a URL");
    assert_eq!(url.scheme(), "rtsp", "the URL must be rtsp://");
    assert!(
        url.username().is_empty() && url.password().is_none(),
        "put no credentials in the URL; this test is anonymous"
    );
    let host = Host::new(url.host_str().expect("URL has no host")).expect("host is not valid");
    let port = NonZeroU16::new(url.port().unwrap_or(554)).expect("port 0");
    let mut path = url.path().to_owned();
    if let Some(q) = url.query() {
        path.push('?');
        path.push_str(q);
    }
    let path = RtspPath::new(&path).expect("path is not a valid RTSP path");

    let mut stream = open_stream(&host, port, &path, None, StreamRole::Main, SystemClock)
        .await
        .expect("open_stream failed");

    let mut frames = 0_usize;
    let mut keyframes = 0_usize;
    let mut b_slices = 0_usize;
    let mut discontinuities = 0_usize;
    let mut param_changes = 0_usize;
    let mut last_verdict = None;
    for _ in 0..FRAMES_TO_OBSERVE {
        let Some(frame) = stream.next_frame().await.expect("stream failed") else {
            break;
        };
        frames += 1;
        keyframes += usize::from(frame.is_keyframe);
        discontinuities += usize::from(frame.discontinuity);
        b_slices += usize::from(contains_b_slice(&frame.data).expect("malformed frame"));
        if let Some(p) = &frame.params {
            param_changes += 1;
            let summary = parse_sps(&p.sps).map(|s| {
                (
                    s.profile_idc,
                    s.pic_order_cnt_type,
                    s.max_num_reorder_frames,
                )
            });
            println!("SPS (profile_idc, pic_order_cnt_type, max_num_reorder_frames): {summary:?}");
            last_verdict = Some(p.reordering());
        }
    }
    println!(
        "frames observed: {frames}, keyframes: {keyframes}, parameter sets seen: {param_changes}"
    );
    println!(
        "discontinuities: {discontinuities}, dropped oversize: {}",
        stream.dropped_oversize()
    );
    println!("frames with a B slice: {b_slices}");
    println!("SPS reorder verdict: {last_verdict:?}");
    assert!(frames > 0, "no frame arrived");
    assert!(param_changes > 0, "no parameter sets arrived");
    if matches!(last_verdict, Some(Ok(ReorderVerdict::NoReordering(_)))) {
        assert_eq!(
            b_slices, 0,
            "the SPS excludes reordering but B slices were seen"
        );
    }
}
