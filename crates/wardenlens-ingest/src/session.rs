//! [`open_stream`] and [`FrameStream`]: the thin retina adapter around the pure mapping.
//!
//! Nothing here logs, and no retina error text leaves this module (see [`IngestError`]).

use std::num::NonZeroU16;
use std::time::Duration;

use futures_util::StreamExt;
use retina::client::{
    Credentials, Demuxed, PlayOptions, Session, SessionOptions, SetupOptions, StreamDirection,
    TcpTransportOptions, Transport,
};
use retina::codec::{CodecItem, FrameFormat, ParametersRef, VideoParametersCodec};
use secrecy::ExposeSecret;
use tokio::time::{Instant, timeout, timeout_at};
use url::Url;
use wardenlens_core::camera::{Credential, Host, RtspPath};
use wardenlens_core::catalogue::StreamRole;
use wardenlens_core::time::Clock;

use crate::error::IngestError;
use crate::frame::{Frame, FrameMapper, RawParams, RawVideoFrame};

/// Longest wait for connect, DESCRIBE, SETUP and PLAY together.
pub const OPEN_TIMEOUT: Duration = Duration::from_secs(15);

/// Longest wait for the next video frame. RTCP and audio do not extend it.
pub const FRAME_TIMEOUT: Duration = Duration::from_secs(10);

/// Largest RTSP response retina will buffer (a DESCRIBE answer is a few KiB). Interleaved RTP is
/// not covered, retina limits each message to under 64 KiB itself.
const MAX_RTSP_MESSAGE_BYTES: usize = 256 * 1024;

/// Most unfinished data retina may hold for one session (its read ring, which pins every packet
/// of the access unit being assembled). Just under 16 MiB, so the ring (a power of two) never
/// grows past 16 MiB, and well over [`crate::MAX_FRAME_BYTES`] plus its RTP and interleaving
/// headers: a frame at the cap still passes and an oversize one is still dropped and counted,
/// while an access unit that never ends fails the session. Needs the patched retina of ADR 0002
/// section 13.
const MAX_BUFFERED_BYTES: usize = 16 * 1024 * 1024 - 64 * 1024;

/// Most NALs in one access unit. Real cameras send a handful (slices, SEI, parameter sets). retina
/// keeps 28 bytes of metadata per NAL however short it is, which `MAX_BUFFERED_BYTES` does not
/// see (a 2-byte NAL costs 4 ring bytes), so this bounds that metadata to about 1.5 MiB (the
/// session also fails at 16 x this many pieces, which fragmented NALs add). More fails the
/// session. Needs the patched retina of ADR 0002 section 13.
pub const MAX_NALS_PER_ACCESS_UNIT: usize = 4096;

/// What `select_video_stream` needs to know about one SDP media section.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamInfo<'a> {
    /// The SDP media type (`video`, `audio`, `application`).
    pub media: &'a str,
    /// The lower-case encoding name (`h264`).
    pub encoding_name: &'a str,
    /// The camera sends this stream to us (not an ONVIF backchannel).
    pub receiving: bool,
}

/// Picks the first receiving H.264 video stream.
///
/// # Errors
/// [`IngestError::NoVideoStream`] when there is no receiving video stream and
/// [`IngestError::UnsupportedCodec`] when there is one but none is H.264.
pub fn select_video_stream(streams: &[StreamInfo<'_>]) -> Result<usize, IngestError> {
    let mut any_video = false;
    for (i, s) in streams.iter().enumerate() {
        if s.receiving && s.media == "video" {
            any_video = true;
            if s.encoding_name == "h264" {
                return Ok(i);
            }
        }
    }
    Err(if any_video {
        IngestError::UnsupportedCodec
    } else {
        IngestError::NoVideoStream
    })
}

/// The URL of the stream, with no user name or password in it.
fn stream_url(host: &Host, port: NonZeroU16, path: &RtspPath) -> Result<Url, IngestError> {
    let url = Url::parse(&format!(
        "rtsp://{}:{}{}",
        host.url_host(),
        port,
        path.as_str()
    ))
    .map_err(|_| IngestError::InvalidUrl)?;
    // A path cannot add an authority, but the credential rule is too important to leave to that.
    if url.scheme() != "rtsp" || !url.username().is_empty() || url.password().is_some() {
        return Err(IngestError::InvalidUrl);
    }
    Ok(url)
}

/// Keeps only the kind of a retina error.
fn classify(e: &retina::Error, otherwise: IngestError) -> IngestError {
    if e.is_basic_auth_refused() {
        return IngestError::BasicAuthRefused;
    }
    match e.status_code() {
        Some(401 | 403) => IngestError::AuthRejected,
        Some(status) => IngestError::Rejected(status),
        None => otherwise,
    }
}

/// An open session yielding the video frames of one stream.
///
/// `Debug` is not implemented: the session holds the camera address.
pub struct FrameStream<C> {
    demuxed: Demuxed,
    stream_i: usize,
    mapper: FrameMapper,
    clock: C,
    role: StreamRole,
    frame_timeout: Duration,
    finished: bool,
}

/// Per-camera choices for [`open_stream_with`]. The default is the safe one.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct OpenOptions {
    /// Answer a Basic-only challenge with the password, which then crosses the network in the
    /// clear (base64 is not protection). Off by default: a Basic-only challenge fails with
    /// [`IngestError::BasicAuthRefused`] and nothing is sent. A challenge that also offers Digest
    /// is answered with Digest either way.
    pub allow_basic_auth: bool,
}

impl OpenOptions {
    /// Sets [`OpenOptions::allow_basic_auth`].
    #[must_use]
    pub fn allow_basic_auth(mut self, allow: bool) -> Self {
        self.allow_basic_auth = allow;
        self
    }
}

/// Opens an RTSP session over TCP (interleaved) and starts playing the first H.264 video stream.
///
/// The URL is built from `host`, `port` and `path` and has no user info. Credentials go only
/// through retina's credential option, which uses them if the camera asks for digest
/// authentication. A Basic-only challenge is refused (see [`OpenOptions::allow_basic_auth`] and
/// [`open_stream_with`]). retina needs them as `String`s, so the password is copied out of its
/// `SecretString` into one that retina owns for the life of the session and is not zeroed.
///
/// # Errors
/// [`IngestError`]: `InvalidUrl`, `OpenTimeout` after [`OPEN_TIMEOUT`], `AuthRejected` or
/// `Rejected` for an RTSP error status, `BasicAuthRefused`, `NoVideoStream`, `UnsupportedCodec`,
/// or `OpenFailed`.
pub async fn open_stream<C: Clock>(
    host: &Host,
    port: NonZeroU16,
    path: &RtspPath,
    credential: Option<&Credential>,
    role: StreamRole,
    clock: C,
) -> Result<FrameStream<C>, IngestError> {
    open_stream_with(
        host,
        port,
        path,
        credential,
        role,
        clock,
        OpenOptions::default(),
    )
    .await
}

/// [`open_stream`] with per-camera [`OpenOptions`].
///
/// # Errors
/// As [`open_stream`].
pub async fn open_stream_with<C: Clock>(
    host: &Host,
    port: NonZeroU16,
    path: &RtspPath,
    credential: Option<&Credential>,
    role: StreamRole,
    clock: C,
    options: OpenOptions,
) -> Result<FrameStream<C>, IngestError> {
    let url = stream_url(host, port, path)?;
    let creds = credential.map(|c| Credentials {
        username: c.user.clone(),
        password: c.password.expose_secret().to_owned(),
    });
    let demuxed_and_index = timeout(OPEN_TIMEOUT, open_session(url, creds, options))
        .await
        .map_err(|_| IngestError::OpenTimeout)??;
    Ok(FrameStream {
        demuxed: demuxed_and_index.0,
        stream_i: demuxed_and_index.1,
        mapper: FrameMapper::new(),
        clock,
        role,
        frame_timeout: FRAME_TIMEOUT,
        finished: false,
    })
}

async fn open_session(
    url: Url,
    creds: Option<Credentials>,
    open: OpenOptions,
) -> Result<(Demuxed, usize), IngestError> {
    let options = SessionOptions::default()
        .creds(creds)
        .max_message_size(MAX_RTSP_MESSAGE_BYTES)
        .max_buffered_bytes(MAX_BUFFERED_BYTES)
        .allow_basic_auth(open.allow_basic_auth);
    let mut session = Session::describe(url, options)
        .await
        .map_err(|e| classify(&e, IngestError::OpenFailed))?;
    let infos: Vec<StreamInfo<'_>> = session
        .streams()
        .iter()
        .map(|s| StreamInfo {
            media: s.media(),
            encoding_name: s.encoding_name(),
            receiving: s.direction() == StreamDirection::Receiving,
        })
        .collect();
    let stream_i = select_video_stream(&infos)?;
    drop(infos);
    let setup = SetupOptions::default()
        .max_nals_per_access_unit(MAX_NALS_PER_ACCESS_UNIT)
        .transport(Transport::Tcp(TcpTransportOptions::default()))
        .frame_format(FrameFormat::MP4);
    session
        .setup(stream_i, setup)
        .await
        .map_err(|e| classify(&e, IngestError::OpenFailed))?;
    let playing = session
        .play(PlayOptions::default())
        .await
        .map_err(|e| classify(&e, IngestError::OpenFailed))?;
    let demuxed = playing
        .demuxed()
        .map_err(|e| classify(&e, IngestError::OpenFailed))?;
    Ok((demuxed, stream_i))
}

impl<C: Clock> FrameStream<C> {
    /// Replaces the idle limit of [`FRAME_TIMEOUT`] used by [`FrameStream::next_frame`].
    #[must_use]
    pub fn with_frame_timeout(mut self, limit: Duration) -> Self {
        self.frame_timeout = limit;
        self
    }

    /// Which stream of the camera this is.
    #[must_use]
    pub fn role(&self) -> StreamRole {
        self.role
    }

    /// Frames dropped so far for being over the size cap.
    #[must_use]
    pub fn dropped_oversize(&self) -> u64 {
        self.mapper.dropped_oversize()
    }

    /// The next video frame, or `None` when the camera closed the session.
    ///
    /// Waits at most the frame timeout ([`FRAME_TIMEOUT`] unless changed) in total, whatever else
    /// the camera sends meanwhile. A dropped oversize frame is not an error and does not end the
    /// wait early. A timeout too large to add to the clock is treated as "never".
    ///
    /// # Errors
    /// `FrameTimeout`, `StreamFailed` (or `AuthRejected`/`Rejected` if retina reports a status),
    /// `UnsupportedCodec` if the parameters turn out not to be H.264, or `Map` for a frame that
    /// cannot be mapped.
    ///
    /// The stream is fused: after any error, and after `Ok(None)`, every later call returns
    /// `Ok(None)` without touching the session, including after `FrameTimeout` and after a
    /// changed timeout. Open a new session to continue; its first frame is a discontinuity.
    pub async fn next_frame(&mut self) -> Result<Option<Frame>, IngestError> {
        if self.finished {
            return Ok(None);
        }
        let out = self.read_frame().await;
        if !matches!(out, Ok(Some(_))) {
            self.finished = true;
        }
        out
    }

    async fn read_frame(&mut self) -> Result<Option<Frame>, IngestError> {
        let now = Instant::now();
        // About 30 years, as tokio's own "far future".
        let deadline = now
            .checked_add(self.frame_timeout)
            .or_else(|| now.checked_add(Duration::from_hours(262_800)))
            .unwrap_or(now);
        loop {
            let item = match timeout_at(deadline, self.demuxed.next()).await {
                Err(_) => return Err(IngestError::FrameTimeout),
                Ok(None) => return Ok(None),
                Ok(Some(Err(e))) => return Err(classify(&e, IngestError::StreamFailed)),
                Ok(Some(Ok(item))) => item,
            };
            let CodecItem::VideoFrame(video) = item else {
                continue;
            };
            let params = if video.has_new_parameters() || self.mapper.wants_params() {
                self.current_params()?
            } else {
                None
            };
            let raw = RawVideoFrame {
                is_random_access_point: video.is_random_access_point(),
                rtp_timestamp: video.timestamp().timestamp(),
                clock_rate: video.timestamp().clock_rate().get(),
                loss: video.loss(),
                params,
                data: video.into_data(),
            };
            if let Some(frame) = self.mapper.map(raw, self.clock.now())? {
                return Ok(Some(frame));
            }
        }
    }

    /// The stream's current SPS and PPS. `Ok(None)` when retina has none yet.
    fn current_params(&self) -> Result<Option<RawParams>, IngestError> {
        let Some(stream) = self.demuxed.streams().get(self.stream_i) else {
            return Ok(None);
        };
        match stream.parameters() {
            Some(ParametersRef::Video(v)) => match v.codec_params() {
                VideoParametersCodec::H264 { sps, pps } => Ok(Some(RawParams {
                    sps: sps.to_vec(),
                    pps: pps.to_vec(),
                })),
                _ => Err(IngestError::UnsupportedCodec),
            },
            _ => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info<'a>(media: &'a str, enc: &'a str, receiving: bool) -> StreamInfo<'a> {
        StreamInfo {
            media,
            encoding_name: enc,
            receiving,
        }
    }

    #[test]
    fn the_buffer_bound_keeps_the_ring_at_16_mib_and_fits_a_frame_at_the_cap() {
        const FRAME: usize = crate::frame::MAX_FRAME_BYTES;
        const { assert!(MAX_BUFFERED_BYTES + 4096 <= 16 * 1024 * 1024) };
        // 8 MiB of payload in 1400-byte packets with 16 bytes of RTP and interleave header each,
        // plus a generous allowance for the unparsed tail.
        const { assert!(MAX_BUFFERED_BYTES > FRAME + FRAME / 50 + 256 * 1024) };
    }

    #[test]
    fn select_video_stream_table() {
        let rows: Vec<(&str, Vec<StreamInfo<'_>>, Result<usize, IngestError>)> = vec![
            ("empty", vec![], Err(IngestError::NoVideoStream)),
            (
                "audio only",
                vec![info("audio", "pcmu", true)],
                Err(IngestError::NoVideoStream),
            ),
            ("h264", vec![info("video", "h264", true)], Ok(0)),
            (
                "audio first",
                vec![
                    info("audio", "mpeg4-generic", true),
                    info("video", "h264", true),
                ],
                Ok(1),
            ),
            (
                "h265",
                vec![info("video", "h265", true)],
                Err(IngestError::UnsupportedCodec),
            ),
            (
                "mjpeg",
                vec![info("video", "jpeg", true)],
                Err(IngestError::UnsupportedCodec),
            ),
            (
                "h265 then h264 picks h264",
                vec![info("video", "h265", true), info("video", "h264", true)],
                Ok(1),
            ),
            (
                "two h264 picks the first",
                vec![info("video", "h264", true), info("video", "h264", true)],
                Ok(0),
            ),
            (
                "sending (backchannel) h264 is not a source",
                vec![info("video", "h264", false)],
                Err(IngestError::NoVideoStream),
            ),
            (
                "metadata stream is not video",
                vec![info("application", "h264", true)],
                Err(IngestError::NoVideoStream),
            ),
            // The encoding name is compared as retina reports it (lower case).
            (
                "upper case is not retina output",
                vec![info("video", "H264", true)],
                Err(IngestError::UnsupportedCodec),
            ),
        ];
        for (name, streams, want) in rows {
            assert_eq!(select_video_stream(&streams), want, "{name}");
        }
    }

    fn url_of(host: &str, port: u16, path: &str) -> Result<String, IngestError> {
        stream_url(
            &Host::new(host).unwrap(),
            NonZeroU16::new(port).unwrap(),
            &RtspPath::new(path).unwrap(),
        )
        .map(|u| u.to_string())
    }

    #[test]
    fn stream_url_table() {
        let rows = [
            (
                "192.0.2.10",
                554,
                "/stream1",
                "rtsp://192.0.2.10:554/stream1",
            ),
            (
                "2001:db8::1",
                8554,
                "/a/b?x=1",
                "rtsp://[2001:db8::1]:8554/a/b?x=1",
            ),
            (
                "cam.example.invalid",
                1,
                "/",
                "rtsp://cam.example.invalid:1/",
            ),
            ("127.0.0.1", 65535, "/s", "rtsp://127.0.0.1:65535/s"),
        ];
        for (host, port, path, want) in rows {
            assert_eq!(url_of(host, port, path).as_deref(), Ok(want));
        }
    }

    #[test]
    fn stream_url_never_has_user_info() {
        // `RtspPath` refuses `@`, so no path can carry user info; the URL check is a second layer.
        for path in ["/a@b", "/@", "/user@192.0.2.9/x"] {
            assert!(RtspPath::new(path).is_err(), "{path}");
        }
        for path in ["/:", "/a:b", "/a:b:c", "/x?y=a:b", "/"] {
            let url = stream_url(
                &Host::new("192.0.2.10").unwrap(),
                NonZeroU16::new(554).unwrap(),
                &RtspPath::new(path).unwrap(),
            )
            .unwrap();
            assert_eq!(url.username(), "", "{path}");
            assert_eq!(url.password(), None, "{path}");
            assert_eq!(url.host_str(), Some("192.0.2.10"), "{path}");
        }
    }
}
