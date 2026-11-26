//! [`IngestError`]: what can go wrong opening or reading a stream.
//!
//! No variant carries text from the camera, the URL, the host or a credential. retina's own error
//! text holds peer addresses and message contents, so it is dropped at the adapter and only the
//! kind (and an RTSP status code, which names no one) survives.

use crate::frame::MapError;

/// Why a stream could not be opened or ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum IngestError {
    /// The host, port and path do not form an RTSP URL.
    #[error("camera address does not form a valid RTSP URL")]
    InvalidUrl,
    /// Connecting, describing, setting up or playing failed (not an RTSP status).
    #[error("could not open the RTSP session")]
    OpenFailed,
    /// Opening took longer than the open timeout.
    #[error("opening the RTSP session timed out")]
    OpenTimeout,
    /// The camera answered 401 or 403: wrong or missing credentials.
    #[error("the camera rejected the credentials")]
    AuthRejected,
    /// The camera answered with another RTSP error status (for example 404 for a wrong path).
    #[error("the camera refused the request with RTSP status {0}")]
    Rejected(u16),
    /// The session describes no video stream.
    #[error("the session has no video stream")]
    NoVideoStream,
    /// The video stream is not H.264.
    #[error("the video stream is not H.264")]
    UnsupportedCodec,
    /// The session failed after it was playing.
    #[error("the RTSP session failed")]
    StreamFailed,
    /// No frame arrived within the idle timeout.
    #[error("no video frame arrived in time")]
    FrameTimeout,
    /// A frame or its parameter sets could not be mapped.
    #[error(transparent)]
    Map(#[from] MapError),
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every variant, built through an exhaustive match so a new one cannot be forgotten.
    fn all() -> Vec<IngestError> {
        let probe = IngestError::InvalidUrl;
        match probe {
            IngestError::InvalidUrl
            | IngestError::OpenFailed
            | IngestError::OpenTimeout
            | IngestError::AuthRejected
            | IngestError::Rejected(_)
            | IngestError::NoVideoStream
            | IngestError::UnsupportedCodec
            | IngestError::StreamFailed
            | IngestError::FrameTimeout
            | IngestError::Map(_) => {}
        }
        let mut v = vec![
            IngestError::InvalidUrl,
            IngestError::OpenFailed,
            IngestError::OpenTimeout,
            IngestError::AuthRejected,
            IngestError::Rejected(404),
            IngestError::NoVideoStream,
            IngestError::UnsupportedCodec,
            IngestError::StreamFailed,
            IngestError::FrameTimeout,
        ];
        v.extend(
            [
                MapError::UnsupportedClockRate,
                MapError::MalformedFrame,
                MapError::BadParameterSet,
            ]
            .map(IngestError::Map),
        );
        v
    }

    #[test]
    fn messages_are_distinct_and_free_of_camera_data() {
        let mut seen = std::collections::HashSet::new();
        for e in all() {
            let text = format!("{e}");
            assert!(seen.insert(text.clone()), "duplicate message {text}");
            let both = format!("{text} {e:?}");
            for needle in ["rtsp://", "@", "192.0.2", "127.0.0.1", "password", "user"] {
                assert!(!both.contains(needle), "{needle} in {both}");
            }
        }
        assert_eq!(seen.len(), 12);
    }

    #[test]
    fn the_status_is_the_only_payload() {
        assert_eq!(
            IngestError::Rejected(404).to_string(),
            "the camera refused the request with RTSP status 404"
        );
    }
}
