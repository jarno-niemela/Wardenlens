//! Where frames come from.

use tokio::sync::mpsc;
use wardenlens_ingest::Frame;

/// A blocking source of frames. `None` ends the recording: the open segment is flushed and
/// indexed (graceful stop). To stop a recorder, end its source.
pub trait FrameSource {
    /// The next frame, blocking until one is available; `None` when the source has ended.
    fn next_frame(&mut self) -> Option<Frame>;
}

impl<I: Iterator<Item = Frame>> FrameSource for I {
    fn next_frame(&mut self) -> Option<Frame> {
        self.next()
    }
}

/// The frame channel of `wardenlens_ingest::Supervisor` as a [`FrameSource`]. It ends when the
/// supervisor stops (the channel closes) after every queued frame was delivered.
///
/// It blocks the calling thread, so it must run on a blocking thread
/// (`tokio::task::spawn_blocking` or a dedicated thread), never inside async code.
#[derive(Debug)]
pub struct ChannelSource(mpsc::Receiver<Frame>);

impl ChannelSource {
    /// Wraps the receiver.
    #[must_use]
    pub fn new(frames: mpsc::Receiver<Frame>) -> Self {
        Self(frames)
    }
}

impl FrameSource for ChannelSource {
    fn next_frame(&mut self) -> Option<Frame> {
        self.0.blocking_recv()
    }
}
