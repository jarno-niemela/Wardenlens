// Copyright (C) The Retina Authors
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::sync::Arc;

use crate::{ConnectionContext, PacketContext, RtspMessageContext, StreamContext, WallTime};
use bytes::Bytes;

/// An opaque `std::error::Error + Send + Sync + 'static` implementation.
///
/// Currently the focus is on providing detailed human-readable error messages.
/// In most cases they have enough information to find the offending packet
/// in Wireshark.
///
/// If you wish to inspect Retina errors programmatically, or if you need
/// errors formatted in a different way, please file an issue on the `retina`
/// repository.
#[derive(Clone, derive_more::Debug, derive_more::Display, derive_more::Error)]
#[display("{_0}")]
#[debug("{_0:?}")]
pub struct Error(#[error(not(source))] pub(crate) Arc<ErrorInt>);

impl Error {
    /// Returns the status code, if the error was generated from a response.
    pub fn status_code(&self) -> Option<u16> {
        match self.0.as_ref() {
            ErrorInt::RtspResponseError { status, .. }
            | ErrorInt::BasicAuthRefused { status, .. } => Some((*status).into()),
            _ => None,
        }
    }

    /// True if the session failed because the peer's only offered
    /// authentication scheme was Basic and `SessionOptions::allow_basic_auth`
    /// was not set. No credentials were sent. (Local patch, see ADR 0002.)
    pub fn is_basic_auth_refused(&self) -> bool {
        matches!(self.0.as_ref(), ErrorInt::BasicAuthRefused { .. })
    }

    /// True if the session failed because the peer sent more unfinished data
    /// than `SessionOptions::max_buffered_bytes`. (Local patch, see ADR 0002.)
    pub fn is_buffer_limit(&self) -> bool {
        matches!(self.0.as_ref(), ErrorInt::BufferLimit { .. })
    }
}

#[derive(Debug, derive_more::Display, derive_more::Error)]
pub(crate) enum ErrorInt {
    /// The method's caller provided an invalid argument.
    #[display("Invalid argument: {_0}")]
    InvalidArgument(#[error(not(source))] String),

    /// Unparseable or unexpected RTSP message.
    #[display("RTSP framing error: {description}\n\nconn: {conn_ctx}\nmsg: {msg_ctx}")]
    RtspFramingError {
        conn_ctx: ConnectionContext,
        msg_ctx: RtspMessageContext,
        description: String,
    },

    #[display(
        "{status} response to {method} CSeq={cseq}: {description}\n\n\
             conn: {conn_ctx}\nmsg: {msg_ctx}"
    )]
    RtspResponseError {
        conn_ctx: ConnectionContext,
        msg_ctx: RtspMessageContext,
        method: crate::rtsp::msg::Method,
        cseq: u32,
        status: crate::rtsp::msg::StatusCode,
        description: String,
    },

    #[display(
        "Received interleaved data on unassigned channel {channel_id}: \n\
         {:?}\n\nconn: {conn_ctx}\nmsg: {msg_ctx}",
        crate::hex::LimitedHex::new(data, 64)
    )]
    RtspUnassignedChannelError {
        conn_ctx: ConnectionContext,
        msg_ctx: RtspMessageContext,
        channel_id: u8,
        data: Bytes,
    },

    #[display("{description}\n\nconn: {conn_ctx}\nstream: {stream_ctx}\npkt: {pkt_ctx}")]
    PacketError {
        conn_ctx: ConnectionContext,
        stream_ctx: StreamContext,
        pkt_ctx: PacketContext,
        stream_id: usize,
        description: String,
    },

    #[display(
        "{description}\n\n\
             conn: {conn_ctx}\nstream: {stream_ctx}\n\
             ssrc: {ssrc:08x}\nseq: {sequence_number}\npkt: {pkt_ctx}"
    )]
    RtpPacketError {
        conn_ctx: ConnectionContext,
        stream_ctx: StreamContext,
        pkt_ctx: crate::PacketContext,
        stream_id: usize,
        ssrc: u32,
        sequence_number: u16,
        description: String,
    },

    #[display("Unable to connect to RTSP server: {_0}")]
    ConnectError(#[error(source)] std::io::Error),

    #[display("Error reading from RTSP peer: {source}\n\nconn: {conn_ctx}\nmsg: {msg_ctx}")]
    RtspReadError {
        conn_ctx: ConnectionContext,
        msg_ctx: RtspMessageContext,
        #[error(source)]
        source: std::io::Error,
    },

    #[display(
        "Error receiving UDP packet: {source}\n\n\
             conn: {conn_ctx}\nstream: {stream_ctx}\nat: {when}"
    )]
    UdpRecvError {
        conn_ctx: ConnectionContext,
        stream_ctx: StreamContext,
        when: WallTime,
        #[error(source)]
        source: std::io::Error,
    },

    #[display("Error writing to RTSP peer: {source}\n\nconn: {conn_ctx}")]
    WriteError {
        conn_ctx: ConnectionContext,
        #[error(source)]
        source: std::io::Error,
    },

    #[display("Failed precondition: {_0}")]
    FailedPrecondition(#[error(not(source))] String),

    #[display("Internal error: {_0}")]
    Internal(#[error(source)] Box<dyn std::error::Error + Send + Sync>),

    #[display("Timeout")]
    Timeout,

    /// The peer sent more than `SessionOptions::max_buffered_bytes` that retina must hold
    /// (an access unit that does not end).
    #[display("Buffered more than {limit} bytes of unfinished data\n\nconn: {conn_ctx}")]
    BufferLimit {
        conn_ctx: ConnectionContext,
        limit: usize,
    },

    /// The peer asked for Basic authentication, which is refused unless
    /// `SessionOptions::allow_basic_auth` is set. No credentials were sent.
    #[display("Basic authentication refused\n\nconn: {conn_ctx}\nmsg: {msg_ctx}")]
    BasicAuthRefused {
        conn_ctx: ConnectionContext,
        msg_ctx: RtspMessageContext,
        method: crate::rtsp::msg::Method,
        cseq: u32,
        status: crate::rtsp::msg::StatusCode,
    },

    #[display("Unsupported: {_0}")]
    Unsupported(#[error(not(source))] String),
}
