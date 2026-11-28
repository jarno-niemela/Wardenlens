//! One HTTP/1.1 POST over a fresh plain-TCP connection, with the retry contract.
//!
//! Contract (ADR 0002: some cameras refuse a large share of TCP connects): up to
//! [`MAX_ATTEMPTS`] attempts. An attempt fails *retryably* when it gets no HTTP response head: the
//! connect is refused or times out, the camera closes the connection before answering, or it stays
//! silent for the request timeout. Between attempts the delay comes from core's [`Backoff`]. After
//! the last failure the result is [`OnvifError::Unreachable`]. Once a head has arrived nothing is
//! retried: the body is read once, capped at [`MAX_BODY_BYTES`] by a limit on the read itself
//! (the read stops at the cap, nothing is buffered past it), and a failure there is final. A
//! `Content-Length` above the cap is refused as soon as the head is read.
//!
//! A head that hyper itself refuses (malformed, over 64 KiB, conflicting lengths) counts as "no
//! head": it is retried like a silent camera and, after the last attempt, reported as
//! [`OnvifError::Unreachable`] rather than as a transport error.
//!
//! Each attempt builds its own request body (see [`Request1::body`]) before it connects, so a
//! WS-Security nonce is never sent twice, and a body that cannot be built ends the call as that
//! error without any connection being opened.
//!
//! The retry is for read-only queries only; a request that changed state must not use it.

use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full, LengthLimitError, Limited};
use hyper::body::{Body, Incoming};
use hyper::header::{CONNECTION, CONTENT_TYPE, HOST};
use hyper::{Method, Request, Response};
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;
use tokio::task::JoinHandle;
use tokio::time::timeout;
use wardenlens_core::camera::Host;
use wardenlens_core::connection::{Backoff, JitterSource};
use wardenlens_core::time::DurationMs;

use crate::{MAX_ATTEMPTS, MAX_BODY_BYTES, OnvifError};

/// Largest response head hyper buffers, in bytes.
const MAX_HEAD_BYTES: usize = 64 * 1024;

/// Timing and retry settings of a client.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct ClientConfig {
    /// How long one TCP connect may take. Default 3 s.
    pub connect_timeout: Duration,
    /// How long, per attempt, the camera may take to send its response head. Default 10 s.
    pub request_timeout: Duration,
    /// How long the whole body may take once the head has arrived. Default 10 s.
    pub body_timeout: Duration,
    /// The delay between attempts. Default [`Backoff::DEFAULT`] (2 s growing to 5 s).
    pub backoff: Backoff,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(3),
            request_timeout: Duration::from_secs(10),
            body_timeout: Duration::from_secs(10),
            backoff: Backoff::DEFAULT,
        }
    }
}

/// Jitter from the operating system's random source. A failing source gives 0: jitter only
/// spreads retries and is not security-relevant.
struct OsJitter;

impl JitterSource for OsJitter {
    fn next_u64(&mut self) -> u64 {
        let mut b = [0_u8; 8];
        if getrandom::fill(&mut b).is_err() {
            return 0;
        }
        u64::from_le_bytes(b)
    }
}

/// The wait before attempt number `attempt` (1 for the first retry): core's backoff, whose
/// zero-based index is `attempt - 1`.
pub(crate) fn retry_delay(
    backoff: &Backoff,
    attempt: u8,
    jitter: &mut impl JitterSource,
) -> Duration {
    let delay: DurationMs = backoff.delay(u32::from(attempt).saturating_sub(1), jitter);
    Duration::from_millis(delay.as_millis())
}

/// Aborts the connection task when dropped, so a cancelled or timed-out call leaves nothing behind.
struct Driver(JoinHandle<()>);

impl Drop for Driver {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// A response whose head arrived. Keeps the connection alive while the body is read.
struct Live {
    response: Response<Incoming>,
    _driver: Driver,
}

/// Where and what to POST.
pub(crate) struct Request1<'a> {
    pub host: &'a Host,
    pub port: u16,
    pub path: &'a str,
    pub action: &'a str,
    /// Builds the body for one attempt. Called once per attempt, so the WS-Security nonce and
    /// `Created` are fresh each time. An error ends the call.
    pub body: &'a (dyn Fn() -> Result<Bytes, OnvifError> + Sync),
}

/// One attempt up to the response head. `None` is a retryable failure; `Some(Err(_))` is final.
async fn attempt(req: &Request1<'_>, cfg: &ClientConfig) -> Option<Result<Live, OnvifError>> {
    // Built before connecting: a request that cannot be built (a user name XML cannot carry, no
    // clock, no randomness) is final and reported as itself, and never opens a connection.
    let body = match (req.body)() {
        Ok(b) => b,
        Err(e) => return Some(Err(e)),
    };
    let stream = timeout(
        cfg.connect_timeout,
        TcpStream::connect((req.host.expose(), req.port)),
    )
    .await
    .ok()?
    .ok()?;
    let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
        .max_buf_size(MAX_HEAD_BYTES)
        .handshake::<_, Full<Bytes>>(TokioIo::new(stream))
        .await
        .ok()?;
    let driver = Driver(tokio::spawn(async move {
        // The connection's own outcome is irrelevant here: the request future reports every
        // failure that matters, and a dropped `Driver` aborts this task anyway.
        let _ = conn.await;
    }));
    let request = Request::builder()
        .method(Method::POST)
        .uri(req.path)
        .header(HOST, format!("{}:{}", req.host.url_host(), req.port))
        .header(
            CONTENT_TYPE,
            format!(
                "application/soap+xml; charset=utf-8; action=\"{}\"",
                req.action
            ),
        )
        .header(CONNECTION, "close")
        .body(Full::new(body));
    let Ok(request) = request else {
        return Some(Err(OnvifError::InvalidServicePath));
    };
    let response = timeout(cfg.request_timeout, sender.send_request(request))
        .await
        .ok()?
        .ok()?;
    Some(Ok(Live {
        response,
        _driver: driver,
    }))
}

/// POSTs `req` and returns the status code with the body (at most [`MAX_BODY_BYTES`]). HTTP 401 is
/// answered with [`OnvifError::Unauthorized`] without reading the body.
pub(crate) async fn post(
    req: &Request1<'_>,
    cfg: &ClientConfig,
) -> Result<(u16, Bytes), OnvifError> {
    let mut jitter = OsJitter;
    let mut live = None;
    for n in 0..MAX_ATTEMPTS {
        if n > 0 {
            tokio::time::sleep(retry_delay(&cfg.backoff, n, &mut jitter)).await;
        }
        match attempt(req, cfg).await {
            None => {}
            Some(Err(e)) => return Err(e),
            Some(Ok(l)) => {
                live = Some(l);
                break;
            }
        }
    }
    let Some(live) = live else {
        return Err(OnvifError::Unreachable {
            attempts: MAX_ATTEMPTS,
        });
    };
    let status = live.response.status().as_u16();
    if status == 401 {
        return Err(OnvifError::Unauthorized);
    }
    let body = live.response.into_body();
    // A declared length over the cap is final at once; waiting for the body would only burn the
    // timeout. (`upper` is the exact `Content-Length` for a sized body.)
    if body
        .size_hint()
        .upper()
        .is_some_and(|n| n > u64::try_from(MAX_BODY_BYTES).unwrap_or(u64::MAX))
    {
        return Err(OnvifError::BodyTooLarge);
    }
    let limited = Limited::new(body, MAX_BODY_BYTES);
    let collected = timeout(cfg.body_timeout, limited.collect())
        .await
        .map_err(|_| OnvifError::Timeout)?;
    match collected {
        Ok(c) => Ok((status, c.to_bytes())),
        Err(e) if e.downcast_ref::<LengthLimitError>().is_some() => Err(OnvifError::BodyTooLarge),
        Err(_) => Err(OnvifError::Transport),
    }
}
