//! The API's accept loop (ADR 0004 section 9): hand-written on `hyper-util`, not `axum::serve`.
//!
//! * `auto::Builder::serve_connection` with `http1_only`, a `TokioTimer` (without one hyper's
//!   timeouts do not run) and a `header_read_timeout`. hyper's HTTP/1 server has no separate
//!   idle setting: that timeout also ends an idle keep-alive connection.
//! * A semaphore caps open connections. The permit is acquired **before** `accept`, so excess
//!   connections wait in the kernel backlog and cost no descriptor here. Accept errors (`EMFILE`,
//!   `ECONNABORTED`, ...) are logged and backed off; they never end the loop.
//! * Graceful shutdown: on stop the listener is dropped, open connections are asked to finish
//!   and are waited for up to a grace period.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use axum::Router;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto;
use hyper_util::server::graceful::GracefulShutdown;
use hyper_util::service::TowerToHyperService;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use wardenlens_ingest::CancelToken;

/// Open connections allowed at once (ADR 0004). A hostile LAN peer can fill them and deny the
/// API, but not recording (accepted residual risk).
pub(crate) const MAX_CONNECTIONS: usize = 256;
/// How long a connection may take to send its request headers; also bounds an idle keep-alive.
pub(crate) const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(10);
/// Pause after a failed `accept`.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);

/// The tunable limits; a struct so tests can shrink them.
#[derive(Debug, Clone, Copy)]
pub(crate) struct HttpLimits {
    pub(crate) max_connections: usize,
    pub(crate) header_read_timeout: Duration,
    /// How long shutdown waits for open requests before dropping them.
    pub(crate) grace: Duration,
}

impl Default for HttpLimits {
    fn default() -> Self {
        Self {
            max_connections: MAX_CONNECTIONS,
            header_read_timeout: HEADER_READ_TIMEOUT,
            grace: Duration::from_secs(5),
        }
    }
}

/// Connections being served now and the most there have been at once.
#[derive(Debug, Clone, Default)]
pub(crate) struct ConnectionStats {
    open: Arc<AtomicUsize>,
    peak: Arc<AtomicUsize>,
}

impl ConnectionStats {
    /// The highest number of connections served at the same time so far.
    #[cfg(test)]
    pub(crate) fn peak(&self) -> usize {
        self.peak.load(Ordering::Relaxed)
    }

    fn opened(&self) {
        let now = self.open.fetch_add(1, Ordering::Relaxed).saturating_add(1);
        self.peak.fetch_max(now, Ordering::Relaxed);
    }

    fn closed(&self) {
        self.open.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Serves `router` on `listener` until `stop` is cancelled, then drains.
pub(crate) async fn serve(
    listener: TcpListener,
    router: Router,
    limits: HttpLimits,
    stats: ConnectionStats,
    stop: CancelToken,
) {
    let permits = Arc::new(Semaphore::new(limits.max_connections));
    let graceful = GracefulShutdown::new();
    let mut builder = auto::Builder::new(TokioExecutor::new()).http1_only();
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(limits.header_read_timeout);
    loop {
        let permit = tokio::select! {
            biased;
            () = stop.cancelled() => break,
            p = Arc::clone(&permits).acquire_owned() => match p {
                Ok(p) => p,
                Err(_) => break,
            },
        };
        let accepted = tokio::select! {
            biased;
            () = stop.cancelled() => break,
            a = listener.accept() => a,
        };
        let stream = match accepted {
            Ok((stream, _peer)) => stream,
            Err(e) => {
                tracing::warn!(kind = ?e.kind(), "accepting an API connection failed");
                drop(permit);
                tokio::time::sleep(ACCEPT_BACKOFF).await;
                continue;
            }
        };
        let conn = builder
            .serve_connection(
                TokioIo::new(stream),
                TowerToHyperService::new(router.clone()),
            )
            .into_owned();
        let conn = graceful.watch(conn);
        let stats = stats.clone();
        stats.opened();
        tokio::spawn(async move {
            // The permit is released when the connection closes, however it ends.
            let _permit = permit;
            if let Err(e) = conn.await {
                tracing::debug!(error = %e, "API connection ended with an error");
            }
            stats.closed();
        });
    }
    drop(listener);
    if tokio::time::timeout(limits.grace, graceful.shutdown())
        .await
        .is_err()
    {
        tracing::warn!("open API connections did not finish in time; dropping them");
    }
}
