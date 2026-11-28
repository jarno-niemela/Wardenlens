//! `wardenlens health` (#69): the probe behind the container healthcheck, so the image needs no
//! `curl`.
//!
//! It loads the config (flag, `WARDENLENS_CONFIG`, default path), takes `api.listen` and sends
//! `GET /api/v1/health` to it, which needs no token. An unspecified listen address (`0.0.0.0`,
//! `::`) is probed on the loopback address of the same family. The whole probe (connect, request,
//! status line) has one deadline of [`TIMEOUT`]. Only a `200` is healthy: a redirect, an error
//! status, a refused connection, a closed one, a garbled answer or a stall is exit 1. The body is
//! never read, so a hostile listener cannot make the probe allocate, and nothing is printed on
//! success. No token or secret is involved.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::process::ExitCode;
use std::time::Duration;

use axum::body::Body;
use hyper::client::conn::http1;
use hyper::{Method, Request, StatusCode, header};
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;

use super::{Context, report_error};
use crate::config_file::{ConfigFileError, load, resolve_path};

/// The probe's deadline.
const TIMEOUT: Duration = Duration::from_secs(3);

/// The path probed.
const PATH: &str = "/api/v1/health";

/// Why the probe failed. The exit code is 1 for all of them.
#[derive(Debug, thiserror::Error)]
pub(crate) enum HealthError {
    /// The config could not be used.
    #[error(transparent)]
    Config(#[from] ConfigFileError),
    /// The async runtime could not be built.
    #[error("the runtime cannot be started")]
    Runtime(#[source] std::io::Error),
    /// The service did not answer within the deadline.
    #[error("no answer within {} s", TIMEOUT.as_secs())]
    Timeout,
    /// The connection or the exchange failed.
    #[error("the service cannot be reached")]
    Connect(#[source] std::io::Error),
    /// The HTTP exchange failed.
    #[error("the answer is not valid HTTP")]
    Http(#[source] hyper::Error),
    /// The request could not be built (an invalid host header value; not expected for an address).
    #[error("the probe request cannot be built")]
    Request(#[source] hyper::http::Error),
    /// The status was not 200.
    #[error("the service answered status {0}")]
    Status(u16),
}

pub(crate) fn execute(ctx: &Context<'_>) -> ExitCode {
    match run(ctx) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            report_error(&e, ctx.log_format);
            ExitCode::FAILURE
        }
    }
}

fn run(ctx: &Context<'_>) -> Result<(), HealthError> {
    let config = load(&resolve_path(ctx.config_flag, ctx.env)?)?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(HealthError::Runtime)?;
    rt.block_on(probe(config.listen(), TIMEOUT))
}

/// The address to connect to for a listen address: unspecified becomes loopback.
fn target(listen: SocketAddr) -> SocketAddr {
    let ip = match listen.ip() {
        IpAddr::V4(a) if a.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(a) if a.is_unspecified() => IpAddr::V6(Ipv6Addr::LOCALHOST),
        // `::ffff:0.0.0.0` is unspecified for the OS (it means any IPv4 address) but not for std.
        IpAddr::V6(a) if a.to_ipv4_mapped().is_some_and(|v4| v4.is_unspecified()) => {
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        }
        other => other,
    };
    SocketAddr::new(ip, listen.port())
}

/// One `GET /api/v1/health` against `listen`, within `deadline`.
async fn probe(listen: SocketAddr, deadline: Duration) -> Result<(), HealthError> {
    tokio::time::timeout(deadline, exchange(target(listen)))
        .await
        .map_err(|_| HealthError::Timeout)?
}

/// The probe request for a `Host` header value. Fails only if the value is not a valid header.
fn build_request(host: &str) -> Result<Request<Body>, HealthError> {
    Request::builder()
        .method(Method::GET)
        .uri(PATH)
        .header(header::HOST, host)
        .header(header::CONNECTION, "close")
        .body(Body::empty())
        .map_err(HealthError::Request)
}

async fn exchange(addr: SocketAddr) -> Result<(), HealthError> {
    let stream = TcpStream::connect(addr)
        .await
        .map_err(HealthError::Connect)?;
    let (mut sender, connection) = http1::handshake::<_, Body>(TokioIo::new(stream))
        .await
        .map_err(HealthError::Http)?;
    // Driving the connection ends when the sender is dropped or the peer closes; the task is
    // aborted with the runtime at process exit.
    let driver = tokio::spawn(connection);
    let request = build_request(&addr.to_string())?;
    let response = sender
        .send_request(request)
        .await
        .map_err(HealthError::Http);
    driver.abort();
    let status = response?.status();
    if status == StatusCode::OK {
        Ok(())
    } else {
        Err(HealthError::Status(status.as_u16()))
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::*;

    const SHORT: Duration = Duration::from_millis(400);

    /// A loopback server that answers every connection with `reply` after reading the request
    /// head, and reports the first request head it saw.
    async fn serve_once(
        reply: &'static [u8],
    ) -> (SocketAddr, tokio::sync::oneshot::Receiver<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let n = s.read(&mut buf).await.unwrap();
            let _ = tx.send(String::from_utf8_lossy(&buf[..n]).into_owned());
            let _ = s.write_all(reply).await;
            let _ = s.shutdown().await;
        });
        (addr, rx)
    }

    #[tokio::test]
    async fn ok_is_healthy_and_the_request_has_no_credentials() {
        let (addr, rx) = serve_once(
            b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 15\r\n\r\n{\"status\":\"ok\"}",
        )
        .await;
        probe(addr, SHORT).await.unwrap();
        let head = rx.await.unwrap();
        assert!(
            head.starts_with("GET /api/v1/health HTTP/1.1\r\n"),
            "{head}"
        );
        assert!(
            !head.to_ascii_lowercase().contains("authorization"),
            "{head}"
        );
    }

    #[tokio::test]
    async fn every_other_status_is_unhealthy() {
        for (line, code) in [
            (
                &b"HTTP/1.1 401 Unauthorized\r\ncontent-length: 0\r\n\r\n"[..],
                401,
            ),
            (
                &b"HTTP/1.1 500 Internal Server Error\r\ncontent-length: 0\r\n\r\n"[..],
                500,
            ),
            (
                &b"HTTP/1.1 503 Service Unavailable\r\ncontent-length: 0\r\n\r\n"[..],
                503,
            ),
            (&b"HTTP/1.1 204 No Content\r\n\r\n"[..], 204),
            (
                &b"HTTP/1.1 302 Found\r\nlocation: /api/v1/health\r\ncontent-length: 0\r\n\r\n"[..],
                302,
            ),
        ] {
            let (addr, _rx) = serve_once(Box::leak(line.to_vec().into_boxed_slice())).await;
            match probe(addr, SHORT).await {
                Err(HealthError::Status(c)) => assert_eq!(c, code),
                other => panic!("{code}: {other:?}"),
            }
        }
    }

    #[tokio::test]
    async fn garbage_and_an_immediate_close_are_unhealthy() {
        let (addr, _rx) = serve_once(b"not http at all\r\n\r\n").await;
        assert!(matches!(
            probe(addr, SHORT).await,
            Err(HealthError::Http(_))
        ));
        let (addr, _rx) = serve_once(b"").await;
        assert!(matches!(
            probe(addr, SHORT).await,
            Err(HealthError::Http(_))
        ));
    }

    #[tokio::test]
    async fn a_stalled_service_times_out() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let _hold = tokio::spawn(async move {
            let (_s, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(30)).await;
        });
        let started = std::time::Instant::now();
        assert!(matches!(
            probe(addr, SHORT).await,
            Err(HealthError::Timeout)
        ));
        // The stalled peer holds for 30 s; a probe that waited for it would pass 25 s. A bound
        // tighter than that only measures host load (TEST-5).
        assert!(started.elapsed() < Duration::from_secs(25));
    }

    #[tokio::test]
    async fn a_huge_status_line_or_endless_headers_do_not_hang_or_allocate_without_bound() {
        // The peer sends headers forever: the deadline ends the probe.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            let _ = s.read(&mut buf).await;
            let _ = s.write_all(b"HTTP/1.1 200 OK\r\n").await;
            loop {
                if s.write_all(b"x-a: bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\r\n")
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });
        assert!(probe(addr, SHORT).await.is_err());
    }

    #[tokio::test]
    async fn a_closed_port_is_unhealthy() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        assert!(matches!(
            probe(addr, SHORT).await,
            Err(HealthError::Connect(_))
        ));
    }

    #[test]
    fn a_bad_host_value_is_a_request_error_not_a_status() {
        assert!(matches!(
            build_request("bad\nhost"),
            Err(HealthError::Request(_))
        ));
        assert!(build_request("127.0.0.1:8080").is_ok());
    }

    #[test]
    fn unspecified_listen_addresses_are_probed_on_loopback() {
        let t = |s: &str| target(s.parse().unwrap()).to_string();
        assert_eq!(t("0.0.0.0:8080"), "127.0.0.1:8080");
        assert_eq!(t("[::]:8080"), "[::1]:8080");
        assert_eq!(t("[::ffff:0.0.0.0]:8080"), "127.0.0.1:8080");
        // A specific address is probed as it is, never rewritten.
        assert_eq!(t("192.168.1.5:9000"), "192.168.1.5:9000");
        assert_eq!(t("127.0.0.1:1"), "127.0.0.1:1");
        assert_eq!(t("[fe80::1]:8080"), "[fe80::1]:8080");
    }

    #[test]
    fn a_missing_config_is_a_failure_before_any_connection() {
        let env = crate::env::Env::default();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("absent.toml");
        let ctx = Context {
            env: &env,
            config_flag: Some(&path),
            log_format: crate::args::LogFormat::Text,
        };
        assert!(matches!(run(&ctx), Err(HealthError::Config(_))));
    }
}
