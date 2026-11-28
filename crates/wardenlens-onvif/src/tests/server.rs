//! A loopback fake camera: a real TCP listener on 127.0.0.1 that drops, answers or stalls.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// What the fake sends once it has read a whole request.
#[derive(Clone)]
pub(crate) enum Reply {
    /// A complete response.
    Http { status: u16, body: Vec<u8> },
    /// Reads the request, then says nothing and holds the connection open.
    Silent,
    /// Reads the request, then closes the connection without answering.
    Close,
    /// A 200 head that promises `promised` bytes, sends `sent` of them, then closes.
    Truncated { promised: usize, sent: usize },
    /// A 200 head with no length, then body bytes until the client hangs up.
    Endless,
    /// A 200 head promising a body, then silence with the connection held open.
    StalledBody,
}

pub(crate) struct Fake {
    pub addr: SocketAddr,
    /// Connections accepted so far, dropped or served.
    pub accepted: Arc<AtomicUsize>,
    /// Every request read in full (head and body as text).
    pub requests: Arc<Mutex<Vec<String>>>,
}

impl Fake {
    pub(crate) fn port(&self) -> u16 {
        self.addr.port()
    }

    pub(crate) fn accepted(&self) -> usize {
        self.accepted.load(Ordering::SeqCst)
    }

    pub(crate) fn last_request(&self) -> String {
        self.requests
            .lock()
            .map_or_else(|_| String::new(), |r| r.last().cloned().unwrap_or_default())
    }
}

/// Starts a fake that drops the first `drop_first` connections without reading, then answers
/// every later one with `reply`.
pub(crate) async fn spawn(drop_first: usize, reply: Reply) -> Fake {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let accepted = Arc::new(AtomicUsize::new(0));
    let requests = Arc::new(Mutex::new(Vec::new()));
    let (acc, reqs) = (accepted.clone(), requests.clone());
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let n = acc.fetch_add(1, Ordering::SeqCst);
            if n < drop_first {
                drop(stream);
                continue;
            }
            tokio::spawn(serve(stream, reply.clone(), reqs.clone()));
        }
    });
    Fake {
        addr,
        accepted,
        requests,
    }
}

pub(crate) fn ok(body: &str) -> Reply {
    Reply::Http {
        status: 200,
        body: body.as_bytes().to_vec(),
    }
}

async fn read_request(stream: &mut TcpStream) -> Option<String> {
    let mut buf = Vec::new();
    let mut chunk = [0_u8; 4096];
    loop {
        let n = stream.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
        let text = String::from_utf8_lossy(&buf).into_owned();
        if let Some(end) = text.find("\r\n\r\n") {
            let len = text[..end]
                .lines()
                .find_map(|l| {
                    let (k, v) = l.split_once(':')?;
                    k.eq_ignore_ascii_case("content-length")
                        .then(|| v.trim().parse::<usize>().ok())?
                })
                .unwrap_or(0);
            if buf.len() >= end + 4 + len {
                return Some(text);
            }
        }
    }
}

async fn serve(mut stream: TcpStream, reply: Reply, requests: Arc<Mutex<Vec<String>>>) {
    let Some(request) = read_request(&mut stream).await else {
        return;
    };
    if let Ok(mut r) = requests.lock() {
        r.push(request);
    }
    match reply {
        Reply::Http { status, body } => {
            let head = format!(
                "HTTP/1.1 {status} X\r\nContent-Type: application/soap+xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(head.as_bytes()).await;
            let _ = stream.write_all(&body).await;
            let _ = stream.shutdown().await;
        }
        Reply::Silent => std::future::pending::<()>().await,
        Reply::Close => drop(stream),
        Reply::Truncated { promised, sent } => {
            let head = format!(
                "HTTP/1.1 200 X\r\nContent-Length: {promised}\r\nConnection: close\r\n\r\n"
            );
            let _ = stream.write_all(head.as_bytes()).await;
            let _ = stream.write_all(&vec![b' '; sent]).await;
            let _ = stream.shutdown().await;
        }
        Reply::Endless => {
            let _ = stream
                .write_all(b"HTTP/1.1 200 X\r\nConnection: close\r\n\r\n")
                .await;
            let block = vec![b' '; 64 * 1024];
            while stream.write_all(&block).await.is_ok() {}
        }
        Reply::StalledBody => {
            let _ = stream
                .write_all(b"HTTP/1.1 200 X\r\nContent-Length: 1000\r\nConnection: close\r\n\r\n")
                .await;
            std::future::pending::<()>().await;
        }
    }
}
