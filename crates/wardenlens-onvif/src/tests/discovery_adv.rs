//! Adversarial socket-path tests for PR #200 (ticket #53). Loopback UDP only; nothing is sent
//! to the multicast group.

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use tokio::net::UdpSocket;

use crate::discovery::{MAX_REPLIES, run};

const LOOP: Ipv4Addr = Ipv4Addr::LOCALHOST;
const ID: &str = "uuid:adv00000000000000000000000000001";

fn good(relates: &str, endpoint: &str) -> Vec<u8> {
    format!(
        r#"<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery"><s:Header><a:RelatesTo>{relates}</a:RelatesTo></s:Header><s:Body><d:ProbeMatches><d:ProbeMatch><a:EndpointReference><a:Address>{endpoint}</a:Address></a:EndpointReference><d:XAddrs>http://10.0.0.9/onvif/device_service</d:XAddrs></d:ProbeMatch></d:ProbeMatches></s:Body></s:Envelope>"#
    )
    .into_bytes()
}

/// A port on loopback with nobody listening (bound, then released).
async fn closed_port() -> SocketAddr {
    let s = UdpSocket::bind((LOOP, 0)).await.unwrap();
    let a = s.local_addr().unwrap();
    drop(s);
    a
}

#[tokio::test]
async fn no_responder_gives_an_empty_result() {
    // Nobody listens on the target port. (Linux does not deliver the ICMP port unreachable to an
    // unconnected UDP socket, so this does not exercise a receive error.)
    let to = closed_port().await;
    let got = run(to, LOOP, Duration::from_millis(200), MAX_REPLIES, ID).await;
    assert_eq!(got, Ok(Vec::new()));
}

#[tokio::test]
async fn strays_do_not_use_up_the_reply_cap() {
    let sock = UdpSocket::bind((LOOP, 0)).await.unwrap();
    let to = sock.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0_u8; 70_000];
        let Ok((_, from)) = sock.recv_from(&mut buf).await else {
            return;
        };
        for i in 0..200 {
            let _ = sock
                .send_to(&good("uuid:someone-else", &format!("urn:uuid:x{i}")), from)
                .await;
        }
        let _ = sock.send_to(&good(ID, "urn:uuid:real"), from).await;
    });
    let got = run(to, LOOP, Duration::from_secs(10), 1, ID).await.unwrap();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].endpoint_ref(), "urn:uuid:real");
}

#[tokio::test]
async fn an_endless_flood_of_garbage_cannot_extend_the_window() {
    let sock = UdpSocket::bind((LOOP, 0)).await.unwrap();
    let to = sock.local_addr().unwrap();
    let flood = tokio::spawn(async move {
        let mut buf = vec![0_u8; 70_000];
        let Ok((_, from)) = sock.recv_from(&mut buf).await else {
            return;
        };
        let junk = vec![b'<'; 60_000];
        loop {
            if sock.send_to(&junk, from).await.is_err() {
                tokio::task::yield_now().await;
            }
            tokio::task::yield_now().await;
        }
    });
    let started = std::time::Instant::now();
    let got = run(to, LOOP, Duration::from_millis(300), MAX_REPLIES, ID).await;
    let took = started.elapsed();
    flood.abort();
    assert_eq!(got, Ok(Vec::new()));
    // The flood must not keep the loop alive past its 300 ms window. Without the deadline check
    // only the datagram cap ends it (tens of seconds), so 6 s leaves 20x for host load (TEST-5).
    assert!(took < Duration::from_secs(6), "{took:?}");
}
