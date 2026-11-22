//! Read-only Reolink Baichuan probe: login, device info, service-port state, event push.
//! Credentials come from the BC_USER / BC_PASS environment variables (set by run_baichuan.sh).
//! Usage: baichuan-probe <ip> <listen-seconds>
use neolink_core::bc_protocol::{
    BcCamera, BcCameraOpt, ConnectionProtocol, Credentials, DiscoveryMethods,
};
use std::time::Duration;

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let (Some(ip), Some(secs)) = (args.get(1), args.get(2)) else {
        eprintln!("usage: baichuan-probe <ip> <seconds>");
        return;
    };
    let secs: u64 = secs.parse().unwrap_or(60);
    let (Ok(user), Ok(pass)) = (std::env::var("BC_USER"), std::env::var("BC_PASS")) else {
        eprintln!("BC_USER / BC_PASS not set");
        return;
    };
    let Ok(addr) = ip.parse() else {
        eprintln!("bad ip");
        return;
    };
    let opts = BcCameraOpt {
        name: "probe".into(),
        channel_id: 0,
        addrs: vec![addr],
        uid: None,
        port: Some(9000),
        protocol: ConnectionProtocol::Tcp,
        discovery: DiscoveryMethods::None,
        max_discovery_retries: 1,
        credentials: Credentials { username: user, password: Some(pass) },
        debug: false,
    };
    let cam = match BcCamera::new(&opts).await {
        Ok(c) => c,
        Err(e) => return println!("CONNECT_FAIL {e}"),
    };
    match cam.login().await {
        Ok(info) => println!("LOGIN_OK resolution={:?}", info.resolution),
        Err(e) => return println!("LOGIN_FAIL {e}"),
    }
    match cam.version().await {
        Ok(v) => println!(
            "VERSION model={:?} hw={} fw={} build={}",
            v.model, v.hardwareVersion, v.firmwareVersion, v.buildDay
        ),
        Err(e) => println!("VERSION_ERR {e}"),
    }
    // Read-only service-port queries (MSG_ID 37). The matching set_* calls are never used.
    println!("SERVERPORT {:?}", cam.get_serverport().await);
    println!("HTTP {:?}", cam.get_http().await);
    println!("HTTPS {:?}", cam.get_https().await);
    println!("RTSP {:?}", cam.get_rtsp().await);
    println!("RTMP {:?}", cam.get_rtmp().await);
    println!("ONVIF {:?}", cam.get_onvif().await);

    match cam.listen_on_motion().await {
        Ok(mut m) => {
            println!("MOTION_SUBSCRIBED (listening {secs}s)");
            let end = tokio::time::Instant::now() + Duration::from_secs(secs);
            while let Ok(r) = tokio::time::timeout_at(end, m.next_motion()).await {
                println!("EVENT {r:?}");
            }
        }
        Err(e) => println!("MOTION_ERR {e}"),
    }
    println!("DONE");
}
