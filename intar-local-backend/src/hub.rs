use anyhow::Result;
use std::collections::HashSet;
use std::net::SocketAddr;
use tokio::net::UdpSocket;

/// Simple UDP fanout hub for per-scenario LAN emulation.
/// Listens on 127.0.0.1:port and rebroadcasts received datagrams to all peers.
///
/// # Errors
/// Returns any socket bind or IO errors encountered while reading or writing.
pub async fn run_udp_hub(_scenario: &str, port: u16) -> Result<()> {
    let bind_addr = SocketAddr::from(([127, 0, 0, 1], port));
    let sock = UdpSocket::bind(bind_addr).await?;
    tracing::info!("intar hub listening on {}", bind_addr);

    let mut peers: HashSet<SocketAddr> = HashSet::new();
    let mut buf = vec![0u8; 65536];

    loop {
        let (len, src) = sock.recv_from(&mut buf).await?;
        if peers.insert(src) {
            tracing::info!("hub: new peer {} ({} total)", src, peers.len());
        }
        for peer in &peers {
            if *peer != src {
                let _ = sock.send_to(&buf[..len], *peer).await;
            }
        }
    }
}
