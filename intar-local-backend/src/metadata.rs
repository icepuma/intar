use anyhow::Result;
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// Run a minimal HTTP metadata server on 127.0.0.1:port that returns agent config.
///
/// Path: GET `/agent-config` -> {"`otlp_http`": "<endpoint>"}
/// The endpoint is chosen via `INTAR_AGENT_DISCOVERY_OTLP` env or defaults to `10.0.2.2:4318`.
///
/// # Errors
/// Returns any socket bind or I/O error encountered while reading or writing.
pub async fn run_metadata_server(_scenario: &str, port: u16) -> Result<()> {
    let bind_addr = SocketAddr::from(([127, 0, 0, 1], port));
    let listener = TcpListener::bind(bind_addr).await?;
    tracing::info!("intar metadata listening on {}", bind_addr);

    loop {
        let (mut socket, _addr) = listener.accept().await?;
        // Spawn per-connection task
        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            let mut req = Vec::new();
            // Read available bytes (simple, not full HTTP parser)
            match socket.read(&mut buf).await {
                Ok(n) if n > 0 => req.extend_from_slice(&buf[..n]),
                _ => {}
            }

            let req_str = String::from_utf8_lossy(&req);
            let first_line = req_str.lines().next().unwrap_or("");
            let path = first_line.split_whitespace().nth(1).unwrap_or("/");

            if path == "/agent-config" {
                let otlp = std::env::var("INTAR_AGENT_DISCOVERY_OTLP")
                    .unwrap_or_else(|_| "http://10.0.2.2:4318/v1/metrics".to_string());
                let body = serde_json::json!({"otlp_http": otlp}).to_string();
                let resp = format!(
                    concat!(
                        "HTTP/1.1 200 OK\r\n",
                        "Content-Type: application/json\r\n",
                        "Content-Length: {}\r\n",
                        "Connection: close\r\n\r\n",
                        "{}"
                    ),
                    body.len(),
                    body
                );
                let _ = socket.write_all(resp.as_bytes()).await;
            } else {
                let resp =
                    b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                let _ = socket.write_all(resp).await;
            }
            let _ = socket.shutdown().await;
        });
    }
}
