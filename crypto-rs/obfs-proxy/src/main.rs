//! `frappuccino-obfs-proxy` — Phase 3b brick 1b. Transparent Salamander
//! de-obfuscation UDP proxy fronting the relay QUIC endpoint.
//!
//! Usage:
//! ```text
//! FRAP_OBFS_PSK=<psk> frappuccino-obfs-proxy <listen addr> <upstream addr>
//! # e.g. FRAP_OBFS_PSK=secret frappuccino-obfs-proxy 0.0.0.0:8445 127.0.0.1:8444
//! ```
//! The PSK MUST match the client's `QuicTarget.obfs_psk`. Deployment + the PSK
//! provisioning are a separate operator step (prod authorization required).

use std::net::SocketAddr;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let mut args = std::env::args().skip(1);
    let listen: SocketAddr = args
        .next()
        .and_then(|s| s.parse().ok())
        .expect("usage: FRAP_OBFS_PSK=<psk> frappuccino-obfs-proxy <listen addr> <upstream addr>");
    let upstream: SocketAddr = args
        .next()
        .and_then(|s| s.parse().ok())
        .expect("missing/invalid <upstream addr> (e.g. 127.0.0.1:8444)");
    let psk = std::env::var("FRAP_OBFS_PSK")
        .expect("FRAP_OBFS_PSK not set")
        .into_bytes();
    assert!(!psk.is_empty(), "FRAP_OBFS_PSK is empty");

    eprintln!("frappuccino-obfs-proxy: listen={listen} upstream={upstream}");
    frappuccino_obfs_proxy::run(listen, upstream, psk).await
}
