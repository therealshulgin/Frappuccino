//! THROWAWAY Phase 2 QUIC spike — relay-side SINK (ROADMAP 10.9,
//! docs/TRANSPORT_PLAN.md Phase 2). Built for x86_64 Linux (WSL) and run on the
//! relay VM behind the Gate-0 netem. Drains both a TCP listener and a QUIC/quinn
//! listener on the same port, then acks 1 byte so the bench client can time the
//! full delivery. Self-signed cert (the spike measures CC, not security).
//!
//! Gated behind `--features sink` so rcgen never enters the Android bench
//! cross-compile. Build: `cargo build --release --bin quic-sink --features sink`.
//!
//! usage: quic-sink [port]   (default 4799)

fn main() {
    #[cfg(feature = "sink")]
    imp::run();
    #[cfg(not(feature = "sink"))]
    {
        eprintln!("quic-sink: rebuild with --features sink");
        std::process::exit(2);
    }
}

#[cfg(feature = "sink")]
mod imp {
    use std::error::Error;
    use std::net::SocketAddr;
    use std::sync::Arc;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    pub fn run() {
        let port: u16 = std::env::args()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or(4799);
        let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
        if let Err(e) = rt.block_on(serve(port)) {
            eprintln!("sink fatal: {e}");
            std::process::exit(1);
        }
    }

    async fn serve(port: u16) -> Result<(), Box<dyn Error>> {
        let bind: SocketAddr = format!("0.0.0.0:{port}").parse()?;

        // TCP drain listener (baseline path).
        let tcp = TcpListener::bind(bind).await?;
        tokio::spawn(async move {
            loop {
                if let Ok((mut s, _peer)) = tcp.accept().await {
                    tokio::spawn(async move {
                        let mut buf = vec![0u8; 1 << 20];
                        loop {
                            match s.read(&mut buf).await {
                                Ok(0) => break, // peer half-closed = transfer done
                                Ok(_) => {}
                                Err(_) => return,
                            }
                        }
                        let _ = s.write_all(&[1u8]).await;
                        let _ = s.flush().await;
                    });
                }
            }
        });

        // QUIC drain listener (quinn).
        let endpoint = quinn::Endpoint::server(server_config()?, bind)?;
        eprintln!("quic-sink: draining TCP + QUIC on 0.0.0.0:{port}");
        while let Some(incoming) = endpoint.accept().await {
            tokio::spawn(async move {
                let conn = match incoming.await {
                    Ok(c) => c,
                    Err(_) => return,
                };
                while let Ok((mut send, mut recv)) = conn.accept_bi().await {
                    tokio::spawn(async move {
                        let mut buf = vec![0u8; 1 << 20];
                        loop {
                            match recv.read(&mut buf).await {
                                Ok(Some(_)) => {}
                                Ok(None) => break, // stream finished = transfer done
                                Err(_) => return,
                            }
                        }
                        let _ = send.write_all(&[1u8]).await;
                        let _ = send.finish();
                    });
                }
            });
        }
        Ok(())
    }

    fn server_config() -> Result<quinn::ServerConfig, Box<dyn Error>> {
        let cert = rcgen::generate_simple_self_signed(vec!["spike".to_string()])?;
        let cert_der = cert.cert.der().clone();
        let key_der = rustls::pki_types::PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());

        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut tls = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_single_cert(
                vec![cert_der],
                rustls::pki_types::PrivateKeyDer::Pkcs8(key_der),
            )?;
        tls.alpn_protocols = vec![b"spike".to_vec()];

        let qsc = quinn::crypto::rustls::QuicServerConfig::try_from(tls)?;
        Ok(quinn::ServerConfig::with_crypto(Arc::new(qsc)))
    }
}
