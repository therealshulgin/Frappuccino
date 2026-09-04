//! THROWAWAY Phase 2 QUIC spike — on-device bench CLIENT (ROADMAP 10.9,
//! docs/TRANSPORT_PLAN.md Phase 2). Cross-compiled for Android arm64, pushed via
//! adb, run once per netem profile. Measures wall-clock to deliver N bytes to the
//! sink (push all bytes, then wait for a 1-byte ack) over:
//!   - `tcp`  : plain kernel TCP (CC = whatever the Android kernel uses = cubic),
//!   - `quic` : QUIC/quinn with a selectable userspace CC (bbr | cubic | newreno).
//!
//! Answers Gate-2: does quinn's userspace CC beat Android's cubic-only kernel by
//! >=3x on a degraded link? Not shipped.
//!
//! usage: quic-bench <quic|tcp> <host:port> <bytes> [bbr|cubic|newreno]

use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::{Duration, Instant};

use quinn::crypto::rustls::QuicClientConfig;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};

const CHUNK: usize = 64 * 1024;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 4 {
        eprintln!("usage: quic-bench <quic|tcp> <host:port> <bytes> [bbr|cubic|newreno]");
        std::process::exit(2);
    }
    let proto = args[1].as_str();
    let target = args[2].clone();
    let bytes: usize = args[3].parse().expect("bytes must be an integer");
    let cc = args.get(4).cloned().unwrap_or_else(|| "bbr".to_string());

    let result = match proto {
        "tcp" => run_tcp(&target, bytes),
        "quic" => {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(1)
                .enable_all()
                .build()
                .expect("tokio runtime");
            rt.block_on(run_quic(&target, bytes, &cc))
        }
        other => {
            eprintln!("unknown proto: {other} (want quic|tcp)");
            std::process::exit(2);
        }
    };

    match result {
        Ok(ms) => {
            // Goodput in Mbit/s over the bulk transfer (excludes connect setup).
            let mbps = (bytes as f64 * 8.0) / (ms as f64 / 1000.0) / 1_000_000.0;
            println!("RESULT proto={proto} cc={cc} bytes={bytes} ms={ms} mbps={mbps:.2}");
        }
        Err(e) => {
            eprintln!("RESULT proto={proto} cc={cc} bytes={bytes} FAILED: {e}");
            std::process::exit(1);
        }
    }
}

fn resolve(target: &str) -> Result<SocketAddr, String> {
    target
        .to_socket_addrs()
        .map_err(|e| format!("resolve {target}: {e}"))?
        .next()
        .ok_or_else(|| format!("no address for {target}"))
}

/// Plain TCP push of `bytes` then wait for the sink's 1-byte ack. The kernel
/// governs congestion control (cubic on the test devices) — this is the baseline
/// QUIC must beat.
fn run_tcp(target: &str, bytes: usize) -> Result<u128, String> {
    let addr = resolve(target)?;
    let buf = vec![0u8; CHUNK];
    let start = Instant::now();
    let mut s = TcpStream::connect(addr).map_err(|e| format!("tcp connect: {e}"))?;
    s.set_nodelay(true).ok();
    let mut remaining = bytes;
    while remaining > 0 {
        let n = remaining.min(CHUNK);
        s.write_all(&buf[..n])
            .map_err(|e| format!("tcp write: {e}"))?;
        remaining -= n;
    }
    s.shutdown(Shutdown::Write).ok();
    let mut ack = [0u8; 1];
    s.read_exact(&mut ack)
        .map_err(|e| format!("tcp ack: {e}"))?;
    Ok(start.elapsed().as_millis())
}

/// QUIC push of `bytes` over one bidirectional stream with the chosen userspace
/// congestion controller, then wait for the sink's 1-byte ack.
async fn run_quic(target: &str, bytes: usize, cc: &str) -> Result<u128, String> {
    let addr = resolve(target)?;
    let bind: SocketAddr = if addr.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    };
    let mut endpoint = quinn::Endpoint::client(bind).map_err(|e| format!("endpoint: {e}"))?;
    endpoint.set_default_client_config(client_config(cc)?);

    let conn = endpoint
        .connect(addr, "spike")
        .map_err(|e| format!("connect setup: {e}"))?
        .await
        .map_err(|e| format!("connect: {e}"))?;

    let (mut send, mut recv) = conn.open_bi().await.map_err(|e| format!("open_bi: {e}"))?;
    let buf = vec![0u8; CHUNK];
    let start = Instant::now();
    let mut remaining = bytes;
    while remaining > 0 {
        let n = remaining.min(CHUNK);
        send.write_all(&buf[..n])
            .await
            .map_err(|e| format!("quic write: {e}"))?;
        remaining -= n;
    }
    send.finish().map_err(|e| format!("finish: {e}"))?;
    let mut ack = [0u8; 1];
    recv.read_exact(&mut ack)
        .await
        .map_err(|e| format!("quic ack: {e}"))?;
    let ms = start.elapsed().as_millis();
    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    Ok(ms)
}

fn client_config(cc: &str) -> Result<quinn::ClientConfig, String> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("tls versions: {e}"))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAll))
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"spike".to_vec()];

    let qcc = QuicClientConfig::try_from(tls).map_err(|e| format!("quic client cfg: {e}"))?;
    let mut cfg = quinn::ClientConfig::new(Arc::new(qcc));

    let mut transport = quinn::TransportConfig::default();
    match cc {
        "bbr" => {
            transport
                .congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
        }
        "cubic" => {
            transport
                .congestion_controller_factory(Arc::new(quinn::congestion::CubicConfig::default()));
        }
        "newreno" => {
            transport.congestion_controller_factory(Arc::new(
                quinn::congestion::NewRenoConfig::default(),
            ));
        }
        other => return Err(format!("unknown cc: {other} (want bbr|cubic|newreno)")),
    }
    transport.max_idle_timeout(Some(
        Duration::from_secs(30)
            .try_into()
            .expect("30s idle timeout"),
    ));
    cfg.transport_config(Arc::new(transport));
    Ok(cfg)
}

/// Accept any server cert — the spike measures congestion control, not security
/// (the sink is ours, on a throwaway port). NEVER ships.
#[derive(Debug)]
struct AcceptAll;

impl ServerCertVerifier for AcceptAll {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}
