//! Transparent Salamander de-obfuscation UDP proxy — Phase 3b brick 1b
//! (transport plan `docs/TRANSPORT_PLAN.md` Phase 3, ROADMAP §10.9).
//!
//! Sits in FRONT of the relay's QUIC endpoint (Caddy on `:8444`). For each
//! client address it relays UDP both ways, applying the shared Salamander
//! transform ([`frappuccino_crypto_stream::salamander`]):
//!
//! ```text
//! client --[salamander-obfuscated QUIC]--> proxy --[plain QUIC]--> upstream(relay)
//! client <--[salamander-obfuscated]------- proxy <--[plain]------- upstream(relay)
//! ```
//!
//! It does NOT terminate QUIC — it only XOR-(de)obfuscates UDP datagrams — so the
//! relay's TLS/cert pin is unchanged and there is no 2nd pin. A PSK-less probe
//! de-obfuscates to garbage that is never a valid QUIC packet; the upstream drops
//! it, nothing comes back, and the port looks dead.
//!
//! Uses the SAME `salamander` module as the client `SalamanderSocket`, so the two
//! are byte-identical by construction (no cross-language interop risk).

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use frappuccino_crypto_stream::salamander::{self, SALT_LEN};
use tokio::net::UdpSocket;
#[cfg(unix)]
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::Mutex as AsyncMutex;

/// Largest datagram handled: a QUIC packet (<= ~1452 B) + the 8-byte salt, with
/// headroom. A larger datagram is truncated on recv and dropped downstream.
const MAX_DGRAM: usize = 2048;

/// A session idle in BOTH directions for this long is torn down.
const SESSION_IDLE: Duration = Duration::from_secs(60);

/// Hard ceiling on concurrent sessions. The Initial-sniff gate already makes
/// session creation effectively PSK-bound (a non-keyed datagram de-obfuscates to
/// bytes that never pass it), so this is belt-and-suspenders against a
/// PSK-holding flood or aggregate scale — well above any realistic client count.
const MAX_SESSIONS: usize = 4096;

/// How often the stats line is emitted (skipped while fully idle).
const STATS_INTERVAL: Duration = Duration::from_secs(60);

/// Lightweight operational counters (all `Relaxed`; monotonic, no ordering needs).
/// Emitted periodically by [`spawn_stats_logger`] for observability — the proxy
/// is otherwise silent, so without these a live deployment is a black box.
#[derive(Default)]
struct Stats {
    sessions_created: AtomicU64,
    sessions_capped: AtomicU64,
    fwd_c2u: AtomicU64,
    fwd_u2c: AtomicU64,
    gate_rejected: AtomicU64,
    deobf_dropped: AtomicU64,
}

/// Per-client relay state: the upstream socket + last-activity (either direction).
struct Session {
    up: Arc<UdpSocket>,
    last_seen: Mutex<Instant>,
}

impl Session {
    fn touch(&self, now: Instant) {
        *self
            .last_seen
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = now;
    }
}

type Sessions = Arc<AsyncMutex<HashMap<SocketAddr, Arc<Session>>>>;

/// Bind `listen` and relay obfuscated QUIC to/from `upstream`, keyed by `psk`.
/// Runs until the listen socket errors unrecoverably, or `SIGTERM`/`SIGINT`
/// arrives — on a signal it returns `Ok(())` for a clean exit (a `systemctl
/// stop`/`restart` then sees a graceful shutdown instead of a `SIGKILL`; the
/// relay being a UDP relay, in-flight datagrams are fire-and-forget and clients
/// re-establish or fall back via brick 3, so there is nothing to drain).
///
/// # Errors
/// Returns the I/O error if binding `listen`, or a later `recv_from` on it, fails.
pub async fn run(listen: SocketAddr, upstream: SocketAddr, psk: Vec<u8>) -> io::Result<()> {
    let listen_sock = Arc::new(UdpSocket::bind(listen).await?);
    let psk = Arc::new(psk);
    #[cfg(unix)]
    {
        // Graceful shutdown on the relay's Linux: SIGTERM/SIGINT -> clean exit(0)
        // so `systemctl stop`/`restart` does not SIGKILL the proxy mid-flight.
        let mut sigterm = signal(SignalKind::terminate())?;
        let mut sigint = signal(SignalKind::interrupt())?;
        tokio::select! {
            r = serve(listen_sock, upstream, psk) => r,
            _ = sigterm.recv() => {
                eprintln!("frappuccino-obfs-proxy: SIGTERM received, shutting down");
                Ok(())
            }
            _ = sigint.recv() => {
                eprintln!("frappuccino-obfs-proxy: SIGINT received, shutting down");
                Ok(())
            }
        }
    }
    // The proxy is a Linux relay daemon; this branch (no unix signals) exists
    // only so the crate still compiles cross-platform for dev tooling.
    #[cfg(not(unix))]
    serve(listen_sock, upstream, psk).await
}

async fn serve(
    listen_sock: Arc<UdpSocket>,
    upstream: SocketAddr,
    psk: Arc<Vec<u8>>,
) -> io::Result<()> {
    let sessions: Sessions = Arc::new(AsyncMutex::new(HashMap::new()));
    let stats = Arc::new(Stats::default());
    spawn_stats_logger(stats.clone(), sessions.clone());
    let mut buf = vec![0u8; MAX_DGRAM];
    loop {
        let (n, client) = listen_sock.recv_from(&mut buf).await?;
        // De-obfuscate in place; garbage / too-short -> drop (dead-port property:
        // a PSK-less probe is never forwarded, so the relay never replies).
        let Some(plain_len) = salamander::deobfuscate_in_place(&mut buf, n, &psk) else {
            stats.deobf_dropped.fetch_add(1, Ordering::Relaxed);
            continue;
        };
        // Reuse a live session for any packet; CREATE one only for a packet that
        // looks like a QUIC v1 Initial. This extends the dead-port property to
        // resource allocation: PSK-less garbage de-obfuscates to bytes that
        // (almost) never pass the Initial sniff, so it never costs an fd/task.
        let session = if let Some(s) = existing_session(&sessions, client).await {
            s
        } else {
            // New client: only spend an fd/task on a QUIC Initial (dead-port for
            // state); PSK-less garbage is dropped here.
            if !looks_like_quic_initial(&buf[..plain_len]) {
                stats.gate_rejected.fetch_add(1, Ordering::Relaxed);
                continue;
            }
            let Ok(s) =
                create_session(&sessions, &listen_sock, &psk, client, upstream, &stats).await
            else {
                continue;
            };
            s
        };
        session.touch(Instant::now());
        // Forward the recovered plain QUIC datagram to the relay.
        if session.up.send(&buf[..plain_len]).await.is_ok() {
            stats.fwd_c2u.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Emit the [`Stats`] line every [`STATS_INTERVAL`] (to stderr -> journald),
/// skipping ticks where the proxy is fully idle and nothing moved since the last
/// emit, so a 24/7 relay does not spam one line per minute forever.
fn spawn_stats_logger(stats: Arc<Stats>, sessions: Sessions) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(STATS_INTERVAL);
        tick.tick().await; // consume the immediate first tick
        let mut last_total = 0u64;
        loop {
            tick.tick().await;
            let active = sessions.lock().await.len();
            let created = stats.sessions_created.load(Ordering::Relaxed);
            let capped = stats.sessions_capped.load(Ordering::Relaxed);
            let fwd_c2u = stats.fwd_c2u.load(Ordering::Relaxed);
            let fwd_u2c = stats.fwd_u2c.load(Ordering::Relaxed);
            let gate_rejected = stats.gate_rejected.load(Ordering::Relaxed);
            let deobf_dropped = stats.deobf_dropped.load(Ordering::Relaxed);
            // Skip only when fully idle AND no counter moved since the last emit,
            // so a pure-probe flood (gate_rejected/deobf_dropped only, no live
            // session) is still surfaced instead of silently suppressed.
            let total = created + capped + fwd_c2u + fwd_u2c + gate_rejected + deobf_dropped;
            if active == 0 && total == last_total {
                continue;
            }
            last_total = total;
            eprintln!(
                "frappuccino-obfs-proxy stats: active={active} created={created} capped={capped} fwd_c2u={fwd_c2u} fwd_u2c={fwd_u2c} gate_rejected={gate_rejected} deobf_dropped={deobf_dropped}"
            );
        }
    });
}

/// Does `p` look like a QUIC v1 client Initial? Long header (high bit) + fixed
/// bit + Initial packet type + version 1, in a datagram padded to >= 1200
/// (RFC 9000 §14.1 requires the Initial-bearing datagram to be padded). We gate
/// session CREATION on this so PSK-less garbage never costs an fd/task — a
/// non-keyed datagram de-obfuscates to bytes that satisfy all four checks with
/// negligible probability. In-session Handshake/short-header packets (often
/// < 1200, no version field) are forwarded WITHOUT this gate.
fn looks_like_quic_initial(p: &[u8]) -> bool {
    p.len() >= 1200
        && (p[0] & 0x80) != 0 // long header
        && (p[0] & 0x40) != 0 // fixed bit
        && (p[0] & 0x30) == 0 // packet type == Initial
        && p[1..5] == [0x00, 0x00, 0x00, 0x01] // QUIC version 1
}

/// The live session for `client`, if any (no creation).
async fn existing_session(sessions: &Sessions, client: SocketAddr) -> Option<Arc<Session>> {
    sessions.lock().await.get(&client).cloned()
}

/// Create a session for `client`: a dedicated upstream socket + a spawned
/// return-path task. The map lock is never held across the upstream bind/connect.
async fn create_session(
    sessions: &Sessions,
    listen_sock: &Arc<UdpSocket>,
    psk: &Arc<Vec<u8>>,
    client: SocketAddr,
    upstream: SocketAddr,
    stats: &Arc<Stats>,
) -> io::Result<Arc<Session>> {
    // Belt-and-suspenders cap, checked before spending an fd (benign TOCTOU vs the
    // insert below: a soft over/undershoot of one is fine for a flood backstop).
    if sessions.lock().await.len() >= MAX_SESSIONS {
        stats.sessions_capped.fetch_add(1, Ordering::Relaxed);
        return Err(io::Error::other("session cap reached"));
    }
    // A dedicated upstream socket (any local port, same family as the relay).
    let bind: SocketAddr = if upstream.is_ipv4() {
        (std::net::Ipv4Addr::UNSPECIFIED, 0).into()
    } else {
        (std::net::Ipv6Addr::UNSPECIFIED, 0).into()
    };
    let up = UdpSocket::bind(bind).await?;
    up.connect(upstream).await?;
    let session = Arc::new(Session {
        up: Arc::new(up),
        last_seen: Mutex::new(Instant::now()),
    });
    sessions.lock().await.insert(client, session.clone());
    stats.sessions_created.fetch_add(1, Ordering::Relaxed);
    spawn_return_path(
        sessions.clone(),
        listen_sock.clone(),
        psk.clone(),
        client,
        session.clone(),
        stats.clone(),
    );
    Ok(session)
}

/// Read the relay's replies for one client, obfuscate them, send them back to the
/// client. Exits (and removes the session) once it is idle `SESSION_IDLE` in BOTH
/// directions — an upload sends many client->relay packets with sparse replies,
/// which must not expire the session, hence the bidirectional `last_seen` check.
fn spawn_return_path(
    sessions: Sessions,
    listen_sock: Arc<UdpSocket>,
    psk: Arc<Vec<u8>>,
    client: SocketAddr,
    session: Arc<Session>,
    stats: Arc<Stats>,
) {
    tokio::spawn(async move {
        let mut rbuf = vec![0u8; MAX_DGRAM];
        let mut obuf = Vec::with_capacity(MAX_DGRAM + SALT_LEN);
        loop {
            match tokio::time::timeout(SESSION_IDLE, session.up.recv(&mut rbuf)).await {
                Ok(Ok(n)) => {
                    session.touch(Instant::now());
                    let mut salt = [0u8; SALT_LEN];
                    if getrandom::getrandom(&mut salt).is_err() {
                        // OS RNG failure is essentially impossible post-boot on
                        // Linux; if it ever happens, end the session (the client
                        // re-establishes) rather than spin or send an unsalted,
                        // fingerprintable packet.
                        eprintln!("frappuccino-obfs-proxy: getrandom failed; ending session");
                        break;
                    }
                    salamander::obfuscate_into(&mut obuf, &rbuf[..n], &psk, salt);
                    if listen_sock.send_to(&obuf, client).await.is_ok() {
                        stats.fwd_u2c.fetch_add(1, Ordering::Relaxed);
                    }
                }
                Ok(Err(_)) => break, // upstream socket error
                Err(_) => {
                    // recv timed out: tear down only if the CLIENT side is idle
                    // too (the bidirectional check that keeps active uploads alive).
                    let idle = session
                        .last_seen
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .elapsed();
                    if idle >= SESSION_IDLE {
                        break;
                    }
                }
            }
        }
        sessions.lock().await.remove(&client);
    });
}

#[cfg(test)]
mod tests {
    use super::{looks_like_quic_initial, serve, MAX_DGRAM, SALT_LEN};
    use frappuccino_crypto_stream::salamander;
    use proptest::prelude::*;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::net::UdpSocket;

    proptest! {
        // Deterministic (fixed seed); failures persisted + shrunk.
        #![proptest_config(ProptestConfig { cases: 512, ..ProptestConfig::default() })]

        /// §10.10 T2b - the QUIC-Initial sniff never panics on a hostile datagram
        /// (any length, including across the 1200 boundary). Plan-B for Kani: the
        /// proxy crate pulls `tokio` and a >= 1200-byte symbolic array is
        /// intractable, while the function is structurally panic-free (it
        /// short-circuits on `len < 1200` before any indexing).
        #[test]
        fn looks_like_quic_initial_never_panics(
            p in proptest::collection::vec(any::<u8>(), 0..1400),
        ) {
            let _ = looks_like_quic_initial(&p); // bool, never a panic
        }

        /// A datagram shorter than 1200 (RFC 9000's Initial padding floor) never
        /// passes the gate, so it can never create a session (dead-port for
        /// state, the anti-DoS guard from the brick-1b review).
        #[test]
        fn short_datagrams_never_pass_the_gate(
            p in proptest::collection::vec(any::<u8>(), 0..1200),
        ) {
            prop_assert!(!looks_like_quic_initial(&p));
        }
    }

    /// The Initial-sniff gate (the anti-DoS guard) requires EACH marker of a QUIC
    /// v1 Initial. A canonical Initial passes; the same datagram with any one
    /// required marker broken is rejected. Pins the bit logic that the echo test
    /// (which only sends a *valid* Initial) and the proptest (no-panic + length)
    /// leave un-mutation-covered. (§10.10 T3.)
    #[test]
    fn gate_requires_each_initial_marker() {
        let mut ok = vec![0xc0u8, 0x00, 0x00, 0x00, 0x01];
        ok.resize(1200, 0);
        assert!(looks_like_quic_initial(&ok), "canonical Initial must pass");
        let mut no_long = ok.clone();
        no_long[0] = 0x40; // long-header bit (0x80) cleared
        assert!(
            !looks_like_quic_initial(&no_long),
            "no long-header bit -> reject"
        );
        let mut no_fixed = ok.clone();
        no_fixed[0] = 0x80; // fixed bit (0x40) cleared
        assert!(
            !looks_like_quic_initial(&no_fixed),
            "no fixed bit -> reject"
        );
        let mut wrong_type = ok.clone();
        wrong_type[0] = 0xd0; // packet-type bits (0x30) set != Initial
        assert!(
            !looks_like_quic_initial(&wrong_type),
            "non-Initial type -> reject"
        );
        let mut wrong_ver = ok.clone();
        wrong_ver[1] = 0x01; // version != 0x00000001
        assert!(
            !looks_like_quic_initial(&wrong_ver),
            "wrong version -> reject"
        );
    }

    /// Obfuscated client datagram -> proxy de-obfuscates -> echo upstream ->
    /// proxy re-obfuscates -> client de-obfuscates == original. Proves both the
    /// de-obfs (forward) and re-obfs (return) legs + the session mapping.
    #[tokio::test]
    async fn echo_roundtrips_through_proxy() {
        let psk = b"proxy-test-psk".to_vec();
        // Fake upstream: echo whatever it receives back to the sender.
        let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        tokio::spawn(async move {
            let mut b = vec![0u8; MAX_DGRAM];
            while let Ok((n, from)) = upstream.recv_from(&mut b).await {
                let _ = upstream.send_to(&b[..n], from).await;
            }
        });
        // Proxy in front of the echo upstream.
        let listen = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listen.local_addr().unwrap();
        let psk_srv = psk.clone();
        tokio::spawn(async move {
            let _ = serve(Arc::new(listen), upstream_addr, Arc::new(psk_srv)).await;
        });
        // Client: obfuscate a payload, send to the proxy, await the obfuscated echo.
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        // A real-looking QUIC v1 Initial: long header + fixed bit (0xc0), version
        // 00000001, padded >= 1200 so it passes the session-creation gate.
        let mut payload = vec![0xc0u8, 0x00, 0x00, 0x00, 0x01];
        payload.resize(1300, 0x5a);
        let mut obf = Vec::new();
        salamander::obfuscate_into(&mut obf, &payload, &psk, [3u8; SALT_LEN]);
        client.send_to(&obf, proxy_addr).await.unwrap();
        let mut rbuf = vec![0u8; MAX_DGRAM];
        let n = tokio::time::timeout(Duration::from_secs(5), client.recv(&mut rbuf))
            .await
            .expect("no reply from proxy")
            .unwrap();
        let plain = salamander::deobfuscate_in_place(&mut rbuf, n, &psk).expect("deobf reply");
        assert_eq!(
            &rbuf[..plain],
            &payload[..],
            "echo round-trips through the proxy"
        );
    }

    /// A valid-PSK but non-Initial datagram (de-obfuscates fine, but is not a
    /// QUIC Initial) must NOT create a session / be forwarded — the resource-DoS
    /// guard (B1). The echo upstream would reply if it were forwarded; assert
    /// silence instead.
    #[tokio::test]
    async fn non_initial_creates_no_session() {
        let psk = b"proxy-test-psk".to_vec();
        let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        tokio::spawn(async move {
            let mut b = vec![0u8; MAX_DGRAM];
            while let Ok((n, from)) = upstream.recv_from(&mut b).await {
                let _ = upstream.send_to(&b[..n], from).await;
            }
        });
        let listen = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listen.local_addr().unwrap();
        let psk_srv = psk.clone();
        tokio::spawn(async move {
            let _ = serve(Arc::new(listen), upstream_addr, Arc::new(psk_srv)).await;
        });
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        // De-obfuscates fine (>= 8 bytes) but is far too short / wrong form for a
        // QUIC Initial -> must be dropped before a session is created.
        let mut obf = Vec::new();
        salamander::obfuscate_into(
            &mut obf,
            b"not a quic initial packet",
            &psk,
            [5u8; SALT_LEN],
        );
        client.send_to(&obf, proxy_addr).await.unwrap();
        let mut rbuf = vec![0u8; 64];
        let r = tokio::time::timeout(Duration::from_millis(500), client.recv(&mut rbuf)).await;
        assert!(
            r.is_err(),
            "non-Initial must not create a session / be forwarded"
        );
    }

    /// A sub-salt (too short) datagram must be dropped by the proxy, never
    /// forwarded — so an echo upstream never sees it and the client gets no reply.
    #[tokio::test]
    async fn too_short_is_dropped_not_forwarded() {
        let psk = b"proxy-test-psk".to_vec();
        let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        tokio::spawn(async move {
            let mut b = vec![0u8; MAX_DGRAM];
            while let Ok((n, from)) = upstream.recv_from(&mut b).await {
                let _ = upstream.send_to(&b[..n], from).await;
            }
        });
        let listen = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listen.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = serve(Arc::new(listen), upstream_addr, Arc::new(psk)).await;
        });
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.send_to(&[1u8, 2, 3], proxy_addr).await.unwrap(); // < SALT_LEN
        let mut rbuf = vec![0u8; 64];
        let r = tokio::time::timeout(Duration::from_millis(500), client.recv(&mut rbuf)).await;
        assert!(
            r.is_err(),
            "sub-salt datagram must be dropped, not echoed back"
        );
    }
}
