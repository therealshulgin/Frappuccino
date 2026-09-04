//! HTTP/3 chunk upload over a pinned QUIC transport — Phase 3a (transport plan
//! `docs/TRANSPORT_PLAN.md` Phase 3, ROADMAP §10.9).
//!
//! The reliability transport. Phase 2 measured quinn's userspace **BBR** beating
//! Android's cubic-only kernel TCP by ×5-15 under loss (Gate-2 = GO); this module
//! productionises that client: `quinn` + `h3` + the BBR congestion controller,
//! uploading the already-encrypted `.strm` chunk over HTTP/3 to a generic h3
//! endpoint that fronts the relay. Generic HTTP/3 (not a bespoke framing) so the
//! traffic is inclassifiable as anything but ordinary QUIC — the obfuscation
//! layer (Phase 3b: a `Hysteria2` front + a 2nd cert pin) layers on top of this
//! without rewriting the client.
//!
//! Same heap-0 contract as [`crate::upload`]: the bearer is read inside Rust and
//! set on the `authorization` header here; it never crosses the FFI. Same
//! [`PutResult`] shape (`http_status == 0` + a machine tag on transport error) so
//! the Kotlin worker maps it through the *identical* status-code branches.
//!
//! ## Connection model (finding M1)
//!
//! A process-global, resettable QUIC connection multiplexes every concurrent
//! upload worker: one `quinn::Endpoint` + one `quinn::Connection` + one h3
//! `SendRequest` handle, shared via a brief `Mutex` (we clone the cheap
//! `SendRequest` out and release the lock before the async send, so the cap=6
//! workers never serialise on it). The driver task runs on a **multi-thread**
//! tokio runtime so the 6 `block_on` calls from the `WorkManager` threads are
//! driven concurrently rather than serialised — otherwise the adaptive-quality
//! manager would observe inflated `uploadMs` and mis-decide.
//!
//! ## Timeouts (finding M2)
//!
//! A per-call ceiling ([`CALL_TIMEOUT`], matching the `DirectTls` 120 s hard
//! ceiling) wraps the send+recv so a stalled PUT can never hold a worker's
//! concurrency permit indefinitely; connection establishment is bounded
//! separately by the 30 s QUIC idle timeout (quinn applies it during the
//! handshake), so the worst-case permit hold is connect + call, always finite.
//! QUIC keep-alive + idle-timeout keep the connection warm across the ~5 s chunk
//! cadence. On a mid-call error the cached connection is dropped only if it
//! actually died ([`reset_quic_client_if_dead`]) — a transient per-stream error
//! never evicts the connection the other concurrent workers are using.

use crate::pin::PinnedCertVerifier;
use crate::salamander_socket::SalamanderSocket;
use crate::upload::{elapsed_ms, PutResult};
use quinn::crypto::rustls::QuicClientConfig;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, MutexGuard, OnceLock, PoisonError};
use std::time::{Duration, Instant};

/// Body slice size (bytes) handed to a single `send_data`. Bounds per-send
/// memory and plays nicely with QUIC flow control; parity with the Phase 2 spike.
const CHUNK: usize = 64 * 1024;

/// Hard ceiling on a single PUT (connect reuse + send + response). Matches the
/// `DirectTls` `reqwest` 120 s call timeout so the concurrency permit is released
/// on the same bound regardless of transport (M2).
const CALL_TIMEOUT: Duration = Duration::from_secs(120);

/// UDP port the client targets. Phase 3a sent plain QUIC straight to Caddy on
/// :8444; Phase 3b (brick 1b) points at the TRANSPARENT Salamander de-obfs proxy
/// on :8445, which de-XORs and forwards plain QUIC to Caddy :8444. The proxy does
/// NOT terminate QUIC, so the host and SPKI pin stay UNCHANGED (the client still
/// validates Caddy's cert end-to-end) — only the port moves and `obfs_psk` is set
/// in [`prod_target`]. No 2nd pin needed (the transparent proxy was the design
/// that made the "2nd pin" assumption obsolete).
const OBF_QUIC_PORT: u16 = 8445;

/// The pinned QUIC endpoint to reach: host (for SNI + pin host-check), UDP port,
/// and the base64 SPKI SHA-256 pin of its cert. Production uses
/// [`prod_target`]; the local integration test injects 127.0.0.1 + its self-
/// signed cert's pin via [`put_chunk_quic_to`].
#[derive(Clone)]
pub struct QuicTarget {
    /// Host for the TLS SNI and the pin's host-check. A DOMAIN in prod since
    /// the 2026-06-27 migration (`prod_target` sets `pin::PINNED_HOST`), not an
    /// IP literal as this line used to say. The name goes out in the
    /// ClientHello: under the Salamander XOR on this UDP path, in clear on the
    /// DirectTls control plane.
    pub host: String,
    /// UDP port of the HTTP/3 endpoint.
    pub port: u16,
    /// Base64 SPKI SHA-256 pins of the endpoint's leaf cert — the peer is
    /// accepted if it matches ANY (primary + optional break-glass, mirroring
    /// [`crate::pin`]). The local integration test passes a single self-signed pin.
    pub pins: Vec<String>,
    /// Phase 3b — when `Some`, datagrams are Salamander-obfuscated with this PSK
    /// (a [`crate::salamander_socket::SalamanderSocket`] wraps the UDP socket);
    /// `None` = plain QUIC (Phase 3a). [`prod_target`] sets it now that the
    /// server-side de-obfuscation proxy (brick 1b) is deployed on :8445.
    pub obfs_psk: Option<Vec<u8>>,
}

impl fmt::Debug for QuicTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never print the obfs PSK.
        f.debug_struct("QuicTarget")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("pins", &self.pins)
            .field("obfs_psk", &self.obfs_psk.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

impl QuicTarget {
    fn authority(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

/// The production HTTP/3 endpoint — the relay domain, QUIC port, relay cert pin.
fn prod_target() -> QuicTarget {
    QuicTarget {
        host: crate::pin::PINNED_HOST.to_owned(),
        port: OBF_QUIC_PORT,
        // Primary + the two pre-seeded break-glass pins (audit D-2): once ObfQuic
        // ships in release (Phase 3b / Lot 3 B), the break-glass rotations work on
        // this path too, not just DirectTls — including the off-host 3rd key
        // (PIN_NEXT2) used for seizure recovery.
        pins: vec![
            crate::pin::PIN_SHA256_B64.to_owned(),
            crate::pin::PIN_NEXT_B64.to_owned(),
            crate::pin::PIN_NEXT2_B64.to_owned(),
        ],
        // Salamander-obfuscated: the de-obfs proxy (brick 1b) is live on :8445
        // and ObfQuic is the release transport since Lot 3 B4. PSK is byte-for-byte
        // the relay's FRAP_OBFS_PSK env (parity verified via SHA-256). It is an
        // app-embedded OBFUSCATION secret (defeats passive DPI + makes the relay a
        // dead port to probers without it), NOT a confidentiality key — an
        // adversary holding the APK can extract it (documented limitation). Rotated
        // 2026-06-27 (Lot 3 B1-PSK, off the long-lived dev value); re-provision
        // again right before the public 8.2.5 release so the shipped PSK is fresh.
        obfs_psk: Some(
            b"15953a10472fb88b089f193570bdcf929dca5f35476d8fbb4b47626924869b22".to_vec(),
        ),
    }
}

/// h3 request-sender handle for our quinn connection. Cheap to clone; each
/// concurrent PUT clones one and opens its own HTTP/3 request stream.
type H3SendRequest = h3::client::SendRequest<h3_quinn::OpenStreams, bytes::Bytes>;

/// Process-global multi-thread tokio runtime driving the QUIC I/O. Built once,
/// lazily; never reset (only the connection is). `None` if the runtime failed to
/// build (reported as a transport error rather than a panic across the FFI).
static QUIC_RT: OnceLock<Option<tokio::runtime::Runtime>> = OnceLock::new();

fn rt() -> Option<&'static tokio::runtime::Runtime> {
    QUIC_RT
        .get_or_init(|| {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .thread_name("frap-quic")
                .build()
                .ok()
        })
        .as_ref()
}

/// Process-global pinned QUIC connection, resettable via [`reset_quic_client`].
static QUIC_CONN: Mutex<Option<QuicConn>> = Mutex::new(None);

fn conn_guard() -> MutexGuard<'static, Option<QuicConn>> {
    QUIC_CONN.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Process-global "QUIC can't establish on this network/session" latch
/// (Phase 3b brick 3 — `docs/TRANSPORT_PLAN.md`, ROADMAP §10.9). Set when a PUT
/// fails to *establish* the QUIC connection (handshake / connect / no runtime —
/// the UDP-blocked-network or `:8444`-down case), NOT on a per-stream error or a
/// real HTTP response. The FFI dispatch reads it to route subsequent chunks
/// straight to `DirectTls` instead of re-paying the connect/idle timeout on
/// every chunk. Cleared (re-arming QUIC) at each recording start — the FFI
/// `upload_transport_rearm` calls [`clear_quic_degraded`] — and on every auth clear
/// (lock / auto-lock / 401 / panic, via [`reset_quic_client`]). So QUIC is
/// re-attempted at the next recording at the latest: a network or endpoint that
/// recovers gets QUIC back without an app restart, even when the app never locks
/// between recordings (auth clears alone can be many recordings apart).
static QUIC_DEGRADED: AtomicBool = AtomicBool::new(false);

/// Whether QUIC has been latched as unable to establish (see [`QUIC_DEGRADED`]).
/// Read by the FFI dispatch to skip QUIC and go straight to `DirectTls`.
#[must_use]
pub fn quic_is_degraded() -> bool {
    QUIC_DEGRADED.load(Ordering::Relaxed)
}

/// Latch QUIC as unable to establish. Called only from connection-establishment
/// failure paths in [`put_chunk_quic_to`].
fn mark_quic_degraded() {
    QUIC_DEGRADED.store(true, Ordering::Relaxed);
}

/// Re-arm QUIC after a degraded latch. Called by [`reset_quic_client`] on every
/// auth clear (lock / auto-lock / 401 / panic) AND directly by the FFI at each
/// recording start (`upload_transport_rearm`) so a recording re-attempts QUIC even
/// when no auth clear happened since the latch was set — an unlocked app can
/// record many times between locks, and the latch must not strand the transport
/// on `DirectTls` across recordings. Clearing the latch alone (this fn) does NOT
/// tear down the connection, so in-flight chunks from a still-draining previous
/// recording are not disrupted.
pub fn clear_quic_degraded() {
    QUIC_DEGRADED.store(false, Ordering::Relaxed);
}

/// A live QUIC/h3 connection plus the bits needed to tear it down. Private —
/// not `Debug` (the workspace `missing_debug_implementations` lint only targets
/// public items).
struct QuicConn {
    /// `host:port` this connection was built for; a request to a different
    /// authority (only the integration test does this) forces a rebuild.
    authority: String,
    endpoint: quinn::Endpoint,
    conn: quinn::Connection,
    send_request: H3SendRequest,
    driver: tokio::task::JoinHandle<()>,
}

/// Close a connection's QUIC + endpoint and stop its driver task. Takes a
/// reference (the close/abort calls are `&self`); the caller's binding drops the
/// `QuicConn` afterwards. Idempotent at the quinn level (closing twice is a no-op).
fn teardown(c: &QuicConn) {
    c.driver.abort();
    c.conn.close(0u32.into(), b"reset");
    c.endpoint.close(0u32.into(), b"reset");
}

/// Drop the process-global QUIC connection so its session keys + any buffered
/// request data are torn down. The QUIC equivalent of `reset_upload_client` /
/// `OkHttp`'s `evictAll`; called from `upload_auth_clear` on every JWT clear
/// (401 / lock / panic-wipe / auto-lock / drain-complete), inheriting the same
/// drain-deferral. In-flight PUTs on a closed connection error out and retry
/// (one rebuilds). Idempotent; no-op if no connection was ever built.
pub fn reset_quic_client() {
    if let Some(c) = conn_guard().take() {
        teardown(&c);
    }
    // Re-arm QUIC: a reset is a clean slate (auth clear: lock / auto-lock / 401 /
    // panic), so the degraded latch must not outlive the connection it was set
    // against. Recording-start re-arm is separate — the FFI calls
    // `clear_quic_degraded` alone, WITHOUT this teardown, so it never drops a
    // connection that a still-draining recording's in-flight chunks are using.
    clear_quic_degraded();
}

/// Drop the cached connection ONLY if the QUIC connection is actually dead
/// (it reported a close reason). Called on a per-PUT error: a stream-scoped
/// failure (one request reset, an early-response `STOP_SENDING`) must NOT tear
/// down the connection the other concurrent workers are happily multiplexing on
/// (that would turn one transient error into a cap-6 retry storm). Only a
/// genuinely broken connection is rebuilt on the next PUT. Idempotent.
fn reset_quic_client_if_dead() {
    let mut guard = conn_guard();
    let dead = guard
        .as_ref()
        .is_some_and(|c| c.conn.close_reason().is_some());
    if dead {
        if let Some(c) = guard.take() {
            teardown(&c);
        }
    }
}

// `put_chunk_quic` REMOVED (2026-09-03), for the same reason and in the same
// gesture as `upload::put_chunk`: it was the bearer-only wrapper, its sole caller
// was the FFI `upload_put_chunk`, and being `pub` it would have gone on being
// compiled into the shipped .so without a single warning.

/// PUT one already-encrypted `.strm` chunk over HTTP/3 to the production
/// endpoint, with an arbitrary header list (the QUIC twin of
/// [`crate::upload::put_chunk_with_headers`]). Phase C relay-blind report chunks
/// pass the per-report capability headers; `Content-Type` is always added. The
/// blob is streamed from disk (ciphertext, no plaintext). Never panics — every
/// failure maps to a [`PutResult`] with `http_status == 0` and a machine tag.
pub fn put_chunk_quic_with_headers(
    url: &str,
    blob_path: &str,
    headers: &[(&str, &str)],
) -> PutResult {
    put_chunk_quic_to_with_headers(&prod_target(), url, blob_path, headers)
}

/// [`put_chunk_quic_with_headers`] against an explicit target — production passes
/// [`prod_target`]; the local h3 integration test passes 127.0.0.1 + its test
/// cert's pin.
pub fn put_chunk_quic_to(
    target: &QuicTarget,
    url: &str,
    bearer: &str,
    blob_path: &str,
) -> PutResult {
    put_chunk_quic_to_with_headers(target, url, blob_path, &[("authorization", bearer)])
}

/// [`put_chunk_quic_to`] generalized to an arbitrary header list. The request
/// path is taken from `url`; the scheme/authority are the target's (so the relay
/// base URL the worker already builds is reused verbatim, while the QUIC
/// endpoint's own address/pin live here).
pub fn put_chunk_quic_to_with_headers(
    target: &QuicTarget,
    url: &str,
    blob_path: &str,
    headers: &[(&str, &str)],
) -> PutResult {
    let started = Instant::now();

    // Missing / empty blob = a concurrent worker already uploaded + secure-
    // deleted it (mirrors the DirectTls `file_missing` path → caller treats it
    // as success). The body is ciphertext, so a plain read is fine.
    let body = match std::fs::read(blob_path) {
        Ok(b) if !b.is_empty() => bytes::Bytes::from(b),
        _ => return PutResult::failed("file_missing", started),
    };

    // Reuse the path from the relay URL; the authority is the QUIC endpoint's.
    let path = match url.parse::<http::Uri>() {
        Ok(u) => u
            .path_and_query()
            .map_or_else(|| u.path().to_owned(), |pq| pq.as_str().to_owned()),
        Err(_) => return PutResult::failed("bad_url", started),
    };
    let endpoint_uri: http::Uri = match format!("https://{}{}", target.authority(), path).parse() {
        Ok(u) => u,
        Err(_) => return PutResult::failed("bad_url", started),
    };

    let Some(rt) = rt() else {
        // No tokio runtime → QUIC is structurally unavailable in this process;
        // latch so subsequent chunks route straight to DirectTls.
        mark_quic_degraded();
        return PutResult::failed("rt_build", started);
    };

    rt.block_on(async move {
        let send_request = match obtain_send_request(target).await {
            Ok(sr) => sr,
            Err(tag) => {
                // Connection establishment failed (handshake / connect / verify)
                // — the UDP-blocked-network or endpoint-down case. Latch so the
                // next chunks skip QUIC; the FFI dispatch falls THIS one back to
                // DirectTls (a per-stream `do_put` error below does NOT latch —
                // the connection is fine for the other concurrent workers).
                mark_quic_degraded();
                return PutResult::failed(tag, started);
            }
        };

        // Phase 3.49 (2026-06-23) — signal-A goodput. `obtain_send_request`
        // above establishes (or reuses) the QUIC connection — on the first
        // chunk that includes the full h3 handshake. `transfer_started` is taken
        // AFTER it, so `transfer_ms` measures only the stream send + response
        // (the cleanest goodput proxy of the two transports, since QUIC
        // separates connect from send explicitly). Logging-only.
        let transfer_started = Instant::now();
        match tokio::time::timeout(
            CALL_TIMEOUT,
            do_put(send_request, endpoint_uri, headers, body),
        )
        .await
        {
            Ok(Ok(status)) => PutResult {
                http_status: status,
                upload_ms: elapsed_ms(started),
                transfer_ms: elapsed_ms(transfer_started),
                error_detail: None,
            },
            Ok(Err(tag)) => {
                // Mid-call failure: rebuild ONLY if the connection actually died
                // (close_reason set) — a stream-scoped error must not evict the
                // connection the other concurrent workers are using. The blob
                // stays on disk and the caller retries either way.
                reset_quic_client_if_dead();
                PutResult::failed(tag, started)
            }
            Err(_) => {
                // Timed out: same rule — only rebuild a genuinely dead
                // connection (a slow-but-alive one may serve the next chunk).
                // A timeout does NOT latch degraded (the connection established
                // fine): the FFI falls THIS chunk back to DirectTls, but the next
                // chunk still tries QUIC. A persistently slow-but-alive data path
                // thus re-pays the timeout per chunk (bounded, never data loss —
                // the blob stays on disk). Intentional: under loss QUIC-BBR
                // usually still beats TLS, so a slow QUIC path must not condemn
                // the transport for the whole session.
                reset_quic_client_if_dead();
                PutResult::failed("timeout", started)
            }
        }
    })
}

/// Get a request-sender for `target`, reusing the cached connection or building
/// a fresh one. Never holds the holder lock across an `.await`: the fast path
/// clones the `SendRequest` out under the lock; the slow path builds the
/// connection *without* the lock, then stores it under a brief re-lock
/// (double-checking so a concurrent first-caller's connection wins and ours is
/// torn down).
async fn obtain_send_request(target: &QuicTarget) -> Result<H3SendRequest, &'static str> {
    let want = target.authority();

    // Fast path: a cached connection for this authority.
    {
        let guard = conn_guard();
        if let Some(c) = guard.as_ref() {
            if c.authority == want {
                return Ok(c.send_request.clone());
            }
        }
    }

    // Slow path: build outside the lock (may race; last writer wins).
    let fresh = build_connection(target).await?;
    let sr = fresh.send_request.clone();

    let mut guard = conn_guard();
    if let Some(c) = guard.as_ref() {
        if c.authority == want {
            // A concurrent caller already published one — use theirs, drop ours.
            let existing = c.send_request.clone();
            drop(guard);
            teardown(&fresh);
            return Ok(existing);
        }
    }
    // Replace any stale-authority connection (test path) and publish ours.
    if let Some(old) = guard.replace(fresh) {
        teardown(&old);
    }
    Ok(sr)
}

/// Connect quinn to `target`, run the HTTP/3 handshake, and spawn the
/// connection driver. Returns the live connection + a request-sender.
async fn build_connection(target: &QuicTarget) -> Result<QuicConn, &'static str> {
    let addr = resolve(&target.host, target.port)?;
    let bind = if addr.is_ipv4() {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
    } else {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
    };

    let mut endpoint = match target.obfs_psk.as_ref() {
        None => quinn::Endpoint::client(bind).map_err(|_| "endpoint")?,
        Some(psk) => {
            // Phase 3b — Salamander obfs: wrap quinn's default socket so every
            // datagram is XOR-scrambled under QUIC. We're inside the tokio
            // runtime (rt.block_on in put_chunk_quic_to), so wrap_udp_socket is
            // valid here.
            let std_sock = std::net::UdpSocket::bind(bind).map_err(|_| "endpoint")?;
            let runtime: std::sync::Arc<dyn quinn::Runtime> =
                std::sync::Arc::new(quinn::TokioRuntime);
            let inner = runtime.wrap_udp_socket(std_sock).map_err(|_| "endpoint")?;
            let obfs = std::sync::Arc::new(SalamanderSocket::new(inner, psk.clone()));
            quinn::Endpoint::new_with_abstract_socket(
                quinn::EndpointConfig::default(),
                None,
                obfs,
                runtime,
            )
            .map_err(|_| "endpoint")?
        }
    };
    endpoint.set_default_client_config(client_config(target)?);

    let conn = endpoint
        .connect(addr, &target.host)
        .map_err(|_| "connect_setup")?
        .await
        .map_err(|_| "connect")?;

    let h3_conn = h3_quinn::Connection::new(conn.clone());
    let (mut driver, send_request) = h3::client::new(h3_conn).await.map_err(|_| "h3_handshake")?;

    // Drive the connection until it closes. We're inside the runtime context
    // (called from `rt.block_on`), so `tokio::spawn` is valid here.
    let driver = tokio::spawn(async move {
        let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
    });

    Ok(QuicConn {
        authority: target.authority(),
        endpoint,
        conn,
        send_request,
        driver,
    })
}

/// Send the request head + body, await the response head, drain the response
/// body. Returns the HTTP status. Every step maps failure to a short tag.
async fn do_put(
    mut send_request: H3SendRequest,
    uri: http::Uri,
    headers: &[(&str, &str)],
    body: bytes::Bytes,
) -> Result<u16, &'static str> {
    let mut builder = http::Request::builder()
        .method(http::Method::PUT)
        .uri(uri)
        .header(http::header::CONTENT_TYPE, "application/octet-stream");
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    let req = builder.body(()).map_err(|_| "req_build")?;

    let mut stream = send_request
        .send_request(req)
        .await
        .map_err(|_| "send_request")?;

    // Stream the body. If the server decides early (401 stale JWT, 507 disk-full)
    // it responds and STOP_SENDINGs mid-body, so a send error here is NOT
    // necessarily fatal: we still fall through to `recv_response`, which yields
    // the real status. Mistaking an early-401/507 for a generic transport error
    // (code 0) would defeat the Kotlin worker's status branches (401 -> clear
    // JWT, 507 -> disk-full breaker). Only if the response read ALSO fails is it
    // a true transport error.
    let mut send_failed = false;
    let mut off = 0;
    while off < body.len() {
        let end = (off + CHUNK).min(body.len());
        if stream.send_data(body.slice(off..end)).await.is_err() {
            send_failed = true;
            break;
        }
        off = end;
    }
    if !send_failed && stream.finish().await.is_err() {
        send_failed = true;
    }

    let resp = stream.recv_response().await.map_err(|_| {
        if send_failed {
            "send_data"
        } else {
            "recv_response"
        }
    })?;
    let status = resp.status().as_u16();

    // Drain the response body so the stream completes cleanly (best-effort: the
    // status is already decided).
    while let Ok(Some(_)) = stream.recv_data().await {}

    Ok(status)
}

/// rustls + quinn client config: TLS 1.3 (QUIC requires it), the per-transport
/// SPKI pin, ALPN `h3`, and the **BBR** congestion controller (the Phase 2
/// winner) with keep-alive sized for the chunk cadence.
fn client_config(target: &QuicTarget) -> Result<quinn::ClientConfig, &'static str> {
    let pin_refs: Vec<&str> = target.pins.iter().map(String::as_str).collect();
    let verifier =
        PinnedCertVerifier::with_pins_and_host(&pin_refs, &target.host).map_err(|_| "verifier")?;

    let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
    let mut tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| "tls_versions")?
        .dangerous()
        .with_custom_certificate_verifier(std::sync::Arc::new(verifier))
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"h3".to_vec()];

    let qcc = QuicClientConfig::try_from(tls).map_err(|_| "quic_cfg")?;
    let mut cfg = quinn::ClientConfig::new(std::sync::Arc::new(qcc));

    let mut transport = quinn::TransportConfig::default();
    transport.congestion_controller_factory(std::sync::Arc::new(
        quinn::congestion::BbrConfig::default(),
    ));
    transport.max_idle_timeout(Some(
        Duration::from_secs(30)
            .try_into()
            .map_err(|_| "idle_timeout")?,
    ));
    transport.keep_alive_interval(Some(Duration::from_secs(10)));
    // Phase 3b — Salamander prepends SALT_LEN (8) bytes to every datagram on the
    // wire, so cap MTU discovery 8 below quinn's default 1452 ceiling: otherwise
    // DPLPMTUD validates a size that, once salted, exceeds the path MTU. DF is
    // set (the kernel won't fragment), so the over-MTU datagram is silently
    // dropped -> a black hole for full-size data packets on sub-1460 paths
    // (IPv6 1280, PPPoE, VPN tunnels). The 1200 floor stays >= INITIAL_MTU and
    // 1200 + 8 fits the IPv6 minimum. Obfs-only; plain QUIC keeps quinn defaults.
    if target.obfs_psk.is_some() {
        let mut mtud = quinn::MtuDiscoveryConfig::default();
        mtud.upper_bound(1444); // 1452 (quinn default) - 8 (salamander SALT_LEN)
        transport.mtu_discovery_config(Some(mtud));
        transport.initial_mtu(1200);
    }
    cfg.transport_config(std::sync::Arc::new(transport));

    Ok(cfg)
}

fn resolve(host: &str, port: u16) -> Result<SocketAddr, &'static str> {
    (host, port)
        .to_socket_addrs()
        .map_err(|_| "resolve")?
        .next()
        .ok_or("resolve")
}

// ============================================================================
// Local HTTP/3 integration test — drives `put_chunk_quic_to` against a throwaway
// in-process h3 server (self-signed cert, pinned via the same extraction the
// real verifier uses). Validates the actual QUIC runtime: handshake completes,
// the BBR transport config is accepted, a multi-slice body streams, the HTTP
// status flows back, `reset_quic_client` rebuilds, and concurrent PUTs share one
// connection (M1). No relay, no device — runs under `cargo test --features quic`.
// ============================================================================

#[cfg(all(test, feature = "quic"))]
mod tests {
    use super::{put_chunk_quic_to, quic_is_degraded, reset_quic_client, QuicTarget};
    use std::sync::mpsc;
    use std::sync::Arc;

    /// Self-sign a throwaway cert for 127.0.0.1; return (cert DER, key DER, the
    /// base64 SPKI pin the client must use). The pin is computed via the crate's
    /// own extraction so it cannot diverge from what the verifier enforces.
    fn gen_cert() -> (
        rustls::pki_types::CertificateDer<'static>,
        rustls::pki_types::PrivateKeyDer<'static>,
        String,
    ) {
        let ck = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()])
            .expect("self-signed cert");
        let cert_der = ck.cert.der().clone();
        let pin = crate::pin::spki_pin_b64(cert_der.as_ref()).expect("pin from cert");
        let key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(
            rustls::pki_types::PrivatePkcs8KeyDer::from(ck.key_pair.serialize_der()),
        );
        (cert_der, key_der, pin)
    }

    fn server_config(
        cert_der: rustls::pki_types::CertificateDer<'static>,
        key_der: rustls::pki_types::PrivateKeyDer<'static>,
    ) -> quinn::ServerConfig {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut tls = rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("tls13")
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .expect("single cert");
        tls.alpn_protocols = vec![b"h3".to_vec()];
        let qsc = quinn::crypto::rustls::QuicServerConfig::try_from(tls).expect("quic server cfg");
        quinn::ServerConfig::with_crypto(Arc::new(qsc))
    }

    /// Spawn the h3 server on its own current-thread runtime + OS thread and
    /// return the bound port + the cert pin. Responds 500 to any path containing
    /// "fail500", else 200 (proves the status flows through `do_put`).
    fn spawn_server(obfs_psk: Option<Vec<u8>>) -> (u16, String) {
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("server rt");
            rt.block_on(async move {
                let (cert_der, key_der, pin) = gen_cert();
                let sc = server_config(cert_der, key_der);
                let endpoint = match obfs_psk {
                    None => quinn::Endpoint::server(sc, "127.0.0.1:0".parse().unwrap())
                        .expect("server endpoint"),
                    Some(psk) => {
                        // Server-side Salamander de-obfuscation (mirrors the
                        // client shim) so the handshake completes through XOR.
                        let std_sock = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind");
                        let runtime: Arc<dyn quinn::Runtime> = Arc::new(quinn::TokioRuntime);
                        let inner = runtime.wrap_udp_socket(std_sock).expect("wrap");
                        let obfs =
                            Arc::new(crate::salamander_socket::SalamanderSocket::new(inner, psk));
                        quinn::Endpoint::new_with_abstract_socket(
                            quinn::EndpointConfig::default(),
                            Some(sc),
                            obfs,
                            runtime,
                        )
                        .expect("server endpoint obfs")
                    }
                };
                let port = endpoint.local_addr().expect("local_addr").port();
                tx.send((port, pin)).expect("send port");
                while let Some(incoming) = endpoint.accept().await {
                    tokio::spawn(async move {
                        if let Ok(conn) = incoming.await {
                            serve_conn(conn).await;
                        }
                    });
                }
            });
        });
        rx.recv().expect("server port")
    }

    async fn serve_conn(conn: quinn::Connection) {
        let Ok(mut h3c) =
            h3::server::Connection::<_, bytes::Bytes>::new(h3_quinn::Connection::new(conn)).await
        else {
            return;
        };
        // h3 0.0.8: accept() yields a RequestResolver; resolve_request() gives
        // the (head, stream) pair.
        while let Ok(Some(resolver)) = h3c.accept().await {
            tokio::spawn(async move {
                let Ok((req, mut stream)) = resolver.resolve_request().await else {
                    return;
                };
                let path = req.uri().path().to_string();
                if path.contains("early401") {
                    // Respond 401 on the headers WITHOUT draining the body —
                    // exercises the early-response path (server decides before
                    // the upload finishes) the client must surface as 401.
                    let resp = http::Response::builder()
                        .status(401)
                        .body(())
                        .expect("resp");
                    let _ = stream.send_response(resp).await;
                    let _ = stream.finish().await;
                    return;
                }
                // Drain the request body.
                while let Ok(Some(_)) = stream.recv_data().await {}
                let code = if path.contains("fail500") {
                    500u16
                } else {
                    200u16
                };
                let resp = http::Response::builder()
                    .status(code)
                    .body(())
                    .expect("resp");
                let _ = stream.send_response(resp).await;
                let _ = stream.finish().await;
            });
        }
    }

    fn write_blob(name: &str, len: usize) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(name);
        std::fs::write(&path, vec![0x5Au8; len]).expect("write blob");
        path
    }

    #[test]
    fn quic_put_roundtrip_status_reset_and_concurrency() {
        let (port, pin) = spawn_server(None);
        let target = QuicTarget {
            host: "127.0.0.1".to_string(),
            port,
            pins: vec![pin],
            obfs_psk: None,
        };
        let bearer = "Bearer test.jwt.value";

        // 1. Happy path — a 256 KiB body spans multiple 64 KiB send_data slices.
        let blob = write_blob("frap_quic_ok.strm", 256 * 1024);
        let r = put_chunk_quic_to(
            &target,
            "https://relay/file/r1/c1.strm",
            bearer,
            blob.to_str().unwrap(),
        );
        assert_eq!(r.http_status, 200, "happy path: {:?}", r.error_detail);
        assert!(r.error_detail.is_none());
        assert!(r.upload_ms < 120_000);

        // 2. Missing blob — reported as the file_missing race tag (caller treats
        //    it as success), no panic, no request sent.
        let r = put_chunk_quic_to(
            &target,
            "https://relay/file/r1/gone.strm",
            bearer,
            "/no/such/blob.strm",
        );
        assert_eq!(r.http_status, 0);
        assert_eq!(r.error_detail.as_deref(), Some("file_missing"));

        // 3. Status pass-through — the server replies 500 for this path; the
        //    transport must surface it verbatim (the Kotlin worker maps 5xx).
        let r = put_chunk_quic_to(
            &target,
            "https://relay/file/r1/fail500.strm",
            bearer,
            blob.to_str().unwrap(),
        );
        assert_eq!(
            r.http_status, 500,
            "status pass-through: {:?}",
            r.error_detail
        );

        // 3b. Early response — the server replies 401 on the headers WITHOUT
        //     draining the (2 MiB) body, STOP_SENDING-ing mid-upload (stale-JWT
        //     shape). The transport must surface 401, not a send error, so the
        //     worker's 401 -> clear-JWT branch fires. Regression guard for the
        //     early-response masking found in review.
        let bigblob = write_blob("frap_quic_early.strm", 2 * 1024 * 1024);
        let r = put_chunk_quic_to(
            &target,
            "https://relay/file/r1/early401.strm",
            bearer,
            bigblob.to_str().unwrap(),
        );
        assert_eq!(
            r.http_status, 401,
            "early 401 must surface as status: {:?}",
            r.error_detail
        );
        let _ = std::fs::remove_file(&bigblob);

        // 4. Reset then reuse — dropping the connection must not wedge the next
        //    PUT; it rebuilds transparently.
        reset_quic_client();
        let r = put_chunk_quic_to(
            &target,
            "https://relay/file/r1/c2.strm",
            bearer,
            blob.to_str().unwrap(),
        );
        assert_eq!(r.http_status, 200, "after reset: {:?}", r.error_detail);

        // 5. Concurrency (M1) — several workers share one multiplexed connection.
        let mut handles = Vec::new();
        for i in 0..4 {
            let t = target.clone();
            let b = blob.clone();
            handles.push(std::thread::spawn(move || {
                let url = format!("https://relay/file/r1/conc_{i}.strm");
                put_chunk_quic_to(&t, &url, "Bearer test.jwt.value", b.to_str().unwrap())
                    .http_status
            }));
        }
        for h in handles {
            assert_eq!(h.join().unwrap(), 200, "concurrent PUT");
        }

        // 6. Degraded latch (Phase 3b brick 3) — a connection-ESTABLISHMENT
        //    failure latches QUIC degraded so the FFI dispatch routes subsequent
        //    chunks to DirectTls; `reset_quic_client` re-arms it. An `.invalid`
        //    host (RFC 6761: resolvers MUST answer NXDOMAIN) parses as a valid URI
        //    authority — so it gets PAST the bad_url check — then fails to
        //    ESTABLISH: normally at resolution (no connect wait), or, if a
        //    misbehaving resolver rewrites `.invalid`, at connect — either path
        //    latches degraded, so the assertion is robust (only the speed is
        //    resolver-dependent). The pin is irrelevant: establishment fails
        //    before TLS.
        reset_quic_client();
        assert!(!quic_is_degraded(), "reset clears the degraded latch");
        let dead = QuicTarget {
            host: "frap-no-such-host.invalid".to_string(),
            port: 443,
            pins: vec!["unused".to_string()],
            obfs_psk: None,
        };
        let r = put_chunk_quic_to(
            &dead,
            "https://relay/file/r1/dead.strm",
            bearer,
            blob.to_str().unwrap(),
        );
        assert_eq!(r.http_status, 0, "dead target: no HTTP response");
        assert!(
            quic_is_degraded(),
            "establishment failure must latch degraded (tag {:?})",
            r.error_detail
        );
        reset_quic_client();
        assert!(
            !quic_is_degraded(),
            "reset re-arms QUIC for the next session"
        );

        // 7. Salamander obfs (Phase 3b brick 1) — a SECOND server that
        //    de-obfuscates, and a client target carrying the matching PSK so the
        //    SalamanderSocket wraps both ends. The full QUIC + h3 handshake and
        //    the PUT must complete THROUGH the per-packet XOR layer (proves the
        //    AsyncUdpSocket shim: obfuscate on send, de-obfuscate on recv, both
        //    directions). reset() first so this builds a fresh obfs connection.
        reset_quic_client();
        let psk = b"frap-loopback-obfs-psk".to_vec();
        let (oport, opin) = spawn_server(Some(psk.clone()));
        let otarget = QuicTarget {
            host: "127.0.0.1".to_string(),
            port: oport,
            pins: vec![opin],
            obfs_psk: Some(psk),
        };
        let r = put_chunk_quic_to(
            &otarget,
            "https://relay/file/r1/obfs.strm",
            bearer,
            blob.to_str().unwrap(),
        );
        assert_eq!(
            r.http_status, 200,
            "obfuscated PUT through salamander: {:?}",
            r.error_detail
        );
        reset_quic_client();

        let _ = std::fs::remove_file(&blob);
    }
}
