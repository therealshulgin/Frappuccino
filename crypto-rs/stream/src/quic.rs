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

use crate::file_range::{FileRange, FileRangeReader, RangeFailure};
use crate::pin::PinnedCertVerifier;
use crate::salamander_socket::SalamanderSocket;
use crate::transport::{Method, OutgoingRequest};
use crate::upload::{elapsed_ms, response_tag, PutResult, REFUSAL_BODY_CAP};
use quinn::crypto::rustls::QuicClientConfig;
use std::fmt;
use std::io::Read as _;
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
/// signed cert's pin via [`send_quic_to`].
#[derive(Clone)]
pub struct QuicTarget {
    /// Host for the TLS SNI and the pin's host-check. A DOMAIN in prod since
    /// the 2026-06-27 migration (`prod_target` sets `pin::PINNED_HOST`), not an
    /// IP literal as this line used to say. The name goes out in the
    /// `ClientHello`: under the Salamander XOR on this UDP path, in clear on the
    /// `DirectTls` control plane.
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
/// failure paths in [`send_quic_to`].
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

/// Send one relay write over HTTP/3 to the production endpoint, the QUIC leg
/// of [`crate::transport::send`].
pub fn send_quic(request: &OutgoingRequest<'_>) -> PutResult {
    send_quic_to(&prod_target(), request)
}

/// [`send_quic`] against an explicit target. The request path is taken from
/// the URL; the scheme and authority are the target's. The body is streamed
/// from its file range in [`CHUNK`]-sized slices (never loaded whole) and,
/// when the range carries an expected hash, re-hashed as it goes: on a
/// mismatch the request stream is reset before its last bytes, so the relay
/// never receives the body whole.
///
/// Local problems (`bad_url`, the [`RangeFailure`] tags) are reported before
/// any network activity, or by their own tag if they occur mid-body, and never
/// latch QUIC as degraded. Every failure is a [`PutResult`], none is raised.
pub fn send_quic_to(target: &QuicTarget, request: &OutgoingRequest<'_>) -> PutResult {
    let started = Instant::now();
    let method = match request.method {
        Method::Put => http::Method::PUT,
        Method::Post => http::Method::POST,
    };
    let url = request.url;
    let headers = request.headers;

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
    let mut body = match request.body.map(FileRange::open).transpose() {
        Ok(body) => body,
        Err(failure) => return PutResult::failed(failure.tag(), started),
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
                // next chunks skip QUIC; the dispatch (`transport::send`) falls
                // THIS one back to DirectTls (a per-stream `do_request` error
                // below does NOT latch — the connection is fine for the other
                // concurrent workers).
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
            do_request(send_request, method, endpoint_uri, headers, body.as_mut()),
        )
        .await
        {
            Ok(Ok((status, body_head))) => PutResult {
                http_status: status,
                upload_ms: elapsed_ms(started),
                transfer_ms: elapsed_ms(transfer_started),
                error_detail: response_tag(status, &body_head),
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
            // runtime (rt.block_on in send_quic_to), so wrap_udp_socket is
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

/// Send the request head and the body (if any), await the response head,
/// drain the response body. Returns the HTTP status and, for a 409, the first
/// [`REFUSAL_BODY_CAP`] bytes of the body (empty otherwise). Every step maps
/// failure to a short tag; a local failure of the body reader resets the
/// request stream and returns the reader's own tag.
async fn do_request(
    mut send_request: H3SendRequest,
    method: http::Method,
    uri: http::Uri,
    headers: &[(&str, &str)],
    body: Option<&mut FileRangeReader>,
) -> Result<(u16, Vec<u8>), &'static str> {
    let mut builder = http::Request::builder().method(method).uri(uri);
    if body.is_some() {
        builder = builder.header(http::header::CONTENT_TYPE, "application/octet-stream");
    }
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
    if let Some(reader) = body {
        let mut slice = vec![0u8; CHUNK];
        loop {
            let read = match reader.read(&mut slice) {
                Ok(0) => break,
                Ok(read) => read,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => {
                    // The file changed or failed under us: abort the request
                    // so the relay never sees the body whole.
                    stream.stop_stream(h3::error::Code::H3_REQUEST_CANCELLED);
                    return Err(reader.failure().map_or("body_read", RangeFailure::tag));
                }
            };
            let Some(filled) = slice.get(..read) else {
                stream.stop_stream(h3::error::Code::H3_REQUEST_CANCELLED);
                return Err("body_read");
            };
            if stream
                .send_data(bytes::Bytes::copy_from_slice(filled))
                .await
                .is_err()
            {
                send_failed = true;
                break;
            }
        }
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
    // status is already decided). A 409 keeps the start of its body, which
    // tells the closure refusal apart from the other conflicts.
    let keep = if status == 409 { REFUSAL_BODY_CAP } else { 0 };
    let mut body_head = Vec::new();
    while let Ok(Some(mut data)) = stream.recv_data().await {
        use bytes::Buf as _;
        while data.has_remaining() {
            let part = data.chunk();
            let room = keep.saturating_sub(body_head.len());
            body_head.extend_from_slice(part.get(..room.min(part.len())).unwrap_or_default());
            let read = part.len();
            data.advance(read);
        }
    }

    Ok((status, body_head))
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
    use super::{quic_is_degraded, reset_quic_client, send_quic_to, QuicTarget};
    use crate::file_range::FileRange;
    use crate::transport::{Method, OutgoingRequest};
    use crate::upload::{PutResult, REPORT_CLOSED_TAG};
    use std::sync::mpsc;
    use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

    /// The QUIC connection and the degraded latch are process-global, so the
    /// tests that drive them run one at a time.
    static SERIAL: Mutex<()> = Mutex::new(());

    fn serial() -> MutexGuard<'static, ()> {
        SERIAL.lock().unwrap_or_else(PoisonError::into_inner)
    }

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
    /// "fail500", else 200 (proves the status flows through `do_request`).
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

    /// PUT the whole file at `blob_path` with a bearer, through the
    /// production send path. A missing file goes through as a one-byte range,
    /// so the send path itself reports it.
    fn put_chunk_quic_to(
        target: &QuicTarget,
        url: &str,
        bearer: &str,
        blob_path: &str,
    ) -> PutResult {
        let body = FileRange::whole_non_empty_file(blob_path)
            .unwrap_or_else(|| FileRange::new(blob_path, 0, 1, None));
        send_quic_to(
            target,
            &OutgoingRequest {
                method: Method::Put,
                url,
                headers: &[("authorization", bearer)],
                body: Some(&body),
            },
        )
    }

    fn write_blob(name: &str, len: usize) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(name);
        std::fs::write(&path, vec![0x5Au8; len]).expect("write blob");
        path
    }

    #[test]
    fn quic_put_roundtrip_status_reset_and_concurrency() {
        let _serial = serial();
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

    /// What the recording server saw of one request: method, path, body, and
    /// whether the body ended cleanly.
    type Seen = Arc<Mutex<Vec<(String, String, Vec<u8>, bool)>>>;

    /// An h3 server that records every request and answers 200 to each one
    /// whose body arrived whole.
    fn spawn_recording_server() -> (u16, String, Seen) {
        let seen: Seen = Arc::new(Mutex::new(Vec::new()));
        let recorder = Arc::clone(&seen);
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("server rt");
            rt.block_on(async move {
                let (cert_der, key_der, pin) = gen_cert();
                let endpoint = quinn::Endpoint::server(
                    server_config(cert_der, key_der),
                    "127.0.0.1:0".parse().unwrap(),
                )
                .expect("server endpoint");
                tx.send((endpoint.local_addr().expect("addr").port(), pin))
                    .expect("send port");
                while let Some(incoming) = endpoint.accept().await {
                    let recorder = Arc::clone(&recorder);
                    tokio::spawn(async move {
                        if let Ok(conn) = incoming.await {
                            serve_recording(conn, recorder).await;
                        }
                    });
                }
            });
        });
        let (port, pin) = rx.recv().expect("server port");
        (port, pin, seen)
    }

    async fn serve_recording(conn: quinn::Connection, seen: Seen) {
        use bytes::Buf as _;
        let Ok(mut h3c) =
            h3::server::Connection::<_, bytes::Bytes>::new(h3_quinn::Connection::new(conn)).await
        else {
            return;
        };
        while let Ok(Some(resolver)) = h3c.accept().await {
            let seen = Arc::clone(&seen);
            tokio::spawn(async move {
                let Ok((req, mut stream)) = resolver.resolve_request().await else {
                    return;
                };
                let mut body = Vec::new();
                let complete = loop {
                    match stream.recv_data().await {
                        Ok(Some(mut data)) => {
                            while data.has_remaining() {
                                let part = data.chunk();
                                body.extend_from_slice(part);
                                let read = part.len();
                                data.advance(read);
                            }
                        }
                        Ok(None) => break true,
                        Err(_) => break false,
                    }
                };
                seen.lock().unwrap().push((
                    req.method().to_string(),
                    req.uri().path().to_string(),
                    body,
                    complete,
                ));
                if complete {
                    let path = req.uri().path();
                    let (code, body): (u16, &'static [u8]) = match path {
                        "/file/r/closed" => (409, br#"{"detail":"Report closed"}"#),
                        "/file/r/conflict" => (
                            409,
                            br#"{"detail":"Chunk already stored with different content"}"#,
                        ),
                        _ => (200, b""),
                    };
                    let resp = http::Response::builder()
                        .status(code)
                        .body(())
                        .expect("resp");
                    let _ = stream.send_response(resp).await;
                    if !body.is_empty() {
                        let _ = stream.send_data(bytes::Bytes::from_static(body)).await;
                    }
                    let _ = stream.finish().await;
                }
            });
        }
    }

    fn sha256(bytes: &[u8]) -> [u8; 32] {
        use sha2::Digest as _;
        sha2::Sha256::digest(bytes).into()
    }

    #[test]
    fn quic_tags_only_the_closure_refusal() {
        let _serial = serial();
        reset_quic_client();
        let (port, pin, _seen) = spawn_recording_server();
        let target = QuicTarget {
            host: "127.0.0.1".to_string(),
            port,
            pins: vec![pin],
            obfs_psk: None,
        };
        let blob = write_blob("frap_quic_refusal.fqe", 1000);
        let body = FileRange::new(&blob, 0, 1000, None);
        for (name, status, tag) in [
            ("closed", 409, Some(REPORT_CLOSED_TAG)),
            ("conflict", 409, None),
            ("fine", 200, None),
        ] {
            let url = format!("https://relay/file/r/{name}");
            let r = send(&target, Method::Put, &url, &[], &body);
            assert_eq!(r.http_status, status, "{name}: {:?}", r.error_detail);
            assert_eq!(r.error_detail.as_deref(), tag, "{name}");
        }
        reset_quic_client();
        let _ = std::fs::remove_file(&blob);
    }

    fn send<'a>(
        target: &QuicTarget,
        method: Method,
        url: &'a str,
        headers: &'a [(&'a str, &'a str)],
        body: &'a FileRange,
    ) -> crate::upload::PutResult {
        send_quic_to(
            target,
            &OutgoingRequest {
                method,
                url,
                headers,
                body: Some(body),
            },
        )
    }

    #[test]
    fn quic_streams_a_body_range_and_never_completes_a_changed_one() {
        let _serial = serial();
        reset_quic_client();
        let (port, pin, seen) = spawn_recording_server();
        let target = QuicTarget {
            host: "127.0.0.1".to_string(),
            port,
            pins: vec![pin],
            obfs_psk: None,
        };
        let data: Vec<u8> = (0u8..=255).cycle().take(300_000).collect();
        let blob = write_blob("frap_quic_range.fqe", 0);
        std::fs::write(&blob, &data).unwrap();

        // A POST of a range in the middle of the file, hash-checked.
        let range = FileRange::new(&blob, 1000, 200_000, Some(sha256(&data[1000..201_000])));
        let headers = [("X-Report-Close-Seq-Limit", "4")];
        let r = send(
            &target,
            Method::Post,
            "https://relay/close/abc",
            &headers,
            &range,
        );
        assert_eq!(r.http_status, 200, "{:?}", r.error_detail);
        {
            let seen = seen.lock().unwrap();
            let (method, path, body, complete) = seen.last().unwrap();
            assert_eq!((method.as_str(), path.as_str()), ("POST", "/close/abc"));
            assert!(complete);
            assert_eq!(body.as_slice(), &data[1000..201_000]);
        }

        // The same range against a hash it no longer has: reset before the
        // last bytes, reported locally, and the relay never gets it whole.
        let changed = FileRange::new(&blob, 1000, 200_000, Some([0u8; 32]));
        let r = send(
            &target,
            Method::Put,
            "https://relay/file/r/changed",
            &[],
            &changed,
        );
        assert_eq!(r.http_status, 0);
        assert_eq!(r.error_detail.as_deref(), Some("body_mismatch"));
        std::thread::sleep(std::time::Duration::from_millis(300));
        let arrived_whole = seen
            .lock()
            .unwrap()
            .iter()
            .any(|(_, path, _, complete)| path == "/file/r/changed" && *complete);
        assert!(!arrived_whole, "a changed body must never arrive whole");

        // Local problems are reported before any request.
        let before = seen.lock().unwrap().len();
        let missing = FileRange::new("/no/such/frap/blob", 0, 1, None);
        let r = send(
            &target,
            Method::Put,
            "https://relay/file/r/missing",
            &[],
            &missing,
        );
        assert_eq!(r.error_detail.as_deref(), Some("file_missing"));
        let short = FileRange::new(&blob, 299_999, 2, None);
        let r = send(
            &target,
            Method::Put,
            "https://relay/file/r/short",
            &[],
            &short,
        );
        assert_eq!(r.error_detail.as_deref(), Some("body_short"));
        assert_eq!(seen.lock().unwrap().len(), before);
        reset_quic_client();
        let _ = std::fs::remove_file(&blob);
    }
}
