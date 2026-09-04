//! Chunk upload over the pinned V2 transport — Phase 1 (transport plan
//! `docs/TRANSPORT_PLAN.md`, §10.7 heap-0).
//!
//! The chunk PUT, ported from Kotlin/`OkHttp` into Rust so the upload bearer
//! never enters the JVM HTTP stack. `DirectTls` only: the same pinned
//! `reqwest::blocking` + [`PinnedCertVerifier`][crate::pin::PinnedCertVerifier]
//! stack the auth/archive calls already use.
//!
//! A process-global, resettable client gives connection reuse (like the old
//! `OkHttp` singleton) without ever holding a lock across the blocking PUT: we
//! clone the `Client` (cheap, `Arc`-shared pool) out of the holder and release
//! the lock before sending, so up to 6 concurrent upload workers don't
//! serialise behind the mutex.

use crate::pin::PinnedCertVerifier;
use rustls::ClientConfig;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Outcome of a chunk PUT.
///
/// `http_status == 0` means the request never produced an HTTP response
/// (connect / TLS / timeout / IO, or a missing blob); `error_detail` carries a
/// short machine tag for the Kotlin side to branch on. The tag `"file_missing"`
/// is the race case (a concurrent worker already uploaded and secure-deleted
/// the blob) — the caller treats it as success, not a retry.
#[derive(Debug, Clone)]
#[must_use]
pub struct PutResult {
    /// HTTP status code, or `0` when no response was obtained.
    pub http_status: u16,
    /// Wall-clock duration of the attempt, milliseconds.
    pub upload_ms: u64,
    /// Phase 3.49 (2026-06-23) — signal-A goodput. Transfer-only duration in
    /// ms: the `send()` / `do_put` time, EXCLUDING file open + client build +
    /// (for QUIC) connection establishment. `0` on failure / no transfer. A
    /// cleaner throughput proxy than `upload_ms` (which folds in setup and the
    /// first-chunk TLS/h3 handshake). Logging-only for now — the adaptive
    /// logic still decides on `upload_ms`.
    pub transfer_ms: u64,
    /// Short tag when `http_status == 0`, else `None`.
    pub error_detail: Option<String>,
}

impl PutResult {
    // `pub(crate)` so the QUIC transport (`quic.rs`) reuses the same failure
    // shape (`http_status == 0` + machine tag) as the DirectTls path.
    pub(crate) fn failed(detail: &str, started: Instant) -> Self {
        Self {
            http_status: 0,
            upload_ms: elapsed_ms(started),
            transfer_ms: 0,
            error_detail: Some(detail.to_owned()),
        }
    }
}

pub(crate) fn elapsed_ms(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

// Process-global pinned upload client, resettable via `reset_upload_client`.
static UPLOAD_CLIENT: Mutex<Option<reqwest::blocking::Client>> = Mutex::new(None);

fn upload_client_guard() -> std::sync::MutexGuard<'static, Option<reqwest::blocking::Client>> {
    UPLOAD_CLIENT
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Build the pinned blocking client. Same TLS stack as
/// [`StreamServerClient`][crate::protocol::StreamServerClient] (explicit ring
/// provider + [`PinnedCertVerifier`]), with upload-sized timeouts: connect 15 s
/// and a 120 s hard ceiling on the whole call so a stalled PUT can never hold a
/// worker's concurrency permit indefinitely (matches the old `OkHttp`
/// `callTimeout`). Returns `None` on any setup failure (the caller reports it as
/// a transport error rather than panicking across the FFI).
fn build_upload_client() -> Option<reqwest::blocking::Client> {
    let verifier = PinnedCertVerifier::new().ok()?;
    let config =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
            .ok()?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
            .with_no_client_auth();

    reqwest::blocking::Client::builder()
        .use_preconfigured_tls(config)
        .connect_timeout(Duration::from_secs(15))
        .timeout(Duration::from_secs(120))
        .build()
        .ok()
}

/// Clone of the process-global client, building it on first use. The clone
/// shares the connection pool; the lock is released before the caller sends.
fn upload_client() -> Option<reqwest::blocking::Client> {
    let mut guard = upload_client_guard();
    if guard.is_none() {
        *guard = build_upload_client();
    }
    guard.clone()
}

/// Drop the process-global upload client so its pooled connections (which may
/// carry the bearer in HTTP/2 state) are torn down. The Rust-transport
/// equivalent of `OkHttp`'s `connectionPool.evictAll()`. In-flight PUTs hold their
/// own clone and finish normally; the next [`put_chunk_with_headers`] rebuilds a
/// fresh client. Idempotent.
pub fn reset_upload_client() {
    *upload_client_guard() = None;
}

// `put_chunk` REMOVED (2026-09-03): the bearer-only wrapper. Its sole caller
// was the FFI `upload_put_chunk`, itself removed when Phase C made every write
// carry a capability signature. Nothing else ever called it, and because it was
// `pub` and re-exported the compiler would never have said so.

/// PUT one already-encrypted `.strm` chunk to `url` with an arbitrary list of
/// request headers (`Content-Type: application/octet-stream` is always added).
/// The Phase C relay-blind report path (FFI `upload_put_report_chunk`) passes the
/// per-report capability headers (`X-Report-PK`, `X-Report-Write-Sig`, and on the
/// creating chunk `X-Report-Create-Sig` + `Authorization`). Header values stay in
/// Rust; none crosses the FFI as a plaintext bearer for the chunk path.
///
/// Never panics: every failure maps to a [`PutResult`] with `http_status == 0`
/// and an `error_detail` tag. A missing or empty file reports `"file_missing"`
/// (race with a concurrent worker), which the caller treats as success.
pub fn put_chunk_with_headers(url: &str, blob_path: &str, headers: &[(&str, &str)]) -> PutResult {
    let started = Instant::now();

    // Missing / empty blob = a concurrent worker already finished and
    // secure-deleted it (mirrors the Kotlin FileNotFoundException-as-success
    // path). Open the file here so reqwest can stream it as the body.
    let Ok(file) = std::fs::File::open(blob_path) else {
        return PutResult::failed("file_missing", started);
    };
    match file.metadata() {
        Ok(meta) if meta.len() > 0 => {}
        _ => return PutResult::failed("file_missing", started),
    }

    let Some(client) = upload_client() else {
        return PutResult::failed("client_build", started);
    };

    // Phase 3.49 (2026-06-23) — signal-A goodput. `started` (above) includes
    // File::open + metadata + client build/clone; `.send()` below also folds in
    // the TLS connect/handshake on the FIRST chunk of a session (pooled
    // connections reuse it afterwards). `transfer_started` excludes the
    // file/client setup so `transfer_ms` is a cleaner link-throughput proxy
    // (body + 1 RTT in steady state, + connect on the very first chunk).
    let transfer_started = Instant::now();
    let mut req = client
        .put(url)
        .header("Content-Type", "application/octet-stream");
    for (name, value) in headers {
        req = req.header(*name, *value);
    }
    match req.body(file).send() {
        Ok(resp) => PutResult {
            http_status: resp.status().as_u16(),
            upload_ms: elapsed_ms(started),
            transfer_ms: elapsed_ms(transfer_started),
            error_detail: None,
        },
        Err(e) => {
            let tag = if e.is_timeout() { "timeout" } else { "network" };
            PutResult::failed(tag, started)
        }
    }
}
