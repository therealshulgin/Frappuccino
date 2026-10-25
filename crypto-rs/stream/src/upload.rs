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

use crate::file_range::{FileRange, FileRangeReader, RangeFailure};
use crate::pin::PinnedCertVerifier;
use crate::transport::{Method, OutgoingRequest};
use rustls::ClientConfig;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Outcome of a relay write.
///
/// `http_status == 0` means the request never produced an HTTP response
/// (connect / TLS / timeout / IO, or a missing body file); `error_detail`
/// carries a short machine tag for the Kotlin side to branch on. With a
/// response, `error_detail` is `None` except for [`REPORT_CLOSED_TAG`]: a 409
/// whose body is the relay's closure refusal, which the caller must tell
/// apart from the other 409s (a write-once conflict, a key mismatch).
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
    /// Short tag when `http_status == 0`; with a response, only
    /// [`REPORT_CLOSED_TAG`], else `None`.
    pub error_detail: Option<String>,
}

/// `error_detail` of a 409 whose body is exactly the relay's
/// `{"detail":"Report closed"}`: the report's signed closure does not cover
/// the name written. Any other 409 carries no tag.
pub const REPORT_CLOSED_TAG: &str = "report_closed";

/// Bytes of a 409 body read at most to recognise the closure refusal. The
/// refusal is far shorter; a longer body is not it.
pub(crate) const REFUSAL_BODY_CAP: usize = 256;

/// The tag a response carries besides its status: [`REPORT_CLOSED_TAG`] for a
/// 409 whose (start of) body is the relay's closure refusal, `None` for
/// anything else. `body_head` is at most [`REFUSAL_BODY_CAP`] bytes, so a body
/// cut there does not parse and carries no tag.
pub(crate) fn response_tag(http_status: u16, body_head: &[u8]) -> Option<String> {
    if http_status != 409 {
        return None;
    }
    let refusal: serde_json::Value = serde_json::from_slice(body_head).ok()?;
    (refusal == serde_json::json!({ "detail": "Report closed" }))
        .then(|| REPORT_CLOSED_TAG.to_owned())
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
/// own clone and finish normally; the next [`send_direct_tls`] rebuilds a
/// fresh client. Idempotent.
pub fn reset_upload_client() {
    *upload_client_guard() = None;
}

/// Send one relay write over the pinned `DirectTls` transport, the TCP leg of
/// [`crate::transport::send`]. The body is streamed from its file range and,
/// when the range carries an expected hash, re-hashed as it goes: the bytes
/// that would complete a body whose hash no longer matches are never sent, so
/// the relay sees a body shorter than its `Content-Length` and stores nothing.
///
/// Local problems are checked before any network activity and reported with
/// their own tags (`bad_url`, and the [`RangeFailure`] tags); a failure in the
/// middle of the body is reported by its local tag too. Every failure is a
/// [`PutResult`], none is raised.
pub fn send_direct_tls(request: &OutgoingRequest<'_>) -> PutResult {
    let started = Instant::now();
    let prepared = match Prepared::new(request) {
        Ok(prepared) => prepared,
        Err(tag) => return PutResult::failed(tag, started),
    };
    let Some(client) = upload_client() else {
        return PutResult::failed("client_build", started);
    };
    prepared.transmit(&client, request.headers, started)
}

/// [`send_direct_tls`] through an explicit client, for tests against a local
/// server with its own pin.
#[cfg(test)]
pub(crate) fn send_direct_tls_via(
    client: &reqwest::blocking::Client,
    request: &OutgoingRequest<'_>,
) -> PutResult {
    let started = Instant::now();
    match Prepared::new(request) {
        Ok(prepared) => prepared.transmit(client, request.headers, started),
        Err(tag) => PutResult::failed(tag, started),
    }
}

/// At most [`REFUSAL_BODY_CAP`] bytes of a response body; what could be read
/// if the read fails part way.
fn body_head(resp: reqwest::blocking::Response) -> Vec<u8> {
    use std::io::Read as _;
    let mut head = Vec::new();
    let cap = u64::try_from(REFUSAL_BODY_CAP).unwrap_or(u64::MAX);
    let _ = resp.take(cap).read_to_end(&mut head);
    head
}

/// A request whose local parts (URL, body file) were checked and opened.
struct Prepared {
    method: reqwest::Method,
    url: reqwest::Url,
    body: Option<FileRangeReader>,
}

impl Prepared {
    fn new(request: &OutgoingRequest<'_>) -> Result<Self, &'static str> {
        let url = reqwest::Url::parse(request.url).map_err(|_| "bad_url")?;
        let body = request
            .body
            .map(FileRange::open)
            .transpose()
            .map_err(RangeFailure::tag)?;
        let method = match request.method {
            Method::Put => reqwest::Method::PUT,
            Method::Post => reqwest::Method::POST,
        };
        Ok(Self { method, url, body })
    }

    fn transmit(
        self,
        client: &reqwest::blocking::Client,
        headers: &[(&str, &str)],
        started: Instant,
    ) -> PutResult {
        let mut builder = client.request(self.method, self.url);
        if self.body.is_some() {
            builder = builder.header("Content-Type", "application/octet-stream");
        }
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        let mut local_failure = None;
        if let Some(reader) = self.body {
            local_failure = Some(reader.failure_slot());
            let len = reader.remaining();
            builder = builder.body(reqwest::blocking::Body::sized(reader, len));
        }
        // `started` includes the file open and the client build/clone; the
        // send also folds in the TLS handshake on the first request of a
        // connection (pooled connections reuse it). `transfer_started`
        // excludes the local setup, so `transfer_ms` is the cleaner
        // link-throughput proxy.
        let transfer_started = Instant::now();
        let sent = builder.send();
        // A body that failed locally takes precedence: the relay cannot have
        // accepted a body that never arrived whole.
        if let Some(failure) = local_failure.and_then(|slot| slot.get().copied()) {
            return PutResult::failed(failure.tag(), started);
        }
        match sent {
            Ok(resp) => {
                let http_status = resp.status().as_u16();
                let transfer_ms = elapsed_ms(transfer_started);
                let error_detail = if http_status == 409 {
                    response_tag(http_status, &body_head(resp))
                } else {
                    None
                };
                PutResult {
                    http_status,
                    upload_ms: elapsed_ms(started),
                    transfer_ms,
                    error_detail,
                }
            }
            Err(e) => {
                let tag = if e.is_timeout() { "timeout" } else { "network" };
                PutResult::failed(tag, started)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_relay::{self, Reply};
    use std::path::PathBuf;

    fn client_for(relay: &test_relay::TestRelay) -> reqwest::blocking::Client {
        reqwest::blocking::Client::builder()
            .use_preconfigured_tls(relay.client_tls())
            .timeout(Duration::from_secs(20))
            .build()
            .unwrap()
    }

    fn scratch(name: &str, bytes: &[u8]) -> PathBuf {
        let path = std::env::temp_dir().join(format!("frap_upload_{}_{name}", std::process::id()));
        std::fs::write(&path, bytes).unwrap();
        path
    }

    fn sha256(bytes: &[u8]) -> [u8; 32] {
        use sha2::Digest as _;
        sha2::Sha256::digest(bytes).into()
    }

    fn put<'a>(url: &'a str, body: Option<&'a FileRange>) -> OutgoingRequest<'a> {
        OutgoingRequest {
            method: Method::Put,
            url,
            headers: &[],
            body,
        }
    }

    #[test]
    fn a_body_range_is_sent_with_its_method_and_headers() {
        let relay = test_relay::spawn(|request| {
            Reply::status(if request.method == "POST" { 204 } else { 201 })
        });
        let client = client_for(&relay);
        let data: Vec<u8> = (0u8..=255).cycle().take(100_000).collect();
        let path = scratch("range", &data);
        let range = FileRange::new(&path, 10, 50_000, Some(sha256(&data[10..50_010])));
        let url = format!("{}/close/abc", relay.base_url());
        let result = send_direct_tls_via(
            &client,
            &OutgoingRequest {
                method: Method::Post,
                url: &url,
                headers: &[("X-Report-Close-Seq-Limit", "4")],
                body: Some(&range),
            },
        );
        assert_eq!(result.http_status, 204, "{:?}", result.error_detail);
        let received = relay.requests();
        assert_eq!(received.len(), 1);
        assert_eq!(received[0].method, "POST");
        assert_eq!(received[0].path, "/close/abc");
        assert_eq!(received[0].header("x-report-close-seq-limit"), Some("4"));
        assert_eq!(
            received[0].header("content-type"),
            Some("application/octet-stream")
        );
        assert_eq!(received[0].body, &data[10..50_010]);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_body_that_no_longer_matches_never_arrives_whole() {
        let relay = test_relay::spawn(|_| Reply::status(204));
        let client = client_for(&relay);
        let data = vec![9u8; 300_000];
        let path = scratch("mismatch", &data);
        let range = FileRange::new(&path, 0, 300_000, Some([0u8; 32]));
        let url = format!("{}/file/r/x", relay.base_url());
        let result = send_direct_tls_via(&client, &put(&url, Some(&range)));
        assert_eq!(result.http_status, 0);
        assert_eq!(result.error_detail.as_deref(), Some("body_mismatch"));
        for request in relay.requests() {
            assert!(!request.complete, "the relay must never get the whole body");
            assert!(request.body.len() < data.len());
        }
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn local_problems_fail_before_the_network() {
        let relay = test_relay::spawn(|_| Reply::status(204));
        let client = client_for(&relay);
        let url = format!("{}/file/r/x", relay.base_url());
        let missing = FileRange::new("/no/such/frap/blob", 0, 1, None);
        let result = send_direct_tls_via(&client, &put(&url, Some(&missing)));
        assert_eq!(result.error_detail.as_deref(), Some("file_missing"));

        let path = scratch("short", b"abc");
        let short = FileRange::new(&path, 0, 10, None);
        let result = send_direct_tls_via(&client, &put(&url, Some(&short)));
        assert_eq!(result.error_detail.as_deref(), Some("body_short"));

        let result = send_direct_tls_via(&client, &put("not a url", None));
        assert_eq!(result.error_detail.as_deref(), Some("bad_url"));
        assert!(relay.requests().is_empty(), "nothing reached the relay");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn statuses_pass_through_and_a_dead_port_is_a_network_failure() {
        let relay = test_relay::spawn(|_| Reply::status(429));
        let client = client_for(&relay);
        let url = format!("{}/file/r/x", relay.base_url());
        let path = scratch("status", b"payload");
        let body = FileRange::new(&path, 0, 7, None);
        let result = send_direct_tls_via(&client, &put(&url, Some(&body)));
        assert_eq!(result.http_status, 429);
        assert!(result.error_detail.is_none());

        // Bind a port, then release it: nothing listens there any more.
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let dead = format!("https://127.0.0.1:{port}/file/r/x");
        let result = send_direct_tls_via(&client, &put(&dead, Some(&body)));
        assert_eq!(result.http_status, 0);
        assert_eq!(result.error_detail.as_deref(), Some("network"));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn only_the_closure_refusal_is_tagged_report_closed() {
        let relay = test_relay::spawn(|request| match request.path.as_str() {
            "/file/r/closed" => Reply::with_body(409, br#"{"detail":"Report closed"}"#),
            "/file/r/conflict" => Reply::with_body(
                409,
                br#"{"detail":"Chunk already stored with different content"}"#,
            ),
            "/file/r/other" => Reply::with_body(400, br#"{"detail":"Report closed"}"#),
            _ => Reply::status(409),
        });
        let client = client_for(&relay);
        let path = scratch("refusal", b"payload");
        let body = FileRange::new(&path, 0, 7, None);
        for (name, status, tag) in [
            ("closed", 409, Some(REPORT_CLOSED_TAG)),
            ("conflict", 409, None),
            ("other", 400, None),
            ("empty", 409, None),
        ] {
            let url = format!("{}/file/r/{name}", relay.base_url());
            let result = send_direct_tls_via(&client, &put(&url, Some(&body)));
            assert_eq!(result.http_status, status, "{name}");
            assert_eq!(result.error_detail.as_deref(), tag, "{name}");
        }
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn the_refusal_must_be_exactly_the_relays() {
        let closed = br#"{"detail":"Report closed"}"#;
        assert_eq!(
            response_tag(409, closed).as_deref(),
            Some(REPORT_CLOSED_TAG)
        );
        assert_eq!(
            response_tag(409, br#"{ "detail" : "Report closed" }"#).as_deref(),
            Some(REPORT_CLOSED_TAG)
        );
        assert!(response_tag(204, closed).is_none());
        assert!(response_tag(409, br#"{"detail":"Report closed","x":1}"#).is_none());
        assert!(response_tag(409, br#"{"detail":"report closed"}"#).is_none());
        assert!(response_tag(409, &closed[..closed.len() - 1]).is_none());
        assert!(response_tag(409, b"").is_none());
    }
}
