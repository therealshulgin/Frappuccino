//! V2 relay protocol — Rust port of `StreamServerClient.kt`.
//!
//! Blocking HTTP client (tokio-less at the caller's level — reqwest still uses
//! an internal tokio runtime, but consumers see a synchronous API). All
//! network calls go through a [`PinnedCertVerifier`][crate::pin::PinnedCertVerifier]
//! so MITM requires breaking ECDSA P-256 for the pinned SPKI.
//!
//! Endpoint contract:
//! * `POST /auth/v2/enroll`           → 200 / 409 / Failed
//! * `POST /auth/challenge`           → `ChallengeValue { nonce, timestamp }`
//! * `POST /auth/v2/verify`           → `Option<Bearer <jwt>>`
//! * `POST /auth/v2/rotate-batch`     → bool
//!
//! Post-S9-pre-audit: every challenge carries a server-emitted Unix timestamp
//! and the client signs `nonce ‖ timestamp_BE_u64` rather than the raw nonce.
//! The server enforces `abs(now - ts) ≤ 30 s` on `/auth/v2/verify`, closing
//! the replay window that was previously only bounded by the 60 s nonce TTL.
//!
//! Timeouts match Kotlin exactly: connect 10 s, read 15 s.

use crate::pin::PinnedCertVerifier;
use frappuccino_crypto_core::identity::StreamIdentity;
use frappuccino_crypto_core::ratchet::{RatchetSignature, RotationProof, BATCH_SIZE};
use rustls::crypto::ring::default_provider;
use rustls::ClientConfig;
use serde::{Deserialize, Serialize};
use std::io::Read;
use std::sync::Arc;
use std::time::Duration;

/// Errors bubbling up from a [`StreamServerClient`] call.
#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    /// Network / HTTP layer failure (DNS, connect, TLS, timeout, malformed
    /// response framing, …).
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    /// JSON decode failure of a response the server sent.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    /// rustls configuration rejected our custom verifier / provider.
    #[error("TLS config error: {0}")]
    Tls(String),
    /// Server returned success but the payload was incoherent (missing field,
    /// unparseable hex, wrong length).
    #[error("invalid server response: {0}")]
    Invalid(String),
    /// I/O failure while streaming a response body into the caller's writer
    /// (mid-stream network read error, or the local sink rejecting the write).
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Outcome of an enrollment attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnrollResult {
    /// HTTP 200 — the identity was newly registered.
    Success,
    /// HTTP 409 — this `ed25519_pk` was already on record. Idempotent retries
    /// hit this path.
    AlreadyEnrolled,
    /// Any other status. `body` is the response body verbatim for logging —
    /// never logged automatically to avoid leaking server internals.
    Failed {
        /// HTTP status code.
        code: u16,
        /// Response body.
        body: String,
    },
}

/// Fresh challenge emitted by `/auth/challenge`. The caller MUST sign
/// `nonce ‖ timestamp_BE_u64` (40 bytes) — signing the raw nonce alone is
/// rejected by the server starting at S9-pre-audit.
///
/// `timestamp` is Unix seconds as seen by the server at the time the nonce
/// was minted. The server keeps a ±30 s tolerance window on verify so a
/// reasonable client clock skew (NTP drift, phone sleep) still authenticates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChallengeValue {
    /// 32-byte server-generated nonce.
    pub nonce: [u8; 32],
    /// Unix seconds when the server minted the nonce.
    pub timestamp: u64,
}

impl ChallengeValue {
    /// The 40-byte message the client must sign via the ratchet. Keeps the
    /// composition in one place so the client and the server can't drift.
    #[must_use]
    pub fn message_bytes(&self) -> [u8; 40] {
        let mut buf = [0u8; 40];
        buf[..32].copy_from_slice(&self.nonce);
        buf[32..].copy_from_slice(&self.timestamp.to_be_bytes());
        buf
    }
}

/// Blocking client for the V2 relay.
///
/// Cheap to clone once built — `reqwest::blocking::Client` internally shares a
/// connection pool via `Arc`.
#[derive(Debug, Clone)]
pub struct StreamServerClient {
    base_url: String,
    http: reqwest::blocking::Client,
}

impl StreamServerClient {
    /// Build a pinned client against `base_url`. Typical input:
    /// `"https://136.244.101.236:8443"`.
    ///
    /// # Errors
    /// Returns [`ProtocolError::Tls`] if the embedded cert / pin can't be
    /// parsed, or [`ProtocolError::Http`] if reqwest can't assemble the
    /// underlying TLS stack (missing crypto provider, etc.).
    pub fn new(base_url: impl Into<String>) -> Result<Self, ProtocolError> {
        let verifier = PinnedCertVerifier::new().map_err(|e| ProtocolError::Tls(e.to_string()))?;

        // Explicit ring provider — avoids relying on `install_default()` global
        // state which other crates may have poisoned.
        let config = ClientConfig::builder_with_provider(Arc::new(default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
            .map_err(|e| ProtocolError::Tls(format!("protocol version: {e}")))?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
            .with_no_client_auth();

        let http = reqwest::blocking::Client::builder()
            .use_preconfigured_tls(config)
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(15))
            .build()?;

        Ok(Self {
            base_url: base_url.into(),
            http,
        })
    }

    // =========================================================================
    // Enrollment
    // =========================================================================

    /// `POST /auth/v2/enroll` — register an identity with its `batch_0` keys.
    ///
    /// `batch0_signature` must be the Ed25519 signature of
    /// `concat(batch0_public_keys)` by the enrollment key owned by the caller.
    ///
    /// # Errors
    /// See [`ProtocolError`].
    pub fn enroll(
        &self,
        identity_pk_hex: &str,
        batch0_public_keys: &[[u8; 32]; BATCH_SIZE],
        batch0_signature: &[u8; 64],
    ) -> Result<EnrollResult, ProtocolError> {
        let body = EnrollBody {
            ed25519_pk: identity_pk_hex.to_string(),
            batch_0_public_keys: batch0_public_keys.iter().map(hex::encode).collect(),
            batch_0_signature: hex::encode(batch0_signature),
        };
        let resp = self
            .http
            .post(format!("{}/auth/v2/enroll", self.base_url))
            .json(&body)
            .send()?;
        let code = resp.status().as_u16();
        match code {
            200 => Ok(EnrollResult::Success),
            409 => Ok(EnrollResult::AlreadyEnrolled),
            _ => {
                let body_text = read_capped(resp, crate::header::MAX_CONTROL_BODY_BYTES)
                    .map(|b| String::from_utf8_lossy(&b).into_owned())
                    .unwrap_or_default();
                Ok(EnrollResult::Failed {
                    code,
                    body: body_text,
                })
            }
        }
    }

    // =========================================================================
    // Challenge + Verify (auth flow)
    // =========================================================================

    /// `POST /auth/challenge` — fetch a fresh 32-byte server nonce + the
    /// timestamp the server stamped it with.
    ///
    /// The client must sign `nonce ‖ timestamp_BE_u64` (see
    /// [`ChallengeValue::message_bytes`]). Signing the raw nonce is rejected
    /// by the server.
    ///
    /// # Errors
    /// [`ProtocolError::Http`] on network failure, [`ProtocolError::Invalid`]
    /// if the server's `nonce` is missing or isn't 64 hex chars, or the
    /// `timestamp` field is missing.
    pub fn challenge(&self) -> Result<ChallengeValue, ProtocolError> {
        let resp = self
            .http
            .post(format!("{}/auth/challenge", self.base_url))
            .header("Content-Type", "application/json")
            .body("")
            .send()?
            .error_for_status()?;
        let raw = read_capped(resp, crate::header::MAX_CONTROL_BODY_BYTES)?;
        let body: ChallengeResponse = serde_json::from_slice(&raw)?;
        let nonce_vec = hex::decode(&body.nonce)
            .map_err(|e| ProtocolError::Invalid(format!("challenge nonce hex: {e}")))?;
        let nonce: [u8; 32] = nonce_vec
            .try_into()
            .map_err(|v: Vec<u8>| ProtocolError::Invalid(format!("nonce length {}", v.len())))?;
        Ok(ChallengeValue {
            nonce,
            timestamp: body.timestamp,
        })
    }

    /// `POST /auth/v2/verify` — exchange a ratchet signature for a JWT bearer.
    ///
    /// `sig` must cover `nonce ‖ timestamp_BE_u64` (= [`ChallengeValue::message_bytes`]).
    /// `nonce_hex` and `timestamp` must be the ones returned by [`challenge`].
    ///
    /// Returns `Some("Bearer <jwt>")` on success, `None` if the server refused
    /// (bad signature, consumed slot, wrong batch, skew beyond ±30 s, etc.).
    ///
    /// # Errors
    /// Network / decode errors; a rejected signature is `Ok(None)`, *not* an
    /// error — mirrors the Kotlin client's `null`-on-non-2xx semantics.
    pub fn verify(
        &self,
        identity: &StreamIdentity,
        sig: &RatchetSignature,
        nonce_hex: &str,
        timestamp: u64,
    ) -> Result<Option<String>, ProtocolError> {
        let body = VerifyBody {
            ed25519_pk: hex::encode(identity.ed25519_pk()),
            ephemeral_pk: hex::encode(sig.ephemeral_public_key),
            batch_number: sig.batch_number,
            key_index: sig.key_index,
            nonce: nonce_hex.to_string(),
            timestamp,
            signature: hex::encode(sig.signature),
        };
        let resp = self
            .http
            .post(format!("{}/auth/v2/verify", self.base_url))
            .json(&body)
            .send()?;
        if !resp.status().is_success() {
            return Ok(None);
        }
        let raw = read_capped(resp, crate::header::MAX_CONTROL_BODY_BYTES)?;
        let json: VerifyResponse = serde_json::from_slice(&raw)?;
        if json.access_token.is_empty() {
            Ok(None)
        } else {
            Ok(Some(format!("Bearer {}", json.access_token)))
        }
    }

    // =========================================================================
    // Rotation
    // =========================================================================

    /// `POST /auth/v2/rotate-batch` — advance from `signer_batch_number` to
    /// `signer_batch_number + 1` using the 50 fresh keys in `proof`.
    ///
    /// Returns `true` iff the server accepted; `false` if it refused (which
    /// includes stale signer, mismatched batch, revoked identity).
    ///
    /// # Errors
    /// Only the network / TLS / framing kind — server refusals are `Ok(false)`.
    pub fn rotate_batch(
        &self,
        identity_pk_hex: &str,
        proof: &RotationProof,
    ) -> Result<bool, ProtocolError> {
        let body = RotateBody {
            ed25519_pk: identity_pk_hex.to_string(),
            signer_batch_number: proof.signer_batch_number,
            signer_key_index: proof.signer_key_index,
            signer_public_key: hex::encode(proof.signer_public_key),
            new_batch_public_keys: proof
                .new_batch_public_keys
                .iter()
                .map(hex::encode)
                .collect(),
            new_batch_signature: hex::encode(proof.signature),
        };
        let resp = self
            .http
            .post(format!("{}/auth/v2/rotate-batch", self.base_url))
            .json(&body)
            .send()?;
        Ok(resp.status().is_success())
    }

    // =========================================================================
    // Archive retrieval (Phase 4.4 — rescue device)
    // =========================================================================

    /// `GET /api/v2/archive/reports/{report_id}/blobs` — list every blob in a
    /// report. **Phase C relay-blind: NO auth** — the `report_id` (derived from
    /// the BIP-39 phrase) IS the capability, so reads carry no bearer and the
    /// relay never sees an identity.
    ///
    /// Returns `Ok(None)` on **404** — no record at this `report_id`, i.e. a
    /// *hole* in the rescue enumeration (an index allocated but never uploaded,
    /// or the end of the range). Returns `Ok(Some(blobs))` when the report
    /// exists. Network / 5xx / TLS surface as `Err` so the caller retries and
    /// NEVER mistakes a transient failure for a hole.
    pub fn archive_list_blobs(
        &self,
        report_id: &str,
    ) -> Result<Option<Vec<ArchiveBlobInfo>>, ProtocolError> {
        let resp = self
            .http
            .get(format!(
                "{}/api/v2/archive/reports/{report_id}/blobs",
                self.base_url
            ))
            .send()?;
        // 404 = record absent (a hole), distinct from a network/5xx failure.
        if resp.status().as_u16() == 404 {
            return Ok(None);
        }
        let resp = resp.error_for_status()?;
        let raw = read_capped(resp, crate::header::MAX_LISTING_BYTES)?;
        let body: ArchiveBlobsResponse = serde_json::from_slice(&raw)?;
        Ok(Some(body.blobs))
    }

    /// `GET /api/v2/archive/reports/{report_id}/{filename}` — fetch a single
    /// blob and stream it into [`writer`]. Doesn't load the whole body in RAM
    /// (uses [`reqwest::blocking::Response::copy_to`]). **Phase C relay-blind:
    /// NO auth.**
    ///
    /// Returns the number of bytes written.
    pub fn archive_download_blob<W: std::io::Write>(
        &self,
        report_id: &str,
        filename: &str,
        writer: &mut W,
    ) -> Result<u64, ProtocolError> {
        let resp = self
            .http
            .get(format!(
                "{}/api/v2/archive/reports/{report_id}/{filename}",
                self.base_url
            ))
            .send()?
            .error_for_status()?;
        // M-2 (WP-C): bound the copy. The relay is the adversary — a hostile
        // response body could be unbounded, and the FFI archive path buffers it
        // in RAM before decrypting (OOM) while the CLI streams it to disk
        // (disk-fill). `Read::take` reads at most cap+1 bytes; if we actually
        // copy more than the cap the relay over-served, so we reject. `resp`
        // implements `Read` (imported at module top); `take` consumes it.
        let cap = crate::header::MAX_ARCHIVE_BLOB_BYTES;
        let mut limited = resp.take(cap + 1);
        let copied = std::io::copy(&mut limited, writer)?; // io::Error -> ProtocolError::Io
        if copied > cap {
            return Err(ProtocolError::Invalid(format!(
                "archive blob exceeds MAX_ARCHIVE_BLOB_BYTES ({cap})"
            )));
        }
        Ok(copied)
    }
}

/// Read at most `cap` bytes of a **control / listing** response body into RAM,
/// rejecting an over-served body. Phase-C motto: the relay is the adversary — an
/// unbounded response body would OOM a low-end rescue device that buffers it in
/// RAM before serde parses it. Mirrors the `Read::take` bound
/// `archive_download_blob` already applies to the blob body: `take` reads at
/// most `cap + 1` so an over-serve is detectable. `resp` implements `Read`
/// (imported at the module top).
pub(crate) fn read_capped(
    resp: reqwest::blocking::Response,
    cap: u64,
) -> Result<Vec<u8>, ProtocolError> {
    read_capped_reader(resp, cap)
}

/// Generic core of [`read_capped`], testable without a live HTTP `Response`.
fn read_capped_reader<R: std::io::Read>(reader: R, cap: u64) -> Result<Vec<u8>, ProtocolError> {
    let mut buf = Vec::new();
    let mut limited = reader.take(cap + 1);
    limited.read_to_end(&mut buf)?; // io::Error -> ProtocolError::Io
    if buf.len() as u64 > cap {
        return Err(ProtocolError::Invalid(format!(
            "response body exceeds cap ({cap} bytes)"
        )));
    }
    Ok(buf)
}

// ============================================================================
// Wire types — Serialize only (we don't decode our own request bodies).
// Field order matches Kotlin's `JSONObject.put` order for byte-exact parity
// with `parity-vectors/protocol/*.json` under `serde_json`'s default
// struct-ordered emission.
// ============================================================================

#[derive(Debug, Serialize)]
struct EnrollBody {
    ed25519_pk: String,
    batch_0_public_keys: Vec<String>,
    batch_0_signature: String,
}

#[derive(Debug, Serialize)]
struct VerifyBody {
    ed25519_pk: String,
    ephemeral_pk: String,
    batch_number: u32,
    key_index: u32,
    nonce: String,
    timestamp: u64,
    signature: String,
}

#[derive(Debug, Serialize)]
struct RotateBody {
    ed25519_pk: String,
    signer_batch_number: u32,
    signer_key_index: u32,
    signer_public_key: String,
    new_batch_public_keys: Vec<String>,
    new_batch_signature: String,
}

#[derive(Debug, Deserialize)]
struct ChallengeResponse {
    nonce: String,
    timestamp: u64,
}

#[derive(Debug, Deserialize)]
struct VerifyResponse {
    #[serde(default)]
    access_token: String,
}

// ---- Phase 4.4 archive retrieval (Phase C relay-blind: identity-free) ------

/// Per-blob metadata returned by
/// `GET /api/v2/archive/reports/{report_id}/blobs`.
#[derive(Debug, Clone, Deserialize)]
pub struct ArchiveBlobInfo {
    pub filename: String,
    #[serde(default)]
    pub size: u64,
    #[serde(default)]
    pub last_modified: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ArchiveBlobsResponse {
    blobs: Vec<ArchiveBlobInfo>,
}

// ============================================================================
// Unit tests — byte-exact parity of request bodies against captured fixtures.
// E2E tests live in `tests/e2e_protocol.rs` and are `#[ignore]`d by default.
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_capped_bounds_a_hostile_body() {
        // #6 (M-2 / WP-C): a control/listing body over the cap is rejected, not
        // buffered unbounded (OOM on the rescue device). Reads at most cap+1.
        assert_eq!(read_capped_reader(&b"hello"[..], 16).unwrap(), b"hello");
        // Exactly at the cap is accepted (boundary).
        assert_eq!(read_capped_reader(&b"hello"[..], 5).unwrap(), b"hello");
        // One byte over the cap is rejected.
        let err = read_capped_reader(&b"hello world"[..], 5).unwrap_err();
        assert!(matches!(err, ProtocolError::Invalid(_)));
        // A large hostile body is bounded: we never materialize more than cap+1.
        let big = vec![0u8; 10 * 1024 * 1024];
        let err = read_capped_reader(&big[..], 64 * 1024).unwrap_err();
        assert!(matches!(err, ProtocolError::Invalid(_)));
    }

    #[test]
    fn enroll_body_matches_kotlin_fixture() {
        // Fixture: crypto-rs/parity-vectors/protocol/enroll_req.json
        let identity_hex = "f373b6de310a66e4b4f0e1ab355c89446762b59b47895d2d42ecfa5ed8d36920";
        let batch_keys_hex = [
            "7e8650d32c0d2797e22f8070711abdc6ddeb4e98ea1e0848f250ba845f3a17f5",
            "17e0116700e346955a96e84617c70662ecef062105d427c6ebff6f319636430a",
        ];
        let mut keys = [[0u8; 32]; BATCH_SIZE];
        keys[0].copy_from_slice(&hex::decode(batch_keys_hex[0]).unwrap());
        keys[1].copy_from_slice(&hex::decode(batch_keys_hex[1]).unwrap());
        // Slots 2..50 remain zero for this shape-only test.
        let sig = [0u8; 64];

        let body = EnrollBody {
            ed25519_pk: identity_hex.to_string(),
            batch_0_public_keys: keys.iter().map(hex::encode).collect(),
            batch_0_signature: hex::encode(sig),
        };
        let json = serde_json::to_string(&body).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["ed25519_pk"], identity_hex);
        assert_eq!(parsed["batch_0_public_keys"][0], batch_keys_hex[0]);
        assert_eq!(parsed["batch_0_public_keys"][1], batch_keys_hex[1]);
        assert_eq!(parsed["batch_0_signature"], hex::encode([0u8; 64]));
        // 50 entries total, even zeroed tail slots included.
        assert_eq!(parsed["batch_0_public_keys"].as_array().unwrap().len(), 50);
    }

    #[test]
    fn verify_body_shape_matches_fixture() {
        // Shape-only test post-S9: the Kotlin fixture verify_req.json predates
        // the timestamp field, so we no longer byte-compare — we just make
        // sure every expected field is present on the wire.
        let body = VerifyBody {
            ed25519_pk: "f373b6de310a66e4b4f0e1ab355c89446762b59b47895d2d42ecfa5ed8d36920".into(),
            ephemeral_pk: "7e8650d32c0d2797e22f8070711abdc6ddeb4e98ea1e0848f250ba845f3a17f5"
                .into(),
            batch_number: 0,
            key_index: 0,
            nonce: "0".repeat(64),
            timestamp: 1_744_567_890,
            signature: "d3e87bfdaf807a39e7f3d824b76d38589899a73ccc50adf73884c535cfc626aee22f8cc31fa1032e3d7733c8aa20fe9cf96db1f292b86512280b8d7cebf0f207".into(),
        };
        let json = serde_json::to_value(&body).unwrap();
        for key in [
            "ed25519_pk",
            "ephemeral_pk",
            "batch_number",
            "key_index",
            "nonce",
            "timestamp",
            "signature",
        ] {
            assert!(json.get(key).is_some(), "missing field {key}");
        }
        assert_eq!(json["batch_number"], 0);
        assert_eq!(json["key_index"], 0);
        assert_eq!(json["timestamp"], 1_744_567_890u64);
    }

    #[test]
    fn challenge_value_message_bytes_is_nonce_concat_ts_be() {
        let nonce = [0x11u8; 32];
        let ts: u64 = 0x0102_0304_0506_0708;
        let cv = ChallengeValue {
            nonce,
            timestamp: ts,
        };
        let bytes = cv.message_bytes();
        assert_eq!(&bytes[..32], &nonce);
        assert_eq!(&bytes[32..], &ts.to_be_bytes());
    }

    #[test]
    fn rotate_body_shape_matches_fixture() {
        // Fixture: crypto-rs/parity-vectors/protocol/rotate_req.json
        let keys: Vec<String> = (0..BATCH_SIZE)
            .map(|i| hex::encode([u8::try_from(i).unwrap_or(0); 32]))
            .collect();
        let body = RotateBody {
            ed25519_pk: "f373b6de310a66e4b4f0e1ab355c89446762b59b47895d2d42ecfa5ed8d36920".into(),
            signer_batch_number: 0,
            signer_key_index: 1,
            signer_public_key: "17e0116700e346955a96e84617c70662ecef062105d427c6ebff6f319636430a"
                .into(),
            new_batch_public_keys: keys,
            new_batch_signature: hex::encode([0u8; 64]),
        };
        let json = serde_json::to_value(&body).unwrap();
        for key in [
            "ed25519_pk",
            "signer_batch_number",
            "signer_key_index",
            "signer_public_key",
            "new_batch_public_keys",
            "new_batch_signature",
        ] {
            assert!(json.get(key).is_some(), "missing field {key}");
        }
        assert_eq!(json["new_batch_public_keys"].as_array().unwrap().len(), 50);
    }

    #[test]
    fn challenge_response_deserializes() {
        let raw = r#"{"nonce":"deadbeef","timestamp":1744567890}"#;
        let parsed: ChallengeResponse = serde_json::from_str(raw).unwrap();
        assert_eq!(parsed.nonce, "deadbeef");
        assert_eq!(parsed.timestamp, 1_744_567_890);
    }

    #[test]
    fn verify_response_missing_token_defaults_empty() {
        let raw = "{}";
        let parsed: VerifyResponse = serde_json::from_str(raw).unwrap();
        assert!(parsed.access_token.is_empty());
    }

    // ---- Phase 4.4 archive shapes (Phase C relay-blind: id-free reads) ------

    #[test]
    fn archive_blobs_response_deserializes() {
        let raw = r#"{
            "blobs": [
                {"filename": "chunk_1.strm", "size": 2048, "last_modified": "2026-05-10T10:00:00"},
                {"filename": "chunk_2.strm", "size": 4096, "last_modified": null}
            ]
        }"#;
        let parsed: ArchiveBlobsResponse = serde_json::from_str(raw).unwrap();
        assert_eq!(parsed.blobs.len(), 2);
        assert_eq!(parsed.blobs[0].filename, "chunk_1.strm");
        assert_eq!(parsed.blobs[0].size, 2048);
        assert!(parsed.blobs[1].last_modified.is_none());
    }
}
