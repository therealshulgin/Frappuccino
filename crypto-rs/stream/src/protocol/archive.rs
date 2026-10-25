//! Archive reads for the rescue: a report's listing with its recorded closure,
//! and one stored object fetched to disk with its stored write signature.
//!
//! The relay is untrusted here. What it serves is input to the rescue's own
//! verification (under the report key the rescue re-derives from the phrase),
//! never a verdict, so this module only enforces shape: a closure that is not
//! exactly `{seq_limit, manifest_sha256, sig}` with canonical values is
//! refused, a signature header that is not 128 lowercase hex characters is
//! reported as malformed, and bodies are bounded.
//!
//! The relay answers 429 when its per-address limit is reached and sends no
//! `Retry-After`; [`ProtocolError::RateLimited`] carries the wait to apply,
//! at least [`RATE_LIMIT_MIN_BACKOFF`].

use super::{read_capped, ArchiveBlobInfo, ProtocolError, StreamServerClient};
use crate::durable::{write_durably, OnDirSyncError};
use crate::header::{MAX_ARCHIVE_BLOB_BYTES, MAX_LISTING_BYTES};
use crate::pathsafe::is_relay_object_name;
use frappuccino_crypto_core::report::MAX_SEQ_LIMIT;
use reqwest::header::{HeaderMap, RETRY_AFTER};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::cell::Cell;
use std::io::{Read, Write};
use std::path::Path;
use std::time::Duration;

/// Shortest wait after a 429.
pub const RATE_LIMIT_MIN_BACKOFF: Duration = Duration::from_secs(60);
/// Longest wait a `Retry-After` header can impose.
const RATE_LIMIT_MAX_BACKOFF: Duration = Duration::from_secs(3600);
/// Whole-request ceiling for one object fetch. The client's default 15 s
/// covers control calls; an object of up to [`MAX_ARCHIVE_BLOB_BYTES`] needs
/// longer on a slow link.
pub const OBJECT_FETCH_TIMEOUT: Duration = Duration::from_secs(300);
/// Header carrying an object's stored 0x08 write signature.
const WRITE_SIG_HEADER: &str = "x-report-write-sig";

// ============================================================================
// Types
// ============================================================================

/// A report's listing: its stored objects and its closure, if recorded.
#[derive(Debug, Clone)]
pub struct ArchiveListing {
    /// Every stored object, `manifest` included once the report is closed.
    pub blobs: Vec<ArchiveBlobInfo>,
    /// The recorded closure, or `None` while the report is open (or on a relay
    /// that predates closures).
    pub closure: Option<ArchiveClosure>,
}

/// A closure as the relay recorded it. Well-formed, not verified: the rescue
/// checks `sig` under the report key it derives itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveClosure {
    seq_limit: u32,
    manifest_sha256: [u8; 32],
    sig: [u8; 64],
}

impl ArchiveClosure {
    /// The closure's `seq_limit`.
    #[must_use]
    pub fn seq_limit(&self) -> u32 {
        self.seq_limit
    }

    /// SHA-256 of the manifest the closure was recorded with.
    #[must_use]
    pub fn manifest_sha256(&self) -> &[u8; 32] {
        &self.manifest_sha256
    }

    /// The 0x09 close signature.
    #[must_use]
    pub fn sig(&self) -> &[u8; 64] {
        &self.sig
    }

    /// True when `manifest` is the manifest this closure was recorded with.
    #[must_use]
    pub fn matches_manifest(&self, manifest: &[u8]) -> bool {
        let digest: [u8; 32] = Sha256::digest(manifest).into();
        digest == self.manifest_sha256
    }
}

/// The `X-Report-Write-Sig` header of a fetched object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteSigHeader {
    /// No header: an object stored before the relay kept signatures, or the
    /// manifest.
    Absent,
    /// One well-formed signature.
    Present([u8; 64]),
    /// A header that is not exactly one value of 128 lowercase hex
    /// characters; the rescue treats it as an invalid signature.
    Malformed,
}

/// Result of [`StreamServerClient::archive_fetch_object`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArchiveObject {
    /// The relay has no such object (or no such report).
    NotFound,
    /// The object was written to the requested path.
    Stored(StoredObject),
}

/// An object written to disk by [`StreamServerClient::archive_fetch_object`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredObject {
    size: u64,
    blob_sha256: [u8; 32],
    write_sig: WriteSigHeader,
}

impl StoredObject {
    /// Bytes written.
    #[must_use]
    pub fn size(&self) -> u64 {
        self.size
    }

    /// SHA-256 of the bytes written, the value a manifest entry or a write
    /// signature covers.
    #[must_use]
    pub fn blob_sha256(&self) -> &[u8; 32] {
        &self.blob_sha256
    }

    /// The write-signature header, read before the body.
    #[must_use]
    pub fn write_sig(&self) -> WriteSigHeader {
        self.write_sig
    }
}

// ============================================================================
// Client calls
// ============================================================================

impl StreamServerClient {
    /// `GET /api/v2/archive/reports/{report_id}/blobs` — the report's objects
    /// and its closure. No authentication: the `report_id`, derived from the
    /// phrase, is the read capability.
    ///
    /// Returns `Ok(None)` on 404 (no record at this id: a hole in the rescue's
    /// enumeration). Network failures, 5xx and malformed listings are errors,
    /// so a transient failure is never mistaken for a hole.
    ///
    /// # Errors
    /// [`ProtocolError::Invalid`] for a `report_id` that is not 32 lowercase
    /// hex characters, or a listing that is malformed, has a malformed
    /// closure or exceeds [`MAX_LISTING_BYTES`]; [`ProtocolError::RateLimited`]
    /// on 429; [`ProtocolError::Http`] for any other failure status or a
    /// network error; [`ProtocolError::Io`] for a body cut while being read.
    pub fn archive_list(&self, report_id: &str) -> Result<Option<ArchiveListing>, ProtocolError> {
        check_report_id(report_id)?;
        let resp = self
            .http
            .get(format!(
                "{}/api/v2/archive/reports/{report_id}/blobs",
                self.base_url
            ))
            .send()?;
        match resp.status().as_u16() {
            404 => return Ok(None),
            429 => return Err(rate_limited(resp.headers())),
            _ => {}
        }
        let raw = read_capped(resp.error_for_status()?, MAX_LISTING_BYTES)?;
        parse_listing(&raw).map(Some)
    }

    /// `GET /api/v2/archive/reports/{report_id}/{filename}` — fetch one stored
    /// object (encrypted, as stored) to `out_path`, never into the caller's
    /// memory. The `X-Report-Write-Sig` header is read before the body. The
    /// file is written durably (see [`crate::durable`]) and hashed as it is
    /// written; nothing is left at `out_path` on error.
    ///
    /// # Errors
    /// [`ProtocolError::Invalid`] for an id or name that is not a relay object
    /// address, or a body larger than [`MAX_ARCHIVE_BLOB_BYTES`];
    /// [`ProtocolError::RateLimited`] on 429; [`ProtocolError::Http`] for any
    /// other failure status or a network error; [`ProtocolError::Io`] for a
    /// failure while streaming or writing.
    pub fn archive_fetch_object(
        &self,
        report_id: &str,
        filename: &str,
        out_path: &Path,
    ) -> Result<ArchiveObject, ProtocolError> {
        check_report_id(report_id)?;
        if !is_relay_object_name(filename) {
            return Err(ProtocolError::Invalid(
                "object name is not a relay object name".into(),
            ));
        }
        let resp = self
            .http
            .get(format!(
                "{}/api/v2/archive/reports/{report_id}/{filename}",
                self.base_url
            ))
            .timeout(OBJECT_FETCH_TIMEOUT)
            .send()?;
        match resp.status().as_u16() {
            404 => return Ok(ArchiveObject::NotFound),
            429 => return Err(rate_limited(resp.headers())),
            _ => {}
        }
        let resp = resp.error_for_status()?;
        let write_sig = parse_write_sig(resp.headers());
        let (size, blob_sha256) = download_to(out_path, resp, MAX_ARCHIVE_BLOB_BYTES)?;
        Ok(ArchiveObject::Stored(StoredObject {
            size,
            blob_sha256,
            write_sig,
        }))
    }
}

// ============================================================================
// Shape checks and helpers (no network)
// ============================================================================

#[derive(Debug, Deserialize)]
struct ListingWire {
    blobs: Vec<ArchiveBlobInfo>,
    #[serde(default)]
    closure: Option<ClosureWire>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ClosureWire {
    seq_limit: u32,
    manifest_sha256: String,
    sig: String,
}

/// Parse a listing body. A missing or `null` closure means none; a present
/// one must be exactly well-formed.
///
/// A body that is not a listing is [`ProtocolError::Invalid`], like one over
/// the size cap: a shape error of what the relay served, which a caller must
/// be able to tell apart from a failure to reach it.
pub(crate) fn parse_listing(raw: &[u8]) -> Result<ArchiveListing, ProtocolError> {
    let wire: ListingWire = serde_json::from_slice(raw)
        .map_err(|error| ProtocolError::Invalid(format!("malformed listing: {error}")))?;
    let closure = wire.closure.as_ref().map(closure_from_wire).transpose()?;
    Ok(ArchiveListing {
        blobs: wire.blobs,
        closure,
    })
}

fn closure_from_wire(wire: &ClosureWire) -> Result<ArchiveClosure, ProtocolError> {
    if wire.seq_limit > MAX_SEQ_LIMIT {
        return Err(ProtocolError::Invalid(
            "closure seq_limit exceeds the sequence space".into(),
        ));
    }
    let manifest_sha256 = lower_hex::<32>(&wire.manifest_sha256).ok_or_else(|| {
        ProtocolError::Invalid("closure manifest_sha256 is not 64 lowercase hex".into())
    })?;
    let sig = lower_hex::<64>(&wire.sig)
        .ok_or_else(|| ProtocolError::Invalid("closure sig is not 128 lowercase hex".into()))?;
    Ok(ArchiveClosure {
        seq_limit: wire.seq_limit,
        manifest_sha256,
        sig,
    })
}

/// Exactly `2 × N` lowercase hex characters, decoded.
fn lower_hex<const N: usize>(text: &str) -> Option<[u8; N]> {
    let canonical = text.len() == 2 * N
        && text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
    if !canonical {
        return None;
    }
    let mut out = [0u8; N];
    hex::decode_to_slice(text, &mut out).ok()?;
    Some(out)
}

/// A `report_id` as the relay addresses it: 32 lowercase hex characters.
fn check_report_id(report_id: &str) -> Result<(), ProtocolError> {
    lower_hex::<16>(report_id)
        .map(|_| ())
        .ok_or_else(|| ProtocolError::Invalid("report_id is not 32 lowercase hex".into()))
}

pub(crate) fn parse_write_sig(headers: &HeaderMap) -> WriteSigHeader {
    let mut values = headers.get_all(WRITE_SIG_HEADER).iter();
    let Some(first) = values.next() else {
        return WriteSigHeader::Absent;
    };
    if values.next().is_some() {
        return WriteSigHeader::Malformed;
    }
    first
        .to_str()
        .ok()
        .and_then(lower_hex::<64>)
        .map_or(WriteSigHeader::Malformed, WriteSigHeader::Present)
}

/// The error for a 429, with the wait to apply: a `Retry-After` in seconds
/// if the relay ever sends one, clamped to `[60 s, 1 h]`, else 60 s.
pub(crate) fn rate_limited(headers: &HeaderMap) -> ProtocolError {
    let requested = headers
        .get(RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .filter(|text| {
            !text.is_empty() && text.len() <= 6 && text.bytes().all(|b| b.is_ascii_digit())
        })
        .and_then(|text| text.parse::<u64>().ok())
        .map(Duration::from_secs);
    let retry_after = requested
        .unwrap_or(RATE_LIMIT_MIN_BACKOFF)
        .clamp(RATE_LIMIT_MIN_BACKOFF, RATE_LIMIT_MAX_BACKOFF);
    ProtocolError::RateLimited { retry_after }
}

/// Write at most `cap` bytes of `body` durably to `out_path`, hashing them.
/// A body longer than `cap` is refused and nothing is left behind.
pub(crate) fn download_to(
    out_path: &Path,
    body: impl Read,
    cap: u64,
) -> Result<(u64, [u8; 32]), ProtocolError> {
    let over_cap = Cell::new(false);
    let mut written = 0u64;
    let mut hasher = Sha256::new();
    let outcome = write_durably(out_path, OnDirSyncError::RemoveDestination, |file| {
        let mut limited = body.take(cap.saturating_add(1));
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let read = match limited.read(&mut buf) {
                Ok(0) => break,
                Ok(read) => read,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            };
            let chunk = buf.get(..read).unwrap_or_default();
            written = written.saturating_add(u64::try_from(read).unwrap_or(u64::MAX));
            if written > cap {
                over_cap.set(true);
                return Err(std::io::Error::other("object exceeds the size cap"));
            }
            hasher.update(chunk);
            file.write_all(chunk)?;
        }
        Ok(())
    });
    match outcome {
        Ok(()) => Ok((written, hasher.finalize().into())),
        Err(_) if over_cap.get() => Err(ProtocolError::Invalid(format!(
            "archive object exceeds MAX_ARCHIVE_BLOB_BYTES ({cap})"
        ))),
        Err(error) => Err(ProtocolError::Io(error)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_relay::{self, Reply};
    use reqwest::header::HeaderValue;

    const RID: &str = "0123456789abcdef0123456789abcdef";

    fn sig_hex() -> String {
        "ab".repeat(64)
    }

    #[test]
    fn listings_parse_with_and_without_closure() {
        let open = parse_listing(br#"{"blobs":[{"filename":"000000.strm","size":3,"last_modified":null}],"closure":null}"#).unwrap();
        assert_eq!(open.blobs.len(), 1);
        assert!(open.closure.is_none());

        let legacy_relay = parse_listing(br#"{"blobs":[]}"#).unwrap();
        assert!(legacy_relay.closure.is_none());

        let body = format!(
            r#"{{"blobs":[],"closure":{{"seq_limit":4,"manifest_sha256":"{}","sig":"{}"}}}}"#,
            "0f".repeat(32),
            sig_hex()
        );
        let closed = parse_listing(body.as_bytes()).unwrap();
        let closure = closed.closure.unwrap();
        assert_eq!(closure.seq_limit(), 4);
        assert_eq!(closure.manifest_sha256(), &[0x0f; 32]);
        assert_eq!(closure.sig(), &[0xab; 64]);
    }

    #[test]
    fn malformed_closures_are_refused() {
        let good_hash = "0f".repeat(32);
        let good_sig = sig_hex();
        let cases = [
            format!(
                r#"{{"seq_limit":1000001,"manifest_sha256":"{good_hash}","sig":"{good_sig}"}}"#
            ),
            format!(r#"{{"seq_limit":-1,"manifest_sha256":"{good_hash}","sig":"{good_sig}"}}"#),
            format!(r#"{{"seq_limit":1.5,"manifest_sha256":"{good_hash}","sig":"{good_sig}"}}"#),
            format!(r#"{{"seq_limit":"4","manifest_sha256":"{good_hash}","sig":"{good_sig}"}}"#),
            format!(
                r#"{{"seq_limit":4,"manifest_sha256":"{}","sig":"{good_sig}"}}"#,
                "0F".repeat(32)
            ),
            format!(
                r#"{{"seq_limit":4,"manifest_sha256":"{}","sig":"{good_sig}"}}"#,
                "0f".repeat(31)
            ),
            format!(
                r#"{{"seq_limit":4,"manifest_sha256":"{good_hash}","sig":"{}"}}"#,
                "ab".repeat(63)
            ),
            format!(
                r#"{{"seq_limit":4,"manifest_sha256":"{good_hash}","sig":"{}"}}"#,
                "zz".repeat(64)
            ),
            format!(r#"{{"seq_limit":4,"manifest_sha256":"{good_hash}"}}"#),
            format!(
                r#"{{"seq_limit":4,"manifest_sha256":"{good_hash}","sig":"{good_sig}","extra":1}}"#
            ),
            "{}".to_owned(),
            "[]".to_owned(),
        ];
        for closure in cases {
            let body = format!(r#"{{"blobs":[],"closure":{closure}}}"#);
            assert!(
                parse_listing(body.as_bytes()).is_err(),
                "accepted {closure}"
            );
        }
        assert!(matches!(
            parse_listing(b"not json").unwrap_err(),
            ProtocolError::Invalid(_)
        ));
        assert!(
            parse_listing(br#"{"closure":null}"#).is_err(),
            "blobs is required"
        );
    }

    #[test]
    fn a_legacy_closure_is_well_formed() {
        let body = format!(
            r#"{{"blobs":[],"closure":{{"seq_limit":0,"manifest_sha256":"{}","sig":"{}"}}}}"#,
            "00".repeat(32),
            sig_hex()
        );
        let closure = parse_listing(body.as_bytes()).unwrap().closure.unwrap();
        assert_eq!(closure.seq_limit(), 0);
        let manifest = b"FQM1\0\0\0\0";
        let real = ArchiveClosure {
            manifest_sha256: Sha256::digest(manifest).into(),
            ..closure
        };
        assert!(real.matches_manifest(manifest));
        assert!(!real.matches_manifest(b"FQM1\0\0\0\x01"));
    }

    #[test]
    fn write_sig_headers_are_read_strictly() {
        let mut headers = HeaderMap::new();
        assert_eq!(parse_write_sig(&headers), WriteSigHeader::Absent);
        headers.insert(WRITE_SIG_HEADER, HeaderValue::from_str(&sig_hex()).unwrap());
        assert_eq!(
            parse_write_sig(&headers),
            WriteSigHeader::Present([0xab; 64])
        );
        headers.append(WRITE_SIG_HEADER, HeaderValue::from_str(&sig_hex()).unwrap());
        assert_eq!(parse_write_sig(&headers), WriteSigHeader::Malformed);
        for bad in [
            "AB".repeat(64),
            "ab".repeat(63),
            String::new(),
            "ab".repeat(65),
        ] {
            let mut headers = HeaderMap::new();
            headers.insert(WRITE_SIG_HEADER, HeaderValue::from_str(&bad).unwrap());
            assert_eq!(
                parse_write_sig(&headers),
                WriteSigHeader::Malformed,
                "{bad}"
            );
        }
    }

    #[test]
    fn a_429_waits_at_least_a_minute() {
        let wait = |headers: &HeaderMap| match rate_limited(headers) {
            ProtocolError::RateLimited { retry_after } => retry_after,
            other => panic!("{other:?}"),
        };
        let mut headers = HeaderMap::new();
        assert_eq!(wait(&headers), Duration::from_secs(60));
        headers.insert(RETRY_AFTER, HeaderValue::from_static("5"));
        assert_eq!(wait(&headers), Duration::from_secs(60));
        headers.insert(RETRY_AFTER, HeaderValue::from_static("120"));
        assert_eq!(wait(&headers), Duration::from_secs(120));
        headers.insert(RETRY_AFTER, HeaderValue::from_static("999999"));
        assert_eq!(wait(&headers), Duration::from_secs(3600));
        headers.insert(
            RETRY_AFTER,
            HeaderValue::from_static("Wed, 21 Oct 2026 07:28:00 GMT"),
        );
        assert_eq!(wait(&headers), Duration::from_secs(60));
    }

    #[test]
    fn ids_and_names_are_checked_before_any_request() {
        assert!(check_report_id(RID).is_ok());
        for bad in ["", "0123456789ABCDEF0123456789abcdef", &RID[..31], "../x"] {
            assert!(check_report_id(bad).is_err(), "{bad}");
        }
    }

    fn scratch_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("frap_archive_{}_{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// A body whose every read fails, like a connection reset mid-stream.
    struct Broken;

    impl Read for Broken {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("connection reset"))
        }
    }

    #[test]
    fn downloads_are_hashed_bounded_and_atomic() {
        let dir = scratch_dir("download");
        let out = dir.join("obj.strm");
        let data = vec![7u8; 200_000];
        let (size, sha) = download_to(&out, &data[..], 200_000).unwrap();
        assert_eq!(size, 200_000);
        assert_eq!(sha, <[u8; 32]>::from(Sha256::digest(&data)));
        assert_eq!(std::fs::read(&out).unwrap(), data);

        let big = dir.join("big.strm");
        let error = download_to(&big, &data[..], 199_999).unwrap_err();
        assert!(matches!(error, ProtocolError::Invalid(_)));
        assert!(!big.exists());
        assert!(!dir.join("big.strm.part").exists());

        let broken = dir.join("broken.strm");
        assert!(matches!(
            download_to(&broken, Broken, 10).unwrap_err(),
            ProtocolError::Io(_)
        ));
        assert!(!broken.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn client(relay: &test_relay::TestRelay) -> StreamServerClient {
        StreamServerClient::with_tls_config(relay.base_url(), relay.client_tls()).unwrap()
    }

    #[test]
    fn listing_end_to_end() {
        let body = format!(
            r#"{{"blobs":[{{"filename":"manifest","size":8}}],"closure":{{"seq_limit":0,"manifest_sha256":"{}","sig":"{}"}}}}"#,
            "11".repeat(32),
            sig_hex()
        );
        let relay = test_relay::spawn(move |request| {
            if request.path.contains("feedfeedfeedfeedfeedfeedfeedfeed") {
                Reply::status(404)
            } else if request.path.contains("baadbaadbaadbaadbaadbaadbaadbaad") {
                Reply::status(429)
            } else if request.path.contains("deaddeaddeaddeaddeaddeaddeaddead") {
                Reply::status(503)
            } else {
                Reply::with_body(200, body.as_bytes())
            }
        });
        let client = client(&relay);
        let listing = client.archive_list(RID).unwrap().unwrap();
        assert_eq!(listing.blobs[0].filename, "manifest");
        assert_eq!(listing.closure.unwrap().manifest_sha256(), &[0x11; 32]);
        assert!(client
            .archive_list("feedfeedfeedfeedfeedfeedfeedfeed")
            .unwrap()
            .is_none());
        assert!(matches!(
            client
                .archive_list("baadbaadbaadbaadbaadbaadbaadbaad")
                .unwrap_err(),
            ProtocolError::RateLimited { .. }
        ));
        assert!(matches!(
            client
                .archive_list("deaddeaddeaddeaddeaddeaddeaddead")
                .unwrap_err(),
            ProtocolError::Http(_)
        ));
        assert!(client.archive_list("NOT-HEX").is_err());
        let paths: Vec<String> = relay.requests().into_iter().map(|r| r.path).collect();
        assert!(
            paths.iter().all(|p| !p.contains("NOT-HEX")),
            "checked before sending"
        );
    }

    #[test]
    fn fetching_writes_the_object_and_reads_its_signature() {
        let object = vec![0x42u8; 150_000];
        let served = object.clone();
        let relay = test_relay::spawn(move |request| {
            if request.path.ends_with("/000001.strm") {
                Reply::with_body(200, &served).header("X-Report-Write-Sig", &"cd".repeat(64))
            } else if request.path.ends_with("/manifest") {
                Reply::with_body(200, b"FQM1\0\0\0\0")
            } else if request.path.ends_with("/limited") {
                Reply::status(429)
            } else {
                Reply::status(404)
            }
        });
        let client = client(&relay);
        let dir = scratch_dir("fetch");

        let out = dir.join("a.strm");
        let ArchiveObject::Stored(stored) = client
            .archive_fetch_object(RID, "000001.strm", &out)
            .unwrap()
        else {
            panic!("expected a stored object");
        };
        assert_eq!(stored.size(), 150_000);
        assert_eq!(
            stored.blob_sha256(),
            &<[u8; 32]>::from(Sha256::digest(&object))
        );
        assert_eq!(stored.write_sig(), WriteSigHeader::Present([0xcd; 64]));
        assert_eq!(std::fs::read(&out).unwrap(), object);

        let manifest = dir.join("m");
        let ArchiveObject::Stored(stored) = client
            .archive_fetch_object(RID, "manifest", &manifest)
            .unwrap()
        else {
            panic!("expected the manifest");
        };
        assert_eq!(stored.write_sig(), WriteSigHeader::Absent);

        let missing = dir.join("missing");
        assert_eq!(
            client
                .archive_fetch_object(RID, "000002.strm", &missing)
                .unwrap(),
            ArchiveObject::NotFound
        );
        assert!(!missing.exists());
        assert!(matches!(
            client
                .archive_fetch_object(RID, "limited", &missing)
                .unwrap_err(),
            ProtocolError::RateLimited { .. }
        ));
        for bad in ["../x", "a/b", "", ".."] {
            assert!(
                client.archive_fetch_object(RID, bad, &missing).is_err(),
                "{bad}"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
