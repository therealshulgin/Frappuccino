//! The queue envelopes as Kotlin sees them: the queue key, inspection, the one
//! send call, the conversion of legacy files, and the timestamp proof.
//!
//! An envelope (`FQE1`, see `frappuccino_crypto_stream::envelope`) is a report
//! object waiting on the device, with the signatures it was given when it was
//! produced, in a trailer sealed under the queue key. Kotlin moves envelope
//! files between directories and decides when to send them; it never reads a
//! trailer, never builds a URL and never signs. Everything that needs the
//! trailer happens here.
//!
//! ## The queue key
//!
//! 32 random bytes per installation. Kotlin persists them in its protected
//! storage, reads them back as a `ByteArray` at process start, installs them
//! with [`queue_key_install`] and wipes its array. Without an installed key no
//! envelope can be written, inspected or sent, and the calls say so
//! ([`FfiError::NoQueueKey`], or the `no_queue_key` tag of
//! [`upload_send_envelope`]) rather than dropping anything: the files stay.

use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use frappuccino_crypto_core::pin_store as core_pin_store;
use frappuccino_crypto_core::report::Manifest;
use frappuccino_crypto_stream::durable::{sync_parent_dir, write_durably, OnDirSyncError};
use frappuccino_crypto_stream::{
    convert_to_envelope, inspect_envelope, open_envelope, write_envelope, Conversion,
    EnvelopeError, EnvelopeFields, EnvelopeKind as StreamEnvelopeKind, EnvelopeRequest,
    EnvelopeTrailer, QueueKey,
};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{hex_lower, report_state, upload_jwt_guard, FfiError, PutOutcome, ReportKeyring};
use crate::{StreamIdentity, TransportMode};

// ============================================================================
// Queue key holder
// ============================================================================

/// The installed queue key. Process-global, like the upload bearer and the
/// PIN-session key, because the envelopes are written by the recording
/// service and read by the upload workers.
static QUEUE_KEY: Mutex<Option<QueueKey>> = Mutex::new(None);

fn queue_key_guard() -> MutexGuard<'static, Option<QueueKey>> {
    // Recover from poison rather than panic across the FFI: the critical
    // sections only swap or copy the key, and a clear must always succeed.
    QUEUE_KEY.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A private copy of the installed key, wiped when dropped, so the global lock
/// is held for a copy only and never across file I/O.
///
/// # Errors
/// [`FfiError::NoQueueKey`] when no key is installed.
pub(crate) fn queue_key_copy() -> Result<QueueKey, FfiError> {
    let guard = queue_key_guard();
    let installed = guard.as_ref().ok_or(FfiError::NoQueueKey)?;
    installed
        .expose(|bytes| QueueKey::from_bytes(bytes))
        .map_err(FfiError::from)
}

/// FFI — 32 fresh random bytes for a new queue key, from the operating
/// system's random source. NOT installed: Kotlin persists them first, then
/// calls [`queue_key_install`], then wipes its array, so the process never
/// seals an envelope under a key that was not stored.
///
/// # Errors
/// [`FfiError::Internal`] if the random source fails.
pub fn queue_key_generate() -> Result<Vec<u8>, FfiError> {
    let key = QueueKey::generate()?;
    Ok(key.expose(|bytes| bytes.to_vec()))
}

/// FFI — install the queue key for this process. Replaces any key already
/// installed (installing the same key again is harmless). Kotlin wipes its
/// array after the call.
///
/// # Errors
/// [`FfiError::InvalidBlob`] unless `key` is 32 bytes.
pub fn queue_key_install(key: &[u8]) -> Result<(), FfiError> {
    let key = QueueKey::from_bytes(key)?;
    *queue_key_guard() = Some(key);
    Ok(())
}

/// FFI — drop and wipe the installed queue key (emergency wipe). Idempotent.
pub fn queue_key_clear() {
    *queue_key_guard() = None;
}

/// FFI — whether a queue key is installed.
#[must_use]
pub fn queue_key_present() -> bool {
    queue_key_guard().is_some()
}

// ============================================================================
// Envelope description
// ============================================================================

/// What an envelope carries, as the UDL enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvelopeKind {
    /// A report object (`PUT /file/{rid}/{name}`): metadata or media chunk.
    Chunk,
    /// A directory entry.
    DirectoryEntry,
    /// A report closure (`POST /close/{rid}`).
    Closure,
    /// An encrypted timestamp proof.
    TimestampProof,
}

impl From<StreamEnvelopeKind> for EnvelopeKind {
    fn from(kind: StreamEnvelopeKind) -> Self {
        match kind {
            StreamEnvelopeKind::Chunk => Self::Chunk,
            StreamEnvelopeKind::DirectoryEntry => Self::DirectoryEntry,
            StreamEnvelopeKind::Closure => Self::Closure,
            StreamEnvelopeKind::TimestampProof => Self::TimestampProof,
        }
    }
}

/// What Kotlin needs to schedule an envelope, decoded from its trailer. No
/// signature and no key: the report address is the only sensitive field, and
/// Kotlin needs it to group a report's envelopes (legacy closures are sent
/// only once no other envelope of the same report is queued).
#[derive(Debug, Clone)]
pub struct EnvelopeInfo {
    /// What the envelope carries.
    pub kind: EnvelopeKind,
    /// The report's id, 32 lowercase hex characters.
    pub report_id_hex: String,
    /// The object name on the relay (empty for a closure).
    pub filename: String,
    /// True for a legacy closure (empty manifest): send it only once no other
    /// envelope of the same report remains queued.
    pub needs_drain: bool,
    /// Whether the envelope can be sent in creation mode.
    pub has_create_sig: bool,
    /// The closure's `seq_limit` (0 for every other kind).
    pub seq_limit: u32,
    /// Size of the payload the relay will receive.
    pub payload_len: u64,
}

impl From<&EnvelopeTrailer> for EnvelopeInfo {
    fn from(trailer: &EnvelopeTrailer) -> Self {
        Self {
            kind: trailer.kind().into(),
            report_id_hex: trailer.report_id_hex(),
            filename: trailer.filename().to_owned(),
            needs_drain: trailer.needs_drain(),
            has_create_sig: trailer.create_sig().is_some(),
            seq_limit: trailer.seq_limit(),
            payload_len: trailer.payload_len(),
        }
    }
}

impl From<Conversion> for EnvelopeInfo {
    fn from(conversion: Conversion) -> Self {
        match conversion {
            Conversion::Converted(trailer) | Conversion::AlreadyConverted(trailer) => {
                Self::from(&trailer)
            }
        }
    }
}

/// FFI — decode the trailer of the envelope at `path`, without reading the
/// payload or checking signatures: cheap enough to run over a whole queue.
///
/// # Errors
/// [`FfiError::NoQueueKey`]; [`FfiError::Io`] if the file is missing or
/// unreadable; [`FfiError::EnvelopeCorrupt`] if the trailer is absent,
/// damaged or sealed under another key (move the file to the failed
/// directory, never retry it).
pub fn envelope_inspect(path: &str) -> Result<EnvelopeInfo, FfiError> {
    let key = queue_key_copy()?;
    let trailer = inspect_envelope(Path::new(path), &key)?;
    Ok(EnvelopeInfo::from(&trailer))
}

// ============================================================================
// Sending
// ============================================================================

/// FFI — send the envelope at `path` to the relay at `base_url` (scheme, host
/// and port). Never throws: every failure is in the [`PutOutcome`].
///
/// Before anything goes on the network the envelope is verified in full:
/// trailer, a re-hash of the payload, `report_id = H(report_pk)` and the
/// signatures. The URL, the headers and the body all come from that verified
/// envelope (`PUT /file/{rid}/{name}` for an object, `POST /close/{rid}` for a
/// closure), and the body is re-hashed again as it is sent. Nothing is signed.
///
/// `use_creation` asks for creation mode: the request also carries the
/// envelope's `X-Report-Create-Sig` and the upload bearer held in Rust. A
/// closure never creates a report, so the flag is ignored for one.
///
/// `error_detail` tags when `http_status == 0`, besides the transport's own
/// (`network`, `timeout`, `quic_fallback:...`, and the body tags of
/// `frappuccino_crypto_stream::RangeFailure`):
/// - `no_queue_key`: no queue key installed; the file is untouched.
/// - `file_missing`: there is no envelope at `path`, and only that.
/// - `envelope_corrupt`: the envelope is damaged or does not verify. Permanent:
///   move it to the failed directory; it is never re-signed.
/// - `envelope_io`: the envelope could not be read (transient I/O).
/// - `no_bearer`: creation mode without a held bearer.
/// - `no_create_sig`: creation mode for an envelope that carries no creation
///   signature.
///
/// With a response, `error_detail` is `None` except `report_closed`
/// ([`frappuccino_crypto_stream::REPORT_CLOSED_TAG`]): a 409 whose body is the
/// relay's `{"detail":"Report closed"}`, the report's closure not covering
/// this name. Every other 409 (a write-once conflict, a key mismatch) comes
/// without a tag.
#[must_use]
pub fn upload_send_envelope(
    base_url: &str,
    path: &str,
    mode: TransportMode,
    use_creation: bool,
) -> PutOutcome {
    let request = match envelope_request(base_url, path, use_creation) {
        Ok(request) => request,
        Err(tag) => {
            return PutOutcome {
                http_status: 0,
                upload_ms: 0,
                transfer_ms: 0,
                error_detail: Some(tag.to_owned()),
                transport_used: "none".to_owned(),
            }
        }
    };
    let outcome = request.send(mode.into());
    PutOutcome {
        http_status: outcome.result.http_status,
        upload_ms: outcome.result.upload_ms,
        transfer_ms: outcome.result.transfer_ms,
        error_detail: outcome.result.error_detail,
        transport_used: outcome.transport_used.as_str().to_owned(),
    }
}

/// Everything [`upload_send_envelope`] does before the network: verify the
/// envelope and build its request. The error is the outcome's tag.
fn envelope_request(
    base_url: &str,
    path: &str,
    use_creation: bool,
) -> Result<EnvelopeRequest, &'static str> {
    let key = queue_key_copy().map_err(|_| "no_queue_key")?;
    let verified = open_envelope(Path::new(path), &key).map_err(|error| match error {
        EnvelopeError::NotFound => "file_missing",
        error if error.is_corrupt() => "envelope_corrupt",
        _ => "envelope_io",
    })?;
    let creates = use_creation && verified.trailer().kind() != StreamEnvelopeKind::Closure;
    let bearer = if creates {
        // Read inside Rust from the holder; it never crosses the FFI. A clear
        // between Kotlin's check and here fails cleanly, the file stays.
        let held = upload_jwt_guard();
        let bearer = held.as_ref().ok_or("no_bearer")?;
        Some(Zeroizing::new(bearer.as_str().to_owned()))
    } else {
        None
    };
    verified
        .request(base_url, bearer.as_ref().map(|b| b.as_str()))
        .map_err(|error| match error {
            EnvelopeError::NoCreateSig => "no_create_sig",
            _ => "envelope_corrupt",
        })
}

// ============================================================================
// Legacy migration
// ============================================================================

/// FFI — migration: turn a pending legacy object of report `n` (a `.strm`
/// chunk, or a `.ots` proof already received) into an envelope, signed now by
/// the legacy key of `n`. `filename` is the object's name on the relay, as
/// the legacy upload path used it. The file at `src_path` is the payload: the
/// trailer is appended and the file renamed to `dst_path`, without a copy.
///
/// Idempotent: a source that already carries a readable trailer is only
/// renamed, and a missing source whose destination is already an envelope is
/// reported as done. Resumable after a power cut during the append, through
/// the marker `<dst_path>.conv` described at
/// `frappuccino_crypto_stream::convert_to_envelope`.
///
/// # Errors
/// [`FfiError::ReportRefused`] for a `kind` other than `Chunk` or
/// `TimestampProof`, or a name the relay would refuse; [`FfiError::NoQueueKey`];
/// [`FfiError::Io`] (a missing source and destination included);
/// [`FfiError::EnvelopeCorrupt`] for a source that ends like an envelope but
/// does not open, which is refused rather than given a second trailer;
/// [`FfiError::InvalidBlob`] for a chunk whose bytes are not a whole STRM blob
/// (see [`check_strm_framing`]), which is refused before anything is signed.
#[allow(clippy::needless_pass_by_value)] // UniFFI hands interface arguments over as owned Arcs.
pub fn legacy_convert_report_object(
    keyring: Arc<ReportKeyring>,
    n: u32,
    kind: EnvelopeKind,
    filename: &str,
    src_path: &str,
    dst_path: &str,
) -> Result<EnvelopeInfo, FfiError> {
    let kind = match kind {
        EnvelopeKind::Chunk => StreamEnvelopeKind::Chunk,
        EnvelopeKind::TimestampProof => StreamEnvelopeKind::TimestampProof,
        EnvelopeKind::DirectoryEntry | EnvelopeKind::Closure => {
            return Err(FfiError::ReportRefused {
                detail: "a legacy report object is a chunk or a timestamp proof".into(),
            })
        }
    };
    let key = queue_key_copy()?;
    let ring = &keyring.inner;
    let src = Path::new(src_path);
    // Set when the framing check refuses the payload, so the error that comes
    // back out of the conversion can be reported as what it is.
    let mut not_whole: Option<&'static str> = None;
    let converted = convert_to_envelope(src, Path::new(dst_path), &key, |digest| {
        // Checked here, on the payload the conversion measured, and not on the
        // file as found: a source resumed after a torn append still carries
        // the bytes that append left after its payload.
        if kind == StreamEnvelopeKind::Chunk {
            match check_strm_framing(src, digest.len()) {
                Ok(()) => {}
                Err(StrmFraming::NotWhole(why)) => {
                    not_whole = Some(why);
                    return Err(EnvelopeError::InvalidFields(why));
                }
                Err(StrmFraming::Io(error)) => {
                    return Err(EnvelopeError::Io {
                        op: "read the source's STRM framing",
                        kind: error.kind(),
                    })
                }
            }
        }
        let write_sig = ring.sign_write(n, filename.as_bytes(), digest.sha256())?;
        EnvelopeFields::object(
            kind,
            ring.report_pk(n)?,
            filename,
            write_sig,
            Some(ring.sign_create(n)?),
        )
    });
    match (converted, not_whole) {
        (Ok(conversion), _) => Ok(conversion.into()),
        (Err(_), Some(why)) => Err(FfiError::InvalidBlob {
            detail: format!("not a whole STRM blob: {why}"),
        }),
        (Err(error), None) => Err(error.into()),
    }
}

/// Why [`check_strm_framing`] refuses a payload.
enum StrmFraming {
    /// The file could not be read: nothing is decided about it.
    Io(std::io::Error),
    /// The bytes are not a whole STRM blob.
    NotWhole(&'static str),
}

/// Check that the first `len` bytes of the file at `path` are a whole STRM
/// blob, as far as its framing can tell without the archive key: a header of
/// a version this format defines, with no grant, and in CHUNKED mode every
/// declared chunk present with nothing after the last one. A file cut short
/// while it was being written fails here, and is never signed as though it
/// were the recording.
///
/// What it cannot see: a SINGLE body is one AEAD message whose length is
/// recorded nowhere, so a SINGLE blob cut short passes, within the bounds of a
/// SINGLE body. Only decryption tells, and the archive key is not on the
/// device. The legacy headers (V1, V2), which this build does not decrypt, are
/// checked with their own layout: their framing is the same.
fn check_strm_framing(path: &Path, len: u64) -> Result<(), StrmFraming> {
    use frappuccino_crypto_stream::header::{
        be_u16, parse_header, HeaderError, AEAD_TAG_BYTES, CHUNK_THRESHOLD,
        LEGACY_HEADER_SIZE_NO_GRANTS, LEGACY_OFF_GRANT_COUNT, MAX_CHUNK_COUNT, MAX_CHUNK_LEN,
        MODE_CHUNKED, MODE_SINGLE, NONCE_BYTES, NONCE_PREFIX_BYTES,
    };
    use std::io::{Read, Seek, SeekFrom};

    let mut file = std::fs::File::open(path).map_err(StrmFraming::Io)?;
    let read_at = |file: &mut std::fs::File, at: u64, out: &mut [u8]| {
        file.seek(SeekFrom::Start(at))
            .and_then(|_| file.read_exact(out))
            .map_err(StrmFraming::Io)
    };

    // The longest header any version has, plus its mode byte.
    let mut prefix = [0u8; LEGACY_HEADER_SIZE_NO_GRANTS + 1];
    let prefix_len = prefix.len().min(usize::try_from(len).unwrap_or(usize::MAX));
    read_at(&mut file, 0, &mut prefix[..prefix_len])?;
    let prefix = &prefix[..prefix_len];
    let (mode, body_start) = match parse_header(prefix) {
        Ok(parsed) => (parsed.mode, parsed.body_start),
        Err(HeaderError::LegacyVersionNotSupported { .. }) => {
            if prefix.len() < LEGACY_HEADER_SIZE_NO_GRANTS + 1 {
                return Err(StrmFraming::NotWhole("the header is cut short"));
            }
            let grants = be_u16(
                prefix[LEGACY_OFF_GRANT_COUNT],
                prefix[LEGACY_OFF_GRANT_COUNT + 1],
            );
            if grants != 0 {
                return Err(StrmFraming::NotWhole("the header declares grants"));
            }
            (
                prefix[LEGACY_HEADER_SIZE_NO_GRANTS],
                LEGACY_HEADER_SIZE_NO_GRANTS + 1,
            )
        }
        Err(HeaderError::TooShort { .. }) => {
            return Err(StrmFraming::NotWhole("the header is cut short"))
        }
        Err(_) => return Err(StrmFraming::NotWhole("not a STRM header")),
    };
    // Every bound below is far under u64::MAX; the conversions cannot fail.
    let as_u64 = |n: usize| u64::try_from(n).unwrap_or(u64::MAX);
    let body_start = as_u64(body_start);
    let body_len = len
        .checked_sub(body_start)
        .ok_or(StrmFraming::NotWhole("the header is cut short"))?;
    let nonce_and_tag = as_u64(NONCE_BYTES + AEAD_TAG_BYTES);

    match mode {
        MODE_SINGLE => {
            if body_len < nonce_and_tag || body_len > CHUNK_THRESHOLD.saturating_add(nonce_and_tag)
            {
                return Err(StrmFraming::NotWhole("a SINGLE body of impossible length"));
            }
            Ok(())
        }
        MODE_CHUNKED => {
            // `len` is a file length: saturating additions keep the cursor
            // comparable with it, and an overflow reads as "past the end".
            let count_at = body_start.saturating_add(as_u64(NONCE_PREFIX_BYTES));
            let mut cursor = count_at.saturating_add(4);
            if cursor > len {
                return Err(StrmFraming::NotWhole("the CHUNKED preamble is cut short"));
            }
            let mut word = [0u8; 4];
            read_at(&mut file, count_at, &mut word)?;
            let count = u32::from_be_bytes(word);
            if count == 0 || count > MAX_CHUNK_COUNT {
                return Err(StrmFraming::NotWhole("an impossible chunk count"));
            }
            for _ in 0..count {
                if cursor.saturating_add(4) > len {
                    return Err(StrmFraming::NotWhole("a declared chunk is missing"));
                }
                read_at(&mut file, cursor, &mut word)?;
                let chunk_len = u64::from(u32::from_be_bytes(word));
                if chunk_len < nonce_and_tag || chunk_len > u64::from(MAX_CHUNK_LEN) {
                    return Err(StrmFraming::NotWhole("a chunk of impossible length"));
                }
                cursor = cursor.saturating_add(4).saturating_add(chunk_len);
                if cursor > len {
                    return Err(StrmFraming::NotWhole("the last chunk is cut short"));
                }
            }
            if cursor != len {
                return Err(StrmFraming::NotWhole("bytes after the last chunk"));
            }
            Ok(())
        }
        _ => Err(StrmFraming::NotWhole("an unknown mode")),
    }
}

/// FFI — migration: turn the pending legacy directory entry of report `n`
/// into an envelope signed by the directory key. The entry's relay name is
/// derived here from `n`, as the legacy upload derived it. Same file handling
/// and idempotence as [`legacy_convert_report_object`].
///
/// # Errors
/// As [`legacy_convert_report_object`].
#[allow(clippy::needless_pass_by_value)] // UniFFI hands interface arguments over as owned Arcs.
pub fn legacy_convert_directory_entry(
    keyring: Arc<ReportKeyring>,
    n: u32,
    src_path: &str,
    dst_path: &str,
) -> Result<EnvelopeInfo, FfiError> {
    let key = queue_key_copy()?;
    let ring = &keyring.inner;
    let name = hex_lower(&ring.directory_entry_name(n)?);
    let conversion =
        convert_to_envelope(Path::new(src_path), Path::new(dst_path), &key, |digest| {
            let write_sig = ring.sign_directory_write(name.as_bytes(), digest.sha256())?;
            EnvelopeFields::object(
                StreamEnvelopeKind::DirectoryEntry,
                ring.directory_pk()?,
                &name,
                write_sig,
                Some(ring.sign_directory_create()?),
            )
        })?;
    Ok(conversion.into())
}

/// FFI — migration: write the closure of legacy report `n` to `out_path` (an
/// empty manifest, `seq_limit` 0, signed by the legacy key). Once the relay
/// records it, the report accepts no new object, so it is sent only after
/// every other envelope of the report has gone: its [`EnvelopeInfo`] says
/// `needs_drain`. It carries no creation signature: a report the relay does
/// not know has nothing to freeze.
///
/// # Errors
/// [`FfiError::NoQueueKey`], [`FfiError::Io`].
#[allow(clippy::needless_pass_by_value)] // UniFFI hands interface arguments over as owned Arcs.
pub fn legacy_write_closure(
    keyring: Arc<ReportKeyring>,
    n: u32,
    out_path: &str,
) -> Result<EnvelopeInfo, FfiError> {
    let key = queue_key_copy()?;
    let ring = &keyring.inner;
    let fields = EnvelopeFields::closure(ring.report_pk(n)?, 0, ring.sign_legacy_close(n)?, None)?;
    let trailer = write_envelope(
        Path::new(out_path),
        &Manifest::empty().to_bytes(),
        fields,
        &key,
    )?;
    Ok(EnvelopeInfo::from(&trailer))
}

// ============================================================================
// Timestamp proof (opt-in)
// ============================================================================

/// Associated data of a timestamp ticket. Distinct from every other blob
/// sealed under the queue key.
const OTS_TICKET_AAD: &[u8] = b"frappuccino-ots-ticket-v1";
/// The ticket is sealed with the queue key used directly as the AEAD key, in
/// the PIN store's blob layout. That layout has a salt field for its KDF; no
/// KDF runs here, so the field is zero.
const OTS_TICKET_SALT: [u8; 16] = [0u8; 16];
/// Length of a chained report's timestamp-proof name (32 lowercase hex).
const OTS_NAME_LEN: usize = 32;
/// Length of a commitment (SHA-256).
const COMMITMENT_LEN: usize = 32;

/// The 31-byte header magic that opens every `OpenTimestamps` proof file.
const OTS_HEADER_MAGIC: [u8; 31] =
    *b"\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94";
/// Major version of the proof file format this reader understands.
const OTS_MAJOR_VERSION: u8 = 0x01;
/// Opcode of the SHA-256 file-hash operation that follows the version.
const OTS_OP_SHA256: u8 = 0x08;

/// The digest an `OpenTimestamps` proof timestamps, read from its header:
/// magic, major version 1, the SHA-256 file-hash opcode, then 32 bytes.
/// `None` for anything else. The proof's attestations are not read: anchoring
/// is checked on a desktop with the CLI.
pub(crate) fn ots_start_digest(proof: &[u8]) -> Option<[u8; COMMITMENT_LEN]> {
    let rest = proof.strip_prefix(OTS_HEADER_MAGIC.as_slice())?;
    let (&version, rest) = rest.split_first()?;
    let (&op, rest) = rest.split_first()?;
    if version != OTS_MAJOR_VERSION || op != OTS_OP_SHA256 {
        return None;
    }
    let (digest, _) = rest.split_first_chunk::<COMMITMENT_LEN>()?;
    Some(*digest)
}

/// True for a chained report's timestamp-proof name: 32 lowercase hex.
fn is_ots_name(name: &str) -> bool {
    name.len() == OTS_NAME_LEN
        && name
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn commitment_array(commitment: &[u8]) -> Result<[u8; COMMITMENT_LEN], FfiError> {
    commitment.try_into().map_err(|_| FfiError::InvalidBlob {
        detail: format!(
            "a commitment is {COMMITMENT_LEN} bytes, got {}",
            commitment.len()
        ),
    })
}

/// FFI — write the timestamp ticket of a closed report: the name its proof
/// will have in the directory (`CloseInfo.ots_name`) and the commitment to
/// submit, sealed under the queue key and written durably to `ticket_path`.
/// The worker that submits the commitment gets the ticket's path only, never
/// its content in clear.
///
/// # Errors
/// [`FfiError::InvalidBlob`] for a name that is not 32 lowercase hex or a
/// commitment that is not 32 bytes; [`FfiError::NoQueueKey`]; [`FfiError::Io`].
pub fn ots_ticket_write(
    ticket_path: &str,
    ots_name: &str,
    commitment: &[u8],
) -> Result<(), FfiError> {
    if !is_ots_name(ots_name) {
        return Err(FfiError::InvalidBlob {
            detail: "a timestamp-proof name is 32 lowercase hex".into(),
        });
    }
    let commitment = commitment_array(commitment)?;
    let key = queue_key_copy()?;
    let mut plain = Zeroizing::new(Vec::with_capacity(OTS_NAME_LEN + COMMITMENT_LEN));
    plain.extend_from_slice(ots_name.as_bytes());
    plain.extend_from_slice(&commitment);
    let sealed = key.expose(|raw| {
        core_pin_store::seal_with_key_and_aad(raw, &OTS_TICKET_SALT, &plain, OTS_TICKET_AAD)
    })?;
    // On any error no ticket is left behind: a ticket on disk is always one
    // whose write went through to the end.
    write_durably(
        Path::new(ticket_path),
        OnDirSyncError::RemoveDestination,
        |file| std::io::Write::write_all(file, &sealed),
    )
    .map_err(|e| FfiError::Io {
        detail: format!("write timestamp ticket: {e}"),
    })
}

/// The proof name and the commitment of a ticket.
fn read_ticket(
    ticket_path: &str,
    key: &QueueKey,
) -> Result<(String, [u8; COMMITMENT_LEN]), FfiError> {
    let sealed = std::fs::read(ticket_path).map_err(|e| FfiError::Io {
        detail: format!("read timestamp ticket: {e}"),
    })?;
    let plain =
        key.expose(|raw| core_pin_store::open_with_key_and_aad(raw, &sealed, OTS_TICKET_AAD))?;
    let corrupt = || FfiError::InvalidBlob {
        detail: "malformed timestamp ticket".into(),
    };
    if plain.len() != OTS_NAME_LEN + COMMITMENT_LEN {
        return Err(corrupt());
    }
    let (name, commitment) = plain.split_at(OTS_NAME_LEN);
    let name = std::str::from_utf8(name).map_err(|_| corrupt())?;
    if !is_ots_name(name) {
        return Err(corrupt());
    }
    Ok((name.to_owned(), commitment_array(commitment)?))
}

/// FFI — the commitment a ticket asks to timestamp (public: it is what the
/// calendars receive).
///
/// # Errors
/// [`FfiError::NoQueueKey`]; [`FfiError::Io`]; [`FfiError::WrongPin`] if the
/// ticket does not open under the installed key; [`FfiError::InvalidBlob`]
/// for a malformed ticket.
pub fn ots_ticket_commitment(ticket_path: &str) -> Result<Vec<u8>, FfiError> {
    let key = queue_key_copy()?;
    let (_, commitment) = read_ticket(ticket_path, &key)?;
    Ok(commitment.to_vec())
}

/// FFI — turn a received `OpenTimestamps` proof into a timestamp-proof
/// envelope at `out_path`, in one call: the proof must timestamp the ticket's
/// commitment; it is encrypted (STRM, to `author`) in memory, signed with the
/// directory key read from the report state at `state_path`, and stored under
/// the ticket's name in the directory. The proof never reaches the disk in
/// clear. Needs the PIN session, like everything that reads the state.
///
/// The ticket is deleted here, right after the envelope is durably written.
/// The encryption is not deterministic, so sealing the same proof again would
/// make another envelope under the same relay name, which the relay refuses
/// (write-once) once the first one was sent; a run started again after a
/// crash finds no ticket instead. Kotlin's own delete afterwards finds nothing.
/// If that delete fails, the call still succeeds: the envelope is the result.
///
/// # Errors
/// [`FfiError::InvalidBlob`] if `proof` is not an `OpenTimestamps` SHA-256
/// proof; [`FfiError::ReportRefused`] if it timestamps another commitment;
/// the errors of [`ots_ticket_commitment`]; [`FfiError::Internal`] without a
/// PIN session; [`FfiError::Io`].
#[allow(clippy::needless_pass_by_value)] // UniFFI hands interface arguments over as owned Arcs.
pub fn pin_session_seal_ots_proof(
    state_path: &str,
    ticket_path: &str,
    proof: &[u8],
    author: Arc<StreamIdentity>,
    out_path: &str,
) -> Result<EnvelopeInfo, FfiError> {
    let key = queue_key_copy()?;
    let (ots_name, commitment) = read_ticket(ticket_path, &key)?;
    match ots_start_digest(proof) {
        Some(digest) if digest == commitment => {}
        Some(_) => {
            return Err(FfiError::ReportRefused {
                detail: "the proof does not timestamp this ticket's commitment".into(),
            })
        }
        None => {
            return Err(FfiError::InvalidBlob {
                detail: "not an OpenTimestamps SHA-256 proof".into(),
            })
        }
    }
    let blob = frappuccino_crypto_stream::encrypt::encrypt(proof, &author.inner)?;
    let blob_sha256: [u8; 32] = Sha256::digest(&blob).into();
    let fields = report_state::with_directory_key(Path::new(state_path), |state| {
        EnvelopeFields::object(
            StreamEnvelopeKind::TimestampProof,
            state.directory_pk(),
            &ots_name,
            state.sign_directory_write(ots_name.as_bytes(), &blob_sha256),
            Some(state.sign_directory_create()),
        )
        .map_err(FfiError::from)
    })?;
    let trailer = write_envelope(Path::new(out_path), &blob, fields, &key)?;
    let ticket = Path::new(ticket_path);
    if frappuccino_crypto_stream::secure_delete_file(ticket).is_ok() {
        let _ = sync_parent_dir(ticket);
    }
    Ok(EnvelopeInfo::from(&trailer))
}

/// Whether a rescued timestamp proof matches the recomputed commitment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OtsStatus {
    /// The proof timestamps exactly the commitment recomputed from the
    /// verified objects.
    Match,
    /// The proof timestamps something else, or is not a readable proof.
    Mismatch,
    /// No proof.
    Absent,
}

/// FFI — rescue: compare a decrypted proof file with the commitment
/// recomputed from the verified objects (`provenance_ots_commitment`). `None`
/// means no proof was found. Only the timestamped digest is checked; the
/// Bitcoin anchoring is checked on a desktop with the CLI.
///
/// # Errors
/// [`FfiError::InvalidBlob`] for a commitment that is not 32 bytes;
/// [`FfiError::Io`] if the proof file cannot be read.
pub fn ots_proof_status(
    decrypted_proof_path: Option<String>,
    commitment: &[u8],
) -> Result<OtsStatus, FfiError> {
    let commitment = commitment_array(commitment)?;
    let Some(path) = decrypted_proof_path else {
        return Ok(OtsStatus::Absent);
    };
    let proof = std::fs::read(&path).map_err(|e| FfiError::Io {
        detail: format!("read timestamp proof: {e}"),
    })?;
    Ok(match ots_start_digest(&proof) {
        Some(digest) if digest == commitment => OtsStatus::Match,
        _ => OtsStatus::Mismatch,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{author, globals, install_session, scratch_dir, MN_FIXED};
    use frappuccino_crypto_core::report::{ReportKeyring as CoreKeyring, ReportRescue};

    /// A minimal proof header timestamping `digest`.
    fn fake_proof(digest: &[u8; 32]) -> Vec<u8> {
        let mut proof = OTS_HEADER_MAGIC.to_vec();
        proof.push(OTS_MAJOR_VERSION);
        proof.push(OTS_OP_SHA256);
        proof.extend_from_slice(digest);
        // Stand-in for the operations and attestations that follow.
        proof.extend_from_slice(&[0xf0, 0x10, 0x00, 0x05]);
        proof
    }

    /// A real STRM blob of `plain_len` bytes, in the mode asked for, as the
    /// legacy recorder left them in its queue.
    fn strm_blob(plain_len: usize, chunked: bool) -> Vec<u8> {
        let plain = vec![0x5Cu8; plain_len];
        let identity = &author().inner;
        if chunked {
            frappuccino_crypto_stream::encrypt_chunked(&plain, identity).unwrap()
        } else {
            frappuccino_crypto_stream::encrypt_single(&plain, identity).unwrap()
        }
    }

    fn keyring() -> Arc<ReportKeyring> {
        Arc::new(ReportKeyring {
            inner: CoreKeyring::from_mnemonic(MN_FIXED, "").unwrap(),
        })
    }

    #[test]
    fn the_queue_key_is_installed_copied_and_cleared() {
        let _g = globals();
        queue_key_clear();
        assert!(!queue_key_present());
        assert!(matches!(queue_key_copy(), Err(FfiError::NoQueueKey)));
        assert!(matches!(
            queue_key_install(&[1u8; 31]),
            Err(FfiError::InvalidBlob { .. })
        ));
        let fresh = queue_key_generate().unwrap();
        assert_eq!(fresh.len(), 32);
        assert_ne!(fresh, queue_key_generate().unwrap());
        assert!(!queue_key_present(), "generating does not install");
        queue_key_install(&fresh).unwrap();
        assert!(queue_key_present());
        assert_eq!(queue_key_copy().unwrap().expose(|k| k.to_vec()), fresh);
        queue_key_clear();
        queue_key_clear();
        assert!(!queue_key_present());
    }

    #[test]
    fn calls_without_a_queue_key_fail_explicitly_and_leave_files_alone() {
        let _g = globals();
        let dir = scratch_dir("env_nokey");
        install_session();
        let src = dir.join("legacy.strm");
        std::fs::write(&src, b"legacy bytes").unwrap();
        queue_key_clear();
        let path = src.to_str().unwrap();
        assert!(matches!(envelope_inspect(path), Err(FfiError::NoQueueKey)));
        let out = upload_send_envelope(
            "https://relay.invalid",
            path,
            TransportMode::DirectTls,
            false,
        );
        assert_eq!(out.error_detail.as_deref(), Some("no_queue_key"));
        assert_eq!(out.http_status, 0);
        let dst = dir.join("L0_x.fqe");
        assert!(matches!(
            legacy_convert_report_object(
                keyring(),
                0,
                EnvelopeKind::Chunk,
                "x_000001.strm",
                path,
                dst.to_str().unwrap()
            ),
            Err(FfiError::NoQueueKey)
        ));
        assert_eq!(std::fs::read(&src).unwrap(), b"legacy bytes");
        assert!(!dst.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn legacy_objects_become_verifiable_envelopes() {
        let _g = globals();
        let dir = scratch_dir("env_legacy");
        install_session();
        let ring = keyring();
        let core_ring = CoreKeyring::from_mnemonic(MN_FIXED, "").unwrap();
        let rescue = ReportRescue::from_mnemonic(MN_FIXED, "").unwrap();

        // A pending legacy chunk of report 3.
        let src = dir.join("sid_000002.strm");
        std::fs::write(&src, strm_blob(64, false)).unwrap();
        let dst = dir.join("L3_sid_000002.fqe");
        let info = legacy_convert_report_object(
            Arc::clone(&ring),
            3,
            EnvelopeKind::Chunk,
            "sid_000002.strm",
            src.to_str().unwrap(),
            dst.to_str().unwrap(),
        )
        .unwrap();
        assert_eq!(info.kind, EnvelopeKind::Chunk);
        assert_eq!(info.filename, "sid_000002.strm");
        assert_eq!(
            info.report_id_hex,
            hex_lower(&core_ring.report_id(3).unwrap())
        );
        assert!(info.has_create_sig);
        assert!(!info.needs_drain);
        assert!(!src.exists());
        let key = queue_key_copy().unwrap();
        let verified = open_envelope(&dst, &key).unwrap();
        rescue
            .legacy(3)
            .unwrap()
            .verify_write(
                b"sid_000002.strm",
                verified.trailer().payload_sha256(),
                verified.trailer().signature(),
            )
            .unwrap();
        // Running it again only finds the envelope in place.
        let again = legacy_convert_report_object(
            Arc::clone(&ring),
            3,
            EnvelopeKind::Chunk,
            "sid_000002.strm",
            src.to_str().unwrap(),
            dst.to_str().unwrap(),
        )
        .unwrap();
        assert_eq!(again.report_id_hex, info.report_id_hex);
        assert_eq!(
            envelope_inspect(dst.to_str().unwrap()).unwrap().filename,
            "sid_000002.strm"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn legacy_proofs_entries_and_closures_become_envelopes() {
        let _g = globals();
        let dir = scratch_dir("env_legacy_more");
        install_session();
        let ring = keyring();
        let core_ring = CoreKeyring::from_mnemonic(MN_FIXED, "").unwrap();
        let rescue = ReportRescue::from_mnemonic(MN_FIXED, "").unwrap();
        let key = queue_key_copy().unwrap();

        // A legacy proof is a timestamp-proof envelope in its own report.
        let ots = dir.join("sid.ots");
        std::fs::write(&ots, fake_proof(&[7u8; 32])).unwrap();
        let ots_dst = dir.join("L3_o.fqe");
        let info = legacy_convert_report_object(
            Arc::clone(&ring),
            3,
            EnvelopeKind::TimestampProof,
            "sid.ots",
            ots.to_str().unwrap(),
            ots_dst.to_str().unwrap(),
        )
        .unwrap();
        assert_eq!(info.kind, EnvelopeKind::TimestampProof);
        open_envelope(&ots_dst, &key).unwrap();

        // A pending directory entry, named and signed by the directory key.
        let entry = dir.join("0000000003");
        std::fs::write(&entry, [0x01u8]).unwrap();
        let entry_dst = dir.join("L3_d.fqe");
        let info = legacy_convert_directory_entry(
            Arc::clone(&ring),
            3,
            entry.to_str().unwrap(),
            entry_dst.to_str().unwrap(),
        )
        .unwrap();
        assert_eq!(info.kind, EnvelopeKind::DirectoryEntry);
        assert_eq!(
            info.report_id_hex,
            hex_lower(&core_ring.directory_id().unwrap())
        );
        assert_eq!(
            Some(info.filename.as_str()),
            rescue.legacy(3).unwrap().directory_entry_name()
        );
        open_envelope(&entry_dst, &key).unwrap();

        // The legacy closure: empty, drained, verifiable at rescue.
        let close = dir.join("L3_z.fqe");
        let info = legacy_write_closure(Arc::clone(&ring), 3, close.to_str().unwrap()).unwrap();
        assert_eq!(info.kind, EnvelopeKind::Closure);
        assert!(info.needs_drain);
        assert!(!info.has_create_sig);
        assert_eq!(info.seq_limit, 0);
        let verified = open_envelope(&close, &key).unwrap();
        let manifest = Manifest::empty().to_bytes();
        rescue
            .legacy(3)
            .unwrap()
            .verify_close(0, &manifest, verified.trailer().signature())
            .unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn legacy_conversion_refuses_what_is_not_a_report_object() {
        let _g = globals();
        let dir = scratch_dir("env_legacy_refuse");
        install_session();
        let ring = keyring();

        // Kinds that are not report objects are refused before any I/O.
        for kind in [EnvelopeKind::Closure, EnvelopeKind::DirectoryEntry] {
            assert!(matches!(
                legacy_convert_report_object(Arc::clone(&ring), 3, kind, "x", "unused", "unused"),
                Err(FfiError::ReportRefused { .. })
            ));
        }
        // A name the relay would refuse is refused, and the source kept.
        let bad = dir.join("bad.strm");
        let blob = strm_blob(64, false);
        std::fs::write(&bad, &blob).unwrap();
        assert!(matches!(
            legacy_convert_report_object(
                Arc::clone(&ring),
                3,
                EnvelopeKind::Chunk,
                "../escape",
                bad.to_str().unwrap(),
                dir.join("bad.fqe").to_str().unwrap()
            ),
            Err(FfiError::ReportRefused { .. })
        ));
        assert_eq!(std::fs::read(&bad).unwrap(), blob);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_legacy_chunk_that_is_not_a_whole_strm_blob_is_never_signed() {
        let _g = globals();
        let dir = scratch_dir("env_legacy_framing");
        install_session();
        let ring = keyring();
        let convert = |src: &std::path::Path, dst: &std::path::Path| {
            legacy_convert_report_object(
                Arc::clone(&ring),
                3,
                EnvelopeKind::Chunk,
                "sid_000001.strm",
                src.to_str().unwrap(),
                dst.to_str().unwrap(),
            )
        };
        // Three chunks: two of 1 MiB and a short last one.
        let whole = strm_blob(2 * 1024 * 1024 + 1000, true);
        let mut cut_in_last = whole.clone();
        cut_in_last.truncate(whole.len() - 10);
        let mut last_chunk_gone = whole.clone();
        last_chunk_gone.truncate(whole.len() - (4 + 24 + 1000 + 16));
        let mut trailing = whole.clone();
        trailing.extend_from_slice(&[0u8; 7]);
        // The legacy layout: an author key between the version and the
        // sealed session key, the same framing after the header.
        let mut legacy_v2 = whole[..5].to_vec();
        legacy_v2[4] = 0x02;
        legacy_v2.extend_from_slice(&[0xABu8; 32]);
        legacy_v2.extend_from_slice(&whole[5..]);
        let mut legacy_grant = legacy_v2.clone();
        legacy_grant[5 + 32 + 80 + 1] = 0x01;
        let mut legacy_cut = legacy_v2.clone();
        legacy_cut.truncate(legacy_v2.len() - 10);
        let not_strm = b"legacy bytes".to_vec();
        for (what, bytes) in [
            ("cut inside the last chunk", &cut_in_last),
            ("last chunk missing", &last_chunk_gone),
            ("bytes after the last chunk", &trailing),
            ("legacy header declaring a grant", &legacy_grant),
            ("legacy blob cut inside the last chunk", &legacy_cut),
            ("not STRM at all", &not_strm),
        ] {
            let src = dir.join("sid_000001.strm");
            let dst = dir.join("L3_sid_000001.fqe");
            std::fs::write(&src, bytes).unwrap();
            assert!(
                matches!(convert(&src, &dst), Err(FfiError::InvalidBlob { .. })),
                "{what}: refused as not a whole blob"
            );
            assert_eq!(
                &std::fs::read(&src).unwrap(),
                bytes,
                "{what}: source intact"
            );
            assert!(!dst.exists(), "{what}: nothing written");
            assert!(
                !dir.join("L3_sid_000001.fqe.conv").exists(),
                "{what}: no marker"
            );
        }
        // A whole blob converts: CHUNKED, SINGLE, and in the legacy layout,
        // which this build does not decrypt but must not lose.
        for (i, bytes) in [whole, strm_blob(64, false), legacy_v2].iter().enumerate() {
            let src = dir.join(format!("sid_00000{i}.strm"));
            let dst = dir.join(format!("L3_sid_00000{i}.fqe"));
            std::fs::write(&src, bytes).unwrap();
            convert(&src, &dst).unwrap();
            assert!(dst.exists());
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sending_refuses_before_the_network() {
        let _g = globals();
        let dir = scratch_dir("env_send");
        install_session();
        let base = "https://relay.invalid:8443";
        let missing = dir.join("absent.fqe");
        let out = upload_send_envelope(
            base,
            missing.to_str().unwrap(),
            TransportMode::DirectTls,
            false,
        );
        assert_eq!(out.error_detail.as_deref(), Some("file_missing"));
        assert_eq!(out.transport_used, "none");

        let junk = dir.join("junk.fqe");
        std::fs::write(&junk, b"not an envelope").unwrap();
        let out = upload_send_envelope(base, junk.to_str().unwrap(), TransportMode::ObfQuic, false);
        assert_eq!(out.error_detail.as_deref(), Some("envelope_corrupt"));
        assert!(matches!(
            envelope_inspect(junk.to_str().unwrap()),
            Err(FfiError::EnvelopeCorrupt { .. })
        ));

        // A payload altered after it was signed is caught before sending.
        let src = dir.join("sid_000001.strm");
        std::fs::write(&src, strm_blob(64, false)).unwrap();
        let env = dir.join("L0_sid_000001.fqe");
        legacy_convert_report_object(
            keyring(),
            0,
            EnvelopeKind::Chunk,
            "sid_000001.strm",
            src.to_str().unwrap(),
            env.to_str().unwrap(),
        )
        .unwrap();
        let env_path = env.to_str().unwrap();
        // Creation mode without a held bearer.
        crate::upload_auth_clear();
        let out = upload_send_envelope(base, env_path, TransportMode::DirectTls, true);
        assert_eq!(out.error_detail.as_deref(), Some("no_bearer"));
        // With a bearer: the URL and the headers come from the envelope.
        crate::upload_auth_store("Bearer test-jwt".into());
        let request = envelope_request(base, env_path, true).unwrap();
        let rid = hex_lower(
            &CoreKeyring::from_mnemonic(MN_FIXED, "")
                .unwrap()
                .report_id(0)
                .unwrap(),
        );
        assert_eq!(request.url(), format!("{base}/file/{rid}/sid_000001.strm"));
        assert_eq!(request.header("Authorization"), Some("Bearer test-jwt"));
        assert!(request.header("X-Report-Create-Sig").is_some());
        let plain = envelope_request(base, env_path, false).unwrap();
        assert_eq!(plain.header("Authorization"), None);
        assert_eq!(plain.header("X-Report-Create-Sig"), None);
        assert!(plain.header("X-Report-Write-Sig").is_some());
        // The same payload altered after signing never leaves the device.
        let mut bytes = std::fs::read(&env).unwrap();
        bytes[0] ^= 1;
        std::fs::write(&env, &bytes).unwrap();
        let out = upload_send_envelope(base, env_path, TransportMode::DirectTls, false);
        assert_eq!(out.error_detail.as_deref(), Some("envelope_corrupt"));

        // A closure never creates: the flag is ignored, not an error, even
        // for a legacy closure that carries no creation signature.
        let close = dir.join("L0_z.fqe");
        legacy_write_closure(keyring(), 0, close.to_str().unwrap()).unwrap();
        let request = envelope_request(base, close.to_str().unwrap(), true).unwrap();
        assert_eq!(request.url(), format!("{base}/close/{rid}"));
        assert_eq!(request.header("Authorization"), None);
        assert_eq!(request.header("X-Report-Close-Seq-Limit"), Some("0"));
        crate::upload_auth_clear();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn proof_headers_are_read_strictly() {
        let digest = [9u8; 32];
        assert_eq!(ots_start_digest(&fake_proof(&digest)), Some(digest));
        let proof = fake_proof(&digest);
        // Truncated digest, other version, other hash op, wrong magic.
        assert_eq!(
            ots_start_digest(&proof[..OTS_HEADER_MAGIC.len() + 2 + 31]),
            None
        );
        let mut other = proof.clone();
        other[OTS_HEADER_MAGIC.len()] = 2;
        assert_eq!(ots_start_digest(&other), None);
        let mut other = proof.clone();
        other[OTS_HEADER_MAGIC.len() + 1] = 0x02;
        assert_eq!(ots_start_digest(&other), None);
        let mut other = proof;
        other[1] = b'X';
        assert_eq!(ots_start_digest(&other), None);
        assert_eq!(ots_start_digest(&[]), None);
    }

    #[test]
    fn a_ticket_round_trips_and_needs_its_key() {
        let _g = globals();
        let dir = scratch_dir("env_ticket");
        install_session();
        let ticket = dir.join("t.bin");
        let name = "0123456789abcdef0123456789abcdef";
        ots_ticket_write(ticket.to_str().unwrap(), name, &[5u8; 32]).unwrap();
        assert_eq!(
            ots_ticket_commitment(ticket.to_str().unwrap()).unwrap(),
            vec![5u8; 32]
        );
        // The name is not in clear on disk.
        let raw = std::fs::read(&ticket).unwrap();
        assert!(!raw.windows(name.len()).any(|w| w == name.as_bytes()));
        // Bad inputs.
        for bad in [
            "0123",
            "0123456789ABCDEF0123456789abcdef",
            "../../etc/passwd/xxxxxxxxxxxxxxxx",
        ] {
            assert!(matches!(
                ots_ticket_write(ticket.to_str().unwrap(), bad, &[5u8; 32]),
                Err(FfiError::InvalidBlob { .. })
            ));
        }
        assert!(matches!(
            ots_ticket_write(ticket.to_str().unwrap(), name, &[5u8; 31]),
            Err(FfiError::InvalidBlob { .. })
        ));
        // Another queue key cannot read it.
        queue_key_install(&[0x77u8; 32]).unwrap();
        assert!(matches!(
            ots_ticket_commitment(ticket.to_str().unwrap()),
            Err(FfiError::WrongPin)
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_received_proof_becomes_a_signed_directory_envelope() {
        let _g = globals();
        let dir = scratch_dir("env_ots_seal");
        install_session();
        let state = dir.join("report_state.bin");
        let state = state.to_str().unwrap();
        crate::pin_session_create_report_state(MN_FIXED.as_bytes(), b"", state).unwrap();
        let mut rescue = ReportRescue::from_mnemonic(MN_FIXED, "").unwrap();
        let ots_name = rescue.chain(0).unwrap().ots_name().unwrap().to_owned();
        let ticket = dir.join("ticket.bin");
        let ticket = ticket.to_str().unwrap();
        let commitment = [0x3Cu8; 32];
        ots_ticket_write(ticket, &ots_name, &commitment).unwrap();
        let author = crate::test_support::author();
        let out = dir.join("s_o.fqe");
        let out = out.to_str().unwrap();

        // A proof of another commitment, or not a proof at all, is refused.
        assert!(matches!(
            pin_session_seal_ots_proof(
                state,
                ticket,
                &fake_proof(&[1u8; 32]),
                Arc::clone(&author),
                out
            ),
            Err(FfiError::ReportRefused { .. })
        ));
        assert!(matches!(
            pin_session_seal_ots_proof(state, ticket, b"not a proof", Arc::clone(&author), out),
            Err(FfiError::InvalidBlob { .. })
        ));
        assert!(!Path::new(out).exists());

        let proof = fake_proof(&commitment);
        let info =
            pin_session_seal_ots_proof(state, ticket, &proof, Arc::clone(&author), out).unwrap();
        assert_eq!(info.kind, EnvelopeKind::TimestampProof);
        assert_eq!(info.filename, ots_name);
        assert_eq!(info.report_id_hex, rescue.directory().report_id_hex());
        let key = queue_key_copy().unwrap();
        let verified = open_envelope(Path::new(out), &key).unwrap();
        rescue
            .directory()
            .verify_write(
                ots_name.as_bytes(),
                verified.trailer().payload_sha256(),
                verified.trailer().signature(),
            )
            .unwrap();
        // The proof is not on disk in clear, and decrypts back.
        let bytes = std::fs::read(out).unwrap();
        assert!(!bytes
            .windows(OTS_HEADER_MAGIC.len())
            .any(|w| w == OTS_HEADER_MAGIC));
        let payload = &bytes[..usize::try_from(info.payload_len).unwrap()];
        let archive =
            frappuccino_crypto_core::identity::ArchiveIdentity::from_mnemonic(MN_FIXED, "")
                .unwrap();
        let (plain, _) = frappuccino_crypto_stream::decrypt::decrypt(payload, &archive).unwrap();
        assert_eq!(plain.as_slice(), proof.as_slice());
        // The ticket is gone with the seal: a run started again finds nothing
        // to seal instead of a second envelope under the same relay name.
        assert!(!Path::new(ticket).exists());
        assert!(matches!(
            pin_session_seal_ots_proof(state, ticket, &proof, Arc::clone(&author), out),
            Err(FfiError::Io { .. })
        ));
        assert_eq!(
            std::fs::read(out).unwrap(),
            bytes,
            "the envelope is untouched"
        );
        // The state was read, not advanced.
        let writer = crate::pin_session_open_report(state, author).unwrap();
        assert_eq!(writer.index(), 0);
        writer.abort();
        // Without the PIN session the directory key is out of reach.
        ots_ticket_write(ticket, &ots_name, &commitment).unwrap();
        crate::pin_session_clear_internal();
        assert!(matches!(
            pin_session_seal_ots_proof(state, ticket, &proof, crate::test_support::author(), out),
            Err(FfiError::Internal { .. })
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ots_status_compares_the_timestamped_digest() {
        let dir = scratch_dir("env_ots_status");
        let proof = dir.join("p.ots");
        std::fs::write(&proof, fake_proof(&[1u8; 32])).unwrap();
        let path = Some(proof.to_str().unwrap().to_owned());
        assert_eq!(
            ots_proof_status(path.clone(), &[1u8; 32]).unwrap(),
            OtsStatus::Match
        );
        assert_eq!(
            ots_proof_status(path, &[2u8; 32]).unwrap(),
            OtsStatus::Mismatch
        );
        assert_eq!(
            ots_proof_status(None, &[2u8; 32]).unwrap(),
            OtsStatus::Absent
        );
        std::fs::write(&proof, b"garbage").unwrap();
        assert_eq!(
            ots_proof_status(Some(proof.to_str().unwrap().to_owned()), &[1u8; 32]).unwrap(),
            OtsStatus::Mismatch
        );
        assert!(ots_proof_status(None, &[1u8; 3]).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
