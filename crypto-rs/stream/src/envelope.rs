//! Queue envelope (`FQE1`): one report object waiting on the device to be
//! sent, together with everything needed to send it, signed when it was
//! produced.
//!
//! ## Layout
//!
//! The envelope is the object's payload with a trailer **appended**, so a file
//! that already holds the payload becomes an envelope by appending and
//! renaming, without a copy:
//!
//! ```text
//! [payload]              kinds 1, 2, 4: the exact bytes the relay will store
//!                        kind 3: the closure manifest (the body of POST /close)
//! [sealed trailer]       nonce(24) ‖ XChaCha20-Poly1305(queue key, nonce, aad, trailer)
//! u32_be(sealed_len)     length of the sealed trailer, nonce and tag included
//! "FQE1"                 magic, the last four bytes of the file
//! ```
//!
//! The trailer, before encryption, is exactly
//!
//! ```text
//! kind(1) ‖ report_id(16) ‖ report_pk(32) ‖ signature(64) ‖ create_sig(64)
//!   ‖ u32_be(seq_limit) ‖ filename_len(1) ‖ filename ‖ u64_be(payload_len)
//!   ‖ payload_sha256(32)
//! ```
//!
//! with `kind` 1 = chunk, 2 = directory entry, 3 = closure, 4 = timestamp
//! proof; `signature` the 0x08 write signature over `filename` and the payload
//! hash (0x09 close signature over `seq_limit` and the manifest hash for kind
//! 3); `create_sig` the 0x07 creation signature, or 64 zero bytes when the
//! envelope carries none; `seq_limit` 0 except for kind 3; `filename` empty
//! for kind 3. The AAD is `"FQE1" ‖ u64_be(payload_len)`, which binds the
//! trailer to the length of the payload in front of it.
//!
//! ## What the encryption is for
//!
//! The trailer holds the report's address on the relay. Encrypting it under a
//! device-local queue key (see [`QueueKey`]) keeps the addresses of pending
//! objects off the filesystem in clear. It is no stronger than the protection
//! of the key itself, which is the caller's to store: anyone who can use the
//! key reads the addresses. The signatures are what the relay and the rescue
//! verify: they are produced with the report key when the object is made, and
//! nothing in this module can produce a new one.
//!
//! ## Strictness
//!
//! [`EnvelopeTrailer::open`] refuses anything that is not exactly this
//! layout (magic, sealed length, kind, filename, every length, the
//! `report_id`/`report_pk` binding). It is written not to panic on any input:
//! it reads its input only through checked accessors, and the property tests in
//! `tests/proptest_envelope.rs` and the Kani harnesses in `kani_proofs.rs`
//! exercise that claim. [`open_envelope`] additionally re-hashes the payload
//! and checks the signatures, which is what a sender runs before every send.

mod file;
#[cfg(feature = "protocol")]
mod request;

pub use file::{
    convert_to_envelope, inspect_envelope, open_envelope, write_envelope, Conversion,
    PayloadDigest, VerifiedEnvelope,
};
#[cfg(feature = "protocol")]
pub use request::EnvelopeRequest;

use crate::pathsafe::{is_relay_name_byte, is_relay_object_name_bytes};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use frappuccino_crypto_core::report::{
    report_id_from_pk, verify_close, verify_create, verify_write, ReportError, MAX_SEQ_LIMIT,
};
use frappuccino_crypto_core::CryptoError;
use rand_core::{OsRng, RngCore};
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

// ============================================================================
// Constants
// ============================================================================

/// The last four bytes of every envelope.
pub const ENVELOPE_MAGIC: [u8; 4] = *b"FQE1";
/// Width of the queue key.
pub const QUEUE_KEY_BYTES: usize = 32;
/// Longest object name an envelope carries (the relay's own limit).
pub const MAX_FILENAME_BYTES: usize = 128;
/// Size of the trailer before encryption, filename excluded.
pub const TRAILER_FIXED_BYTES: usize =
    1 + REPORT_ID_BYTES + PK_BYTES + SIG_BYTES + SIG_BYTES + 4 + 1 + 8 + HASH_BYTES;
/// Smallest sealed trailer (empty filename).
pub const MIN_SEALED_TRAILER_BYTES: usize = NONCE_BYTES + TRAILER_FIXED_BYTES + TAG_BYTES;
/// Largest sealed trailer (filename of [`MAX_FILENAME_BYTES`]).
pub const MAX_SEALED_TRAILER_BYTES: usize = MIN_SEALED_TRAILER_BYTES + MAX_FILENAME_BYTES;
/// `u32_be(sealed_len) ‖ magic`.
pub const FOOTER_BYTES: usize = 8;
/// How many bytes from the end of a file always contain a whole trailer.
pub const MAX_TAIL_BYTES: usize = MAX_SEALED_TRAILER_BYTES + FOOTER_BYTES;

const REPORT_ID_BYTES: usize = 16;
const PK_BYTES: usize = 32;
const SIG_BYTES: usize = 64;
const HASH_BYTES: usize = 32;
const NONCE_BYTES: usize = 24;
const TAG_BYTES: usize = 16;
/// `"FQM1" ‖ u32_be(count)`.
const MANIFEST_HEADER_BYTES: u64 = 8;
/// `u32_be(seq) ‖ sha256`.
const MANIFEST_ENTRY_BYTES: u64 = 36;

/// Largest closure manifest: one entry per possible sequence number.
#[must_use]
pub fn max_manifest_bytes() -> u64 {
    MANIFEST_HEADER_BYTES + MANIFEST_ENTRY_BYTES * u64::from(MAX_SEQ_LIMIT)
}

// ============================================================================
// Errors
// ============================================================================

/// Failures of the envelope codec and of the envelope files.
///
/// No variant carries key material or the content of a trailer.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum EnvelopeError {
    /// The envelope file does not exist.
    #[error("envelope file not found")]
    NotFound,
    /// An I/O operation failed.
    #[error("I/O error during {op}: {kind}")]
    Io {
        /// What was being done.
        op: &'static str,
        /// The kind of the underlying error.
        kind: std::io::ErrorKind,
    },
    /// The file does not end with the envelope magic: it carries no trailer.
    #[error("no envelope trailer")]
    NoTrailer,
    /// The file ends with the magic but its framing or trailer is not
    /// exactly the envelope layout.
    #[error("malformed envelope: {0}")]
    Malformed(&'static str),
    /// The trailer does not decrypt under the queue key: tampered, damaged,
    /// or sealed under another key.
    #[error("envelope trailer does not decrypt under the queue key")]
    Undecryptable,
    /// The trailer's `report_id` is not the one its `report_pk` maps to.
    #[error("report_id does not match report_pk")]
    ReportIdMismatch,
    /// The payload does not hash to the value the trailer records.
    #[error("payload does not match the trailer's hash")]
    PayloadMismatch,
    /// A signature or a manifest carried by the envelope does not verify.
    #[error("envelope verification failed: {0}")]
    Verification(ReportError),
    /// The caller's signing step failed while building an envelope.
    #[error("signing failed: {0}")]
    Signing(ReportError),
    /// Fields offered to build an envelope break the layout's rules.
    #[error("invalid envelope fields: {0}")]
    InvalidFields(&'static str),
    /// Creation was requested but the envelope carries no creation signature.
    #[error("creation requested but the envelope carries no create_sig")]
    NoCreateSig,
    /// Creation was requested for a closure, which never creates a report.
    #[error("a closure is never sent in creation mode")]
    CreationNotApplicable,
    /// A queue key of the wrong length.
    #[error("a queue key is {QUEUE_KEY_BYTES} bytes")]
    InvalidQueueKey,
    /// The operating system's random source failed.
    #[error("random source failure")]
    Rng,
    /// The trailer could not be encrypted.
    #[error("trailer encryption failed")]
    Seal,
}

impl EnvelopeError {
    /// True when the envelope itself is unusable and must never be sent: a
    /// sender files it as failed rather than retrying it. `NotFound`, I/O
    /// errors and caller errors are not corruption.
    #[must_use]
    pub fn is_corrupt(&self) -> bool {
        matches!(
            self,
            Self::NoTrailer
                | Self::Malformed(_)
                | Self::Undecryptable
                | Self::ReportIdMismatch
                | Self::PayloadMismatch
                | Self::Verification(_)
        )
    }

    pub(crate) fn io(op: &'static str, error: &std::io::Error) -> Self {
        if error.kind() == std::io::ErrorKind::NotFound {
            Self::NotFound
        } else {
            Self::Io {
                op,
                kind: error.kind(),
            }
        }
    }
}

/// Lets a signing closure use `?` on the report crate's results.
impl From<ReportError> for EnvelopeError {
    fn from(error: ReportError) -> Self {
        Self::Signing(error)
    }
}

/// Lets a signing closure use `?` on the legacy keyring's results.
impl From<CryptoError> for EnvelopeError {
    fn from(error: CryptoError) -> Self {
        Self::Signing(ReportError::Crypto(error))
    }
}

// ============================================================================
// Queue key
// ============================================================================

/// The device-local key that seals envelope trailers. Wiped on drop, never
/// printed.
pub struct QueueKey(Zeroizing<[u8; QUEUE_KEY_BYTES]>);

impl fmt::Debug for QueueKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("QueueKey(<redacted>)")
    }
}

impl QueueKey {
    /// A fresh random key.
    ///
    /// # Errors
    /// [`EnvelopeError::Rng`] if the operating system's random source fails.
    pub fn generate() -> Result<Self, EnvelopeError> {
        let mut key = Zeroizing::new([0u8; QUEUE_KEY_BYTES]);
        OsRng
            .try_fill_bytes(key.as_mut())
            .map_err(|_| EnvelopeError::Rng)?;
        Ok(Self(key))
    }

    /// A key from its 32 bytes. The caller wipes its own copy.
    ///
    /// # Errors
    /// [`EnvelopeError::InvalidQueueKey`] unless `bytes` is 32 bytes long.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, EnvelopeError> {
        if bytes.len() != QUEUE_KEY_BYTES {
            return Err(EnvelopeError::InvalidQueueKey);
        }
        let mut key = Zeroizing::new([0u8; QUEUE_KEY_BYTES]);
        key.copy_from_slice(bytes);
        Ok(Self(key))
    }

    /// Lend the raw key to `f`, for instance to hand it to the platform's
    /// protected storage once, at creation.
    pub fn expose<R>(&self, f: impl FnOnce(&[u8; QUEUE_KEY_BYTES]) -> R) -> R {
        f(&self.0)
    }

    fn cipher(&self) -> XChaCha20Poly1305 {
        XChaCha20Poly1305::new(self.0.as_slice().into())
    }
}

// ============================================================================
// Kind
// ============================================================================

/// What an envelope carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvelopeKind {
    /// A report object (`PUT /file/{rid}/{name}`): the metadata object or a
    /// media chunk.
    Chunk,
    /// A directory entry (`PUT` into the directory report).
    DirectoryEntry,
    /// A report closure (`POST /close/{rid}`), payload = manifest.
    Closure,
    /// An encrypted timestamp proof (`PUT` into the directory report).
    TimestampProof,
}

impl EnvelopeKind {
    /// The wire byte.
    #[must_use]
    pub fn to_byte(self) -> u8 {
        match self {
            Self::Chunk => 1,
            Self::DirectoryEntry => 2,
            Self::Closure => 3,
            Self::TimestampProof => 4,
        }
    }

    /// The kind of a wire byte, if it names one.
    #[must_use]
    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            1 => Some(Self::Chunk),
            2 => Some(Self::DirectoryEntry),
            3 => Some(Self::Closure),
            4 => Some(Self::TimestampProof),
            _ => None,
        }
    }
}

// ============================================================================
// Fields offered by the producer
// ============================================================================

/// What a producer supplies to make an envelope: the signed parts. The
/// payload length and hash are measured from the payload itself, and the
/// `report_id` is recomputed from `report_pk`, so neither can disagree with
/// what is written.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct EnvelopeFields {
    #[zeroize(skip)]
    kind: EnvelopeKind,
    report_pk: [u8; PK_BYTES],
    signature: [u8; SIG_BYTES],
    create_sig: Option<[u8; SIG_BYTES]>,
    seq_limit: u32,
    filename: String,
}

impl fmt::Debug for EnvelopeFields {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The address and the signatures stay out of logs.
        f.debug_struct("EnvelopeFields")
            .field("kind", &self.kind)
            .field("has_create_sig", &self.create_sig.is_some())
            .field("seq_limit", &self.seq_limit)
            .finish_non_exhaustive()
    }
}

impl EnvelopeFields {
    /// Fields of an object envelope (chunk, directory entry, timestamp proof):
    /// the 0x08 `write_sig` over `filename`, and optionally the 0x07
    /// `create_sig` of the report.
    ///
    /// # Errors
    /// [`EnvelopeError::InvalidFields`] for [`EnvelopeKind::Closure`], a
    /// filename the relay would refuse, or an all-zero `create_sig` (zeros are
    /// the wire form of "none").
    pub fn object(
        kind: EnvelopeKind,
        report_pk: [u8; PK_BYTES],
        filename: &str,
        write_sig: [u8; SIG_BYTES],
        create_sig: Option<[u8; SIG_BYTES]>,
    ) -> Result<Self, EnvelopeError> {
        if kind == EnvelopeKind::Closure {
            return Err(EnvelopeError::InvalidFields(
                "a closure is built with EnvelopeFields::closure",
            ));
        }
        Self {
            kind,
            report_pk,
            signature: write_sig,
            create_sig,
            seq_limit: 0,
            filename: filename.to_owned(),
        }
        .checked()
    }

    /// Fields of a closure envelope: the 0x09 `close_sig` over `seq_limit`
    /// and the manifest, and optionally the report's 0x07 `create_sig`.
    ///
    /// # Errors
    /// [`EnvelopeError::InvalidFields`] for a `seq_limit` above
    /// `MAX_SEQ_LIMIT` or an all-zero `create_sig`.
    pub fn closure(
        report_pk: [u8; PK_BYTES],
        seq_limit: u32,
        close_sig: [u8; SIG_BYTES],
        create_sig: Option<[u8; SIG_BYTES]>,
    ) -> Result<Self, EnvelopeError> {
        Self {
            kind: EnvelopeKind::Closure,
            report_pk,
            signature: close_sig,
            create_sig,
            seq_limit,
            filename: String::new(),
        }
        .checked()
    }

    /// The first rule these fields break, if any. The rules hold for every
    /// envelope whatever its payload.
    fn rule_violation(&self) -> Option<&'static str> {
        fields_rule_violation(
            self.kind,
            self.create_sig.as_ref(),
            self.seq_limit,
            self.filename.as_bytes(),
        )
    }

    /// [`Self::rule_violation`] as a construction error.
    fn checked(self) -> Result<Self, EnvelopeError> {
        match self.rule_violation() {
            Some(rule) => Err(EnvelopeError::InvalidFields(rule)),
            None => Ok(self),
        }
    }
}

/// The object name the relay keeps for a closure's manifest; a PUT to it is
/// refused, so no envelope may target it.
const RESERVED_MANIFEST_NAME: &str = "manifest";

/// The first layout rule these parts of an envelope break, whatever its
/// payload, if any. The one statement of these rules: the producer applies
/// it to its [`EnvelopeFields`], and the decoder to the parts it has read,
/// before it assembles anything.
fn fields_rule_violation(
    kind: EnvelopeKind,
    create_sig: Option<&[u8; SIG_BYTES]>,
    seq_limit: u32,
    filename: &[u8],
) -> Option<&'static str> {
    if create_sig == Some(&[0u8; SIG_BYTES]) {
        return Some("an all-zero create_sig is the wire form of none");
    }
    if kind == EnvelopeKind::Closure {
        if !filename.is_empty() {
            return Some("a closure carries no filename");
        }
        if seq_limit > MAX_SEQ_LIMIT {
            return Some("seq_limit exceeds the sequence space");
        }
    } else {
        if !is_relay_object_name_bytes(filename) || filename == RESERVED_MANIFEST_NAME.as_bytes() {
            return Some("filename is not a name the relay accepts");
        }
        if seq_limit != 0 {
            return Some("only a closure carries a seq_limit");
        }
    }
    None
}

/// The first rule a payload of `payload_len` bytes breaks for an envelope of
/// this `kind` and `seq_limit`, if any. Shared like [`fields_rule_violation`].
fn payload_rule_violation(
    kind: EnvelopeKind,
    seq_limit: u32,
    payload_len: u64,
) -> Option<&'static str> {
    if kind != EnvelopeKind::Closure {
        return (payload_len == 0).then_some("an object payload is never empty");
    }
    let Some(entries) = payload_len
        .checked_sub(MANIFEST_HEADER_BYTES)
        .filter(|body| body % MANIFEST_ENTRY_BYTES == 0 && payload_len <= max_manifest_bytes())
        .map(|body| body / MANIFEST_ENTRY_BYTES)
    else {
        return Some("a closure payload is not a manifest's size");
    };
    let seq_limit = u64::from(seq_limit);
    if (seq_limit == 0) != (entries == 0) || entries > seq_limit {
        return Some("seq_limit cannot match a manifest of this size");
    }
    None
}

// ============================================================================
// Trailer
// ============================================================================

/// A decoded, validated trailer.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct EnvelopeTrailer {
    fields: EnvelopeFields,
    report_id: [u8; REPORT_ID_BYTES],
    payload_len: u64,
    payload_sha256: [u8; HASH_BYTES],
}

impl fmt::Debug for EnvelopeTrailer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EnvelopeTrailer")
            .field("fields", &self.fields)
            .field("payload_len", &self.payload_len)
            .finish_non_exhaustive()
    }
}

// ---- public API -------------------------------------------------------------

impl EnvelopeTrailer {
    /// Build the trailer of `payload` from `fields`, measuring the payload
    /// and checking the signatures against it before anything is written: a
    /// producer cannot queue an envelope that its own sender would refuse.
    ///
    /// # Errors
    /// [`EnvelopeError::InvalidFields`] if the payload's size breaks the
    /// kind's rules, [`EnvelopeError::Verification`] if a signature does not
    /// verify.
    pub fn for_payload(fields: EnvelopeFields, payload: &[u8]) -> Result<Self, EnvelopeError> {
        let digest = PayloadDigest::of_bytes(payload)?;
        let trailer = Self::from_parts(fields, &digest)?;
        trailer.verify_signatures(Some(payload))?;
        Ok(trailer)
    }

    /// Decode and validate the trailer at the end of a file of `file_len`
    /// bytes, given its last bytes in `tail` (at least [`MAX_TAIL_BYTES`] of
    /// them, or the whole file if it is shorter).
    ///
    /// Checks the framing, decrypts under `key`, decodes the layout exactly,
    /// and checks that `report_id` is the one `report_pk` maps to. The
    /// payload and the signatures are not checked here (see
    /// [`open_envelope`]).
    ///
    /// # Errors
    /// [`EnvelopeError::NoTrailer`] without the magic,
    /// [`EnvelopeError::Malformed`] for any framing or layout violation,
    /// [`EnvelopeError::Undecryptable`], [`EnvelopeError::ReportIdMismatch`].
    pub fn open(file_len: u64, tail: &[u8], key: &QueueKey) -> Result<Self, EnvelopeError> {
        let (sealed, payload_len) = locate_sealed_trailer(file_len, tail)?;
        let (nonce, ciphertext) = sealed
            .split_first_chunk::<NONCE_BYTES>()
            .ok_or(EnvelopeError::Malformed("trailer truncated"))?;
        let plain = Zeroizing::new(
            key.cipher()
                .decrypt(
                    XNonce::from_slice(nonce),
                    Payload {
                        msg: ciphertext,
                        aad: &trailer_aad(payload_len),
                    },
                )
                .map_err(|_| EnvelopeError::Undecryptable)?,
        );
        let trailer = decode_plain(&plain)?;
        if trailer.payload_len != payload_len {
            return Err(EnvelopeError::Malformed(
                "payload length differs from the file framing",
            ));
        }
        if report_id_from_pk(&trailer.fields.report_pk) != trailer.report_id {
            return Err(EnvelopeError::ReportIdMismatch);
        }
        Ok(trailer)
    }

    /// The bytes appended after the payload: `sealed trailer ‖ u32_be(len) ‖
    /// "FQE1"`, under a fresh random nonce.
    ///
    /// # Errors
    /// [`EnvelopeError::Rng`] or [`EnvelopeError::Seal`].
    pub fn seal(&self, key: &QueueKey) -> Result<Vec<u8>, EnvelopeError> {
        let plain = self.encode_plain()?;
        let mut nonce = [0u8; NONCE_BYTES];
        OsRng
            .try_fill_bytes(&mut nonce)
            .map_err(|_| EnvelopeError::Rng)?;
        let ciphertext = key
            .cipher()
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &plain,
                    aad: &trailer_aad(self.payload_len),
                },
            )
            .map_err(|_| EnvelopeError::Seal)?;
        let sealed_len = NONCE_BYTES + ciphertext.len();
        let sealed_len_be = u32::try_from(sealed_len)
            .map_err(|_| EnvelopeError::Seal)?
            .to_be_bytes();
        let mut tail = Vec::with_capacity(sealed_len + FOOTER_BYTES);
        tail.extend_from_slice(&nonce);
        tail.extend_from_slice(&ciphertext);
        tail.extend_from_slice(&sealed_len_be);
        tail.extend_from_slice(&ENVELOPE_MAGIC);
        Ok(tail)
    }

    /// What the envelope carries.
    #[must_use]
    pub fn kind(&self) -> EnvelopeKind {
        self.fields.kind
    }

    /// The report's 16-byte id (`H(report_pk)`).
    #[must_use]
    pub fn report_id(&self) -> &[u8; REPORT_ID_BYTES] {
        &self.report_id
    }

    /// The report id as 32 lowercase hex characters, its form in URLs.
    #[must_use]
    pub fn report_id_hex(&self) -> String {
        hex::encode(self.report_id)
    }

    /// The report public key.
    #[must_use]
    pub fn report_pk(&self) -> &[u8; PK_BYTES] {
        &self.fields.report_pk
    }

    /// The main signature: 0x08 write signature, or 0x09 close signature for
    /// a closure.
    #[must_use]
    pub fn signature(&self) -> &[u8; SIG_BYTES] {
        &self.fields.signature
    }

    /// The 0x07 creation signature, if the envelope carries one.
    #[must_use]
    pub fn create_sig(&self) -> Option<&[u8; SIG_BYTES]> {
        self.fields.create_sig.as_ref()
    }

    /// The closure's `seq_limit` (0 for every other kind).
    #[must_use]
    pub fn seq_limit(&self) -> u32 {
        self.fields.seq_limit
    }

    /// The object name on the relay (empty for a closure).
    #[must_use]
    pub fn filename(&self) -> &str {
        &self.fields.filename
    }

    /// Length of the payload in front of the trailer.
    #[must_use]
    pub fn payload_len(&self) -> u64 {
        self.payload_len
    }

    /// SHA-256 of the payload.
    #[must_use]
    pub fn payload_sha256(&self) -> &[u8; HASH_BYTES] {
        &self.payload_sha256
    }

    /// True for a closure with an empty manifest, which is how a legacy
    /// report is closed: it is sent only once no other envelope of the same
    /// report remains queued. A chained report is never closed empty.
    #[must_use]
    pub fn needs_drain(&self) -> bool {
        self.fields.kind == EnvelopeKind::Closure && self.fields.seq_limit == 0
    }
}

// ---- private helpers --------------------------------------------------------

impl EnvelopeTrailer {
    /// Assemble and validate a trailer for a payload of the given digest.
    fn from_parts(fields: EnvelopeFields, digest: &PayloadDigest) -> Result<Self, EnvelopeError> {
        let trailer = Self {
            report_id: report_id_from_pk(&fields.report_pk),
            fields,
            payload_len: digest.len(),
            payload_sha256: *digest.sha256(),
        };
        match trailer.rule_violation() {
            Some(rule) => Err(EnvelopeError::InvalidFields(rule)),
            None => Ok(trailer),
        }
    }

    /// The first structural rule this trailer breaks, if any. The decoder
    /// checks the same two rule sets on the parts it reads, so producer and
    /// decoder enforce the same layout.
    fn rule_violation(&self) -> Option<&'static str> {
        self.fields.rule_violation().or_else(|| {
            payload_rule_violation(self.fields.kind, self.fields.seq_limit, self.payload_len)
        })
    }

    /// Check the main signature, and the creation signature if present.
    /// `manifest` is the payload, required for a closure (the close signature
    /// covers the parsed manifest), ignored otherwise.
    pub(crate) fn verify_signatures(&self, manifest: Option<&[u8]>) -> Result<(), EnvelopeError> {
        let pk = &self.fields.report_pk;
        if self.fields.kind == EnvelopeKind::Closure {
            let manifest =
                manifest.ok_or(EnvelopeError::Malformed("closure manifest unavailable"))?;
            verify_close(pk, self.fields.seq_limit, manifest, &self.fields.signature)
                .map_err(EnvelopeError::Verification)?;
        } else {
            verify_write(
                pk,
                self.fields.filename.as_bytes(),
                &self.payload_sha256,
                &self.fields.signature,
            )
            .map_err(EnvelopeError::Verification)?;
        }
        if let Some(create_sig) = &self.fields.create_sig {
            verify_create(pk, create_sig).map_err(EnvelopeError::Verification)?;
        }
        Ok(())
    }

    /// The trailer before encryption. The buffer is sized exactly so it never
    /// reallocates (a reallocation would leave an unwiped copy behind).
    fn encode_plain(&self) -> Result<Zeroizing<Vec<u8>>, EnvelopeError> {
        let name = self.fields.filename.as_bytes();
        let name_len = u8::try_from(name.len()).map_err(|_| EnvelopeError::Seal)?;
        let mut plain = Zeroizing::new(Vec::with_capacity(TRAILER_FIXED_BYTES + name.len()));
        plain.push(self.fields.kind.to_byte());
        plain.extend_from_slice(&self.report_id);
        plain.extend_from_slice(&self.fields.report_pk);
        plain.extend_from_slice(&self.fields.signature);
        plain.extend_from_slice(&self.fields.create_sig.unwrap_or([0u8; SIG_BYTES]));
        plain.extend_from_slice(&self.fields.seq_limit.to_be_bytes());
        plain.push(name_len);
        plain.extend_from_slice(name);
        plain.extend_from_slice(&self.payload_len.to_be_bytes());
        plain.extend_from_slice(&self.payload_sha256);
        Ok(plain)
    }
}

/// `"FQE1" ‖ u64_be(payload_len)`.
fn trailer_aad(payload_len: u64) -> [u8; 12] {
    let mut aad = [0u8; 12];
    aad[..4].copy_from_slice(&ENVELOPE_MAGIC);
    aad[4..].copy_from_slice(&payload_len.to_be_bytes());
    aad
}

/// Find the sealed trailer in `tail` from the footer, and the payload length
/// the framing implies. Pure arithmetic on the framing, no decryption.
pub(crate) fn locate_sealed_trailer(
    file_len: u64,
    tail: &[u8],
) -> Result<(&[u8], u64), EnvelopeError> {
    let tail_len =
        u64::try_from(tail.len()).map_err(|_| EnvelopeError::Malformed("tail too long"))?;
    if tail_len > file_len {
        return Err(EnvelopeError::Malformed("tail longer than the file"));
    }
    let (rest, footer) = tail
        .split_last_chunk::<FOOTER_BYTES>()
        .ok_or(EnvelopeError::NoTrailer)?;
    let (sealed_len_be, magic) = footer
        .split_first_chunk::<4>()
        .ok_or(EnvelopeError::NoTrailer)?;
    if *magic != ENVELOPE_MAGIC {
        return Err(EnvelopeError::NoTrailer);
    }
    let sealed_len = usize::try_from(u32::from_be_bytes(*sealed_len_be))
        .map_err(|_| EnvelopeError::Malformed("trailer length out of range"))?;
    if !(MIN_SEALED_TRAILER_BYTES..=MAX_SEALED_TRAILER_BYTES).contains(&sealed_len) {
        return Err(EnvelopeError::Malformed("trailer length out of range"));
    }
    let sealed_start = rest
        .len()
        .checked_sub(sealed_len)
        .ok_or(EnvelopeError::Malformed("file shorter than its trailer"))?;
    let sealed = rest
        .get(sealed_start..)
        .ok_or(EnvelopeError::Malformed("file shorter than its trailer"))?;
    // Lossless: `sealed_len` is at most MAX_SEALED_TRAILER_BYTES here.
    let framing = u64::try_from(sealed_len + FOOTER_BYTES)
        .map_err(|_| EnvelopeError::Malformed("trailer length out of range"))?;
    let payload_len = file_len
        .checked_sub(framing)
        .ok_or(EnvelopeError::Malformed("file shorter than its trailer"))?;
    Ok((sealed, payload_len))
}

/// Decode the trailer's plaintext layout exactly. Structural only: the
/// `report_id` binding and the framing's payload length are checked by the
/// caller. Written not to panic whatever `plain` holds; the Kani harness in
/// `kani_proofs.rs` (every length up to a short filename) and the envelope
/// property tests exercise that.
///
/// The length of the input fixes where every field lies, so it is checked
/// first: the filename is what the fixed fields leave, and its declared
/// length byte must say the same. Each later step tests its `Option` with
/// `let ... else`. `ok_or(..)?` would refuse the same inputs, but the model
/// checker behind Kani does not see through it that a refused input stops
/// there: it goes on into the filename loops with lengths it cannot bound,
/// and the harness no longer finishes.
///
/// The layout rules are then checked on the parts as read, and the trailer
/// is assembled only once they hold. A refused trailer is never copied out
/// of the input, so the refusal path has nothing to wipe; that also keeps the
/// wipe loops of a dropped trailer out of the Kani harness, which would
/// otherwise run them on every path through the decoder.
pub(crate) fn decode_plain(plain: &[u8]) -> Result<EnvelopeTrailer, EnvelopeError> {
    const TRUNCATED: EnvelopeError = EnvelopeError::Malformed("trailer truncated");
    let Some(name_len) = plain.len().checked_sub(TRAILER_FIXED_BYTES) else {
        return Err(TRUNCATED);
    };
    let Some((kind_byte, rest)) = plain.split_first() else {
        return Err(TRUNCATED);
    };
    let Some(kind) = EnvelopeKind::from_byte(*kind_byte) else {
        return Err(EnvelopeError::Malformed("unknown envelope kind"));
    };
    let Some((report_id, rest)) = rest.split_first_chunk::<REPORT_ID_BYTES>() else {
        return Err(TRUNCATED);
    };
    let Some((report_pk, rest)) = rest.split_first_chunk::<PK_BYTES>() else {
        return Err(TRUNCATED);
    };
    let Some((signature, rest)) = rest.split_first_chunk::<SIG_BYTES>() else {
        return Err(TRUNCATED);
    };
    let Some((create_sig, rest)) = rest.split_first_chunk::<SIG_BYTES>() else {
        return Err(TRUNCATED);
    };
    let Some((seq_limit, rest)) = rest.split_first_chunk::<4>() else {
        return Err(TRUNCATED);
    };
    let Some((declared_name_len, rest)) = rest.split_first() else {
        return Err(TRUNCATED);
    };
    if usize::from(*declared_name_len) != name_len {
        return Err(EnvelopeError::Malformed(
            "trailer length does not match its filename length",
        ));
    }
    let Some((name, rest)) = rest.split_at_checked(name_len) else {
        return Err(TRUNCATED);
    };
    let Some((payload_len, rest)) = rest.split_first_chunk::<8>() else {
        return Err(TRUNCATED);
    };
    let Some((payload_sha256, _)) = rest.split_first_chunk::<HASH_BYTES>() else {
        return Err(TRUNCATED);
    };
    let create_sig = (*create_sig != [0u8; SIG_BYTES]).then_some(create_sig);
    let seq_limit = u32::from_be_bytes(*seq_limit);
    let payload_len = u64::from_be_bytes(*payload_len);
    if let Some(rule) = fields_rule_violation(kind, create_sig, seq_limit, name)
        .or_else(|| payload_rule_violation(kind, seq_limit, payload_len))
    {
        return Err(EnvelopeError::Malformed(rule));
    }
    let Some(filename) = filename_from_bytes(name) else {
        return Err(EnvelopeError::Malformed(
            "filename is not a relay object name",
        ));
    };
    Ok(EnvelopeTrailer {
        fields: EnvelopeFields {
            kind,
            report_pk: *report_pk,
            signature: *signature,
            create_sig: create_sig.copied(),
            seq_limit,
            filename,
        },
        report_id: *report_id,
        payload_len,
        payload_sha256: *payload_sha256,
    })
}

/// The trailer's filename bytes as a string, or `None` if a byte is outside
/// the relay alphabet. Only the alphabet is checked here; the full name rule
/// (length, `.`, `..`, the reserved name, empty for a closure) is
/// [`fields_rule_violation`]. The decoder calls this only once the name has
/// passed that rule, so the check cannot fail there; it stays because it is
/// what makes the conversion exact.
///
/// The bytes are checked before any conversion, and the conversion maps each
/// byte to one character. Keep the check in front of it: it is what makes
/// the conversion exact, since the conversion then only ever sees ASCII,
/// where a byte and a character are the same thing, and a name with any other
/// byte is refused here rather than turned into a different string. Going
/// through `str::from_utf8` would accept the same names, but its validation
/// loops advance by a step that depends on the bytes, which the model checker
/// unrolls to its global bound: the Kani harness over the decoder then no
/// longer finishes.
///
/// The string is allocated once at its final size: a reallocation would
/// leave an unwiped copy of the name behind.
fn filename_from_bytes(name: &[u8]) -> Option<String> {
    if !name.iter().all(|&byte| is_relay_name_byte(byte)) {
        return None;
    }
    let mut filename = String::with_capacity(name.len());
    filename.extend(name.iter().map(|&byte| char::from(byte)));
    Some(filename)
}

#[cfg(test)]
pub(crate) mod test_support {
    //! Deterministic report keys and signatures for envelope tests, built on
    //! the legacy keyring of a fixed test phrase.

    use super::{EnvelopeFields, EnvelopeKind};
    use frappuccino_crypto_core::report::{Manifest, ManifestEntry, ReportKeyring};
    use sha2::{Digest, Sha256};

    /// The fixed test phrase of the core report KATs.
    pub(crate) const MN_FIXED: &str = "abaisser abandon abdiquer abeille abolir aborder aboutir \
         aboyer abrasif abreuver abriter abroger";

    pub(crate) fn keyring() -> ReportKeyring {
        ReportKeyring::from_mnemonic(MN_FIXED, "").unwrap()
    }

    pub(crate) fn sha256(bytes: &[u8]) -> [u8; 32] {
        Sha256::digest(bytes).into()
    }

    /// Fields of a validly signed object envelope for `payload`.
    pub(crate) fn object_fields(
        kind: EnvelopeKind,
        filename: &str,
        payload: &[u8],
        with_create: bool,
    ) -> EnvelopeFields {
        let ring = keyring();
        let pk = ring.report_pk(3).unwrap();
        let write_sig = ring
            .sign_write(3, filename.as_bytes(), &sha256(payload))
            .unwrap();
        let create = with_create.then(|| ring.sign_create(3).unwrap());
        EnvelopeFields::object(kind, pk, filename, write_sig, create).unwrap()
    }

    /// A non-empty manifest and its validly signed closure fields, signed by
    /// a chained report writer.
    pub(crate) fn closure_fields() -> (Vec<u8>, EnvelopeFields) {
        use frappuccino_crypto_core::report::ReportDeviceState;
        let mut state = ReportDeviceState::from_mnemonic(MN_FIXED, "").unwrap();
        let opening = state.open_report().unwrap();
        let mut writer = opening.release_after_persist(|_| Ok::<(), ()>(())).unwrap();
        let meta = writer.prepare_metadata(&[1u8; 32], &[2u8; 32]).unwrap();
        writer.commit(meta).unwrap();
        let chunk = writer.prepare_chunk(4, &[3u8; 32], &[4u8; 32]).unwrap();
        writer.commit(chunk).unwrap();
        let close = writer.prepare_close().unwrap();
        let manifest = close.manifest().to_vec();
        let fields = EnvelopeFields::closure(
            *close.report_pk(),
            close.seq_limit(),
            *close.close_sig(),
            Some(*close.create_sig()),
        )
        .unwrap();
        // Same bytes the core writer produced.
        let expected = Manifest::from_entries(vec![
            ManifestEntry {
                seq: 0,
                blob_sha256: [2u8; 32],
            },
            ManifestEntry {
                seq: 4,
                blob_sha256: [4u8; 32],
            },
        ])
        .unwrap();
        assert_eq!(manifest, expected.to_bytes());
        (manifest, fields)
    }

    /// The empty manifest and the legacy closure fields of index 3.
    pub(crate) fn legacy_closure_fields() -> (Vec<u8>, EnvelopeFields) {
        let ring = keyring();
        let close_sig = ring.sign_legacy_close(3).unwrap();
        let fields =
            EnvelopeFields::closure(ring.report_pk(3).unwrap(), 0, close_sig, None).unwrap();
        (Manifest::empty().to_bytes(), fields)
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::*;
    use super::*;

    fn key() -> QueueKey {
        QueueKey::from_bytes(&[0x42u8; 32]).unwrap()
    }

    /// A whole envelope in memory.
    fn envelope(payload: &[u8], fields: EnvelopeFields) -> Vec<u8> {
        let trailer = EnvelopeTrailer::for_payload(fields, payload).unwrap();
        let mut bytes = payload.to_vec();
        bytes.extend_from_slice(&trailer.seal(&key()).unwrap());
        bytes
    }

    fn open_bytes(bytes: &[u8]) -> Result<EnvelopeTrailer, EnvelopeError> {
        let start = bytes.len().saturating_sub(MAX_TAIL_BYTES);
        EnvelopeTrailer::open(bytes.len() as u64, &bytes[start..], &key())
    }

    #[test]
    fn layout_constants_are_the_documented_sizes() {
        assert_eq!(TRAILER_FIXED_BYTES, 222);
        assert_eq!(MIN_SEALED_TRAILER_BYTES, 262);
        assert_eq!(MAX_SEALED_TRAILER_BYTES, 390);
        assert_eq!(max_manifest_bytes(), 36_000_008);
    }

    #[test]
    fn object_roundtrip_keeps_every_field() {
        let payload = b"STRM chunk bytes";
        let fields = object_fields(EnvelopeKind::Chunk, "000001.strm", payload, true);
        let bytes = envelope(payload, fields.clone());
        let trailer = open_bytes(&bytes).unwrap();
        assert_eq!(trailer.kind(), EnvelopeKind::Chunk);
        assert_eq!(trailer.filename(), "000001.strm");
        assert_eq!(trailer.payload_len(), payload.len() as u64);
        assert_eq!(trailer.payload_sha256(), &sha256(payload));
        assert_eq!(trailer.report_pk(), &fields.report_pk);
        assert_eq!(trailer.report_id(), &report_id_from_pk(&fields.report_pk));
        assert_eq!(trailer.report_id_hex().len(), 32);
        assert!(trailer.create_sig().is_some());
        assert_eq!(trailer.seq_limit(), 0);
        assert!(!trailer.needs_drain());
        trailer.verify_signatures(None).unwrap();
        // The file layout: payload first, then the sealed trailer, its length
        // and the magic.
        assert!(bytes.starts_with(payload));
        assert!(bytes.ends_with(b"FQE1"));
        let sealed_len =
            u32::from_be_bytes(bytes[bytes.len() - 8..bytes.len() - 4].try_into().unwrap());
        assert_eq!(
            sealed_len as usize,
            MIN_SEALED_TRAILER_BYTES + "000001.strm".len()
        );
    }

    #[test]
    fn closures_roundtrip_and_flag_the_legacy_ones() {
        let (manifest, fields) = closure_fields();
        let trailer = open_bytes(&envelope(&manifest, fields)).unwrap();
        assert_eq!(trailer.kind(), EnvelopeKind::Closure);
        assert_eq!(trailer.filename(), "");
        assert_eq!(trailer.seq_limit(), 5);
        assert!(!trailer.needs_drain());
        trailer.verify_signatures(Some(&manifest)).unwrap();

        let (empty, legacy) = legacy_closure_fields();
        let trailer = open_bytes(&envelope(&empty, legacy)).unwrap();
        assert!(trailer.needs_drain());
        assert!(trailer.create_sig().is_none());
        trailer.verify_signatures(Some(&empty)).unwrap();
    }

    #[test]
    fn producing_refuses_a_signature_that_does_not_cover_the_payload() {
        let fields = object_fields(EnvelopeKind::Chunk, "000001.strm", b"signed bytes", false);
        let error = EnvelopeTrailer::for_payload(fields, b"other bytes").unwrap_err();
        assert!(matches!(
            error,
            EnvelopeError::Verification(ReportError::InvalidSignature)
        ));

        let (manifest, fields) = closure_fields();
        let mut forged = manifest.clone();
        forged[10] ^= 1;
        assert!(matches!(
            EnvelopeTrailer::for_payload(fields, &forged).unwrap_err(),
            EnvelopeError::Verification(_)
        ));
    }

    #[test]
    fn field_rules_are_enforced_at_construction() {
        let pk = [7u8; 32];
        let sig = [9u8; 64];
        for bad in [
            "",
            ".",
            "..",
            "a/b",
            "a..b",
            "manifest",
            "é.strm",
            &"a".repeat(129),
        ] {
            assert!(
                EnvelopeFields::object(EnvelopeKind::Chunk, pk, bad, sig, None).is_err(),
                "{bad:?}"
            );
        }
        assert!(EnvelopeFields::object(EnvelopeKind::Closure, pk, "x", sig, None).is_err());
        assert!(
            EnvelopeFields::object(EnvelopeKind::Chunk, pk, "x", sig, Some([0u8; 64])).is_err()
        );
        assert!(EnvelopeFields::closure(pk, MAX_SEQ_LIMIT + 1, sig, None).is_err());
        assert!(EnvelopeFields::closure(pk, MAX_SEQ_LIMIT, sig, None).is_ok());
        assert!(EnvelopeFields::object(
            EnvelopeKind::TimestampProof,
            pk,
            &"a".repeat(128),
            sig,
            None
        )
        .is_ok());
    }

    #[test]
    fn payload_sizes_are_checked_per_kind() {
        // An empty object payload.
        let fields = object_fields(EnvelopeKind::DirectoryEntry, "abc", b"", false);
        assert!(matches!(
            EnvelopeTrailer::for_payload(fields, b"").unwrap_err(),
            EnvelopeError::InvalidFields(_)
        ));
        // A closure whose seq_limit cannot match its manifest's size.
        let (manifest, fields) = closure_fields();
        let wrong = EnvelopeFields::closure(fields.report_pk, 0, fields.signature, None).unwrap();
        assert!(matches!(
            EnvelopeTrailer::for_payload(wrong, &manifest).unwrap_err(),
            EnvelopeError::InvalidFields(_)
        ));
        // A closure payload that is not a manifest's size.
        let odd = EnvelopeFields::closure(fields.report_pk, 5, fields.signature, None).unwrap();
        assert!(EnvelopeTrailer::for_payload(odd, &manifest[..manifest.len() - 1]).is_err());
    }

    #[test]
    fn tampering_anywhere_in_the_trailer_or_footer_is_refused() {
        let payload = b"payload bytes";
        let bytes = envelope(
            payload,
            object_fields(EnvelopeKind::Chunk, "x.strm", payload, false),
        );
        let trailer_start = payload.len();
        for position in trailer_start..bytes.len() {
            let mut forged = bytes.clone();
            forged[position] ^= 0x01;
            assert!(open_bytes(&forged).is_err(), "flip at {position} accepted");
        }
    }

    #[test]
    fn the_aad_binds_the_payload_length() {
        let payload = b"payload bytes";
        let bytes = envelope(
            payload,
            object_fields(EnvelopeKind::Chunk, "x.strm", payload, false),
        );
        // One byte more or less in front of an intact trailer.
        let mut longer = vec![0u8];
        longer.extend_from_slice(&bytes);
        assert_eq!(
            open_bytes(&longer).unwrap_err(),
            EnvelopeError::Undecryptable
        );
        assert_eq!(
            open_bytes(&bytes[1..]).unwrap_err(),
            EnvelopeError::Undecryptable
        );
    }

    #[test]
    fn another_key_cannot_open_the_trailer() {
        let payload = b"p";
        let bytes = envelope(
            payload,
            object_fields(EnvelopeKind::Chunk, "x", payload, false),
        );
        let other = QueueKey::from_bytes(&[0x43u8; 32]).unwrap();
        let start = bytes.len().saturating_sub(MAX_TAIL_BYTES);
        assert_eq!(
            EnvelopeTrailer::open(bytes.len() as u64, &bytes[start..], &other).unwrap_err(),
            EnvelopeError::Undecryptable
        );
    }

    #[test]
    fn framing_errors_are_reported_without_decrypting() {
        assert_eq!(open_bytes(b"").unwrap_err(), EnvelopeError::NoTrailer);
        assert_eq!(open_bytes(b"short").unwrap_err(), EnvelopeError::NoTrailer);
        assert_eq!(
            open_bytes(&[0u8; 500]).unwrap_err(),
            EnvelopeError::NoTrailer
        );
        let mut too_small = vec![0u8; 300];
        too_small.extend_from_slice(&261u32.to_be_bytes());
        too_small.extend_from_slice(b"FQE1");
        assert!(matches!(
            open_bytes(&too_small).unwrap_err(),
            EnvelopeError::Malformed(_)
        ));
        let mut too_big = vec![0u8; 500];
        too_big.extend_from_slice(&391u32.to_be_bytes());
        too_big.extend_from_slice(b"FQE1");
        assert!(matches!(
            open_bytes(&too_big).unwrap_err(),
            EnvelopeError::Malformed(_)
        ));
        let mut longer_than_file = vec![0u8; 100];
        longer_than_file.extend_from_slice(&300u32.to_be_bytes());
        longer_than_file.extend_from_slice(b"FQE1");
        assert!(matches!(
            open_bytes(&longer_than_file).unwrap_err(),
            EnvelopeError::Malformed(_)
        ));
        // A tail claimed to be longer than its file.
        assert!(matches!(
            EnvelopeTrailer::open(3, b"FQE1FQE1", &key()).unwrap_err(),
            EnvelopeError::Malformed(_)
        ));
    }

    /// Seal an arbitrary plaintext as if it were a trailer, so the decoder's
    /// own checks are reached past the AEAD.
    fn seal_plain(plain: &[u8], payload_len: u64) -> Vec<u8> {
        let nonce = [5u8; NONCE_BYTES];
        let ct = key()
            .cipher()
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: plain,
                    aad: &trailer_aad(payload_len),
                },
            )
            .unwrap();
        let mut bytes = vec![0xAAu8; usize::try_from(payload_len).unwrap()];
        bytes.extend_from_slice(&nonce);
        bytes.extend_from_slice(&ct);
        bytes.extend_from_slice(&u32::try_from(NONCE_BYTES + ct.len()).unwrap().to_be_bytes());
        bytes.extend_from_slice(b"FQE1");
        bytes
    }

    fn valid_plain() -> (Vec<u8>, u64) {
        let payload = b"0123456789";
        let fields = object_fields(EnvelopeKind::Chunk, "000002.strm", payload, false);
        let trailer = EnvelopeTrailer::for_payload(fields, payload).unwrap();
        (
            trailer.encode_plain().unwrap().to_vec(),
            payload.len() as u64,
        )
    }

    #[test]
    fn the_decoder_rejects_each_layout_violation() {
        let (plain, payload_len) = valid_plain();
        assert!(open_bytes(&seal_plain(&plain, payload_len)).is_ok());

        let mut bad_kind = plain.clone();
        bad_kind[0] = 9;
        assert_eq!(
            open_bytes(&seal_plain(&bad_kind, payload_len)).unwrap_err(),
            EnvelopeError::Malformed("unknown envelope kind")
        );

        let mut wrong_rid = plain.clone();
        wrong_rid[1] ^= 1;
        assert_eq!(
            open_bytes(&seal_plain(&wrong_rid, payload_len)).unwrap_err(),
            EnvelopeError::ReportIdMismatch
        );

        let name_len_at = 1 + 16 + 32 + 64 + 64 + 4;
        let mut long_name = plain.clone();
        long_name[name_len_at] += 1;
        assert!(matches!(
            open_bytes(&seal_plain(&long_name, payload_len)).unwrap_err(),
            EnvelopeError::Malformed(_)
        ));

        let mut bad_name = plain.clone();
        bad_name[name_len_at + 1] = b'/';
        assert!(matches!(
            open_bytes(&seal_plain(&bad_name, payload_len)).unwrap_err(),
            EnvelopeError::Malformed(_)
        ));

        let mut seq_limit_on_object = plain.clone();
        seq_limit_on_object[name_len_at - 1] = 1;
        assert!(matches!(
            open_bytes(&seal_plain(&seq_limit_on_object, payload_len)).unwrap_err(),
            EnvelopeError::Malformed(_)
        ));

        // The trailer's own payload length disagrees with the framing.
        let len_at = plain.len() - 32 - 8;
        let mut other_len = plain.clone();
        other_len[len_at + 7] ^= 1;
        assert!(matches!(
            open_bytes(&seal_plain(&other_len, payload_len)).unwrap_err(),
            EnvelopeError::Malformed(_)
        ));

        let truncated = &plain[..plain.len() - 1];
        assert!(matches!(
            open_bytes(&seal_plain(truncated, payload_len)).unwrap_err(),
            EnvelopeError::Malformed(_)
        ));
    }

    /// The filename comes out as the exact bytes of the trailer, and a byte
    /// outside the relay alphabet is refused, whether or not it is valid
    /// UTF-8.
    #[test]
    fn the_decoder_keeps_the_filename_bytes_and_refuses_any_other() {
        let (plain, payload_len) = valid_plain();
        let name_at = 1 + 16 + 32 + 64 + 64 + 4 + 1;
        let name = &plain[name_at..name_at + "000002.strm".len()];
        let trailer = open_bytes(&seal_plain(&plain, payload_len)).unwrap();
        assert_eq!(trailer.filename().as_bytes(), name);

        let refused = EnvelopeError::Malformed("filename is not a name the relay accepts");
        for byte in [0x00, b' ', b'/', b'%', 0x7f, 0x80, 0xc3, 0xe9, 0xff] {
            let mut bad = plain.clone();
            bad[name_at + 3] = byte;
            assert_eq!(
                open_bytes(&seal_plain(&bad, payload_len)).unwrap_err(),
                refused,
                "byte {byte:#04x}"
            );
        }
        // "é" in UTF-8, the same length as the bytes it replaces.
        let mut accented = plain.clone();
        accented[name_at..name_at + 2].copy_from_slice("é".as_bytes());
        assert_eq!(
            open_bytes(&seal_plain(&accented, payload_len)).unwrap_err(),
            refused
        );
        // The reserved name, beyond the filename bound of the Kani harness.
        let mut reserved = plain[..name_at - 1].to_vec();
        reserved.push(8);
        reserved.extend_from_slice(b"manifest");
        reserved.extend_from_slice(&plain[plain.len() - 40..]);
        assert_eq!(
            open_bytes(&seal_plain(&reserved, payload_len)).unwrap_err(),
            refused
        );
    }

    /// The conversion behind the decoder's filename: every byte of the relay
    /// alphabet comes out as itself, and every other byte, including the
    /// ones that would map to a two-byte character, is refused.
    #[test]
    fn filename_conversion_is_exact_and_refuses_bytes_outside_the_alphabet() {
        for byte in 0..=u8::MAX {
            match filename_from_bytes(&[b'a', byte, b'z']) {
                Some(name) => {
                    assert!(is_relay_name_byte(byte), "byte {byte:#04x} accepted");
                    assert_eq!(name.as_bytes(), [b'a', byte, b'z'], "byte {byte:#04x}");
                }
                None => assert!(!is_relay_name_byte(byte), "byte {byte:#04x} refused"),
            }
        }
        assert_eq!(filename_from_bytes(b"").as_deref(), Some(""));
    }

    #[test]
    fn queue_keys_are_checked_and_redacted() {
        assert_eq!(
            QueueKey::from_bytes(&[0u8; 31]).unwrap_err(),
            EnvelopeError::InvalidQueueKey
        );
        assert_eq!(
            QueueKey::from_bytes(&[0u8; 33]).unwrap_err(),
            EnvelopeError::InvalidQueueKey
        );
        let generated = QueueKey::generate().unwrap();
        let other = QueueKey::generate().unwrap();
        assert_ne!(generated.expose(|k| *k), other.expose(|k| *k));
        assert_eq!(format!("{generated:?}"), "QueueKey(<redacted>)");
        let debug = format!(
            "{:?}",
            object_fields(EnvelopeKind::Chunk, "000777.strm", b"p", true)
        );
        assert!(!debug.contains("000777"), "{debug}");
    }

    #[test]
    fn kinds_have_stable_wire_bytes() {
        for (kind, byte) in [
            (EnvelopeKind::Chunk, 1),
            (EnvelopeKind::DirectoryEntry, 2),
            (EnvelopeKind::Closure, 3),
            (EnvelopeKind::TimestampProof, 4),
        ] {
            assert_eq!(kind.to_byte(), byte);
            assert_eq!(EnvelopeKind::from_byte(byte), Some(kind));
        }
        assert_eq!(EnvelopeKind::from_byte(0), None);
        assert_eq!(EnvelopeKind::from_byte(5), None);
    }

    #[test]
    fn corruption_is_classified() {
        assert!(EnvelopeError::Undecryptable.is_corrupt());
        assert!(EnvelopeError::Verification(ReportError::InvalidSignature).is_corrupt());
        assert!(!EnvelopeError::NotFound.is_corrupt());
        assert!(!EnvelopeError::Signing(ReportError::InvalidSignature).is_corrupt());
        assert!(!EnvelopeError::NoCreateSig.is_corrupt());
    }
}
