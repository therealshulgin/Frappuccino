//! STRM blob encryption — self-sealed streams addressable only by the
//! archive identity of the same BIP-39 phrase.
//!
//! The encoder writes a `VERSION_V3` blob with `grant_count = 0` (the STRM
//! format never adds extra recipients in-blob — sharing goes through a
//! future server-side re-sealing primitive). V3 carries NO author identity at
//! rest (F-C1 fix): the header is `MAGIC ‖ V3 ‖ sealed_session_key ‖
//! grant_count`. For the CHUNKED mode it binds `chunk_count` into the AEAD's
//! AAD so a truncation attack (dropping trailing chunks + patching the
//! `chunk_count` field) is rejected — V1 accepted it silently.

use crate::header::{
    CHUNK_SIZE, CHUNK_THRESHOLD, HEADER_SIZE_NO_GRANTS, MAGIC, MAX_CHUNK_COUNT, MODE_CHUNKED,
    MODE_SINGLE, NONCE_BYTES, NONCE_PREFIX_BYTES, OFF_GRANT_COUNT, OFF_MAGIC, OFF_SEALED,
    OFF_VERSION, SEALED_ENVELOPE_SIZE, SESSION_KEY_BYTES, VERSION_CURRENT,
};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use frappuccino_crypto_core::identity::StreamIdentity;
use frappuccino_crypto_core::seal;
use frappuccino_crypto_core::CryptoError;
use rand_core::{OsRng, RngCore};
use zeroize::Zeroize;

/// Specific error type for the encrypt path. Mirrors `DecryptError`'s layout.
#[derive(Debug, thiserror::Error)]
pub enum EncryptError {
    #[error(transparent)]
    Core(#[from] CryptoError),
    #[error("AEAD encryption failed: {0}")]
    Aead(String),
    #[error("plaintext too large: {chunks} chunks exceeds MAX_CHUNK_COUNT = {max}")]
    TooLarge { chunks: u64, max: u32 },
}

/// Encrypt `plaintext` in mode SINGLE for the given `author` identity.
///
/// The author is also the only recipient (`grant_count` = 0). Use
/// [`encrypt_chunked`] for payloads that should be streamed chunk-by-chunk
/// (video capture, large files).
///
/// # Errors
/// Returns an [`EncryptError::Core`] if the sealed envelope can't be built,
/// or [`EncryptError::Aead`] if XChaCha20-Poly1305 encryption fails (never
/// in practice).
pub fn encrypt_single(plaintext: &[u8], author: &StreamIdentity) -> Result<Vec<u8>, EncryptError> {
    // 1. Fresh 32-byte session key (wipe on function exit via Zeroize).
    let mut session_key = [0u8; SESSION_KEY_BYTES];
    OsRng.fill_bytes(&mut session_key);

    // 2. Header (sealed session key + grant_count=0; V3 carries no author
    //    identity at rest).
    let mut header = Vec::with_capacity(HEADER_SIZE_NO_GRANTS);
    write_header_prefix(&mut header, author, &session_key)?;

    // 3. Body: mode byte + nonce + ct. AAD is the header bytes verbatim.
    let mut nonce = [0u8; NONCE_BYTES];
    OsRng.fill_bytes(&mut nonce);
    let cipher = XChaCha20Poly1305::new(session_key.as_slice().into());
    let ct = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &header,
            },
        )
        .map_err(|e| EncryptError::Aead(e.to_string()))?;

    session_key.zeroize();

    let mut blob = header;
    blob.push(MODE_SINGLE);
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&ct);
    Ok(blob)
}

/// Encrypt `plaintext` in mode CHUNKED with [`CHUNK_SIZE`] chunks.
///
/// Emits a `VERSION_V3` blob — the AAD of every chunk binds
/// `chunk_count` explicitly so a truncation attack (dropping trailing chunks)
/// is rejected by the decoder.
///
/// # Errors
/// * [`EncryptError::Core`] if the sealed envelope can't be built.
/// * [`EncryptError::Aead`] if `XChaCha20-Poly1305` encryption fails.
/// * [`EncryptError::TooLarge`] if the plaintext would need more than
///   [`MAX_CHUNK_COUNT`] chunks (≥ 1 TiB in practice).
///
/// # Panics
/// Cannot panic in practice: `NONCE_BYTES + ct.len()` is bounded by
/// `MAX_CHUNK_LEN = 2 MiB`, which fits in `u32`.
pub fn encrypt_chunked(plaintext: &[u8], author: &StreamIdentity) -> Result<Vec<u8>, EncryptError> {
    // chunk_count is part of the AAD, so it must be known before encrypting
    // the first chunk. ceil(len / CHUNK_SIZE) — zero for empty plaintext.
    let chunks_u64 = (plaintext.len() as u64).div_ceil(CHUNK_SIZE as u64);
    let chunk_count = u32::try_from(chunks_u64).map_err(|_| EncryptError::TooLarge {
        chunks: chunks_u64,
        max: MAX_CHUNK_COUNT,
    })?;
    if chunk_count > MAX_CHUNK_COUNT {
        return Err(EncryptError::TooLarge {
            chunks: chunks_u64,
            max: MAX_CHUNK_COUNT,
        });
    }

    let mut session_key = [0u8; SESSION_KEY_BYTES];
    OsRng.fill_bytes(&mut session_key);

    let mut header = Vec::with_capacity(HEADER_SIZE_NO_GRANTS);
    write_header_prefix(&mut header, author, &session_key)?;

    // Shared random prefix for all chunks of this stream.
    let mut nonce_prefix = [0u8; NONCE_PREFIX_BYTES];
    OsRng.fill_bytes(&mut nonce_prefix);

    // V2/V3 AAD = header ‖ MODE_CHUNKED ‖ nonce_prefix ‖ chunk_count (BE u32).
    let aad = build_chunked_aad(&header, &nonce_prefix, chunk_count);

    let cipher = XChaCha20Poly1305::new(session_key.as_slice().into());
    let mut chunks_bytes = Vec::new();
    let mut chunk_index: u32 = 0;
    let mut offset = 0;
    while offset < plaintext.len() {
        let end = (offset + CHUNK_SIZE).min(plaintext.len());
        let plain = &plaintext[offset..end];

        // nonce = prefix || chunk_index_BE(4).
        let mut nonce = [0u8; NONCE_BYTES];
        nonce[..NONCE_PREFIX_BYTES].copy_from_slice(&nonce_prefix);
        nonce[NONCE_PREFIX_BYTES..].copy_from_slice(&chunk_index.to_be_bytes());

        let ct = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: plain,
                    aad: &aad,
                },
            )
            .map_err(|e| EncryptError::Aead(e.to_string()))?;

        // Chunk frame = total_len(u32 BE = nonce+ct) || nonce || ct.
        let total_len = u32::try_from(NONCE_BYTES + ct.len())
            .expect("chunk len fits in u32 (ct <= MAX_CHUNK_LEN)");
        chunks_bytes.extend_from_slice(&total_len.to_be_bytes());
        chunks_bytes.extend_from_slice(&nonce);
        chunks_bytes.extend_from_slice(&ct);

        chunk_index += 1;
        offset = end;
    }
    debug_assert_eq!(chunk_index, chunk_count);
    session_key.zeroize();

    let mut blob = header;
    blob.push(MODE_CHUNKED);
    blob.extend_from_slice(&nonce_prefix);
    blob.extend_from_slice(&chunk_count.to_be_bytes());
    blob.extend_from_slice(&chunks_bytes);
    Ok(blob)
}

/// Pick SINGLE or CHUNKED based on the Kotlin threshold (`<= 10 MiB = SINGLE`).
/// Convenience wrapper when the caller doesn't want to think about modes.
///
/// # Errors
/// Forwards from [`encrypt_single`] / [`encrypt_chunked`].
pub fn encrypt(plaintext: &[u8], author: &StreamIdentity) -> Result<Vec<u8>, EncryptError> {
    if plaintext.len() as u64 <= CHUNK_THRESHOLD {
        encrypt_single(plaintext, author)
    } else {
        encrypt_chunked(plaintext, author)
    }
}

// ============================================================================
// Helpers
// ============================================================================

fn write_header_prefix(
    out: &mut Vec<u8>,
    author: &StreamIdentity,
    session_key: &[u8; 32],
) -> Result<(), EncryptError> {
    debug_assert_eq!(out.len(), OFF_MAGIC);
    out.extend_from_slice(&MAGIC);
    debug_assert_eq!(out.len(), OFF_VERSION);
    out.push(VERSION_CURRENT);

    // V3: the sealed session key follows the version byte directly. The
    // author's long-term Ed25519 identity is deliberately NOT written (F-C1):
    // keeping it at rest let a relay-disk seizure map report_id -> identity
    // with zero keys. `author` is still needed for its X25519 public key (the
    // seal recipient) — nothing else.
    debug_assert_eq!(out.len(), OFF_SEALED);
    let sealed = seal::seal(session_key, author.x25519_pk())?;
    assert_eq!(sealed.len(), SEALED_ENVELOPE_SIZE);
    out.extend_from_slice(&sealed);

    // grant_count = 0 (the STRM format never adds grants in-blob).
    debug_assert_eq!(out.len(), OFF_GRANT_COUNT);
    out.extend_from_slice(&[0u8; 2]);
    debug_assert_eq!(out.len(), HEADER_SIZE_NO_GRANTS);
    Ok(())
}

/// Build the extended AAD used by `VERSION_V2`/`VERSION_V3` chunked blobs.
/// Shared between [`encrypt_chunked`] and [`crate::decrypt::decrypt`] so any
/// drift would show up as AEAD failures in tests immediately. (V2 and V3 share
/// the construction — only the embedded `header_bytes` differ in length.)
///
/// Layout: `header_bytes ‖ MODE_CHUNKED ‖ nonce_prefix ‖ chunk_count_BE_u32`.
pub(crate) fn build_chunked_aad(
    header: &[u8],
    nonce_prefix: &[u8; NONCE_PREFIX_BYTES],
    chunk_count: u32,
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(header.len() + 1 + NONCE_PREFIX_BYTES + 4);
    aad.extend_from_slice(header);
    aad.push(MODE_CHUNKED);
    aad.extend_from_slice(nonce_prefix);
    aad.extend_from_slice(&chunk_count.to_be_bytes());
    aad
}
