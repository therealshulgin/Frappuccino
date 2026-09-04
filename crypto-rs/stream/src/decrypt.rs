//! STRM blob decryption — the archive-mode entry point.
//!
//! Accepts a blob produced by either our [`crate::encrypt`] or the Kotlin
//! `SovereignEncryptor`, and recovers the plaintext after authenticating
//! every byte of the header via the AEAD tag.

use crate::encrypt::build_chunked_aad;
use crate::header::{
    self, AEAD_TAG_BYTES, CHUNK_THRESHOLD, ED25519_PK_BYTES, MAX_CHUNK_COUNT, MAX_CHUNK_LEN,
    MODE_CHUNKED, MODE_SINGLE, NONCE_BYTES, NONCE_PREFIX_BYTES, SEALED_ENVELOPE_SIZE, VERSION_V2,
    VERSION_V3,
};
// Only the `legacy-strm` build has a match arm for V1, so importing the constant
// unconditionally would be an unused import in the shipped configuration.
#[cfg(feature = "legacy-strm")]
use crate::header::VERSION_V1;
// VERSION_V1/V2/V3 are re-exported by `parse_header`; keeping them imported
// here makes the `decrypt_chunked` dispatch on `version` self-documenting.
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use frappuccino_crypto_core::identity::ArchiveIdentity;
use frappuccino_crypto_core::CryptoError;
use zeroize::Zeroizing;

/// Error type specific to STRM decoding paths. Mostly a thin wrapper over
/// [`CryptoError`] so the caller can pattern-match on structural problems
/// without parsing error strings.
#[derive(Debug, thiserror::Error)]
pub enum DecryptError {
    /// Wraps any error bubbling up from the crypto core.
    #[error(transparent)]
    Core(#[from] CryptoError),
    /// The blob was not well-formed (bad magic, wrong version, truncated, …).
    #[error("malformed STRM blob: {0}")]
    Malformed(String),
}

/// Non-secret metadata about a decrypted blob, useful for the caller's UI /
/// audit log. Returned alongside the plaintext.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlobMetadata {
    /// STRM format version — `VERSION_V1` (legacy Kotlin SINGLE), `VERSION_V2`
    /// (previous Rust encoder), or `VERSION_V3` (current — no author identity
    /// at rest).
    pub version: u8,
    /// `MODE_SINGLE` or `MODE_CHUNKED`.
    pub mode: u8,
    /// The Ed25519 public key of the author — `Some` for legacy V1/V2 blobs,
    /// `None` for V3 (the identity is no longer written at rest; F-C1).
    /// Informational only — never used to decrypt.
    pub author_ed25519_pk: Option<[u8; ED25519_PK_BYTES]>,
    /// Number of additional grants in the header. Always 0: a blob declaring
    /// one is refused by `parse_header`, so this only ever reports 0.
    pub grant_count: u16,
    /// Total plaintext bytes recovered.
    pub plaintext_len: usize,
}

/// Decrypt `blob` under `archive` and return `(plaintext, metadata)`.
///
/// The plaintext is wrapped in `Zeroizing` so it wipes on drop when the
/// caller's binding goes out of scope.
///
/// # Errors
/// * [`DecryptError::Malformed`] for structural errors (wrong magic, wrong
///   version, truncated blob, invalid chunk count).
/// * [`DecryptError::Core`] wrapping [`CryptoError::WrongPin`] if the sealed
///   envelope wasn't for this archive identity, or any AEAD tag fails.
pub fn decrypt(
    blob: &[u8],
    archive: &ArchiveIdentity,
) -> Result<(Zeroizing<Vec<u8>>, BlobMetadata), DecryptError> {
    let parsed = header::parse_header(blob).map_err(|e| DecryptError::Malformed(e.to_string()))?;
    let version = parsed.version;
    let mode = parsed.mode;
    let author_pk = parsed.author_ed25519_pk;
    let grant_count = parsed.grant_count;

    // The sealed envelope offset is version-resolved by `parse_header`
    // (V3 = 5, legacy V1/V2 = 37) — never hard-code it here.
    let sealed = &blob[parsed.sealed_offset..parsed.sealed_offset + SEALED_ENVELOPE_SIZE];

    // AAD is the literal header bytes, matching the Kotlin
    // `SovereignEncryptor.writeBoth` semantics.
    let header_aad: &[u8] = &blob[..parsed.header_end];

    // Unseal session key. The 32-byte `K_s` wipes on drop of this Zeroizing.
    let session_key = archive.decrypt_session_key(sealed)?;
    if session_key.len() != 32 {
        return Err(DecryptError::Malformed("session key wrong size".into()));
    }
    let key_arr: [u8; 32] = session_key[..]
        .try_into()
        .map_err(|_| DecryptError::Malformed("session key slice".into()))?;

    let body = &blob[parsed.body_start..];
    let (plaintext, _sessionkey_lives_until_here) = match mode {
        MODE_SINGLE => decrypt_single(body, &key_arr, header_aad)?,
        MODE_CHUNKED => decrypt_chunked(body, &key_arr, header_aad, version)?,
        other => {
            return Err(DecryptError::Malformed(format!(
                "unknown mode byte {other:#x}"
            )))
        }
    };

    let plen = plaintext.len();
    Ok((
        plaintext,
        BlobMetadata {
            version,
            mode,
            author_ed25519_pk: author_pk,
            grant_count,
            plaintext_len: plen,
        },
    ))
}

// ============================================================================
// Mode SINGLE
// ============================================================================

fn decrypt_single(
    body: &[u8],
    key: &[u8; 32],
    aad: &[u8],
) -> Result<(Zeroizing<Vec<u8>>, ()), DecryptError> {
    if body.len() < NONCE_BYTES + AEAD_TAG_BYTES {
        return Err(DecryptError::Malformed(format!(
            "SINGLE body too short: {}",
            body.len()
        )));
    }
    // Phase 6.1.13 — defense-in-depth contre un blob SINGLE artificiellement
    // gonflé. Un blob SINGLE valide a forcément `body_len <= CHUNK_THRESHOLD
    // + NONCE_BYTES + AEAD_TAG_BYTES` (sinon il aurait été émis en CHUNKED
    // par encrypt.rs:170 qui split à CHUNK_THRESHOLD). Rejeter avant de
    // déclencher l'XChaCha20 alloue moins de mémoire et plante plus tôt si
    // un attaquant tente un DoS via un body de plusieurs Go.
    let max_single_body = usize::try_from(CHUNK_THRESHOLD)
        .expect("CHUNK_THRESHOLD (10 MiB) fits usize")
        + NONCE_BYTES
        + AEAD_TAG_BYTES;
    if body.len() > max_single_body {
        return Err(DecryptError::Malformed(format!(
            "SINGLE body too large: {} > {} (CHUNK_THRESHOLD + nonce + tag)",
            body.len(),
            max_single_body
        )));
    }
    let nonce = &body[..NONCE_BYTES];
    let ct = &body[NONCE_BYTES..];
    let cipher = XChaCha20Poly1305::new(key.as_slice().into());
    let plaintext = cipher
        .decrypt(XNonce::from_slice(nonce), Payload { msg: ct, aad })
        .map_err(|_| DecryptError::Core(CryptoError::WrongPin))?;
    Ok((Zeroizing::new(plaintext), ()))
}

// ============================================================================
// Mode CHUNKED
// ============================================================================

fn decrypt_chunked(
    body: &[u8],
    key: &[u8; 32],
    header_aad: &[u8],
    version: u8,
) -> Result<(Zeroizing<Vec<u8>>, ()), DecryptError> {
    if body.len() < NONCE_PREFIX_BYTES + 4 {
        return Err(DecryptError::Malformed("CHUNKED body too short".into()));
    }
    let mut nonce_prefix = [0u8; NONCE_PREFIX_BYTES];
    nonce_prefix.copy_from_slice(&body[..NONCE_PREFIX_BYTES]);
    let chunk_count_bytes: [u8; 4] = body[NONCE_PREFIX_BYTES..NONCE_PREFIX_BYTES + 4]
        .try_into()
        .map_err(|_| DecryptError::Malformed("chunk_count slice".into()))?;
    let chunk_count = u32::from_be_bytes(chunk_count_bytes);
    if chunk_count > MAX_CHUNK_COUNT {
        return Err(DecryptError::Malformed(format!(
            "chunk_count {chunk_count} exceeds cap {MAX_CHUNK_COUNT}"
        )));
    }

    // RT-02 fix: V1 CHUNKED is now rejected outright. The V1 AAD did not bind
    // `chunk_count`, so an attacker controlling the wire could drop trailing
    // chunks and have each remaining chunk still verify (every per-chunk AEAD
    // tag stays valid because the per-chunk nonce + AAD are unchanged). The
    // only V1 user we ever shipped was the pre-S5 Kotlin encoder which Rust
    // is now byte-replacing — historical V1 archives must go through
    // `frappuccino-cli migrate-v1-strm` (followup) before being read.
    //
    // V1 SINGLE remains accepted via decrypt_single — there is no truncation
    // surface there since the AAD is the whole header and the body is one
    // AEAD message.
    let owned_aad: Vec<u8>;
    let aad: &[u8] = match version {
        VERSION_V2 | VERSION_V3 => {
            owned_aad = build_chunked_aad(header_aad, &nonce_prefix, chunk_count);
            &owned_aad
        }
        // Only reachable with `legacy-strm` on; without it a V1 blob is refused
        // by `parse_header` long before here.
        #[cfg(feature = "legacy-strm")]
        VERSION_V1 => {
            return Err(DecryptError::Malformed(
                "V1 CHUNKED rejected since S9 — silent-truncation primitive (RT-02)".into(),
            ))
        }
        _ => {
            return Err(DecryptError::Malformed(format!(
                "unsupported version {version:#x} for CHUNKED"
            )))
        }
    };

    let cipher = XChaCha20Poly1305::new(key.as_slice().into());
    // RT-08: wrap the accumulator in `Zeroizing` from the start. With a bare
    // `Vec::new()`, every grow-and-realloc copies the plaintext into a fresh
    // allocation and frees the old buffer without zeroing it — for a 100 MB
    // stream that's ~7 leaked plaintext fragments (64 KB, 128 KB, …, 64 MB)
    // sitting in the heap until overwritten. `Zeroizing<Vec<u8>>` zeroes the
    // current buffer on drop; reallocs still leak, but the peak-final buffer
    // is at least clean at scope exit. A fully zero-leak path needs a custom
    // allocator and is tracked as a defense-in-depth follow-up.
    let mut out: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::new());
    let mut cursor = NONCE_PREFIX_BYTES + 4;

    for i in 0..chunk_count {
        if body.len() < cursor + 4 {
            return Err(DecryptError::Malformed(format!("chunk {i}: missing len")));
        }
        let chunk_len_bytes: [u8; 4] = body[cursor..cursor + 4]
            .try_into()
            .map_err(|_| DecryptError::Malformed("chunk_len slice".into()))?;
        let chunk_len = u32::from_be_bytes(chunk_len_bytes);
        cursor += 4;
        let nonce_plus_tag =
            u32::try_from(NONCE_BYTES + AEAD_TAG_BYTES).expect("24 + 16 = 40 fits in u32");
        if !(nonce_plus_tag..=MAX_CHUNK_LEN).contains(&chunk_len) {
            return Err(DecryptError::Malformed(format!(
                "chunk {i}: total_len {chunk_len} out of range"
            )));
        }
        let total = chunk_len as usize;
        if body.len() < cursor + total {
            return Err(DecryptError::Malformed(format!(
                "chunk {i}: truncated body"
            )));
        }
        let chunk_nonce = &body[cursor..cursor + NONCE_BYTES];
        // V2/V3: nonce must match the deterministic derivation
        // nonce_prefix ‖ i.to_be_bytes() to prevent silent chunk reorder
        // (permuting same-length frames).
        if matches!(version, VERSION_V2 | VERSION_V3) {
            let mut expected_nonce = [0u8; NONCE_BYTES];
            expected_nonce[..NONCE_PREFIX_BYTES].copy_from_slice(&nonce_prefix);
            expected_nonce[NONCE_PREFIX_BYTES..].copy_from_slice(&i.to_be_bytes());
            if chunk_nonce != expected_nonce {
                return Err(DecryptError::Malformed(format!(
                    "chunk {i}: nonce mismatch (reorder or tampering detected)"
                )));
            }
        }
        let chunk_ct = &body[cursor + NONCE_BYTES..cursor + total];
        cursor += total;

        let plain = cipher
            .decrypt(
                XNonce::from_slice(chunk_nonce),
                Payload { msg: chunk_ct, aad },
            )
            .map_err(|_| DecryptError::Core(CryptoError::WrongPin))?;
        out.extend_from_slice(&plain);
    }

    // B-CR-5 (audit 2026-06-26) — strict parser: reject trailing bytes after
    // the last declared chunk. `chunk_count` is bound into the V2 AAD, so a
    // tail cannot smuggle *authenticated* data (it is invisible to decrypt);
    // but a well-formed blob has `cursor == body.len()` by construction
    // (`encrypt.rs` emits no padding). Any residue means a malformed/tampered
    // blob — reject it loudly instead of silently ignoring, matching the upper
    // bound already enforced on SINGLE bodies (decrypt_single above).
    if cursor != body.len() {
        return Err(DecryptError::Malformed(format!(
            "trailing bytes after last chunk: cursor {} != body len {}",
            cursor,
            body.len()
        )));
    }

    Ok((out, ()))
}
