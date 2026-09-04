//! PIN-protected sealed-box — byte-exact with Kotlin `PinProtectedStore`.
//!
//! ## Role
//!
//! Wraps an arbitrary plaintext (typically: a serialized ratchet state, or a
//! mnemonic cached for quick unlock) with a user-chosen PIN. The KDF is
//! Argon2id tuned for ~1.2 s on a Snapdragon 8+ Gen 1 (Solana Seeker), making
//! brute-force of a 6-digit PIN impractical without dedicated GPU hardware.
//!
//! ## Format (41-byte header + AEAD)
//!
//! ```text
//! blob = [0]     version  = 0x01              (1 byte)
//!        [1..]   salt     (16 bytes, random per seal)
//!        [17..]  nonce    (24 bytes, random per seal)
//!        [41..]  ciphertext || poly1305_tag   (plaintext.len + 16 bytes)
//! ```
//!
//! ## Invariants (`PLAN_RUST_EXEC.md` §1.5 — must NEVER drift from Kotlin)
//!
//! * Argon2id params: `m = 256 MiB, t = 4, p = 1, tag_len = 32`
//! * AEAD: `XChaCha20-Poly1305-IETF`
//! * AAD: the fixed byte string `"frappuccino-v2-pin-store-v1"`
//! * Version byte: `0x01`
//! * Salt = 16 bytes, nonce = 24 bytes, tag = 16 bytes
//!
//! ## Wrong-PIN vs tampered-blob
//!
//! A failed AEAD authentication returns [`CryptoError::WrongPin`] regardless
//! of the reason (wrong PIN, tampered ciphertext, wrong salt, …). The caller
//! must count this toward the lockout budget — the Kotlin-side
//! `PinAttemptTracker` stays in charge of that policy since it lives in
//! `SharedPreferences`.

use crate::error::CryptoError;
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use rand_core::{OsRng, RngCore};
use zeroize::Zeroizing;

// ============================================================================
// Format constants — MUST match Kotlin verbatim.
// ============================================================================

/// Blob format version byte.
pub const VERSION: u8 = 1;

/// Return type of [`open_extended`]: unwrapped plaintext, the Argon2id-derived
/// key (so the caller can fast-reseal via [`seal_with_key`] without paying the
/// KDF a second time), and the salt bound to this blob.
pub type OpenExtended = (
    Zeroizing<Vec<u8>>,
    Zeroizing<[u8; KEY_BYTES]>,
    [u8; SALT_BYTES],
);
/// Argon2id salt length.
pub const SALT_BYTES: usize = 16;
/// `XChaCha20` nonce length.
pub const NONCE_BYTES: usize = 24;
/// AEAD key length (= Argon2id output length).
pub const KEY_BYTES: usize = 32;
/// Poly1305 tag length (appended to the ciphertext).
pub const TAG_BYTES: usize = 16;
/// Offset where the salt ends (= nonce starts) in the blob.
const SALT_END: usize = 1 + SALT_BYTES;
/// Size of the framed header: `version || salt || nonce`.
pub const HEADER_SIZE: usize = 1 + SALT_BYTES + NONCE_BYTES;

/// Argon2id `t_cost` — iteration count.
pub const ARGON2_OPS: u32 = 4;
/// Argon2id `m_cost` — memory in KiB (256 MiB = 262 144 KiB).
pub const ARGON2_MEM_KIB: u32 = 256 * 1024;
/// Argon2id `p_cost` — parallelism.
pub const ARGON2_PARALLELISM: u32 = 1;

/// Domain-separation AAD. The exact bytes are part of the contract — changing
/// them invalidates every sealed blob already on disk.
pub const AAD: &[u8] = b"frappuccino-v2-pin-store-v1";

// ============================================================================
// Public API
// ============================================================================

/// Seal `plaintext` under a user-chosen `pin`. The OS `CSPRNG` picks a fresh
/// salt and nonce, so two calls with identical inputs produce different blobs.
///
/// # Errors
/// * [`CryptoError::EmptyInput`] if `pin` is empty.
/// * [`CryptoError::DerivationFailed`] on Argon2id / AEAD construction errors
///   (never in practice with valid inputs).
pub fn seal(pin: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let mut salt = [0u8; SALT_BYTES];
    let mut nonce = [0u8; NONCE_BYTES];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce);
    seal_deterministic(pin, plaintext, &salt, &nonce)
}

/// Seal with caller-supplied salt + nonce. **Test-only** — never reuse a
/// (salt, nonce) pair in production: doing so leaks plaintext XOR under
/// `XChaCha20` and lets an attacker forge valid ciphertexts.
///
/// The Kotlin parity fixture uses this path so we can verify byte-exact
/// reproduction of a known blob.
///
/// # Errors
/// Same as [`seal`] plus nothing extra.
pub fn seal_deterministic(
    pin: &[u8],
    plaintext: &[u8],
    salt: &[u8; SALT_BYTES],
    nonce: &[u8; NONCE_BYTES],
) -> Result<Vec<u8>, CryptoError> {
    if pin.is_empty() {
        return Err(CryptoError::EmptyInput);
    }

    let key = derive_key(pin, salt)?;
    let cipher = XChaCha20Poly1305::new(key.as_slice().into());
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad: AAD,
            },
        )
        .map_err(|e| CryptoError::DerivationFailed(format!("AEAD encrypt: {e}")))?;

    let mut blob = Vec::with_capacity(HEADER_SIZE + ciphertext.len());
    blob.push(VERSION);
    blob.extend_from_slice(salt);
    blob.extend_from_slice(nonce);
    blob.extend_from_slice(&ciphertext);
    Ok(blob)
}

/// Open a previously-sealed blob. Returns the plaintext in a
/// [`Zeroizing<Vec<u8>>`] so it wipes on drop.
///
/// # Errors
/// * [`CryptoError::EmptyInput`] if `pin` is empty.
/// * [`CryptoError::InvalidBlob`] if the blob is too short or has an
///   unsupported version byte.
/// * [`CryptoError::WrongPin`] if the AEAD tag does not authenticate — the
///   caller cannot tell "wrong PIN" from "tampered blob" by design.
pub fn open(pin: &[u8], blob: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if pin.is_empty() {
        return Err(CryptoError::EmptyInput);
    }
    if blob.len() < HEADER_SIZE + TAG_BYTES {
        return Err(CryptoError::InvalidBlob(format!(
            "blob too short: {} (minimum {})",
            blob.len(),
            HEADER_SIZE + TAG_BYTES
        )));
    }
    if blob[0] != VERSION {
        return Err(CryptoError::InvalidBlob(format!(
            "unsupported version byte {:#x} (expected {:#x})",
            blob[0], VERSION
        )));
    }

    // Safe slices — bounds checked above.
    let salt: [u8; SALT_BYTES] = blob[1..SALT_END]
        .try_into()
        .map_err(|_| CryptoError::InvalidBlob("salt slice".into()))?;
    let nonce: [u8; NONCE_BYTES] = blob[SALT_END..HEADER_SIZE]
        .try_into()
        .map_err(|_| CryptoError::InvalidBlob("nonce slice".into()))?;
    let ciphertext = &blob[HEADER_SIZE..];

    let key = derive_key(pin, &salt)?;
    let cipher = XChaCha20Poly1305::new(key.as_slice().into());
    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: ciphertext,
                aad: AAD,
            },
        )
        .map_err(|_| CryptoError::WrongPin)?;

    Ok(Zeroizing::new(plaintext))
}

/// Fast reseal companion to [`open`]: returns the derived Argon2id key and
/// salt alongside the plaintext so the caller can later produce a new blob
/// via [`seal_with_key`] **without re-running Argon2id** (~1-2 s on Seeker).
///
/// Used for the ratchet persistence path, where the blob is rewritten after
/// every signature. The caller MUST zero `derived_key` as soon as the resealing
/// session ends (e.g. on lock / app exit) — the key alone is enough to decrypt
/// any blob sealed under the same pin+salt pair.
///
/// # Errors
/// Same as [`open`].
pub fn open_extended(pin: &[u8], blob: &[u8]) -> Result<OpenExtended, CryptoError> {
    if pin.is_empty() {
        return Err(CryptoError::EmptyInput);
    }
    if blob.len() < HEADER_SIZE + TAG_BYTES {
        return Err(CryptoError::InvalidBlob(format!(
            "blob too short: {} (minimum {})",
            blob.len(),
            HEADER_SIZE + TAG_BYTES
        )));
    }
    if blob[0] != VERSION {
        return Err(CryptoError::InvalidBlob(format!(
            "unsupported version byte {:#x} (expected {:#x})",
            blob[0], VERSION
        )));
    }

    let salt: [u8; SALT_BYTES] = blob[1..SALT_END]
        .try_into()
        .map_err(|_| CryptoError::InvalidBlob("salt slice".into()))?;
    let nonce: [u8; NONCE_BYTES] = blob[SALT_END..HEADER_SIZE]
        .try_into()
        .map_err(|_| CryptoError::InvalidBlob("nonce slice".into()))?;
    let ciphertext = &blob[HEADER_SIZE..];

    let key = derive_key(pin, &salt)?;
    let cipher = XChaCha20Poly1305::new(key.as_slice().into());
    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: ciphertext,
                aad: AAD,
            },
        )
        .map_err(|_| CryptoError::WrongPin)?;

    Ok((Zeroizing::new(plaintext), key, salt))
}

/// Fast reseal: build a new blob using a previously-derived Argon2id key and
/// the original salt. Generates a fresh random nonce.
///
/// Pair with [`open_extended`] to avoid re-running the ~1 s Argon2id round
/// on every re-encrypt. The `derived_key` is treated as a secret and
/// **must** be zeroed once resealing sessions end.
///
/// # Errors
/// * [`CryptoError::DerivationFailed`] if the AEAD construction fails
///   (never in practice).
pub fn seal_with_key(
    derived_key: &[u8; KEY_BYTES],
    salt: &[u8; SALT_BYTES],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let mut nonce = [0u8; NONCE_BYTES];
    OsRng.fill_bytes(&mut nonce);

    let cipher = XChaCha20Poly1305::new(derived_key.as_slice().into());
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: AAD,
            },
        )
        .map_err(|e| CryptoError::DerivationFailed(format!("AEAD encrypt: {e}")))?;

    let mut blob = Vec::with_capacity(HEADER_SIZE + ciphertext.len());
    blob.push(VERSION);
    blob.extend_from_slice(salt);
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&ciphertext);
    Ok(blob)
}

/// Open a blob (sealed by [`seal`] or [`seal_with_key`]) using a
/// previously-derived Argon2id key directly — the fast counterpart to
/// [`open`], skipping the ~1 s KDF. Only the nonce is read from the blob; the
/// embedded salt is ignored (the key is supplied, not re-derived from it).
///
/// Used to reload a *secondary* PIN-sealed secret (e.g. the provenance signing
/// seed) during an already-unlocked session, reusing the ratchet's cached
/// Argon2id key so there is no second KDF and no PIN re-entry. The
/// `derived_key` is secret — the caller must zero it when the session ends.
///
/// # Errors
/// * [`CryptoError::InvalidBlob`] if the blob is too short or has an
///   unsupported version byte.
/// * [`CryptoError::WrongPin`] if the AEAD tag does not authenticate (wrong
///   key or tampered blob).
pub fn open_with_key(
    derived_key: &[u8; KEY_BYTES],
    blob: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if blob.len() < HEADER_SIZE + TAG_BYTES {
        return Err(CryptoError::InvalidBlob(format!(
            "blob too short: {} (minimum {})",
            blob.len(),
            HEADER_SIZE + TAG_BYTES
        )));
    }
    if blob[0] != VERSION {
        return Err(CryptoError::InvalidBlob(format!(
            "unsupported version byte {:#x} (expected {:#x})",
            blob[0], VERSION
        )));
    }

    let nonce: [u8; NONCE_BYTES] = blob[SALT_END..HEADER_SIZE]
        .try_into()
        .map_err(|_| CryptoError::InvalidBlob("nonce slice".into()))?;
    let ciphertext = &blob[HEADER_SIZE..];

    let cipher = XChaCha20Poly1305::new(derived_key.as_slice().into());
    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: ciphertext,
                aad: AAD,
            },
        )
        .map_err(|_| CryptoError::WrongPin)?;

    Ok(Zeroizing::new(plaintext))
}

// ============================================================================
// Internal — KDF
// ============================================================================

/// Derive a 32-byte AEAD key from `pin` + `salt` via Argon2id(256 MiB, t=4).
///
/// The returned key is wrapped in [`Zeroizing`] so the caller cannot leak
/// it past the end of the enclosing scope.
fn derive_key(
    pin: &[u8],
    salt: &[u8; SALT_BYTES],
) -> Result<Zeroizing<[u8; KEY_BYTES]>, CryptoError> {
    let params = Params::new(
        ARGON2_MEM_KIB,
        ARGON2_OPS,
        ARGON2_PARALLELISM,
        Some(KEY_BYTES),
    )
    .map_err(|e| CryptoError::DerivationFailed(format!("argon2 params: {e}")))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key = Zeroizing::new([0u8; KEY_BYTES]);
    argon2
        // Phase 6.1.4-A : pin est déjà &[u8], plus de .as_bytes() (l'API
        // accepte directement des bytes pour le PIN au lieu d'un String).
        .hash_password_into(pin, salt, &mut key[..])
        .map_err(|e| CryptoError::DerivationFailed(format!("argon2: {e}")))?;
    Ok(key)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // Argon2id at 256 MiB × 4 ops ≈ 1.2 s per call. Each test does a seal +
    // an open = 2 calls = ~2.5 s. Keep the suite small — RFC-style test
    // vectors live in the `argon2` crate itself; we only need round-trips
    // here to catch integration mistakes.

    #[test]
    fn seal_open_roundtrip_short_plaintext() {
        let blob = seal(b"123456", b"hello").unwrap();
        let out = open(b"123456", &blob).unwrap();
        assert_eq!(&out[..], b"hello");
    }

    #[test]
    fn seal_open_roundtrip_empty_plaintext() {
        let blob = seal(b"998877", &[]).unwrap();
        let out = open(b"998877", &blob).unwrap();
        assert_eq!(&out[..], b"");
    }

    #[test]
    fn open_with_wrong_pin_rejected() {
        let blob = seal(b"correct", b"payload").unwrap();
        let err = open(b"wrong", &blob).unwrap_err();
        assert!(matches!(err, CryptoError::WrongPin), "got {err:?}");
    }

    #[test]
    fn open_with_tampered_ciphertext_rejected() {
        let mut blob = seal(b"pin", b"payload").unwrap();
        // Flip a bit in the ciphertext section.
        let ct_idx = HEADER_SIZE + 1;
        blob[ct_idx] ^= 0x01;
        let err = open(b"pin", &blob).unwrap_err();
        // Deliberately indistinguishable from WrongPin — see module doc.
        assert!(matches!(err, CryptoError::WrongPin), "got {err:?}");
    }

    #[test]
    fn open_with_truncated_blob_rejected() {
        let err = open(b"pin", &[0u8; HEADER_SIZE]).unwrap_err();
        assert!(matches!(err, CryptoError::InvalidBlob(_)), "got {err:?}");
    }

    #[test]
    fn open_with_wrong_version_rejected() {
        let mut blob = seal(b"pin", b"payload").unwrap();
        blob[0] = 0xFF;
        let err = open(b"pin", &blob).unwrap_err();
        assert!(matches!(err, CryptoError::InvalidBlob(_)), "got {err:?}");
    }

    #[test]
    fn empty_pin_rejected() {
        assert!(matches!(seal(b"", b"x"), Err(CryptoError::EmptyInput)));
        let blob = seal(b"pin", b"x").unwrap();
        assert!(matches!(open(b"", &blob), Err(CryptoError::EmptyInput)));
    }

    #[test]
    fn seal_deterministic_is_reproducible() {
        let salt = [1u8; SALT_BYTES];
        let nonce = [2u8; NONCE_BYTES];
        let a = seal_deterministic(b"pin", b"data", &salt, &nonce).unwrap();
        let b = seal_deterministic(b"pin", b"data", &salt, &nonce).unwrap();
        assert_eq!(a, b, "same inputs must produce byte-identical blobs");
    }

    #[test]
    fn open_extended_then_seal_with_key_roundtrip() {
        // Simulate the fast-reseal path used by the ratchet persistence:
        //   1. initial seal with PIN                (~1.2 s Argon2id)
        //   2. open_extended → plaintext + key + salt (~1.2 s Argon2id once)
        //   3. seal_with_key → new blob            (~µs — no Argon2id)
        //   4. open the new blob with the same PIN succeeds
        let initial = seal(b"123456", b"ratchet-state-v1").unwrap();
        let (plaintext, key, salt) = open_extended(b"123456", &initial).unwrap();
        assert_eq!(&plaintext[..], b"ratchet-state-v1");

        let new_blob = seal_with_key(&key, &salt, b"ratchet-state-v2").unwrap();
        // Same salt → new nonce → different blob bytes
        assert_ne!(initial, new_blob);

        // Opening the fast-resealed blob with the original PIN must work.
        let round = open(b"123456", &new_blob).unwrap();
        assert_eq!(&round[..], b"ratchet-state-v2");
    }

    #[test]
    fn open_extended_wrong_pin_rejected() {
        let blob = seal(b"correct", b"payload").unwrap();
        let err = open_extended(b"wrong", &blob).unwrap_err();
        assert!(matches!(err, CryptoError::WrongPin), "got {err:?}");
    }

    #[test]
    fn open_with_key_roundtrip_and_wrong_key_rejected() {
        // The fast secondary-secret path: derive the key once via the primary
        // blob, seal a second secret under it, reopen WITHOUT Argon2id.
        let primary = seal(b"123456", b"ratchet-state").unwrap();
        let (_pt, key, salt) = open_extended(b"123456", &primary).unwrap();
        let blob = seal_with_key(&key, &salt, b"provenance-seed-32-bytes-padding!").unwrap();

        let out = open_with_key(&key, &blob).unwrap();
        assert_eq!(&out[..], b"provenance-seed-32-bytes-padding!");

        // A wrong key authenticates to nothing.
        let wrong = Zeroizing::new([0u8; KEY_BYTES]);
        assert!(matches!(
            open_with_key(&wrong, &blob),
            Err(CryptoError::WrongPin)
        ));
        // A truncated blob is rejected structurally.
        assert!(matches!(
            open_with_key(&key, &[0u8; HEADER_SIZE]),
            Err(CryptoError::InvalidBlob(_))
        ));
    }
}
