//! `crypto_box_seal` — pure-Rust reproduction of libsodium's sealed box.
//!
//! The Frappuccino STRM format stores the session key as a 80-byte sealed
//! envelope (32 B ephemeral public key + 16 B Poly1305 tag + 32 B ciphertext)
//! produced by libsodium `crypto_box_seal`. We reproduce the exact construction
//! so an Android-encrypted blob unseals under the Rust archive identity and
//! vice-versa.
//!
//! ## Algorithm (verbatim from libsodium)
//!
//! ```text
//! seal(m, pk):
//!   (epk, esk) = crypto_box_keypair()                 // X25519 ephemeral
//!   nonce      = Blake2b(epk || pk, out=24)           // NaCl-style nonce derivation
//!   c          = crypto_box_easy(m, nonce, pk, esk)   // XSalsa20-Poly1305, tag-prepended
//!   return epk || c
//! ```
//!
//! `crypto_box_easy` / `NaCl` box uses:
//!   * shared secret = `HSalsa20(X25519(esk, pk), nonce=0)`
//!   * XSalsa20-Poly1305 ciphertext in `tag (16) || ct` layout
//!
//! ## Output size
//!
//! Output is `32 + 16 + plaintext.len()` = 48 + plaintext length. For a
//! 32-byte session key it's 80 bytes, matching `SovereignEncryptor`'s
//! `SEALED_ENVELOPE_SIZE = SESSION_KEY_BYTES + SEALED_BOX_OVERHEAD` constant.

// `recipient_pk` and `recipient_sk` are the standard NaCl naming; clippy's
// `similar_names` would otherwise ding every seal/box function in the crate.
// Kept as a module-level allow rather than a per-fn attribute.
#![allow(clippy::similar_names)]

use crate::error::CryptoError;
use blake2::digest::{Update, VariableOutput};
use blake2::Blake2bVar;
use crypto_box::aead::Aead;
use crypto_box::{Nonce, PublicKey, SalsaBox, SecretKey};
use rand_core::OsRng;
use zeroize::Zeroizing;

/// Length of the ephemeral public key prepended to the sealed envelope.
pub const EPHEMERAL_PK_BYTES: usize = 32;
/// Length of the Poly1305 authentication tag.
pub const SEAL_TAG_BYTES: usize = 16;
/// Overhead of a sealed envelope over the plaintext = epk + tag = 48 bytes.
pub const SEAL_OVERHEAD: usize = EPHEMERAL_PK_BYTES + SEAL_TAG_BYTES;

/// Seal `plaintext` for the recipient with X25519 public key `recipient_pk`.
///
/// Returns `epk || ciphertext_with_tag` = `32 + 16 + plaintext.len()` bytes.
///
/// # Errors
/// Returns [`CryptoError::DerivationFailed`] if the AEAD encryption fails
/// (never in practice with valid inputs).
pub fn seal(plaintext: &[u8], recipient_pk: &[u8; 32]) -> Result<Vec<u8>, CryptoError> {
    // 1. Generate an ephemeral X25519 keypair. OsRng is wired through the
    //    crypto_box crate's PublicKey/SecretKey constructors.
    let eph_secret = SecretKey::generate(&mut OsRng);
    let eph_public = eph_secret.public_key();
    let recipient = PublicKey::from(*recipient_pk);

    // 2. Derive the NaCl-style nonce from Blake2b(epk || recipient_pk, 24 B).
    let nonce_bytes = seal_nonce(eph_public.as_bytes(), recipient_pk);

    // 3. Encrypt with XSalsa20-Poly1305 (NaCl "box_easy" = tag-prepended).
    let salsabox = SalsaBox::new(&recipient, &eph_secret);
    let nonce_ga = Nonce::from_slice(&nonce_bytes);
    let ct = salsabox
        .encrypt(nonce_ga, plaintext)
        .map_err(|e| CryptoError::DerivationFailed(format!("crypto_box encrypt: {e}")))?;

    // 4. Output = epk || ct.
    let mut out = Vec::with_capacity(EPHEMERAL_PK_BYTES + ct.len());
    out.extend_from_slice(eph_public.as_bytes());
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Unseal a blob produced by [`seal`] (or libsodium `crypto_box_seal`) with the
/// recipient's X25519 secret key.
///
/// Both the recipient's pk and sk are required: the sk decrypts, the pk is
/// used to re-derive the nonce (which depends on `Blake2b(epk || pk)`).
///
/// # Errors
/// Returns [`CryptoError::WrongPin`] on AEAD tag mismatch — the caller can't
/// distinguish "wrong recipient" from "tampered blob", matching the Kotlin
/// `SecurityException` behavior. (`WrongPin` is reused as a generic
/// authentication failure — S8 may introduce a dedicated variant if the
/// distinction becomes useful.)
pub fn seal_open(
    blob: &[u8],
    recipient_pk: &[u8; 32],
    recipient_sk: &[u8; 32],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if blob.len() < SEAL_OVERHEAD {
        return Err(CryptoError::InvalidBlob(format!(
            "sealed blob too short: {} (minimum {})",
            blob.len(),
            SEAL_OVERHEAD
        )));
    }
    let mut epk_bytes = [0u8; EPHEMERAL_PK_BYTES];
    epk_bytes.copy_from_slice(&blob[..EPHEMERAL_PK_BYTES]);
    let ct = &blob[EPHEMERAL_PK_BYTES..];

    let eph_public = PublicKey::from(epk_bytes);
    let my_secret = SecretKey::from(*recipient_sk);
    let salsabox = SalsaBox::new(&eph_public, &my_secret);

    let nonce_bytes = seal_nonce(&epk_bytes, recipient_pk);
    let nonce_ga = Nonce::from_slice(&nonce_bytes);

    let plaintext = salsabox
        .decrypt(nonce_ga, ct)
        .map_err(|_| CryptoError::WrongPin)?;
    Ok(Zeroizing::new(plaintext))
}

/// Derive the seal nonce from `Blake2b(epk || pk, out=24)` — the exact shape
/// of libsodium's internal `_crypto_box_seal_nonce` (keyless, 24-byte output).
fn seal_nonce(epk: &[u8; 32], pk: &[u8; 32]) -> [u8; 24] {
    let mut hasher = Blake2bVar::new(24).expect("24 <= Blake2b max output 64");
    Update::update(&mut hasher, epk);
    Update::update(&mut hasher, pk);
    let mut nonce = [0u8; 24];
    hasher
        .finalize_variable(&mut nonce)
        .expect("24-byte output matches the constructor size");
    nonce
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Round-trip: seal then unseal must recover the plaintext.
    #[test]
    fn seal_open_roundtrip() {
        let sk = SecretKey::generate(&mut OsRng);
        let pk = sk.public_key();
        let pk_bytes: [u8; 32] = *pk.as_bytes();
        let sk_bytes: [u8; 32] = sk.to_bytes();

        let session_key = [0x42u8; 32];
        let blob = seal(&session_key, &pk_bytes).unwrap();
        assert_eq!(blob.len(), SEAL_OVERHEAD + session_key.len());

        let opened = seal_open(&blob, &pk_bytes, &sk_bytes).unwrap();
        assert_eq!(&opened[..], &session_key[..]);
    }

    #[test]
    fn seal_open_wrong_recipient_rejected() {
        let victim = SecretKey::generate(&mut OsRng);
        let attacker = SecretKey::generate(&mut OsRng);
        let victim_pk: [u8; 32] = *victim.public_key().as_bytes();

        let blob = seal(b"secret", &victim_pk).unwrap();

        // Try to open with the attacker's keys (wrong pk used for nonce derivation
        // AND wrong sk for X25519 — both contribute to the failure).
        let attacker_pk: [u8; 32] = *attacker.public_key().as_bytes();
        let attacker_sk: [u8; 32] = attacker.to_bytes();
        let err = seal_open(&blob, &attacker_pk, &attacker_sk).unwrap_err();
        assert!(matches!(err, CryptoError::WrongPin), "got {err:?}");
    }

    #[test]
    fn seal_open_tampered_ciphertext_rejected() {
        let sk = SecretKey::generate(&mut OsRng);
        let pk_bytes: [u8; 32] = *sk.public_key().as_bytes();
        let sk_bytes: [u8; 32] = sk.to_bytes();
        let mut blob = seal(b"payload", &pk_bytes).unwrap();
        blob[40] ^= 1;
        assert!(matches!(
            seal_open(&blob, &pk_bytes, &sk_bytes),
            Err(CryptoError::WrongPin)
        ));
    }

    #[test]
    fn seal_open_truncated_rejected() {
        let err = seal_open(&[0u8; 10], &[0u8; 32], &[0u8; 32]).unwrap_err();
        assert!(matches!(err, CryptoError::InvalidBlob(_)));
    }

    /// The nonce is deterministic in (epk, pk) — two seals of different
    /// plaintexts to the same recipient must produce different epks (and
    /// therefore different nonces).
    #[test]
    fn seal_epk_rerandomizes_per_call() {
        let sk = SecretKey::generate(&mut OsRng);
        let pk_bytes: [u8; 32] = *sk.public_key().as_bytes();
        let blob_a = seal(b"x", &pk_bytes).unwrap();
        let blob_b = seal(b"x", &pk_bytes).unwrap();
        assert_ne!(&blob_a[..32], &blob_b[..32], "epk must differ per call");
    }

    #[test]
    fn seal_nonce_is_deterministic_in_inputs() {
        let epk = [1u8; 32];
        let pk = [2u8; 32];
        assert_eq!(seal_nonce(&epk, &pk), seal_nonce(&epk, &pk));
    }
}
