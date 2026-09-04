//! HKDF-SHA256 (RFC 5869) — byte-exact with the Kotlin reference impl.
//!
//! The Kotlin `Hkdf.sha256(ikm, salt, info, length)` helper accepts a nullable
//! salt that defaults to 32 zero bytes when `null`. The `RustCrypto` `hkdf` crate
//! matches this behavior: `Hkdf::new(None, ikm)` uses a zero-filled salt of
//! `HashLen` (32 bytes for SHA-256) internally, so we preserve exact parity.
//!
//! Length bounds: HKDF's extract/expand allows up to 255 × `HashLen` output bytes
//! = 255 × 32 = 8160 for SHA-256. We reject larger `length` with
//! `CryptoError::DerivationFailed` to mirror the Kotlin guard.

use crate::error::CryptoError;
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

/// Maximum output length for HKDF-SHA256 (RFC 5869 §2.3: L ≤ 255·HashLen).
pub const MAX_OUTPUT_BYTES: usize = 255 * 32;

/// Compute HKDF-SHA256 (extract + expand) matching the Kotlin reference exactly.
///
/// - `ikm` — Input Key Material (secret — typically a chain key or BIP-39 seed).
/// - `salt` — optional non-secret salt. `None` is treated as 32 zero bytes,
///   preserving byte-exact compatibility with the Kotlin `salt: null` branch.
/// - `info` — domain-separation context string. Never change a context string
///   post-deployment — it's baked into identity / ratchet derivations.
/// - `length` — output byte count (1..=8160).
///
/// Returns `Zeroizing<Vec<u8>>` so the derived bytes are wiped when the caller
/// drops the value. The caller should not `.to_vec()` away from the wrapper.
///
/// # Errors
/// Returns [`CryptoError::DerivationFailed`] if `length` is 0 or > 8160, or if
/// the underlying HKDF expansion fails (never in practice with a valid length).
pub fn sha256(
    ikm: &[u8],
    salt: Option<&[u8]>,
    info: &[u8],
    length: usize,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if length == 0 || length > MAX_OUTPUT_BYTES {
        return Err(CryptoError::DerivationFailed(format!(
            "HKDF output length must be in 1..={MAX_OUTPUT_BYTES}, got {length}"
        )));
    }
    let hk = Hkdf::<Sha256>::new(salt, ikm);
    let mut okm = vec![0u8; length];
    hk.expand(info, &mut okm)
        .map_err(|e| CryptoError::DerivationFailed(e.to_string()))?;
    Ok(Zeroizing::new(okm))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 5869 test case 1 (Basic test case with SHA-256).
    /// <https://www.rfc-editor.org/rfc/rfc5869#appendix-A.1>
    #[test]
    fn rfc5869_test_case_1() {
        let ikm = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let salt = hex::decode("000102030405060708090a0b0c").unwrap();
        let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();
        let expected = hex::decode(
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf\
             34007208d5b887185865",
        )
        .unwrap();
        let out = sha256(&ikm, Some(&salt), &info, 42).unwrap();
        assert_eq!(&out[..], expected.as_slice());
    }

    /// RFC 5869 test case 3 (no salt → `HashLen` zero bytes, no info).
    #[test]
    fn rfc5869_test_case_3_null_salt() {
        let ikm = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let expected = hex::decode(
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d\
             9d201395faa4b61a96c8",
        )
        .unwrap();
        // Both None and Some(&[0u8; 32]) must produce the same output.
        let with_none = sha256(&ikm, None, &[], 42).unwrap();
        let with_zeros = sha256(&ikm, Some(&[0u8; 32]), &[], 42).unwrap();
        assert_eq!(&with_none[..], expected.as_slice());
        assert_eq!(&with_zeros[..], expected.as_slice());
    }

    #[test]
    fn zero_length_rejected() {
        let err = sha256(&[1, 2, 3], None, b"test", 0).unwrap_err();
        assert!(matches!(err, CryptoError::DerivationFailed(_)));
    }

    #[test]
    fn over_max_length_rejected() {
        let err = sha256(&[1, 2, 3], None, b"test", MAX_OUTPUT_BYTES + 1).unwrap_err();
        assert!(matches!(err, CryptoError::DerivationFailed(_)));
    }

    #[test]
    fn max_length_accepted() {
        let out = sha256(&[1, 2, 3], None, b"test", MAX_OUTPUT_BYTES).unwrap();
        assert_eq!(out.len(), MAX_OUTPUT_BYTES);
    }
}
