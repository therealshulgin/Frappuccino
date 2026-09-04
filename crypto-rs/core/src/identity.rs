//! Identity derivation — byte-exact with Kotlin `EnrollmentKit` / `ArchiveIdentity`.
//!
//! ## Architecture (V2 asymmetry)
//!
//! Frappuccino's V2 design splits key material into three lifecycle roles:
//!
//! - **[`StreamIdentity`]** — public-only wrapper. Published as the user's
//!   pseudonymous identity, used for self-addressed sealed-box encryption.
//!   Safe to store on the device indefinitely.
//! - **[`EnrollmentKit`]** — one-shot holder of the long-term Ed25519 secret.
//!   Lives only during initial enrollment: sign the first batch of ratchet
//!   keys, publish the identity, then `drop` (wipes the secret). After that,
//!   the device *cannot* sign with the long-term key anymore.
//! - **[`ArchiveIdentity`]** — derivable on demand from the BIP-39 phrase to
//!   unseal session keys for archived streams. The X25519 secret lives in a
//!   [`LockedSecret`] (mlock'd page) for the duration of archive-mode usage.
//!
//! ## Derivation pipeline
//!
//! ```text
//! mnemonic + passphrase
//!   └─▶ BIP-39 PBKDF2-HMAC-SHA512 (2048 iter) ──▶ seed (64 B)
//!         ├─▶ HKDF("stream.identity.ed25519.v1", 32) ──▶ Ed25519 seed ──▶ (ed_pk, ed_sk)
//!         ├─▶ HKDF("stream.encryption.x25519.v1", 32) ──▶ libsodium-shape ──▶ (x_pk, x_sk)
//!         └─▶ HKDF("stream.ratchet.chain0.v2",    32) ──▶ chain_0 (→ `EphemeralRatchet`)
//! ```
//!
//! The X25519 key derivation matches `libsodium crypto_box_seed_keypair`:
//! `sk = SHA-512(seed)[..32]` (no Ed25519→X25519 conversion), so the Kotlin
//! wire format is preserved.
//!
//! ## Invariants (immutable — break = lose every enrolled identity)
//!
//! HKDF context strings hard-coded in this module:
//! `"stream.identity.ed25519.v1"`, `"stream.encryption.x25519.v1"`,
//! `"stream.ratchet.chain0.v2"`. See `PLAN_RUST_EXEC.md` §1.2.

use crate::bip39::{self, Language};
use crate::error::CryptoError;
use crate::hkdf;
use crate::secret::LockedSecret;
use crate::signature_domain::SignatureDomain;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256, Sha512};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};
use zeroize::Zeroizing;

// ============================================================================
// HKDF context strings — PLAN_RUST_EXEC.md §1.2
// ============================================================================

const CTX_IDENTITY: &[u8] = b"stream.identity.ed25519.v1";
const CTX_ENCRYPTION: &[u8] = b"stream.encryption.x25519.v1";
const CTX_CHAIN0: &[u8] = b"stream.ratchet.chain0.v2";

const ED25519_SEED_BYTES: usize = 32;
const ED25519_PK_BYTES: usize = 32;
const ED25519_SK_BYTES: usize = 64; // libsodium convention: seed || pk
const X25519_KEY_BYTES: usize = 32;
const CHAIN_KEY_BYTES: usize = 32;

// ============================================================================
// StreamIdentity — public-only, cheap to clone, safe to Debug-print partially.
// ============================================================================

/// Publicly identifying keypair pair (Ed25519 + X25519 public halves only).
///
/// Derived deterministically from a BIP-39 mnemonic; reproducing the same
/// phrase reproduces the same identity. Contains no secret material, so
/// `Clone` + `PartialEq` + non-redacted `Debug` are all safe.
#[derive(Clone, PartialEq, Eq)]
pub struct StreamIdentity {
    ed25519_pk: [u8; ED25519_PK_BYTES],
    x25519_pk: [u8; X25519_KEY_BYTES],
}

impl StreamIdentity {
    /// Build an identity from already-published Ed25519 + X25519 public keys.
    /// Used when re-hydrating a saved identity on device (both pubs persisted
    /// during onboarding) without needing the BIP-39 phrase.
    #[must_use]
    pub fn from_public_keys(
        ed25519_pk: [u8; ED25519_PK_BYTES],
        x25519_pk: [u8; X25519_KEY_BYTES],
    ) -> Self {
        Self {
            ed25519_pk,
            x25519_pk,
        }
    }

    /// The 32-byte Ed25519 verification key.
    #[must_use]
    pub fn ed25519_pk(&self) -> &[u8; ED25519_PK_BYTES] {
        &self.ed25519_pk
    }

    /// The 32-byte X25519 public key (target of `crypto_box_seal`).
    #[must_use]
    pub fn x25519_pk(&self) -> &[u8; X25519_KEY_BYTES] {
        &self.x25519_pk
    }

    /// Ed25519 public key encoded as 64 lowercase hex characters.
    #[must_use]
    pub fn ed25519_pk_hex(&self) -> String {
        hex_encode(&self.ed25519_pk)
    }

    /// Human-readable fingerprint for the user to verify they typed the
    /// correct phrase: `SHA-256(ed25519_pk)` truncated to 12 bytes, hex-encoded
    /// (24 chars), then split into 6 groups of 4 chars separated by spaces.
    /// Matches Kotlin `hash.take(12).hex().chunked(4).join(" ")` verbatim.
    #[must_use]
    pub fn readable_fingerprint(&self) -> String {
        use std::fmt::Write;
        let hash = Sha256::digest(self.ed25519_pk);
        let mut hex = String::with_capacity(24);
        for b in &hash.as_slice()[..12] {
            // write! to a String cannot fail; `.expect` flagged by clippy
            // otherwise.
            let _ = write!(hex, "{b:02x}");
        }
        let mut out = String::with_capacity(29); // 6*4 + 5 separators
        for (i, chunk) in hex.as_bytes().chunks(4).enumerate() {
            if i > 0 {
                out.push(' ');
            }
            // `chunk` contains only ASCII hex digits produced two lines above.
            // `from_utf8` on ASCII bytes is infallible, but we match safely
            // rather than `.expect()` per Rust_guidelines.md.
            if let Ok(s) = std::str::from_utf8(chunk) {
                out.push_str(s);
            }
        }
        out
    }

    /// Verify that `signature` is a valid Ed25519 signature of `message` under
    /// this identity's public key.
    ///
    /// Uses dalek's `verify_strict` which rejects non-canonical encodings of
    /// `R` (malleability). The Python relay verifies via libsodium
    /// `crypto_sign_open` (strict by default since `ED25519_COMPAT` isn't set);
    /// matching strictness here keeps client and server symmetrical so a
    /// malleable signature accepted by one is never silently re-accepted
    /// by the other (RT-10).
    ///
    /// # Errors
    /// Returns [`CryptoError::InvalidSignature`] on any verification failure,
    /// including non-canonical `R` rejections.
    pub fn verify(&self, message: &[u8], signature: &[u8; 64]) -> Result<(), CryptoError> {
        let vk = VerifyingKey::from_bytes(&self.ed25519_pk)
            .map_err(|_| CryptoError::InvalidSignature)?;
        let sig = Signature::from_bytes(signature);
        vk.verify_strict(message, &sig)
            .map_err(|_| CryptoError::InvalidSignature)
    }
}

impl std::fmt::Debug for StreamIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "StreamIdentity(ed25519_pk={}, fingerprint={})",
            self.ed25519_pk_hex(),
            self.readable_fingerprint()
        )
    }
}

// ============================================================================
// EnrollmentKit — one-shot long-term Ed25519 + chain_0.
// ============================================================================

/// One-shot holder of the long-term Ed25519 secret and the initial ratchet
/// chain key. After `sign_once` + `take_chain_zero` are called (or the kit
/// drops), the long-term secret is wiped and unrecoverable without re-typing
/// the BIP-39 phrase.
///
/// Both secrets live in [`LockedSecret`] (mlock'd pages, zero on drop).
#[must_use]
pub struct EnrollmentKit {
    identity: StreamIdentity,
    // Wrapped in Option so the consume-once contract is enforced at the type
    // level: post-consumption the field is None and re-use returns
    // CryptoError::AlreadyConsumed.
    signing_key: Option<LockedSecret>,
    chain_0: Option<LockedSecret>,
}

impl EnrollmentKit {
    /// Derive a fresh kit from a BIP-39 mnemonic + passphrase.
    ///
    /// # Errors
    /// * [`CryptoError::InvalidMnemonicWord`] if the phrase contains unknown words.
    /// * [`CryptoError::DerivationFailed`] on HKDF / mlock failures.
    pub fn from_mnemonic(mnemonic: &str, passphrase: &str) -> Result<Self, CryptoError> {
        let seed = bip39::mnemonic_to_seed(mnemonic, passphrase, Language::French)?;

        let ed_seed = hkdf::sha256(seed.as_bytes(), None, CTX_IDENTITY, ED25519_SEED_BYTES)?;
        let x_seed = hkdf::sha256(seed.as_bytes(), None, CTX_ENCRYPTION, X25519_KEY_BYTES)?;
        let chain_bytes = hkdf::sha256(seed.as_bytes(), None, CTX_CHAIN0, CHAIN_KEY_BYTES)?;

        // Ed25519: ed25519-dalek's SigningKey::from_bytes uses the seed directly per RFC 8032.
        // RT-11: hold this stack copy of the long-term identity seed in
        // `Zeroizing` so it is wiped at scope exit. `ed_seed` is already
        // `Zeroizing<Vec<u8>>`, but this fixed-size array copy would otherwise
        // linger on the stack (a Cellebrite / heap-dump residue of the root key).
        let ed_seed_arr: Zeroizing<[u8; ED25519_SEED_BYTES]> = Zeroizing::new(
            ed_seed[..]
                .try_into()
                .map_err(|_| CryptoError::DerivationFailed("ed seed length".into()))?,
        );
        let signing = SigningKey::from_bytes(&ed_seed_arr);
        let ed_pk = signing.verifying_key().to_bytes();

        // X25519 libsodium seed_keypair: sk = SHA-512(seed)[..32], pk = sk * basepoint.
        // RT-11: the scalar copy survives the by-value move into
        // `X25519StaticSecret`, so hold it in `Zeroizing` (wiped at scope exit).
        let mut x_sk_bytes: Zeroizing<[u8; X25519_KEY_BYTES]> =
            Zeroizing::new([0u8; X25519_KEY_BYTES]);
        x_sk_bytes.copy_from_slice(&Sha512::digest(&x_seed[..])[..X25519_KEY_BYTES]);
        let x_static = X25519StaticSecret::from(*x_sk_bytes);
        let x_pk = X25519PublicKey::from(&x_static).to_bytes();
        // x_sk is not needed for enrollment — archive path re-derives it.

        // Move ed_sk into a locked page (libsodium format: seed || pk = 64 bytes).
        let mut ed_sk_full = [0u8; ED25519_SK_BYTES];
        ed_sk_full[..ED25519_SEED_BYTES].copy_from_slice(&ed_seed_arr[..]);
        ed_sk_full[ED25519_SEED_BYTES..].copy_from_slice(&ed_pk);
        let mut ed_sk_locked = LockedSecret::new_zeroed(ED25519_SK_BYTES)?;
        ed_sk_locked.write_and_wipe_source(&mut ed_sk_full)?;

        let mut chain_locked = LockedSecret::new_zeroed(CHAIN_KEY_BYTES)?;
        // chain_bytes is Zeroizing<Vec<u8>>, clone into fixed buffer then wipe.
        let mut chain_arr = [0u8; CHAIN_KEY_BYTES];
        chain_arr.copy_from_slice(&chain_bytes[..]);
        chain_locked.write_and_wipe_source(&mut chain_arr)?;

        let identity = StreamIdentity {
            ed25519_pk: ed_pk,
            x25519_pk: x_pk,
        };
        Ok(Self {
            identity,
            signing_key: Some(ed_sk_locked),
            chain_0: Some(chain_locked),
        })
    }

    /// The public identity, safe to clone and publish.
    #[must_use]
    pub fn identity(&self) -> &StreamIdentity {
        &self.identity
    }

    /// Sign `message` with the long-term Ed25519 key under an explicit
    /// signature `domain` (R-C-1 domain separation).
    ///
    /// The long-term key signs two distinct things — `concat(batch_0_pks)` at
    /// enrollment ([`SignatureDomain::Enrollment`]) and `nonce‖ts` for archive
    /// auth ([`SignatureDomain::ArchiveAuth`]) — so the caller MUST pass the
    /// matching domain; its one-byte tag is prepended to `message` before
    /// signing, and the server mirrors it.
    /// Kotlin allows multiple calls before close; we keep the same relaxed
    /// contract — the consume-once enforcement is on [`Self::take_chain_zero`]
    /// and is effectively enforced by the kit dropping shortly after enroll.
    ///
    /// # Errors
    /// Returns [`CryptoError::AlreadyConsumed`] if called after `close()`, or
    /// [`CryptoError::DerivationFailed`] if the locked buffer is not the
    /// expected 64-byte size (should never happen — the kit constructor
    /// guarantees the layout).
    pub fn sign_once(
        &self,
        message: &[u8],
        domain: SignatureDomain,
    ) -> Result<[u8; 64], CryptoError> {
        let sk = self
            .signing_key
            .as_ref()
            .ok_or(CryptoError::AlreadyConsumed("ed25519_signing_key"))?;
        sk.with_bytes(|bytes| {
            // RT-11: hold the seed in `Zeroizing` so the stack copy is wiped
            // at scope exit, even though the source `bytes` is in mlock'd
            // memory. The 32-byte stack buffer feeding `SigningKey::from_bytes`
            // wouldn't otherwise be zeroed when the closure returns.
            if bytes.len() < ED25519_SEED_BYTES {
                return Err(CryptoError::DerivationFailed(
                    "ed25519 seed slice size".into(),
                ));
            }
            let mut seed: Zeroizing<[u8; ED25519_SEED_BYTES]> =
                Zeroizing::new([0u8; ED25519_SEED_BYTES]);
            seed.copy_from_slice(&bytes[..ED25519_SEED_BYTES]);
            let signing = SigningKey::from_bytes(&seed);
            let tbs = domain.prefixed(message);
            Ok(signing.sign(&tbs).to_bytes())
        })
    }

    /// Consume the `chain_0` key, handing ownership to the ratchet.
    ///
    /// Single-shot: after this call the kit's internal `chain_0` slot is
    /// `None` and subsequent calls return [`CryptoError::AlreadyConsumed`].
    ///
    /// # Errors
    /// [`CryptoError::AlreadyConsumed`] on second call.
    pub fn take_chain_zero(&mut self) -> Result<LockedSecret, CryptoError> {
        self.chain_0
            .take()
            .ok_or(CryptoError::AlreadyConsumed("chain_0"))
    }

    /// Proactively wipe both secrets before drop. Rare in practice — letting
    /// the kit go out of scope has the same effect via `Drop`.
    pub fn close(&mut self) {
        self.signing_key = None;
        self.chain_0 = None;
    }
}

impl Drop for EnrollmentKit {
    fn drop(&mut self) {
        // Fields implement Drop themselves (LockedSecret wipes + munlocks);
        // setting them to None triggers the Drop chain deterministically.
        self.signing_key = None;
        self.chain_0 = None;
    }
}

impl std::fmt::Debug for EnrollmentKit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "EnrollmentKit(identity={:?}, signing_key=<redacted>, chain_0=<redacted>)",
            self.identity
        )
    }
}

// ============================================================================
// ArchiveIdentity — re-derivable on demand for unsealing archived streams.
// ============================================================================

/// Holder of the X25519 private half, for unsealing archived session keys.
///
/// Derived on demand from the BIP-39 phrase (not stored on disk). The X25519
/// secret lives in a [`LockedSecret`] (mlock'd). Callers should drop this
/// instance as soon as the archive-mode session ends.
#[must_use]
pub struct ArchiveIdentity {
    identity: StreamIdentity,
    x25519_sk: LockedSecret,
}

impl ArchiveIdentity {
    /// Re-derive the archive identity from a BIP-39 mnemonic + passphrase.
    ///
    /// # Errors
    /// * [`CryptoError::InvalidMnemonicWord`] if the phrase contains unknown words.
    /// * [`CryptoError::DerivationFailed`] on HKDF / mlock failures.
    pub fn from_mnemonic(mnemonic: &str, passphrase: &str) -> Result<Self, CryptoError> {
        let seed = bip39::mnemonic_to_seed(mnemonic, passphrase, Language::French)?;

        let ed_seed = hkdf::sha256(seed.as_bytes(), None, CTX_IDENTITY, ED25519_SEED_BYTES)?;
        let x_seed = hkdf::sha256(seed.as_bytes(), None, CTX_ENCRYPTION, X25519_KEY_BYTES)?;

        // Ed25519 public key (we don't keep its secret — only used for fingerprint display).
        // RT-11: wipe this stack copy of the identity seed at scope exit.
        let ed_seed_arr: Zeroizing<[u8; ED25519_SEED_BYTES]> = Zeroizing::new(
            ed_seed[..]
                .try_into()
                .map_err(|_| CryptoError::DerivationFailed("ed seed length".into()))?,
        );
        let ed_pk = SigningKey::from_bytes(&ed_seed_arr)
            .verifying_key()
            .to_bytes();

        // X25519 libsodium seed_keypair derivation.
        let mut x_sk_bytes = [0u8; X25519_KEY_BYTES];
        x_sk_bytes.copy_from_slice(&Sha512::digest(&x_seed[..])[..X25519_KEY_BYTES]);
        let x_pk = X25519PublicKey::from(&X25519StaticSecret::from(x_sk_bytes)).to_bytes();

        // Move x_sk into a locked page.
        let mut x_sk_locked = LockedSecret::new_zeroed(X25519_KEY_BYTES)?;
        x_sk_locked.write_and_wipe_source(&mut x_sk_bytes)?;

        let identity = StreamIdentity {
            ed25519_pk: ed_pk,
            x25519_pk: x_pk,
        };
        Ok(Self {
            identity,
            x25519_sk: x_sk_locked,
        })
    }

    /// The public identity — same fingerprint as [`EnrollmentKit::identity`].
    #[must_use]
    pub fn identity(&self) -> &StreamIdentity {
        &self.identity
    }

    /// Read-only scoped access to the 32-byte X25519 secret scalar. Used by
    /// S6's `crypto_box_seal_open` to unseal archived session keys.
    pub fn with_x25519_sk<R>(&self, f: impl FnOnce(&[u8]) -> R) -> R {
        self.x25519_sk.with_bytes(f)
    }

    /// Unseal a session key that was produced by `crypto_box_seal(K_s, x25519_pk)`
    /// (either by our [`crate::seal::seal`] or libsodium on the Android side).
    ///
    /// The 80-byte `sealed_envelope` layout is `epk(32) || tag(16) || ct(32)`.
    /// The returned 32-byte session key wipes on drop.
    ///
    /// # Errors
    /// * [`CryptoError::InvalidBlob`] if the envelope is the wrong size.
    /// * [`CryptoError::WrongPin`] if the AEAD tag fails verification, i.e.
    ///   the envelope was not sealed *for this identity* (or is tampered).
    pub fn decrypt_session_key(
        &self,
        sealed_envelope: &[u8],
    ) -> Result<zeroize::Zeroizing<Vec<u8>>, CryptoError> {
        let expected = crate::seal::SEAL_OVERHEAD + 32;
        if sealed_envelope.len() != expected {
            return Err(CryptoError::InvalidBlob(format!(
                "sealed envelope must be {expected} bytes, got {}",
                sealed_envelope.len()
            )));
        }
        self.x25519_sk.with_bytes(|sk_bytes| {
            let sk: [u8; 32] = sk_bytes
                .try_into()
                .map_err(|_| CryptoError::DerivationFailed("x25519 sk slice".into()))?;
            crate::seal::seal_open(sealed_envelope, &self.identity.x25519_pk, &sk)
        })
    }
}

impl std::fmt::Debug for ArchiveIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ArchiveIdentity(identity={:?}, x25519_sk=<redacted>)",
            self.identity
        )
    }
}

// ============================================================================
// Helpers
// ============================================================================

fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        // write! to String cannot fail; explicit `let _ =` silences the
        // unused Result while avoiding .unwrap().
        let _ = write!(s, "{b:02x}");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    const MN_FIXED: &str = "abaisser abandon abdiquer abeille abolir aborder aboutir aboyer abrasif abreuver abriter abroger";

    #[test]
    fn enrollment_kit_identity_matches_archive_identity() {
        // Same mnemonic/passphrase must produce identical public keys via
        // the enrollment path and the archive path.
        let kit = EnrollmentKit::from_mnemonic(MN_FIXED, "").unwrap();
        let archive = ArchiveIdentity::from_mnemonic(MN_FIXED, "").unwrap();
        assert_eq!(kit.identity().ed25519_pk(), archive.identity().ed25519_pk());
        assert_eq!(kit.identity().x25519_pk(), archive.identity().x25519_pk());
    }

    #[test]
    fn sign_once_then_verify_roundtrip() {
        let kit = EnrollmentKit::from_mnemonic(MN_FIXED, "").unwrap();
        let msg = b"enrollment payload";
        let sig = kit
            .sign_once(msg, crate::signature_domain::SignatureDomain::Enrollment)
            .unwrap();
        kit.identity()
            .verify(
                &crate::signature_domain::SignatureDomain::Enrollment.prefixed(msg),
                &sig,
            )
            .expect("freshly-produced signature must verify");
    }

    #[test]
    fn signature_domains_are_separated() {
        // R-C-1: a signature minted in one domain must NOT verify in another,
        // even though the underlying message bytes are identical.
        let kit = EnrollmentKit::from_mnemonic(MN_FIXED, "").unwrap();
        let msg = b"nonce-or-batch-bytes";
        let dom = crate::signature_domain::SignatureDomain::Enrollment;
        let other = crate::signature_domain::SignatureDomain::ArchiveAuth;
        let sig = kit.sign_once(msg, dom).unwrap();
        // Verifies under its own domain...
        kit.identity()
            .verify(&dom.prefixed(msg), &sig)
            .expect("must verify under its own domain");
        // ...but not under a different domain (the whole point of R-C-1)...
        assert!(matches!(
            kit.identity()
                .verify(&other.prefixed(msg), &sig)
                .unwrap_err(),
            CryptoError::InvalidSignature
        ));
        // ...nor against the bare, untagged message.
        assert!(matches!(
            kit.identity().verify(msg, &sig).unwrap_err(),
            CryptoError::InvalidSignature
        ));
    }

    #[test]
    fn verify_rejects_tampered_message() {
        let kit = EnrollmentKit::from_mnemonic(MN_FIXED, "").unwrap();
        let msg = b"enrollment payload";
        let sig = kit
            .sign_once(msg, crate::signature_domain::SignatureDomain::Enrollment)
            .unwrap();
        let err = kit.identity().verify(b"tampered", &sig).unwrap_err();
        assert!(matches!(err, CryptoError::InvalidSignature));
    }

    #[test]
    fn take_chain_zero_is_consume_once() {
        let mut kit = EnrollmentKit::from_mnemonic(MN_FIXED, "").unwrap();
        let chain = kit.take_chain_zero().unwrap();
        assert_eq!(chain.len(), CHAIN_KEY_BYTES);
        let err = kit.take_chain_zero().unwrap_err();
        assert!(matches!(err, CryptoError::AlreadyConsumed("chain_0")));
    }

    #[test]
    fn close_then_sign_returns_already_consumed() {
        let mut kit = EnrollmentKit::from_mnemonic(MN_FIXED, "").unwrap();
        kit.close();
        let err = kit
            .sign_once(b"msg", crate::signature_domain::SignatureDomain::Enrollment)
            .unwrap_err();
        assert!(matches!(
            err,
            CryptoError::AlreadyConsumed("ed25519_signing_key")
        ));
    }

    #[test]
    fn fingerprint_format_is_six_groups_of_four_hex() {
        let kit = EnrollmentKit::from_mnemonic(MN_FIXED, "").unwrap();
        let fp = kit.identity().readable_fingerprint();
        let groups: Vec<&str> = fp.split(' ').collect();
        assert_eq!(groups.len(), 6, "expected 6 groups, got {fp:?}");
        for g in groups {
            assert_eq!(g.len(), 4);
            assert!(g.chars().all(|c| c.is_ascii_hexdigit()));
        }
    }

    #[test]
    fn debug_redacts_secrets() {
        let kit = EnrollmentKit::from_mnemonic(MN_FIXED, "").unwrap();
        let dbg = format!("{kit:?}");
        assert!(dbg.contains("<redacted>"));
        assert!(!dbg.contains("ed25519_sk="));

        let archive = ArchiveIdentity::from_mnemonic(MN_FIXED, "").unwrap();
        let dbg = format!("{archive:?}");
        assert!(dbg.contains("<redacted>"));
    }
}
