//! Report capability keyring — **relay-blind reports** (Phase C,
//! `docs/RELAY_BLIND_REPORTS.md`; motto: *a seizure exposes nothing*).
//!
//! A report is addressed and authorized by a key derived from the BIP-39 seed,
//! **not** by the witness's identity. The relay stores `report_id → report_pk`
//! and never the identity, so seizing the relay disk reveals no
//! `identity → report → when` link.
//!
//! ## Derivation (a dedicated HKDF context, never identity/ratchet/provenance)
//!
//! ```text
//! master_seed (BIP-39, 64 B)
//!   └─▶ HKDF("stream.report.master.v1", 32) ─────────────▶ report_master  (mlock'd, persisted PIN-sealed)
//!         └─▶ HKDF("stream.report.key.v1" ‖ u32_be(n), 32) ─▶ report_sk_n (Ed25519 seed, transient)
//!               ├─▶ Ed25519_public ─────────────────────────▶ report_pk_n
//!               └─▶ report_id_n = SHA-256("stream.report.id.v1" ‖ report_pk_n)[..16]   (128 bits)
//! ```
//!
//! Two HKDF levels (mirroring [`crate::provenance::ProvenanceSigner`], which
//! persists a *derived* 32-byte seed rather than the master BIP-39 seed): the
//! holder keeps only `report_master`, and `report_sk_n` is derived transiently
//! per operation, used, and wiped. The witness re-derives any `report_id_n`
//! from the phrase alone at rescue (device with no local state), so reports are
//! enumerable by derivation without the relay ever indexing them by identity.
//!
//! ## Signatures (domain-separated, [`SignatureDomain`])
//!
//! - `create_sig = Ed25519(report_sk_n, 0x07 ‖ report_id_n ‖ report_pk_n)` —
//!   authorizes the lazy creation of `report_id_n` at its first chunk PUT.
//! - `write_sig  = Ed25519(report_sk_n, 0x08 ‖ report_id_n ‖ filename ‖ sha256(body))` —
//!   authorizes writing one chunk; rides every PUT.
//!
//! `report_id` is signed as its **raw 16 bytes** (the relay hex-decodes the
//! `{report_id}` path component before verifying), `report_pk` as its raw 32
//! bytes, `sha256(body)` as its raw 32 bytes. The fixed-width `report_id`
//! prefix and `sha256` suffix anchor the variable-length `filename` in the
//! middle unambiguously. The relay (verifier) mirrors these byte layouts in
//! `server/app/routes/upload.py`; changing one invalidates every in-flight
//! report signature.

use crate::bip39::{self, Language};
use crate::error::CryptoError;
use crate::hkdf;
use crate::secret::LockedSecret;
use crate::signature_domain::SignatureDomain;
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

// ============================================================================
// Constants
// ============================================================================

/// Ed25519 public key length.
const PK_BYTES: usize = 32;
/// Ed25519 seed (private) length — RFC 8032, fed to `SigningKey::from_bytes`.
const ED25519_SEED_BYTES: usize = 32;
/// `report_master` width (the persisted, PIN-sealed report seed).
const REPORT_MASTER_BYTES: usize = 32;
/// `report_id` width — 128 bits, rendered as 32 hex chars in URLs.
const REPORT_ID_BYTES: usize = 16;
/// SHA-256 digest / body-hash width.
const HASH_BYTES: usize = 32;

/// HKDF context for the intermediate report seed (distinct from identity /
/// provenance / ratchet — a different context => a different key from the same
/// BIP-39 seed). **Immutable wire constant**: changing it orphans every report.
const CTX_REPORT_MASTER: &[u8] = b"stream.report.master.v1";
/// HKDF context for the per-index report signing seed (suffixed with
/// `u32_be(n)`). **Immutable wire constant.**
const CTX_REPORT_KEY: &[u8] = b"stream.report.key.v1";
/// SHA-256 domain prefix binding a `report_pk` to its `report_id`. **Immutable
/// wire constant** (the relay hex-encodes the result as the report's id).
const CTX_REPORT_ID: &[u8] = b"stream.report.id.v1";
/// HKDF context for the report **directory**'s signing seed — a singleton report
/// (no index) whose blob set is the witness's authoritative list of allocated
/// report indices. A distinct context => a distinct key from every per-index
/// report, so the directory is just another `report_id → report_pk` to the relay
/// (unlinkable to identity), but the rescue device fetches it directly (a fixed,
/// phrase-derived address) to learn `n_max` and enumerate reports EXACTLY rather
/// than by a hole-tolerance guess. **Immutable wire constant.**
const CTX_REPORT_DIRECTORY: &[u8] = b"stream.report.directory.v1";
/// HKDF context for the **opaque name** of a directory entry (M-1, audit
/// 2026-06-26). The directory's blob names used to be the plain decimal index
/// (`%010d`), which (a) fingerprinted the directory as a session counter,
/// distinct from content reports' `<sid>_NNNNNN.strm`, and (b) let a relay
/// operator read `n_max` (session count) and the allocation cadence straight off
/// the names. The name is now `hex(HKDF(report_master, ctx || u32_be(n))[..16])` —
/// opaque, indistinguishable from any other blob. **It is derived from the SECRET
/// `report_master`, never from `directory_pk`**: the relay sees `directory_pk`
/// (the `X-Report-PK` header) and could otherwise re-derive every entry name and
/// recover each index. With the master the name is preimage-resistant and
/// unguessable to the relay; the rescue device, holding the phrase, re-derives it
/// to map name->index. **Immutable wire constant** (changing it orphans every
/// directory entry written under the old context; the rescue dual-reads the
/// legacy `%010d` scheme for forward-compat). The relay never parses this name
/// (it stores + signs over the bytes), so this is a client-writer / client-rescue
/// contract, not a relay one.
const CTX_REPORT_DIR_ENTRY: &[u8] = b"stream.report.directory.entry.v1";

// ============================================================================
// Public, secret-free helper
// ============================================================================

/// Derive the 16-byte `report_id` that a given `report_pk` maps to:
/// `SHA-256("stream.report.id.v1" ‖ report_pk)[..16]`.
///
/// Pure and secret-free (the pk is public), so the relay and the diff-fuzz
/// parity harness can recompute the binding without the keyring. The relay
/// uses this to check `report_id == H(presented report_pk)` before trusting a
/// creation.
#[must_use]
pub fn report_id_from_pk(report_pk: &[u8; PK_BYTES]) -> [u8; REPORT_ID_BYTES] {
    let mut h = Sha256::new();
    h.update(CTX_REPORT_ID);
    h.update(report_pk);
    let digest = h.finalize();
    let mut id = [0u8; REPORT_ID_BYTES];
    id.copy_from_slice(&digest[..REPORT_ID_BYTES]);
    id
}

/// Build + sign a `create_sig` (`0x07 ‖ report_id ‖ report_pk`) under `sk`.
/// Shared by the per-index reports and the directory (same byte layout / domain;
/// only the signing key differs), so a layout change can never drift between them.
fn sign_create_under(sk: &SigningKey) -> [u8; 64] {
    let pk = sk.verifying_key().to_bytes();
    let id = report_id_from_pk(&pk);
    let mut msg = Vec::with_capacity(REPORT_ID_BYTES + PK_BYTES);
    msg.extend_from_slice(&id);
    msg.extend_from_slice(&pk);
    let tbs = SignatureDomain::ReportCreate.prefixed(&msg);
    sk.sign(&tbs).to_bytes()
}

/// Build + sign a `write_sig` (`0x08 ‖ report_id ‖ filename ‖ body_sha256`) under
/// `sk`. Shared by the per-index reports and the directory.
fn sign_write_under(sk: &SigningKey, filename: &[u8], body_sha256: &[u8; HASH_BYTES]) -> [u8; 64] {
    let pk = sk.verifying_key().to_bytes();
    let id = report_id_from_pk(&pk);
    let mut msg = Vec::with_capacity(REPORT_ID_BYTES + filename.len() + HASH_BYTES);
    msg.extend_from_slice(&id);
    msg.extend_from_slice(filename);
    msg.extend_from_slice(body_sha256);
    let tbs = SignatureDomain::ReportWrite.prefixed(&msg);
    sk.sign(&tbs).to_bytes()
}

// ============================================================================
// ReportKeyring — seed-derived secret, derives per-report capability keys
// ============================================================================

/// The witness's report capability keyring. Holds only the intermediate
/// `report_master` (32 bytes, mlock'd, zeroed on drop); every per-report key
/// `report_sk_n` is derived transiently from it.
///
/// Derived once at enrollment ([`Self::from_mnemonic`]); the caller PIN-seals
/// its [`Self::with_master_bytes`] and reloads it at unlock ([`Self::from_seed`])
/// so it is live during recording — its lifecycle mirrors the
/// [`crate::provenance::ProvenanceSigner`] (a seed-derived secret that must
/// survive background recording and is wiped only at lock).
pub struct ReportKeyring {
    report_master: LockedSecret,
}

impl ReportKeyring {
    /// Derive the keyring from a BIP-39 mnemonic (enrollment time). Persist the
    /// `report_master` afterwards via [`Self::with_master_bytes`].
    ///
    /// # Errors
    /// [`CryptoError`] on an invalid mnemonic or an HKDF / mlock failure.
    pub fn from_mnemonic(mnemonic: &str, passphrase: &str) -> Result<Self, CryptoError> {
        let seed = bip39::mnemonic_to_seed(mnemonic, passphrase, Language::French)?;
        let derived = hkdf::sha256(
            seed.as_bytes(),
            None,
            CTX_REPORT_MASTER,
            REPORT_MASTER_BYTES,
        )?;
        let mut master = [0u8; REPORT_MASTER_BYTES];
        master.copy_from_slice(&derived[..]);
        Self::from_master_array(master)
    }

    /// Reconstruct from the persisted 32-byte `report_master` (recording time,
    /// loaded from the PIN-sealed store at unlock).
    ///
    /// # Errors
    /// [`CryptoError::DerivationFailed`] on an mlock failure.
    pub fn from_seed(report_master: &[u8; REPORT_MASTER_BYTES]) -> Result<Self, CryptoError> {
        Self::from_master_array(*report_master)
    }

    fn from_master_array(mut master: [u8; REPORT_MASTER_BYTES]) -> Result<Self, CryptoError> {
        let mut locked = LockedSecret::new_zeroed(REPORT_MASTER_BYTES)?;
        locked.write_and_wipe_source(&mut master)?;
        Ok(Self {
            report_master: locked,
        })
    }

    /// Read-only scoped access to the 32-byte `report_master`, so the caller can
    /// PIN-seal it for persistence (used once, at enrollment). Mirrors
    /// [`crate::provenance::ProvenanceSigner::with_seed_bytes`].
    pub fn with_master_bytes<R>(&self, f: impl FnOnce(&[u8]) -> R) -> R {
        self.report_master.with_bytes(f)
    }

    /// Derive the transient per-index Ed25519 signing key `report_sk_n`. The
    /// seed buffer is wiped at scope exit ([`Zeroizing`]); the returned
    /// `SigningKey` zeroizes on drop (dalek `zeroize` feature), so the secret
    /// never lingers past the caller's use.
    fn report_signing_key(&self, n: u32) -> Result<SigningKey, CryptoError> {
        let mut info = Vec::with_capacity(CTX_REPORT_KEY.len() + 4);
        info.extend_from_slice(CTX_REPORT_KEY);
        info.extend_from_slice(&n.to_be_bytes());
        let okm = self.with_master_bytes(|m| hkdf::sha256(m, None, &info, ED25519_SEED_BYTES))?;
        let mut seed: Zeroizing<[u8; ED25519_SEED_BYTES]> =
            Zeroizing::new([0u8; ED25519_SEED_BYTES]);
        seed.copy_from_slice(&okm[..]);
        Ok(SigningKey::from_bytes(&seed))
    }

    /// The public capability key `report_pk_n` for report index `n`.
    ///
    /// # Errors
    /// [`CryptoError::DerivationFailed`] on an HKDF failure (never with the
    /// valid master length the constructor guarantees).
    pub fn report_pk(&self, n: u32) -> Result<[u8; PK_BYTES], CryptoError> {
        Ok(self.report_signing_key(n)?.verifying_key().to_bytes())
    }

    /// The 16-byte `report_id_n` for report index `n` (the relay-facing,
    /// identity-free address). Re-derivable from the phrase at rescue.
    ///
    /// # Errors
    /// [`CryptoError::DerivationFailed`] on an HKDF failure.
    pub fn report_id(&self, n: u32) -> Result<[u8; REPORT_ID_BYTES], CryptoError> {
        let pk = self.report_pk(n)?;
        Ok(report_id_from_pk(&pk))
    }

    /// `create_sig` for report `n`: `Ed25519(report_sk_n, 0x07 ‖ report_id_n ‖
    /// report_pk_n)`. Authorizes lazy creation at the first chunk PUT; binds the
    /// id to its pk so the relay can verify `report_id == H(report_pk)`.
    ///
    /// # Errors
    /// [`CryptoError::DerivationFailed`] on an HKDF failure.
    pub fn sign_create(&self, n: u32) -> Result<[u8; 64], CryptoError> {
        Ok(sign_create_under(&self.report_signing_key(n)?))
    }

    /// `write_sig` for chunk `filename` of report `n`: `Ed25519(report_sk_n,
    /// 0x08 ‖ report_id_n ‖ filename ‖ body_sha256)`. Rides every chunk PUT;
    /// binds the chunk's name and body hash to the report.
    ///
    /// `body_sha256` MUST be the SHA-256 of the exact bytes the relay stores
    /// (the sealed `.strm`), so the relay's streaming hash matches byte-for-byte.
    ///
    /// # Errors
    /// [`CryptoError::DerivationFailed`] on an HKDF failure.
    pub fn sign_write(
        &self,
        n: u32,
        filename: &[u8],
        body_sha256: &[u8; HASH_BYTES],
    ) -> Result<[u8; 64], CryptoError> {
        Ok(sign_write_under(
            &self.report_signing_key(n)?,
            filename,
            body_sha256,
        ))
    }

    // ========================================================================
    // Report directory — the witness's authoritative `n_max` for exact rescue
    // ========================================================================
    //
    // A singleton report (dedicated HKDF context, no index) whose blob *names*
    // are the opaque `directory_entry_name(n)` of the allocated indices (M-1 —
    // not the plain index). The device appends one tiny blob per session start;
    // at rescue the witness fetches the directory's blob list (id-free) and
    // re-derives `directory_entry_name(0..)` to match the names back to indices
    // (derive-and-match), so it enumerates reports `0..n_max` EXACTLY rather than
    // guessing where to stop with a hole-tolerance constant.
    // To the relay the directory is just another `report_id → report_pk`
    // (phrase-derived, unlinkable to identity), addressed and signed by these
    // same 0x07/0x08 capability sigs.

    /// The directory's transient Ed25519 signing key (no index — a singleton).
    fn directory_signing_key(&self) -> Result<SigningKey, CryptoError> {
        let okm = self.with_master_bytes(|m| {
            hkdf::sha256(m, None, CTX_REPORT_DIRECTORY, ED25519_SEED_BYTES)
        })?;
        let mut seed: Zeroizing<[u8; ED25519_SEED_BYTES]> =
            Zeroizing::new([0u8; ED25519_SEED_BYTES]);
        seed.copy_from_slice(&okm[..]);
        Ok(SigningKey::from_bytes(&seed))
    }

    /// The directory's public capability key `report_pk_directory`.
    ///
    /// # Errors
    /// [`CryptoError::DerivationFailed`] on an HKDF failure.
    pub fn directory_pk(&self) -> Result<[u8; PK_BYTES], CryptoError> {
        Ok(self.directory_signing_key()?.verifying_key().to_bytes())
    }

    /// The directory's 16-byte `report_id` (the fixed, phrase-derived address the
    /// rescue device fetches directly to learn `n_max`).
    ///
    /// # Errors
    /// [`CryptoError::DerivationFailed`] on an HKDF failure.
    pub fn directory_id(&self) -> Result<[u8; REPORT_ID_BYTES], CryptoError> {
        Ok(report_id_from_pk(&self.directory_pk()?))
    }

    /// The opaque blob NAME (16 bytes; rendered as 32 lowercase hex by the
    /// callers) of directory entry `n` (M-1): `HKDF(report_master,
    /// "stream.report.directory.entry.v1" || u32_be(n))[..16]`. This is the
    /// relay-visible filename the device PUTs for session `n`'s directory entry,
    /// replacing the old plain `%010d` index so the directory no longer
    /// fingerprints as a session counter and the index is unreadable from the
    /// name. Derived from the SECRET `report_master` (see [`CTX_REPORT_DIR_ENTRY`])
    /// so the relay cannot enumerate it from the public `directory_pk`. The rescue
    /// device re-derives `directory_entry_name(0..)` and matches against the
    /// directory's blob list to recover `n_max` exactly (derive-and-match).
    ///
    /// # Errors
    /// [`CryptoError::DerivationFailed`] on an HKDF failure.
    pub fn directory_entry_name(&self, n: u32) -> Result<[u8; REPORT_ID_BYTES], CryptoError> {
        let mut info = Vec::with_capacity(CTX_REPORT_DIR_ENTRY.len() + 4);
        info.extend_from_slice(CTX_REPORT_DIR_ENTRY);
        info.extend_from_slice(&n.to_be_bytes());
        let okm = self.with_master_bytes(|m| hkdf::sha256(m, None, &info, REPORT_ID_BYTES))?;
        let mut name = [0u8; REPORT_ID_BYTES];
        name.copy_from_slice(&okm[..]);
        Ok(name)
    }

    /// `create_sig` for the directory's first (creating) entry.
    ///
    /// # Errors
    /// [`CryptoError::DerivationFailed`] on an HKDF failure.
    pub fn sign_directory_create(&self) -> Result<[u8; 64], CryptoError> {
        Ok(sign_create_under(&self.directory_signing_key()?))
    }

    /// `write_sig` for a directory entry (`filename` = the opaque
    /// [`Self::directory_entry_name`] of an index, M-1; signed verbatim).
    ///
    /// # Errors
    /// [`CryptoError::DerivationFailed`] on an HKDF failure.
    pub fn sign_directory_write(
        &self,
        filename: &[u8],
        body_sha256: &[u8; HASH_BYTES],
    ) -> Result<[u8; 64], CryptoError> {
        Ok(sign_write_under(
            &self.directory_signing_key()?,
            filename,
            body_sha256,
        ))
    }
}

impl std::fmt::Debug for ReportKeyring {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ReportKeyring(report_master=<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::EnrollmentKit;
    use crate::provenance::ProvenanceSigner;
    use ed25519_dalek::{Signature, VerifyingKey};

    const MN_FIXED: &str = "abaisser abandon abdiquer abeille abolir aborder aboutir aboyer abrasif abreuver abriter abroger";

    /// Verify `sig` over `domain.prefixed(message)` under `pk` (dalek strict,
    /// matching the relay's libsodium `crypto_sign_open`).
    fn verify(pk: &[u8; 32], domain: SignatureDomain, message: &[u8], sig: &[u8; 64]) -> bool {
        let Ok(vk) = VerifyingKey::from_bytes(pk) else {
            return false;
        };
        vk.verify_strict(&domain.prefixed(message), &Signature::from_bytes(sig))
            .is_ok()
    }

    fn create_msg(id: &[u8; 16], pk: &[u8; 32]) -> Vec<u8> {
        let mut m = Vec::new();
        m.extend_from_slice(id);
        m.extend_from_slice(pk);
        m
    }

    fn write_msg(id: &[u8; 16], filename: &[u8], body_sha256: &[u8; 32]) -> Vec<u8> {
        let mut m = Vec::new();
        m.extend_from_slice(id);
        m.extend_from_slice(filename);
        m.extend_from_slice(body_sha256);
        m
    }

    #[test]
    fn deterministic_and_distinct_from_other_seed_keys() {
        let k1 = ReportKeyring::from_mnemonic(MN_FIXED, "").unwrap();
        let k2 = ReportKeyring::from_mnemonic(MN_FIXED, "").unwrap();
        // Same phrase => same per-index key (re-derivable at rescue).
        assert_eq!(k1.report_pk(0).unwrap(), k2.report_pk(0).unwrap());
        assert_eq!(k1.report_id(7).unwrap(), k2.report_id(7).unwrap());

        // Distinct HKDF context => distinct from identity and provenance keys.
        let kit = EnrollmentKit::from_mnemonic(MN_FIXED, "").unwrap();
        let prov = ProvenanceSigner::from_mnemonic(MN_FIXED, "").unwrap();
        let rpk0 = k1.report_pk(0).unwrap();
        assert_ne!(&rpk0, kit.identity().ed25519_pk());
        assert_ne!(&rpk0, prov.public_key());
    }

    #[test]
    fn per_index_keys_and_ids_are_distinct() {
        let k = ReportKeyring::from_mnemonic(MN_FIXED, "").unwrap();
        let pk0 = k.report_pk(0).unwrap();
        let pk1 = k.report_pk(1).unwrap();
        assert_ne!(pk0, pk1, "different n must yield a different report_pk");
        assert_ne!(
            k.report_id(0).unwrap(),
            k.report_id(1).unwrap(),
            "different n must yield a different report_id"
        );
        // report_id is exactly H(ctx ‖ report_pk)[..16].
        assert_eq!(k.report_id(0).unwrap(), report_id_from_pk(&pk0));
        // u32 index must not silently truncate / alias.
        assert_ne!(k.report_pk(0).unwrap(), k.report_pk(256).unwrap());
        assert_ne!(k.report_pk(1).unwrap(), k.report_pk(0x0100_0001).unwrap());
    }

    #[test]
    fn from_seed_roundtrip_matches_mnemonic() {
        let original = ReportKeyring::from_mnemonic(MN_FIXED, "").unwrap();
        let master: [u8; 32] = original.with_master_bytes(|b| b.try_into().unwrap());
        let restored = ReportKeyring::from_seed(&master).unwrap();
        assert_eq!(
            original.report_pk(3).unwrap(),
            restored.report_pk(3).unwrap()
        );
        assert_eq!(
            original.report_id(3).unwrap(),
            restored.report_id(3).unwrap()
        );
        // A different master (here via passphrase) yields different keys —
        // proves keys are master-bound, not phrase-prefix-bound.
        let other = ReportKeyring::from_mnemonic(MN_FIXED, "p").unwrap();
        assert_ne!(original.report_pk(3).unwrap(), other.report_pk(3).unwrap());
    }

    #[test]
    fn sign_create_verifies_under_report_pk_and_domain() {
        let k = ReportKeyring::from_mnemonic(MN_FIXED, "").unwrap();
        let n = 5;
        let pk = k.report_pk(n).unwrap();
        let id = k.report_id(n).unwrap();
        let sig = k.sign_create(n).unwrap();
        let msg = create_msg(&id, &pk);
        // Verifies under its own (pk, domain)...
        assert!(verify(&pk, SignatureDomain::ReportCreate, &msg, &sig));
        // ...not under the write domain (R-C-1 separation)...
        assert!(!verify(&pk, SignatureDomain::ReportWrite, &msg, &sig));
        // ...not under another report's pk...
        let other_pk = k.report_pk(n + 1).unwrap();
        assert!(!verify(
            &other_pk,
            SignatureDomain::ReportCreate,
            &msg,
            &sig
        ));
        // ...not over a tampered binding (swapped id).
        let bad = create_msg(&k.report_id(n + 1).unwrap(), &pk);
        assert!(!verify(&pk, SignatureDomain::ReportCreate, &bad, &sig));
    }

    #[test]
    fn sign_write_verifies_and_is_bound_to_name_body_and_index() {
        let k = ReportKeyring::from_mnemonic(MN_FIXED, "").unwrap();
        let n = 2;
        let pk = k.report_pk(n).unwrap();
        let id = k.report_id(n).unwrap();
        let filename = b"3f1c9a0e7b2d4f60.strm";
        let body = [0xABu8; 32];
        let sig = k.sign_write(n, filename, &body).unwrap();
        let msg = write_msg(&id, filename, &body);
        assert!(verify(&pk, SignatureDomain::ReportWrite, &msg, &sig));
        // Wrong domain (create) must fail.
        assert!(!verify(&pk, SignatureDomain::ReportCreate, &msg, &sig));
        // Bound to filename.
        let msg_name = write_msg(&id, b"other.strm", &body);
        assert!(!verify(&pk, SignatureDomain::ReportWrite, &msg_name, &sig));
        // Bound to body hash.
        let msg_body = write_msg(&id, filename, &[0xCDu8; 32]);
        assert!(!verify(&pk, SignatureDomain::ReportWrite, &msg_body, &sig));
        // Bound to index: a sig for n must not verify against report n+1's id/pk.
        let pk2 = k.report_pk(n + 1).unwrap();
        let id2 = k.report_id(n + 1).unwrap();
        let msg2 = write_msg(&id2, filename, &body);
        assert!(!verify(&pk2, SignatureDomain::ReportWrite, &msg2, &sig));
    }

    #[test]
    fn create_and_write_signatures_do_not_cross_verify() {
        // A create_sig and a write_sig over coincidental bytes never interchange
        // (the whole point of the 0x07/0x08 domain tags).
        let k = ReportKeyring::from_mnemonic(MN_FIXED, "").unwrap();
        let n = 9;
        let pk = k.report_pk(n).unwrap();
        let id = k.report_id(n).unwrap();
        let create = k.sign_create(n).unwrap();
        let write = k.sign_write(n, b"x", &[0u8; 32]).unwrap();
        let create_msg = create_msg(&id, &pk);
        let write_msg = write_msg(&id, b"x", &[0u8; 32]);
        // Each verifies only in its own lane.
        assert!(verify(
            &pk,
            SignatureDomain::ReportCreate,
            &create_msg,
            &create
        ));
        assert!(verify(
            &pk,
            SignatureDomain::ReportWrite,
            &write_msg,
            &write
        ));
        // Cross-checks fail both ways.
        assert!(!verify(
            &pk,
            SignatureDomain::ReportWrite,
            &write_msg,
            &create
        ));
        assert!(!verify(
            &pk,
            SignatureDomain::ReportCreate,
            &create_msg,
            &write
        ));
    }

    #[test]
    fn directory_is_distinct_from_indexed_reports_and_signs() {
        let k = ReportKeyring::from_mnemonic(MN_FIXED, "").unwrap();
        let dir_pk = k.directory_pk().unwrap();
        let dir_id = k.directory_id().unwrap();
        // Deterministic (re-derivable at rescue from the phrase alone).
        let k2 = ReportKeyring::from_mnemonic(MN_FIXED, "").unwrap();
        assert_eq!(dir_pk, k2.directory_pk().unwrap());
        assert_eq!(dir_id, k2.directory_id().unwrap());
        // report_id == H(ctx ‖ pk) like any report.
        assert_eq!(dir_id, report_id_from_pk(&dir_pk));
        // Distinct from EVERY per-index report (different HKDF context) — probe a
        // spread of indices incl. the ones the per-index test guards.
        for n in [0u32, 1, 7, 256, 4096, 0x0100_0001, u32::MAX] {
            assert_ne!(
                dir_pk,
                k.report_pk(n).unwrap(),
                "directory collides with report {n}"
            );
            assert_ne!(
                dir_id,
                k.report_id(n).unwrap(),
                "directory id collides with report {n}"
            );
        }
        // create_sig / write_sig verify under the directory pk + their domains,
        // and don't cross-verify (0x07/0x08 separation), same as indexed reports.
        let create = k.sign_directory_create().unwrap();
        let filename = b"00000005";
        let body = [0x5Au8; 32];
        let write = k.sign_directory_write(filename, &body).unwrap();
        assert!(verify(
            &dir_pk,
            SignatureDomain::ReportCreate,
            &create_msg(&dir_id, &dir_pk),
            &create
        ));
        assert!(verify(
            &dir_pk,
            SignatureDomain::ReportWrite,
            &write_msg(&dir_id, filename, &body),
            &write
        ));
        assert!(!verify(
            &dir_pk,
            SignatureDomain::ReportWrite,
            &write_msg(&dir_id, filename, &body),
            &create
        ));
        assert!(!verify(
            &dir_pk,
            SignatureDomain::ReportCreate,
            &create_msg(&dir_id, &dir_pk),
            &write
        ));
    }

    #[test]
    fn directory_entry_names_are_opaque_deterministic_and_secret_bound() {
        let k = ReportKeyring::from_mnemonic(MN_FIXED, "").unwrap();
        // Deterministic (re-derivable at rescue from the phrase alone).
        let k2 = ReportKeyring::from_mnemonic(MN_FIXED, "").unwrap();
        assert_eq!(
            k.directory_entry_name(5).unwrap(),
            k2.directory_entry_name(5).unwrap()
        );
        // Distinct per index (incl. byte-boundary indices, like the report keys).
        assert_ne!(
            k.directory_entry_name(0).unwrap(),
            k.directory_entry_name(1).unwrap()
        );
        assert_ne!(
            k.directory_entry_name(0).unwrap(),
            k.directory_entry_name(256).unwrap()
        );
        assert_ne!(
            k.directory_entry_name(1).unwrap(),
            k.directory_entry_name(0x0100_0001).unwrap()
        );

        // Opaque: the 32-hex name does NOT readably encode the index — it never
        // parses back as the decimal index (the M-1 fingerprint we removed), and
        // it is NOT the old `%010d` form. This disjointness is exactly what lets
        // the rescue dual-read legacy + opaque entries without ambiguity.
        let name0 = to_hex(&k.directory_entry_name(0).unwrap());
        assert_eq!(name0.len(), 32, "16 bytes -> 32 lowercase hex chars");
        assert!(
            name0.parse::<u32>().is_err(),
            "an opaque name must never parse as its index"
        );
        assert_ne!(
            name0,
            format!("{:010}", 0),
            "must not be the legacy %010d form"
        );

        // Secret-bound: a different master (here via passphrase) yields different
        // names, so the relay — which sees only directory_pk, never report_master —
        // cannot derive (and thus cannot enumerate) the entry names.
        let other = ReportKeyring::from_mnemonic(MN_FIXED, "p").unwrap();
        assert_ne!(
            k.directory_entry_name(3).unwrap(),
            other.directory_entry_name(3).unwrap()
        );

        // Distinct from the directory's own report_id and from any per-index
        // report_id (different HKDF context => no aliasing into addressing).
        assert_ne!(
            k.directory_entry_name(0).unwrap(),
            k.directory_id().unwrap()
        );
        for n in [0u32, 1, 7, 256] {
            assert_ne!(
                k.directory_entry_name(n).unwrap(),
                k.report_id(n).unwrap(),
                "entry name collides with report_id {n}"
            );
        }

        // Regression KAT — pin n=0 so an accidental change to the context or the
        // derivation (which would silently orphan every directory entry already on
        // the relay) breaks this test. On a DELIBERATE change, run with
        // `--nocapture` and copy the printed value here.
        println!("KAT directory_entry_name(0) = {name0}");
        assert_eq!(name0, EXP_DIR_ENTRY_NAME_0, "directory_entry_name(0) drift");
    }

    const EXP_DIR_ENTRY_NAME_0: &str = "988deb4340e1dde7d40a40e19803b163";

    #[test]
    fn debug_redacts_master() {
        let k = ReportKeyring::from_mnemonic(MN_FIXED, "").unwrap();
        let dbg = format!("{k:?}");
        assert!(dbg.contains("<redacted>"));
        assert!(dbg.contains("ReportKeyring"));
    }

    // ---- Cross-language KAT (audit ③) --------------------------------------
    //
    // Fixed report-capability vectors derived by THIS crate from `MN_FIXED`,
    // pinned here AND verified byte-for-byte by the relay in
    // `server/tests/test_report_sig_kat.py`. Rust PRODUCES the signatures; the
    // Python relay must VERIFY these exact bytes against its own reconstructed
    // messages. The relay-blind report sigs are the one crypto contract whose
    // Rust↔server parity was only HAND-checked (the diff-fuzz corpus is
    // Kotlin↔Rust and the route tests sign in Python with the server's own
    // constants, so they cannot catch a one-sided drift). This KAT closes that:
    // a change to the report-id context, the 0x07/0x08 domain tags, the message
    // byte-layout, or the key derivation breaks one side's test. If you change
    // the report crypto ON PURPOSE, run this test with `--nocapture`, copy the
    // printed values into both `EXP_*` below and the Python KAT.

    const KAT_FILENAME: &[u8] = b"kat_000000.strm";

    /// The KAT chunk body hash: bytes `00 01 02 … 1f` (Python: `bytes(range(32))`).
    fn kat_body_sha256() -> [u8; 32] {
        [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ]
    }

    fn to_hex(bytes: &[u8]) -> String {
        use std::fmt::Write as _;
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            let _ = write!(s, "{b:02x}");
        }
        s
    }

    const EXP_REPORT_PK: &str = "5339770a3e754ca07f33f7f1d183f2a2f162795a575b885dd6b8d0fa416ebc47";
    const EXP_REPORT_ID: &str = "21e4f004dfb2b5da3e14537505f19f92";
    const EXP_CREATE_SIG: &str = "3ef66c784192466fb5eda1e2191247024f014fbd34e9f94c6a110c3ab68d7677\
         0a685e5c982cf90dc251049706bd9323c685911704371bc994c20ffe48cb1b07";
    const EXP_WRITE_SIG: &str = "76a6fae277d4ac08831c36823a810cbd35e049763e734f4b6f5c6e9e6c6765fb\
         779297c175165648e9dc6d12c8c22fcde7d9b7a0eb58a6736ff9593f4b559603";

    #[test]
    fn report_sig_cross_language_kat() {
        let k = ReportKeyring::from_mnemonic(MN_FIXED, "").unwrap();
        let pk = k.report_pk(0).unwrap();
        let id = k.report_id(0).unwrap();
        let body = kat_body_sha256();
        let create_sig = k.sign_create(0).unwrap();
        let write_sig = k.sign_write(0, KAT_FILENAME, &body).unwrap();

        // Emit the vectors so the Python KAT can be regenerated on a deliberate
        // crypto change (`cargo test report_sig_cross_language_kat -- --nocapture`).
        println!("KAT report_pk   = {}", to_hex(&pk));
        println!("KAT report_id   = {}", to_hex(&id));
        println!("KAT body_sha256 = {}", to_hex(&body));
        println!("KAT create_sig  = {}", to_hex(&create_sig));
        println!("KAT write_sig   = {}", to_hex(&write_sig));

        // Pin the exact bytes (catches a Rust-side drift). MUST equal the Python
        // KAT constants.
        assert_eq!(to_hex(&pk), EXP_REPORT_PK, "report_pk drift");
        assert_eq!(to_hex(&id), EXP_REPORT_ID, "report_id drift");
        assert_eq!(to_hex(&create_sig), EXP_CREATE_SIG, "create_sig drift");
        assert_eq!(to_hex(&write_sig), EXP_WRITE_SIG, "write_sig drift");

        // Live cross-check: the pinned sigs verify under their own domains.
        assert!(verify(
            &pk,
            SignatureDomain::ReportCreate,
            &create_msg(&id, &pk),
            &create_sig
        ));
        assert!(verify(
            &pk,
            SignatureDomain::ReportWrite,
            &write_msg(&id, KAT_FILENAME, &body),
            &write_sig
        ));
    }
}
