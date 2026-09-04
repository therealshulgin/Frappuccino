//! Provenance primitives — the **lean "hash + Bitcoin" model** (ROADMAP §10.11).
//!
//! After the metadata walk-back (2026-06-25, motto: *a seizure exposes nothing*),
//! provenance is reduced to its irreducible, non-exposing core:
//!
//! 1. **Integrity** — [`hash_plaintext_chunk`] over each plaintext chunk, folded
//!    into a [`chunk_merkle_root`]. Recomputable from the disclosed chunks at
//!    verify time, so nothing has to be stored.
//! 2. **Anteriority** — that root, salted, is committed to Bitcoin via
//!    `OpenTimestamps` (the commitment is [`ots_media_commitment`]).
//!
//! There is deliberately **no manifest, no signature, no sealing, no identity
//! attestation**. Those existed only to bake *attribution* into a stored,
//! seizable artifact — which, against a state adversary, is a liability for the
//! witness, not an asset (non-repudiation becomes a weapon; a stored
//! identity↔recording map is exactly what a seizure must not expose). Attribution
//! is therefore **on-demand**: a witness signs a disclosure statement with their
//! identity key when and to whom they choose — never committed here.
//!
//! What remains of the old machinery is the [`ProvenanceSigner`]: a dedicated,
//! seed-derived secret kept **only** to derive the per-recording OTS blinding
//! salt ([`ProvenanceSigner::ots_salt`]). The salt blinds the public Bitcoin
//! breadcrumb so a logging relay — or anyone holding the recording later — cannot
//! link the on-chain timestamp to it without the witness disclosing the salt
//! (re-derivable from the BIP-39 phrase, never transmitted).

use crate::bip39::{self, Language};
use crate::error::CryptoError;
use crate::hkdf;
use crate::secret::LockedSecret;
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};

// ============================================================================
// Constants
// ============================================================================

/// Length of a SHA-256 digest / chunk hash / Merkle node.
const HASH_BYTES: usize = 32;
/// Recording identifier length (= reportId, already non-identifying).
const RECORDING_ID_BYTES: usize = 16;
/// Ed25519 public key length.
const PK_BYTES: usize = 32;

// Domain tags keep the Merkle leaf / node / empty hashes from ever colliding
// (second-preimage hardening).
const MERKLE_LEAF_TAG: u8 = 0x00;
const MERKLE_NODE_TAG: u8 = 0x01;
const MERKLE_EMPTY_TAG: u8 = 0x02;

/// HKDF context for the dedicated provenance key (distinct from the long-term
/// identity key — a different context => a different key from the same seed).
const CTX_PROVENANCE: &[u8] = b"stream.provenance.ed25519.v1";
const PROV_SEED_BYTES: usize = 32;

/// §10.11 — width of the per-recording `OpenTimestamps` commitment salt (full
/// SHA-256) and its HKDF context. The salt blinds the public Bitcoin breadcrumb
/// and is derived from the secret provenance seed, so a relay (which never sees
/// the seed) can't recompute it.
const OTS_SALT_BYTES: usize = 32;
const CTX_OTS_SALT: &[u8] = b"stream.provenance.ots-salt.v1";

// ============================================================================
// ProvenanceSigner — seed-derived secret, kept only to derive the OTS salt
// ============================================================================

/// The witness's dedicated provenance secret. A separate Ed25519 key derived
/// from the BIP-39 seed under its own HKDF context — never the device, never the
/// long-term identity key. Derived once at enrollment ([`Self::from_mnemonic`]);
/// the caller PIN-seals its [`Self::with_seed_bytes`] and reloads it at unlock
/// ([`Self::from_seed`]) so it is live during recording.
///
/// In the lean model it no longer *signs* anything — its sole job is to derive
/// the per-recording OTS blinding salt ([`Self::ots_salt`]). The public half is
/// retained as a stable per-witness identifier for tests/diagnostics.
///
/// The 32-byte seed lives in an mlock'd [`LockedSecret`] and is zeroed on drop.
pub struct ProvenanceSigner {
    public_key: [u8; PK_BYTES],
    signing_seed: LockedSecret,
}

impl ProvenanceSigner {
    /// Derive the provenance key from a BIP-39 mnemonic (enrollment time).
    /// Persist the seed afterwards via [`Self::with_seed_bytes`].
    ///
    /// # Errors
    /// [`CryptoError`] on an invalid mnemonic or an HKDF / mlock failure.
    pub fn from_mnemonic(mnemonic: &str, passphrase: &str) -> Result<Self, CryptoError> {
        let seed = bip39::mnemonic_to_seed(mnemonic, passphrase, Language::French)?;
        let derived = hkdf::sha256(seed.as_bytes(), None, CTX_PROVENANCE, PROV_SEED_BYTES)?;
        let mut seed_arr = [0u8; PROV_SEED_BYTES];
        seed_arr.copy_from_slice(&derived[..]);
        Self::from_seed_array(seed_arr)
    }

    /// Reconstruct from the persisted 32-byte provenance seed (recording time,
    /// loaded from the PIN-sealed store at unlock).
    ///
    /// # Errors
    /// [`CryptoError::DerivationFailed`] on an mlock failure.
    pub fn from_seed(seed: &[u8; PROV_SEED_BYTES]) -> Result<Self, CryptoError> {
        Self::from_seed_array(*seed)
    }

    fn from_seed_array(mut seed_arr: [u8; PROV_SEED_BYTES]) -> Result<Self, CryptoError> {
        let public_key = SigningKey::from_bytes(&seed_arr).verifying_key().to_bytes();
        let mut locked = LockedSecret::new_zeroed(PROV_SEED_BYTES)?;
        locked.write_and_wipe_source(&mut seed_arr)?;
        Ok(Self {
            public_key,
            signing_seed: locked,
        })
    }

    /// The provenance public key — a stable per-witness identifier (no longer a
    /// manifest `signer_pk`, since nothing is signed in the lean model).
    #[must_use]
    pub fn public_key(&self) -> &[u8; PK_BYTES] {
        &self.public_key
    }

    /// Read-only scoped access to the 32-byte seed, so the caller can PIN-seal
    /// it for persistence (used once, at enrollment). Mirrors
    /// `ArchiveIdentity::with_x25519_sk`.
    pub fn with_seed_bytes<R>(&self, f: impl FnOnce(&[u8]) -> R) -> R {
        self.signing_seed.with_bytes(f)
    }

    /// §10.11 — derive the per-recording `OpenTimestamps` commitment salt from
    /// the provenance seed. Deterministic in `recording_id`, so it is
    /// re-derivable from the BIP-39 phrase at rescue (never stored, never sent to
    /// the relay): `HKDF-SHA256(ikm = seed, info = CTX_OTS_SALT ‖ recording_id)`.
    ///
    /// # Errors
    /// [`CryptoError::DerivationFailed`] on an HKDF failure (never with the valid
    /// seed length the constructor guarantees).
    pub fn ots_salt(
        &self,
        recording_id: &[u8; RECORDING_ID_BYTES],
    ) -> Result<[u8; OTS_SALT_BYTES], CryptoError> {
        let mut info = Vec::with_capacity(CTX_OTS_SALT.len() + RECORDING_ID_BYTES);
        info.extend_from_slice(CTX_OTS_SALT);
        info.extend_from_slice(recording_id);
        let okm = self.with_seed_bytes(|seed| hkdf::sha256(seed, None, &info, OTS_SALT_BYTES))?;
        let mut salt = [0u8; OTS_SALT_BYTES];
        salt.copy_from_slice(&okm[..]);
        Ok(salt)
    }
}

impl std::fmt::Debug for ProvenanceSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ProvenanceSigner(public_key={:02x?}, signing_seed=<redacted>)",
            &self.public_key
        )
    }
}

// ============================================================================
// Public helpers — integrity (Merkle root) + the salted OTS commitment
// ============================================================================

/// SHA-256 of one plaintext media chunk — the leaf input to the media root.
#[must_use]
pub fn hash_plaintext_chunk(chunk: &[u8]) -> [u8; HASH_BYTES] {
    sha256_concat(&[chunk])
}

/// Merkle root over an ordered list of plaintext chunk hashes — the media
/// integrity commitment. Order-sensitive and domain-separated.
#[must_use]
pub fn chunk_merkle_root(chunk_hashes: &[[u8; HASH_BYTES]]) -> [u8; HASH_BYTES] {
    merkle_root(chunk_hashes)
}

/// §10.11 (lean "hash + Bitcoin") — the salted `OpenTimestamps` commitment over
/// the media Merkle root: `SHA-256(salt ‖ root)`. The root ([`chunk_merkle_root`])
/// binds the whole video (integrity); the salt ([`ProvenanceSigner::ots_salt`])
/// blinds the public Bitcoin breadcrumb. This is the single value the device
/// submits to the relay for timestamping — no signature, no manifest.
#[must_use]
pub fn ots_media_commitment(
    salt: &[u8; OTS_SALT_BYTES],
    root: &[u8; HASH_BYTES],
) -> [u8; HASH_BYTES] {
    sha256_concat(&[&salt[..], &root[..]])
}

// ============================================================================
// Internal: Merkle + SHA-256
// ============================================================================

/// Binary Merkle root with domain-separated leaf / node hashing. Odd nodes are
/// promoted unchanged (no duplicate-node ambiguity). Empty input maps to a fixed
/// domain-tagged constant.
fn merkle_root(leaves: &[[u8; HASH_BYTES]]) -> [u8; HASH_BYTES] {
    if leaves.is_empty() {
        return sha256_concat(&[&[MERKLE_EMPTY_TAG]]);
    }
    let mut level: Vec<[u8; HASH_BYTES]> = leaves
        .iter()
        .map(|l| sha256_concat(&[&[MERKLE_LEAF_TAG], l]))
        .collect();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut pair = level.chunks_exact(2);
        for c in &mut pair {
            next.push(sha256_concat(&[&[MERKLE_NODE_TAG], &c[0], &c[1]]));
        }
        if let [last] = pair.remainder() {
            next.push(*last);
        }
        level = next;
    }
    // `level` has exactly one element here (loop exits at len == 1, and a
    // non-empty input never collapses to zero). Fold to avoid indexing.
    level.into_iter().next().unwrap_or([0u8; HASH_BYTES])
}

fn sha256_concat(parts: &[&[u8]]) -> [u8; HASH_BYTES] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    let digest = h.finalize();
    let mut out = [0u8; HASH_BYTES];
    out.copy_from_slice(&digest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::EnrollmentKit;

    const MN_FIXED: &str = "abaisser abandon abdiquer abeille abolir aborder aboutir aboyer abrasif abreuver abriter abroger";

    #[test]
    fn chunk_merkle_root_is_order_sensitive() {
        let a = hash_plaintext_chunk(b"a");
        let b = hash_plaintext_chunk(b"b");
        let c = hash_plaintext_chunk(b"c");
        let r1 = chunk_merkle_root(&[a, b, c]);
        let r2 = chunk_merkle_root(&[b, a, c]);
        assert_ne!(r1, r2, "swapping two chunks must change the root");
        // Stable / deterministic.
        assert_eq!(r1, chunk_merkle_root(&[a, b, c]));
        // Single-leaf and empty are well-defined and distinct.
        assert_ne!(chunk_merkle_root(&[a]), chunk_merkle_root(&[]));
    }

    // ----- ProvenanceSigner (dedicated, seed-derived; salt deriver) -----

    #[test]
    fn provenance_signer_deterministic_and_distinct_from_identity() {
        let s1 = ProvenanceSigner::from_mnemonic(MN_FIXED, "").unwrap();
        let s2 = ProvenanceSigner::from_mnemonic(MN_FIXED, "").unwrap();
        assert_eq!(
            s1.public_key(),
            s2.public_key(),
            "same phrase must derive the same provenance key"
        );
        // Distinct HKDF context => distinct from the long-term identity key.
        let kit = EnrollmentKit::from_mnemonic(MN_FIXED, "").unwrap();
        assert_ne!(
            s1.public_key(),
            kit.identity().ed25519_pk(),
            "provenance key must not equal the identity key"
        );
    }

    #[test]
    fn provenance_signer_from_seed_roundtrip() {
        let original = ProvenanceSigner::from_mnemonic(MN_FIXED, "").unwrap();
        // The enrollment-time path: extract the seed to persist (PIN-sealed).
        let seed: [u8; 32] = original.with_seed_bytes(|b| b.try_into().unwrap());
        // The recording-time path: reload from the persisted seed.
        let restored = ProvenanceSigner::from_seed(&seed).unwrap();
        assert_eq!(
            original.public_key(),
            restored.public_key(),
            "reconstructing from the persisted seed yields the same key"
        );
    }

    #[test]
    fn provenance_signer_debug_redacts_seed() {
        let signer = ProvenanceSigner::from_mnemonic(MN_FIXED, "").unwrap();
        let dbg = format!("{signer:?}");
        assert!(dbg.contains("<redacted>"));
        assert!(dbg.contains("ProvenanceSigner"));
    }

    // ----- OpenTimestamps salt + media commitment (lean model) -----

    #[test]
    fn ots_salt_deterministic_seed_and_recording_bound() {
        let s = ProvenanceSigner::from_mnemonic(MN_FIXED, "").unwrap();
        let rid_a = [7u8; RECORDING_ID_BYTES];
        let rid_b = [8u8; RECORDING_ID_BYTES];
        let salt_a1 = s.ots_salt(&rid_a).unwrap();
        let salt_a2 = s.ots_salt(&rid_a).unwrap();
        let salt_b = s.ots_salt(&rid_b).unwrap();
        // Deterministic in (seed, recording_id): re-derivable at rescue from the
        // phrase + the recording_id.
        assert_eq!(
            salt_a1, salt_a2,
            "same seed+recording_id must yield the same salt"
        );
        // Per-recording: a different recording_id yields a different salt.
        assert_ne!(
            salt_a1, salt_b,
            "different recording_id must yield a different salt"
        );
        // Seed-bound: a different seed (here via a BIP-39 passphrase) yields a
        // different salt — the relay, holding no seed, cannot recompute it.
        let s_other = ProvenanceSigner::from_mnemonic(MN_FIXED, "a-passphrase").unwrap();
        assert_ne!(
            salt_a1,
            s_other.ots_salt(&rid_a).unwrap(),
            "a different provenance seed must yield a different salt"
        );
    }

    #[test]
    fn ots_media_commitment_is_salt_then_root() {
        // Lean "hash + Bitcoin" contract: SHA-256(salt ‖ media root), no signature.
        let salt = [9u8; OTS_SALT_BYTES];
        let root = chunk_merkle_root(&[[4u8; HASH_BYTES], [5u8; HASH_BYTES]]);
        let c = ots_media_commitment(&salt, &root);
        assert_eq!(c, sha256_concat(&[&salt[..], &root[..]]));
        // Salt-bound and root-bound: changing either changes the commitment.
        assert_ne!(c, ots_media_commitment(&[1u8; OTS_SALT_BYTES], &root));
        assert_ne!(c, ots_media_commitment(&salt, &[7u8; HASH_BYTES]));
    }
}
