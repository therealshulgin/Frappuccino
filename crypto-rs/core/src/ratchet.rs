//! Ephemeral Ed25519 ratchet (V2) — byte-exact with Kotlin `EphemeralRatchet`.
//!
//! ## Why a ratchet?
//!
//! Frappuccino's V2 design publishes **one long-term Ed25519 identity key** at
//! enrollment time, then uses it only *once* to sign a batch of 50 ephemeral
//! public keys. After that, the device signs every upload / request with a
//! freshly-consumed ephemeral key and immediately wipes the private half.
//! Forward secrecy: if an attacker extracts the device state at time T they
//! can only forge signatures for the *remaining* slots in the current batch,
//! never for past uploads.
//!
//! ## Derivation
//!
//! ```text
//! chain_N
//!   ├─▶ HKDF(CTX_BATCH_SEEDS, 50·32)  ──▶ seeds[50]  ──▶ 50 × (pk, sk) via ed25519
//!   └─▶ HKDF(CTX_NEXT_CHAIN,  32)     ──▶ chain_{N+1}
//! ```
//!
//! ## Serialized format (V2, 4876 bytes)
//!
//! ```text
//! payload (4844 bytes):
//!   [0]         version byte            = 0x02
//!   [1..5]      batch_number            (u32 big-endian)
//!   [5..12]     consumed_mask           (7 bytes, bit i = consumed[i])
//!   [12..44]    next_chain_key          (32 bytes)
//!   [44..4844]  50 × (pk 32B || sk 64B) = 4800 bytes
//! mac (32 bytes):
//!   [4844..4876] HMAC-SHA256(HKDF(next_chain_key, CTX_BLOB_MAC, 32), payload[0..4844])
//! ```
//!
//! ## Legacy V1 (4844 bytes)
//!
//! Identical layout but **no MAC** and version byte = `0x01`. We accept V1
//! on read (no integrity check) and migrate automatically: the next
//! `serialize()` produces a V2 blob, after which the old V1 file should be
//! overwritten. Post-S5 the Kotlin impl has also migrated, so V1 exists only
//! in historical backups.
//!
//! ## Invariants (`PLAN_RUST_EXEC.md` §1.3 — drift = lose all enrolled identities)
//!
//! * `BATCH_SIZE = 50`
//! * HKDF contexts (exact bytes): `"frappuccino-v2-ratchet-batch-seeds"`,
//!   `"frappuccino-v2-ratchet-next-chain"`, `"frappuccino-v2-ratchet-blob-mac"`
//! * Blob is big-endian for `batch_number`; `consumed_mask` LSB = slot 0.

use crate::error::CryptoError;
use crate::hkdf;
use crate::signature_domain::SignatureDomain;
use ed25519_dalek::{Signer, SigningKey};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

// ============================================================================
// Constants
// ============================================================================

/// Number of keys per batch.
pub const BATCH_SIZE: usize = 50;
/// Ed25519 public key length.
pub const ED25519_PK_BYTES: usize = 32;
/// Ed25519 private key length (libsodium layout: seed || pk).
pub const ED25519_SK_BYTES: usize = 64;
/// Ed25519 seed length (RFC 8032 "secret key").
pub const ED25519_SEED_BYTES: usize = 32;
/// Chain key length.
pub const CHAIN_KEY_BYTES: usize = 32;
/// Ed25519 signature length.
pub const SIGNATURE_BYTES: usize = 64;
/// Consumed-mask length (7 bytes × 8 = 56 bits, 50 used).
pub const MASK_BYTES: usize = 7;

/// Legacy blob version (no MAC).
pub const VERSION_V1: u8 = 1;
/// Current blob version (MAC-authenticated).
pub const VERSION_V2: u8 = 2;
/// Version written by [`EphemeralRatchet::serialize`].
pub const VERSION: u8 = VERSION_V2;

/// Header = version(1) + `batch_number`(4) + mask(7) + chain(32) = 44 bytes.
pub const SERIALIZED_HEADER_SIZE: usize = 1 + 4 + MASK_BYTES + CHAIN_KEY_BYTES;
/// Per-slot size = pk(32) + sk(64) = 96 bytes.
pub const SERIALIZED_PER_SLOT_SIZE: usize = ED25519_PK_BYTES + ED25519_SK_BYTES;
/// Payload size (V1 blob size, V2 payload-without-MAC size).
pub const SERIALIZED_PAYLOAD_SIZE: usize =
    SERIALIZED_HEADER_SIZE + BATCH_SIZE * SERIALIZED_PER_SLOT_SIZE;
/// Legacy V1 blob size.
pub const SERIALIZED_SIZE_V1: usize = SERIALIZED_PAYLOAD_SIZE;
/// V2 MAC length.
pub const MAC_BYTES: usize = 32;
/// Current V2 blob size = payload + MAC.
pub const SERIALIZED_SIZE: usize = SERIALIZED_PAYLOAD_SIZE + MAC_BYTES;

// Domain-separation for HKDF derivations.
const CTX_BATCH_SEEDS: &[u8] = b"frappuccino-v2-ratchet-batch-seeds";
const CTX_NEXT_CHAIN: &[u8] = b"frappuccino-v2-ratchet-next-chain";
const CTX_BLOB_MAC: &[u8] = b"frappuccino-v2-ratchet-blob-mac";

// Byte offsets inside the serialized payload. Exposed so parity tests (and
// higher-level inspectors) can read sub-fields without magic numbers.
pub const OFF_BATCH_NUMBER: usize = 1;
pub const OFF_MASK: usize = 5;
pub const OFF_CHAIN: usize = 12;
pub const OFF_SLOTS: usize = SERIALIZED_HEADER_SIZE;

// ============================================================================
// Value types
// ============================================================================

/// One ephemeral signature bundle emitted by [`EphemeralRatchet::sign_and_advance`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RatchetSignature {
    /// 64-byte Ed25519 signature over the caller-supplied message.
    pub signature: [u8; SIGNATURE_BYTES],
    /// The ephemeral public key corresponding to the consumed slot.
    pub ephemeral_public_key: [u8; ED25519_PK_BYTES],
    /// Batch number that was active when the signature was produced.
    pub batch_number: u32,
    /// 0-based index of the consumed slot within the batch.
    pub key_index: u32,
}

/// Proof of a batch rotation. The server verifies
/// `signature == Ed25519(signer_sk, concat(new_batch_public_keys))` against
/// the known `signer_public_key` from the previous batch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RotationProof {
    /// Post-rotation batch number.
    pub new_batch_number: u32,
    /// 50 fresh public keys derived from the next chain.
    pub new_batch_public_keys: [[u8; ED25519_PK_BYTES]; BATCH_SIZE],
    /// The key that signed `signature` — must match a slot known to the server.
    pub signer_public_key: [u8; ED25519_PK_BYTES],
    /// Batch number the signer belongs to (= `new_batch_number - 1`).
    pub signer_batch_number: u32,
    /// Slot the signer consumed in that batch.
    pub signer_key_index: u32,
    /// 64-byte Ed25519 signature of `concat(new_batch_public_keys)`.
    pub signature: [u8; SIGNATURE_BYTES],
}

// ============================================================================
// EphemeralRatchet
// ============================================================================

/// Stateful batched Ed25519 ratchet.
///
/// Not thread-safe — pin to a single thread. Zeroes all private material and
/// the chain key on `Drop`.
#[must_use]
pub struct EphemeralRatchet {
    batch_number: u32,
    consumed: [bool; BATCH_SIZE],
    public_keys: [[u8; ED25519_PK_BYTES]; BATCH_SIZE],
    // 64-byte libsodium-layout sk (seed || pk). When a slot is consumed the
    // whole buffer is filled with zeros, so serialized blobs of consumed
    // slots contain `pk || zeros(64)` — matching Kotlin exactly.
    private_keys: [[u8; ED25519_SK_BYTES]; BATCH_SIZE],
    next_chain_key: Option<[u8; CHAIN_KEY_BYTES]>,
    initialized: bool,
}

impl EphemeralRatchet {
    /// Create an empty ratchet. Call [`Self::initialize`] or
    /// [`Self::deserialize`] before any sign / rotate operation.
    ///
    /// (the struct is already `#[must_use]` so no attribute here.)
    pub fn new() -> Self {
        Self {
            batch_number: 0,
            consumed: [false; BATCH_SIZE],
            public_keys: [[0u8; ED25519_PK_BYTES]; BATCH_SIZE],
            private_keys: [[0u8; ED25519_SK_BYTES]; BATCH_SIZE],
            next_chain_key: None,
            initialized: false,
        }
    }

    /// Bootstrap batch 0 from `master_chain_key` (the `chain_0` produced by
    /// [`crate::identity::EnrollmentKit::take_chain_zero`]).
    ///
    /// Derives the 50 slot keypairs and `chain_1`, then wipes the input.
    ///
    /// # Errors
    /// * [`CryptoError::DerivationFailed`] if already initialized or HKDF fails.
    pub fn initialize(
        &mut self,
        master_chain_key: &mut [u8; CHAIN_KEY_BYTES],
    ) -> Result<(), CryptoError> {
        if self.initialized {
            return Err(CryptoError::DerivationFailed(
                "ratchet already initialized".into(),
            ));
        }
        self.derive_batch(master_chain_key, 0)?;
        master_chain_key.zeroize();
        self.initialized = true;
        Ok(())
    }

    /// Current batch number (0 at fresh init, incremented by each rotation).
    #[must_use]
    pub fn batch_number(&self) -> u32 {
        self.batch_number
    }

    /// Number of unconsumed slots remaining in the current batch.
    #[must_use]
    pub fn remaining_in_batch(&self) -> usize {
        self.consumed.iter().filter(|c| !**c).count()
    }

    /// True if the slot at `index` has already been consumed.
    ///
    /// # Errors
    /// [`CryptoError::DerivationFailed`] if `index >= BATCH_SIZE`.
    pub fn is_consumed(&self, index: usize) -> Result<bool, CryptoError> {
        if index >= BATCH_SIZE {
            return Err(CryptoError::DerivationFailed(format!(
                "index {index} out of range"
            )));
        }
        Ok(self.consumed[index])
    }

    /// Copy of the public key at `index` (consumed or not).
    ///
    /// # Errors
    /// [`CryptoError::DerivationFailed`] if `index >= BATCH_SIZE` or not initialized.
    pub fn public_key_at(&self, index: usize) -> Result<[u8; ED25519_PK_BYTES], CryptoError> {
        self.check_initialized()?;
        if index >= BATCH_SIZE {
            return Err(CryptoError::DerivationFailed(format!(
                "index {index} out of range"
            )));
        }
        Ok(self.public_keys[index])
    }

    /// Snapshot of all 50 public keys in the current batch.
    ///
    /// # Errors
    /// [`CryptoError::DerivationFailed`] if not initialized.
    pub fn batch_public_keys(&self) -> Result<[[u8; ED25519_PK_BYTES]; BATCH_SIZE], CryptoError> {
        self.check_initialized()?;
        Ok(self.public_keys)
    }

    /// Sign `message` with the first unconsumed slot, then wipe that slot.
    ///
    /// **The last slot of a batch is reserved for [`Self::advance_batch`]** and
    /// this call refuses it. A failed authentication consumes its slot anyway
    /// (the key is wiped before the request goes out), so a run of failures on a
    /// wrong clock or a dead network could drain all 50 without a rotation ever
    /// being attempted: the client only auto-rotates after a *successful*
    /// verify. At zero slots the device can neither sign nor rotate, and the
    /// relay refuses to re-enroll an identity it already knows, so the
    /// enrollment is lost with nothing recoverable but a new phrase.
    ///
    /// Holding one slot back makes a rotation always possible, which is the
    /// property that was missing. It costs one signature out of fifty and it is
    /// what stops the batch from becoming unrecoverable. `advance_batch` is
    /// deliberately NOT subject to the reserve, or the reserve would protect
    /// nothing.
    ///
    /// # Errors
    /// * [`CryptoError::DerivationFailed`] if only the reserved slot is left, if
    ///   the batch is exhausted, if it is not initialized, or if the signing key
    ///   is malformed (shouldn't happen).
    ///
    /// # Panics
    /// The `u32::try_from(idx)` can never fail: `idx < BATCH_SIZE = 50` always
    /// fits in `u32`. The `expect` is kept to make the intent explicit and
    /// because clippy pedantic demands the docstring entry.
    pub fn sign_and_advance(&mut self, message: &[u8]) -> Result<RatchetSignature, CryptoError> {
        self.check_initialized()?;
        // The reserve. Checked before taking a slot, so a refusal consumes
        // nothing and leaves the batch exactly able to rotate.
        if self.remaining_in_batch() <= 1 {
            return Err(CryptoError::DerivationFailed(format!(
                "batch {} is down to its reserved slot — call advance_batch() \
                 (the last slot is held back so a rotation is always possible)",
                self.batch_number
            )));
        }
        let idx = self.first_available_index()?;
        // RT-11: hold the seed in `Zeroizing` so the stack copy is wiped at
        // function exit. `SigningKey::from_bytes` already has `ZeroizeOnDrop`
        // since dalek 2.1, but the local 32-byte buffer feeding it survives
        // until scope-end without help.
        let mut seed: Zeroizing<[u8; ED25519_SEED_BYTES]> =
            Zeroizing::new([0u8; ED25519_SEED_BYTES]);
        seed.copy_from_slice(&self.private_keys[idx][..ED25519_SEED_BYTES]);
        let signing = SigningKey::from_bytes(&seed);
        // R-C-1: commit to the AuthChallenge domain so this slot signature can
        // only be used at /auth/v2/verify, never replayed in another context
        // (e.g. a future endpoint signing a short blob with an ephemeral slot).
        let tbs = SignatureDomain::AuthChallenge.prefixed(message);
        let sig = signing.sign(&tbs).to_bytes();
        let pk = self.public_keys[idx];
        let batch = self.batch_number;

        // Wipe the consumed slot's private material.
        self.private_keys[idx].zeroize();
        self.consumed[idx] = true;

        Ok(RatchetSignature {
            signature: sig,
            ephemeral_public_key: pk,
            batch_number: batch,
            key_index: u32::try_from(idx).expect("idx < BATCH_SIZE = 50 fits in u32"),
        })
    }

    /// Consume one slot to sign `concat(new_batch_public_keys)`, rotate to
    /// batch `N+1`, and return a server-verifiable [`RotationProof`].
    ///
    /// # Errors
    /// [`CryptoError::DerivationFailed`] if not initialized, batch exhausted,
    /// no `next_chain_key` is present, or the batch number would overflow
    /// `u32::MAX` (unreachable in practice; fail-closed to preserve monotonicity).
    ///
    /// # Panics
    /// Can't panic in practice: the `u32::try_from(signer_idx)` call is
    /// bounded by `signer_idx < BATCH_SIZE = 50` which always fits `u32`.
    pub fn advance_batch(&mut self) -> Result<RotationProof, CryptoError> {
        self.check_initialized()?;
        let signer_idx = self.first_available_index()?;
        let signer_pk = self.public_keys[signer_idx];
        let signer_batch = self.batch_number;
        // #19 — refuse to advance past u32::MAX rather than wrap (release build,
        // no overflow-checks) or panic (debug), which would violate strict batch
        // monotonicity. Computed BEFORE any mutation of `self` (the wipe/install
        // below), so an overflow leaves the ratchet fully intact and fail-closed
        // (re-enroll required). Unreachable in practice (~4.29e9 rotations).
        let new_batch_number = signer_batch.checked_add(1).ok_or_else(|| {
            CryptoError::DerivationFailed(
                "batch_number overflow (u32::MAX rotations) — re-enroll required".into(),
            )
        })?;
        // RT-11: same hardening as sign_and_advance — the signer seed is
        // copied to the stack to feed `SigningKey::from_bytes`; wrap it so
        // the buffer is zeroed at function exit, before the new batch is
        // installed in `self`.
        let mut signer_seed: Zeroizing<[u8; ED25519_SEED_BYTES]> =
            Zeroizing::new([0u8; ED25519_SEED_BYTES]);
        signer_seed.copy_from_slice(&self.private_keys[signer_idx][..ED25519_SEED_BYTES]);

        let mut old_chain = self
            .next_chain_key
            .take()
            .ok_or_else(|| CryptoError::DerivationFailed("missing next_chain_key".into()))?;

        // Derive new batch material into scratch arrays (don't touch self's batch
        // yet — we need the signer's sk to still be alive for the signature step).
        let mut new_public_keys = [[0u8; ED25519_PK_BYTES]; BATCH_SIZE];
        let mut new_private_keys = [[0u8; ED25519_SK_BYTES]; BATCH_SIZE];
        derive_batch_into(&old_chain, &mut new_public_keys, &mut new_private_keys)?;

        let next_chain_bytes = hkdf::sha256(&old_chain, None, CTX_NEXT_CHAIN, CHAIN_KEY_BYTES)?;
        let mut new_next_chain = [0u8; CHAIN_KEY_BYTES];
        new_next_chain.copy_from_slice(&next_chain_bytes[..]);

        // Sign the concatenation of the 50 new public keys.
        let mut concat = [0u8; BATCH_SIZE * ED25519_PK_BYTES];
        for (i, pk) in new_public_keys.iter().enumerate() {
            concat[i * ED25519_PK_BYTES..(i + 1) * ED25519_PK_BYTES].copy_from_slice(pk);
        }
        let signing = SigningKey::from_bytes(&signer_seed);
        // R-C-1: commit to the BatchRotation domain — distinct from the
        // AuthChallenge slot signatures, which use the same ephemeral keys but
        // a different message (`nonce‖ts` vs `concat(50 pk)`).
        let tbs = SignatureDomain::BatchRotation.prefixed(&concat);
        let signature = signing.sign(&tbs).to_bytes();

        // Wipe the old batch + old chain.
        for sk in &mut self.private_keys {
            sk.zeroize();
        }
        for pk in &mut self.public_keys {
            pk.zeroize();
        }
        for c in &mut self.consumed {
            *c = false;
        }
        old_chain.zeroize();

        // Install the new batch.
        self.public_keys = new_public_keys;
        self.private_keys = new_private_keys;
        self.next_chain_key = Some(new_next_chain);
        self.batch_number = new_batch_number;

        Ok(RotationProof {
            new_batch_number: self.batch_number,
            new_batch_public_keys: self.public_keys,
            signer_public_key: signer_pk,
            signer_batch_number: signer_batch,
            signer_key_index: u32::try_from(signer_idx)
                .expect("signer_idx < BATCH_SIZE = 50 fits in u32"),
            signature,
        })
    }

    // ------------------------------------------------------------------------
    // Serialization
    // ------------------------------------------------------------------------

    /// Produce the V2 serialized blob ([`SERIALIZED_SIZE`] = 4876 bytes).
    ///
    /// # Errors
    /// [`CryptoError::DerivationFailed`] if not initialized or `next_chain_key`
    /// is missing, or HKDF/HMAC fails (never in practice).
    pub fn serialize(&self) -> Result<Vec<u8>, CryptoError> {
        self.check_initialized()?;
        let chain = self
            .next_chain_key
            .as_ref()
            .ok_or_else(|| CryptoError::DerivationFailed("missing next_chain_key".into()))?;

        let mut blob = vec![0u8; SERIALIZED_SIZE];
        blob[0] = VERSION;
        blob[OFF_BATCH_NUMBER..OFF_MASK].copy_from_slice(&self.batch_number.to_be_bytes());
        for (i, &c) in self.consumed.iter().enumerate() {
            if c {
                blob[OFF_MASK + i / 8] |= 1 << (i % 8);
            }
        }
        blob[OFF_CHAIN..OFF_CHAIN + CHAIN_KEY_BYTES].copy_from_slice(chain);

        let mut offset = OFF_SLOTS;
        for i in 0..BATCH_SIZE {
            blob[offset..offset + ED25519_PK_BYTES].copy_from_slice(&self.public_keys[i]);
            offset += ED25519_PK_BYTES;
            blob[offset..offset + ED25519_SK_BYTES].copy_from_slice(&self.private_keys[i]);
            offset += ED25519_SK_BYTES;
        }

        // Compute + append the MAC.
        let mac_key = hkdf::sha256(chain, None, CTX_BLOB_MAC, MAC_BYTES)?;
        let mac = hmac_sha256(&mac_key, &blob[..SERIALIZED_PAYLOAD_SIZE])?;
        blob[SERIALIZED_PAYLOAD_SIZE..SERIALIZED_SIZE].copy_from_slice(&mac);
        Ok(blob)
    }

    /// Reconstruct a ratchet from [`Self::serialize`] output.
    ///
    /// Accepts only V2 (4876 bytes, MAC-verified). Legacy V1 blobs are
    /// rejected at parse time — the V1 layout had no MAC, which made an
    /// attacker writing the inner blob (post-PIN-seal in particular paths)
    /// indistinguishable from a legitimate state. Historical V1 backups
    /// must be re-sealed via the dedicated migration tool
    /// [`Self::migrate_from_v1`] before being read.
    ///
    /// # Errors
    /// * [`CryptoError::InvalidBlob`] for V1 blobs (rejected since RT-03 fix),
    ///   unsupported version byte, wrong size, or V2 MAC verification failure.
    pub fn deserialize(blob: &[u8]) -> Result<Self, CryptoError> {
        if blob.is_empty() {
            return Err(CryptoError::InvalidBlob("empty blob".into()));
        }
        match blob[0] {
            VERSION_V2 => {
                if blob.len() != SERIALIZED_SIZE {
                    return Err(CryptoError::InvalidBlob(format!(
                        "V2 size mismatch: expected {SERIALIZED_SIZE}, got {}",
                        blob.len()
                    )));
                }
                verify_mac(blob)?;
                Self::read_payload(&blob[..SERIALIZED_PAYLOAD_SIZE])
            }
            VERSION_V1 => Err(CryptoError::InvalidBlob(
                "V1 ratchet blob rejected since RT-03 — \
                 use frappuccino-cli migrate-v1-ratchet to re-seal as V2"
                    .into(),
            )),
            other => Err(CryptoError::InvalidBlob(format!(
                "unsupported version byte {other:#x} (expected {VERSION_V2:#x})"
            ))),
        }
    }

    /// Migrate a V1 ratchet blob in-memory: parse the legacy 4844-byte payload
    /// (no MAC) and produce a fresh `EphemeralRatchet` instance. The next
    /// [`Self::serialize`] will produce a V2 (MAC-authenticated) blob ready
    /// to replace the V1 file on disk.
    ///
    /// **Use only from the migration CLI tool** — never from the app's hot
    /// path. The whole point of the RT-03 fix is to make sure stray V1 input
    /// is rejected by `deserialize`; this function is the explicit, audited
    /// escape hatch for legitimate historical backups.
    ///
    /// # Errors
    /// * [`CryptoError::InvalidBlob`] if `blob[0]` is not [`VERSION_V1`] or
    ///   the size doesn't match [`SERIALIZED_SIZE_V1`].
    pub fn migrate_from_v1(blob: &[u8]) -> Result<Self, CryptoError> {
        if blob.is_empty() {
            return Err(CryptoError::InvalidBlob("empty blob".into()));
        }
        if blob[0] != VERSION_V1 {
            return Err(CryptoError::InvalidBlob(format!(
                "migrate_from_v1 expected version {VERSION_V1:#x}, got {:#x}",
                blob[0]
            )));
        }
        if blob.len() != SERIALIZED_SIZE_V1 {
            return Err(CryptoError::InvalidBlob(format!(
                "V1 size mismatch: expected {SERIALIZED_SIZE_V1}, got {}",
                blob.len()
            )));
        }
        Self::read_payload(blob)
    }

    /// Zeroize the secret material in place — every private-key byte and the
    /// next chain key. Shared by [`Self::wipe`] and the [`Drop`] impl so the
    /// security-critical zeroization lives in exactly one (mutation-covered)
    /// place.
    ///
    /// Leaves `next_chain_key` as `Some([0; _])` rather than `None` so a test
    /// can observe the cleared bytes; callers that need a reusable ratchet
    /// (see [`Self::wipe`]) drop it to `None` afterwards.
    fn zeroize_secrets(&mut self) {
        for sk in &mut self.private_keys {
            sk.zeroize();
        }
        if let Some(ref mut chain) = self.next_chain_key {
            chain.zeroize();
        }
    }

    /// Explicit zero-out of all in-memory state, reusable for a fresh
    /// [`Self::initialize`] call afterwards.
    pub fn wipe(&mut self) {
        self.zeroize_secrets();
        for pk in &mut self.public_keys {
            pk.zeroize();
        }
        for c in &mut self.consumed {
            *c = false;
        }
        self.next_chain_key = None;
        self.batch_number = 0;
        self.initialized = false;
    }

    // ------------------------------------------------------------------------
    // Internal helpers
    // ------------------------------------------------------------------------

    fn check_initialized(&self) -> Result<(), CryptoError> {
        if !self.initialized {
            return Err(CryptoError::DerivationFailed(
                "ratchet not initialized".into(),
            ));
        }
        Ok(())
    }

    fn first_available_index(&self) -> Result<usize, CryptoError> {
        self.consumed.iter().position(|&c| !c).ok_or_else(|| {
            CryptoError::DerivationFailed(format!(
                "batch {} exhausted — call advance_batch()",
                self.batch_number
            ))
        })
    }

    fn derive_batch(
        &mut self,
        chain: &[u8; CHAIN_KEY_BYTES],
        target_batch_number: u32,
    ) -> Result<(), CryptoError> {
        derive_batch_into(chain, &mut self.public_keys, &mut self.private_keys)?;
        for c in &mut self.consumed {
            *c = false;
        }
        let next_chain = hkdf::sha256(chain, None, CTX_NEXT_CHAIN, CHAIN_KEY_BYTES)?;
        let mut new_next = [0u8; CHAIN_KEY_BYTES];
        new_next.copy_from_slice(&next_chain[..]);
        if let Some(ref mut old) = self.next_chain_key {
            old.zeroize();
        }
        self.next_chain_key = Some(new_next);
        self.batch_number = target_batch_number;
        Ok(())
    }

    fn read_payload(payload: &[u8]) -> Result<Self, CryptoError> {
        debug_assert_eq!(payload.len(), SERIALIZED_PAYLOAD_SIZE);
        let mut ratchet = Self::new();
        let batch_bytes: [u8; 4] = payload[OFF_BATCH_NUMBER..OFF_MASK]
            .try_into()
            .map_err(|_| CryptoError::InvalidBlob("batch_number slice".into()))?;
        ratchet.batch_number = u32::from_be_bytes(batch_bytes);

        for i in 0..BATCH_SIZE {
            let byte = payload[OFF_MASK + i / 8];
            ratchet.consumed[i] = (byte >> (i % 8)) & 1 == 1;
        }

        let mut chain = [0u8; CHAIN_KEY_BYTES];
        chain.copy_from_slice(&payload[OFF_CHAIN..OFF_CHAIN + CHAIN_KEY_BYTES]);
        ratchet.next_chain_key = Some(chain);

        let mut offset = OFF_SLOTS;
        for i in 0..BATCH_SIZE {
            ratchet.public_keys[i].copy_from_slice(&payload[offset..offset + ED25519_PK_BYTES]);
            offset += ED25519_PK_BYTES;
            ratchet.private_keys[i].copy_from_slice(&payload[offset..offset + ED25519_SK_BYTES]);
            offset += ED25519_SK_BYTES;
        }
        ratchet.initialized = true;
        Ok(ratchet)
    }
}

impl Default for EphemeralRatchet {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for EphemeralRatchet {
    fn drop(&mut self) {
        // Delegate to the single audited zeroization path (mutation-covered by
        // `zeroize_secrets_clears_private_keys_and_chain`). A `Drop` body can't
        // be observed from safe Rust without reading freed memory (UB), so the
        // cargo-mutants `drop`->no-op survivor is inherent; the guarantee that
        // the compiler doesn't dead-store-eliminate the zeroize is covered by
        // the zeroize-audit plugin (ROADMAP 8.4.2).
        self.zeroize_secrets();
    }
}

impl std::fmt::Debug for EphemeralRatchet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "EphemeralRatchet(initialized={}, batch={}, remaining={}, private_keys=<redacted>)",
            self.initialized,
            self.batch_number,
            self.remaining_in_batch()
        )
    }
}

// ============================================================================
// Free helpers
// ============================================================================

/// Derive the 50 slot keypairs from a chain key into the caller-provided arrays.
fn derive_batch_into(
    chain: &[u8; CHAIN_KEY_BYTES],
    public_keys: &mut [[u8; ED25519_PK_BYTES]; BATCH_SIZE],
    private_keys: &mut [[u8; ED25519_SK_BYTES]; BATCH_SIZE],
) -> Result<(), CryptoError> {
    let seeds = hkdf::sha256(
        chain,
        None,
        CTX_BATCH_SEEDS,
        BATCH_SIZE * ED25519_SEED_BYTES,
    )?;
    for i in 0..BATCH_SIZE {
        let seed_start = i * ED25519_SEED_BYTES;
        let seed_end = seed_start + ED25519_SEED_BYTES;
        let mut seed: [u8; ED25519_SEED_BYTES] = seeds[seed_start..seed_end]
            .try_into()
            .map_err(|_| CryptoError::DerivationFailed("seed slice".into()))?;
        let signing = SigningKey::from_bytes(&seed);
        public_keys[i] = signing.verifying_key().to_bytes();
        // libsodium layout: seed(32) || pk(32).
        private_keys[i][..ED25519_SEED_BYTES].copy_from_slice(&seed);
        private_keys[i][ED25519_SEED_BYTES..].copy_from_slice(&public_keys[i]);
        seed.zeroize();
    }
    Ok(())
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Result<[u8; MAC_BYTES], CryptoError> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key)
        .map_err(|e| CryptoError::DerivationFailed(e.to_string()))?;
    mac.update(data);
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; MAC_BYTES];
    out.copy_from_slice(&result);
    Ok(out)
}

/// Verify the V2 MAC in constant time. Caller has already checked size + version byte.
fn verify_mac(blob: &[u8]) -> Result<(), CryptoError> {
    let chain_bytes: [u8; CHAIN_KEY_BYTES] = blob[OFF_CHAIN..OFF_CHAIN + CHAIN_KEY_BYTES]
        .try_into()
        .map_err(|_| CryptoError::InvalidBlob("chain slice".into()))?;
    let mac_key = hkdf::sha256(&chain_bytes, None, CTX_BLOB_MAC, MAC_BYTES)?;
    let expected = hmac_sha256(&mac_key, &blob[..SERIALIZED_PAYLOAD_SIZE])?;
    let actual = &blob[SERIALIZED_PAYLOAD_SIZE..SERIALIZED_SIZE];
    if expected.as_slice().ct_eq(actual).unwrap_u8() == 1 {
        Ok(())
    } else {
        Err(CryptoError::InvalidBlob(
            "MAC verification failed — tampered or corrupted".into(),
        ))
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh(chain0: [u8; 32]) -> EphemeralRatchet {
        let mut r = EphemeralRatchet::new();
        let mut c = chain0;
        r.initialize(&mut c).unwrap();
        assert_eq!(c, [0u8; 32], "initialize must wipe master chain key");
        r
    }

    #[test]
    fn fresh_batch_has_50_unique_pks_and_remaining_50() {
        let r = fresh([1u8; 32]);
        assert_eq!(r.batch_number(), 0);
        assert_eq!(r.remaining_in_batch(), 50);
        let pks = r.batch_public_keys().unwrap();
        // Loose uniqueness check — HKDF + Ed25519 ensures it with overwhelming prob.
        for i in 0..BATCH_SIZE {
            for j in i + 1..BATCH_SIZE {
                assert_ne!(pks[i], pks[j]);
            }
        }
    }

    #[test]
    fn sign_and_advance_consumes_slot_zero_then_one() {
        let mut r = fresh([2u8; 32]);
        let sig0 = r.sign_and_advance(b"hello").unwrap();
        assert_eq!(sig0.key_index, 0);
        assert_eq!(sig0.batch_number, 0);
        assert!(r.is_consumed(0).unwrap());
        assert_eq!(r.remaining_in_batch(), 49);

        let sig1 = r.sign_and_advance(b"again").unwrap();
        assert_eq!(sig1.key_index, 1);
        assert!(r.is_consumed(1).unwrap());
    }

    // ── Crash-safety (Grok Q2 / data-loss hardening) ───────────────────────
    // The persisted blob is the single source of truth for "which slot is
    // next". The Kotlin orchestration (StreamUploadManager) consumes a slot,
    // re-seals the blob to disk, and ONLY THEN sends the signature to the
    // server. These tests pin the invariants that make that ordering safe
    // against a process crash / OOM / kill at any point in the sequence.

    /// Crash BETWEEN `sign_and_advance` and the disk re-seal: the in-RAM
    /// consume is lost, and reloading the last persisted blob shows the slot
    /// un-consumed. Because Kotlin persists *before* the network call, the
    /// signature was never sent, so reusing the slot is correct — no replay,
    /// no wasted slot. Ed25519 is deterministic, so even if the first sig HAD
    /// reached the server, the on-device retry is a byte-identical replay that
    /// the server's atomic single-use guard rejects: the device never forks.
    #[test]
    fn unpersisted_consume_is_a_noop_after_reload() {
        let mut r = fresh([7u8; 32]);
        let on_disk = r.serialize().unwrap(); // last persisted state (slot 0 free)

        let sig = r.sign_and_advance(b"nonce-a").unwrap();
        assert_eq!(sig.key_index, 0);
        assert!(r.is_consumed(0).unwrap());

        // Simulate the crash: drop the RAM state, reload from disk.
        let mut reloaded = EphemeralRatchet::deserialize(&on_disk).unwrap();
        assert_eq!(reloaded.remaining_in_batch(), 50);
        assert!(!reloaded.is_consumed(0).unwrap());

        let replay = reloaded.sign_and_advance(b"nonce-a").unwrap();
        assert_eq!(replay.key_index, 0);
        assert_eq!(
            replay.signature, sig.signature,
            "deterministic replay — server double-spend guard is the backstop"
        );
    }

    /// Crash AFTER the disk re-seal: the slot is legitimately burned. The
    /// reload must show it consumed and advance to the next slot — burned but
    /// safe, never re-used.
    #[test]
    fn persisted_consume_survives_reload() {
        let mut r = fresh([8u8; 32]);
        let sig0 = r.sign_and_advance(b"n0").unwrap();
        assert_eq!(sig0.key_index, 0);
        let persisted = r.serialize().unwrap(); // re-seal landed on disk

        let mut reloaded = EphemeralRatchet::deserialize(&persisted).unwrap();
        assert!(reloaded.is_consumed(0).unwrap());
        assert_eq!(reloaded.remaining_in_batch(), 49);
        let sig1 = reloaded.sign_and_advance(b"n1").unwrap();
        assert_eq!(sig1.key_index, 1, "slot 0 is never re-issued");
    }

    /// Torn / partial write during the re-seal (power loss mid-`saveRatchetBlob`)
    /// must NEVER yield a half-valid ratchet: every truncation and every
    /// single-byte flip is rejected cleanly (no panic), so the device falls
    /// back to its last good blob instead of loading corruption.
    #[test]
    fn torn_blob_write_is_rejected_not_silently_accepted() {
        let mut r = fresh([9u8; 32]);
        r.sign_and_advance(b"x").unwrap();
        let good = r.serialize().unwrap();

        for len in 0..good.len() {
            assert!(
                EphemeralRatchet::deserialize(&good[..len]).is_err(),
                "truncation to {len} bytes must be rejected"
            );
        }
        for i in 0..good.len() {
            let mut torn = good.clone();
            torn[i] ^= 0x01;
            assert!(
                EphemeralRatchet::deserialize(&torn).is_err(),
                "single-byte flip at offset {i} must be rejected"
            );
        }
    }

    /// Crash mid-`advance_batch` (new batch installed in RAM, not yet
    /// persisted): reloading the pre-rotation blob leaves the old batch with
    /// the signer slot un-consumed, and a re-rotation produces the SAME new
    /// batch (it is derived deterministically from the chain). The server's
    /// strictly-monotonic `batch_number` therefore sees an idempotent retry,
    /// never a forked lineage.
    #[test]
    fn interrupted_rotation_reuses_signer_slot_and_is_deterministic() {
        let mut r = fresh([10u8; 32]);
        let pre_rotation = r.serialize().unwrap();

        let proof_a = r.advance_batch().unwrap();
        assert_eq!(proof_a.new_batch_number, 1);

        let mut reloaded = EphemeralRatchet::deserialize(&pre_rotation).unwrap();
        assert_eq!(reloaded.batch_number(), 0);
        let proof_b = reloaded.advance_batch().unwrap();
        assert_eq!(proof_b.new_batch_number, 1);
        assert_eq!(
            proof_b.new_batch_public_keys, proof_a.new_batch_public_keys,
            "rotation is deterministic from the chain — a crash-retry cannot fork the lineage"
        );
    }

    #[test]
    fn sign_without_initialize_returns_error() {
        let mut r = EphemeralRatchet::new();
        assert!(matches!(
            r.sign_and_advance(b"x"),
            Err(CryptoError::DerivationFailed(_))
        ));
    }

    #[test]
    fn signing_stops_one_slot_before_exhaustion() {
        // BATCH_SIZE - 1 signatures are available; the last slot is the reserve.
        let mut r = fresh([3u8; 32]);
        for i in 0..BATCH_SIZE - 1 {
            r.sign_and_advance(b"x")
                .unwrap_or_else(|e| panic!("signature {i} must be available: {e:?}"));
        }
        assert_eq!(r.remaining_in_batch(), 1, "exactly the reserve is left");
        assert!(matches!(
            r.sign_and_advance(b"x"),
            Err(CryptoError::DerivationFailed(_))
        ));
        // And the refusal took nothing: the reserve is still there.
        assert_eq!(r.remaining_in_batch(), 1);
    }

    #[test]
    fn the_reserved_slot_can_still_rotate() {
        // The property the reserve exists for. Without it this is the state a
        // run of failed authentications reaches, and from which the device can
        // neither sign nor rotate; the relay then refuses to re-enroll a known
        // identity, so the enrollment is lost. Drive the batch down to the
        // reserve and rotate out of it.
        let mut r = fresh([7u8; 32]);
        for _ in 0..BATCH_SIZE - 1 {
            r.sign_and_advance(b"x").unwrap();
        }
        assert_eq!(r.remaining_in_batch(), 1);
        assert!(r.sign_and_advance(b"x").is_err(), "signing must be refused");

        let proof = r
            .advance_batch()
            .expect("rotation out of the reserve must always be possible");
        assert_eq!(
            proof.signer_key_index as usize,
            BATCH_SIZE - 1,
            "the rotation signed with the reserved slot"
        );
        assert_eq!(r.batch_number(), 1);
        assert_eq!(
            r.remaining_in_batch(),
            BATCH_SIZE,
            "a fresh batch is available"
        );
        // And the device signs again on the new batch.
        r.sign_and_advance(b"x").expect("the new batch signs");
    }

    #[test]
    fn advance_batch_increments_and_signs() {
        let mut r = fresh([4u8; 32]);
        let old_pks = r.batch_public_keys().unwrap();
        let proof = r.advance_batch().unwrap();
        assert_eq!(proof.signer_batch_number, 0);
        assert_eq!(proof.signer_key_index, 0);
        assert_eq!(proof.new_batch_number, 1);
        assert_eq!(r.batch_number(), 1);
        // New batch keys differ from old ones.
        let new_pks = r.batch_public_keys().unwrap();
        for i in 0..BATCH_SIZE {
            assert_ne!(old_pks[i], new_pks[i]);
        }
        assert_eq!(proof.new_batch_public_keys, new_pks);
    }

    #[test]
    fn advance_batch_refuses_to_overflow_batch_number() {
        // #19 — at u32::MAX the next rotation must fail-closed (Err) rather than
        // wrap (release) or panic (debug), preserving strict batch monotonicity.
        let mut r = fresh([9u8; 32]);
        r.batch_number = u32::MAX; // unreachable in practice; forced for the invariant
        let err = r.advance_batch().unwrap_err();
        assert!(matches!(err, CryptoError::DerivationFailed(_)));
        // Fail-closed BEFORE any mutation: the ratchet is left fully intact.
        assert_eq!(r.batch_number(), u32::MAX);
        assert_eq!(r.remaining_in_batch(), 50);
    }

    #[test]
    fn serialize_size_is_4876_and_version_2() {
        let r = fresh([5u8; 32]);
        let blob = r.serialize().unwrap();
        assert_eq!(blob.len(), SERIALIZED_SIZE);
        assert_eq!(blob[0], VERSION_V2);
    }

    #[test]
    fn serialize_then_deserialize_is_noop() {
        let mut r = fresh([6u8; 32]);
        r.sign_and_advance(b"abc").unwrap();
        r.sign_and_advance(b"def").unwrap();
        let blob = r.serialize().unwrap();
        let r2 = EphemeralRatchet::deserialize(&blob).unwrap();
        let blob2 = r2.serialize().unwrap();
        assert_eq!(
            blob, blob2,
            "serialize → deserialize → serialize must be idempotent"
        );
        assert_eq!(r2.batch_number(), r.batch_number());
        assert_eq!(r2.remaining_in_batch(), r.remaining_in_batch());
    }

    #[test]
    fn migrate_from_v1_then_serialize_produces_v2() {
        // Migration path: dedicated CLI tool reads a V1 blob, calls
        // migrate_from_v1, then serialize() → produces a V2 blob ready to
        // be written back. Round-tripping through V1 should yield byte-
        // identical V2 to the original.
        let r = fresh([7u8; 32]);
        let v2 = r.serialize().unwrap();
        // Construct a legacy V1 blob by stripping the MAC + flipping byte 0.
        let mut v1 = v2[..SERIALIZED_PAYLOAD_SIZE].to_vec();
        v1[0] = VERSION_V1;
        let r_from_v1 = EphemeralRatchet::migrate_from_v1(&v1).unwrap();
        let migrated = r_from_v1.serialize().unwrap();
        assert_eq!(
            migrated, v2,
            "V1 → V2 migration must be byte-identical to original V2"
        );
    }

    #[test]
    fn deserialize_v1_now_rejected() {
        // RT-03 fix: deserialize() must reject V1 blobs outright. The only
        // path accepting V1 is the explicit migrate_from_v1 escape hatch.
        let r = fresh([7u8; 32]);
        let v2 = r.serialize().unwrap();
        let mut v1 = v2[..SERIALIZED_PAYLOAD_SIZE].to_vec();
        v1[0] = VERSION_V1;
        let err = EphemeralRatchet::deserialize(&v1).unwrap_err();
        let msg = format!("{err:?}");
        assert!(
            msg.contains("V1 ratchet blob rejected"),
            "expected V1 rejection (RT-03), got {msg}"
        );
    }

    #[test]
    fn deserialize_v2_rejects_tampered_payload() {
        let r = fresh([8u8; 32]);
        let mut blob = r.serialize().unwrap();
        // Flip a byte inside the payload (not in the MAC region).
        blob[100] ^= 0x01;
        let err = EphemeralRatchet::deserialize(&blob).unwrap_err();
        assert!(matches!(err, CryptoError::InvalidBlob(_)), "got {err:?}");
    }

    #[test]
    fn deserialize_v2_rejects_tampered_mac() {
        let r = fresh([9u8; 32]);
        let mut blob = r.serialize().unwrap();
        let mac_idx = SERIALIZED_PAYLOAD_SIZE + 5;
        blob[mac_idx] ^= 0x01;
        assert!(matches!(
            EphemeralRatchet::deserialize(&blob),
            Err(CryptoError::InvalidBlob(_))
        ));
    }

    #[test]
    fn deserialize_wrong_version_rejected() {
        let mut blob = vec![0u8; SERIALIZED_SIZE];
        blob[0] = 99;
        assert!(matches!(
            EphemeralRatchet::deserialize(&blob),
            Err(CryptoError::InvalidBlob(_))
        ));
    }

    #[test]
    fn deserialize_empty_rejected() {
        assert!(matches!(
            EphemeralRatchet::deserialize(&[]),
            Err(CryptoError::InvalidBlob(_))
        ));
    }

    #[test]
    fn wipe_zeroes_state_and_allows_reinitialize() {
        let mut r = fresh([10u8; 32]);
        r.sign_and_advance(b"x").unwrap();
        r.wipe();
        // wipe() delegates the secret-clearing to zeroize_secrets(); pin that
        // the private-key bytes are actually gone (kills a no-op of the call).
        assert!(
            r.private_keys.iter().all(|sk| sk.iter().all(|&b| b == 0)),
            "wipe must zero every private-key byte"
        );
        assert!(r.next_chain_key.is_none());
        assert_eq!(r.batch_number(), 0);
        assert!(!r.is_consumed(0).unwrap_or(true));
        let mut chain = [42u8; 32];
        r.initialize(&mut chain).unwrap();
        assert_eq!(r.remaining_in_batch(), 50);
    }

    #[test]
    fn zeroize_secrets_clears_private_keys_and_chain() {
        // The security invariant behind Drop (which delegates here): every
        // private-key byte and the next chain key is cleared in place. Pinning
        // the byte-level result kills a mutation that no-ops the zeroize loops
        // — a runtime Drop can't be observed without reading freed memory (UB),
        // so this direct call is the strongest safe-Rust check. The companion
        // no-dead-store-elimination guarantee is covered by the zeroize-audit
        // plugin (ROADMAP 8.4.2).
        let mut r = fresh([11u8; 32]);
        r.sign_and_advance(b"x").unwrap();
        assert!(
            r.private_keys.iter().any(|sk| sk.iter().any(|&b| b != 0)),
            "precondition: secret material present before zeroize"
        );
        r.next_chain_key = Some([0x42u8; CHAIN_KEY_BYTES]);
        r.zeroize_secrets();
        assert!(
            r.private_keys.iter().all(|sk| sk.iter().all(|&b| b == 0)),
            "every private-key byte must be zero after zeroize_secrets"
        );
        assert_eq!(
            r.next_chain_key,
            Some([0u8; CHAIN_KEY_BYTES]),
            "the next chain key bytes must be zeroed in place"
        );
    }

    #[test]
    fn serialize_consumed_mask_survives_high_slot_index() {
        // serialize() writes the consumed bitmask as `blob[OFF_MASK + i / 8] |=
        // 1 << (i % 8)`. serialize_then_deserialize_is_noop only consumes slots
        // 0..2, where i / 8 == 0, so `OFF_MASK + i / 8` == `OFF_MASK - i / 8`
        // and a `+`->`-` mutation on the byte offset is invisible. Consume a
        // slot with i >= 8 (i / 8 >= 1) so the offset actually moves, then
        // round-trip and require the high slot's consumed bit to survive.
        let mut r = fresh([12u8; 32]);
        for _ in 0..9 {
            r.sign_and_advance(b"x").unwrap(); // consume slots 0..=8
        }
        assert!(r.is_consumed(8).unwrap());
        let blob = r.serialize().unwrap();
        let r2 = EphemeralRatchet::deserialize(&blob).unwrap();
        assert!(
            r2.is_consumed(8).unwrap(),
            "slot 8's consumed bit must survive serialize (kills the OFF_MASK + i/8 off-by-one)"
        );
        assert!(r2.is_consumed(0).unwrap());
        assert!(!r2.is_consumed(9).unwrap());
        assert_eq!(r2.remaining_in_batch(), BATCH_SIZE - 9);
    }

    #[test]
    fn debug_redacts_secret_material() {
        // The Debug impl must never spill key material into logs — it prints
        // `private_keys=<redacted>`. A mutant that no-ops fmt (empty output)
        // drops the marker -> caught; the length bound rejects a bulk key dump.
        let r = fresh([13u8; 32]);
        let dbg = format!("{r:?}");
        assert!(
            dbg.contains("EphemeralRatchet"),
            "Debug must name the type: {dbg}"
        );
        assert!(
            dbg.contains("<redacted>"),
            "Debug must redact key material: {dbg}"
        );
        assert!(
            dbg.contains("batch="),
            "Debug must keep the non-secret fields: {dbg}"
        );
        assert!(
            dbg.len() < 256,
            "Debug is suspiciously long ({} chars) — possible key dump",
            dbg.len()
        );
    }
}
