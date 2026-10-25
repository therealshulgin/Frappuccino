//! The chained report scheme: the device state `(i, C_i, directory seed)` and
//! the opening of report `i`.
//!
//! Every report key is derived from a chain link `C_i`; opening report `i`
//! replaces `C_i` by `C_{i+1}`, so the persisted state only ever holds the link
//! of the NEXT report. See the parent module for the derivation diagram and for
//! what this does and does not protect.

use super::writer::ReportWriter;
use super::{
    directory_seed_from_master, hex_lower, report_id_from_pk, report_master_from_seed,
    sign_create_under, sign_write_under, signing_key_from_okm, ReportError, HASH_BYTES, NAME_BYTES,
    PK_BYTES, REPORT_ID_BYTES, REPORT_MASTER_BYTES, SIG_BYTES,
};
use crate::bip39::{self, Language};
use crate::error::CryptoError;
use crate::hkdf;
use ed25519_dalek::SigningKey;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

// ============================================================================
// Wire constants
// ============================================================================

/// HKDF context of the first chain link, `C_0 = HKDF(report_master, ctx, 32)`.
/// **Immutable wire constant**: changing it orphans every chained report.
const CTX_CHAIN_ROOT: &[u8] = b"stream.report.chain.v2.root";
/// HKDF context of the chain step, `C_{i+1} = HKDF(C_i, ctx, 32)`. **Immutable
/// wire constant.**
const CTX_CHAIN_NEXT: &[u8] = b"stream.report.chain.v2.next";
/// HKDF context of report `i`'s Ed25519 seed, `seed_i = HKDF(C_i, ctx, 32)`.
/// **Immutable wire constant.**
const CTX_CHAIN_KEY: &[u8] = b"stream.report.chain.v2.key";
/// HKDF context of the name of report `i`'s directory entry,
/// `hex(HKDF(C_i, ctx, 16))`. Derived from the secret link, so the relay, which
/// sees the directory's public key, cannot enumerate the names. **Immutable
/// wire constant.**
const CTX_CHAIN_DIR_ENTRY: &[u8] = b"stream.report.chain.v2.directory-entry";
/// HKDF context of the name under which report `i`'s timestamp proof is
/// stored in the directory, `hex(HKDF(C_i, ctx, 16))`. **Immutable wire
/// constant.**
const CTX_CHAIN_OTS_NAME: &[u8] = b"stream.report.chain.v2.ots-name";

/// Associated data the FFI layer binds when it seals a serialized
/// [`ReportDeviceState`] under the PIN-session key. Distinct from the PIN
/// store's own AAD, so a sealed state can never be opened as another sealed
/// blob, nor the reverse. **Immutable wire constant.**
pub const CTX_STATE_AAD: &[u8] = b"frappuccino-report-state-v2";

/// Version byte of a serialized [`ReportDeviceState`].
pub const STATE_VERSION: u8 = 0x02;

/// Width of one chain link `C_i`.
const LINK_BYTES: usize = 32;

/// Exact length of a serialized [`ReportDeviceState`]:
/// `version(1) ‖ u32_be(i)(4) ‖ C_i(32) ‖ directory seed(32)`.
pub const STATE_BYTES: usize = 1 + 4 + LINK_BYTES + LINK_BYTES;

/// Largest migration point [`ReportDeviceState::migrate_from_master`] accepts.
/// Migrating to `k` walks the chain `k` steps; the bound keeps that walk
/// within a few seconds on a phone.
pub const MAX_MIGRATION_INDEX: u32 = 1_000_000;

// ============================================================================
// ChainLink — one secret link C_i
// ============================================================================

/// One chain link `C_i`. Secret: it derives report `i`'s key and every link
/// after it. Wiped on drop, never printed.
#[derive(Zeroize, ZeroizeOnDrop)]
pub(super) struct ChainLink([u8; LINK_BYTES]);

impl ChainLink {
    /// `C_0 = HKDF(report_master, CTX_CHAIN_ROOT, 32)`.
    pub(super) fn root(report_master: &[u8]) -> Result<Self, CryptoError> {
        let okm = hkdf::sha256(report_master, None, CTX_CHAIN_ROOT, LINK_BYTES)?;
        Self::from_slice(&okm)
    }

    /// `C_{i+1} = HKDF(C_i, CTX_CHAIN_NEXT, 32)`.
    pub(super) fn successor(&self) -> Result<Self, CryptoError> {
        let okm = hkdf::sha256(&self.0, None, CTX_CHAIN_NEXT, LINK_BYTES)?;
        Self::from_slice(&okm)
    }

    /// An explicit copy, wiped on drop like the original. Used by the rescue's
    /// link cache, which hands out links without giving up its own.
    pub(super) fn duplicate(&self) -> Self {
        Self(self.0)
    }

    /// Report `i`'s Ed25519 signing key, from `seed_i = HKDF(C_i, CTX_CHAIN_KEY, 32)`.
    pub(super) fn signing_key(&self) -> Result<SigningKey, CryptoError> {
        let okm = hkdf::sha256(&self.0, None, CTX_CHAIN_KEY, LINK_BYTES)?;
        signing_key_from_okm(&okm)
    }

    /// Report `i`'s public key, its `report_id`, its directory entry name and
    /// the name of its timestamp proof. Everything the rescue device needs to
    /// find and verify report `i`, and nothing that signs.
    pub(super) fn public_view(&self) -> Result<ChainPublic, CryptoError> {
        let report_pk = self.signing_key()?.verifying_key().to_bytes();
        Ok(ChainPublic {
            report_id: report_id_from_pk(&report_pk),
            report_pk,
            directory_entry_name: self.name(CTX_CHAIN_DIR_ENTRY)?,
            ots_name: self.name(CTX_CHAIN_OTS_NAME)?,
        })
    }

    /// `hex(HKDF(C_i, ctx, 16))`, the wire form of an opaque object name.
    fn name(&self, ctx: &[u8]) -> Result<String, CryptoError> {
        let okm = hkdf::sha256(&self.0, None, ctx, NAME_BYTES)?;
        Ok(hex_lower(&okm))
    }

    fn from_slice(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != LINK_BYTES {
            return Err(CryptoError::DerivationFailed(format!(
                "a chain link is {LINK_BYTES} bytes, got {}",
                bytes.len()
            )));
        }
        let mut link = Self([0u8; LINK_BYTES]);
        link.0.copy_from_slice(bytes);
        Ok(link)
    }
}

impl std::fmt::Debug for ChainLink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ChainLink(<redacted>)")
    }
}

/// The public half of one chained report, derived from its link.
pub(super) struct ChainPublic {
    pub(super) report_id: [u8; REPORT_ID_BYTES],
    pub(super) report_pk: [u8; PK_BYTES],
    pub(super) directory_entry_name: String,
    pub(super) ots_name: String,
}

// ============================================================================
// DirectorySeed — the persistent directory key
// ============================================================================

/// The directory's Ed25519 seed. Unlike the chain links it never advances: the
/// directory is one report for the device's whole life.
#[derive(Zeroize, ZeroizeOnDrop)]
struct DirectorySeed([u8; LINK_BYTES]);

impl DirectorySeed {
    fn from_master(report_master: &[u8]) -> Result<Self, CryptoError> {
        let okm = directory_seed_from_master(report_master)?;
        Self::from_slice(&okm)
    }

    fn from_slice(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != LINK_BYTES {
            return Err(CryptoError::DerivationFailed(format!(
                "a directory seed is {LINK_BYTES} bytes, got {}",
                bytes.len()
            )));
        }
        let mut seed = Self([0u8; LINK_BYTES]);
        seed.0.copy_from_slice(bytes);
        Ok(seed)
    }

    fn signing_key(&self) -> SigningKey {
        SigningKey::from_bytes(&self.0)
    }
}

// ============================================================================
// ReportDeviceState — what the device persists
// ============================================================================

/// The device's whole report state: the index `i` of the next report, its
/// chain link `C_i`, and the directory seed. Never holds `report_master`.
///
/// Serialized by [`Self::to_bytes`] as `0x02 ‖ u32_be(i) ‖ C_i ‖ directory
/// seed` ([`STATE_BYTES`] bytes). Sealing that buffer (with [`CTX_STATE_AAD`])
/// and writing it durably is the FFI layer's job, as is serializing every
/// transition behind one process-wide lock.
pub struct ReportDeviceState {
    next_index: u32,
    link: ChainLink,
    directory_seed: DirectorySeed,
}

impl ReportDeviceState {
    /// The state of a fresh enrollment, at index 0. The intermediate
    /// `report_master` is wiped before this returns.
    ///
    /// # Errors
    /// [`ReportError::Crypto`] on an invalid mnemonic or an HKDF failure.
    pub fn from_mnemonic(mnemonic: &str, passphrase: &str) -> Result<Self, ReportError> {
        let seed = bip39::mnemonic_to_seed(mnemonic, passphrase, Language::French)?;
        let master = report_master_from_seed(seed.as_bytes())?;
        Self::from_master_at(&master, 0)
    }

    /// The state of a device migrating from the legacy scheme: the chain starts
    /// at index `k`, so legacy indices `0..k` and chained indices `k..` never
    /// overlap. Walks the chain `k` steps from `C_0`.
    ///
    /// The caller is expected to wipe the legacy `report_master` once this
    /// state is durably written, since the state is all the device needs from
    /// then on.
    ///
    /// # Errors
    /// [`ReportError::MigrationIndexTooLarge`] if `k > MAX_MIGRATION_INDEX`;
    /// [`ReportError::Crypto`] on an HKDF failure.
    pub fn migrate_from_master(
        report_master: &[u8; REPORT_MASTER_BYTES],
        k: u32,
    ) -> Result<Self, ReportError> {
        if k > MAX_MIGRATION_INDEX {
            return Err(ReportError::MigrationIndexTooLarge {
                k,
                max: MAX_MIGRATION_INDEX,
            });
        }
        Self::from_master_at(report_master, k)
    }

    fn from_master_at(report_master: &[u8], k: u32) -> Result<Self, ReportError> {
        let mut link = ChainLink::root(report_master)?;
        for _ in 0..k {
            link = link.successor()?;
        }
        Ok(Self {
            next_index: k,
            link,
            directory_seed: DirectorySeed::from_master(report_master)?,
        })
    }

    /// Parse a serialized state (the plaintext, after the FFI layer unsealed
    /// it). Strict: exactly [`STATE_BYTES`] bytes and version [`STATE_VERSION`].
    ///
    /// # Errors
    /// [`ReportError::InvalidState`] on any length or version mismatch.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ReportError> {
        let Some((&version, rest)) = bytes.split_first() else {
            return Err(ReportError::InvalidState("empty"));
        };
        if version != STATE_VERSION {
            return Err(ReportError::InvalidState("unsupported version"));
        }
        if bytes.len() != STATE_BYTES {
            return Err(ReportError::InvalidState("wrong length"));
        }
        let Some((index_be, rest)) = rest.split_first_chunk::<4>() else {
            return Err(ReportError::InvalidState("truncated index"));
        };
        let Some((link_bytes, directory_bytes)) = rest.split_first_chunk::<LINK_BYTES>() else {
            return Err(ReportError::InvalidState("truncated chain link"));
        };
        Ok(Self {
            next_index: u32::from_be_bytes(*index_be),
            link: ChainLink::from_slice(link_bytes)?,
            directory_seed: DirectorySeed::from_slice(directory_bytes)?,
        })
    }

    /// Serialize the state, secret bytes included. The buffer is wiped when
    /// dropped; seal it, never store it as is.
    #[must_use]
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(Vec::with_capacity(STATE_BYTES));
        out.push(STATE_VERSION);
        out.extend_from_slice(&self.next_index.to_be_bytes());
        out.extend_from_slice(&self.link.0);
        out.extend_from_slice(&self.directory_seed.0);
        out
    }

    /// Index of the report the next [`Self::open_report`] will open.
    #[must_use]
    pub fn next_index(&self) -> u32 {
        self.next_index
    }

    /// Open report `i = next_index()`: derive its writer from `C_i`, then
    /// advance this state to `(i + 1, C_{i+1})` and wipe `C_i`.
    ///
    /// The writer is not handed out directly. It comes inside a
    /// [`ReportOpening`] that also carries the serialized advanced state, and
    /// [`ReportOpening::release_after_persist`] releases the writer only once
    /// the caller has written that state durably. As long as the caller's
    /// write really is durable, no object is signed with a key the persisted
    /// state can still derive: if the write fails, the writer is dropped
    /// unused. What storage then holds is the caller's: the state as it was
    /// (the next opening derives index `i` again) or, for a write that failed
    /// after replacing the file, the advanced state (index `i` is skipped).
    /// Either way the key of index `i` signed nothing.
    ///
    /// On error the state is left unchanged.
    ///
    /// # Errors
    /// [`ReportError::IndexExhausted`] at `i = u32::MAX`; [`ReportError::Crypto`]
    /// on an HKDF failure.
    pub fn open_report(&mut self) -> Result<ReportOpening, ReportError> {
        let index = self.next_index;
        let advanced_index = index.checked_add(1).ok_or(ReportError::IndexExhausted)?;
        let writer = ReportWriter::from_link(index, &self.link)?;
        let advanced_link = self.link.successor()?;
        // Assigning drops the previous link, whose bytes ZeroizeOnDrop wipes.
        self.link = advanced_link;
        self.next_index = advanced_index;
        Ok(ReportOpening {
            writer,
            advanced_state: self.to_bytes(),
        })
    }

    // ------------------------------------------------------------------------
    // Directory signatures (the persistent directory key)
    // ------------------------------------------------------------------------

    /// The directory's public key, identical to the legacy keyring's.
    #[must_use]
    pub fn directory_pk(&self) -> [u8; PK_BYTES] {
        self.directory_seed.signing_key().verifying_key().to_bytes()
    }

    /// The directory's `report_id`, identical to the legacy keyring's.
    #[must_use]
    pub fn directory_id(&self) -> [u8; REPORT_ID_BYTES] {
        report_id_from_pk(&self.directory_pk())
    }

    /// `create_sig` of the directory (0x07).
    #[must_use]
    pub fn sign_directory_create(&self) -> [u8; SIG_BYTES] {
        sign_create_under(&self.directory_seed.signing_key())
    }

    /// `write_sig` (0x08) of a directory object: an entry (named by
    /// [`ReportWriter::directory_entry_name`]) or a timestamp proof (named by
    /// [`ReportWriter::ots_name`]). `filename` is signed verbatim, so pass the
    /// hex name's bytes.
    #[must_use]
    pub fn sign_directory_write(
        &self,
        filename: &[u8],
        body_sha256: &[u8; HASH_BYTES],
    ) -> [u8; SIG_BYTES] {
        sign_write_under(&self.directory_seed.signing_key(), filename, body_sha256)
    }
}

impl std::fmt::Debug for ReportDeviceState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ReportDeviceState(<redacted>)")
    }
}

// ============================================================================
// ReportOpening — a writer that waits for the advanced state to be persisted
// ============================================================================

/// The result of [`ReportDeviceState::open_report`]: the writer of the opened
/// report, held back until the advanced state is persisted. Dropping it drops
/// the writer, whose key is wiped.
#[must_use = "the writer is only released by release_after_persist"]
pub struct ReportOpening {
    writer: ReportWriter,
    advanced_state: Zeroizing<Vec<u8>>,
}

impl ReportOpening {
    /// Index of the opened report.
    #[must_use]
    pub fn index(&self) -> u32 {
        self.writer.index()
    }

    /// Hand the serialized advanced state to `persist` (which is expected to
    /// seal it and write it durably), and release the writer only if `persist`
    /// succeeds. On failure the writer is dropped and its key wiped, and the
    /// error is returned unchanged.
    ///
    /// # Errors
    /// Whatever `persist` returns.
    pub fn release_after_persist<E>(
        self,
        persist: impl FnOnce(&[u8]) -> Result<(), E>,
    ) -> Result<ReportWriter, E> {
        let Self {
            writer,
            advanced_state,
        } = self;
        persist(&advanced_state)?;
        Ok(writer)
    }
}

impl std::fmt::Debug for ReportOpening {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ReportOpening(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::super::{verify_create, verify_write, ReportKeyring, ReportRescue};
    use super::*;
    use proptest::prelude::*;

    const MN_FIXED: &str = "abaisser abandon abdiquer abeille abolir aborder aboutir aboyer abrasif abreuver abriter abroger";

    fn master_of(mnemonic: &str) -> [u8; 32] {
        let keyring = ReportKeyring::from_mnemonic(mnemonic, "").unwrap();
        keyring.with_master_bytes(|b| b.try_into().unwrap())
    }

    fn open_writer(state: &mut ReportDeviceState) -> ReportWriter {
        state
            .open_report()
            .unwrap()
            .release_after_persist(|_| Ok::<(), ()>(()))
            .unwrap()
    }

    #[test]
    fn fresh_state_starts_at_zero_and_round_trips() {
        let state = ReportDeviceState::from_mnemonic(MN_FIXED, "").unwrap();
        assert_eq!(state.next_index(), 0);
        let bytes = state.to_bytes();
        assert_eq!(bytes.len(), STATE_BYTES);
        assert_eq!(bytes[0], STATE_VERSION);
        assert_eq!(&bytes[1..5], &[0, 0, 0, 0]);
        let parsed = ReportDeviceState::from_bytes(&bytes).unwrap();
        assert_eq!(*parsed.to_bytes(), *bytes);
    }

    #[test]
    fn from_bytes_rejects_wrong_length_and_version() {
        let state = ReportDeviceState::from_mnemonic(MN_FIXED, "").unwrap();
        let good = state.to_bytes();
        assert_eq!(
            ReportDeviceState::from_bytes(&[]).unwrap_err(),
            ReportError::InvalidState("empty")
        );
        assert_eq!(
            ReportDeviceState::from_bytes(&good[..STATE_BYTES - 1]).unwrap_err(),
            ReportError::InvalidState("wrong length")
        );
        let mut long = good.to_vec();
        long.push(0);
        assert_eq!(
            ReportDeviceState::from_bytes(&long).unwrap_err(),
            ReportError::InvalidState("wrong length")
        );
        for version in [0x00u8, 0x01, 0x03, 0xFF] {
            let mut other = good.to_vec();
            other[0] = version;
            assert_eq!(
                ReportDeviceState::from_bytes(&other).unwrap_err(),
                ReportError::InvalidState("unsupported version"),
                "version {version:#04x} must be refused"
            );
        }
    }

    #[test]
    fn migration_at_zero_equals_fresh_enrollment() {
        let fresh = ReportDeviceState::from_mnemonic(MN_FIXED, "").unwrap();
        let migrated = ReportDeviceState::migrate_from_master(&master_of(MN_FIXED), 0).unwrap();
        assert_eq!(*fresh.to_bytes(), *migrated.to_bytes());
    }

    #[test]
    fn migration_to_k_equals_k_openings() {
        let mut walked = ReportDeviceState::from_mnemonic(MN_FIXED, "").unwrap();
        for _ in 0..3 {
            let _ = open_writer(&mut walked);
        }
        let migrated = ReportDeviceState::migrate_from_master(&master_of(MN_FIXED), 3).unwrap();
        assert_eq!(migrated.next_index(), 3);
        assert_eq!(*walked.to_bytes(), *migrated.to_bytes());
    }

    #[test]
    fn migration_refuses_an_index_past_the_bound() {
        let err =
            ReportDeviceState::migrate_from_master(&master_of(MN_FIXED), MAX_MIGRATION_INDEX + 1)
                .unwrap_err();
        assert_eq!(
            err,
            ReportError::MigrationIndexTooLarge {
                k: MAX_MIGRATION_INDEX + 1,
                max: MAX_MIGRATION_INDEX
            }
        );
    }

    #[test]
    fn opening_advances_the_state_and_changes_every_secret_link() {
        let mut state = ReportDeviceState::from_mnemonic(MN_FIXED, "").unwrap();
        let before = state.to_bytes();
        let writer0 = open_writer(&mut state);
        let after = state.to_bytes();
        assert_eq!(writer0.index(), 0);
        assert_eq!(state.next_index(), 1);
        // The link moved on; the directory seed did not.
        assert_ne!(before[5..37], after[5..37]);
        assert_eq!(before[37..], after[37..]);
        let writer1 = open_writer(&mut state);
        assert_eq!(writer1.index(), 1);
        assert_ne!(writer0.report_pk(), writer1.report_pk());
        assert_ne!(writer0.report_id(), writer1.report_id());
    }

    #[test]
    fn opened_writers_match_the_rescue_derivation() {
        let mut state = ReportDeviceState::from_mnemonic(MN_FIXED, "").unwrap();
        let mut rescue = ReportRescue::from_mnemonic(MN_FIXED, "").unwrap();
        for index in 0..3 {
            let writer = open_writer(&mut state);
            let found = rescue.chain(index).unwrap();
            assert_eq!(writer.report_pk(), found.report_pk());
            assert_eq!(writer.report_id(), found.report_id());
            assert_eq!(
                Some(writer.directory_entry_name()),
                found.directory_entry_name()
            );
            assert_eq!(Some(writer.ots_name()), found.ots_name());
        }
    }

    #[test]
    fn opening_at_the_last_index_fails_and_leaves_the_state_unchanged() {
        let state = ReportDeviceState::from_mnemonic(MN_FIXED, "").unwrap();
        let mut bytes = state.to_bytes().to_vec();
        bytes[1..5].copy_from_slice(&u32::MAX.to_be_bytes());
        let mut last = ReportDeviceState::from_bytes(&bytes).unwrap();
        assert_eq!(last.open_report().unwrap_err(), ReportError::IndexExhausted);
        assert_eq!(*last.to_bytes(), bytes[..]);
    }

    #[test]
    fn the_writer_is_released_only_after_a_successful_persist() {
        let mut state = ReportDeviceState::from_mnemonic(MN_FIXED, "").unwrap();
        let opening = state.open_report().unwrap();
        let expected = state.to_bytes();
        assert_eq!(opening.index(), 0);
        let mut seen = Vec::new();
        let writer = opening
            .release_after_persist(|advanced| {
                seen.extend_from_slice(advanced);
                Ok::<(), &str>(())
            })
            .unwrap();
        assert_eq!(seen, *expected, "persist must receive the advanced state");
        assert_eq!(writer.index(), 0);

        let failed = state
            .open_report()
            .unwrap()
            .release_after_persist(|_| Err::<(), &str>("disk full"));
        assert_eq!(failed.unwrap_err(), "disk full");
    }

    #[test]
    fn directory_key_is_the_legacy_one_and_signs() {
        let state = ReportDeviceState::from_mnemonic(MN_FIXED, "").unwrap();
        let keyring = ReportKeyring::from_mnemonic(MN_FIXED, "").unwrap();
        assert_eq!(state.directory_pk(), keyring.directory_pk().unwrap());
        assert_eq!(state.directory_id(), keyring.directory_id().unwrap());
        // Ed25519 is deterministic, so the two code paths sign identical bytes.
        assert_eq!(
            state.sign_directory_create(),
            keyring.sign_directory_create().unwrap()
        );
        let body = [0x5Au8; 32];
        let name = b"0123456789abcdef0123456789abcdef";
        let sig = state.sign_directory_write(name, &body);
        assert_eq!(sig, keyring.sign_directory_write(name, &body).unwrap());
        verify_create(&state.directory_pk(), &state.sign_directory_create()).unwrap();
        verify_write(&state.directory_pk(), name, &body, &sig).unwrap();
        // The directory key does not advance with the chain.
        let mut advanced = ReportDeviceState::from_mnemonic(MN_FIXED, "").unwrap();
        let _ = open_writer(&mut advanced);
        assert_eq!(advanced.directory_pk(), state.directory_pk());
    }

    #[test]
    fn chain_keys_are_distinct_from_legacy_keys_and_passphrase_bound() {
        let mut state = ReportDeviceState::from_mnemonic(MN_FIXED, "").unwrap();
        let keyring = ReportKeyring::from_mnemonic(MN_FIXED, "").unwrap();
        let writer = open_writer(&mut state);
        assert_ne!(*writer.report_pk(), keyring.report_pk(0).unwrap());
        assert_ne!(*writer.report_pk(), keyring.directory_pk().unwrap());
        let mut other = ReportDeviceState::from_mnemonic(MN_FIXED, "p").unwrap();
        assert_ne!(writer.report_pk(), open_writer(&mut other).report_pk());
    }

    #[test]
    fn debug_output_is_redacted() {
        let mut state = ReportDeviceState::from_mnemonic(MN_FIXED, "").unwrap();
        assert_eq!(format!("{state:?}"), "ReportDeviceState(<redacted>)");
        let opening = state.open_report().unwrap();
        assert_eq!(format!("{opening:?}"), "ReportOpening(<redacted>)");
        let link = ChainLink::root(&master_of(MN_FIXED)).unwrap();
        assert_eq!(format!("{link:?}"), "ChainLink(<redacted>)");
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        /// The parser never panics, and anything it accepts serializes back to
        /// the same bytes.
        #[test]
        fn from_bytes_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..96)) {
            if let Ok(state) = ReportDeviceState::from_bytes(&bytes) {
                prop_assert_eq!(&state.to_bytes()[..], &bytes[..]);
            }
        }

        /// Any well-formed state round-trips.
        #[test]
        fn well_formed_state_round_trips(
            index in any::<u32>(),
            link in any::<[u8; 32]>(),
            seed in any::<[u8; 32]>(),
        ) {
            let mut bytes = vec![STATE_VERSION];
            bytes.extend_from_slice(&index.to_be_bytes());
            bytes.extend_from_slice(&link);
            bytes.extend_from_slice(&seed);
            let state = ReportDeviceState::from_bytes(&bytes).unwrap();
            prop_assert_eq!(state.next_index(), index);
            prop_assert_eq!(&state.to_bytes()[..], &bytes[..]);
        }
    }
}
