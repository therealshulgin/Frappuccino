//! Rescue-side derivation: from the phrase alone, every report the device may
//! have written, in both schemes, and the secret-free checks to run on what
//! the relay returns.
//!
//! The rescue device does not know where the legacy scheme stopped, so it asks
//! for both families at every index ([`ReportRescue::legacy`],
//! [`ReportRescue::chain`]) and lets the directory listing and the relay's
//! answers tell which reports exist. Chained links are derived in sequence
//! from `C_0`; a cache keeps every 64th link plus the last one handed out, so
//! walking the indices in order costs about two HKDF steps per index, and
//! revisiting an index costs at most 63.

use super::chain::ChainLink;
use super::{
    hex_lower, report_master_from_seed, verify_close, verify_create, verify_write, Manifest,
    ReportError, ReportKeyring, HASH_BYTES, PK_BYTES, REPORT_ID_BYTES, REPORT_MASTER_BYTES,
    SIG_BYTES,
};
use crate::bip39::{self, Language};
use crate::error::CryptoError;

/// Distance between two cached chain links.
const CHECKPOINT_STRIDE: u32 = 64;

/// Which derivation produced a report, and so which closure shape is valid
/// for it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReportScheme {
    /// Legacy per-index key from `report_master`. A legacy closure is always
    /// empty.
    Legacy,
    /// Chained key from link `C_i`. A chained closure always lists seq 0.
    Chain,
    /// The directory, a single report for the device's whole life. A closure
    /// of the directory is an anomaly, whatever its shape.
    Directory,
}

/// The public description of one report as the rescue device re-derives it.
/// Holds no secret: everything here can be recomputed from the phrase, and
/// the names are the ones the relay already shows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RescueReport {
    scheme: ReportScheme,
    index: Option<u32>,
    report_id: [u8; REPORT_ID_BYTES],
    report_pk: [u8; PK_BYTES],
    directory_entry_name: Option<String>,
    ots_name: Option<String>,
}

impl RescueReport {
    /// The derivation scheme.
    #[must_use]
    pub fn scheme(&self) -> ReportScheme {
        self.scheme
    }

    /// The report index, `None` for the directory.
    #[must_use]
    pub fn index(&self) -> Option<u32> {
        self.index
    }

    /// The 16-byte `report_id`, recomputed from the re-derived key.
    #[must_use]
    pub fn report_id(&self) -> &[u8; REPORT_ID_BYTES] {
        &self.report_id
    }

    /// The `report_id` as 32 lowercase hex, its form in relay URLs.
    #[must_use]
    pub fn report_id_hex(&self) -> String {
        hex_lower(&self.report_id)
    }

    /// The re-derived public key.
    #[must_use]
    pub fn report_pk(&self) -> &[u8; PK_BYTES] {
        &self.report_pk
    }

    /// Name (32 lowercase hex) of this report's entry in the directory, `None`
    /// for the directory itself. For a legacy report this is the opaque name;
    /// entries written before opaque names existed used `format!("{index:010}")`.
    #[must_use]
    pub fn directory_entry_name(&self) -> Option<&str> {
        self.directory_entry_name.as_deref()
    }

    /// Name (32 lowercase hex) of this report's timestamp proof in the
    /// directory. Chained reports only: a legacy proof lives inside its own
    /// report under a name the phrase does not determine.
    #[must_use]
    pub fn ots_name(&self) -> Option<&str> {
        self.ots_name.as_deref()
    }

    /// Check a 0x07 `create_sig` under this report's key.
    ///
    /// # Errors
    /// As [`verify_create`].
    #[must_use = "a verification result must be checked"]
    pub fn verify_create(&self, create_sig: &[u8; SIG_BYTES]) -> Result<(), ReportError> {
        verify_create(&self.report_pk, create_sig)
    }

    /// Check a 0x08 `write_sig` of object `filename` under this report's key.
    ///
    /// # Errors
    /// As [`verify_write`].
    #[must_use = "a verification result must be checked"]
    pub fn verify_write(
        &self,
        filename: &[u8],
        body_sha256: &[u8; HASH_BYTES],
        write_sig: &[u8; SIG_BYTES],
    ) -> Result<(), ReportError> {
        verify_write(&self.report_pk, filename, body_sha256, write_sig)
    }

    /// Check a 0x09 closure under this report's key ([`verify_close`]), then
    /// the shape the scheme allows: a legacy closure must be empty, a chained
    /// one must list seq 0. The directory accepts any well-formed shape; the
    /// caller reports its closure as an anomaly either way.
    ///
    /// # Errors
    /// As [`verify_close`], plus [`ReportError::InvalidManifest`] for a shape
    /// the scheme forbids.
    #[must_use = "a verification result must be checked"]
    pub fn verify_close(
        &self,
        seq_limit: u32,
        manifest: &[u8],
        close_sig: &[u8; SIG_BYTES],
    ) -> Result<Manifest, ReportError> {
        let parsed = verify_close(&self.report_pk, seq_limit, manifest, close_sig)?;
        match self.scheme {
            ReportScheme::Legacy if !parsed.is_empty() => Err(ReportError::InvalidManifest(
                "a legacy closure lists no object",
            )),
            ReportScheme::Chain if parsed.entries().first().map(|e| e.seq) != Some(0) => Err(
                ReportError::InvalidManifest("a chained closure lists seq 0 first"),
            ),
            _ => Ok(parsed),
        }
    }
}

/// Everything the rescue device derives from the phrase. Holds the legacy
/// `report_master` (inside a [`ReportKeyring`], mlock'd) and a cache of chain
/// links, all wiped on drop.
pub struct ReportRescue {
    legacy: ReportKeyring,
    links: LinkCache,
    directory: RescueReport,
}

impl ReportRescue {
    /// Derive the rescue material from the BIP-39 phrase.
    ///
    /// # Errors
    /// [`ReportError::Crypto`] on an invalid mnemonic, an HKDF failure or an
    /// mlock failure.
    pub fn from_mnemonic(mnemonic: &str, passphrase: &str) -> Result<Self, ReportError> {
        let seed = bip39::mnemonic_to_seed(mnemonic, passphrase, Language::French)?;
        let master = report_master_from_seed(seed.as_bytes())?;
        let master: &[u8; REPORT_MASTER_BYTES] = master.as_slice().try_into().map_err(|_| {
            CryptoError::DerivationFailed("report_master has the wrong length".into())
        })?;
        let root = ChainLink::root(master)?;
        let legacy = ReportKeyring::from_seed(master)?;
        let directory = RescueReport {
            scheme: ReportScheme::Directory,
            index: None,
            report_id: legacy.directory_id()?,
            report_pk: legacy.directory_pk()?,
            directory_entry_name: None,
            ots_name: None,
        };
        Ok(Self {
            legacy,
            links: LinkCache::new(root),
            directory,
        })
    }

    /// The directory report.
    #[must_use]
    pub fn directory(&self) -> &RescueReport {
        &self.directory
    }

    /// Legacy report `index`.
    ///
    /// # Errors
    /// [`ReportError::Crypto`] on an HKDF failure.
    pub fn legacy(&self, index: u32) -> Result<RescueReport, ReportError> {
        Ok(RescueReport {
            scheme: ReportScheme::Legacy,
            index: Some(index),
            report_id: self.legacy.report_id(index)?,
            report_pk: self.legacy.report_pk(index)?,
            directory_entry_name: Some(hex_lower(&self.legacy.directory_entry_name(index)?)),
            ots_name: None,
        })
    }

    /// Chained report `index`. Takes `&mut self` to extend the link cache.
    ///
    /// # Errors
    /// [`ReportError::Crypto`] on an HKDF failure.
    pub fn chain(&mut self, index: u32) -> Result<RescueReport, ReportError> {
        let public = self.links.link(index)?.public_view()?;
        Ok(RescueReport {
            scheme: ReportScheme::Chain,
            index: Some(index),
            report_id: public.report_id,
            report_pk: public.report_pk,
            directory_entry_name: Some(public.directory_entry_name),
            ots_name: Some(public.ots_name),
        })
    }
}

impl std::fmt::Debug for ReportRescue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ReportRescue(<redacted>)")
    }
}

/// Cache of chain links: `checkpoints[j] = C_{64 j}`, plus the last link
/// handed out.
struct LinkCache {
    // Boxed so that growing the vector moves pointers, not key bytes: a
    // reallocation frees the old buffer without wiping it.
    #[allow(clippy::vec_box)]
    checkpoints: Vec<Box<ChainLink>>,
    last: Option<(u32, ChainLink)>,
}

impl LinkCache {
    fn new(root: ChainLink) -> Self {
        Self {
            checkpoints: vec![Box::new(root)],
            last: None,
        }
    }

    /// `C_index`.
    fn link(&mut self, index: u32) -> Result<ChainLink, CryptoError> {
        let (mut at, mut link) = self.start_for(index)?;
        while at < index {
            link = link.successor()?;
            at += 1;
        }
        self.last = Some((index, link.duplicate()));
        Ok(link)
    }

    /// The closest known link at or below `index`: the last link handed out
    /// when it lies in the same stride, otherwise the stride's checkpoint.
    fn start_for(&mut self, index: u32) -> Result<(u32, ChainLink), CryptoError> {
        let slot = index / CHECKPOINT_STRIDE;
        let base = slot * CHECKPOINT_STRIDE;
        if let Some((at, link)) = &self.last {
            if (base..=index).contains(at) {
                return Ok((*at, link.duplicate()));
            }
        }
        let slot = usize::try_from(slot)
            .map_err(|_| CryptoError::DerivationFailed("chain index too large".into()))?;
        while self.checkpoints.len() <= slot {
            let Some(previous) = self.checkpoints.last() else {
                return Err(CryptoError::DerivationFailed(
                    "chain cache lost its root".into(),
                ));
            };
            let mut link = previous.duplicate();
            for _ in 0..CHECKPOINT_STRIDE {
                link = link.successor()?;
            }
            self.checkpoints.push(Box::new(link));
        }
        let Some(checkpoint) = self.checkpoints.get(slot) else {
            return Err(CryptoError::DerivationFailed(
                "chain cache is missing a checkpoint".into(),
            ));
        };
        Ok((base, checkpoint.duplicate()))
    }
}

#[cfg(test)]
mod tests {
    use super::super::{sign_close_under, ReportDeviceState, ReportKeyring, ReportWriter};
    use super::*;

    const MN_FIXED: &str = "abaisser abandon abdiquer abeille abolir aborder aboutir aboyer abrasif abreuver abriter abroger";

    fn rescue() -> ReportRescue {
        ReportRescue::from_mnemonic(MN_FIXED, "").unwrap()
    }

    fn open(state: &mut ReportDeviceState) -> ReportWriter {
        state
            .open_report()
            .unwrap()
            .release_after_persist(|_| Ok::<(), ()>(()))
            .unwrap()
    }

    /// `C_index`, walked from the root without any cache.
    fn walked_link(index: u32) -> ChainLink {
        let keyring = ReportKeyring::from_mnemonic(MN_FIXED, "").unwrap();
        let mut link = keyring.with_master_bytes(ChainLink::root).unwrap();
        for _ in 0..index {
            link = link.successor().unwrap();
        }
        link
    }

    #[test]
    fn legacy_reports_match_the_keyring() {
        let r = rescue();
        let keyring = ReportKeyring::from_mnemonic(MN_FIXED, "").unwrap();
        for index in [0u32, 1, 9, 256] {
            let found = r.legacy(index).unwrap();
            assert_eq!(found.scheme(), ReportScheme::Legacy);
            assert_eq!(found.index(), Some(index));
            assert_eq!(*found.report_pk(), keyring.report_pk(index).unwrap());
            assert_eq!(*found.report_id(), keyring.report_id(index).unwrap());
            assert_eq!(
                found.directory_entry_name(),
                Some(hex_lower(&keyring.directory_entry_name(index).unwrap()).as_str())
            );
            assert_eq!(found.ots_name(), None);
        }
    }

    #[test]
    fn the_directory_matches_the_device_state() {
        let r = rescue();
        let state = ReportDeviceState::from_mnemonic(MN_FIXED, "").unwrap();
        let dir = r.directory();
        assert_eq!(dir.scheme(), ReportScheme::Directory);
        assert_eq!(dir.index(), None);
        assert_eq!(*dir.report_pk(), state.directory_pk());
        assert_eq!(*dir.report_id(), state.directory_id());
        assert_eq!(dir.report_id_hex().len(), 32);
        assert_eq!(dir.directory_entry_name(), None);
        dir.verify_create(&state.sign_directory_create()).unwrap();
    }

    #[test]
    fn chain_lookups_agree_in_any_order_across_checkpoints() {
        let mut r = rescue();
        // Out of order, across stride boundaries, then back again.
        for index in [130u32, 5, 63, 64, 65, 0, 129, 128, 200, 64] {
            let found = r.chain(index).unwrap();
            let expected = walked_link(index).public_view().unwrap();
            assert_eq!(*found.report_pk(), expected.report_pk, "index {index}");
            assert_eq!(*found.report_id(), expected.report_id, "index {index}");
            assert_eq!(
                found.directory_entry_name(),
                Some(expected.directory_entry_name.as_str())
            );
            assert_eq!(found.ots_name(), Some(expected.ots_name.as_str()));
            assert_eq!(found.scheme(), ReportScheme::Chain);
            assert_eq!(found.index(), Some(index));
        }
    }

    #[test]
    fn the_two_families_and_their_names_never_collide() {
        let mut r = rescue();
        for index in 0u32..4 {
            let legacy = r.legacy(index).unwrap();
            let chain = r.chain(index).unwrap();
            assert_ne!(legacy.report_id(), chain.report_id());
            assert_ne!(legacy.directory_entry_name(), chain.directory_entry_name());
            assert_ne!(chain.directory_entry_name(), chain.ots_name());
            assert_ne!(chain.report_id(), r.directory().report_id());
        }
    }

    #[test]
    fn a_device_closure_verifies_at_rescue() {
        let mut state = ReportDeviceState::from_mnemonic(MN_FIXED, "").unwrap();
        let _ = open(&mut state);
        let mut writer = open(&mut state);
        let meta = writer.prepare_metadata(&[1; 32], &[2; 32]).unwrap();
        let found = rescue().chain(1).unwrap();
        found
            .verify_write(
                meta.filename().as_bytes(),
                meta.blob_sha256(),
                meta.write_sig(),
            )
            .unwrap();
        found.verify_create(writer.create_sig()).unwrap();
        writer.commit(meta).unwrap();
        let close = writer.prepare_close().unwrap();
        let manifest = found
            .verify_close(close.seq_limit(), close.manifest(), close.close_sig())
            .unwrap();
        assert_eq!(manifest.blob_sha256(0), Some(&[2; 32]));
        // The same closure does not verify as report 0's.
        let mut r = rescue();
        assert_eq!(
            r.chain(0)
                .unwrap()
                .verify_close(close.seq_limit(), close.manifest(), close.close_sig())
                .unwrap_err(),
            ReportError::InvalidSignature
        );
    }

    #[test]
    fn a_legacy_closure_verifies_and_must_be_empty() {
        let r = rescue();
        let keyring = ReportKeyring::from_mnemonic(MN_FIXED, "").unwrap();
        let empty = Manifest::empty().to_bytes();
        let sig = keyring.sign_legacy_close(3).unwrap();
        let found = r.legacy(3).unwrap();
        assert!(found.verify_close(0, &empty, &sig).unwrap().is_empty());
        assert_eq!(
            r.legacy(4)
                .unwrap()
                .verify_close(0, &empty, &sig)
                .unwrap_err(),
            ReportError::InvalidSignature
        );
        // A validly signed but non-empty legacy closure is refused by shape.
        let one = Manifest::from_entries(vec![super::super::ManifestEntry {
            seq: 0,
            blob_sha256: [7; 32],
        }])
        .unwrap();
        let signing_key = keyring.report_signing_key(3).unwrap();
        let sig = sign_close_under(&signing_key, 1, &one.sha256());
        assert_eq!(
            found.verify_close(1, &one.to_bytes(), &sig).unwrap_err(),
            ReportError::InvalidManifest("a legacy closure lists no object")
        );
    }

    #[test]
    fn a_chained_closure_without_seq_zero_is_refused_by_shape() {
        let mut r = rescue();
        let link = walked_link(2);
        let signing_key = link.signing_key().unwrap();
        let found = r.chain(2).unwrap();
        let empty = Manifest::empty();
        let sig = sign_close_under(&signing_key, 0, &empty.sha256());
        assert_eq!(
            found.verify_close(0, &empty.to_bytes(), &sig).unwrap_err(),
            ReportError::InvalidManifest("a chained closure lists seq 0 first")
        );
        let late = Manifest::from_entries(vec![super::super::ManifestEntry {
            seq: 1,
            blob_sha256: [7; 32],
        }])
        .unwrap();
        let sig = sign_close_under(&signing_key, 2, &late.sha256());
        assert_eq!(
            found.verify_close(2, &late.to_bytes(), &sig).unwrap_err(),
            ReportError::InvalidManifest("a chained closure lists seq 0 first")
        );
    }

    #[test]
    fn the_directory_accepts_any_well_formed_closure_shape() {
        // A directory closure is reported as an anomaly by the caller; the
        // verifier only says whether it is authentic.
        let r = rescue();
        let keyring = ReportKeyring::from_mnemonic(MN_FIXED, "").unwrap();
        let signing_key = keyring.directory_signing_key().unwrap();
        let empty = Manifest::empty();
        let sig = sign_close_under(&signing_key, 0, &empty.sha256());
        assert!(r
            .directory()
            .verify_close(0, &empty.to_bytes(), &sig)
            .unwrap()
            .is_empty());
        let late = Manifest::from_entries(vec![super::super::ManifestEntry {
            seq: 3,
            blob_sha256: [7; 32],
        }])
        .unwrap();
        let sig = sign_close_under(&signing_key, 4, &late.sha256());
        assert_eq!(
            r.directory()
                .verify_close(4, &late.to_bytes(), &sig)
                .unwrap(),
            late
        );
    }

    #[test]
    fn debug_output_is_redacted() {
        assert_eq!(format!("{:?}", rescue()), "ReportRescue(<redacted>)");
    }
}
