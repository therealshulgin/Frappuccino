//! The writer of one chained report: pure signing and bookkeeping, no I/O.
//!
//! Each object is recorded in two steps so that the caller can sign BEFORE
//! writing and record only AFTER the write is durable:
//!
//! 1. [`ReportWriter::prepare_metadata`] / [`ReportWriter::prepare_chunk`] check
//!    the sequence number and sign the object (0x08). Nothing changes in the
//!    writer, so a failure anywhere after this step leaves it as it was.
//! 2. The caller writes the signed object durably, then hands the
//!    [`PreparedObject`] back to [`ReportWriter::commit`], which records it.
//!
//! [`ReportWriter::prepare_close`] then builds the [`Manifest`] of everything
//! committed, signs it (0x09) and stops the writer from accepting more objects.
//! Ed25519 is deterministic, so calling it again yields the same bytes and a
//! failed closure write can simply be retried.
//!
//! Dropping the writer wipes its key; that is also how a recording is aborted
//! without a closure.

use super::chain::ChainLink;
use super::manifest::{chain_object_name, Manifest, ManifestEntry, MAX_SEQ};
use super::{
    sign_close_under, sign_create_under, sign_write_under, ReportError, HASH_BYTES, PK_BYTES,
    REPORT_ID_BYTES, SIG_BYTES,
};
use crate::error::CryptoError;
use ed25519_dalek::SigningKey;
use std::collections::BTreeMap;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Sequence number of the metadata object, always the first one recorded.
const METADATA_SEQ: u32 = 0;

/// What the writer remembers of one recorded object.
#[derive(Zeroize, ZeroizeOnDrop)]
struct RecordedObject {
    /// SHA-256 of the stored (encrypted) bytes: goes into the manifest.
    blob_sha256: [u8; HASH_BYTES],
    /// SHA-256 of the plaintext: goes into the timestamp commitment.
    plain_sha256: [u8; HASH_BYTES],
}

/// The writer of chained report `i`, obtained from
/// [`super::ReportOpening::release_after_persist`]. Holds the report's signing
/// key and the table `seq → (sha256 blob, sha256 plaintext)` of recorded
/// objects.
pub struct ReportWriter {
    index: u32,
    signing_key: SigningKey,
    report_id: [u8; REPORT_ID_BYTES],
    report_pk: [u8; PK_BYTES],
    create_sig: [u8; SIG_BYTES],
    directory_entry_name: String,
    ots_name: String,
    recorded: BTreeMap<u32, RecordedObject>,
    closing: bool,
}

// ============================================================================
// Construction and public data
// ============================================================================

impl ReportWriter {
    /// Derive the writer of report `index` from its chain link.
    pub(super) fn from_link(index: u32, link: &ChainLink) -> Result<Self, CryptoError> {
        let signing_key = link.signing_key()?;
        let public = link.public_view()?;
        let create_sig = sign_create_under(&signing_key);
        Ok(Self {
            index,
            signing_key,
            report_id: public.report_id,
            report_pk: public.report_pk,
            create_sig,
            directory_entry_name: public.directory_entry_name,
            ots_name: public.ots_name,
            recorded: BTreeMap::new(),
            closing: false,
        })
    }

    /// Index `i` of this report.
    #[must_use]
    pub fn index(&self) -> u32 {
        self.index
    }

    /// The report's 16-byte `report_id` (its relay address).
    #[must_use]
    pub fn report_id(&self) -> &[u8; REPORT_ID_BYTES] {
        &self.report_id
    }

    /// The report's public key (`X-Report-PK`).
    #[must_use]
    pub fn report_pk(&self) -> &[u8; PK_BYTES] {
        &self.report_pk
    }

    /// The report's 0x07 `create_sig`, carried by every object of the report
    /// so that whichever reaches the relay first can create it.
    #[must_use]
    pub fn create_sig(&self) -> &[u8; SIG_BYTES] {
        &self.create_sig
    }

    /// Name (32 lowercase hex) of this report's entry in the directory.
    #[must_use]
    pub fn directory_entry_name(&self) -> &str {
        &self.directory_entry_name
    }

    /// Name (32 lowercase hex) under which this report's timestamp proof is
    /// stored in the directory.
    #[must_use]
    pub fn ots_name(&self) -> &str {
        &self.ots_name
    }

    /// Number of recorded objects (metadata included).
    #[must_use]
    pub fn recorded_count(&self) -> usize {
        self.recorded.len()
    }

    /// True once the metadata object (seq 0) is recorded.
    #[must_use]
    pub fn has_metadata(&self) -> bool {
        self.recorded.contains_key(&METADATA_SEQ)
    }

    /// True once [`Self::prepare_close`] has succeeded.
    #[must_use]
    pub fn is_closing(&self) -> bool {
        self.closing
    }
}

// ============================================================================
// Recording objects
// ============================================================================

impl ReportWriter {
    /// Whether object `seq` could be prepared now. The same check
    /// [`Self::prepare_chunk`] and [`Self::commit`] run, exposed so a caller can
    /// refuse before doing expensive work (reading and encrypting a chunk).
    ///
    /// # Errors
    /// [`ReportError::WriterClosing`], [`ReportError::SeqOutOfRange`],
    /// [`ReportError::MetadataRequired`] (a chunk before seq 0) or
    /// [`ReportError::DuplicateSeq`].
    pub fn check_sealable(&self, seq: u32) -> Result<(), ReportError> {
        if self.closing {
            return Err(ReportError::WriterClosing);
        }
        if seq > MAX_SEQ {
            return Err(ReportError::SeqOutOfRange(seq));
        }
        if seq != METADATA_SEQ && !self.has_metadata() {
            return Err(ReportError::MetadataRequired);
        }
        if self.recorded.contains_key(&seq) {
            return Err(ReportError::DuplicateSeq(seq));
        }
        Ok(())
    }

    /// Sign the metadata object (seq 0), the first object of every report.
    /// `blob_sha256` is the SHA-256 of the exact bytes that will be stored,
    /// `plain_sha256` that of the plaintext.
    ///
    /// # Errors
    /// See [`Self::check_sealable`].
    pub fn prepare_metadata(
        &self,
        plain_sha256: &[u8; HASH_BYTES],
        blob_sha256: &[u8; HASH_BYTES],
    ) -> Result<PreparedObject, ReportError> {
        self.prepare(METADATA_SEQ, plain_sha256, blob_sha256)
    }

    /// Sign media chunk `seq` (`1..=MAX_SEQ`, in any order, gaps allowed).
    ///
    /// # Errors
    /// [`ReportError::SeqReservedForMetadata`] for `seq = 0`; otherwise see
    /// [`Self::check_sealable`].
    pub fn prepare_chunk(
        &self,
        seq: u32,
        plain_sha256: &[u8; HASH_BYTES],
        blob_sha256: &[u8; HASH_BYTES],
    ) -> Result<PreparedObject, ReportError> {
        if seq == METADATA_SEQ {
            return Err(ReportError::SeqReservedForMetadata);
        }
        self.prepare(seq, plain_sha256, blob_sha256)
    }

    fn prepare(
        &self,
        seq: u32,
        plain_sha256: &[u8; HASH_BYTES],
        blob_sha256: &[u8; HASH_BYTES],
    ) -> Result<PreparedObject, ReportError> {
        self.check_sealable(seq)?;
        let filename = chain_object_name(seq)?;
        let write_sig = sign_write_under(&self.signing_key, filename.as_bytes(), blob_sha256);
        Ok(PreparedObject {
            report_id: self.report_id,
            seq,
            filename,
            plain_sha256: *plain_sha256,
            blob_sha256: *blob_sha256,
            write_sig,
        })
    }

    /// Record a prepared object, once the caller has written it durably. The
    /// checks of [`Self::check_sealable`] run again, so two preparations of the
    /// same `seq` can never both be recorded.
    ///
    /// # Errors
    /// [`ReportError::ForeignPreparation`] if `prepared` came from another
    /// writer; otherwise see [`Self::check_sealable`]. On error nothing is
    /// recorded.
    // Taken by value on purpose although only its fields are read: the prepared
    // object is a one-shot token, so the caller cannot hand the same one in
    // twice, and it is wiped when this returns.
    #[allow(clippy::needless_pass_by_value)]
    pub fn commit(&mut self, prepared: PreparedObject) -> Result<(), ReportError> {
        if prepared.report_id != self.report_id {
            return Err(ReportError::ForeignPreparation);
        }
        self.check_sealable(prepared.seq)?;
        self.recorded.insert(
            prepared.seq,
            RecordedObject {
                blob_sha256: prepared.blob_sha256,
                plain_sha256: prepared.plain_sha256,
            },
        );
        Ok(())
    }
}

// ============================================================================
// Closing
// ============================================================================

impl ReportWriter {
    /// Build the manifest of every recorded object, sign the closure (0x09) and
    /// refuse every later preparation or commit. Idempotent: a second call
    /// returns identical bytes, so a failed write of the closure is retried by
    /// calling it again.
    ///
    /// # Errors
    /// [`ReportError::MetadataRequired`] if seq 0 was never recorded: a chained
    /// closure always lists the metadata object, so an empty one is never
    /// signed. The writer is left open in that case.
    pub fn prepare_close(&mut self) -> Result<PreparedClose, ReportError> {
        if !self.has_metadata() {
            return Err(ReportError::MetadataRequired);
        }
        let entries = self
            .recorded
            .iter()
            .map(|(&seq, object)| ManifestEntry {
                seq,
                blob_sha256: object.blob_sha256,
            })
            .collect();
        // BTreeMap iterates in increasing key order and every key passed
        // `check_sealable`, so this cannot fail; it is still checked.
        let manifest = Manifest::from_entries(entries)?;
        let seq_limit = manifest.seq_limit();
        let manifest_bytes = manifest.to_bytes();
        let manifest_sha256 = manifest.sha256();
        let close_sig = sign_close_under(&self.signing_key, seq_limit, &manifest_sha256);
        let plaintext_hashes = self
            .recorded
            .range(METADATA_SEQ + 1..)
            .map(|(_, object)| object.plain_sha256)
            .collect();
        self.closing = true;
        Ok(PreparedClose {
            index: self.index,
            report_id: self.report_id,
            report_pk: self.report_pk,
            create_sig: self.create_sig,
            seq_limit,
            manifest: manifest_bytes,
            manifest_sha256,
            close_sig,
            plaintext_hashes,
            // Cloned, not moved: the writer keeps its own copy because a failed
            // closure write calls `prepare_close` again.
            ots_name: self.ots_name.clone(),
        })
    }
}

impl std::fmt::Debug for ReportWriter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ReportWriter(<redacted>)")
    }
}

// ============================================================================
// PreparedObject
// ============================================================================

/// One object signed by [`ReportWriter::prepare_metadata`] or
/// [`ReportWriter::prepare_chunk`], not yet recorded. Carries what the caller
/// writes next to the object: its relay name and its `write_sig`; the report's
/// public key and `create_sig` come from the writer.
#[derive(Zeroize, ZeroizeOnDrop)]
#[must_use = "a prepared object is recorded only by ReportWriter::commit"]
pub struct PreparedObject {
    report_id: [u8; REPORT_ID_BYTES],
    seq: u32,
    filename: String,
    plain_sha256: [u8; HASH_BYTES],
    blob_sha256: [u8; HASH_BYTES],
    write_sig: [u8; SIG_BYTES],
}

impl PreparedObject {
    /// Sequence number.
    #[must_use]
    pub fn seq(&self) -> u32 {
        self.seq
    }

    /// Relay object name, `format!("{seq:06}.strm")`.
    #[must_use]
    pub fn filename(&self) -> &str {
        &self.filename
    }

    /// SHA-256 of the stored bytes, as signed.
    #[must_use]
    pub fn blob_sha256(&self) -> &[u8; HASH_BYTES] {
        &self.blob_sha256
    }

    /// SHA-256 of the plaintext.
    #[must_use]
    pub fn plain_sha256(&self) -> &[u8; HASH_BYTES] {
        &self.plain_sha256
    }

    /// The 0x08 `write_sig` over `report_id ‖ filename ‖ blob_sha256`.
    #[must_use]
    pub fn write_sig(&self) -> &[u8; SIG_BYTES] {
        &self.write_sig
    }
}

impl std::fmt::Debug for PreparedObject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreparedObject")
            .field("seq", &self.seq)
            .finish_non_exhaustive()
    }
}

// ============================================================================
// PreparedClose
// ============================================================================

/// A signed closure from [`ReportWriter::prepare_close`]: the manifest bytes
/// (the payload sent to the relay), `seq_limit`, the 0x09 signature, and what
/// the timestamp commitment needs.
#[derive(Zeroize, ZeroizeOnDrop)]
#[must_use = "a closure takes effect only once written and sent"]
pub struct PreparedClose {
    index: u32,
    report_id: [u8; REPORT_ID_BYTES],
    report_pk: [u8; PK_BYTES],
    create_sig: [u8; SIG_BYTES],
    seq_limit: u32,
    manifest: Vec<u8>,
    manifest_sha256: [u8; HASH_BYTES],
    close_sig: [u8; SIG_BYTES],
    plaintext_hashes: Vec<[u8; HASH_BYTES]>,
    ots_name: String,
}

impl PreparedClose {
    /// Index `i` of the closed report.
    #[must_use]
    pub fn index(&self) -> u32 {
        self.index
    }

    /// The report's `report_id`.
    #[must_use]
    pub fn report_id(&self) -> &[u8; REPORT_ID_BYTES] {
        &self.report_id
    }

    /// The report's public key.
    #[must_use]
    pub fn report_pk(&self) -> &[u8; PK_BYTES] {
        &self.report_pk
    }

    /// The report's 0x07 `create_sig`.
    #[must_use]
    pub fn create_sig(&self) -> &[u8; SIG_BYTES] {
        &self.create_sig
    }

    /// `seq_limit` = last recorded `seq` + 1.
    #[must_use]
    pub fn seq_limit(&self) -> u32 {
        self.seq_limit
    }

    /// The manifest's exact bytes.
    #[must_use]
    pub fn manifest(&self) -> &[u8] {
        &self.manifest
    }

    /// SHA-256 of the manifest bytes.
    #[must_use]
    pub fn manifest_sha256(&self) -> &[u8; HASH_BYTES] {
        &self.manifest_sha256
    }

    /// The 0x09 `close_sig`.
    #[must_use]
    pub fn close_sig(&self) -> &[u8; SIG_BYTES] {
        &self.close_sig
    }

    /// Plaintext SHA-256 of every recorded chunk (`seq >= 1`), in increasing
    /// `seq`: the leaves of the timestamp commitment. The metadata object is
    /// not part of it.
    #[must_use]
    pub fn plaintext_hashes(&self) -> &[[u8; HASH_BYTES]] {
        &self.plaintext_hashes
    }

    /// Name (32 lowercase hex) of this report's timestamp proof in the
    /// directory.
    #[must_use]
    pub fn ots_name(&self) -> &str {
        &self.ots_name
    }
}

impl std::fmt::Debug for PreparedClose {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreparedClose")
            .field("seq_limit", &self.seq_limit)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::super::{verify_close, verify_create, verify_write, ReportDeviceState};
    use super::*;

    const MN_FIXED: &str = "abaisser abandon abdiquer abeille abolir aborder aboutir aboyer abrasif abreuver abriter abroger";

    fn writers(count: usize) -> Vec<ReportWriter> {
        let mut state = ReportDeviceState::from_mnemonic(MN_FIXED, "").unwrap();
        (0..count)
            .map(|_| {
                state
                    .open_report()
                    .unwrap()
                    .release_after_persist(|_| Ok::<(), ()>(()))
                    .unwrap()
            })
            .collect()
    }

    fn writer() -> ReportWriter {
        writers(1).pop().unwrap()
    }

    fn record(writer: &mut ReportWriter, seq: u32, plain: u8, blob: u8) {
        let prepared = if seq == 0 {
            writer.prepare_metadata(&[plain; 32], &[blob; 32])
        } else {
            writer.prepare_chunk(seq, &[plain; 32], &[blob; 32])
        }
        .unwrap();
        writer.commit(prepared).unwrap();
    }

    #[test]
    fn a_chunk_before_the_metadata_is_refused() {
        let w = writer();
        assert_eq!(
            w.prepare_chunk(1, &[0; 32], &[0; 32]).unwrap_err(),
            ReportError::MetadataRequired
        );
        assert_eq!(w.check_sealable(5), Err(ReportError::MetadataRequired));
        assert_eq!(w.check_sealable(0), Ok(()));
    }

    #[test]
    fn seq_zero_is_reserved_and_the_range_is_bounded() {
        let mut w = writer();
        assert_eq!(
            w.prepare_chunk(0, &[0; 32], &[0; 32]).unwrap_err(),
            ReportError::SeqReservedForMetadata
        );
        record(&mut w, 0, 1, 2);
        assert_eq!(
            w.prepare_chunk(MAX_SEQ + 1, &[0; 32], &[0; 32])
                .unwrap_err(),
            ReportError::SeqOutOfRange(MAX_SEQ + 1)
        );
        let top = w.prepare_chunk(MAX_SEQ, &[0; 32], &[0; 32]).unwrap();
        assert_eq!(top.filename(), "999999.strm");
    }

    #[test]
    fn preparing_changes_nothing_until_commit() {
        let mut w = writer();
        let first = w.prepare_metadata(&[1; 32], &[2; 32]).unwrap();
        // A preparation that is never committed (the write failed) leaves the
        // writer exactly as it was: seq 0 can be prepared again.
        drop(first);
        assert_eq!(w.recorded_count(), 0);
        assert!(!w.has_metadata());
        let again = w.prepare_metadata(&[1; 32], &[2; 32]).unwrap();
        w.commit(again).unwrap();
        assert!(w.has_metadata());
        assert_eq!(w.recorded_count(), 1);
    }

    #[test]
    fn a_seq_is_recorded_once() {
        let mut w = writer();
        record(&mut w, 0, 1, 2);
        let a = w.prepare_chunk(3, &[1; 32], &[2; 32]).unwrap();
        let b = w.prepare_chunk(3, &[1; 32], &[2; 32]).unwrap();
        w.commit(a).unwrap();
        assert_eq!(w.commit(b).unwrap_err(), ReportError::DuplicateSeq(3));
        assert_eq!(
            w.prepare_chunk(3, &[1; 32], &[2; 32]).unwrap_err(),
            ReportError::DuplicateSeq(3)
        );
        assert_eq!(
            w.prepare_metadata(&[1; 32], &[2; 32]).unwrap_err(),
            ReportError::DuplicateSeq(0)
        );
        assert_eq!(w.recorded_count(), 2);
    }

    #[test]
    fn a_preparation_cannot_be_committed_into_another_report() {
        let mut both = writers(2);
        let mut second = both.pop().unwrap();
        let first = both.pop().unwrap();
        let foreign = first.prepare_metadata(&[1; 32], &[2; 32]).unwrap();
        assert_eq!(
            second.commit(foreign).unwrap_err(),
            ReportError::ForeignPreparation
        );
        assert_eq!(second.recorded_count(), 0);
    }

    #[test]
    fn signatures_verify_under_the_report_key() {
        let w = writer();
        verify_create(w.report_pk(), w.create_sig()).unwrap();
        let prepared = w.prepare_metadata(&[1; 32], &[2; 32]).unwrap();
        assert_eq!(prepared.filename(), "000000.strm");
        assert_eq!(prepared.seq(), 0);
        assert_eq!(prepared.blob_sha256(), &[2; 32]);
        assert_eq!(prepared.plain_sha256(), &[1; 32]);
        verify_write(
            w.report_pk(),
            prepared.filename().as_bytes(),
            prepared.blob_sha256(),
            prepared.write_sig(),
        )
        .unwrap();
        // The signature binds the stored bytes' hash, not the plaintext's.
        assert_eq!(
            verify_write(
                w.report_pk(),
                prepared.filename().as_bytes(),
                prepared.plain_sha256(),
                prepared.write_sig(),
            )
            .unwrap_err(),
            ReportError::InvalidSignature
        );
    }

    #[test]
    fn closing_without_metadata_is_refused_and_keeps_the_writer_open() {
        let mut w = writer();
        assert_eq!(
            w.prepare_close().unwrap_err(),
            ReportError::MetadataRequired
        );
        assert!(!w.is_closing());
        record(&mut w, 0, 1, 2);
        assert!(w.prepare_close().is_ok());
    }

    #[test]
    fn the_closure_lists_every_recorded_object_in_order() {
        let mut w = writer();
        record(&mut w, 0, 0xA0, 0xB0);
        // Out of capture order, with a hole at 3: neither matters.
        record(&mut w, 4, 0xA4, 0xB4);
        record(&mut w, 1, 0xA1, 0xB1);
        record(&mut w, 2, 0xA2, 0xB2);
        let close = w.prepare_close().unwrap();
        assert_eq!(close.seq_limit(), 5);
        assert_eq!(close.index(), 0);
        assert_eq!(close.report_id(), w.report_id());
        assert_eq!(close.report_pk(), w.report_pk());
        assert_eq!(close.create_sig(), w.create_sig());
        assert_eq!(close.ots_name(), w.ots_name());
        let manifest = verify_close(
            w.report_pk(),
            close.seq_limit(),
            close.manifest(),
            close.close_sig(),
        )
        .unwrap();
        let listed: Vec<(u32, u8)> = manifest
            .entries()
            .iter()
            .map(|e| (e.seq, e.blob_sha256[0]))
            .collect();
        assert_eq!(listed, [(0, 0xB0), (1, 0xB1), (2, 0xB2), (4, 0xB4)]);
        assert_eq!(close.manifest_sha256(), &manifest.sha256());
        // The timestamp leaves are the plaintext hashes of seq >= 1, in order.
        assert_eq!(
            close.plaintext_hashes(),
            [[0xA1; 32], [0xA2; 32], [0xA4; 32]]
        );
    }

    #[test]
    fn closing_is_idempotent_and_final() {
        let mut w = writer();
        record(&mut w, 0, 1, 2);
        record(&mut w, 1, 3, 4);
        let pending = w.prepare_chunk(2, &[5; 32], &[6; 32]).unwrap();
        let first = w.prepare_close().unwrap();
        let second = w.prepare_close().unwrap();
        assert_eq!(first.manifest(), second.manifest());
        assert_eq!(first.close_sig(), second.close_sig());
        assert_eq!(first.seq_limit(), second.seq_limit());
        assert!(w.is_closing());
        // Nothing more can enter the closed set: not a new preparation, not
        // one prepared before the closure.
        assert_eq!(w.check_sealable(3), Err(ReportError::WriterClosing));
        assert_eq!(
            w.prepare_chunk(3, &[0; 32], &[0; 32]).unwrap_err(),
            ReportError::WriterClosing
        );
        assert_eq!(w.commit(pending).unwrap_err(), ReportError::WriterClosing);
        assert_eq!(w.prepare_close().unwrap().seq_limit(), 2);
    }

    #[test]
    fn debug_output_is_redacted() {
        let mut w = writer();
        assert_eq!(format!("{w:?}"), "ReportWriter(<redacted>)");
        let prepared = w.prepare_metadata(&[1; 32], &[2; 32]).unwrap();
        assert_eq!(format!("{prepared:?}"), "PreparedObject { seq: 0, .. }");
        w.commit(prepared).unwrap();
        let close = w.prepare_close().unwrap();
        assert_eq!(format!("{close:?}"), "PreparedClose { seq_limit: 1, .. }");
    }
}
