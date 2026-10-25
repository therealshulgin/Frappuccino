//! The writer of one chained report, as Kotlin holds it.
//!
//! Obtained from `pin_session_open_report`. It holds the report's signing key
//! (inside `core::report::ReportWriter`), the signatures of the report's
//! directory entry, and the table of objects sealed so far. Every object is
//! encrypted, signed and written as a queue envelope in ONE call, and recorded
//! in the table only once its envelope is durably on disk; [`ReportWriter::close_report`]
//! signs the closure over exactly that table and wipes the key. After a
//! successful close or an [`ReportWriter::abort`], every call fails with
//! [`FfiError::WriterClosed`].
//!
//! The methods take `&self` and lock internally. Encryption runs outside the
//! lock (it does not need the key); signing, writing the envelope and
//! recording it run under it, so a closure can never be signed between the
//! write of an object and its recording, and an abort waits at most for one
//! envelope write.

use std::path::Path;
use std::sync::{Mutex, MutexGuard, PoisonError};

use frappuccino_crypto_core::identity::StreamIdentity as CoreStreamIdentity;
use frappuccino_crypto_core::report::{self as core_report, ReportDeviceState};
use frappuccino_crypto_stream::{write_envelope, EnvelopeFields, EnvelopeKind};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::envelopes::queue_key_copy;
use crate::{hex_lower, lock_poisoned, FfiError};

/// Body of every directory entry. The entry's NAME is what the rescue reads;
/// the body carries nothing, and in particular no index.
const DIRECTORY_ENTRY_BODY: [u8; 1] = [0x01];

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

// ============================================================================
// Directory entry signatures
// ============================================================================

/// The signed parts of a report's directory entry, computed while the state
/// (and so the directory key) is open, so the writer never holds that key.
/// Public values: the relay sees all of them.
pub(crate) struct DirectoryEntrySigs {
    directory_pk: [u8; 32],
    create_sig: [u8; 64],
    entry_name: String,
    write_sig: [u8; 64],
}

impl DirectoryEntrySigs {
    pub(crate) fn sign(state: &ReportDeviceState, entry_name: &str) -> Self {
        let body_sha256 = sha256(&DIRECTORY_ENTRY_BODY);
        Self {
            directory_pk: state.directory_pk(),
            create_sig: state.sign_directory_create(),
            entry_name: entry_name.to_owned(),
            write_sig: state.sign_directory_write(entry_name.as_bytes(), &body_sha256),
        }
    }
}

// ============================================================================
// FFI records
// ============================================================================

/// Result of [`ReportWriter::seal_chunk_file`].
#[derive(Debug, Clone)]
pub struct SealedChunk {
    /// The sequence number sealed.
    pub seq: u32,
    /// Size of the encrypted object the relay will store.
    pub blob_bytes: u64,
}

/// Result of a successful [`ReportWriter::close_report`].
#[derive(Debug, Clone)]
pub struct CloseInfo {
    /// Index of the closed report.
    pub index: u32,
    /// Its `report_id`, 32 lowercase hex.
    pub report_id_hex: String,
    /// `seq_limit` of the closure (last sealed seq + 1).
    pub seq_limit: u32,
    /// Number of objects the closure lists, metadata included.
    pub object_count: u32,
    /// Plaintext SHA-256 of every sealed chunk (`seq >= 1`), in increasing
    /// `seq`: the leaves of the timestamp commitment
    /// (`provenance_ots_commitment`). The metadata object is not among them.
    pub plaintext_hashes: Vec<Vec<u8>>,
    /// Name (32 lowercase hex) the report's timestamp proof takes in the
    /// directory (`ots_ticket_write`).
    pub ots_name: String,
}

// ============================================================================
// ReportWriter
// ============================================================================

struct WriterInner {
    core: core_report::ReportWriter,
    directory: DirectoryEntrySigs,
}

/// What a sealed object is.
#[derive(Clone, Copy)]
enum ObjectRole {
    /// The metadata object, seq 0.
    Metadata,
    /// Media chunk `seq >= 1`.
    Chunk(u32),
}

impl ObjectRole {
    fn seq(self) -> u32 {
        match self {
            Self::Metadata => 0,
            Self::Chunk(seq) => seq,
        }
    }
}

/// FFI object: the writer of one open report.
pub struct ReportWriter {
    index: u32,
    report_id_hex: String,
    author: CoreStreamIdentity,
    inner: Mutex<Option<WriterInner>>,
}

impl std::fmt::Debug for ReportWriter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ReportWriter(<redacted>)")
    }
}

// ---- construction (crate) --------------------------------------------------

impl ReportWriter {
    pub(crate) fn new(
        core: core_report::ReportWriter,
        directory: DirectoryEntrySigs,
        author: CoreStreamIdentity,
    ) -> Self {
        Self {
            index: core.index(),
            report_id_hex: hex_lower(core.report_id()),
            author,
            inner: Mutex::new(Some(WriterInner { core, directory })),
        }
    }

    /// Wipe the key without a closure. True if the writer was open.
    pub(crate) fn abort_now(&self) -> bool {
        // Poison-recover: the abort exists to wipe the key, and must run even
        // after a panic held the lock.
        let mut guard = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        guard.take().is_some()
    }

    fn lock(&self) -> Result<MutexGuard<'_, Option<WriterInner>>, FfiError> {
        self.inner.lock().map_err(|_| lock_poisoned())
    }

    /// Test-only: poison the lock the way a panic under it would, with the
    /// key still inside.
    #[cfg(test)]
    pub(crate) fn poison_for_test(&self) {
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = self.inner.lock();
            panic!("test: a panic while the writer's lock is held");
        }));
    }

    /// Test-only: whether the writer still holds its key, poisoned or not.
    #[cfg(test)]
    pub(crate) fn holds_key_for_test(&self) -> bool {
        self.inner
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_some()
    }
}

// ---- public API (FFI) -------------------------------------------------------

impl ReportWriter {
    /// Index of the report.
    #[must_use]
    pub fn index(&self) -> u32 {
        self.index
    }

    /// The report's `report_id`, 32 lowercase hex.
    #[must_use]
    pub fn report_id_hex(&self) -> String {
        self.report_id_hex.clone()
    }

    /// Whether the writer still accepts objects or a closure (neither closed
    /// nor aborted).
    #[must_use]
    pub fn is_open(&self) -> bool {
        // A poisoned writer accepts nothing.
        self.inner.lock().is_ok_and(|guard| guard.is_some())
    }

    /// Write the report's directory entry envelope to `out_path`, signed by the
    /// directory key when the report was opened. The first thing to write,
    /// before the metadata. Writing it again replaces the file.
    ///
    /// # Errors
    /// [`FfiError::WriterClosed`], [`FfiError::NoQueueKey`], [`FfiError::Io`].
    pub fn seal_directory_entry(&self, out_path: &str) -> Result<(), FfiError> {
        let key = queue_key_copy()?;
        let guard = self.lock()?;
        let inner = guard.as_ref().ok_or(FfiError::WriterClosed)?;
        let directory = &inner.directory;
        let fields = EnvelopeFields::object(
            EnvelopeKind::DirectoryEntry,
            directory.directory_pk,
            &directory.entry_name,
            directory.write_sig,
            Some(directory.create_sig),
        )?;
        write_envelope(Path::new(out_path), &DIRECTORY_ENTRY_BODY, fields, &key)?;
        Ok(())
    }

    /// Seal the metadata JSON as seq 0 into the envelope at `out_path`. The
    /// first object of every report: chunks are refused until it is sealed.
    ///
    /// # Errors
    /// As [`Self::seal_chunk_file`].
    pub fn seal_metadata(&self, json: &[u8], out_path: &str) -> Result<(), FfiError> {
        self.seal_object(ObjectRole::Metadata, json, Path::new(out_path))
            .map(|_| ())
    }

    /// Seal media chunk `seq` (the capture number, `>= 1`, gaps allowed) from
    /// the MP4 at `input_path` into the envelope at `out_path`: read the MP4,
    /// hash the plaintext, encrypt it to the author, hash the encrypted object,
    /// sign it, write the envelope durably, and only then record `seq`.
    ///
    /// Transactional: on any error the writer's table is unchanged, nothing is
    /// left at `out_path`, and the MP4 is untouched (Kotlin deletes it after a
    /// success). A retry with the same `out_path` overwrites whatever a failed
    /// attempt left.
    ///
    /// # Errors
    /// [`FfiError::ReportRefused`] for seq 0, a `seq` above 999 999, a chunk
    /// before the metadata, or a `seq` already sealed; [`FfiError::WriterClosed`]
    /// once closing has started or after an abort; [`FfiError::NoQueueKey`];
    /// [`FfiError::Io`] for the MP4 or the envelope.
    pub fn seal_chunk_file(
        &self,
        seq: u32,
        input_path: &str,
        out_path: &str,
    ) -> Result<SealedChunk, FfiError> {
        if seq == 0 {
            return Err(FfiError::from(
                core_report::ReportError::SeqReservedForMetadata,
            ));
        }
        let plaintext = Zeroizing::new(std::fs::read(input_path).map_err(|e| FfiError::Io {
            detail: format!("read chunk {seq}: {e}"),
        })?);
        let blob_bytes =
            self.seal_object(ObjectRole::Chunk(seq), &plaintext, Path::new(out_path))?;
        Ok(SealedChunk { seq, blob_bytes })
        // plaintext (Zeroizing) drops here → wiped.
    }

    /// Close the report: sign the closure over every sealed object (0x09),
    /// write its envelope durably to `out_path`, then wipe the key. Returns
    /// what the timestamp commitment needs. A failed write can be retried by
    /// calling `close_report` again (same manifest, same signature); once closing has
    /// started no further object is accepted.
    ///
    /// # Errors
    /// [`FfiError::ReportRefused`] if the metadata was never sealed (the
    /// writer stays open: a chained closure always lists seq 0);
    /// [`FfiError::WriterClosed`]; [`FfiError::NoQueueKey`]; [`FfiError::Io`].
    pub fn close_report(&self, out_path: &str) -> Result<CloseInfo, FfiError> {
        let key = queue_key_copy()?;
        let mut guard = self.lock()?;
        let inner = guard.as_mut().ok_or(FfiError::WriterClosed)?;
        let prepared = inner.core.prepare_close()?;
        let fields = EnvelopeFields::closure(
            *prepared.report_pk(),
            prepared.seq_limit(),
            *prepared.close_sig(),
            Some(*prepared.create_sig()),
        )?;
        write_envelope(Path::new(out_path), prepared.manifest(), fields, &key)?;
        let info = CloseInfo {
            index: prepared.index(),
            report_id_hex: hex_lower(prepared.report_id()),
            seq_limit: prepared.seq_limit(),
            object_count: u32::try_from(inner.core.recorded_count()).map_err(|_| {
                FfiError::Internal {
                    detail: "object count overflows u32".into(),
                }
            })?,
            plaintext_hashes: prepared
                .plaintext_hashes()
                .iter()
                .map(|hash| hash.to_vec())
                .collect(),
            ots_name: prepared.ots_name().to_owned(),
        };
        // Taking the inner drops the core writer, whose key is wiped.
        *guard = None;
        Ok(info)
    }

    /// Wipe the key without writing a closure (emergency wipe, or a recording
    /// that could not start). Idempotent.
    pub fn abort(&self) {
        let _ = self.abort_now();
    }
}

// ---- private helpers --------------------------------------------------------

impl ReportWriter {
    /// Encrypt `plaintext`, then sign, write and record it as `role`.
    /// Returns the size of the encrypted object.
    fn seal_object(
        &self,
        role: ObjectRole,
        plaintext: &[u8],
        out_path: &Path,
    ) -> Result<u64, FfiError> {
        let key = queue_key_copy()?;
        // Refuse before the expensive part, then encrypt without the lock.
        {
            let guard = self.lock()?;
            let inner = guard.as_ref().ok_or(FfiError::WriterClosed)?;
            inner.core.check_sealable(role.seq())?;
        }
        let plain_sha256 = sha256(plaintext);
        let blob = frappuccino_crypto_stream::encrypt::encrypt(plaintext, &self.author)?;
        let blob_sha256 = sha256(&blob);
        let blob_bytes = u64::try_from(blob.len()).map_err(|_| FfiError::Internal {
            detail: "object size overflows u64".into(),
        })?;

        let mut guard = self.lock()?;
        let inner = guard.as_mut().ok_or(FfiError::WriterClosed)?;
        let prepared = match role {
            ObjectRole::Metadata => inner.core.prepare_metadata(&plain_sha256, &blob_sha256),
            ObjectRole::Chunk(seq) => inner.core.prepare_chunk(seq, &plain_sha256, &blob_sha256),
        }?;
        let fields = EnvelopeFields::object(
            EnvelopeKind::Chunk,
            *inner.core.report_pk(),
            prepared.filename(),
            *prepared.write_sig(),
            Some(*inner.core.create_sig()),
        )?;
        write_envelope(out_path, &blob, fields, &key)?;
        if let Err(error) = inner.core.commit(prepared) {
            // Unreachable while the lock is held across prepare and commit,
            // but a signed envelope that is not in the table must not stay:
            // the rescue would count it as a second signer.
            let _ = std::fs::remove_file(out_path);
            return Err(error.into());
        }
        Ok(blob_bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{author, globals, install_session, scratch_dir, MN_FIXED};
    use crate::{pin_session_create_report_state, pin_session_open_report, queue_key_clear};
    use frappuccino_crypto_core::identity::ArchiveIdentity;
    use frappuccino_crypto_core::report::{chain_object_name, ReportRescue};
    use frappuccino_crypto_stream::{open_envelope, EnvelopeTrailer};
    use std::path::PathBuf;
    use std::sync::Arc;

    struct Fixture {
        dir: PathBuf,
        writer: Arc<ReportWriter>,
    }

    impl Fixture {
        fn new(name: &str) -> Self {
            let dir = scratch_dir(name);
            install_session();
            let state = dir.join("report_state.bin");
            let state = state.to_str().unwrap();
            pin_session_create_report_state(MN_FIXED.as_bytes(), b"", state).unwrap();
            let writer = pin_session_open_report(state, author()).unwrap();
            Self { dir, writer }
        }

        fn path(&self, name: &str) -> PathBuf {
            self.dir.join(name)
        }

        fn out(&self, name: &str) -> String {
            self.path(name).to_str().unwrap().to_owned()
        }

        fn mp4(&self, seq: u32, bytes: &[u8]) -> String {
            let path = self.path(&format!("chunk_{seq}.mp4"));
            std::fs::write(&path, bytes).unwrap();
            path.to_str().unwrap().to_owned()
        }

        fn open(&self, name: &str) -> EnvelopeTrailer {
            let key = queue_key_copy().unwrap();
            open_envelope(&self.path(name), &key)
                .unwrap()
                .trailer()
                .clone()
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            self.writer.abort();
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn decrypt_payload(path: &Path, trailer: &EnvelopeTrailer) -> Vec<u8> {
        let bytes = std::fs::read(path).unwrap();
        let payload = &bytes[..usize::try_from(trailer.payload_len()).unwrap()];
        let archive = ArchiveIdentity::from_mnemonic(MN_FIXED, "").unwrap();
        let (plain, _) = frappuccino_crypto_stream::decrypt::decrypt(payload, &archive).unwrap();
        plain.to_vec()
    }

    #[test]
    fn a_whole_report_seals_into_verifiable_envelopes() {
        let _g = globals();
        let fx = Fixture::new("writer_whole");
        let w = &fx.writer;
        let mut rescue = ReportRescue::from_mnemonic(MN_FIXED, "").unwrap();
        let found = rescue.chain(0).unwrap();

        w.seal_directory_entry(&fx.out("s_d.fqe")).unwrap();
        let entry = fx.open("s_d.fqe");
        assert_eq!(entry.kind(), EnvelopeKind::DirectoryEntry);
        assert_eq!(Some(entry.filename()), found.directory_entry_name());
        assert_eq!(entry.report_id(), rescue.directory().report_id());
        assert!(entry.create_sig().is_some());

        w.seal_metadata(br#"{"sessionId":"s"}"#, &fx.out("s_c000000.fqe"))
            .unwrap();
        let meta = fx.open("s_c000000.fqe");
        assert_eq!(meta.filename(), "000000.strm");
        assert_eq!(meta.report_id_hex(), w.report_id_hex());
        assert_eq!(
            decrypt_payload(&fx.path("s_c000000.fqe"), &meta),
            br#"{"sessionId":"s"}"#
        );

        // Chunks out of capture order, with a hole at 2.
        let chunk3 = fx.mp4(3, b"third chunk of mp4");
        let chunk1 = fx.mp4(1, b"first chunk of mp4");
        let sealed = w
            .seal_chunk_file(3, &chunk3, &fx.out("s_c000003.fqe"))
            .unwrap();
        assert_eq!(sealed.seq, 3);
        w.seal_chunk_file(1, &chunk1, &fx.out("s_c000001.fqe"))
            .unwrap();
        let three = fx.open("s_c000003.fqe");
        assert_eq!(three.filename(), "000003.strm");
        assert_eq!(three.payload_len(), sealed.blob_bytes);
        found
            .verify_write(b"000003.strm", three.payload_sha256(), three.signature())
            .unwrap();
        found.verify_create(three.create_sig().unwrap()).unwrap();
        assert_eq!(
            decrypt_payload(&fx.path("s_c000003.fqe"), &three),
            b"third chunk of mp4"
        );
        // The MP4 is left for Kotlin to delete.
        assert!(Path::new(&chunk3).exists());

        let info = w.close_report(&fx.out("s_z.fqe")).unwrap();
        assert!(!w.is_open());
        assert_eq!(info.index, 0);
        assert_eq!(info.report_id_hex, w.report_id_hex());
        assert_eq!(info.seq_limit, 4);
        assert_eq!(info.object_count, 3);
        assert_eq!(
            info.plaintext_hashes,
            vec![
                sha256(b"first chunk of mp4").to_vec(),
                sha256(b"third chunk of mp4").to_vec()
            ]
        );
        assert_eq!(Some(info.ots_name.as_str()), found.ots_name());
        let closure = fx.open("s_z.fqe");
        assert_eq!(closure.kind(), EnvelopeKind::Closure);
        assert!(!closure.needs_drain());
        let bytes = std::fs::read(fx.path("s_z.fqe")).unwrap();
        let manifest = &bytes[..usize::try_from(closure.payload_len()).unwrap()];
        let parsed = found
            .verify_close(closure.seq_limit(), manifest, closure.signature())
            .unwrap();
        let listed: Vec<u32> = parsed.entries().iter().map(|e| e.seq).collect();
        assert_eq!(listed, [0, 1, 3]);
        assert_eq!(parsed.blob_sha256(3), Some(three.payload_sha256()));

        // Closed: everything is refused.
        let chunk4 = fx.mp4(4, b"late");
        assert!(matches!(
            w.seal_chunk_file(4, &chunk4, &fx.out("s_c000004.fqe")),
            Err(FfiError::WriterClosed)
        ));
        assert!(!fx.path("s_c000004.fqe").exists());
        assert!(matches!(
            w.close_report(&fx.out("again.fqe")),
            Err(FfiError::WriterClosed)
        ));
        assert!(matches!(
            w.seal_directory_entry(&fx.out("again_d.fqe")),
            Err(FfiError::WriterClosed)
        ));
    }

    #[test]
    fn the_sequence_rules_are_enforced_before_any_write() {
        let _g = globals();
        let fx = Fixture::new("writer_rules");
        let w = &fx.writer;
        let mp4 = fx.mp4(1, b"bytes");
        // A chunk before the metadata.
        assert!(matches!(
            w.seal_chunk_file(1, &mp4, &fx.out("c1.fqe")),
            Err(FfiError::ReportRefused { .. })
        ));
        assert!(!fx.path("c1.fqe").exists());
        // A closure before the metadata leaves the writer open.
        assert!(matches!(
            w.close_report(&fx.out("z.fqe")),
            Err(FfiError::ReportRefused { .. })
        ));
        assert!(w.is_open());
        assert!(!fx.path("z.fqe").exists());
        w.seal_metadata(b"{}", &fx.out("c0.fqe")).unwrap();
        // seq 0 is the metadata's, and only once.
        assert!(matches!(
            w.seal_chunk_file(0, &mp4, &fx.out("c0b.fqe")),
            Err(FfiError::ReportRefused { .. })
        ));
        assert!(matches!(
            w.seal_metadata(b"{}", &fx.out("c0c.fqe")),
            Err(FfiError::ReportRefused { .. })
        ));
        w.seal_chunk_file(1, &mp4, &fx.out("c1.fqe")).unwrap();
        // A seq sealed twice; the first envelope stays as it was.
        let before = std::fs::read(fx.path("c1.fqe")).unwrap();
        assert!(matches!(
            w.seal_chunk_file(1, &mp4, &fx.out("c1.fqe")),
            Err(FfiError::ReportRefused { .. })
        ));
        assert_eq!(std::fs::read(fx.path("c1.fqe")).unwrap(), before);
        // Out of the sequence space.
        assert!(matches!(
            w.seal_chunk_file(1_000_000, &mp4, &fx.out("big.fqe")),
            Err(FfiError::ReportRefused { .. })
        ));
        assert_eq!(chain_object_name(999_999).unwrap(), "999999.strm");
    }

    #[test]
    fn a_failed_seal_changes_nothing_and_can_be_retried() {
        let _g = globals();
        let fx = Fixture::new("writer_failures");
        let w = &fx.writer;
        w.seal_metadata(b"{}", &fx.out("c0.fqe")).unwrap();
        // A missing MP4.
        assert!(matches!(
            w.seal_chunk_file(1, &fx.out("absent.mp4"), &fx.out("c1.fqe")),
            Err(FfiError::Io { .. })
        ));
        // An envelope that cannot be written (its directory does not exist).
        let mp4 = fx.mp4(1, b"chunk one");
        let unwritable = fx.path("no_such_dir").join("c1.fqe");
        assert!(matches!(
            w.seal_chunk_file(1, &mp4, unwritable.to_str().unwrap()),
            Err(FfiError::Io { .. })
        ));
        assert_eq!(std::fs::read(&mp4).unwrap(), b"chunk one", "MP4 intact");
        // No queue key: refused before any work.
        queue_key_clear();
        assert!(matches!(
            w.seal_chunk_file(1, &mp4, &fx.out("c1.fqe")),
            Err(FfiError::NoQueueKey)
        ));
        assert!(matches!(
            w.close_report(&fx.out("z.fqe")),
            Err(FfiError::NoQueueKey)
        ));
        install_session();
        // None of the failures recorded seq 1: it seals now.
        w.seal_chunk_file(1, &mp4, &fx.out("c1.fqe")).unwrap();
        // A closure whose write fails is retried with the same content, and
        // nothing more is accepted in between.
        let bad_close = fx.path("no_such_dir").join("z.fqe");
        assert!(matches!(
            w.close_report(bad_close.to_str().unwrap()),
            Err(FfiError::Io { .. })
        ));
        assert!(w.is_open());
        let mp4_2 = fx.mp4(2, b"late chunk");
        assert!(matches!(
            w.seal_chunk_file(2, &mp4_2, &fx.out("c2.fqe")),
            Err(FfiError::WriterClosed)
        ));
        let info = w.close_report(&fx.out("z.fqe")).unwrap();
        assert_eq!(info.seq_limit, 2);
        assert_eq!(info.object_count, 2);
    }

    #[test]
    fn an_abort_wipes_without_a_closure() {
        let _g = globals();
        let fx = Fixture::new("writer_abort");
        let w = &fx.writer;
        w.seal_metadata(b"{}", &fx.out("c0.fqe")).unwrap();
        w.abort();
        w.abort();
        assert!(!w.is_open());
        assert!(matches!(
            w.close_report(&fx.out("z.fqe")),
            Err(FfiError::WriterClosed)
        ));
        assert!(matches!(
            w.seal_metadata(b"{}", &fx.out("c0b.fqe")),
            Err(FfiError::WriterClosed)
        ));
        assert!(!fx.path("z.fqe").exists());
        assert_eq!(format!("{w:?}"), "ReportWriter(<redacted>)");
    }
}
