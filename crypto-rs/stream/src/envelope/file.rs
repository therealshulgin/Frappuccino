//! Envelope files: durable writing, conversion of an existing payload file by
//! appending a trailer, inspection, and full verification before a send.

use super::{
    max_manifest_bytes, EnvelopeError, EnvelopeFields, EnvelopeKind, EnvelopeTrailer, QueueKey,
    MAX_TAIL_BYTES,
};
use crate::durable::{sync_parent_dir, write_durably, OnDirSyncError};
use crate::file_range::{FileRange, FileRangeReader, RangeFailure};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

/// Read buffer for hashing a payload in place.
const HASH_BUF_BYTES: usize = 64 * 1024;

// ============================================================================
// Payload digest
// ============================================================================

/// Length and SHA-256 of a payload, what its signature is computed over.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PayloadDigest {
    len: u64,
    sha256: [u8; 32],
}

impl PayloadDigest {
    /// Digest of an in-memory payload.
    ///
    /// # Errors
    /// [`EnvelopeError::InvalidFields`] if the length does not fit a `u64`.
    pub fn of_bytes(payload: &[u8]) -> Result<Self, EnvelopeError> {
        Ok(Self {
            len: u64::try_from(payload.len())
                .map_err(|_| EnvelopeError::InvalidFields("payload too large"))?,
            sha256: Sha256::digest(payload).into(),
        })
    }

    /// Payload length in bytes.
    #[must_use]
    pub fn len(&self) -> u64 {
        self.len
    }

    /// True for an empty payload.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// SHA-256 of the payload.
    #[must_use]
    pub fn sha256(&self) -> &[u8; 32] {
        &self.sha256
    }
}

// ============================================================================
// Verified envelope
// ============================================================================

/// An envelope whose trailer decrypted, whose payload re-hashed to the
/// recorded value and whose signatures verified, at the time it was opened.
#[derive(Debug, Clone)]
pub struct VerifiedEnvelope {
    path: PathBuf,
    trailer: EnvelopeTrailer,
}

impl VerifiedEnvelope {
    /// The envelope file.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The decoded trailer.
    #[must_use]
    pub fn trailer(&self) -> &EnvelopeTrailer {
        &self.trailer
    }

    /// The payload as a byte range of the file that must still hash to the
    /// verified value when it is read again, for instance as a request body.
    #[must_use]
    pub fn payload_range(&self) -> FileRange {
        FileRange::new(
            self.path.clone(),
            0,
            self.trailer.payload_len(),
            Some(*self.trailer.payload_sha256()),
        )
    }

    /// Stream the payload, re-hashing it: the read that would complete it
    /// fails if the bytes changed since they were verified.
    ///
    /// # Errors
    /// The [`RangeFailure`] of opening the range.
    pub fn payload_reader(&self) -> Result<FileRangeReader, RangeFailure> {
        self.payload_range().open()
    }
}

/// Result of [`convert_to_envelope`].
#[derive(Debug, Clone)]
pub enum Conversion {
    /// The trailer was appended and the file renamed.
    Converted(EnvelopeTrailer),
    /// The file already carried a trailer readable under the key (or only
    /// the destination exists, holding one): nothing was appended, the file
    /// was renamed if needed.
    AlreadyConverted(EnvelopeTrailer),
}

// ============================================================================
// Writing
// ============================================================================

/// Write `payload` followed by its sealed trailer to `out_path`, durably: a
/// `.part` sibling, `sync_all`, rename, then a flush of the directory entry.
///
/// The signatures in `fields` are checked against `payload` first, so an
/// envelope its own sender would refuse is never written. An existing file at
/// `out_path` is replaced, which makes a retry under the same deterministic
/// name overwrite whatever a failed attempt left. On error the function tries
/// to leave nothing at `out_path` (see [`crate::durable`]).
///
/// # Errors
/// The rule and verification errors of [`EnvelopeTrailer::for_payload`], the
/// sealing errors, and [`EnvelopeError::Io`] for the file operations.
pub fn write_envelope(
    out_path: &Path,
    payload: &[u8],
    fields: EnvelopeFields,
    key: &QueueKey,
) -> Result<EnvelopeTrailer, EnvelopeError> {
    let trailer = EnvelopeTrailer::for_payload(fields, payload)?;
    let tail = trailer.seal(key)?;
    // The payload's source (the MP4, the writer's table) is still there on
    // an error, and a retry writes the same name again.
    write_durably(out_path, OnDirSyncError::RemoveDestination, |file| {
        file.write_all(payload)?;
        file.write_all(&tail)
    })
    .map_err(|error| EnvelopeError::io("write envelope", &error))?;
    Ok(trailer)
}

/// Suffix of the marker [`convert_to_envelope`] keeps next to its
/// destination (`<dst>.conv`) while it appends a trailer.
const CONVERSION_MARKER_SUFFIX: &str = ".conv";

/// Turn the file at `src`, whose whole content is the payload, into an
/// envelope at `dst` by appending a trailer and renaming, without copying the
/// payload.
///
/// `sign` receives the payload's length and hash, measured here from the
/// open file, and returns the signed fields; the trailer is checked against
/// them before it is appended. The append is flushed (`sync_all`) before the
/// rename, and the directory entry after it.
///
/// Idempotent and resumable: a `src` that already ends with a trailer
/// readable under `key` is only renamed, and a missing `src` whose `dst`
/// already holds one is reported as done. A `src` that ends with the magic
/// but whose trailer does not open is refused rather than given a second
/// trailer.
///
/// Before the append, the payload's length and hash are recorded durably in a
/// marker `<dst>.conv`, removed once the envelope is in place. A power cut
/// during the append can leave part of a trailer (or zeros) after the
/// payload, which nothing in the file tells apart from payload bytes; a run
/// that finds the marker, and the recorded payload at the start of the
/// source, cuts the source back to it and converts again from there, so
/// those bytes are never signed as payload.
///
/// # Errors
/// [`EnvelopeError::NotFound`] if neither file is usable,
/// [`EnvelopeError::Signing`] from `sign`, the rule and verification errors
/// of the trailer, the trailer errors of a `src` that already ends with the
/// magic, [`EnvelopeError::Malformed`] for a `src` shorter than its marker
/// records, and [`EnvelopeError::Io`] (a marker that is unreadable or does
/// not describe the start of `src` included: nothing is cut then).
pub fn convert_to_envelope(
    src: &Path,
    dst: &Path,
    key: &QueueKey,
    sign: impl FnOnce(&PayloadDigest) -> Result<EnvelopeFields, EnvelopeError>,
) -> Result<Conversion, EnvelopeError> {
    let marker = conversion_marker_path(dst)?;
    let mut file = match OpenOptions::new().read(true).write(true).open(src) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let done = already_at_destination(dst, key)?;
            remove_conversion_marker(&marker)?;
            return Ok(done);
        }
        Err(error) => return Err(EnvelopeError::io("open source", &error)),
    };
    let digest = match resume_point(&mut file, &marker, key)? {
        Resume::AlreadyConverted(trailer) => {
            drop(file);
            move_into_place(src, dst)?;
            remove_conversion_marker(&marker)?;
            return Ok(Conversion::AlreadyConverted(*trailer));
        }
        Resume::Convert(digest) => digest,
    };
    let fields = sign(&digest)?;
    let trailer = trailer_for_file(&mut file, fields, &digest)?;
    let tail = trailer.seal(key)?;
    write_conversion_marker(&marker, &digest)?;
    append_tail(&mut file, digest.len(), &tail)?;
    drop(file);
    move_into_place(src, dst)?;
    remove_conversion_marker(&marker)?;
    Ok(Conversion::Converted(trailer))
}

/// Where a conversion of an opened source starts.
enum Resume {
    /// The source already carries a trailer readable under the key.
    AlreadyConverted(Box<EnvelopeTrailer>),
    /// The payload, measured: the first `len()` bytes of the source, which is
    /// that long now.
    Convert(PayloadDigest),
}

/// Decide where the conversion of `file` starts. Without a marker the whole
/// file is the payload, unless it already ends with a trailer. With one, the
/// recorded payload must be the start of the file; anything after it that is
/// not a readable trailer is what an interrupted append left, and it is cut.
fn resume_point(file: &mut File, marker: &Path, key: &QueueKey) -> Result<Resume, EnvelopeError> {
    let recorded = read_conversion_marker(marker)?;
    let file_len = file_len(file)?;
    match EnvelopeTrailer::open(file_len, &read_tail(file, file_len)?, key) {
        Ok(trailer) => return Ok(Resume::AlreadyConverted(Box::new(trailer))),
        Err(EnvelopeError::NoTrailer) => {}
        // With a marker, a trailer that does not open is a torn append.
        Err(_) if recorded.is_some() => {}
        Err(error) => return Err(error),
    }
    let Some(recorded) = recorded else {
        return Ok(Resume::Convert(hash_prefix(file, file_len)?));
    };
    if recorded.len() > file_len {
        return Err(EnvelopeError::Malformed(
            "source shorter than the payload its conversion recorded",
        ));
    }
    // Cut only a source that starts with exactly the recorded payload: a
    // marker left over from another conversion never truncates anything.
    let digest = hash_prefix(file, recorded.len())?;
    if digest != recorded {
        return Err(EnvelopeError::io(
            "check the conversion marker",
            &std::io::Error::from(std::io::ErrorKind::InvalidData),
        ));
    }
    if digest.len() < file_len {
        file.set_len(digest.len())
            .and_then(|()| file.sync_all())
            .map_err(|error| EnvelopeError::io("cut an interrupted append", &error))?;
    }
    Ok(Resume::Convert(digest))
}

/// `<dst>.conv`.
fn conversion_marker_path(dst: &Path) -> Result<PathBuf, EnvelopeError> {
    let mut name = dst
        .file_name()
        .ok_or_else(|| {
            EnvelopeError::io(
                "name the conversion marker",
                &std::io::Error::from(std::io::ErrorKind::InvalidInput),
            )
        })?
        .to_os_string();
    name.push(CONVERSION_MARKER_SUFFIX);
    Ok(dst.with_file_name(name))
}

/// Bytes of a marker: the payload length (u64, big-endian), then its SHA-256.
const CONVERSION_MARKER_LEN: usize = 8 + 32;

/// The payload a marker records, `None` without a marker.
fn read_conversion_marker(marker: &Path) -> Result<Option<PayloadDigest>, EnvelopeError> {
    let bytes = match std::fs::read(marker) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(EnvelopeError::io("read conversion marker", &error)),
    };
    // Written whole by `write_durably`, so another size is not a torn write;
    // it stops the conversion and leaves the source as it is.
    let unreadable = || {
        EnvelopeError::io(
            "read conversion marker",
            &std::io::Error::from(std::io::ErrorKind::InvalidData),
        )
    };
    let recorded: &[u8; CONVERSION_MARKER_LEN] =
        bytes.as_slice().try_into().map_err(|_| unreadable())?;
    let (len, sha256) = recorded.split_at(8);
    Ok(Some(PayloadDigest {
        len: u64::from_be_bytes(len.try_into().map_err(|_| unreadable())?),
        sha256: sha256.try_into().map_err(|_| unreadable())?,
    }))
}

/// Record the payload durably before the append starts.
fn write_conversion_marker(marker: &Path, payload: &PayloadDigest) -> Result<(), EnvelopeError> {
    write_durably(marker, OnDirSyncError::RemoveDestination, |file| {
        file.write_all(&payload.len().to_be_bytes())?;
        file.write_all(payload.sha256())
    })
    .map_err(|error| EnvelopeError::io("write conversion marker", &error))
}

/// Remove the marker once the envelope is in place, durably: a marker that
/// came back after a power cut would be found by no later run, the
/// conversion being done.
fn remove_conversion_marker(marker: &Path) -> Result<(), EnvelopeError> {
    match std::fs::remove_file(marker) {
        Ok(()) => sync_parent_dir(marker)
            .map_err(|error| EnvelopeError::io("remove conversion marker", &error)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(EnvelopeError::io("remove conversion marker", &error)),
    }
}

// ============================================================================
// Reading
// ============================================================================

/// Decode the trailer of the envelope at `path` without reading the payload
/// or checking signatures: cheap enough to run over a whole queue.
///
/// # Errors
/// [`EnvelopeError::NotFound`], [`EnvelopeError::Io`], and the errors of
/// [`EnvelopeTrailer::open`].
pub fn inspect_envelope(path: &Path, key: &QueueKey) -> Result<EnvelopeTrailer, EnvelopeError> {
    let mut file = File::open(path).map_err(|error| EnvelopeError::io("open envelope", &error))?;
    let file_len = file_len(&file)?;
    EnvelopeTrailer::open(file_len, &read_tail(&mut file, file_len)?, key)
}

/// Open the envelope at `path` and verify it entirely: trailer, re-hash of the
/// payload, `report_id`/`report_pk` binding, main signature, and creation
/// signature if present. This is the check a sender runs before every send;
/// an error for which [`EnvelopeError::is_corrupt`] holds means the envelope
/// must never be sent.
///
/// # Errors
/// [`EnvelopeError::NotFound`], [`EnvelopeError::Io`], the errors of
/// [`EnvelopeTrailer::open`], [`EnvelopeError::PayloadMismatch`] and
/// [`EnvelopeError::Verification`].
pub fn open_envelope(path: &Path, key: &QueueKey) -> Result<VerifiedEnvelope, EnvelopeError> {
    let mut file = File::open(path).map_err(|error| EnvelopeError::io("open envelope", &error))?;
    let file_len = file_len(&file)?;
    let trailer = EnvelopeTrailer::open(file_len, &read_tail(&mut file, file_len)?, key)?;
    let manifest = if trailer.kind() == EnvelopeKind::Closure {
        let manifest = read_prefix(&mut file, trailer.payload_len())?;
        if PayloadDigest::of_bytes(&manifest)?.sha256() != trailer.payload_sha256() {
            return Err(EnvelopeError::PayloadMismatch);
        }
        Some(manifest)
    } else {
        if hash_prefix(&mut file, trailer.payload_len())?.sha256() != trailer.payload_sha256() {
            return Err(EnvelopeError::PayloadMismatch);
        }
        None
    };
    trailer.verify_signatures(manifest.as_deref())?;
    Ok(VerifiedEnvelope {
        path: path.to_path_buf(),
        trailer,
    })
}

// ============================================================================
// Private helpers
// ============================================================================

fn file_len(file: &File) -> Result<u64, EnvelopeError> {
    file.metadata()
        .map(|meta| meta.len())
        .map_err(|error| EnvelopeError::io("measure file", &error))
}

/// The last `min(file_len, MAX_TAIL_BYTES)` bytes of the file.
fn read_tail(file: &mut File, file_len: u64) -> Result<Vec<u8>, EnvelopeError> {
    let max_tail = u64::try_from(MAX_TAIL_BYTES).unwrap_or(u64::MAX);
    let tail_len = file_len.min(max_tail);
    let mut tail = vec![0u8; usize::try_from(tail_len).unwrap_or(MAX_TAIL_BYTES)];
    file.seek(SeekFrom::Start(file_len - tail_len))
        .and_then(|_| file.read_exact(&mut tail))
        .map_err(|error| EnvelopeError::io("read trailer", &error))?;
    Ok(tail)
}

/// Stream-hash the first `len` bytes of the file.
fn hash_prefix(file: &mut File, len: u64) -> Result<PayloadDigest, EnvelopeError> {
    file.seek(SeekFrom::Start(0))
        .map_err(|error| EnvelopeError::io("read payload", &error))?;
    let mut hasher = Sha256::new();
    let mut remaining = len;
    let mut buf = vec![0u8; HASH_BUF_BYTES];
    while remaining > 0 {
        let want = usize::try_from(remaining).map_or(buf.len(), |left| left.min(buf.len()));
        let window = buf
            .get_mut(..want)
            .ok_or(EnvelopeError::Malformed("read window"))?;
        file.read_exact(window)
            .map_err(|error| EnvelopeError::io("read payload", &error))?;
        hasher.update(&*window);
        remaining -= u64::try_from(want).map_err(|_| EnvelopeError::Malformed("read window"))?;
    }
    Ok(PayloadDigest {
        len,
        sha256: hasher.finalize().into(),
    })
}

/// Read the first `len` bytes of the file, a closure manifest. `len` is
/// bounded by the largest possible manifest before any allocation.
fn read_prefix(file: &mut File, len: u64) -> Result<Vec<u8>, EnvelopeError> {
    if len > max_manifest_bytes() {
        return Err(EnvelopeError::Malformed(
            "manifest larger than the sequence space allows",
        ));
    }
    let len = usize::try_from(len).map_err(|_| EnvelopeError::Malformed("manifest too large"))?;
    let mut bytes = vec![0u8; len];
    file.seek(SeekFrom::Start(0))
        .and_then(|_| file.read_exact(&mut bytes))
        .map_err(|error| EnvelopeError::io("read manifest", &error))?;
    Ok(bytes)
}

/// The trailer for the payload already in `file`, checked against it: a
/// closure's manifest is read back and verified as bytes, any other payload by
/// the digest just measured.
fn trailer_for_file(
    file: &mut File,
    fields: EnvelopeFields,
    digest: &PayloadDigest,
) -> Result<EnvelopeTrailer, EnvelopeError> {
    if fields.kind == EnvelopeKind::Closure {
        let manifest = read_prefix(file, digest.len())?;
        if PayloadDigest::of_bytes(&manifest)? != *digest {
            return Err(EnvelopeError::PayloadMismatch);
        }
        return EnvelopeTrailer::for_payload(fields, &manifest);
    }
    let trailer = EnvelopeTrailer::from_parts(fields, digest)?;
    trailer.verify_signatures(None)?;
    Ok(trailer)
}

/// Append `tail` after the first `payload_len` bytes and flush. On failure,
/// truncate back to the payload so a retry starts from the same file.
fn append_tail(file: &mut File, payload_len: u64, tail: &[u8]) -> Result<(), EnvelopeError> {
    let appended = file
        .seek(SeekFrom::Start(payload_len))
        .and_then(|_| file.write_all(tail))
        .and_then(|()| file.sync_all());
    if let Err(error) = appended {
        let _ = file.set_len(payload_len).and_then(|()| file.sync_all());
        return Err(EnvelopeError::io("append trailer", &error));
    }
    Ok(())
}

/// Rename `src` to `dst` (unless they are the same path) and flush the
/// directory entry.
fn move_into_place(src: &Path, dst: &Path) -> Result<(), EnvelopeError> {
    if src != dst {
        std::fs::rename(src, dst).map_err(|error| EnvelopeError::io("rename envelope", &error))?;
    }
    sync_parent_dir(dst).map_err(|error| EnvelopeError::io("sync directory", &error))
}

/// `src` is gone: done already if `dst` holds a readable trailer.
fn already_at_destination(dst: &Path, key: &QueueKey) -> Result<Conversion, EnvelopeError> {
    let trailer = inspect_envelope(dst, key)?;
    sync_parent_dir(dst).map_err(|error| EnvelopeError::io("sync directory", &error))?;
    Ok(Conversion::AlreadyConverted(trailer))
}

#[cfg(test)]
mod tests {
    use super::super::test_support::*;
    use super::*;
    use frappuccino_crypto_core::report::ReportError;

    fn key() -> QueueKey {
        QueueKey::from_bytes(&[0x24u8; 32]).unwrap()
    }

    fn scratch_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("frap_envfile_{}_{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn chunk_fields(payload: &[u8]) -> EnvelopeFields {
        object_fields(EnvelopeKind::Chunk, "000001.strm", payload, true)
    }

    #[test]
    fn written_envelopes_open_inspect_and_stream() {
        let dir = scratch_dir("write");
        let path = dir.join("s_c000001.fqe");
        let payload: Vec<u8> = (0u8..=255).cycle().take(300_000).collect();
        let written = write_envelope(&path, &payload, chunk_fields(&payload), &key()).unwrap();
        assert!(!dir.join("s_c000001.fqe.part").exists());

        let inspected = inspect_envelope(&path, &key()).unwrap();
        assert_eq!(inspected, written);

        let verified = open_envelope(&path, &key()).unwrap();
        assert_eq!(verified.trailer(), &written);
        assert_eq!(verified.path(), path.as_path());
        let range = verified.payload_range();
        assert_eq!((range.offset(), range.len()), (0, payload.len() as u64));
        let mut streamed = Vec::new();
        verified
            .payload_reader()
            .unwrap()
            .read_to_end(&mut streamed)
            .unwrap();
        assert_eq!(streamed, payload);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn closures_are_verified_against_their_manifest() {
        let dir = scratch_dir("closure");
        let (manifest, fields) = closure_fields();
        let path = dir.join("s_z.fqe");
        write_envelope(&path, &manifest, fields, &key()).unwrap();
        let verified = open_envelope(&path, &key()).unwrap();
        assert_eq!(verified.trailer().seq_limit(), 5);

        let (empty, legacy) = legacy_closure_fields();
        let legacy_path = dir.join("L3_z.fqe");
        write_envelope(&legacy_path, &empty, legacy, &key()).unwrap();
        assert!(inspect_envelope(&legacy_path, &key())
            .unwrap()
            .needs_drain());
        open_envelope(&legacy_path, &key()).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_payload_altered_after_writing_is_caught() {
        let dir = scratch_dir("altered");
        let path = dir.join("e.fqe");
        let payload = vec![1u8; 5000];
        write_envelope(&path, &payload, chunk_fields(&payload), &key()).unwrap();
        let mut bytes = std::fs::read(&path).unwrap();
        bytes[100] ^= 0xFF;
        std::fs::write(&path, &bytes).unwrap();
        // The trailer still opens: only the full check sees the change.
        inspect_envelope(&path, &key()).unwrap();
        let error = open_envelope(&path, &key()).unwrap_err();
        assert_eq!(error, EnvelopeError::PayloadMismatch);
        assert!(error.is_corrupt());

        // A closure manifest altered in place.
        let (manifest, fields) = closure_fields();
        let closure = dir.join("z.fqe");
        write_envelope(&closure, &manifest, fields, &key()).unwrap();
        let mut bytes = std::fs::read(&closure).unwrap();
        bytes[20] ^= 1;
        std::fs::write(&closure, &bytes).unwrap();
        assert_eq!(
            open_envelope(&closure, &key()).unwrap_err(),
            EnvelopeError::PayloadMismatch
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_stream_of_a_payload_changed_after_verification_fails() {
        let dir = scratch_dir("toctou");
        let path = dir.join("e.fqe");
        let payload = vec![3u8; 200_000];
        write_envelope(&path, &payload, chunk_fields(&payload), &key()).unwrap();
        let verified = open_envelope(&path, &key()).unwrap();
        let mut bytes = std::fs::read(&path).unwrap();
        bytes[199_999] ^= 1;
        std::fs::write(&path, &bytes).unwrap();
        let mut reader = verified.payload_reader().unwrap();
        let mut sink = Vec::new();
        assert!(reader.read_to_end(&mut sink).is_err());
        assert_eq!(reader.failure(), Some(RangeFailure::Mismatch));
        assert!(sink.len() < payload.len());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_and_foreign_files_are_reported() {
        let dir = scratch_dir("missing");
        assert_eq!(
            inspect_envelope(&dir.join("absent.fqe"), &key()).unwrap_err(),
            EnvelopeError::NotFound
        );
        assert_eq!(
            open_envelope(&dir.join("absent.fqe"), &key()).unwrap_err(),
            EnvelopeError::NotFound
        );
        let plain = dir.join("plain.strm");
        std::fs::write(&plain, b"not an envelope at all").unwrap();
        assert_eq!(
            inspect_envelope(&plain, &key()).unwrap_err(),
            EnvelopeError::NoTrailer
        );
        let payload = b"x";
        let sealed = dir.join("other_key.fqe");
        write_envelope(&sealed, payload, chunk_fields(payload), &key()).unwrap();
        let other = QueueKey::from_bytes(&[0x25u8; 32]).unwrap();
        assert_eq!(
            open_envelope(&sealed, &other).unwrap_err(),
            EnvelopeError::Undecryptable
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_refuses_bad_signatures_and_leaves_nothing() {
        let dir = scratch_dir("refuse");
        let path = dir.join("e.fqe");
        let error = write_envelope(&path, b"other", chunk_fields(b"signed"), &key()).unwrap_err();
        assert!(matches!(
            error,
            EnvelopeError::Verification(ReportError::InvalidSignature)
        ));
        assert!(!path.exists());
        assert!(!dir.join("e.fqe.part").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn conversion_appends_renames_and_is_idempotent() {
        let dir = scratch_dir("convert");
        let src = dir.join("legacy.strm");
        let dst = dir.join("L3_sid_000001.fqe");
        let payload: Vec<u8> = (0u8..200).collect();
        std::fs::write(&src, &payload).unwrap();

        let mut seen = None;
        let outcome = convert_to_envelope(&src, &dst, &key(), |digest| {
            seen = Some(*digest);
            Ok(chunk_fields(&payload))
        })
        .unwrap();
        assert!(matches!(outcome, Conversion::Converted(_)));
        let digest = seen.unwrap();
        assert_eq!(digest.len(), 200);
        assert!(!digest.is_empty());
        assert_eq!(digest.sha256(), &sha256(&payload));
        assert!(!src.exists());
        let verified = open_envelope(&dst, &key()).unwrap();
        assert_eq!(verified.trailer().payload_len(), 200);
        let on_disk = std::fs::read(&dst).unwrap();
        assert_eq!(&on_disk[..200], payload.as_slice());

        // Running again after the rename: src is gone, dst already done.
        let again =
            convert_to_envelope(&src, &dst, &key(), |_| panic!("must not re-sign")).unwrap();
        assert!(matches!(again, Conversion::AlreadyConverted(_)));

        // A crash between the append and the rename: src carries the trailer.
        std::fs::rename(&dst, &src).unwrap();
        let resumed =
            convert_to_envelope(&src, &dst, &key(), |_| panic!("must not re-sign")).unwrap();
        assert!(matches!(resumed, Conversion::AlreadyConverted(_)));
        assert_eq!(std::fs::read(&dst).unwrap(), on_disk, "no second trailer");
        assert!(!src.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn conversion_failures_leave_the_source_as_it_was() {
        let dir = scratch_dir("convert_fail");
        let src = dir.join("legacy.strm");
        let dst = dir.join("out.fqe");
        let payload = b"legacy chunk".to_vec();
        std::fs::write(&src, &payload).unwrap();

        // The signer fails.
        let error = convert_to_envelope(&src, &dst, &key(), |_| {
            Err(ReportError::InvalidSignature.into())
        })
        .unwrap_err();
        assert!(matches!(error, EnvelopeError::Signing(_)));
        assert!(!error.is_corrupt());
        assert_eq!(std::fs::read(&src).unwrap(), payload);

        // The signer signs other bytes.
        let error =
            convert_to_envelope(&src, &dst, &key(), |_| Ok(chunk_fields(b"else"))).unwrap_err();
        assert!(matches!(error, EnvelopeError::Verification(_)));
        assert_eq!(std::fs::read(&src).unwrap(), payload);
        assert!(!dst.exists());

        // Neither file exists.
        assert_eq!(
            convert_to_envelope(&dir.join("none"), &dir.join("none.fqe"), &key(), |_| {
                panic!("nothing to sign")
            })
            .unwrap_err(),
            EnvelopeError::NotFound
        );

        // A source that ends with the magic but does not open is refused.
        let mut fake = payload.clone();
        fake.extend_from_slice(&[0u8; 300]);
        fake.extend_from_slice(&300u32.to_be_bytes());
        fake.extend_from_slice(b"FQE1");
        std::fs::write(&src, &fake).unwrap();
        let error =
            convert_to_envelope(&src, &dst, &key(), |_| panic!("must not sign")).unwrap_err();
        assert_eq!(error, EnvelopeError::Undecryptable);
        assert_eq!(std::fs::read(&src).unwrap(), fake);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A source as a power cut during the append leaves it: the payload,
    /// then `torn` (part of a trailer, or zeros), and the marker the
    /// conversion wrote before appending.
    fn interrupted_conversion(dir: &Path, payload: &[u8], torn: &[u8]) -> (PathBuf, PathBuf) {
        let src = dir.join("legacy.strm");
        let dst = dir.join("L3_sid_000001.fqe");
        let mut bytes = payload.to_vec();
        bytes.extend_from_slice(torn);
        std::fs::write(&src, &bytes).unwrap();
        let marker = conversion_marker_path(&dst).unwrap();
        write_conversion_marker(&marker, &PayloadDigest::of_bytes(payload).unwrap()).unwrap();
        (src, dst)
    }

    /// Sign whatever digest the conversion measured, as the legacy signer
    /// of the migration does.
    fn sign_measured(digest: &PayloadDigest) -> EnvelopeFields {
        let ring = keyring();
        let name = "000001.strm";
        let write_sig = ring
            .sign_write(3, name.as_bytes(), digest.sha256())
            .unwrap();
        let create = ring.sign_create(3).unwrap();
        EnvelopeFields::object(
            EnvelopeKind::Chunk,
            ring.report_pk(3).unwrap(),
            name,
            write_sig,
            Some(create),
        )
        .unwrap()
    }

    fn sealed_tail(payload: &[u8]) -> Vec<u8> {
        EnvelopeTrailer::for_payload(chunk_fields(payload), payload)
            .unwrap()
            .seal(&key())
            .unwrap()
    }

    #[test]
    fn an_interrupted_append_is_cut_back_and_never_signed_as_payload() {
        let payload: Vec<u8> = (0u8..200).collect();
        let tail = sealed_tail(&payload);
        let mut ends_with_magic = tail.clone();
        // All of the trailer reached the disk but a page in its middle.
        ends_with_magic[10..60].fill(0);
        for (case, torn) in [
            ("fragment", tail[..100].to_vec()),
            ("zeros", vec![0u8; 150]),
            ("magic", ends_with_magic),
        ] {
            let dir = scratch_dir(&format!("convert_torn_{case}"));
            let (src, dst) = interrupted_conversion(&dir, &payload, &torn);
            let mut seen = None;
            let outcome = convert_to_envelope(&src, &dst, &key(), |digest| {
                seen = Some(*digest);
                Ok(sign_measured(digest))
            })
            .unwrap();
            assert!(matches!(outcome, Conversion::Converted(_)), "{case}");
            assert_eq!(
                seen.unwrap().len(),
                200,
                "{case}: only the payload is signed"
            );
            let verified = open_envelope(&dst, &key()).unwrap();
            assert_eq!(verified.trailer().payload_len(), 200, "{case}");
            assert_eq!(&std::fs::read(&dst).unwrap()[..200], payload.as_slice());
            assert!(!conversion_marker_path(&dst).unwrap().exists(), "{case}");
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    #[test]
    fn the_marker_goes_once_the_conversion_is_done() {
        let dir = scratch_dir("convert_marker");
        let payload = b"legacy chunk".to_vec();
        // A crash after the marker was written, before the append started.
        let (src, dst) = interrupted_conversion(&dir, &payload, &[]);
        convert_to_envelope(&src, &dst, &key(), |_| Ok(chunk_fields(&payload))).unwrap();
        let marker = conversion_marker_path(&dst).unwrap();
        assert!(!marker.exists());
        // A crash after the rename, before the marker went.
        let recorded = PayloadDigest::of_bytes(&payload).unwrap();
        write_conversion_marker(&marker, &recorded).unwrap();
        let again =
            convert_to_envelope(&src, &dst, &key(), |_| panic!("must not re-sign")).unwrap();
        assert!(matches!(again, Conversion::AlreadyConverted(_)));
        assert!(!marker.exists());
        // Before the rename: the source carries the whole trailer.
        std::fs::rename(&dst, &src).unwrap();
        write_conversion_marker(&marker, &recorded).unwrap();
        let resumed =
            convert_to_envelope(&src, &dst, &key(), |_| panic!("must not re-sign")).unwrap();
        assert!(matches!(resumed, Conversion::AlreadyConverted(_)));
        assert!(!marker.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_source_shorter_than_its_marker_is_refused_untouched() {
        let dir = scratch_dir("convert_short");
        let payload = vec![7u8; 64];
        let (src, dst) = interrupted_conversion(&dir, &payload, &[]);
        let marker = conversion_marker_path(&dst).unwrap();
        let longer = PayloadDigest {
            len: 65,
            sha256: [0; 32],
        };
        write_conversion_marker(&marker, &longer).unwrap();
        let error =
            convert_to_envelope(&src, &dst, &key(), |_| panic!("must not sign")).unwrap_err();
        assert!(matches!(error, EnvelopeError::Malformed(_)));
        assert_eq!(std::fs::read(&src).unwrap(), payload);
        // A marker of another payload, shorter than this source, cuts nothing.
        let other = PayloadDigest::of_bytes(&[8u8; 10]).unwrap();
        write_conversion_marker(&marker, &other).unwrap();
        let error =
            convert_to_envelope(&src, &dst, &key(), |_| panic!("must not sign")).unwrap_err();
        assert!(matches!(error, EnvelopeError::Io { .. }));
        assert_eq!(std::fs::read(&src).unwrap(), payload);
        // A marker that is not one length stops the conversion, nothing more.
        std::fs::write(&marker, b"bad").unwrap();
        let error =
            convert_to_envelope(&src, &dst, &key(), |_| panic!("must not sign")).unwrap_err();
        assert!(matches!(error, EnvelopeError::Io { .. }));
        assert!(!error.is_corrupt());
        assert_eq!(std::fs::read(&src).unwrap(), payload);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_closure_can_be_converted_in_place() {
        let dir = scratch_dir("convert_closure");
        let (manifest, fields) = closure_fields();
        let path = dir.join("z.fqe");
        std::fs::write(&path, &manifest).unwrap();
        let outcome = convert_to_envelope(&path, &path, &key(), |_| Ok(fields)).unwrap();
        assert!(matches!(outcome, Conversion::Converted(_)));
        open_envelope(&path, &key()).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
