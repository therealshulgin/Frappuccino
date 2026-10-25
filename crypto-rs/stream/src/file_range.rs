//! A byte range of a file on disk, read once, optionally checked against an
//! expected SHA-256.
//!
//! Both transports stream request bodies from disk through a
//! [`FileRangeReader`] rather than loading them in RAM, and a queued envelope
//! is sent as the payload range of its file. When an expected hash is given,
//! the reader hashes what it reads and checks the digest **before handing out
//! the bytes that complete the range**: on a mismatch the final read fails, so
//! a body whose bytes changed after they were verified never leaves complete.
//! A sized HTTP body that stops short is refused by the receiver, which is what
//! makes this check effective on the wire and not only in a log.
//!
//! Every failure is recorded as a [`RangeFailure`], readable after the reader
//! was moved into an HTTP client, so a transport can tell a local file problem
//! (no network fallback can fix it) from a network one.

use sha2::{Digest, Sha256};
use std::fmt;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

/// SHA-256 digest width.
const SHA256_BYTES: usize = 32;

/// Why a file range could not be read in full.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RangeFailure {
    /// The file does not exist.
    Missing,
    /// The file exists but could not be opened, measured or positioned.
    Open,
    /// The file ended before the end of the range.
    Short,
    /// A read failed part-way through the range.
    Read,
    /// The bytes of the range do not hash to the expected SHA-256.
    Mismatch,
}

impl RangeFailure {
    /// Every failure, in a fixed order (used to recognise their tags).
    const ALL: [Self; 5] = [
        Self::Missing,
        Self::Open,
        Self::Short,
        Self::Read,
        Self::Mismatch,
    ];

    /// The machine tag a transport reports for this failure in
    /// [`crate::upload::PutResult::error_detail`]. `"file_missing"` is the
    /// only one that means the file is absent.
    #[must_use]
    pub fn tag(self) -> &'static str {
        match self {
            Self::Missing => "file_missing",
            Self::Open => "file_open",
            Self::Short => "body_short",
            Self::Read => "body_read",
            Self::Mismatch => "body_mismatch",
        }
    }

    /// True when `tag` is the tag of a [`RangeFailure`].
    #[must_use]
    pub fn is_tag(tag: &str) -> bool {
        Self::ALL.iter().any(|failure| failure.tag() == tag)
    }
}

/// A byte range `[offset, offset + len)` of the file at `path`, with an
/// optional expected SHA-256 of exactly those bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileRange {
    path: PathBuf,
    offset: u64,
    len: u64,
    expected_sha256: Option<[u8; SHA256_BYTES]>,
}

impl FileRange {
    /// Describe a range. Nothing is opened until [`Self::open`].
    #[must_use]
    pub fn new(
        path: impl Into<PathBuf>,
        offset: u64,
        len: u64,
        expected_sha256: Option<[u8; SHA256_BYTES]>,
    ) -> Self {
        Self {
            path: path.into(),
            offset,
            len,
            expected_sha256,
        }
    }

    /// The whole of the file at `path`, as it is now, with no expected hash.
    /// Returns `None` when the file is missing, unreadable or empty. Test
    /// helper: production bodies are envelope payload ranges.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn whole_non_empty_file(path: impl Into<PathBuf>) -> Option<Self> {
        let path = path.into();
        let len = std::fs::metadata(&path).ok()?.len();
        if len == 0 {
            return None;
        }
        Some(Self::new(path, 0, len, None))
    }

    /// Path of the file.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// First byte of the range.
    #[must_use]
    pub fn offset(&self) -> u64 {
        self.offset
    }

    /// Length of the range in bytes.
    #[must_use]
    pub fn len(&self) -> u64 {
        self.len
    }

    /// True for an empty range.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The SHA-256 the range must hash to, if one was given.
    #[must_use]
    pub fn expected_sha256(&self) -> Option<&[u8; SHA256_BYTES]> {
        self.expected_sha256.as_ref()
    }

    /// Open the file, check that it is long enough for the range, and
    /// position a reader at its start.
    ///
    /// # Errors
    /// [`RangeFailure::Missing`] if the file does not exist,
    /// [`RangeFailure::Open`] if it cannot be opened, measured or positioned,
    /// [`RangeFailure::Short`] if it ends before the range does, and
    /// [`RangeFailure::Mismatch`] for an empty range whose expected hash is
    /// not the hash of nothing.
    pub fn open(&self) -> Result<FileRangeReader, RangeFailure> {
        let mut file = File::open(&self.path).map_err(|error| match error.kind() {
            io::ErrorKind::NotFound => RangeFailure::Missing,
            _ => RangeFailure::Open,
        })?;
        let file_len = file.metadata().map_err(|_| RangeFailure::Open)?.len();
        let end = self
            .offset
            .checked_add(self.len)
            .ok_or(RangeFailure::Short)?;
        if file_len < end {
            return Err(RangeFailure::Short);
        }
        file.seek(SeekFrom::Start(self.offset))
            .map_err(|_| RangeFailure::Open)?;
        if self.len == 0 {
            // No read will ever complete the range, so check it here.
            if let Some(expected) = self.expected_sha256 {
                if sha256_of(&[]) != expected {
                    return Err(RangeFailure::Mismatch);
                }
            }
        }
        Ok(FileRangeReader {
            file,
            remaining: self.len,
            hasher: Sha256::new(),
            expected_sha256: self.expected_sha256,
            failure: Arc::new(OnceLock::new()),
        })
    }
}

/// Reader over an opened [`FileRange`]. See the module documentation for the
/// hash check.
pub struct FileRangeReader {
    file: File,
    remaining: u64,
    hasher: Sha256,
    expected_sha256: Option<[u8; SHA256_BYTES]>,
    failure: Arc<OnceLock<RangeFailure>>,
}

impl fmt::Debug for FileRangeReader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FileRangeReader")
            .field("remaining", &self.remaining)
            .field("checks_hash", &self.expected_sha256.is_some())
            .field("failure", &self.failure.get())
            .finish_non_exhaustive()
    }
}

// ---- public API -------------------------------------------------------------

impl FileRangeReader {
    /// Bytes of the range not read yet.
    #[must_use]
    pub fn remaining(&self) -> u64 {
        self.remaining
    }

    /// The failure that stopped this reader, if any.
    #[must_use]
    pub fn failure(&self) -> Option<RangeFailure> {
        self.failure.get().copied()
    }

    /// A handle on the failure slot that stays readable after the reader was
    /// moved, for instance into an HTTP request body.
    #[must_use]
    pub fn failure_slot(&self) -> Arc<OnceLock<RangeFailure>> {
        // Cloning the Arc shares the slot; that is the point of the handle.
        Arc::clone(&self.failure)
    }
}

// ---- private helpers --------------------------------------------------------

impl FileRangeReader {
    /// Record `failure` (the first one wins) and return the matching error.
    fn fail(&self, failure: RangeFailure) -> io::Error {
        let _ = self.failure.set(failure);
        let kind = match failure {
            RangeFailure::Missing => io::ErrorKind::NotFound,
            RangeFailure::Short => io::ErrorKind::UnexpectedEof,
            RangeFailure::Mismatch => io::ErrorKind::InvalidData,
            RangeFailure::Open | RangeFailure::Read => io::ErrorKind::Other,
        };
        io::Error::new(kind, failure.tag())
    }

    /// Account for `read` bytes just read into `chunk`, and check the hash
    /// when they complete the range.
    fn consume(&mut self, chunk: &[u8]) -> io::Result<()> {
        self.hasher.update(chunk);
        let read = u64::try_from(chunk.len()).map_err(|_| self.fail(RangeFailure::Read))?;
        self.remaining = self
            .remaining
            .checked_sub(read)
            .ok_or_else(|| self.fail(RangeFailure::Read))?;
        if self.remaining == 0 {
            if let Some(expected) = self.expected_sha256 {
                let digest: [u8; SHA256_BYTES] = self.hasher.finalize_reset().into();
                if digest != expected {
                    return Err(self.fail(RangeFailure::Mismatch));
                }
            }
        }
        Ok(())
    }
}

// ---- trait implementations --------------------------------------------------

impl Read for FileRangeReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if let Some(failure) = self.failure() {
            return Err(self.fail(failure));
        }
        if self.remaining == 0 || buf.is_empty() {
            return Ok(0);
        }
        let want = usize::try_from(self.remaining).map_or(buf.len(), |left| left.min(buf.len()));
        let window = buf
            .get_mut(..want)
            .ok_or_else(|| self.fail(RangeFailure::Read))?;
        let read = match self.file.read(window) {
            Ok(0) => return Err(self.fail(RangeFailure::Short)),
            Ok(read) => read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => return Err(error),
            Err(_) => return Err(self.fail(RangeFailure::Read)),
        };
        let chunk = window
            .get(..read)
            .ok_or_else(|| self.fail(RangeFailure::Read))?;
        self.consume(chunk)?;
        Ok(read)
    }
}

/// SHA-256 of `bytes`.
pub(crate) fn sha256_of(bytes: &[u8]) -> [u8; SHA256_BYTES] {
    Sha256::digest(bytes).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    /// A fresh scratch file holding `bytes`, removed on drop.
    struct Scratch(PathBuf);

    impl Scratch {
        fn with(name: &str, bytes: &[u8]) -> Self {
            let path =
                std::env::temp_dir().join(format!("frap_range_{}_{name}", std::process::id()));
            let mut file = File::create(&path).unwrap();
            file.write_all(bytes).unwrap();
            Self(path)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    fn read_all(range: &FileRange) -> Result<Vec<u8>, (io::Error, Option<RangeFailure>)> {
        let mut reader = range
            .open()
            .map_err(|f| (io::Error::other("open"), Some(f)))?;
        let mut out = Vec::new();
        match reader.read_to_end(&mut out) {
            Ok(_) => Ok(out),
            Err(error) => Err((error, reader.failure())),
        }
    }

    #[test]
    fn reads_exactly_the_range_and_checks_its_hash() {
        let data: Vec<u8> = (0u8..=255).cycle().take(200_000).collect();
        let file = Scratch::with("ok", &data);
        let slice = &data[1000..150_000];
        let range = FileRange::new(&file.0, 1000, 149_000, Some(sha256_of(slice)));
        assert_eq!(read_all(&range).unwrap(), slice);

        let unchecked = FileRange::new(&file.0, 0, 10, None);
        assert_eq!(read_all(&unchecked).unwrap(), &data[..10]);
    }

    #[test]
    fn a_mismatch_withholds_the_bytes_that_complete_the_range() {
        let data = vec![0x5Au8; 100_000];
        let file = Scratch::with("mismatch", &data);
        let range = FileRange::new(&file.0, 0, 100_000, Some([0u8; 32]));
        let mut reader = range.open().unwrap();
        let mut delivered = 0usize;
        let mut buf = [0u8; 4096];
        let error = loop {
            match reader.read(&mut buf) {
                Ok(0) => panic!("a mismatching range must not end cleanly"),
                Ok(n) => delivered += n,
                Err(error) => break error,
            }
        };
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(reader.failure(), Some(RangeFailure::Mismatch));
        assert!(delivered < data.len(), "the final bytes were withheld");
        // A failed reader keeps failing.
        assert!(reader.read(&mut buf).is_err());
    }

    #[test]
    fn missing_short_and_empty_ranges_are_distinguished() {
        let missing = FileRange::new("/no/such/frap/file", 0, 1, None);
        assert_eq!(missing.open().unwrap_err(), RangeFailure::Missing);

        let file = Scratch::with("short", b"hello");
        let past_end = FileRange::new(&file.0, 3, 5, None);
        assert_eq!(past_end.open().unwrap_err(), RangeFailure::Short);
        let overflow = FileRange::new(&file.0, u64::MAX, 2, None);
        assert_eq!(overflow.open().unwrap_err(), RangeFailure::Short);

        let empty_ok = FileRange::new(&file.0, 5, 0, Some(sha256_of(&[])));
        assert_eq!(read_all(&empty_ok).unwrap(), b"");
        let empty_bad = FileRange::new(&file.0, 5, 0, Some([1u8; 32]));
        assert_eq!(empty_bad.open().unwrap_err(), RangeFailure::Mismatch);
    }

    #[test]
    fn a_file_truncated_after_open_reports_short() {
        let file = Scratch::with("truncated", &[7u8; 1000]);
        let range = FileRange::new(&file.0, 0, 1000, None);
        let mut reader = range.open().unwrap();
        std::fs::OpenOptions::new()
            .write(true)
            .open(&file.0)
            .unwrap()
            .set_len(10)
            .unwrap();
        let mut out = Vec::new();
        let error = reader.read_to_end(&mut out).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
        assert_eq!(reader.failure(), Some(RangeFailure::Short));
    }

    #[test]
    fn whole_file_treats_missing_and_empty_alike() {
        assert!(FileRange::whole_non_empty_file("/no/such/frap/file").is_none());
        let empty = Scratch::with("empty", b"");
        assert!(FileRange::whole_non_empty_file(&empty.0).is_none());
        let full = Scratch::with("full", b"abc");
        let range = FileRange::whole_non_empty_file(&full.0).unwrap();
        assert_eq!((range.offset(), range.len()), (0, 3));
    }

    #[test]
    fn tags_are_recognised() {
        for failure in RangeFailure::ALL {
            assert!(RangeFailure::is_tag(failure.tag()));
        }
        assert!(!RangeFailure::is_tag("network"));
        assert_eq!(RangeFailure::Missing.tag(), "file_missing");
    }
}
