//! The closing manifest of a report and the names of chained report objects.
//!
//! Wire format (exact bytes, hashed and signed by 0x09):
//!
//! ```text
//! "FQM1" ‖ u32_be(count) ‖ count × ( u32_be(seq) ‖ sha256(blob_seq)(32) )
//! ```
//!
//! with `seq` strictly increasing. `blob_seq` is the exact byte string the
//! relay stores under the object name of `seq`. `seq_limit` is the last `seq`
//! plus one, or 0 for an empty manifest. The relay only checks the magic and
//! the length; the rescue device parses it with [`Manifest::parse`], which
//! refuses anything that is not exactly this shape.

use super::{sha256, ReportError, HASH_BYTES};

/// The manifest's leading magic.
pub const MANIFEST_MAGIC: [u8; 4] = *b"FQM1";

/// Largest sequence number of a chained report object. Names have six decimal
/// digits (`000000.strm` to `999999.strm`).
pub const MAX_SEQ: u32 = 999_999;

/// Largest `seq_limit` a closure can carry (`MAX_SEQ + 1`).
pub const MAX_SEQ_LIMIT: u32 = MAX_SEQ + 1;

/// `magic(4) ‖ count(4)`.
const HEADER_BYTES: usize = 8;
/// `seq(4) ‖ sha256(32)`.
const ENTRY_BYTES: usize = 4 + HASH_BYTES;
/// Suffix of every chained object name.
const OBJECT_SUFFIX: &str = ".strm";
/// Number of decimal digits in a chained object name.
const SEQ_DIGITS: usize = 6;

/// One manifest line: an object's sequence number and the SHA-256 of the
/// exact bytes stored for it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ManifestEntry {
    /// Sequence number (`0` is the metadata object, `>= 1` are media chunks).
    pub seq: u32,
    /// SHA-256 of the stored (encrypted) object.
    pub blob_sha256: [u8; HASH_BYTES],
}

/// A validated closing manifest: entries in strictly increasing `seq`, each
/// `seq <= MAX_SEQ`. Every constructor enforces this, so a `Manifest` value is
/// always one [`Self::parse`] would accept.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Manifest {
    entries: Vec<ManifestEntry>,
}

impl Manifest {
    /// The empty manifest (`"FQM1" ‖ 0u32`), carried by legacy closures only.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Build a manifest from entries already in strictly increasing `seq`.
    ///
    /// # Errors
    /// [`ReportError::InvalidManifest`] if a `seq` exceeds [`MAX_SEQ`] or the
    /// order is not strictly increasing.
    pub fn from_entries(entries: Vec<ManifestEntry>) -> Result<Self, ReportError> {
        let mut previous: Option<u32> = None;
        for entry in &entries {
            if entry.seq > MAX_SEQ {
                return Err(ReportError::InvalidManifest("sequence number out of range"));
            }
            if previous.is_some_and(|p| entry.seq <= p) {
                return Err(ReportError::InvalidManifest(
                    "sequence numbers are not strictly increasing",
                ));
            }
            previous = Some(entry.seq);
        }
        Ok(Self { entries })
    }

    /// Strict parser: magic, a count no larger than the sequence space, a
    /// length of exactly `8 + 36 × count` bytes, then the [`Self::from_entries`]
    /// rules. Never allocates more than the input justifies.
    ///
    /// # Errors
    /// [`ReportError::InvalidManifest`] naming the first rule broken.
    pub fn parse(bytes: &[u8]) -> Result<Self, ReportError> {
        let Some((magic, rest)) = bytes.split_first_chunk::<4>() else {
            return Err(ReportError::InvalidManifest("truncated header"));
        };
        if *magic != MANIFEST_MAGIC {
            return Err(ReportError::InvalidManifest("bad magic"));
        }
        let Some((count_be, body)) = rest.split_first_chunk::<4>() else {
            return Err(ReportError::InvalidManifest("truncated header"));
        };
        let count = u32::from_be_bytes(*count_be);
        if count > MAX_SEQ_LIMIT {
            return Err(ReportError::InvalidManifest(
                "count exceeds the sequence space",
            ));
        }
        let count = usize::try_from(count)
            .map_err(|_| ReportError::InvalidManifest("count exceeds the sequence space"))?;
        let expected = count
            .checked_mul(ENTRY_BYTES)
            .ok_or(ReportError::InvalidManifest(
                "count exceeds the sequence space",
            ))?;
        if body.len() != expected {
            return Err(ReportError::InvalidManifest("length does not match count"));
        }
        let mut entries = Vec::with_capacity(count);
        for line in body.chunks_exact(ENTRY_BYTES) {
            let Some((seq_be, hash)) = line.split_first_chunk::<4>() else {
                return Err(ReportError::InvalidManifest("truncated entry"));
            };
            let blob_sha256: [u8; HASH_BYTES] = hash
                .try_into()
                .map_err(|_| ReportError::InvalidManifest("truncated entry"))?;
            entries.push(ManifestEntry {
                seq: u32::from_be_bytes(*seq_be),
                blob_sha256,
            });
        }
        Self::from_entries(entries)
    }

    /// The exact wire bytes.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_BYTES + self.entries.len() * ENTRY_BYTES);
        out.extend_from_slice(&MANIFEST_MAGIC);
        out.extend_from_slice(&self.count().to_be_bytes());
        for entry in &self.entries {
            out.extend_from_slice(&entry.seq.to_be_bytes());
            out.extend_from_slice(&entry.blob_sha256);
        }
        out
    }

    /// SHA-256 of [`Self::to_bytes`], the value 0x09 signs.
    #[must_use]
    pub fn sha256(&self) -> [u8; HASH_BYTES] {
        sha256(&self.to_bytes())
    }

    /// `seq_limit`: the last `seq` plus one, or 0 for the empty manifest.
    #[must_use]
    pub fn seq_limit(&self) -> u32 {
        // Every seq is <= MAX_SEQ, so the addition cannot overflow.
        self.entries.last().map_or(0, |last| last.seq + 1)
    }

    /// The entries, in strictly increasing `seq`.
    #[must_use]
    pub fn entries(&self) -> &[ManifestEntry] {
        &self.entries
    }

    /// Number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True for the empty manifest.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The expected SHA-256 of object `seq`, if the manifest lists it.
    #[must_use]
    pub fn blob_sha256(&self, seq: u32) -> Option<&[u8; HASH_BYTES]> {
        self.entries
            .binary_search_by_key(&seq, |entry| entry.seq)
            .ok()
            .and_then(|position| self.entries.get(position))
            .map(|entry| &entry.blob_sha256)
    }

    /// The entry count as written on the wire. Strictly increasing sequence
    /// numbers bounded by `MAX_SEQ` mean at most `MAX_SEQ_LIMIT` entries, which
    /// fits a `u32`; the fallback is unreachable.
    fn count(&self) -> u32 {
        u32::try_from(self.entries.len()).unwrap_or(u32::MAX)
    }
}

/// The object name of sequence number `seq` in a chained report:
/// `format!("{seq:06}.strm")`.
///
/// # Errors
/// [`ReportError::SeqOutOfRange`] if `seq > MAX_SEQ`.
pub fn chain_object_name(seq: u32) -> Result<String, ReportError> {
    if seq > MAX_SEQ {
        return Err(ReportError::SeqOutOfRange(seq));
    }
    Ok(format!("{seq:06}{OBJECT_SUFFIX}"))
}

/// The sequence number of a chained object name, if `name` is exactly six
/// ASCII digits followed by `.strm` (the relay's `[0-9]{6}\.strm`). Anything
/// else, including legacy chunk names, yields `None`.
#[must_use]
pub fn parse_chain_object_name(name: &str) -> Option<u32> {
    let digits = name.strip_suffix(OBJECT_SUFFIX)?;
    if digits.len() != SEQ_DIGITS || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn entry(seq: u32, fill: u8) -> ManifestEntry {
        ManifestEntry {
            seq,
            blob_sha256: [fill; HASH_BYTES],
        }
    }

    #[test]
    fn empty_manifest_is_magic_and_zero_count() {
        let empty = Manifest::empty();
        assert_eq!(empty.to_bytes(), b"FQM1\x00\x00\x00\x00");
        assert_eq!(empty.seq_limit(), 0);
        assert!(empty.is_empty());
        assert_eq!(Manifest::parse(b"FQM1\x00\x00\x00\x00").unwrap(), empty);
    }

    #[test]
    fn layout_is_exact_and_round_trips() {
        let manifest =
            Manifest::from_entries(vec![entry(0, 0xAA), entry(1, 0xBB), entry(7, 0xCC)]).unwrap();
        let bytes = manifest.to_bytes();
        assert_eq!(bytes.len(), 8 + 3 * 36);
        assert_eq!(&bytes[..4], b"FQM1");
        assert_eq!(&bytes[4..8], &[0, 0, 0, 3]);
        assert_eq!(&bytes[8..12], &[0, 0, 0, 0]);
        assert_eq!(&bytes[12..44], &[0xAA; 32]);
        assert_eq!(&bytes[80..84], &[0, 0, 0, 7]);
        assert_eq!(manifest.seq_limit(), 8);
        assert_eq!(Manifest::parse(&bytes).unwrap(), manifest);
        assert_eq!(manifest.blob_sha256(1), Some(&[0xBB; 32]));
        assert_eq!(manifest.blob_sha256(2), None);
        assert_eq!(manifest.sha256(), sha256(&bytes));
    }

    #[test]
    fn parser_rejects_every_malformed_shape() {
        let good = Manifest::from_entries(vec![entry(0, 1), entry(2, 2)])
            .unwrap()
            .to_bytes();
        let cases: Vec<(Vec<u8>, &str)> = vec![
            (Vec::new(), "truncated header"),
            (b"FQM".to_vec(), "truncated header"),
            (b"FQM1\x00\x00\x00".to_vec(), "truncated header"),
            (b"FQM2\x00\x00\x00\x00".to_vec(), "bad magic"),
            (b"fqm1\x00\x00\x00\x00".to_vec(), "bad magic"),
            (
                good[..good.len() - 1].to_vec(),
                "length does not match count",
            ),
            (
                [good.as_slice(), &[0]].concat(),
                "length does not match count",
            ),
            (
                b"FQM1\x00\x00\x00\x01".to_vec(),
                "length does not match count",
            ),
            (
                b"FQM1\xff\xff\xff\xff".to_vec(),
                "count exceeds the sequence space",
            ),
            (
                b"FQM1\x00\x0f\x42\x41".to_vec(),
                "count exceeds the sequence space",
            ),
        ];
        for (bytes, reason) in cases {
            assert_eq!(
                Manifest::parse(&bytes).unwrap_err(),
                ReportError::InvalidManifest(reason),
                "input {bytes:02x?}"
            );
        }
    }

    #[test]
    fn order_and_range_are_enforced() {
        let not_increasing = [
            vec![entry(1, 0), entry(1, 0)],
            vec![entry(2, 0), entry(1, 0)],
        ];
        for entries in not_increasing {
            assert_eq!(
                Manifest::from_entries(entries.clone()).unwrap_err(),
                ReportError::InvalidManifest("sequence numbers are not strictly increasing")
            );
            let raw = raw_manifest(&entries);
            assert_eq!(
                Manifest::parse(&raw).unwrap_err(),
                ReportError::InvalidManifest("sequence numbers are not strictly increasing")
            );
        }
        let out_of_range = vec![entry(MAX_SEQ + 1, 0)];
        assert_eq!(
            Manifest::parse(&raw_manifest(&out_of_range)).unwrap_err(),
            ReportError::InvalidManifest("sequence number out of range")
        );
        let top = Manifest::from_entries(vec![entry(MAX_SEQ, 0)]).unwrap();
        assert_eq!(top.seq_limit(), MAX_SEQ_LIMIT);
    }

    /// Encode entries without validation, to feed the parser bad orderings.
    fn raw_manifest(entries: &[ManifestEntry]) -> Vec<u8> {
        let mut out = b"FQM1".to_vec();
        out.extend_from_slice(&u32::try_from(entries.len()).unwrap().to_be_bytes());
        for e in entries {
            out.extend_from_slice(&e.seq.to_be_bytes());
            out.extend_from_slice(&e.blob_sha256);
        }
        out
    }

    #[test]
    fn object_names_are_six_digits_and_strict() {
        assert_eq!(chain_object_name(0).unwrap(), "000000.strm");
        assert_eq!(chain_object_name(42).unwrap(), "000042.strm");
        assert_eq!(chain_object_name(MAX_SEQ).unwrap(), "999999.strm");
        assert_eq!(
            chain_object_name(MAX_SEQ + 1).unwrap_err(),
            ReportError::SeqOutOfRange(MAX_SEQ + 1)
        );
        assert_eq!(parse_chain_object_name("000000.strm"), Some(0));
        assert_eq!(parse_chain_object_name("000123.strm"), Some(123));
        assert_eq!(parse_chain_object_name("999999.strm"), Some(MAX_SEQ));
        for bad in [
            "",
            ".strm",
            "00123.strm",
            "0001234.strm",
            "00012a.strm",
            "+00123.strm",
            "-00123.strm",
            " 00123.strm",
            "000123.STRM",
            "000123.strmx",
            "000123",
            "manifest",
            "1a2b3c4d5e6f7a8b_000001.strm",
            "\u{0661}\u{0662}\u{0663}\u{0664}\u{0665}\u{0666}.strm",
        ] {
            assert_eq!(
                parse_chain_object_name(bad),
                None,
                "{bad:?} must be refused"
            );
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        #[test]
        fn parse_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..256)) {
            if let Ok(manifest) = Manifest::parse(&bytes) {
                prop_assert_eq!(manifest.to_bytes(), bytes);
            }
        }

        #[test]
        fn valid_manifests_round_trip(
            seqs in proptest::collection::btree_set(0u32..=MAX_SEQ, 0..40),
            fill in any::<u8>(),
        ) {
            let entries: Vec<ManifestEntry> = seqs
                .iter()
                .map(|&seq| entry(seq, fill ^ seq.to_le_bytes()[0]))
                .collect();
            let manifest = Manifest::from_entries(entries).unwrap();
            let parsed = Manifest::parse(&manifest.to_bytes()).unwrap();
            prop_assert_eq!(&parsed, &manifest);
            prop_assert_eq!(parsed.seq_limit(), seqs.last().map_or(0, |s| s + 1));
        }

        #[test]
        fn object_names_round_trip(seq in 0u32..=MAX_SEQ) {
            let name = chain_object_name(seq).unwrap();
            prop_assert_eq!(parse_chain_object_name(&name), Some(seq));
        }
    }
}
