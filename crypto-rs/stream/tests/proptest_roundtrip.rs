//! Property-based round-trip for STRM blob encryption.
//!
//! For any plaintext, `decrypt(encrypt(pt)) == pt`, in both SINGLE and CHUNKED
//! modes (including the chunk boundaries where the chunk loop and the
//! AAD `chunk_count` binding live), and `decrypt` never panics on arbitrary
//! bytes.
//!
//! Complements: the KAT parity tests (fixed Kotlin vectors), the boundary tests
//! (exact-threshold *rejection*), and the `fuzz_decrypt_blob` target (no-crash).
//! proptest adds the randomized round-trip *correctness* invariant with
//! deterministic shrinking to a minimal reproducer.

use frappuccino_crypto_core::identity::{ArchiveIdentity, StreamIdentity};
use frappuccino_crypto_stream::header::CHUNK_SIZE;
use frappuccino_crypto_stream::{decrypt, encrypt_chunked, encrypt_single};
use proptest::prelude::*;
use std::sync::OnceLock;

/// A fixed, valid 12-word French BIP-39 phrase (same phrase the identity unit
/// tests use). The round-trip property is over the *plaintext*, not the
/// identity, so a single derivation is enough.
const MN: &str = "abaisser abandon abdiquer abeille abolir aborder aboutir aboyer abrasif abreuver abriter abroger";

/// Derive the author (public) + archive (private) identity exactly once —
/// BIP-39 PBKDF2 + the mlock'd archive secret are not free to rebuild per case.
fn ids() -> &'static (StreamIdentity, ArchiveIdentity) {
    static IDS: OnceLock<(StreamIdentity, ArchiveIdentity)> = OnceLock::new();
    IDS.get_or_init(|| {
        let archive = ArchiveIdentity::from_mnemonic(MN, "").expect("archive identity");
        let author = archive.identity().clone();
        (author, archive)
    })
}

/// A deterministic byte pattern of a given length — used instead of asking
/// proptest to generate megabyte-long random vectors (which would build an
/// enormous, slow-to-shrink value tree). The round-trip property does not need
/// the *content* to be random for the large sizes; it needs the *length* to
/// land on chunk boundaries.
fn pattern(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| u8::try_from(i.wrapping_mul(7919) & 0xff).unwrap_or(0))
        .collect()
}

/// Plaintext lengths that land on / around chunk boundaries.
fn chunk_boundary_len() -> impl Strategy<Value = usize> {
    let c = CHUNK_SIZE;
    prop_oneof![
        0usize..=64usize,
        (c - 2)..=(c + 2),
        (2 * c - 2)..=(2 * c + 2),
    ]
}

proptest! {
    // Deterministic (fixed seed); failures persisted + shrunk.
    #![proptest_config(ProptestConfig { cases: 128, ..ProptestConfig::default() })]

    /// SINGLE mode round-trips for any small/medium plaintext (random content).
    #[test]
    fn encrypt_single_roundtrip(pt in proptest::collection::vec(any::<u8>(), 0..8192)) {
        let (author, archive) = ids();
        let blob = encrypt_single(&pt, author).expect("encrypt_single");
        let (out, meta) = decrypt(&blob, archive).expect("decrypt");
        prop_assert_eq!(&out[..], &pt[..]);
        prop_assert_eq!(meta.mode, 1);
        prop_assert_eq!(meta.version, 3);
        prop_assert_eq!(meta.author_ed25519_pk, None);
    }

    /// `decrypt` must never panic on arbitrary bytes — a deterministic,
    /// shrinking complement to the libFuzzer `fuzz_decrypt_blob` target.
    #[test]
    fn decrypt_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..4096)) {
        let (_author, archive) = ids();
        let _ = decrypt(&bytes, archive); // Ok or Err, but never a panic.
    }
}

proptest! {
    // Fewer cases — each allocates up to ~2 × CHUNK_SIZE.
    #![proptest_config(ProptestConfig { cases: 24, ..ProptestConfig::default() })]

    /// CHUNKED mode round-trips across chunk boundaries.
    #[test]
    fn encrypt_chunked_roundtrip(len in chunk_boundary_len()) {
        let (author, archive) = ids();
        let pt = pattern(len);
        let blob = encrypt_chunked(&pt, author).expect("encrypt_chunked");
        let (out, meta) = decrypt(&blob, archive).expect("decrypt");
        prop_assert_eq!(out.len(), pt.len());
        prop_assert_eq!(&out[..], &pt[..]);
        prop_assert_eq!(meta.mode, 2);
        prop_assert_eq!(meta.version, 3);
        prop_assert_eq!(meta.author_ed25519_pk, None);
        prop_assert_eq!(meta.plaintext_len, pt.len());
    }
}
