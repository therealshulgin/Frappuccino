//! Motto regression guard (F-C1): the witness's long-term identity must NEVER
//! appear at rest inside a STRM blob.
//!
//! Why this test exists: the prior STRM format wrote the 32-byte
//! `author_ed25519_pk` (the witness's long-term identity == JWT subject ==
//! ratchet-registry key) IN CLEAR into every blob header. A relay-disk seizure
//! could then map `report_id -> identity` with zero keys — exactly what the
//! motto ("a seizure exposes nothing, not even who") forbids. Two prior audits
//! plus a design review missed it because the motto acceptance test grepped
//! `reports.json` ASCII, not the BINARY bytes of the blob. This test closes
//! that gap at the source: it scans the raw encoder output for the identity
//! bytes and fails if they reappear.
//!
//! It is deliberately format-agnostic about HOW the identity is kept out (V3
//! drops the field; any future format must keep it out too): it asserts on the
//! observable bytes, not on a version number.

use frappuccino_crypto_core::identity::ArchiveIdentity;
use frappuccino_crypto_stream::{decrypt, encrypt_chunked, encrypt_single};

const MN: &str = "abaisser abandon abdiquer abeille abolir aborder aboutir aboyer abrasif abreuver abriter abroger";

/// True if `needle` appears as a contiguous byte run anywhere in `haystack`.
fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && needle.len() <= haystack.len()
        && haystack.windows(needle.len()).any(|w| w == needle)
}

#[test]
fn strm_blob_never_embeds_author_identity_at_rest() {
    let archive = ArchiveIdentity::from_mnemonic(MN, "").expect("archive identity");
    let author = archive.identity().clone();
    let ed_pk = author.ed25519_pk().to_vec();
    let x_pk = author.x25519_pk().to_vec();

    // Sanity: the keys are real 32-byte values (an all-zero key would make the
    // absence assertion trivially pass).
    assert_eq!(ed_pk.len(), 32);
    assert_eq!(x_pk.len(), 32);
    assert!(
        ed_pk.iter().any(|&b| b != 0),
        "ed25519 pk must be non-trivial"
    );
    assert!(
        x_pk.iter().any(|&b| b != 0),
        "x25519 pk must be non-trivial"
    );

    // SINGLE and CHUNKED cover both header writers. We scan the WHOLE blob
    // (header + body): the ciphertext is random so a false hit is negligible,
    // and scanning everything is the strongest statement that nothing keyed to
    // the witness leaks at rest.
    let single = encrypt_single(b"temoignage: rien ne doit fuir", &author).unwrap();
    let chunked = encrypt_chunked(&vec![0x5au8; 2 * 1024 * 1024 + 7], &author).unwrap();

    for (label, blob) in [("SINGLE", &single), ("CHUNKED", &chunked)] {
        assert!(
            !contains_bytes(blob, &ed_pk),
            "{label}: author Ed25519 identity found at rest in the blob (F-C1 regression)"
        );
        assert!(
            !contains_bytes(blob, &x_pk),
            "{label}: author X25519 key found at rest in the blob (F-C1 regression)"
        );
        // The decoded metadata must report no author either.
        let (_pt, meta) = decrypt(blob, &archive).expect("decrypt");
        assert_eq!(
            meta.author_ed25519_pk, None,
            "{label}: decoded metadata must carry no author identity"
        );
    }
}
