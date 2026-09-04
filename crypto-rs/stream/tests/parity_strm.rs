//! Byte-exact parity tests for STRM blob decryption against the Kotlin reference.
//!
//! The fixtures are **V1** blobs, written by the pre-S5 Kotlin encoder, and they
//! are the only STRM vectors in the tree produced by a different implementation.
//! The three tests that read them therefore need `legacy-strm` (the CLI
//! configuration); CI runs the suite with that feature on as well, because
//! taking the legacy decoder out of the shipped `.so` must not quietly take the
//! cross-implementation evidence out of the dossier.
//!
//! The other three build V3 blobs with the current encoder and are **not**
//! gated. Gating the whole file would have been simpler and would have removed
//! the shipped configuration's own encrypt/decrypt round-trip from its own test
//! run, which is the opposite of what reducing the parser is for.
//!
//! Loads fixtures from `crypto-rs/parity-vectors/strm_blobs/*.strm` produced
//! on an Android device by `ParityVectorsDumper`, and asserts that our Rust
//! `decrypt` recovers the original plaintext.
//!
//! STRM blobs contain random session keys + random nonces, so we cannot check
//! blob bytes against Kotlin — only the decrypted plaintext. Byte-exact checks
//! on the encrypted side are covered by the `encrypt → decrypt` internal
//! round-trip tests below.

use frappuccino_crypto_core::identity::ArchiveIdentity;
use frappuccino_crypto_stream::header::{
    parse_header, HEADER_SIZE_NO_GRANTS, MODE_CHUNKED, NONCE_PREFIX_BYTES,
};
use frappuccino_crypto_stream::{decrypt, encrypt_chunked, encrypt_single};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

fn vectors_dir() -> PathBuf {
    // tests/ are run with CARGO_MANIFEST_DIR = crypto-rs/stream.
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.push("parity-vectors");
    p
}

#[derive(Deserialize)]
struct StrmFile {
    mnemonic: String,
    passphrase: String,
    cases: Vec<Case>,
}

#[derive(Deserialize)]
#[allow(dead_code)] // fields kept for fixture introspection / error messages
struct Case {
    filename: String,
    mode: String,
    plaintext_size: usize,
    plaintext_sha256: String,
    plaintext_hex: Option<String>,
    plaintext_filename: Option<String>,
    description: String,
    blob_size: usize,
}

/// Decode the expected plaintext either from `plaintext_hex` (inline for small
/// cases) or from a sibling `.bin` file (large cases).
fn load_plaintext(case: &Case, dir: &Path) -> Vec<u8> {
    if let Some(hex) = &case.plaintext_hex {
        hex::decode(hex).expect("plaintext_hex decode")
    } else if let Some(name) = &case.plaintext_filename {
        fs::read(dir.join(name)).expect("plaintext_filename read")
    } else {
        Vec::new()
    }
}

#[test]
// Reads the kotlin-produced v1 fixtures, so it only runs in the CLI configuration.
#[cfg(feature = "legacy-strm")]
fn strm_blobs_decrypt_to_expected_plaintext() {
    use frappuccino_crypto_stream::header::VERSION_V1;
    let dir = vectors_dir().join("strm_blobs");
    let raw = fs::read_to_string(dir.join("vectors.json")).unwrap();
    let file: StrmFile = serde_json::from_str(&raw).unwrap();

    let archive = ArchiveIdentity::from_mnemonic(&file.mnemonic, &file.passphrase)
        .expect("ArchiveIdentity from mnemonic");

    for case in &file.cases {
        // chunked_3mb.strm is .gitignored (3 MB) — skip if missing.
        let blob_path = dir.join(&case.filename);
        if !blob_path.exists() {
            eprintln!("skip missing fixture: {}", case.filename);
            continue;
        }
        let blob = fs::read(&blob_path).unwrap_or_else(|e| panic!("read {}: {e}", case.filename));
        let expected = load_plaintext(case, &dir);
        assert_eq!(expected.len(), case.plaintext_size);

        // RT-02 fix: V1 CHUNKED blobs (silent-truncation primitive) are now
        // rejected at decrypt time. The Kotlin-produced fixture
        // `chunked_3mb.strm` is V1+CHUNKED and is kept in the parity set as a
        // regression guard for the rejection itself, not for the legacy
        // happy-path. V1 SINGLE fixtures continue to decrypt cleanly.
        let parsed =
            parse_header(&blob).unwrap_or_else(|e| panic!("{}: parse_header {e:?}", case.filename));
        if parsed.version == VERSION_V1 && parsed.mode == MODE_CHUNKED {
            let err = decrypt(&blob, &archive).unwrap_err();
            let msg = format!("{err:?}");
            assert!(
                msg.contains("V1 CHUNKED rejected"),
                "{}: expected V1 CHUNKED rejection (RT-02), got {msg}",
                case.filename
            );
            continue;
        }

        let (plaintext, meta) =
            decrypt(&blob, &archive).unwrap_or_else(|e| panic!("{}: decrypt {e:?}", case.filename));
        assert_eq!(
            &plaintext[..],
            expected.as_slice(),
            "{}: decrypted plaintext diverges from fixture",
            case.filename
        );

        // Note: the dumper's "mode" label is the caller's *intent*, not what
        // the encoder actually picked — e.g. `single_small.strm` was produced
        // with fileSize=-1 which falls outside `0..CHUNK_THRESHOLD` and so
        // the encoder selected CHUNKED. The authoritative value is the mode
        // byte inside the blob (== meta.mode) — we only sanity-check it's
        // one of the two valid modes.
        assert!(
            matches!(meta.mode, 1 | 2),
            "{}: mode byte must be 1 or 2, got {}",
            case.filename,
            meta.mode
        );
        // The Kotlin dumper always wrote VERSION_V1 — this is our retro-compat
        // regression guard. If this ever fails, the legacy read path is
        // broken and any device still holding v1 blobs will go silent.
        assert_eq!(
            meta.version, 1,
            "{}: fixture is Kotlin-produced VERSION_V1",
            case.filename
        );
        // Legacy V1/V2 blobs DO embed the author identity at rest — the
        // decoder must still surface it (Some). V3 drops it (None); see the
        // round-trip tests below and motto_no_identity_at_rest.rs.
        assert!(
            meta.author_ed25519_pk.is_some(),
            "{}: legacy V1 blob must surface its embedded author",
            case.filename
        );

        // SHA-256 sanity vs the fixture (redundant with byte-eq but reads better
        // in the error message for large plaintexts).
        let sha = hex::encode(Sha256::digest(&plaintext[..]));
        assert_eq!(sha, case.plaintext_sha256, "{}: SHA-256", case.filename);
    }
}

#[test]
fn rust_encrypt_then_rust_decrypt_roundtrip_single() {
    let dir = vectors_dir().join("strm_blobs");
    let raw = fs::read_to_string(dir.join("vectors.json")).unwrap();
    let file: StrmFile = serde_json::from_str(&raw).unwrap();

    // Reuse the fixture's mnemonic to avoid bringing in EnrollmentKit here.
    let archive = ArchiveIdentity::from_mnemonic(&file.mnemonic, &file.passphrase).unwrap();

    // Build a StreamIdentity from the archive's public keys (both views share them).
    let author = archive.identity().clone();

    let plaintext = b"The quick brown fox jumps over the lazy dog.";
    let blob = encrypt_single(plaintext, &author).unwrap();
    let (out, meta) = decrypt(&blob, &archive).unwrap();
    assert_eq!(&out[..], plaintext);
    assert_eq!(meta.mode, 1);
    assert_eq!(meta.version, 3, "encoder must emit VERSION_V3");
    // V3 carries NO author identity at rest (F-C1) — the metadata reflects it.
    assert_eq!(
        meta.author_ed25519_pk, None,
        "V3 must not surface any author identity"
    );
}

#[test]
fn rust_encrypt_then_rust_decrypt_roundtrip_chunked() {
    let dir = vectors_dir().join("strm_blobs");
    let raw = fs::read_to_string(dir.join("vectors.json")).unwrap();
    let file: StrmFile = serde_json::from_str(&raw).unwrap();

    let archive = ArchiveIdentity::from_mnemonic(&file.mnemonic, &file.passphrase).unwrap();
    let author = archive.identity().clone();

    // 3 chunks of 1 MiB minus a few bytes → triggers mid-chunk boundaries.
    let plaintext: Vec<u8> = (0..(3 * 1024 * 1024 - 7))
        .map(|i: usize| u8::try_from((i * 7919) & 0xFF).unwrap_or(0))
        .collect();
    let blob = encrypt_chunked(&plaintext, &author).unwrap();
    let (out, meta) = decrypt(&blob, &archive).unwrap();
    assert_eq!(&out[..], plaintext.as_slice());
    assert_eq!(meta.mode, 2);
    assert_eq!(meta.version, 3, "encoder must emit VERSION_V3");
    assert_eq!(meta.author_ed25519_pk, None, "V3 carries no author at rest");
    assert_eq!(meta.plaintext_len, plaintext.len());
}

/// Truncation attack: take a well-formed v2 chunked blob, drop the last chunk
/// from the body, and patch `chunk_count` in the body to match. In V1, this
/// would have decrypted silently (AAD = header only, unchanged). In V2, the
/// AAD binds the claimed `chunk_count` → the first chunk's AEAD tag fails
/// because the authenticated `chunk_count` no longer matches the one the
/// encoder used.
#[test]
fn decrypt_v2_rejects_chunk_count_truncation() {
    let dir = vectors_dir().join("strm_blobs");
    let raw = fs::read_to_string(dir.join("vectors.json")).unwrap();
    let file: StrmFile = serde_json::from_str(&raw).unwrap();
    let archive = ArchiveIdentity::from_mnemonic(&file.mnemonic, &file.passphrase).unwrap();
    let author = archive.identity().clone();

    // Exactly 2 full chunks + 1 byte → 3 chunks, easy to truncate the tail.
    let plaintext: Vec<u8> = vec![0x42; 2 * 1024 * 1024 + 1];
    let blob = encrypt_chunked(&plaintext, &author).unwrap();
    let (_, meta) = decrypt(&blob, &archive).expect("original blob must decrypt");
    assert_eq!(meta.version, 3);

    // Layout (v3 chunked, 0 grants):
    //   [0..87]         header
    //   [87]            MODE_CHUNKED = 0x02
    //   [88..108]       nonce_prefix (20)
    //   [108..112]      chunk_count = 3 (BE u32)
    //   [112..]         chunks: total_len(4) ‖ nonce(24) ‖ ct(...)
    let header_end = HEADER_SIZE_NO_GRANTS;
    let chunk_count_off = header_end + 1 + NONCE_PREFIX_BYTES;

    // Walk past the first 2 chunks to find where chunk #3 starts.
    let mut cursor = chunk_count_off + 4;
    for _ in 0..2 {
        let total_len = u32::from_be_bytes(blob[cursor..cursor + 4].try_into().unwrap()) as usize;
        cursor += 4 + total_len;
    }
    // Drop chunk #3, patch chunk_count to 2.
    let mut truncated = blob[..cursor].to_vec();
    truncated[chunk_count_off..chunk_count_off + 4].copy_from_slice(&2u32.to_be_bytes());

    let result = decrypt(&truncated, &archive);
    assert!(
        result.is_err(),
        "truncated v2 blob must fail AEAD (chunk_count bound in AAD)"
    );
}

#[test]
// Tampers with a v1 fixture blob, so it only runs in the CLI configuration.
#[cfg(feature = "legacy-strm")]
fn decrypt_rejects_tampered_magic() {
    let dir = vectors_dir().join("strm_blobs");
    let blob_path = dir.join("single_small.strm");
    if !blob_path.exists() {
        return; // fixture absent (skipped)
    }
    let raw = fs::read_to_string(dir.join("vectors.json")).unwrap();
    let file: StrmFile = serde_json::from_str(&raw).unwrap();
    let archive = ArchiveIdentity::from_mnemonic(&file.mnemonic, &file.passphrase).unwrap();

    let mut blob = fs::read(&blob_path).unwrap();
    blob[0] = b'X'; // corrupt magic
    assert!(decrypt(&blob, &archive).is_err());
}

#[test]
// Decrypts a v1 fixture with the wrong archive key, so it only runs in the CLI configuration.
#[cfg(feature = "legacy-strm")]
fn decrypt_rejects_wrong_recipient() {
    let dir = vectors_dir().join("strm_blobs");
    let blob_path = dir.join("single_small.strm");
    if !blob_path.exists() {
        return;
    }
    let _raw = fs::read_to_string(dir.join("vectors.json")).unwrap();

    // Different mnemonic → different archive identity → sealed envelope
    // won't unseal.
    let attacker_mn = "bambin bambou banane bandeau banlieue banque banquise bassin bastion bataille bateau batterie";
    // Guard: test only runs if the decoy is actually a valid wordlist phrase.
    let Ok(attacker_archive) = ArchiveIdentity::from_mnemonic(attacker_mn, "") else {
        eprintln!("skip: decoy mnemonic contains unknown words");
        return;
    };

    let blob = fs::read(&blob_path).unwrap();
    assert!(decrypt(&blob, &attacker_archive).is_err());
}
