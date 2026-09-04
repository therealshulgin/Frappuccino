//! Byte-exact parity tests for `PinProtectedStore` against the Kotlin reference.
//!
//! Loads `parity-vectors/pin_store/seal.json`, parses salt + nonce out of the
//! captured blob, and asserts that:
//!   1. `seal_deterministic(pin, plaintext, salt, nonce)` reproduces the blob
//!      byte-for-byte — proves our Argon2id + `XChaCha20-Poly1305` wiring is
//!      identical to libsodium's.
//!   2. `open(pin, blob)` recovers the plaintext — proves the decrypt path too.
//!
//! ## Cost note
//!
//! Each case runs Argon2id twice (seal + open) at the production
//! `256 MiB × t=4` parameters ≈ 1.2 s per call on a dev laptop. Three cases
//! → ~7 s total. This is why Argon2 RFC vectors live in the upstream crate
//! rather than here; we only need round-trip parity against Kotlin fixtures.

use frappuccino_crypto_core::pin_store::{
    open, seal_deterministic, HEADER_SIZE, NONCE_BYTES, SALT_BYTES, VERSION,
};
use serde::Deserialize;
use std::fs;
use std::path::PathBuf;

fn vectors_dir() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.push("parity-vectors");
    p
}

#[derive(Deserialize)]
struct SealFile {
    kdf: String,
    kdf_ops_limit: u32,
    kdf_mem_limit_bytes: u64,
    cipher: String,
    aad: String,
    salt_bytes: usize,
    nonce_bytes: usize,
    tag_bytes: usize,
    version_byte: u8,
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Case {
    pin: String,
    plaintext_hex: String,
    blob_hex: String,
}

#[test]
fn pin_store_matches_kotlin_fixtures() {
    let path = vectors_dir().join("pin_store").join("seal.json");
    let raw =
        fs::read_to_string(&path).unwrap_or_else(|e| panic!("Missing {}: {e}", path.display()));
    let file: SealFile = serde_json::from_str(&raw).unwrap();

    // Guard the format contract — these values are baked into every sealed
    // blob already on disk. Any drift here means either Kotlin changed the
    // spec (talk to the team first) or Rust picked wrong defaults.
    assert_eq!(file.kdf, "Argon2id");
    assert_eq!(file.kdf_ops_limit, 4);
    assert_eq!(file.kdf_mem_limit_bytes, 256 * 1024 * 1024);
    assert_eq!(file.cipher, "XChaCha20-Poly1305-IETF");
    assert_eq!(file.aad, "frappuccino-v2-pin-store-v1");
    assert_eq!(file.salt_bytes, SALT_BYTES);
    assert_eq!(file.nonce_bytes, NONCE_BYTES);
    assert_eq!(file.tag_bytes, 16);
    assert_eq!(file.version_byte, VERSION);

    for (i, case) in file.cases.iter().enumerate() {
        let blob_expected = hex::decode(&case.blob_hex).expect("blob_hex must be valid hex");
        let plaintext = hex::decode(&case.plaintext_hex).expect("plaintext_hex");

        // --- Extract salt + nonce from the captured blob so we can reproduce it ---
        assert_eq!(
            blob_expected[0], VERSION,
            "case {i}: captured blob has unexpected version"
        );
        let salt_end = 1 + SALT_BYTES;
        let salt: [u8; SALT_BYTES] = blob_expected[1..salt_end].try_into().expect("salt slice");
        let nonce: [u8; NONCE_BYTES] = blob_expected[salt_end..HEADER_SIZE]
            .try_into()
            .expect("nonce slice");

        // --- 1. Encrypt path: Rust reseals the same plaintext with the captured
        //         salt + nonce and must land on the exact same bytes.
        // Phase 6.1.4-A : pin est maintenant &[u8] côté Rust API. Le PIN
        // dans le fixture JSON est une String UTF-8 (digits ASCII en
        // pratique), donc as_bytes() donne le même hash Argon2 qu'avant.
        let blob_actual = seal_deterministic(case.pin.as_bytes(), &plaintext, &salt, &nonce)
            .unwrap_or_else(|e| panic!("case {i}: seal_deterministic failed: {e:?}"));
        assert_eq!(
            blob_actual,
            blob_expected,
            "case {i}: seal_deterministic produced a different blob than Kotlin\n\
             pin={:?} plaintext_len={}",
            case.pin,
            plaintext.len()
        );

        // --- 2. Decrypt path: open the Kotlin-captured blob with Rust.
        let recovered = open(case.pin.as_bytes(), &blob_expected)
            .unwrap_or_else(|e| panic!("case {i}: open failed: {e:?}"));
        assert_eq!(
            &recovered[..],
            plaintext.as_slice(),
            "case {i}: open recovered wrong plaintext"
        );
    }
}
