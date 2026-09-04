//! Byte-exact parity test for HKDF-SHA256 against the Kotlin reference.
//!
//! Uses the `ratchet/init.json` fixture produced by `ParityVectorsDumper`:
//! the Kotlin side computed `HKDF-SHA256(chain_0, null, CTX_NEXT_CHAIN, 32)`
//! and recorded the result as `chain_1_hex`. Our Rust implementation must
//! produce the same 32 bytes for the same inputs.
//!
//! If this fails, either:
//!   1. Our HKDF signature does not match Kotlin's null-salt handling, OR
//!   2. The domain-separation context string drifted (which would break every
//!      enrolled ratchet — see `PLAN_RUST_EXEC.md` §1.3 for immutability).

use frappuccino_crypto_core::hkdf::sha256;
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
struct RatchetInit {
    hkdf_ctx_next_chain: String,
    chain_0_hex: String,
    chain_1_hex: String,
}

#[test]
fn hkdf_sha256_next_chain_matches_kotlin() {
    let path = vectors_dir().join("ratchet").join("init.json");
    let raw =
        fs::read_to_string(&path).unwrap_or_else(|e| panic!("Missing {}: {e}", path.display()));
    let v: RatchetInit = serde_json::from_str(&raw).unwrap();

    // Guard the invariant — context string is load-bearing.
    assert_eq!(
        v.hkdf_ctx_next_chain, "frappuccino-v2-ratchet-next-chain",
        "CTX_NEXT_CHAIN must match PLAN_RUST_EXEC.md §1.3 verbatim"
    );

    let ikm = hex::decode(&v.chain_0_hex).unwrap();
    let expected = hex::decode(&v.chain_1_hex).unwrap();

    // Kotlin call: Hkdf.sha256(ikm=chain_0, salt=null, info=CTX, length=32)
    // Rust call : sha256(ikm, None, info, 32)
    let actual = sha256(&ikm, None, v.hkdf_ctx_next_chain.as_bytes(), 32).unwrap();

    assert_eq!(
        &actual[..],
        expected.as_slice(),
        "HKDF(chain_0, null, \"{}\", 32) divergence\n  expected: {}\n  actual:   {}",
        v.hkdf_ctx_next_chain,
        v.chain_1_hex,
        hex::encode(&actual[..]),
    );
}

#[test]
fn hkdf_sha256_batch_seeds_length_matches_contract() {
    // Sanity check that HKDF can produce 50*32 = 1600 bytes in one go — the
    // batch-seeds derivation the ratchet will use in S5. This doesn't compare
    // against a fixture (batch_0_public_keys are ed25519-derived, validated
    // byte-exact in S3+), just that the length path works.
    let path = vectors_dir().join("ratchet").join("init.json");
    let raw = fs::read_to_string(&path).unwrap();
    let v: RatchetInit = serde_json::from_str(&raw).unwrap();
    let ikm = hex::decode(&v.chain_0_hex).unwrap();

    let seeds = sha256(&ikm, None, b"frappuccino-v2-ratchet-batch-seeds", 50 * 32).unwrap();
    assert_eq!(seeds.len(), 50 * 32);
    assert!(seeds.iter().any(|&b| b != 0), "seeds must not be all-zero");
}
