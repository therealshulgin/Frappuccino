//! Byte-exact parity tests for identity derivation against the Kotlin reference.
//!
//! Loads `parity-vectors/identity/derive.json` and, for every captured case,
//! reconstructs the `EnrollmentKit` + `ArchiveIdentity` paths and asserts that
//! `ed25519_pk`, `x25519_pk`, `chain_0`, and `fingerprint` all match exactly.
//!
//! If any of these fail, either:
//!   1. Kotlin changed an HKDF context string (invariant break — see
//!      `PLAN_RUST_EXEC.md` §1.2), or
//!   2. Rust diverged (bug — fix here, don't regenerate vectors).

use frappuccino_crypto_core::identity::{ArchiveIdentity, EnrollmentKit};
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
struct DeriveFile {
    hkdf_ctx_identity: String,
    hkdf_ctx_encryption: String,
    hkdf_ctx_chain0: String,
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Case {
    mnemonic: String,
    passphrase: String,
    ed25519_pk_hex: String,
    x25519_pk_hex: String,
    chain_0_hex: String,
    fingerprint: String,
}

#[test]
fn identity_derivation_matches_kotlin_fixtures() {
    let path = vectors_dir().join("identity").join("derive.json");
    let raw =
        fs::read_to_string(&path).unwrap_or_else(|e| panic!("Missing {}: {e}", path.display()));
    let file: DeriveFile = serde_json::from_str(&raw).unwrap();

    // Guard the HKDF context strings — these are load-bearing invariants.
    // Any drift breaks every enrolled identity on the production server.
    assert_eq!(file.hkdf_ctx_identity, "stream.identity.ed25519.v1");
    assert_eq!(file.hkdf_ctx_encryption, "stream.encryption.x25519.v1");
    assert_eq!(file.hkdf_ctx_chain0, "stream.ratchet.chain0.v2");

    for (i, case) in file.cases.iter().enumerate() {
        // -- Enrollment path --
        let mut kit = EnrollmentKit::from_mnemonic(&case.mnemonic, &case.passphrase)
            .unwrap_or_else(|e| panic!("case {i}: EnrollmentKit failed: {e:?}"));

        assert_eq!(
            kit.identity().ed25519_pk_hex(),
            case.ed25519_pk_hex,
            "case {i}: ed25519_pk divergence for mnemonic={:?} pp={:?}",
            case.mnemonic,
            case.passphrase,
        );
        let x_pk_actual = hex_encode(kit.identity().x25519_pk());
        assert_eq!(x_pk_actual, case.x25519_pk_hex, "case {i}: x25519_pk");
        assert_eq!(
            kit.identity().readable_fingerprint(),
            case.fingerprint,
            "case {i}: fingerprint"
        );

        // Consume chain_0 and compare against the Kotlin-captured value.
        let chain = kit.take_chain_zero().unwrap();
        chain.with_bytes(|bytes| {
            assert_eq!(hex_encode(bytes), case.chain_0_hex, "case {i}: chain_0");
        });

        // -- Archive path must produce identical public keys --
        let archive = ArchiveIdentity::from_mnemonic(&case.mnemonic, &case.passphrase).unwrap();
        assert_eq!(
            hex_encode(archive.identity().ed25519_pk()),
            case.ed25519_pk_hex,
            "case {i}: ArchiveIdentity.ed_pk diverges from EnrollmentKit"
        );
        assert_eq!(
            hex_encode(archive.identity().x25519_pk()),
            case.x25519_pk_hex,
            "case {i}: ArchiveIdentity.x_pk diverges from EnrollmentKit"
        );
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}
