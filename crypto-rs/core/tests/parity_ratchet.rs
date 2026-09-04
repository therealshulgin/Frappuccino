//! Byte-exact parity tests for `EphemeralRatchet` against the Kotlin reference.
//!
//! Covers four fixture families produced by the Android dumper:
//!
//! 1. `ratchet/init.json`          → `batch_0` public keys + `chain_1`
//! 2. `ratchet/sign.json`          → 2 signatures from slot 0 and 1
//! 3. `ratchet/rotate.json`        → `RotationProof` after one `advance_batch`
//! 4. `ratchet/blob_v2.bin`        → full V2 blob after 2 signs
//! 5. `ratchet/blob_v1_legacy.bin` → V1 blob → must migrate to `blob_v2.bin` on re-serialize
//!
//! Any of these diverging = a protocol-breaking bug. All enrolled identities
//! on the production server would become unreachable.

use ed25519_dalek::{Signature, VerifyingKey};
use frappuccino_crypto_core::ratchet::{
    EphemeralRatchet, BATCH_SIZE, CHAIN_KEY_BYTES, OFF_CHAIN, SERIALIZED_PAYLOAD_SIZE,
    SERIALIZED_SIZE, SERIALIZED_SIZE_V1,
};
use frappuccino_crypto_core::signature_domain::SignatureDomain;
use serde::Deserialize;
use std::fs;
use std::path::PathBuf;

fn vectors_dir() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.push("parity-vectors");
    p
}

fn chain_0() -> [u8; 32] {
    // 0x00..0x1f — identical to the dumper's hardcoded value.
    let mut c = [0u8; 32];
    for (i, b) in c.iter_mut().enumerate() {
        *b = u8::try_from(i).expect("i < 32 fits in u8");
    }
    c
}

fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

// ============================================================================
// init.json
// ============================================================================

#[derive(Deserialize)]
struct InitFile {
    hkdf_ctx_batch_seeds: String,
    hkdf_ctx_next_chain: String,
    chain_0_hex: String,
    chain_1_hex: String,
    batch_0_public_keys_hex: Vec<String>,
}

#[test]
fn ratchet_init_matches_kotlin_fixture() {
    let raw = fs::read_to_string(vectors_dir().join("ratchet").join("init.json")).unwrap();
    let v: InitFile = serde_json::from_str(&raw).unwrap();

    // Guard the invariants so a silent context-string drift shows up here first.
    assert_eq!(v.hkdf_ctx_batch_seeds, "frappuccino-v2-ratchet-batch-seeds");
    assert_eq!(v.hkdf_ctx_next_chain, "frappuccino-v2-ratchet-next-chain");

    let chain0_fixture = hex::decode(&v.chain_0_hex).unwrap();
    assert_eq!(chain0_fixture, &chain_0()[..]);
    assert_eq!(v.batch_0_public_keys_hex.len(), BATCH_SIZE);

    let mut r = EphemeralRatchet::new();
    let mut c = chain_0();
    r.initialize(&mut c).unwrap();

    let pks = r.batch_public_keys().unwrap();
    for (i, expected_hex) in v.batch_0_public_keys_hex.iter().enumerate() {
        assert_eq!(
            hex_encode(&pks[i]),
            *expected_hex,
            "batch_0 public key {i} divergence"
        );
    }

    // chain_1 is embedded inside the next serialized blob at offset OFF_CHAIN.
    let blob = r.serialize().unwrap();
    let chain_1_actual = &blob[OFF_CHAIN..OFF_CHAIN + CHAIN_KEY_BYTES];
    assert_eq!(
        hex_encode(chain_1_actual),
        v.chain_1_hex,
        "chain_1 divergence"
    );
}

// ============================================================================
// sign.json
// ============================================================================

#[derive(Deserialize)]
struct SignFile {
    chain_0_hex: String,
    signs: Vec<SignCase>,
}

#[derive(Deserialize)]
struct SignCase {
    message_hex: String,
    key_index: u32,
    batch_number: u32,
    ephemeral_pk_hex: String,
}

#[test]
fn ratchet_sign_matches_kotlin_fixture() {
    let raw = fs::read_to_string(vectors_dir().join("ratchet").join("sign.json")).unwrap();
    let v: SignFile = serde_json::from_str(&raw).unwrap();

    assert_eq!(hex::decode(&v.chain_0_hex).unwrap(), &chain_0()[..]);

    let mut r = EphemeralRatchet::new();
    let mut c = chain_0();
    r.initialize(&mut c).unwrap();

    for (i, case) in v.signs.iter().enumerate() {
        let msg = hex::decode(&case.message_hex).unwrap();
        let sig = r.sign_and_advance(&msg).unwrap();
        assert_eq!(
            sig.batch_number, case.batch_number,
            "case {i}: batch_number"
        );
        assert_eq!(sig.key_index, case.key_index, "case {i}: key_index");
        assert_eq!(
            hex_encode(&sig.ephemeral_public_key),
            case.ephemeral_pk_hex,
            "case {i}: ephemeral_pk"
        );
        // R-C-1: the signature must verify against the (byte-exact-checked)
        // ephemeral pk over the AuthChallenge-domain-prefixed message. This is
        // authoritative (Ed25519 math) and non-circular — it would catch a
        // wrong-message or wrong-domain regression. It replaces the frozen
        // byte-exact KAT, which is no longer regenerable from an authoritative
        // source (there is no Kotlin-native signer; production signs via the
        // Rust FFI, and R-C-1 intentionally changed the signed bytes).
        let vk = VerifyingKey::from_bytes(&sig.ephemeral_public_key)
            .expect("ephemeral pk is a valid Ed25519 point");
        let signature = Signature::from_bytes(&sig.signature);
        let tbs = SignatureDomain::AuthChallenge.prefixed(&msg);
        vk.verify_strict(&tbs, &signature)
            .unwrap_or_else(|e| panic!("case {i}: AuthChallenge signature invalid: {e}"));
    }
}

// ============================================================================
// rotate.json
// ============================================================================

#[derive(Deserialize)]
struct RotateFile {
    chain_0_hex: String,
    signer_batch_number: u32,
    signer_key_index: u32,
    signer_pk_hex: String,
    new_batch_number: u32,
    new_batch_public_keys_hex: Vec<String>,
}

#[test]
fn ratchet_rotate_matches_kotlin_fixture() {
    let raw = fs::read_to_string(vectors_dir().join("ratchet").join("rotate.json")).unwrap();
    let v: RotateFile = serde_json::from_str(&raw).unwrap();

    assert_eq!(hex::decode(&v.chain_0_hex).unwrap(), &chain_0()[..]);

    let mut r = EphemeralRatchet::new();
    let mut c = chain_0();
    r.initialize(&mut c).unwrap();
    let proof = r.advance_batch().unwrap();

    assert_eq!(proof.signer_batch_number, v.signer_batch_number);
    assert_eq!(proof.signer_key_index, v.signer_key_index);
    assert_eq!(hex_encode(&proof.signer_public_key), v.signer_pk_hex);
    assert_eq!(proof.new_batch_number, v.new_batch_number);

    assert_eq!(v.new_batch_public_keys_hex.len(), BATCH_SIZE);
    for (i, expected) in v.new_batch_public_keys_hex.iter().enumerate() {
        assert_eq!(
            hex_encode(&proof.new_batch_public_keys[i]),
            *expected,
            "new_batch_public_keys[{i}] divergence"
        );
    }

    // R-C-1: the rotation signature must verify against the signer pk over the
    // BatchRotation-domain-prefixed concat(new_batch_public_keys) — authoritative
    // and non-circular (same rationale as the sign test).
    let mut concat = Vec::with_capacity(BATCH_SIZE * 32);
    for pk in &proof.new_batch_public_keys {
        concat.extend_from_slice(pk);
    }
    let vk = VerifyingKey::from_bytes(&proof.signer_public_key)
        .expect("signer pk is a valid Ed25519 point");
    let signature = Signature::from_bytes(&proof.signature);
    let tbs = SignatureDomain::BatchRotation.prefixed(&concat);
    vk.verify_strict(&tbs, &signature)
        .expect("BatchRotation signature must verify");

    // After a single slot consumed for rotation, the ratchet is on batch 1
    // with 50 fresh slots available.
    assert_eq!(r.batch_number(), 1);
    assert_eq!(r.remaining_in_batch(), BATCH_SIZE);
}

// ============================================================================
// blob_v2.bin + blob_v1_legacy.bin
// ============================================================================

#[test]
fn ratchet_blob_v2_matches_kotlin_fixture() {
    // The Kotlin dumper produced blob_v2 after initialize(chain_0) + 2 signs.
    let expected = fs::read(vectors_dir().join("ratchet").join("blob_v2.bin")).unwrap();
    assert_eq!(
        expected.len(),
        SERIALIZED_SIZE,
        "fixture must be 4876 bytes"
    );

    let mut r = EphemeralRatchet::new();
    let mut c = chain_0();
    r.initialize(&mut c).unwrap();
    r.sign_and_advance(b"first").unwrap();
    r.sign_and_advance(b"second").unwrap();
    let actual = r.serialize().unwrap();

    assert_eq!(actual.len(), SERIALIZED_SIZE);
    // Compare payload and MAC separately for a better error message if they diverge.
    assert_eq!(
        &actual[..SERIALIZED_PAYLOAD_SIZE],
        &expected[..SERIALIZED_PAYLOAD_SIZE],
        "V2 payload (version, batch_num, mask, chain, 50 slots) divergence"
    );
    assert_eq!(
        &actual[SERIALIZED_PAYLOAD_SIZE..],
        &expected[SERIALIZED_PAYLOAD_SIZE..],
        "V2 MAC divergence (HKDF or HMAC path differs from Kotlin)"
    );
}

#[test]
fn ratchet_blob_v1_legacy_migrates_to_v2() {
    // Post-RT-03: deserialize() rejects V1 outright; the migration path
    // is `migrate_from_v1` (used only by the dedicated CLI tool). The
    // round-trip parity contract is unchanged: V1 + serialize → V2 must
    // match the Kotlin-produced V2 fixture byte-exact.
    let v1 = fs::read(vectors_dir().join("ratchet").join("blob_v1_legacy.bin")).unwrap();
    assert_eq!(v1.len(), SERIALIZED_SIZE_V1);
    assert_eq!(v1[0], 1, "V1 blob must carry version byte 0x01");

    let v2_expected = fs::read(vectors_dir().join("ratchet").join("blob_v2.bin")).unwrap();

    // Sanity: deserialize must NOT accept the V1 blob anymore.
    assert!(
        EphemeralRatchet::deserialize(&v1).is_err(),
        "RT-03 regression: deserialize must reject V1 blobs"
    );

    let r = EphemeralRatchet::migrate_from_v1(&v1).unwrap();
    let migrated = r.serialize().unwrap();
    assert_eq!(
        migrated, v2_expected,
        "V1 → V2 migration must produce byte-identical V2 blob"
    );
}
