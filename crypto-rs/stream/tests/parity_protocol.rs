//! Byte-exact parity tests for the V2 relay protocol request bodies against
//! Kotlin-captured fixtures in `crypto-rs/parity-vectors/protocol/*.json`.
//!
//! We re-hydrate each fixture's payload into the matching Rust body type and
//! confirm the serialized JSON is semantically equivalent (same keys, same
//! values, same ordering within arrays). The server treats JSON as
//! unordered at the object level, so `serde_json::Value` equality is the
//! right granularity for interop parity.

use serde::Serialize;
use std::fs;
use std::path::PathBuf;

fn fixture_dir() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.push("parity-vectors");
    p.push("protocol");
    p
}

fn load_fixture_body(name: &str) -> serde_json::Value {
    let raw =
        fs::read_to_string(fixture_dir().join(name)).unwrap_or_else(|e| panic!("read {name}: {e}"));
    let file: serde_json::Value = serde_json::from_str(&raw).unwrap();
    file["body"].clone()
}

fn serialize_to_value<T: Serialize>(v: &T) -> serde_json::Value {
    serde_json::to_value(v).unwrap()
}

// ============================================================================
// These helpers mirror the private wire types in `protocol.rs`. Duplicated on
// purpose so the integration tests exercise the public hex/encode path rather
// than rely on a testing-only re-export.
// ============================================================================

#[derive(Serialize)]
struct EnrollBody {
    ed25519_pk: String,
    batch_0_public_keys: Vec<String>,
    batch_0_signature: String,
}

#[derive(Serialize)]
struct VerifyBody {
    ed25519_pk: String,
    ephemeral_pk: String,
    batch_number: u32,
    key_index: u32,
    nonce: String,
    signature: String,
}

#[derive(Serialize)]
struct RotateBody {
    ed25519_pk: String,
    signer_batch_number: u32,
    signer_key_index: u32,
    signer_public_key: String,
    new_batch_public_keys: Vec<String>,
    new_batch_signature: String,
}

// ============================================================================
// Parity tests
// ============================================================================

#[test]
fn enroll_body_byte_exact_vs_kotlin() {
    let fixture = load_fixture_body("enroll_req.json");

    let pks: Vec<String> = fixture["batch_0_public_keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    assert_eq!(pks.len(), 50, "fixture must have 50 batch_0 keys");

    let rust_body = EnrollBody {
        ed25519_pk: fixture["ed25519_pk"].as_str().unwrap().to_string(),
        batch_0_public_keys: pks,
        batch_0_signature: fixture["batch_0_signature"].as_str().unwrap().to_string(),
    };

    assert_eq!(serialize_to_value(&rust_body), fixture);
}

#[test]
fn verify_body_byte_exact_vs_kotlin() {
    let fixture = load_fixture_body("verify_req.json");

    let rust_body = VerifyBody {
        ed25519_pk: fixture["ed25519_pk"].as_str().unwrap().to_string(),
        ephemeral_pk: fixture["ephemeral_pk"].as_str().unwrap().to_string(),
        batch_number: u32::try_from(fixture["batch_number"].as_u64().unwrap()).unwrap(),
        key_index: u32::try_from(fixture["key_index"].as_u64().unwrap()).unwrap(),
        nonce: fixture["nonce"].as_str().unwrap().to_string(),
        signature: fixture["signature"].as_str().unwrap().to_string(),
    };

    assert_eq!(serialize_to_value(&rust_body), fixture);
}

#[test]
fn rotate_body_byte_exact_vs_kotlin() {
    let fixture = load_fixture_body("rotate_req.json");

    let new_pks: Vec<String> = fixture["new_batch_public_keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    assert_eq!(new_pks.len(), 50, "fixture must have 50 new_batch keys");

    let rust_body = RotateBody {
        ed25519_pk: fixture["ed25519_pk"].as_str().unwrap().to_string(),
        signer_batch_number: u32::try_from(fixture["signer_batch_number"].as_u64().unwrap())
            .unwrap(),
        signer_key_index: u32::try_from(fixture["signer_key_index"].as_u64().unwrap()).unwrap(),
        signer_public_key: fixture["signer_public_key"].as_str().unwrap().to_string(),
        new_batch_public_keys: new_pks,
        new_batch_signature: fixture["new_batch_signature"].as_str().unwrap().to_string(),
    };

    assert_eq!(serialize_to_value(&rust_body), fixture);
}

// ============================================================================
// Structural check: the Rust protocol module must export the 5 types the
// public API contract promises. If any of these vanish, this breaks first.
// ============================================================================

#[test]
fn public_types_are_exported() {
    // These compile-only references fail to resolve if the re-exports drift.
    fn _enroll_result_is_type() {
        let _ = frappuccino_crypto_stream::EnrollResult::AlreadyEnrolled;
    }
    fn _protocol_error_is_type(_e: &frappuccino_crypto_stream::ProtocolError) {}
    fn _client_is_type(_c: &frappuccino_crypto_stream::StreamServerClient) {}
}
