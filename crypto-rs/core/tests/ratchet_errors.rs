//! Error-path coverage for `EphemeralRatchet`.
//!
//! Complements the happy-path tests in `ratchet.rs` and the `fuzz_ratchet_deserialize`
//! harness. Targets the explicit `return Err(…)` branches so `cargo tarpaulin`
//! visits every guard.

use frappuccino_crypto_core::identity::EnrollmentKit;
use frappuccino_crypto_core::ratchet::{EphemeralRatchet, BATCH_SIZE, CHAIN_KEY_BYTES};
use frappuccino_crypto_core::CryptoError;

const MN: &str = "abaisser abandon abdiquer abeille abolir aborder aboutir aboyer abrasif abreuver abriter abroger";

fn fresh_ratchet() -> EphemeralRatchet {
    let mut kit = EnrollmentKit::from_mnemonic(MN, "").unwrap();
    let chain = kit.take_chain_zero().unwrap();
    let mut chain_bytes = [0u8; CHAIN_KEY_BYTES];
    chain.with_bytes(|b| chain_bytes.copy_from_slice(b));
    let mut r = EphemeralRatchet::new();
    r.initialize(&mut chain_bytes).unwrap();
    r
}

// ---------- init / state guards ------------------------------------------

#[test]
fn initialize_rejects_double_init() {
    let mut r = fresh_ratchet();
    let mut chain = [0u8; CHAIN_KEY_BYTES];
    let err = r.initialize(&mut chain).unwrap_err();
    assert!(
        matches!(err, CryptoError::DerivationFailed(_)),
        "expected DerivationFailed, got {err:?}"
    );
}

#[test]
fn sign_before_initialize_rejected() {
    let mut r = EphemeralRatchet::new();
    let err = r.sign_and_advance(b"x").unwrap_err();
    assert!(
        matches!(err, CryptoError::DerivationFailed(_)),
        "expected DerivationFailed, got {err:?}"
    );
}

#[test]
fn advance_batch_before_initialize_rejected() {
    let mut r = EphemeralRatchet::new();
    let err = r.advance_batch().unwrap_err();
    assert!(
        matches!(err, CryptoError::DerivationFailed(_)),
        "expected DerivationFailed, got {err:?}"
    );
}

#[test]
fn serialize_before_initialize_rejected() {
    let r = EphemeralRatchet::new();
    let err = r.serialize().unwrap_err();
    assert!(
        matches!(err, CryptoError::DerivationFailed(_)),
        "expected DerivationFailed, got {err:?}"
    );
}

#[test]
fn batch_public_keys_before_initialize_rejected() {
    let r = EphemeralRatchet::new();
    assert!(r.batch_public_keys().is_err());
}

#[test]
fn public_key_at_out_of_range_rejected() {
    let r = fresh_ratchet();
    let err = r.public_key_at(BATCH_SIZE).unwrap_err();
    assert!(matches!(err, CryptoError::DerivationFailed(_)));
    let err2 = r.public_key_at(1000).unwrap_err();
    assert!(matches!(err2, CryptoError::DerivationFailed(_)));
}

#[test]
fn is_consumed_out_of_range_rejected() {
    let r = fresh_ratchet();
    let err = r.is_consumed(BATCH_SIZE).unwrap_err();
    assert!(matches!(err, CryptoError::DerivationFailed(_)));
}

#[test]
fn signing_stops_at_the_reserved_slot() {
    // A batch can no longer be signed to exhaustion: the last slot is reserved
    // for advance_batch, so signing refuses one step earlier than it used to.
    // The refusal takes nothing, which is what leaves the rotation possible.
    let mut r = fresh_ratchet();
    for _ in 0..BATCH_SIZE - 1 {
        r.sign_and_advance(b"msg").unwrap();
    }
    let err = r.sign_and_advance(b"msg").unwrap_err();
    assert!(matches!(err, CryptoError::DerivationFailed(_)));
    assert_eq!(r.remaining_in_batch(), 1, "the reserve is untouched");
    // And it is genuinely usable: the rotation out of the reserve succeeds.
    r.advance_batch()
        .expect("advance_batch must always be possible from the reserve");
}

// ---------- deserialize error paths --------------------------------------

#[test]
fn deserialize_empty_blob_rejected() {
    let err = EphemeralRatchet::deserialize(&[]).unwrap_err();
    assert!(matches!(err, CryptoError::InvalidBlob(_)));
}

#[test]
fn deserialize_unknown_version_byte_rejected() {
    let mut blob = vec![0xFFu8; 4876];
    blob[0] = 0x99; // neither V1 nor V2
    let err = EphemeralRatchet::deserialize(&blob).unwrap_err();
    let s = format!("{err:?}");
    assert!(
        s.contains("unsupported version"),
        "expected 'unsupported version', got {s}"
    );
}

#[test]
fn deserialize_v2_wrong_size_rejected() {
    let mut blob = vec![0u8; 100]; // way too short
    blob[0] = 0x02; // V2
    let err = EphemeralRatchet::deserialize(&blob).unwrap_err();
    let s = format!("{err:?}");
    assert!(s.contains("V2 size mismatch"), "got {s}");
}

#[test]
fn deserialize_v1_now_rejected() {
    // RT-03 fix: deserialize() rejects all V1 blobs, regardless of size.
    // The legacy "V1 size mismatch" error is now reachable only via the
    // dedicated `migrate_from_v1` escape hatch (CLI migration tool).
    let mut blob = vec![0u8; 100];
    blob[0] = 0x01; // V1
    let err = EphemeralRatchet::deserialize(&blob).unwrap_err();
    let s = format!("{err:?}");
    assert!(
        s.contains("V1 ratchet blob rejected"),
        "RT-03 regression: expected V1 rejection, got {s}"
    );
}

#[test]
fn migrate_from_v1_size_mismatch_rejected() {
    // The migrate_from_v1 escape hatch still validates the V1 layout.
    let mut blob = vec![0u8; 100]; // too short for V1
    blob[0] = 0x01;
    let err = EphemeralRatchet::migrate_from_v1(&blob).unwrap_err();
    let s = format!("{err:?}");
    assert!(s.contains("V1 size mismatch"), "got {s}");
}

#[test]
fn migrate_from_v1_rejects_non_v1() {
    // Defensive: migrate_from_v1 must refuse a V2 blob (avoid the case
    // where a caller wires the CLI tool against an already-migrated file).
    let r = fresh_ratchet();
    let v2 = r.serialize().unwrap();
    let err = EphemeralRatchet::migrate_from_v1(&v2).unwrap_err();
    let s = format!("{err:?}");
    assert!(s.contains("expected version"), "got {s}");
}

#[test]
fn deserialize_v2_mac_mismatch_rejected() {
    let r = fresh_ratchet();
    let mut blob = r.serialize().unwrap();
    // Flip a byte inside the payload — the MAC no longer covers it.
    blob[50] ^= 0x01;
    let err = EphemeralRatchet::deserialize(&blob).unwrap_err();
    assert!(matches!(
        err,
        CryptoError::InvalidBlob(_) | CryptoError::InvalidSignature
    ));
}
