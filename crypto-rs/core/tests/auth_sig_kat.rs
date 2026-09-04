//! `auth_sig_kat.rs` — cross-language Known-Answer Test for the V2 auth /
//! rotation / enrollment signatures (domain tags 0x01 / 0x02 / 0x03), the
//! symmetric companion to the relay-blind report-sig KAT (0x07 / 0x08) in
//! `core/src/report.rs` + `server/tests/test_report_sig_kat.py` (WP-E1).
//!
//! These three signatures are the live V2 auth contract the relay verifies in
//! `server/app/routes/auth_v2.py`:
//!
//!   - `0x01 AuthChallenge` — an ephemeral slot signs `nonce ‖ ts_be_u64`
//!     (`POST /auth/v2/verify`).
//!   - `0x02 BatchRotation` — an ephemeral slot signs `concat(50 new pk)`
//!     (`POST /auth/v2/rotate-batch`).
//!   - `0x03 Enrollment`    — the long-term key signs `concat(50 batch_0 pk)`
//!     (`POST /auth/v2/enroll`).
//!
//! Until WP-E1 their Rust<->server byte-parity was only ever HAND-checked: the
//! diff-fuzz corpus is a Kotlin<->Rust boundary differential (it never leaves
//! the FFI) and the route tests (`test_e2e_v2.py`) SIGN in Python using the
//! server's OWN `signature_domain` constants. So a one-sided drift — a changed
//! domain tag, a changed message layout (the `ts` width / endianness, the
//! concat order), or a changed key derivation on the Rust client OR the Python
//! relay, but not both — round-trips green in both suites while breaking every
//! real login / rotation in production (`401 Invalid signature`).
//!
//! This KAT closes that gap exactly like the report KAT: Rust (the source of
//! truth) PRODUCES the bytes here from a fixed mnemonic, pins them as `EXP_*`,
//! and the relay (`server/tests/test_auth_sig_kat.py`) must VERIFY these exact
//! bytes against the messages it reconstructs itself. If either side drifts,
//! one side's test fails. To regenerate on a DELIBERATE change, run
//! `cargo test -p frappuccino-crypto-core --test auth_sig_kat -- --nocapture`
//! and copy the printed values into both this file and the Python KAT.

use ed25519_dalek::{Signature, VerifyingKey};
use frappuccino_crypto_core::identity::EnrollmentKit;
use frappuccino_crypto_core::ratchet::EphemeralRatchet;
use frappuccino_crypto_core::signature_domain::SignatureDomain;
use sha2::{Digest, Sha256};

const CHAIN_KEY_BYTES: usize = 32;

/// The same fixed French phrase as the report KAT and the in-crate
/// ratchet / identity tests, so every KAT regenerates from one mnemonic.
const MN_FIXED: &str =
    "abaisser abandon abdiquer abeille abolir aborder aboutir aboyer abrasif abreuver abriter abroger";

/// Fixed 0x01 challenge nonce: bytes `00 01 02 … 1f`. The relay rebuilds the
/// signed message as `nonce_bytes(32) ‖ ts.to_bytes(8, "big", unsigned)`.
fn kat_nonce() -> [u8; 32] {
    [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ]
}

/// Fixed, in-range unix-seconds timestamp for the 0x01 vector.
const KAT_TS: u64 = 1_700_000_000;

fn auth_message() -> Vec<u8> {
    let mut m = Vec::with_capacity(40);
    m.extend_from_slice(&kat_nonce());
    m.extend_from_slice(&KAT_TS.to_be_bytes());
    m
}

fn concat_pks(pks: &[[u8; 32]]) -> Vec<u8> {
    let mut c = Vec::with_capacity(pks.len() * 32);
    for pk in pks {
        c.extend_from_slice(pk);
    }
    c
}

fn to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    to_hex(&h.finalize())
}

/// Verify `sig` over `domain.prefixed(message)` under `pk` (dalek strict,
/// matching the relay's libsodium `crypto_sign_open`).
fn verify(pk: &[u8; 32], domain: SignatureDomain, message: &[u8], sig: &[u8; 64]) -> bool {
    let Ok(vk) = VerifyingKey::from_bytes(pk) else {
        return false;
    };
    vk.verify_strict(&domain.prefixed(message), &Signature::from_bytes(sig))
        .is_ok()
}

// ---- Pinned vectors (MUST stay byte-identical to test_auth_sig_kat.py) ------
// Produced by this test from MN_FIXED; see the module doc for regeneration.
const EXP_LTK_PK: &str = "f373b6de310a66e4b4f0e1ab355c89446762b59b47895d2d42ecfa5ed8d36920";
const EXP_SLOT0_PK: &str = "7e8650d32c0d2797e22f8070711abdc6ddeb4e98ea1e0848f250ba845f3a17f5";
const EXP_SIGNER_PK: &str = "17e0116700e346955a96e84617c70662ecef062105d427c6ebff6f319636430a";
const EXP_ENROLL_SIG: &str = "de566cdb5ef4c2c9f72e65840bfb659d001b3be2c04ef89f616da8323f66eec9\
     b401b89e8a8794aa4dde3a1606a74ab79d67321065fa5783b1af33b014021f0e";
const EXP_AUTH_SIG: &str = "34d773b2b2567a1ec97a0781a8f98a3ac6eb7532f14c7ab48ac0689aaeca6811\
     eace91c27390050869b95f9628ecc48eacffbc092f7e2ffd8e129e8b2a36ba0d";
const EXP_ROTATION_SIG: &str = "a4eb59d61f4494eba107b7223d43b3b763d474c9a291de3763a21e10eebe7818\
     cdeed5388f29b968f89ec1c98c5e6af8a1644e65909a737f9c16e778d4a65308";
const EXP_BATCH0_CONCAT_SHA256: &str =
    "098e921e1314168f910c1f9db5b80028d97180722fdabdbc1d891418e4b89dd2";
const EXP_BATCH1_CONCAT_SHA256: &str =
    "df92598ba7ccdd766835bcf5f2754bced587f969eabd9ad5b97dda093cc0b7c4";

#[test]
fn auth_sig_cross_language_kat() {
    // --- Reproduce the production enroll -> auth -> rotate flow, deterministic.
    let mut kit = EnrollmentKit::from_mnemonic(MN_FIXED, "").unwrap();
    let mut ratchet = EphemeralRatchet::new();
    let chain = kit.take_chain_zero().unwrap();
    let mut chain_bytes = [0u8; CHAIN_KEY_BYTES];
    chain.with_bytes(|b| chain_bytes.copy_from_slice(b));
    ratchet.initialize(&mut chain_bytes).unwrap();

    let ltk_pk = *kit.identity().ed25519_pk();
    let batch0_pks = ratchet.batch_public_keys().unwrap();

    // 0x03 Enrollment — long-term key signs concat(batch_0 pks).
    let batch0_concat = concat_pks(&batch0_pks);
    let enroll_sig = kit
        .sign_once(&batch0_concat, SignatureDomain::Enrollment)
        .unwrap();

    // 0x01 AuthChallenge — slot 0 signs nonce‖ts.
    let auth_msg = auth_message();
    let sig0 = ratchet.sign_and_advance(&auth_msg).unwrap();
    assert_eq!(sig0.batch_number, 0);
    assert_eq!(sig0.key_index, 0);
    let slot0_pk = sig0.ephemeral_public_key;

    // 0x02 BatchRotation — the next slot (1) signs concat(batch_1 pks).
    let proof = ratchet.advance_batch().unwrap();
    assert_eq!(proof.new_batch_number, 1);
    assert_eq!(proof.signer_batch_number, 0);
    assert_eq!(proof.signer_key_index, 1);
    let signer_pk = proof.signer_public_key;
    let batch1_concat = concat_pks(&proof.new_batch_public_keys);

    // --- Emit for regeneration (`-- --nocapture`) ----------------------------
    println!("KAT ltk_pk        = {}", to_hex(&ltk_pk));
    println!("KAT slot0_pk      = {}", to_hex(&slot0_pk));
    println!("KAT signer_pk     = {}", to_hex(&signer_pk));
    println!("KAT enroll_sig    = {}", to_hex(&enroll_sig));
    println!("KAT auth_sig      = {}", to_hex(&sig0.signature));
    println!("KAT rotation_sig  = {}", to_hex(&proof.signature));
    println!("KAT batch0_sha256 = {}", sha256_hex(&batch0_concat));
    println!("KAT batch1_sha256 = {}", sha256_hex(&batch1_concat));
    println!("KAT batch0_concat = {}", to_hex(&batch0_concat));
    println!("KAT batch1_concat = {}", to_hex(&batch1_concat));
    println!("KAT nonce         = {}", to_hex(&kat_nonce()));
    println!("KAT ts            = {KAT_TS}");

    // --- Pin the exact bytes (catches a Rust-side drift) ---------------------
    assert_eq!(to_hex(&ltk_pk), EXP_LTK_PK, "ltk_pk drift");
    assert_eq!(to_hex(&slot0_pk), EXP_SLOT0_PK, "slot0_pk drift");
    assert_eq!(to_hex(&signer_pk), EXP_SIGNER_PK, "signer_pk drift");
    assert_eq!(to_hex(&enroll_sig), EXP_ENROLL_SIG, "enroll_sig drift");
    assert_eq!(to_hex(&sig0.signature), EXP_AUTH_SIG, "auth_sig drift");
    assert_eq!(
        to_hex(&proof.signature),
        EXP_ROTATION_SIG,
        "rotation_sig drift"
    );
    assert_eq!(
        sha256_hex(&batch0_concat),
        EXP_BATCH0_CONCAT_SHA256,
        "batch_0 concat drift"
    );
    assert_eq!(
        sha256_hex(&batch1_concat),
        EXP_BATCH1_CONCAT_SHA256,
        "batch_1 concat drift"
    );

    // --- Live cross-check: each pinned sig verifies under its own domain ------
    assert!(verify(
        &slot0_pk,
        SignatureDomain::AuthChallenge,
        &auth_msg,
        &sig0.signature
    ));
    assert!(verify(
        &signer_pk,
        SignatureDomain::BatchRotation,
        &batch1_concat,
        &proof.signature
    ));
    assert!(verify(
        &ltk_pk,
        SignatureDomain::Enrollment,
        &batch0_concat,
        &enroll_sig
    ));

    // --- Negative: no signature cross-verifies in another domain (R-C-1) -----
    assert!(!verify(
        &slot0_pk,
        SignatureDomain::BatchRotation,
        &auth_msg,
        &sig0.signature
    ));
    assert!(!verify(
        &signer_pk,
        SignatureDomain::AuthChallenge,
        &batch1_concat,
        &proof.signature
    ));
    // Enrollment and rotation share the SAME message shape (`concat(50 pk)`);
    // only the domain tag (0x03 vs 0x02) keeps them apart — the exact forgery
    // surface R-C-1 closed. Pin that an enroll sig never verifies as a rotation
    // even though the relay would otherwise rebuild an identical 1600-byte buffer.
    assert!(!verify(
        &ltk_pk,
        SignatureDomain::BatchRotation,
        &batch0_concat,
        &enroll_sig
    ));

    ratchet.wipe();
}
