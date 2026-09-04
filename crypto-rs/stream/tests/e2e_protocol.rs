//! End-to-end tests against the live V2 relay (`https://136.244.101.236:8443`).
//!
//! All tests are `#[ignore]` by default — run with:
//! ```sh
//! cargo test -p frappuccino-crypto-stream --test e2e_protocol --release -- --ignored
//! ```
//!
//! Requires network connectivity to the Vultr relay. Each run generates a
//! fresh BIP-39 mnemonic so there are no identity collisions between runs.
//!
//! Mirrors `stream-crypto/src/androidTest/java/.../StreamServerClientTest.kt`.

use frappuccino_crypto_core::bip39;
use frappuccino_crypto_core::identity::EnrollmentKit;
use frappuccino_crypto_core::ratchet::{EphemeralRatchet, RatchetSignature, BATCH_SIZE};
use frappuccino_crypto_core::signature_domain::SignatureDomain;
use frappuccino_crypto_stream::pin::PinnedCertVerifier;
use frappuccino_crypto_stream::{EnrollResult, StreamServerClient};
use rustls::ClientConfig;
use std::sync::Arc;
use std::time::Duration;

const BASE_URL: &str = "https://relay.shake-document-protect.org:8443";
const CHAIN_KEY_BYTES: usize = 32;

// ============================================================================
// Helpers — fresh identity + initialized ratchet
// ============================================================================

struct FreshIdentity {
    kit: EnrollmentKit,
    ratchet: EphemeralRatchet,
    batch0_pks: [[u8; 32]; BATCH_SIZE],
    enroll_sig: [u8; 64],
    pk_hex: String,
}

fn fresh_identity() -> FreshIdentity {
    let mnemonic = bip39::generate_fr();
    let mut kit = EnrollmentKit::from_mnemonic(&mnemonic, "").expect("kit from mnemonic");

    let mut ratchet = EphemeralRatchet::new();
    let chain = kit.take_chain_zero().expect("chain_0");
    let mut chain_bytes = [0u8; CHAIN_KEY_BYTES];
    chain.with_bytes(|b| chain_bytes.copy_from_slice(b));
    ratchet.initialize(&mut chain_bytes).expect("ratchet init");

    let batch0_pks = ratchet.batch_public_keys().expect("batch_0 pks");
    let mut concat = Vec::with_capacity(BATCH_SIZE * 32);
    for pk in &batch0_pks {
        concat.extend_from_slice(pk);
    }
    let enroll_sig = kit
        .sign_once(&concat, SignatureDomain::Enrollment)
        .expect("sign batch_0");
    let pk_hex = hex::encode(kit.identity().ed25519_pk());

    FreshIdentity {
        kit,
        ratchet,
        batch0_pks,
        enroll_sig,
        pk_hex,
    }
}

// ============================================================================
// Flow tests
// ============================================================================

#[test]
#[ignore = "E2E test: requires live Vultr relay + network"]
fn e2e_enroll_authenticate_rotate_against_live_server() {
    let mut ident = fresh_identity();
    let client = StreamServerClient::new(BASE_URL).expect("client build");

    // 1. Enroll
    let r = client
        .enroll(&ident.pk_hex, &ident.batch0_pks, &ident.enroll_sig)
        .expect("enroll call");
    assert_eq!(r, EnrollResult::Success, "first enroll must succeed");

    // 2. Challenge + verify on batch_0 slot 0
    let challenge = client.challenge().expect("challenge");
    let message = challenge.message_bytes();
    let sig0: RatchetSignature = ident
        .ratchet
        .sign_and_advance(&message)
        .expect("sign slot 0");
    assert_eq!(sig0.batch_number, 0);
    assert_eq!(sig0.key_index, 0);

    let nonce_hex = hex::encode(challenge.nonce);
    let jwt = client
        .verify(ident.kit.identity(), &sig0, &nonce_hex, challenge.timestamp)
        .expect("verify call");
    let jwt = jwt.expect("server issued a JWT");
    assert!(jwt.starts_with("Bearer "), "jwt prefix: {jwt}");

    // 3. Rotate (consume slot 1 for the rotation signature)
    let proof = ident.ratchet.advance_batch().expect("advance batch");
    assert_eq!(proof.new_batch_number, 1);
    assert_eq!(proof.signer_batch_number, 0);
    let rot_ok = client
        .rotate_batch(&ident.pk_hex, &proof)
        .expect("rotate call");
    assert!(rot_ok, "rotation must succeed");

    // 5. Verify on batch_1 slot 0
    let challenge2 = client.challenge().expect("challenge #2");
    let msg2 = challenge2.message_bytes();
    let sig2 = ident
        .ratchet
        .sign_and_advance(&msg2)
        .expect("sign slot 0 of batch 1");
    assert_eq!(sig2.batch_number, 1);
    assert_eq!(sig2.key_index, 0);
    let jwt2 = client
        .verify(
            ident.kit.identity(),
            &sig2,
            &hex::encode(challenge2.nonce),
            challenge2.timestamp,
        )
        .expect("verify batch_1");
    assert!(jwt2.is_some(), "batch_1 JWT expected");

    // 6. Replay attack: stale sig from batch_0 must be refused after rotation.
    let challenge3 = client.challenge().expect("challenge #3");
    let fake_old = RatchetSignature {
        signature: sig0.signature,
        ephemeral_public_key: sig0.ephemeral_public_key,
        batch_number: 0,
        key_index: 0,
    };
    let rejected = client
        .verify(
            ident.kit.identity(),
            &fake_old,
            &hex::encode(challenge3.nonce),
            challenge3.timestamp,
        )
        .expect("verify should return Ok(None), not Err");
    assert!(rejected.is_none(), "stale batch_0 sig must be refused");

    ident.ratchet.wipe();
}

#[test]
#[ignore = "E2E test: requires live Vultr relay + network"]
fn e2e_enroll_twice_returns_already_enrolled() {
    let ident = fresh_identity();
    let client = StreamServerClient::new(BASE_URL).expect("client");

    let r1 = client
        .enroll(&ident.pk_hex, &ident.batch0_pks, &ident.enroll_sig)
        .unwrap();
    assert_eq!(r1, EnrollResult::Success);

    let r2 = client
        .enroll(&ident.pk_hex, &ident.batch0_pks, &ident.enroll_sig)
        .unwrap();
    assert_eq!(r2, EnrollResult::AlreadyEnrolled);
}

// ============================================================================
// Defense-in-depth negative test (CRIT-01) — a wrong pin must break the
// handshake regardless of what cert the peer presents.
// ============================================================================

#[test]
#[ignore = "E2E test: requires live Vultr relay + network"]
fn e2e_wrong_spki_pin_rejects_handshake() {
    // Obvious 32-byte zero pin — should never match any real cert.
    let wrong_pin_b64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    let verifier = PinnedCertVerifier::with_pin_b64(wrong_pin_b64).expect("wrong verifier");

    let config =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
            .with_no_client_auth();

    let http = reqwest::blocking::Client::builder()
        .use_preconfigured_tls(config)
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(15))
        .build()
        .unwrap();

    // The handshake MUST fail — that's the defense-in-depth property we're
    // asserting (wrong SPKI pin = connection refused). reqwest's error
    // message wording varies between versions (sometimes "tls", sometimes
    // just "error sending request"), so we only assert the failure itself.
    let err = http
        .get(format!("{BASE_URL}/auth/challenge"))
        .send()
        .expect_err("wrong SPKI pin MUST fail");
    // Sanity: the error must mention the URL we tried (proves reqwest did
    // attempt the connection, not some earlier config failure).
    let msg = err.to_string().to_lowercase();
    assert!(
        msg.contains(BASE_URL.trim_start_matches("https://"))
            || msg.contains("tls")
            || msg.contains("certificate")
            || msg.contains("handshake")
            || msg.contains("invalid")
            || msg.contains("sending request"),
        "wrong SPKI pin should surface a connection error, got: {err}"
    );
}
