//! Drift-detection lock-step test for the six HKDF context strings used
//! across the V2 protocol.
//!
//! `AUDIT_SCOPE_RUST.md §4` lists these constants as **immutable invariants**:
//! changing any byte invalidates every previously-derived identity / ratchet
//! state on every device that already enrolled. There is no migration path —
//! the chain key + slot keys would all rederive into different bytes, the
//! server would reject the new public keys as "unknown identity", and the
//! user would have to start from scratch.
//!
//! The constants live in two private module statics
//! (`identity::CTX_*` and `ratchet::CTX_*`) so they aren't accessible from
//! integration tests. Rather than refactor them into a public surface (which
//! would invite *more* casual modification, the opposite of what we want),
//! this test mirrors the byte literals here and asserts their SHA-256
//! against hex digests committed at audit time.
//!
//! Drift behaviours:
//!  - **Runtime constant changed, test not updated**: parity tests
//!    (`parity_strm`, `parity_ratchet`) immediately fail because the Kotlin
//!    fixtures derive different bytes; this is the primary alarm.
//!  - **Runtime constant changed, test updated to match**: this file shows a
//!    diff in source review with both the byte literal and the SHA-256
//!    digest changing — caught at code-review time, never silently.
//!
//! The 6 SHA-256 digests below were captured 2026-05-07 against
//! frappuccino-crypto-core 0.1.0 commit fbcab3e.

use sha2::{Digest, Sha256};

fn assert_locked(label: &str, ctx: &[u8], expected_hex: &str) {
    let got = hex::encode(Sha256::digest(ctx));
    assert_eq!(
        got, expected_hex,
        "HKDF context drift on `{label}`: SHA-256 = {got}, expected {expected_hex}. \
         Changing this value orphans every enrolled identity — abort and revert."
    );
}

#[test]
fn ctx_identity_ed25519_v1_is_locked() {
    // Mirror of `crypto-rs/core/src/identity.rs::CTX_IDENTITY`.
    assert_locked(
        "CTX_IDENTITY",
        b"stream.identity.ed25519.v1",
        "9979baf1fb2de7b5c8b741cb3261f0137ff1c596216b477fbcc5a7ddae3b95fc",
    );
}

#[test]
fn ctx_encryption_x25519_v1_is_locked() {
    // Mirror of `crypto-rs/core/src/identity.rs::CTX_ENCRYPTION`.
    assert_locked(
        "CTX_ENCRYPTION",
        b"stream.encryption.x25519.v1",
        "3d425cc5aa1143a4ccd82732f9cfd0ede89f4141acbda7fdc6bd8d3b1271d19b",
    );
}

#[test]
fn ctx_ratchet_chain0_v2_is_locked() {
    // Mirror of `crypto-rs/core/src/identity.rs::CTX_CHAIN0`.
    assert_locked(
        "CTX_CHAIN0",
        b"stream.ratchet.chain0.v2",
        "b061687c3a5a5aa4be498c25c91c5f9d95b12ab6867f08e6883a58fc6495db42",
    );
}

#[test]
fn ctx_ratchet_batch_seeds_is_locked() {
    // Mirror of `crypto-rs/core/src/ratchet.rs::CTX_BATCH_SEEDS`.
    assert_locked(
        "CTX_BATCH_SEEDS",
        b"frappuccino-v2-ratchet-batch-seeds",
        "f24fcdb23440f121c94e588d89b98c6e8afe8c4dc9b7dc1fee6050db9fae71b6",
    );
}

#[test]
fn ctx_ratchet_next_chain_is_locked() {
    // Mirror of `crypto-rs/core/src/ratchet.rs::CTX_NEXT_CHAIN`.
    assert_locked(
        "CTX_NEXT_CHAIN",
        b"frappuccino-v2-ratchet-next-chain",
        "a8dd597afba2ba7cda868d3feb51fed151a23e2a1b9fd26e3d772dbb7b6c01ad",
    );
}

#[test]
fn ctx_ratchet_blob_mac_is_locked() {
    // Mirror of `crypto-rs/core/src/ratchet.rs::CTX_BLOB_MAC`.
    assert_locked(
        "CTX_BLOB_MAC",
        b"frappuccino-v2-ratchet-blob-mac",
        "d4169ab1eab2ae05a797a7ccc64d8da10809f53c53a9e3c1559da514f4403891",
    );
}
