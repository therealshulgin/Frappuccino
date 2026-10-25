//! Drift-detection lock-step test for the HKDF context strings used across
//! the V2 protocol: the six identity / ratchet contexts, then the report
//! contexts at the end of the file.
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
//! The six identity / ratchet digests were captured 2026-05-07 against
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

// ---------------------------------------------------------------------------
// Report contexts (`core/src/report.rs`, `core/src/report/chain.rs`).
//
// Same rule: changing one of these orphans reports already on the relay. The
// legacy ones derive every report written before a device migrated; the chained
// ones derive every report written after, and the rescue device re-derives both
// from the phrase. The chained derivation is also pinned end to end by the KAT
// in `tests/report_chain_kat.rs`.
// ---------------------------------------------------------------------------

#[test]
fn ctx_report_legacy_contexts_are_locked() {
    // Mirrors of `report.rs::CTX_REPORT_MASTER`, `CTX_REPORT_KEY`,
    // `CTX_REPORT_ID`, `CTX_REPORT_DIRECTORY`, `CTX_REPORT_DIR_ENTRY`.
    assert_locked(
        "CTX_REPORT_MASTER",
        b"stream.report.master.v1",
        "b6eae74bdaeb901fe170a5a0bc4739cfd0246fe5b0d44980134018cbfa747fe9",
    );
    assert_locked(
        "CTX_REPORT_KEY",
        b"stream.report.key.v1",
        "2a322e17f80a0c978e048b7a25169db1bef25503e79ad63f0c363073225b4426",
    );
    assert_locked(
        "CTX_REPORT_ID",
        b"stream.report.id.v1",
        "1e38957b1441ec1c2c64763c112db31c007c1f89bae46a73938e61c732fc3b72",
    );
    assert_locked(
        "CTX_REPORT_DIRECTORY",
        b"stream.report.directory.v1",
        "5e6d0bd69d9d6b3a942b5907adfdb996c9b886b6e02bbff652f9ffae571c3cc3",
    );
    assert_locked(
        "CTX_REPORT_DIR_ENTRY",
        b"stream.report.directory.entry.v1",
        "c212b0db0ddd5e23f500a3b1687070337c3a51448008c51f8d42c8702f3d6b06",
    );
}

#[test]
fn ctx_report_chain_contexts_are_locked() {
    // Mirrors of `report/chain.rs::CTX_CHAIN_*`.
    assert_locked(
        "CTX_CHAIN_ROOT",
        b"stream.report.chain.v2.root",
        "823f1fd455a7c12f7a6cd8d0298da79bcb79986e478592af652a01fd371fe1b4",
    );
    assert_locked(
        "CTX_CHAIN_NEXT",
        b"stream.report.chain.v2.next",
        "f515bfad364a09679c0263b9cb1c3bde7a62ac8422de6ff77b8c0c266532b555",
    );
    assert_locked(
        "CTX_CHAIN_KEY",
        b"stream.report.chain.v2.key",
        "416598d991c2968865fd4aa7ed4bac1b0012ffe219e24ed7ff5a965022d6b1bf",
    );
    assert_locked(
        "CTX_CHAIN_DIR_ENTRY",
        b"stream.report.chain.v2.directory-entry",
        "b53e0668187fa6a96ea6b5478b7d806feccb26905a88ef3c9438454da9881384",
    );
    assert_locked(
        "CTX_CHAIN_OTS_NAME",
        b"stream.report.chain.v2.ots-name",
        "77ae58cf5d6a2c6bc106a3e24a9f8e16bfe8ac665dbf993c20a446608c9384e4",
    );
}

#[test]
fn ctx_report_state_aad_is_locked() {
    // `CTX_STATE_AAD` is public (the FFI layer seals the state with it), so
    // check the runtime constant itself as well as its mirror.
    assert_eq!(
        frappuccino_crypto_core::report::CTX_STATE_AAD,
        b"frappuccino-report-state-v2"
    );
    assert_locked(
        "CTX_STATE_AAD",
        frappuccino_crypto_core::report::CTX_STATE_AAD,
        "12d8eff47986c8d6151bc4fe4a4c2a7dc16a9a5c9ddabc4a23132f1b7e7196c3",
    );
}
