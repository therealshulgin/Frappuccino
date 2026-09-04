//! `frappuccino-crypto-core` — pure-Rust cryptographic primitives for Frappuccino.
//!
//! Sprint progress per [`PLAN_RUST_EXEC.md`](../../../PLAN_RUST_EXEC.md):
//!
//! - **S1 (done): [`bip39`]** — mnemonic generation, normalization, seed derivation
//! - **S2 (done): [`hkdf`], [`secret`]** — HKDF-SHA256 helper + `SecretBytes` / `LockedSecret`
//! - **S3 (done): [`identity`]** — `StreamIdentity`, `EnrollmentKit`, `ArchiveIdentity`
//! - **S4 (done): [`pin_store`]** — Argon2id + XChaCha20-Poly1305 sealed blobs
//! - **S5 (done): [`ratchet`]** — Ephemeral Ed25519 ratchet (V2 blob with HMAC-SHA256)
//!
//! All invariants (HKDF context strings, Argon2id params, blob layouts) are
//! documented in `PLAN_RUST_EXEC.md §1` and MUST remain byte-exact with the
//! Kotlin reference implementation in `stream-crypto/`.

pub mod bip39;
pub mod error;
pub mod hkdf;
pub mod identity;
pub mod pin_store;
pub mod provenance;
pub mod ratchet;
pub mod report;
pub mod seal;
pub mod secret;
pub mod signature_domain;

pub use error::CryptoError;

/// Library version string returned to the FFI layer for smoke-testing.
#[must_use]
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_non_empty() {
        assert!(!version().is_empty());
    }
}
