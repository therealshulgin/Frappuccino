//! Fuzz target: `stream::decrypt::decrypt(blob, &archive)`.
//!
//! Goal: no panic for any `blob: &[u8]`, regardless of length or contents.
//! The archive is a fixed valid identity so the fuzzer only exercises the
//! blob parser / AEAD path — not the `ArchiveIdentity::from_mnemonic` path
//! (covered by `fuzz_pin_store_open` via a cousin code path).
//!
//! Entry points reached:
//!   * header bounds check
//!   * magic / version validation
//!   * grant_count arithmetic
//!   * sealed-envelope unsealing (wrong pin) → `WrongPin`
//!   * SINGLE + CHUNKED body parsing (cursor arithmetic, MAX_CHUNK_* caps)
//!   * XChaCha20-Poly1305 tag verification
//!
//! `WrongPin` / `Malformed` / `Core(AlreadyConsumed)` are expected failure
//! modes — only an actual panic from inside the decoder is a bug.

#![no_main]

use std::sync::OnceLock;

use frappuccino_crypto_core::identity::ArchiveIdentity;
use frappuccino_crypto_stream::decrypt::decrypt;
use libfuzzer_sys::fuzz_target;

// Rebuilding the ArchiveIdentity once per call would waste BIP-39 +
// HKDF work on every iteration — we'd fuzz the mnemonic pipeline, not
// the decoder. Initialise once and reuse.
static ARCHIVE: OnceLock<ArchiveIdentity> = OnceLock::new();

fn archive() -> &'static ArchiveIdentity {
    ARCHIVE.get_or_init(|| {
        // Canonical fixture mnemonic used across parity-vectors/*.json.
        let mn = "abaisser abandon abdiquer abeille abolir aborder aboutir aboyer abrasif abreuver abriter abroger";
        ArchiveIdentity::from_mnemonic(mn, "").expect("fixture archive identity")
    })
}

fuzz_target!(|data: &[u8]| {
    // We don't care about Ok vs Err: the invariant is "no panic". A small
    // percentage of random bytes may happen to parse as a structurally
    // valid blob that still fails AEAD — all expected outcomes.
    let _ = decrypt(data, archive());
});
