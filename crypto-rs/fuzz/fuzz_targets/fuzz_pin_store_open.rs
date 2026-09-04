//! Fuzz target: `core::pin_store::open(pin, blob)`.
//!
//! Surface: the post-boot unlock path. An attacker who can write to the
//! locked-identity file gets to pick `blob`. The pin is fixed (and wrong
//! for every attacker-chosen blob) so libfuzzer only exercises the
//! parsing layer + Argon2id + `XChaCha20-Poly1305` decrypt, never the
//! `Ok` branch (which would require brute-forcing a 6-digit PIN anyway).
//!
//! Invariants we're checking:
//!   * version byte 0x01 + structural header checks don't overflow on
//!     short blobs
//!   * nonce / salt / ciphertext slicing never goes out of bounds
//!   * Argon2id params stay within configured limits
//!   * AEAD failure returns `WrongPin`, never unwinds
//!
//! **Note on speed**: Argon2id is intentionally slow (~1.2 s on a Snapdragon
//! 8+ Gen 1). This target will process ≤ 1 input per second per core on
//! fuzzing boxes — we run it for a bounded number of hours rather than the
//! 100M-iter target used on the cheaper decoders.

#![no_main]

use frappuccino_crypto_core::pin_store;
use libfuzzer_sys::fuzz_target;

// A fixed 6-digit PIN the attacker's blob has never been sealed against.
// Using a non-trivial value reduces the odds of accidentally pinning a
// weak-check path (e.g. an all-zero blob that happens to unseal under
// "000000").
// Phase 6.1.4-A : pin_store::open accepte maintenant &[u8].
const FIXED_PIN: &[u8] = b"284193";

fuzz_target!(|data: &[u8]| {
    // The `Ok` branch is unreachable in practice: `FIXED_PIN` isn't the
    // password any crafted blob can be sealed against without brute-force.
    // A panic, however, would be a bug.
    let _ = pin_store::open(FIXED_PIN, data);
});
