//! Fuzz target: `core::ratchet::EphemeralRatchet::deserialize(blob)`.
//!
//! Goal: no panic on any `blob: &[u8]`. The ratchet blob format has two
//! versions (V1 legacy, 4844 bytes no MAC; V2 current, 4876 bytes with
//! HMAC-SHA256). Corner cases we want libfuzzer to reach:
//!
//!   * version byte validation
//!   * `consumed_mask` LSB/MSB alignment
//!   * 50 × (pk || sk) section boundaries
//!   * MAC tag position + length arithmetic
//!   * constant-time MAC equality
//!
//! All four failure modes (`WrongVersion`, `InvalidBlob`, `InvalidSignature`,
//! `Core(AlreadyConsumed)`) are expected — only a panic is a bug.

#![no_main]

use frappuccino_crypto_core::ratchet::EphemeralRatchet;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = EphemeralRatchet::deserialize(data);
});
