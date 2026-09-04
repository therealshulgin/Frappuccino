//! Differential-fuzz corpus dumper — ROADMAP 8.4 item 3 ("diff-fuzz Kotlin<->Rust").
//!
//! Emits a deterministic JSONL corpus to stdout: one line per test case,
//! `{"api", "args":[hex...], "outcome":{...}}`. Each line records the REFERENCE
//! outcome of calling the FFI-layer function (`frappuccino_crypto_ffi::*`)
//! DIRECTLY in Rust. The Kotlin/JVM harness replays the same `args` through the
//! generated UniFFI bindings (Kotlin -> JNA -> the same Rust fn) and diffs its
//! outcome against `outcome`:
//!   * a divergent value / error variant = a marshalling bug in the glue;
//!   * a JVM crash instead of an `FfiException` = an uncaught Rust panic
//!     crossing the boundary (must be impossible — see `panic = "unwind"`).
//!
//! Scope: the deterministic, raw-bytes-in APIs — i.e. the untrusted-input ->
//! marshalling -> Rust-parse surface flagged by audits 8.1: bip39 validate,
//! identity from public keys, ratchet deserialize round-trip, pin-store open,
//! archive identity from mnemonic. (Randomised APIs like `strm_encrypt` /
//! `pin_store_seal` need a round-trip oracle — a follow-up corpus mode.)
//!
//! Usage: `frappuccino-difffuzz-dump [seed] [cases_per_api] > corpus.jsonl`

// Tooling bin: the splitmix64 byte extraction is mask-bounded; allow the cast
// rather than wrapping every draw in try_from.
#![allow(clippy::cast_possible_truncation)]
// The module prose is full of technical tokens (JSONL, JNA, UniFFI, FFI, ...);
// backticking each is noise for a tooling bin.
#![allow(clippy::doc_markdown)]

use std::sync::Arc;

// The ffi crate's lib name is `uniffi_frappuccino` (see its `[lib] name`),
// which is how it's imported even though the package is `frappuccino-crypto-ffi`.
use serde_json::{json, Value};
use uniffi_frappuccino::{
    self as ffi, ArchiveIdentity, EnrollmentKit, EphemeralRatchet, FfiError, StreamIdentity,
};

/// Known-good 12-word FR mnemonic (same vector used by the parity tests).
const VALID_MNEMONIC: &[u8] = b"abaisser abandon abdiquer abeille abolir aborder aboutir aboyer abrasif abreuver abriter abroger";

/// Deterministic splitmix64 PRNG — same seed reproduces the same corpus, so a
/// failing case is replayable. The corpus inputs are written to the file, so
/// the Kotlin harness never needs to reproduce this stream.
#[derive(Debug)]
struct Rng(u64);

impl Rng {
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// Uniform-ish draw in `0..n` (n > 0).
    fn below(&mut self, n: u64) -> u64 {
        self.next_u64() % n
    }

    fn bytes(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| (self.next_u64() & 0xff) as u8).collect()
    }

    /// Pick one element of `choices` (non-empty).
    fn pick<'a, T>(&mut self, choices: &'a [T]) -> &'a T {
        &choices[self.below(choices.len() as u64) as usize]
    }
}

/// Stable `(variant, detail)` projection of an `FfiError`. We compare the FIELD
/// values (which UniFFI marshals verbatim across the boundary), NOT the Display
/// string — Rust `thiserror` and the Kotlin-generated `toString` render
/// independently and would diverge for non-marshalling reasons.
fn err_repr(e: &FfiError) -> (&'static str, String) {
    match e {
        FfiError::InvalidMnemonicWord { word, language } => {
            ("InvalidMnemonicWord", format!("{word}|{language}"))
        }
        FfiError::InvalidMnemonic { detail } => ("InvalidMnemonic", detail.clone()),
        FfiError::DerivationFailed { detail } => ("DerivationFailed", detail.clone()),
        FfiError::EmptyInput => ("EmptyInput", String::new()),
        FfiError::AlreadyConsumed { resource } => ("AlreadyConsumed", resource.clone()),
        FfiError::InvalidSignature => ("InvalidSignature", String::new()),
        FfiError::WrongPin => ("WrongPin", String::new()),
        FfiError::InvalidBlob { detail } => ("InvalidBlob", detail.clone()),
        FfiError::Network { detail } => ("Network", detail.clone()),
        FfiError::Internal { detail } => ("Internal", detail.clone()),
        FfiError::Io { detail } => ("Io", detail.clone()),
    }
}

fn err_val(e: &FfiError) -> Value {
    let (variant, detail) = err_repr(e);
    json!({ "tag": "err", "variant": variant, "detail": detail })
}

fn ok_bytes(b: &[u8]) -> Value {
    json!({ "tag": "ok_bytes", "value": hex::encode(b) })
}

fn ok_str(s: &str) -> Value {
    json!({ "tag": "ok_str", "value": s })
}

fn ok_void() -> Value {
    json!({ "tag": "ok_void" })
}

// `outcome` is built fresh per call and logically consumed here; the by-value
// signature reads cleaner than threading a reference through the `case_*` fns.
#[allow(clippy::needless_pass_by_value)]
fn emit(api: &str, args: &[&[u8]], outcome: Value) {
    let args_hex: Vec<String> = args.iter().map(hex::encode).collect();
    println!(
        "{}",
        json!({ "api": api, "args": args_hex, "outcome": outcome })
    );
}

// ---------------------------------------------------------------------------
// Per-API case emission. Each mirrors exactly what the Kotlin harness will do.
// ---------------------------------------------------------------------------

fn case_bip39_validate(input: &[u8]) {
    let outcome = match ffi::bip39_validate_fr(input) {
        Ok(()) => ok_void(),
        Err(e) => err_val(&e),
    };
    emit("bip39_validate_fr", &[input], outcome);
}

fn case_identity_fingerprint(ed: &[u8], x: &[u8]) {
    // Kotlin: StreamIdentity.fromPublicKeys(ed, x).readableFingerprint().
    let outcome = match StreamIdentity::from_public_keys(ed, x) {
        Ok(id) => ok_str(&id.readable_fingerprint()),
        Err(e) => err_val(&e),
    };
    emit("identity_fingerprint", &[ed, x], outcome);
}

fn case_ratchet_roundtrip(blob: &[u8]) {
    // deserialize then re-serialize (both deterministic).
    let outcome = match EphemeralRatchet::deserialize(blob) {
        Ok(r) => match r.serialize() {
            Ok(b) => ok_bytes(&b),
            Err(e) => err_val(&e),
        },
        Err(e) => err_val(&e),
    };
    emit("ratchet_deserialize_serialize", &[blob], outcome);
}

fn case_pin_open(pin: &[u8], blob: &[u8]) {
    let outcome = match ffi::pin_store_open(pin, blob) {
        Ok(pt) => ok_bytes(&pt),
        Err(e) => err_val(&e),
    };
    emit("pin_store_open", &[pin, blob], outcome);
}

fn case_archive_from_mnemonic(mn: &[u8], pass: &[u8]) {
    let outcome = match ArchiveIdentity::from_mnemonic(mn, pass) {
        Ok(a) => ok_str(&a.identity().ed25519_pk_hex()),
        Err(e) => err_val(&e),
    };
    emit("archive_from_mnemonic", &[mn, pass], outcome);
}

fn main() {
    let mut argv = std::env::args().skip(1);
    let seed: u64 = argv
        .next()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0x5EED_2026);
    let per: usize = argv.next().and_then(|s| s.parse().ok()).unwrap_or(150);
    let mut rng = Rng(seed);

    // --- Reference valid material (computed once) -------------------------
    // A real V2 ratchet blob (pure HKDF derivation, no Argon2).
    let kit = Arc::new(EnrollmentKit::from_mnemonic(VALID_MNEMONIC, b"").expect("valid kit"));
    let id = kit.identity().expect("identity");
    let real_ed = id.ed25519_pk();
    let real_x = id.x25519_pk();
    let ratchet = EphemeralRatchet::from_kit(kit).expect("ratchet from kit");
    let valid_ratchet_blob = ratchet.serialize().expect("serialize ratchet");
    // A real pin-store blob (one Argon2id ~1 s, reused for many open cases).
    let valid_pin: &[u8] = b"1234";
    let secret_pt: &[u8] = b"top-secret ratchet state bytes";
    let valid_pin_blob = ffi::pin_store_seal(valid_pin, secret_pt).expect("seal");

    // --- bip39_validate_fr ----------------------------------------------
    case_bip39_validate(VALID_MNEMONIC); // Ok(())
    case_bip39_validate(b""); // empty
    for _ in 0..per {
        let len = rng.below(40) as usize;
        let input = rng.bytes(len);
        case_bip39_validate(&input);
    }

    // --- identity_fingerprint -------------------------------------------
    case_identity_fingerprint(&real_ed, &real_x); // Ok(fingerprint)
    let pk_lens = [0usize, 16, 31, 32, 33, 64];
    for _ in 0..per {
        let ed_len = *rng.pick(&pk_lens);
        let ed = rng.bytes(ed_len);
        let x_len = *rng.pick(&pk_lens);
        let x = rng.bytes(x_len);
        case_identity_fingerprint(&ed, &x);
    }

    // --- ratchet_deserialize_serialize ----------------------------------
    case_ratchet_roundtrip(&valid_ratchet_blob); // Ok(re-serialized)
                                                 // A 1-byte-flipped valid blob → WrongPin (MAC) or InvalidBlob.
    {
        let mut tampered = valid_ratchet_blob.clone();
        if !tampered.is_empty() {
            let i = rng.below(tampered.len() as u64) as usize;
            tampered[i] ^= 0x01;
        }
        case_ratchet_roundtrip(&tampered);
    }
    let blob_lens = [0usize, 1, 44, 100, 4844, 4875, 4876, 4877, 8192];
    for _ in 0..per {
        let len = *rng.pick(&blob_lens);
        let blob = rng.bytes(len);
        case_ratchet_roundtrip(&blob);
    }

    // --- pin_store_open --------------------------------------------------
    case_pin_open(valid_pin, &valid_pin_blob); // Ok(secret_pt)
    case_pin_open(b"9999", &valid_pin_blob); // WrongPin
    case_pin_open(b"", &valid_pin_blob); // empty pin
    for _ in 0..per {
        let pin_len = 1 + rng.below(8) as usize;
        let pin = rng.bytes(pin_len);
        let blob_len = rng.below(200) as usize;
        let blob = rng.bytes(blob_len);
        case_pin_open(&pin, &blob);
    }

    // --- archive_from_mnemonic ------------------------------------------
    case_archive_from_mnemonic(VALID_MNEMONIC, b""); // Ok(pk_hex)
    for _ in 0..per {
        let len = rng.below(48) as usize;
        let mn = rng.bytes(len);
        case_archive_from_mnemonic(&mn, b"");
    }
}
