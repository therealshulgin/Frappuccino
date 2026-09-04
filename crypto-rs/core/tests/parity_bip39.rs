//! Byte-exact parity tests for BIP-39 against the Kotlin reference implementation.
//!
//! Loads fixtures from `crypto-rs/parity-vectors/bip39/*.json` produced by
//! `ParityVectorsDumper` on a real Android device, and asserts that our Rust
//! implementation produces identical outputs.
//!
//! If any of these fail, either:
//!   1. The Kotlin impl changed an invariant (and we need to decide whether to
//!      follow — see `PLAN_RUST_EXEC.md` §1 for what's immutable), OR
//!   2. The Rust impl diverged (bug — fix it, don't regenerate vectors).

use frappuccino_crypto_core::bip39::{
    mnemonic_to_seed, normalize_phrase, normalize_word, Language,
};
use frappuccino_crypto_core::CryptoError;
use serde::Deserialize;
use std::fs;
use std::path::PathBuf;

fn vectors_dir() -> PathBuf {
    // CARGO_MANIFEST_DIR = crypto-rs/core/, parity-vectors = crypto-rs/parity-vectors/
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.push("parity-vectors");
    p
}

#[derive(Deserialize)]
struct SeedFile {
    #[allow(dead_code)]
    schema_version: u32,
    #[allow(dead_code)]
    description: String,
    #[allow(dead_code)]
    language: String,
    #[allow(dead_code)]
    algorithm: String,
    iterations: u32,
    seed_bytes: u32,
    cases: Vec<SeedCase>,
}

#[derive(Deserialize)]
struct SeedCase {
    mnemonic: String,
    passphrase: String,
    seed_hex: String,
}

#[derive(Deserialize)]
struct NormalizeFile {
    cases: Vec<NormalizeCase>,
}

#[derive(Deserialize)]
struct NormalizeCase {
    input: String,
    canonical: String,
}

#[derive(Deserialize)]
struct InvalidFile {
    invalid_words: Vec<InvalidWord>,
}

#[derive(Deserialize)]
struct InvalidWord {
    word: String,
}

#[test]
fn bip39_mnemonic_to_seed_matches_kotlin_fixtures() {
    let path = vectors_dir().join("bip39").join("seed.json");
    let raw = fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "Missing parity fixture at {}: {e}. Run ParityVectorsDumper on a device first (see PLAN_RUST_EXEC.md §5.1).",
            path.display()
        )
    });
    let file: SeedFile = serde_json::from_str(&raw).expect("seed.json must be valid JSON");

    // Sanity: our constants agree with what the Kotlin dumper captured.
    assert_eq!(file.iterations, 2048, "PBKDF2 iteration count contract");
    assert_eq!(file.seed_bytes, 64, "seed length contract");

    for (i, case) in file.cases.iter().enumerate() {
        let actual = mnemonic_to_seed(&case.mnemonic, &case.passphrase, Language::French)
            .unwrap_or_else(|e| panic!("case {i}: mnemonic_to_seed failed: {e:?}"));
        let expected = hex::decode(&case.seed_hex).expect("seed_hex must be valid hex");
        assert_eq!(
            &actual.as_bytes()[..],
            expected.as_slice(),
            "case {i}: mnemonic={:?} passphrase={:?}\n  expected: {}\n  actual:   {}",
            case.mnemonic,
            case.passphrase,
            case.seed_hex,
            hex::encode(actual.as_bytes()),
        );
    }
}

#[test]
fn bip39_normalize_phrase_matches_kotlin_fixtures() {
    let path = vectors_dir().join("bip39").join("normalize.json");
    let raw =
        fs::read_to_string(&path).unwrap_or_else(|e| panic!("Missing {}: {e}", path.display()));
    let file: NormalizeFile = serde_json::from_str(&raw).unwrap();
    for (i, case) in file.cases.iter().enumerate() {
        // `normalize_phrase` now returns `Zeroizing<String>` (no `PartialEq`);
        // compare/format via the deref.
        let actual = normalize_phrase(&case.input, Language::French).unwrap();
        assert_eq!(
            *actual, case.canonical,
            "case {i}: input={:?}\n  expected: {}\n  actual:   {}",
            case.input, case.canonical, *actual
        );
    }
}

#[test]
fn bip39_normalize_word_rejects_invalid_matches_kotlin_fixtures() {
    let path = vectors_dir().join("bip39").join("normalize-invalid.json");
    let raw =
        fs::read_to_string(&path).unwrap_or_else(|e| panic!("Missing {}: {e}", path.display()));
    let file: InvalidFile = serde_json::from_str(&raw).unwrap();
    for case in file.invalid_words {
        let err = normalize_word(&case.word, Language::French).unwrap_err();
        assert!(
            matches!(err, CryptoError::InvalidMnemonicWord { .. }),
            "word={:?} expected InvalidMnemonicWord, got {err:?}",
            case.word
        );
    }
}
