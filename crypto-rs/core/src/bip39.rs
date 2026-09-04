//! BIP-39 French wordlist support — byte-exact with the Kotlin reference impl.
//!
//! ## Invariants (must match `stream-crypto/.../Bip39.kt` verbatim)
//!
//! | Constant | Value |
//! |---|---|
//! | `WORD_COUNT` | 12 |
//! | `ENTROPY_BITS` | 128 |
//! | `ENTROPY_BYTES` | 16 |
//! | `CHECKSUM_BITS` | 4 |
//! | `PBKDF2_ITERATIONS` | 2048 |
//! | `SEED_BYTES` | 64 |
//! | Algorithm (seed) | PBKDF2-HMAC-SHA512 |
//! | Salt prefix | `"mnemonic"` (UTF-8) |
//! | Normalization | NFD → strip combining marks → lowercase → lookup in stripped→canonical map |
//!
//! ## BT-HIGH-10 remediation
//!
//! `normalize_word` **throws** on unknown words (returns `Err`), matching the
//! Kotlin implementation post-remediation. No silent fallback to avoid typos
//! producing a "typo seed" that's valid-looking but irrecoverable.

use crate::error::CryptoError;
use hmac::Hmac;
use sha2::{Digest, Sha256, Sha512};
use std::fmt;
use unicode_normalization::{char::is_combining_mark, UnicodeNormalization};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Number of words in a canonical BIP-39 mnemonic (Frappuccino uses 12).
pub const WORD_COUNT: usize = 12;
/// Bits of entropy in a 12-word mnemonic.
pub const ENTROPY_BITS: usize = 128;
/// Bytes of entropy = 16.
pub const ENTROPY_BYTES: usize = ENTROPY_BITS / 8;
/// Checksum bits appended to the entropy (128 / 32 = 4).
pub const CHECKSUM_BITS: usize = ENTROPY_BITS / 32;
/// PBKDF2 iteration count (BIP-39 standard).
pub const PBKDF2_ITERATIONS: u32 = 2048;
/// Output seed size (bytes).
pub const SEED_BYTES: usize = 64;

/// 64-byte BIP-39 seed, produced by [`mnemonic_to_seed`].
///
/// Newtype wrapper (per `Rust_guidelines.md`: "typed wrappers for byte buffers,
/// not raw `[u8; N]`") that guarantees:
///   * zero-on-drop — the inner array is wiped when the value goes out of scope,
///   * redacted Debug — `println!("{seed:?}")` prints `Seed(<64-byte redacted>)`
///     rather than leaking seed bytes into logs or error messages,
///   * `#[must_use]` — accidental `let _ = mnemonic_to_seed(...)` is flagged.
///
/// Expose inner bytes via [`Seed::as_bytes`] only when you actually need them
/// (e.g., to feed HKDF). Never clone unless you own the new copy's lifecycle.
#[derive(ZeroizeOnDrop)]
#[must_use]
pub struct Seed([u8; SEED_BYTES]);

impl Seed {
    /// Read-only view of the seed bytes. Caller must not copy out lightly.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; SEED_BYTES] {
        &self.0
    }

    /// Length in bytes (always [`SEED_BYTES`]).
    #[must_use]
    pub const fn len(&self) -> usize {
        SEED_BYTES
    }

    /// Always `false` — a `Seed` is a fixed 64-byte array.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        false
    }
}

impl fmt::Debug for Seed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Seed(<{SEED_BYTES}-byte redacted>)")
    }
}

/// BIP-39 language selector. French is the Frappuccino default — enrolled
/// identities were generated in FR and can't migrate without losing archives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Language {
    French,
}

impl Language {
    /// The name embedded in `CryptoError::InvalidMnemonicWord.language`.
    pub const fn name(self) -> &'static str {
        match self {
            Language::French => "fr",
        }
    }

    /// Returns the 2048-word BIP-39 wordlist for this language.
    pub fn wordlist(self) -> &'static [&'static str] {
        match self {
            Language::French => fr::wordlist_fr(),
        }
    }
}

/// Returns a stripped-accents lowercase form of `s` (NFD + remove combining marks).
/// Not a constant-time operation — only used on public BIP-39 wordlist entries
/// and user input (not on secret material).
#[must_use]
pub fn strip_accents(s: &str) -> String {
    s.nfd().filter(|c| !is_combining_mark(*c)).collect()
}

/// Normalize a single user-typed word to its canonical BIP-39 form.
///
/// Strips accents, lowercases, and looks up in the language's stripped→canonical
/// map. Unknown words return `Err(InvalidMnemonicWord)` — **no silent fallback**
/// (BT-HIGH-10).
///
/// # Errors
/// - [`CryptoError::EmptyInput`] if `input` is empty or whitespace-only after trim.
/// - [`CryptoError::InvalidMnemonicWord`] if the stripped lowercase form is not
///   in the wordlist.
pub fn normalize_word(input: &str, lang: Language) -> Result<String, CryptoError> {
    let trimmed = input.trim().to_lowercase();
    if trimmed.is_empty() {
        return Err(CryptoError::EmptyInput);
    }
    let stripped_input = strip_accents(&trimmed);
    for &canonical in lang.wordlist() {
        if strip_accents(&canonical.to_lowercase()) == stripped_input {
            return Ok(canonical.to_string());
        }
    }
    Err(CryptoError::InvalidMnemonicWord {
        word: trimmed,
        language: lang.name(),
    })
}

/// Normalize a full mnemonic phrase word-by-word.
///
/// Splits on any whitespace, normalizes each word, joins with a single space.
///
/// # Errors
/// Any word-level [`CryptoError::InvalidMnemonicWord`] short-circuits.
pub fn normalize_phrase(input: &str, lang: Language) -> Result<Zeroizing<String>, CryptoError> {
    // Accumulate into a `Zeroizing` buffer so the fully-assembled canonical
    // phrase — the root secret — is wiped on drop, and wipe each per-word
    // `String` too (the previous `Vec<String>` + `join` left both un-wiped on
    // the heap). Symmetric with `salt.zeroize()` and the `Seed` ZeroizeOnDrop
    // in `mnemonic_to_seed`. Deref makes the return a drop-in for `String`.
    let mut acc = Zeroizing::new(String::new());
    let mut first = true;
    for w in input.split_whitespace() {
        let word = Zeroizing::new(normalize_word(w, lang)?);
        if !first {
            acc.push(' ');
        }
        acc.push_str(word.as_str());
        first = false;
    }
    Ok(acc)
}

/// Derive a 64-byte BIP-39 seed from a mnemonic + optional passphrase.
///
/// - Normalizes the mnemonic first (so users can type without accents).
/// - Salt = `"mnemonic" || passphrase` (UTF-8 bytes, per BIP-39 spec).
/// - PBKDF2-HMAC-SHA512 with 2048 iterations.
///
/// Returns a [`Seed`] (zero-on-drop, redacted Debug) — the caller owns the
/// lifecycle and must not clone the inner bytes except through [`Seed::as_bytes`].
///
/// # Errors
/// If the mnemonic contains unknown words, returns [`CryptoError::InvalidMnemonicWord`].
pub fn mnemonic_to_seed(
    mnemonic: &str,
    passphrase: &str,
    lang: Language,
) -> Result<Seed, CryptoError> {
    let normalized = normalize_phrase(mnemonic, lang)?;

    let mut salt: Vec<u8> = Vec::with_capacity(8 + passphrase.len());
    salt.extend_from_slice(b"mnemonic");
    salt.extend_from_slice(passphrase.as_bytes());

    let mut seed_bytes = [0u8; SEED_BYTES];
    pbkdf2::pbkdf2::<Hmac<Sha512>>(
        normalized.as_bytes(),
        &salt,
        PBKDF2_ITERATIONS,
        &mut seed_bytes,
    )
    .map_err(|e| CryptoError::DerivationFailed(e.to_string()))?;

    // Zeroize salt bytes (contains passphrase which is secret material).
    salt.zeroize();
    Ok(Seed(seed_bytes))
}

/// Generate a 12-word mnemonic from 128 bits of cryptographic entropy.
///
/// Returns a [`Zeroizing<String>`] — the heap buffer is wiped when the
/// wrapper drops. Callers should avoid `.to_string()` / `.clone()` on
/// this value, which would bypass the zeroization guarantee.
#[must_use]
pub fn from_entropy(entropy: &[u8; ENTROPY_BYTES], lang: Language) -> Zeroizing<String> {
    let wordlist = lang.wordlist();
    // Compute 4-bit checksum from SHA-256(entropy)[0..1] shifted to top 4 bits.
    let hash = Sha256::digest(entropy);
    let checksum_byte = hash[0];

    // Build a 132-bit stream of (entropy || checksum_bits) as a vec of bool-like bits.
    // BIP-39: entropy big-endian, checksum bits = top CHECKSUM_BITS of hash[0].
    let mut bits = Zeroizing::new([false; ENTROPY_BITS + CHECKSUM_BITS]);
    for (byte_idx, &b) in entropy.iter().enumerate() {
        for bit_idx in 0..8 {
            bits[byte_idx * 8 + bit_idx] = (b >> (7 - bit_idx)) & 1 == 1;
        }
    }
    for bit_idx in 0..CHECKSUM_BITS {
        bits[ENTROPY_BITS + bit_idx] = (checksum_byte >> (7 - bit_idx)) & 1 == 1;
    }

    // Encode 12 × 11-bit indices.
    let mut out: Vec<&str> = Vec::with_capacity(WORD_COUNT);
    for word_idx in 0..WORD_COUNT {
        let mut value: usize = 0;
        for bit_idx in 0..11 {
            value = (value << 1) | usize::from(bits[word_idx * 11 + bit_idx]);
        }
        out.push(wordlist[value]);
    }
    Zeroizing::new(out.join(" "))
}

/// Fill `out` with fresh entropy from the OS CSPRNG.
///
/// Wrapper over `rand_core::OsRng` so callers don't need to thread the RNG type.
pub fn fresh_entropy(out: &mut [u8; ENTROPY_BYTES]) {
    use rand_core::RngCore;
    rand_core::OsRng.fill_bytes(out);
}

/// Generate a fresh FR mnemonic from OS entropy.
///
/// Convenience wrapper over [`fresh_entropy`] + [`from_entropy`]. Returns a
/// [`Zeroizing<String>`] that wipes its heap buffer on drop.
#[must_use]
pub fn generate_fr() -> Zeroizing<String> {
    let mut entropy = [0u8; ENTROPY_BYTES];
    fresh_entropy(&mut entropy);
    let mnemonic = from_entropy(&entropy, Language::French);
    entropy.zeroize();
    mnemonic
}

/// Validate that a mnemonic string has the correct word count AND checksum.
/// Used by the parity tests; not typically invoked in production paths that
/// go straight to [`mnemonic_to_seed`].
///
/// # Errors
/// Returns `Err` for: wrong word count, unknown word, checksum mismatch.
pub fn validate(mnemonic: &str, lang: Language) -> Result<(), CryptoError> {
    let normalized = normalize_phrase(mnemonic, lang)?;
    let words: Vec<&str> = normalized.split_whitespace().collect();
    if words.len() != WORD_COUNT {
        return Err(CryptoError::InvalidMnemonic(format!(
            "expected {WORD_COUNT} words, got {}",
            words.len()
        )));
    }
    let wordlist = lang.wordlist();

    // Map each word → index in wordlist.
    let mut indices: Vec<usize> = Vec::with_capacity(WORD_COUNT);
    for w in &words {
        let idx = wordlist.iter().position(|cw| cw == w).ok_or_else(|| {
            CryptoError::InvalidMnemonicWord {
                word: (*w).to_string(),
                language: lang.name(),
            }
        })?;
        indices.push(idx);
    }

    // Reassemble bit stream.
    let mut bits = Zeroizing::new([false; ENTROPY_BITS + CHECKSUM_BITS]);
    for (word_idx, &i) in indices.iter().enumerate() {
        for bit_idx in 0..11 {
            bits[word_idx * 11 + bit_idx] = (i >> (10 - bit_idx)) & 1 == 1;
        }
    }
    let mut entropy = Zeroizing::new([0u8; ENTROPY_BYTES]);
    for byte_idx in 0..ENTROPY_BYTES {
        let mut v: u8 = 0;
        for bit_idx in 0..8 {
            v = (v << 1) | u8::from(bits[byte_idx * 8 + bit_idx]);
        }
        entropy[byte_idx] = v;
    }
    let checksum_byte = Sha256::digest(*entropy)[0];
    for bit_idx in 0..CHECKSUM_BITS {
        let expected = (checksum_byte >> (7 - bit_idx)) & 1 == 1;
        if expected != bits[ENTROPY_BITS + bit_idx] {
            return Err(CryptoError::InvalidMnemonic("checksum mismatch".into()));
        }
    }
    Ok(())
}

/// French BIP-39 wordlist (2048 words). Embedded verbatim from
/// `stream-crypto/src/main/resources/bip39_fr.txt` — any diff breaks wire
/// compatibility with the Kotlin impl.
mod fr {
    use std::sync::OnceLock;

    static WORDS_FR: &str = include_str!("bip39_fr.txt");
    static WORDLIST: OnceLock<Vec<&'static str>> = OnceLock::new();

    pub fn wordlist_fr() -> &'static [&'static str] {
        WORDLIST.get_or_init(|| {
            let words: Vec<&'static str> =
                WORDS_FR.lines().filter(|line| !line.is_empty()).collect();
            assert_eq!(
                words.len(),
                2048,
                "BIP-39 FR wordlist must have exactly 2048 words, got {}",
                words.len()
            );
            words
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wordlist_is_2048() {
        assert_eq!(Language::French.wordlist().len(), 2048);
        assert_eq!(Language::French.wordlist()[0], "abaisser");
        assert_eq!(Language::French.wordlist()[1], "abandon");
    }

    #[test]
    fn normalize_word_canonical_from_stripped() {
        // The FR wordlist is stored in NFD (decomposed) form, so the canonical
        // return is also NFD — "acade" + U+0301 COMBINING ACUTE + "mie" rather
        // than "académie" as a single precomposed U+00E9 codepoint. This matches
        // the Kotlin reference which reads the file verbatim.
        let out = normalize_word("academie", Language::French).unwrap();
        assert_eq!(out, "acade\u{301}mie");

        assert_eq!(
            normalize_word("ABANDON", Language::French).unwrap(),
            "abandon"
        );
    }

    #[test]
    fn normalize_word_unknown_throws() {
        let err = normalize_word("xyz", Language::French).unwrap_err();
        assert!(matches!(err, CryptoError::InvalidMnemonicWord { .. }));
    }

    #[test]
    fn normalize_phrase_whitespace_collapsed() {
        let out = normalize_phrase(
            "  abaisser   abandon  abdiquer abeille abolir aborder aboutir aboyer abrasif abreuver abriter abroger  ",
            Language::French,
        )
        .unwrap();
        // `out` is `Zeroizing<String>` (no `PartialEq`); compare the deref.
        assert_eq!(
            *out,
            "abaisser abandon abdiquer abeille abolir aborder aboutir aboyer abrasif abreuver abriter abroger"
        );
    }

    #[test]
    fn from_entropy_zero_entropy_matches_spec() {
        // Entropy all-zero → sha256(0x00*16)[0] has its top 4 bits = 0x7.
        let entropy = [0u8; 16];
        let mn = from_entropy(&entropy, Language::French);
        // First 11 bits = 0 → first word = wordlist[0] = "abaisser".
        assert!(mn.starts_with("abaisser "), "got: {}", mn.as_str());
    }

    #[test]
    fn generate_fr_roundtrips_through_validate() {
        let mn = generate_fr();
        validate(mn.as_str(), Language::French).expect("generated mnemonic must validate");
    }

    #[test]
    fn seed_debug_is_redacted() {
        // Proves we don't leak seed bytes through println!("{seed:?}") / log crates.
        let seed = mnemonic_to_seed(
            "abaisser abandon abdiquer abeille abolir aborder aboutir aboyer abrasif abreuver abriter abroger",
            "",
            Language::French,
        )
        .unwrap();
        let dbg = format!("{seed:?}");
        assert_eq!(dbg, "Seed(<64-byte redacted>)");
    }
}
