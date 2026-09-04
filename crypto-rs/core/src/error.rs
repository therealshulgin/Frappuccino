//! Error types for `frappuccino-crypto-core`.
//!
//! Every failure mode in this crate surfaces as one of these variants.
//! FFI and higher layers can map them to language-native exceptions.

use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CryptoError {
    /// A BIP-39 word was not found in the active wordlist.
    /// Equivalent of Kotlin's `IllegalArgumentException("Mot BIP-39 inconnu ...")`.
    #[error("unknown BIP-39 word: '{word}' (language={language})")]
    InvalidMnemonicWord {
        word: String,
        language: &'static str,
    },

    /// Mnemonic phrase did not have the expected number of words or failed checksum.
    #[error("invalid mnemonic phrase: {0}")]
    InvalidMnemonic(String),

    /// Internal derivation failure (should never happen barring bugs).
    #[error("derivation failed: {0}")]
    DerivationFailed(String),

    /// An input was empty when a non-empty value was required.
    #[error("empty input")]
    EmptyInput,

    /// A consume-once resource (long-term Ed25519 key, `chain_0`) has already
    /// been used. Enforced at the Rust type level for `EnrollmentKit`.
    #[error("resource '{0}' already consumed")]
    AlreadyConsumed(&'static str),

    /// A signature produced by `ed25519-dalek` did not verify under the given
    /// public key. Distinct from `InvalidMnemonic*` so verify-path errors are
    /// disambiguated from input-path errors.
    #[error("ed25519 signature verification failed")]
    InvalidSignature,

    /// `PinProtectedStore::open` failed to authenticate the blob under the
    /// given PIN. Whether the blob was tampered or the PIN was wrong is
    /// deliberately indistinguishable — the caller should treat both as
    /// "wrong PIN" and count it toward the lockout tracker.
    #[error("PIN verification failed")]
    WrongPin,

    /// A blob (ratchet serialization, PIN store envelope, STRM frame) has
    /// an unsupported header version byte or structural mismatch that is
    /// not ambiguous with wrong-PIN.
    #[error("invalid blob: {0}")]
    InvalidBlob(String),
}
