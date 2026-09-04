//! `frappuccino-crypto-ffi` — `UniFFI` surface exposing the Rust crypto core
//! to Android Kotlin (and later iOS Swift, Python via CLI).
//!
//! S8a scope: full BIP-39 + `PinStore` + Identity + Ratchet surface for the
//! core crate.
//! S8b scope: STRM `encrypt` / `decrypt` and V2 relay client
//! (`StreamServerClient`).
//!
//! # Design notes
//!
//! * All secret material stays *inside* Rust. The most sensitive plaintext /
//!   session keys never cross the boundary at all: STRM decrypt writes the
//!   plaintext to a file inside Rust (`strm_decrypt_to_file`) and the archive
//!   session key is unsealed + consumed in Rust (B-CR-4 removed the dead
//!   `decrypt_session_key` FFI export). The few secret `bytes` that must cross
//!   for PIN-sealing (derived key, report master, ratchet blob) are returned as
//!   `Vec<u8>` copies that Kotlin zeroizes after use (`SecureWipe`).
//! * `EnrollmentKit` is wrapped in `Mutex<Option<_>>` so the one-shot semantics
//!   (`take_chain_into_ratchet`, `close()`) can be enforced across FFI —
//!   `Arc<Self>` is `Send + Sync` without giving up `&mut self` semantics.
//! * `EphemeralRatchet` similarly wraps in `Mutex<_>` for the same reason —
//!   `sign_and_advance` + `advance_batch` need `&mut self`.
//!
//! Note on lint overrides: the `UniFFI`-generated scaffolding emits
//! `#[no_mangle]` functions and statics with the Rust ABI so the Kotlin
//! bindings can link against them. We silence the related lints crate-wide
//! rather than scattering `#[allow]` around generated code we don't control.
#![allow(clippy::no_mangle_with_rust_abi)]
#![allow(clippy::empty_line_after_doc_comments)]
#![allow(unsafe_code)]

use std::sync::{Arc, Mutex};

use frappuccino_crypto_core::bip39::{self as core_bip39, Language};
use frappuccino_crypto_core::identity as core_identity;
use frappuccino_crypto_core::pin_store as core_pin_store;
use frappuccino_crypto_core::provenance as core_provenance;
use frappuccino_crypto_core::ratchet as core_ratchet;
use frappuccino_crypto_core::report as core_report;
use frappuccino_crypto_core::signature_domain::SignatureDomain;
use frappuccino_crypto_core::CryptoError as CoreCryptoError;
use frappuccino_crypto_stream::decrypt::decrypt as strm_core_decrypt;
use frappuccino_crypto_stream::encrypt::encrypt as strm_core_encrypt;
use frappuccino_crypto_stream::{
    DecryptError as StreamDecryptError, EncryptError as StreamEncryptError,
    ProtocolError as StreamProtocolError, SecureDeleteError as StreamSecureDeleteError,
};

uniffi::include_scaffolding!("frappuccino");

const CHAIN_KEY_BYTES: usize = 32;

// ============================================================================
// Errors
// ============================================================================

/// Error mapped across the `UniFFI` boundary. Mirrors `CryptoError` variants
/// that Kotlin needs to distinguish, plus an `Internal` catch-all for FFI-only
/// failure modes (poisoned mutex, slice→array length mismatch).
#[derive(Debug, thiserror::Error)]
pub enum FfiError {
    #[error("unknown BIP-39 word: '{word}' (language={language})")]
    InvalidMnemonicWord { word: String, language: String },
    #[error("invalid mnemonic: {detail}")]
    InvalidMnemonic { detail: String },
    #[error("derivation failed: {detail}")]
    DerivationFailed { detail: String },
    #[error("empty input")]
    EmptyInput,
    #[error("resource '{resource}' already consumed")]
    AlreadyConsumed { resource: String },
    #[error("ed25519 signature verification failed")]
    InvalidSignature,
    #[error("PIN verification failed")]
    WrongPin,
    #[error("invalid blob: {detail}")]
    InvalidBlob { detail: String },
    #[error("network error: {detail}")]
    Network { detail: String },
    #[error("internal FFI error: {detail}")]
    Internal { detail: String },
    /// Phase 6.1.4-D : I/O error during `secure_delete_file`. Distinct
    /// from `Internal` so Kotlin callers can distinguish a transient
    /// FS error (file gone, permission denied) from a logic bug.
    #[error("I/O error: {detail}")]
    Io { detail: String },
}

impl From<CoreCryptoError> for FfiError {
    fn from(e: CoreCryptoError) -> Self {
        match e {
            CoreCryptoError::InvalidMnemonicWord { word, language } => Self::InvalidMnemonicWord {
                word,
                language: language.to_string(),
            },
            CoreCryptoError::InvalidMnemonic(m) => Self::InvalidMnemonic { detail: m },
            CoreCryptoError::DerivationFailed(m) => Self::DerivationFailed { detail: m },
            CoreCryptoError::EmptyInput => Self::EmptyInput,
            CoreCryptoError::AlreadyConsumed(r) => Self::AlreadyConsumed {
                resource: r.to_string(),
            },
            CoreCryptoError::InvalidSignature => Self::InvalidSignature,
            CoreCryptoError::WrongPin => Self::WrongPin,
            CoreCryptoError::InvalidBlob(m) => Self::InvalidBlob { detail: m },
        }
    }
}

impl From<StreamDecryptError> for FfiError {
    fn from(e: StreamDecryptError) -> Self {
        match e {
            StreamDecryptError::Core(c) => Self::from(c),
            StreamDecryptError::Malformed(m) => Self::InvalidBlob { detail: m },
        }
    }
}

impl From<StreamEncryptError> for FfiError {
    fn from(e: StreamEncryptError) -> Self {
        match e {
            StreamEncryptError::Core(c) => Self::from(c),
            // XChaCha20-Poly1305 encrypt failures are bounded-RAM only;
            // surfacing as Internal keeps Kotlin callers from needing to
            // special-case a never-in-practice branch.
            StreamEncryptError::Aead(m) => Self::Internal {
                detail: format!("AEAD encrypt: {m}"),
            },
            // MAX_CHUNK_COUNT × CHUNK_SIZE ≈ 1 TiB — hitting this means
            // the caller is streaming something pathological; surface as
            // Internal so the upload pipeline logs and drops the job.
            StreamEncryptError::TooLarge { chunks, max } => Self::Internal {
                detail: format!("plaintext {chunks} chunks exceeds cap {max}"),
            },
        }
    }
}

impl From<StreamProtocolError> for FfiError {
    fn from(e: StreamProtocolError) -> Self {
        match e {
            StreamProtocolError::Http(h) => Self::Network {
                detail: h.to_string(),
            },
            StreamProtocolError::Json(j) => Self::Network {
                detail: format!("json: {j}"),
            },
            StreamProtocolError::Tls(t) => Self::Network {
                detail: format!("tls: {t}"),
            },
            StreamProtocolError::Invalid(m) => Self::InvalidBlob { detail: m },
            StreamProtocolError::Io(io) => Self::Io {
                detail: io.to_string(),
            },
        }
    }
}

impl From<StreamSecureDeleteError> for FfiError {
    fn from(e: StreamSecureDeleteError) -> Self {
        match e {
            StreamSecureDeleteError::Io(io) => Self::Io {
                detail: io.to_string(),
            },
        }
    }
}

fn lock_poisoned() -> FfiError {
    FfiError::Internal {
        detail: "mutex poisoned".to_string(),
    }
}

// ============================================================================
// Smoke-test API (stable for S0 RustSmokeTest.kt)
// ============================================================================

/// Smoke-test API: returns a fixed string. Kotlin side asserts this value
/// in `mobile/src/androidTestRust/.../rust/RustSmokeTest.kt`.
#[must_use]
pub fn hello_world() -> String {
    "hello from rust via uniffi (S0)".to_string()
}

/// Delegates to the core crate so the smoke test proves cross-crate linking
/// inside the workspace works end-to-end.
#[must_use]
pub fn core_version() -> String {
    frappuccino_crypto_core::version().to_string()
}

// ============================================================================
// BIP-39
// ============================================================================

/// Fresh 12-word FR mnemonic using OS entropy.
///
/// Phase 6.1.4-B : retourne `Vec<u8>` (UTF-8 bytes) au lieu de `String`. Évite
/// que le mnemonic — secret le plus sensible avec le PIN — passe par une
/// String Java immuable côté Kotlin (non-wipeable, intern pool).
#[must_use]
pub fn bip39_generate_fr() -> Vec<u8> {
    // core_bip39::generate_fr() retourne Zeroizing<String>. On extrait les
    // bytes UTF-8 via .as_bytes().to_vec() — copie nécessaire pour franchir
    // le boundary FFI (UniFFI move la valeur côté Kotlin). Le Zeroizing
    // d'origine wipe la backing String à son drop.
    (*core_bip39::generate_fr()).as_bytes().to_vec()
}

/// Normalize a single word against the FR wordlist.
///
/// Note Phase 6.1.4-B : ce helper UI (autocomplete keyboard) reste sur
/// `&str`/`String` car il ne traite qu'un mot isolé, pas le mnemonic complet.
/// Le risque secrecy est limité (1 mot ne révèle pas la phrase entière).
///
/// # Errors
/// [`FfiError::InvalidMnemonicWord`] if the input (after NFD + trim +
/// lowercase + canonical-prefix) doesn't resolve to a known word.
pub fn bip39_normalize_word_fr(input: &str) -> Result<String, FfiError> {
    core_bip39::normalize_word(input, Language::French).map_err(FfiError::from)
}

/// Validate a full 12-word FR mnemonic (structure + checksum + known words).
///
/// Phase 6.1.4-B : `mnemonic` est `&[u8]` (UTF-8 bytes) au lieu de `&str`.
/// Le caller Kotlin passe son `ByteArray` directement, pas une `String`.
/// On valide UTF-8 une fois ici, puis on délègue à core (qui prend `&str`).
///
/// # Errors
/// [`FfiError::InvalidMnemonic`] si bytes pas UTF-8 valide. Sinon any
/// variant de [`FfiError`] matching the underlying [`CoreCryptoError`].
pub fn bip39_validate_fr(mnemonic: &[u8]) -> Result<(), FfiError> {
    let s = std::str::from_utf8(mnemonic).map_err(|e| FfiError::InvalidMnemonic {
        detail: format!("mnemonic bytes are not valid UTF-8: {e}"),
    })?;
    core_bip39::validate(s, Language::French).map_err(FfiError::from)
}

// ============================================================================
// Pin store
// ============================================================================

/// Encrypt `plaintext` under a PIN — Argon2id m=256 MiB / t=4 + XChaCha20-Poly1305.
///
/// # Errors
/// [`FfiError::EmptyInput`] on empty PIN, [`FfiError::DerivationFailed`] on
/// Argon2 failure (OOM).
pub fn pin_store_seal(pin: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, FfiError> {
    core_pin_store::seal(pin, plaintext).map_err(FfiError::from)
}

/// Decrypt a blob produced by [`pin_store_seal`]. Returns the plaintext.
///
/// Kotlin is expected to zero the returned `ByteArray` as soon as it's done.
///
/// # Errors
/// [`FfiError::WrongPin`] for bad PIN / tampered blob (deliberately
/// ambiguous — feed the lockout tracker), [`FfiError::InvalidBlob`] for
/// structural problems (wrong version byte, too short).
pub fn pin_store_open(pin: &[u8], blob: &[u8]) -> Result<Vec<u8>, FfiError> {
    core_pin_store::open(pin, blob)
        .map(|z| z.to_vec())
        .map_err(FfiError::from)
}

// Lot 4b P6 (2026-06-27) — R-CR-1 export surfaces RETIRÉES. The
// `pin_store_open_extended` (+ `UnsealedBlob`), `pin_store_seal_with_key` and
// `pin_store_open_with_key` exports returned / accepted the Argon2id-derived key
// across the FFI. They have no caller left after the no-export migration (P2):
// the StreamUploadManager paths open / seal / reseal entirely in-crate via the
// PIN-session holder (`pin_session_*`, `EphemeralRatchet::reseal_session_blob`,
// `{ProvenanceSigner,ReportKeyring}::seal_with_session`). Only `pin_store_open`
// survives ON THE FFI SURFACE — the diff-fuzz Kotlin↔Rust parity harness crosses
// the boundary for it (`difffuzz-jvm/.../Main.kt`) and it has 0 prod caller. The
// export of `pin_store_seal` was removed on 2026-09-03: this comment used to
// claim the harness exercised it too, which was never true — the harness only
// ever OPENS, and the blob it opens is built by the Rust-side dumper. The Rust
// `pin_store_seal` below stays for that dumper and for three unit tests.

// ============================================================================
// StreamIdentity
// ============================================================================

/// FFI wrapper holding a `core::identity::StreamIdentity`. Immutable after
/// construction, so no lock needed.
#[derive(Debug)]
pub struct StreamIdentity {
    inner: core_identity::StreamIdentity,
}

impl StreamIdentity {
    /// Rebuild an identity from persisted public keys.
    ///
    /// # Errors
    /// [`FfiError::InvalidBlob`] if either key isn't 32 bytes.
    pub fn from_public_keys(ed25519_pk: &[u8], x25519_pk: &[u8]) -> Result<Self, FfiError> {
        let ed_arr: [u8; 32] = ed25519_pk.try_into().map_err(|_| FfiError::InvalidBlob {
            detail: format!("ed25519_pk must be 32 bytes, got {}", ed25519_pk.len()),
        })?;
        let x_arr: [u8; 32] = x25519_pk.try_into().map_err(|_| FfiError::InvalidBlob {
            detail: format!("x25519_pk must be 32 bytes, got {}", x25519_pk.len()),
        })?;
        Ok(Self {
            inner: core_identity::StreamIdentity::from_public_keys(ed_arr, x_arr),
        })
    }

    #[must_use]
    pub fn ed25519_pk(&self) -> Vec<u8> {
        self.inner.ed25519_pk().to_vec()
    }

    #[must_use]
    pub fn x25519_pk(&self) -> Vec<u8> {
        self.inner.x25519_pk().to_vec()
    }

    #[must_use]
    pub fn ed25519_pk_hex(&self) -> String {
        self.inner.ed25519_pk_hex()
    }

    #[must_use]
    pub fn readable_fingerprint(&self) -> String {
        self.inner.readable_fingerprint()
    }

    /// # Errors
    /// [`FfiError::InvalidSignature`] on bad length or verify failure.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), FfiError> {
        let sig: [u8; 64] = signature
            .try_into()
            .map_err(|_| FfiError::InvalidSignature)?;
        self.inner.verify(message, &sig).map_err(FfiError::from)
    }
}

// ============================================================================
// EnrollmentKit
// ============================================================================

/// FFI wrapper enforcing the one-shot contract across the language boundary.
/// The inner `Option` is consumed by `take_chain_into_ratchet` (for `chain_0`)
/// and `close()` (for the whole kit including the Ed25519 secret).
pub struct EnrollmentKit {
    inner: Mutex<Option<core_identity::EnrollmentKit>>,
}

impl std::fmt::Debug for EnrollmentKit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never format the secret material — just report presence.
        let state = match self.inner.lock() {
            Ok(g) => {
                if g.is_some() {
                    "live"
                } else {
                    "closed"
                }
            }
            Err(_) => "poisoned",
        };
        write!(f, "EnrollmentKit({state})")
    }
}

impl EnrollmentKit {
    /// Phase 6.1.4-B : `mnemonic` et `passphrase` sont `&[u8]` (UTF-8 bytes)
    /// au lieu de `&str`. Le caller Kotlin passe ses `ByteArray` directement,
    /// le mnemonic ne touche jamais le pool intern Java. Validation UTF-8
    /// faite ici une fois, puis délégation au core (qui garde `&str`).
    ///
    /// # Errors
    /// [`FfiError::InvalidMnemonic`] si UTF-8 invalide. Sinon any derivation /
    /// BIP-39 error wrapped as [`FfiError`].
    pub fn from_mnemonic(mnemonic: &[u8], passphrase: &[u8]) -> Result<Self, FfiError> {
        let mnemonic_s = std::str::from_utf8(mnemonic).map_err(|e| FfiError::InvalidMnemonic {
            detail: format!("mnemonic bytes are not valid UTF-8: {e}"),
        })?;
        let passphrase_s =
            std::str::from_utf8(passphrase).map_err(|e| FfiError::InvalidMnemonic {
                detail: format!("passphrase bytes are not valid UTF-8: {e}"),
            })?;
        let kit = core_identity::EnrollmentKit::from_mnemonic(mnemonic_s, passphrase_s)
            .map_err(FfiError::from)?;
        Ok(Self {
            inner: Mutex::new(Some(kit)),
        })
    }

    /// # Errors
    /// [`FfiError::AlreadyConsumed`] if the kit was `close()`d first.
    pub fn identity(&self) -> Result<Arc<StreamIdentity>, FfiError> {
        let guard = self.inner.lock().map_err(|_| lock_poisoned())?;
        let kit = guard.as_ref().ok_or(FfiError::AlreadyConsumed {
            resource: "enrollment_kit".to_string(),
        })?;
        Ok(Arc::new(StreamIdentity {
            inner: kit.identity().clone(),
        }))
    }

    /// Sign `concat(batch_0_public_keys)` at enrollment, in the R-C-1
    /// [`SignatureDomain::Enrollment`] domain.
    ///
    /// # Errors
    /// [`FfiError::AlreadyConsumed`] after `wipe()`.
    pub fn sign_enrollment(&self, message: &[u8]) -> Result<Vec<u8>, FfiError> {
        self.sign_with_domain(message, SignatureDomain::Enrollment)
    }

    // Phase C relay-blind reports — `sign_archive_challenge` (the 0x04
    // ArchiveAuth domain) is retired: archive reads are now identity-free
    // (the phrase-derived report_id is the capability), so there is no
    // archive-auth signature any more.

    fn sign_with_domain(
        &self,
        message: &[u8],
        domain: SignatureDomain,
    ) -> Result<Vec<u8>, FfiError> {
        let guard = self.inner.lock().map_err(|_| lock_poisoned())?;
        let kit = guard.as_ref().ok_or(FfiError::AlreadyConsumed {
            resource: "enrollment_kit".to_string(),
        })?;
        kit.sign_once(message, domain)
            .map(|arr| arr.to_vec())
            .map_err(FfiError::from)
    }

    /// Proactive wipe — on return the kit can no longer sign or hand out
    /// `chain_0`. Safe to call multiple times.
    ///
    /// Named `wipe` (not `close`) so the generated Kotlin class doesn't clash
    /// with `AutoCloseable.close()`'s inherited signature — that clash
    /// produces `Conflicting overloads` errors at the Kotlin compile step.
    pub fn wipe(&self) {
        // Fail-closed on a poisoned lock: `wipe` exists solely to zeroize the
        // enrollment secrets, so it MUST run even after a panic held the lock —
        // exactly when a residual matters most. Mirror the poison-recover
        // discipline already used by `upload_jwt_guard` / `pin_session_guard`;
        // `if let Ok(..)` silently skipped the scrub on poison (fail-open).
        let mut guard = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *guard = None;
    }
}

// ============================================================================
// ArchiveIdentity
// ============================================================================

/// FFI wrapper for `core::identity::ArchiveIdentity`. Immutable after
/// construction (the inner X25519 secret stays put) → no lock.
#[derive(Debug)]
pub struct ArchiveIdentity {
    inner: core_identity::ArchiveIdentity,
}

impl ArchiveIdentity {
    /// Phase 6.1.4-B : `mnemonic` et `passphrase` sont `&[u8]` (UTF-8 bytes).
    /// Le mnemonic ne touche jamais le pool intern Java côté caller.
    ///
    /// # Errors
    /// [`FfiError::InvalidMnemonic`] si UTF-8 invalide. Sinon any derivation /
    /// BIP-39 error wrapped as [`FfiError`].
    pub fn from_mnemonic(mnemonic: &[u8], passphrase: &[u8]) -> Result<Self, FfiError> {
        let mnemonic_s = std::str::from_utf8(mnemonic).map_err(|e| FfiError::InvalidMnemonic {
            detail: format!("mnemonic bytes are not valid UTF-8: {e}"),
        })?;
        let passphrase_s =
            std::str::from_utf8(passphrase).map_err(|e| FfiError::InvalidMnemonic {
                detail: format!("passphrase bytes are not valid UTF-8: {e}"),
            })?;
        core_identity::ArchiveIdentity::from_mnemonic(mnemonic_s, passphrase_s)
            .map(|a| Self { inner: a })
            .map_err(FfiError::from)
    }

    #[must_use]
    pub fn identity(&self) -> Arc<StreamIdentity> {
        Arc::new(StreamIdentity {
            inner: self.inner.identity().clone(),
        })
    }

    // B-CR-4 (audit 2026-06-26) — `decrypt_session_key` removed from the FFI
    // (see frappuccino.udl). It surfaced the 32-byte STRM session key into a
    // non-Zeroizing JVM ByteArray (R-CR-1 class) and had no production caller:
    // the live archive path decrypts inside Rust (`strm_decrypt_to_file`), so
    // the session key never crosses the boundary. The core unseal
    // (`core::identity::ArchiveIdentity::decrypt_session_key`) stays — it is
    // the in-Rust primitive used by `stream::decrypt`.
}

// ============================================================================
// RatchetSignature / RotationProof (FFI projections)
// ============================================================================

/// Plain-data record mirroring `core::ratchet::RatchetSignature` with
/// `Vec<u8>` instead of fixed arrays so `UniFFI` can ferry it across.
#[derive(Debug, Clone)]
pub struct RatchetSignature {
    pub signature: Vec<u8>,
    pub ephemeral_public_key: Vec<u8>,
    pub batch_number: u32,
    pub key_index: u32,
}

impl From<core_ratchet::RatchetSignature> for RatchetSignature {
    fn from(s: core_ratchet::RatchetSignature) -> Self {
        Self {
            signature: s.signature.to_vec(),
            ephemeral_public_key: s.ephemeral_public_key.to_vec(),
            batch_number: s.batch_number,
            key_index: s.key_index,
        }
    }
}

/// Plain-data record mirroring `core::ratchet::RotationProof`.
#[derive(Debug, Clone)]
pub struct RotationProof {
    pub new_batch_number: u32,
    pub new_batch_public_keys: Vec<Vec<u8>>,
    pub signer_public_key: Vec<u8>,
    pub signer_batch_number: u32,
    pub signer_key_index: u32,
    pub signature: Vec<u8>,
}

impl From<core_ratchet::RotationProof> for RotationProof {
    fn from(p: core_ratchet::RotationProof) -> Self {
        Self {
            new_batch_number: p.new_batch_number,
            new_batch_public_keys: p.new_batch_public_keys.iter().map(|k| k.to_vec()).collect(),
            signer_public_key: p.signer_public_key.to_vec(),
            signer_batch_number: p.signer_batch_number,
            signer_key_index: p.signer_key_index,
            signature: p.signature.to_vec(),
        }
    }
}

// ============================================================================
// EphemeralRatchet
// ============================================================================

/// FFI wrapper for `core::ratchet::EphemeralRatchet`. Wraps in Mutex so
/// &mut-self methods (`sign_and_advance`, `advance_batch`) are reachable
/// through the FFI-shared &self handle.
pub struct EphemeralRatchet {
    inner: Mutex<core_ratchet::EphemeralRatchet>,
}

impl std::fmt::Debug for EphemeralRatchet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "EphemeralRatchet(<opaque>)")
    }
}

impl EphemeralRatchet {
    /// Drain `chain_0` from `kit` and initialize a fresh ratchet.
    /// After this call, `kit.take_chain_into_ratchet` would return
    /// `AlreadyConsumed`.
    ///
    /// # Errors
    /// [`FfiError::AlreadyConsumed`] if the kit's chain was already drained.
    // Clippy wants `&Arc<EnrollmentKit>`, but UniFFI's generated scaffolding
    // calls this function with an owned `Arc`. Overriding here keeps the
    // signature UDL-compatible without loosening pedantic lints workspace-wide.
    #[allow(clippy::needless_pass_by_value)]
    pub fn from_kit(kit: Arc<EnrollmentKit>) -> Result<Self, FfiError> {
        let chain_locked = {
            let mut guard = kit.inner.lock().map_err(|_| lock_poisoned())?;
            let kit_inner = guard.as_mut().ok_or(FfiError::AlreadyConsumed {
                resource: "enrollment_kit".to_string(),
            })?;
            kit_inner.take_chain_zero().map_err(FfiError::from)?
        };
        let mut chain_bytes = [0u8; CHAIN_KEY_BYTES];
        chain_locked.with_bytes(|b| chain_bytes.copy_from_slice(b));
        // `chain_locked` drops here → mlock'd page zeroed.
        drop(chain_locked);
        let mut ratchet = core_ratchet::EphemeralRatchet::new();
        ratchet
            .initialize(&mut chain_bytes)
            .map_err(FfiError::from)?;
        // `chain_bytes` also zeroed by `initialize` on success.
        Ok(Self {
            inner: Mutex::new(ratchet),
        })
    }

    /// Resume a ratchet from a previously-serialized blob (V1 or V2).
    ///
    /// # Errors
    /// [`FfiError::InvalidBlob`] on malformed input, [`FfiError::WrongPin`] on
    /// V2 MAC failure.
    pub fn deserialize(blob: &[u8]) -> Result<Self, FfiError> {
        core_ratchet::EphemeralRatchet::deserialize(blob)
            .map(|r| Self {
                inner: Mutex::new(r),
            })
            .map_err(FfiError::from)
    }

    /// Serialize to a V2 blob (4876 bytes).
    ///
    /// # Errors
    /// [`FfiError::AlreadyConsumed`] if the ratchet was wiped.
    pub fn serialize(&self) -> Result<Vec<u8>, FfiError> {
        let guard = self.inner.lock().map_err(|_| lock_poisoned())?;
        guard.serialize().map_err(FfiError::from)
    }

    /// Lot 4b — serialize the ratchet and seal it with the held PIN-session key,
    /// all in-crate. Returns the sealed blob (ciphertext) for Kotlin to persist;
    /// neither the 50-key plaintext nor the derived key crosses the FFI. Replaces
    /// the `serialize()` + `pin_store_seal_with_key()` round-trip on the
    /// fast-reseal hot path. The ratchet lock is released before the holder is
    /// touched (no nested lock).
    ///
    /// # Errors
    /// [`FfiError::AlreadyConsumed`] if the ratchet was wiped, [`FfiError::Internal`]
    /// if no PIN session is active.
    pub fn reseal_session_blob(&self) -> Result<Vec<u8>, FfiError> {
        let plaintext = {
            let guard = self.inner.lock().map_err(|_| lock_poisoned())?;
            zeroize::Zeroizing::new(guard.serialize().map_err(FfiError::from)?)
        };
        match with_pin_session(|key, salt| core_pin_store::seal_with_key(key, salt, &plaintext)) {
            Some(res) => res.map_err(FfiError::from),
            None => Err(FfiError::Internal {
                detail: "reseal ratchet: no active PIN session".into(),
            }),
        }
        // plaintext (Zeroizing) drops here → wiped.
    }

    /// Lot 4b — serialize + PIN-seal (Argon2id) the ratchet in-crate, for the
    /// INITIAL enrollment persistence (before any PIN session holder exists).
    /// The 50-key plaintext never crosses the FFI. Does NOT populate the holder —
    /// the caller follows with `pin_session_populate` to prime the fast-reseal
    /// session (replaces `serialize()` + `pin_store_seal()`).
    ///
    /// # Errors
    /// [`FfiError::AlreadyConsumed`] if wiped, [`FfiError::EmptyInput`] on an
    /// empty PIN, [`FfiError::DerivationFailed`] on Argon2 OOM.
    pub fn seal_with_pin(&self, pin: &[u8]) -> Result<Vec<u8>, FfiError> {
        let plaintext = {
            let guard = self.inner.lock().map_err(|_| lock_poisoned())?;
            zeroize::Zeroizing::new(guard.serialize().map_err(FfiError::from)?)
        };
        core_pin_store::seal(pin, &plaintext).map_err(FfiError::from)
        // plaintext (Zeroizing) drops here → wiped.
    }

    /// The active batch number (monotonic, incremented on each rotation; 0 once
    /// wiped). Lets Kotlin read the counter WITHOUT serializing the whole 50-key
    /// blob just to parse the header (Lot 4b — resolves the S8c.2 TODO; the
    /// 50-sk plaintext no longer crosses for a non-secret read).
    ///
    /// # Errors
    /// [`FfiError::Internal`] only if the internal lock is poisoned.
    pub fn batch_number(&self) -> Result<u32, FfiError> {
        let guard = self.inner.lock().map_err(|_| lock_poisoned())?;
        Ok(guard.batch_number())
    }

    /// 50 × 32-byte public keys of the active batch.
    ///
    /// # Errors
    /// [`FfiError::AlreadyConsumed`] if wiped.
    pub fn batch_public_keys(&self) -> Result<Vec<Vec<u8>>, FfiError> {
        let guard = self.inner.lock().map_err(|_| lock_poisoned())?;
        let pks = guard.batch_public_keys().map_err(FfiError::from)?;
        Ok(pks.iter().map(|k| k.to_vec()).collect())
    }

    /// Number of unconsumed slots left in the current batch.
    ///
    /// `BATCH_SIZE = 50` so the value always fits in `u32`. Returns the
    /// `usize` from the core ratchet cast to `u32` — used by the Kotlin
    /// auto-rotate trigger which previously had no real signal and treated
    /// the batch as eternally full (RT-07).
    ///
    /// # Errors
    /// [`FfiError::Internal`] on poisoned mutex.
    pub fn remaining_in_batch(&self) -> Result<u32, FfiError> {
        let guard = self.inner.lock().map_err(|_| lock_poisoned())?;
        let n = guard.remaining_in_batch();
        u32::try_from(n).map_err(|_| FfiError::Internal {
            detail: format!("remaining_in_batch overflows u32: {n}"),
        })
    }

    /// Sign `message` with the next unused slot, mark it consumed.
    ///
    /// # Errors
    /// [`FfiError::AlreadyConsumed`] on wiped state or no slot left.
    pub fn sign_and_advance(&self, message: &[u8]) -> Result<RatchetSignature, FfiError> {
        let mut guard = self.inner.lock().map_err(|_| lock_poisoned())?;
        guard
            .sign_and_advance(message)
            .map(RatchetSignature::from)
            .map_err(FfiError::from)
    }

    /// Roll forward to batch N+1, signing the 50 new pubs with one of the
    /// current batch's slots.
    ///
    /// # Errors
    /// [`FfiError::AlreadyConsumed`] on wiped state.
    pub fn advance_batch(&self) -> Result<RotationProof, FfiError> {
        let mut guard = self.inner.lock().map_err(|_| lock_poisoned())?;
        guard
            .advance_batch()
            .map(RotationProof::from)
            .map_err(FfiError::from)
    }

    /// Proactive wipe — all 50 private keys + chain key zeroed.
    pub fn wipe(&self) {
        // Fail-closed on a poisoned lock (see `EnrollmentKit::wipe`): the scrub
        // of the 50 Ed25519 private keys + chain key MUST run even after a panic
        // held the lock. This only advances the zeroization that `Drop` would do
        // anyway — no slot / batch / monotonicity / filesystem state is touched.
        let mut guard = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.wipe();
    }
}

// ============================================================================
// STRM (stream blob encrypt/decrypt)
// ============================================================================

/// Non-secret metadata accompanying a decrypted STRM blob. Kotlin dictionary
/// — fields match `BlobMetadata` in the UDL 1-to-1.
#[derive(Debug, Clone)]
pub struct BlobMetadata {
    pub version: u8,
    pub mode: u8,
    pub grant_count: u16,
    pub plaintext_len: u64,
}

/// Test-only plaintext + metadata bundle for [`strm_decrypt`]. **Not
/// FFI-exported** (Phase 8.1.6 forensic finding #2): production decrypt uses
/// [`strm_decrypt_to_file`], which keeps plaintext off the JVM heap.
#[cfg(test)]
#[derive(Debug, Clone)]
struct StrmPlaintext {
    plaintext: Vec<u8>,
    metadata: BlobMetadata,
}

/// Encrypt `plaintext` as a self-sealed STRM blob. Picks SINGLE or CHUNKED
/// automatically based on size (`> 10 MiB` = CHUNKED).
///
/// # Errors
/// Forwards [`StreamEncryptError`] via [`FfiError`].
#[allow(clippy::needless_pass_by_value)]
pub fn strm_encrypt(plaintext: &[u8], author: Arc<StreamIdentity>) -> Result<Vec<u8>, FfiError> {
    strm_core_encrypt(plaintext, &author.inner).map_err(FfiError::from)
}

/// M-1 (WP-C) — the SHARED path-safety guard for relay-supplied archive blob
/// filenames, exposed so the Android rescue validates names with the exact same
/// rule as the CLI and the FFI download entry points (one canonical guard, no
/// per-client drift). `true` iff `name` is a single, safe path component (no
/// separator, not `.`/`..`, not absolute, not empty) — safe to join onto a local
/// output directory. The download FFIs also enforce this internally; this
/// predicate lets the caller skip a poisoned blob cleanly before building a path.
#[must_use]
pub fn archive_blob_filename_is_safe(name: &str) -> bool {
    frappuccino_crypto_stream::is_safe_blob_filename(name)
}

/// Phase 6.1.4-C — variante "le plaintext ne touche jamais la JVM heap".
///
/// Lit `input_path` (typiquement un MP4 plaintext sur disk produit par `CameraX`),
/// chiffre en STRM, écrit le résultat à `output_path`. Le plaintext est
/// chargé en `Zeroizing<Vec<u8>>` côté Rust : la mémoire est wipée
/// automatiquement au drop (via `volatile_set_memory` du crate zeroize,
/// résistant aux optimisations LLVM).
///
/// Pourquoi : avant ce refactor, `strm_encrypt` recevait un `&[u8]` que
/// Kotlin construisait via `chunkFile.readBytes()` — le plaintext existait
/// donc en heap JVM pendant ~10ms (durée de la copie + FFI). Un dump heap
/// pendant ce temps exposait la vidéo en clair. Maintenant Rust ouvre
/// directement le file et le `ByteArray` Kotlin n'existe pas.
///
/// Retourne la taille du blob écrit (octets) pour log côté caller.
///
/// # Errors
/// [`FfiError::Io`] sur erreur I/O (file not found, permission denied,
/// disk full). [`FfiError::Internal`] / autres pour erreurs crypto.
#[allow(clippy::needless_pass_by_value)]
pub fn strm_encrypt_file(
    input_path: &str,
    output_path: &str,
    author: Arc<StreamIdentity>,
) -> Result<u64, FfiError> {
    use zeroize::Zeroizing;
    // Lit le file en Vec<u8> et wrap immédiatement en Zeroizing pour wipe
    // au drop. Le crate zeroize utilise `volatile_set_memory` que LLVM ne
    // peut pas éliminer (= équivalent du ZeroizeOnDrop pattern).
    let plaintext = Zeroizing::new(std::fs::read(input_path).map_err(|e| FfiError::Io {
        detail: format!("read {input_path}: {e}"),
    })?);
    let blob = strm_core_encrypt(&plaintext, &author.inner).map_err(FfiError::from)?;
    let blob_len = blob.len() as u64;
    // WP-D (audit H1) — fsync the .strm BEFORE returning. The caller
    // (StreamChunkEncryptor.encryptChunk) secure-deletes the plaintext MP4 the
    // instant this returns, and THAT delete is synced. With a bare
    // `std::fs::write` the blob's data blocks can still sit in the page cache
    // while the only other copy (the plaintext) is durably destroyed — a
    // power-loss in that window is total, silent loss of the chunk. File::create
    // + write_all + sync_all forces the blob to stable storage first.
    let mut f = std::fs::File::create(output_path).map_err(|e| FfiError::Io {
        detail: format!("create {output_path}: {e}"),
    })?;
    std::io::Write::write_all(&mut f, &blob).map_err(|e| FfiError::Io {
        detail: format!("write {output_path}: {e}"),
    })?;
    f.sync_all().map_err(|e| FfiError::Io {
        detail: format!("sync {output_path}: {e}"),
    })?;
    drop(f);
    // Best-effort fsync of the parent directory so the new file's directory
    // entry is durable too (the data sync above covers the blocks; the entry
    // needs a dir fsync on some filesystems). Unix-only (Android target); a
    // no-op elsewhere where a directory can't be opened as a File.
    #[cfg(unix)]
    if let Some(parent) = std::path::Path::new(output_path).parent() {
        let _ = std::fs::File::open(parent).and_then(|d| d.sync_all());
    }
    Ok(blob_len)
}

/// Decrypt a STRM blob under `archive`. Returns plaintext + metadata.
///
/// **Test-only, NOT FFI-exported** (Phase 8.1.6 forensic finding #2,
/// 2026-06-03): the returned `Vec<u8>` is a non-`Zeroizing` plaintext copy
/// that would cross the `UniFFI` boundary into a JVM `ByteArray` and linger on
/// the heap. Sealed behind `#[cfg(test)]`; production MUST use
/// [`strm_decrypt_to_file`], which keeps the plaintext Rust-side.
///
/// # Errors
/// [`FfiError::InvalidBlob`] for structural problems, [`FfiError::WrongPin`]
/// if the envelope wasn't sealed for `archive`.
#[cfg(test)]
#[allow(clippy::needless_pass_by_value)]
fn strm_decrypt(blob: &[u8], archive: Arc<ArchiveIdentity>) -> Result<StrmPlaintext, FfiError> {
    let (plaintext_z, meta) = strm_core_decrypt(blob, &archive.inner).map_err(FfiError::from)?;
    let plen = u64::try_from(meta.plaintext_len).map_err(|_| FfiError::Internal {
        detail: "plaintext_len overflows u64 (impossible)".to_string(),
    })?;
    Ok(StrmPlaintext {
        plaintext: plaintext_z.to_vec(),
        metadata: BlobMetadata {
            version: meta.version,
            mode: meta.mode,
            grant_count: meta.grant_count,
            plaintext_len: plen,
        },
    })
}

/// Phase H2-B.18 (Red MED-4 fix, 2026-05-19) — `strm_decrypt` variant
/// where the plaintext never touches the JVM heap, mirroring
/// [`strm_encrypt_file`].
///
/// Reads the encrypted STRM blob from `input_path` (encrypted, so safe
/// to materialise as a regular `Vec<u8>` here), decrypts inside Rust
/// into a `Zeroizing<Vec<u8>>` (wiped on drop via the `zeroize`
/// crate's `volatile_set_memory` — resistant to LLVM dead-store
/// elimination), writes the plaintext bytes to `output_path`, and
/// returns ONLY the non-secret [`BlobMetadata`]. The plaintext itself
/// never crosses the `UniFFI` boundary — Kotlin gets only a metadata
/// dictionary.
///
/// Why : `strm_decrypt` returns a `Vec<u8>` plaintext that traverses
/// `UniFFI` and lands as a `ByteArray` on the JVM heap. A heap dump
/// during the ~ms read window exposes the original file in clear text.
/// This variant keeps the plaintext on disk (where the caller is
/// expected to follow up with `secure_delete_file` after consumption)
/// and in Rust only — symmetric to the Phase 6.1.4-C work on the
/// encryption side. Red Team audit `Red MED-4`.
///
/// Failure handling : if the file write fails after a successful
/// decrypt, we best-effort `secure_delete_file` the partial output
/// (overwrite + truncate + unlink) so plaintext fragments don't
/// linger on disk. Errors during cleanup are swallowed — the primary
/// error (the write failure) is what the caller needs to see.
///
/// # Errors
/// [`FfiError::Io`] for filesystem failures (read on `input_path`,
/// write on `output_path`). Crypto errors (e.g. [`FfiError::WrongPin`]
/// when the blob wasn't sealed for `archive`, [`FfiError::InvalidBlob`]
/// for structural issues) forward from [`strm_core_decrypt`].
#[allow(clippy::needless_pass_by_value)]
pub fn strm_decrypt_to_file(
    input_path: &str,
    output_path: &str,
    archive: Arc<ArchiveIdentity>,
) -> Result<BlobMetadata, FfiError> {
    // Read the encrypted blob. Already encrypted, so a regular Vec<u8>
    // on the Rust heap is fine — no zeroization needed for ciphertext.
    let blob = std::fs::read(input_path).map_err(|e| FfiError::Io {
        detail: format!("read {input_path}: {e}"),
    })?;
    // Decrypt — `plaintext_z` is a `Zeroizing<Vec<u8>>`. Stays in
    // Rust scope ; dropped at end of this function (wiped via
    // volatile_set_memory then deallocated).
    let (plaintext_z, meta) = strm_core_decrypt(&blob, &archive.inner).map_err(FfiError::from)?;
    let plen = u64::try_from(meta.plaintext_len).map_err(|_| FfiError::Internal {
        detail: "plaintext_len overflows u64 (impossible)".to_string(),
    })?;
    // Write plaintext to disk. On failure, best-effort
    // secure-delete the partial output (overwrite + truncate +
    // unlink) so plaintext fragments don't linger if e.g. disk
    // filled after a partial write.
    if let Err(e) = std::fs::write(output_path, plaintext_z.as_slice()) {
        // Swallow the cleanup error : the primary error (e) is what
        // the caller needs. The partial file may or may not exist —
        // secure_delete_file is idempotent and a no-op on missing
        // files.
        let _ = frappuccino_crypto_stream::secure_delete_file(std::path::Path::new(output_path));
        return Err(FfiError::Io {
            detail: format!("write {output_path}: {e}"),
        });
    }
    // plaintext_z drops here — Zeroizing wipes its backing memory
    // via volatile_set_memory before the allocator reclaims it.
    Ok(BlobMetadata {
        version: meta.version,
        mode: meta.mode,
        grant_count: meta.grant_count,
        plaintext_len: plen,
    })
}

// ============================================================================
// Phase 6.1.4-D — Secure delete pour fichiers temporaires sensibles
// ============================================================================

/// Secure-delete `path` : overwrite avec random bytes + fsync + truncate +
/// unlink. Voir `frappuccino_crypto_stream::secure_delete` pour les détails.
///
/// No-op si `path` n'existe pas (idempotent — pas d'erreur).
///
/// # Errors
/// [`FfiError::Io`] sur erreur I/O (permission denied, disk full, etc.).
pub fn secure_delete_file(path: &str) -> Result<(), FfiError> {
    frappuccino_crypto_stream::secure_delete_file(std::path::Path::new(path))
        .map_err(FfiError::from)
}

// ============================================================================
// Provenance (lean hash + Bitcoin, §10.11)
// ============================================================================

/// FFI wrapper for `core::provenance::ProvenanceSigner` — a dedicated,
/// seed-derived secret kept **only** to derive the per-recording OTS blinding
/// salt. Despite the name it signs nothing: the signed-manifest design it was
/// built for was removed in the 2026-06-25 metadata walk-back, along with tags
/// 0x05/0x06. Immutable after construction (the seed stays mlock'd inside) →
/// no lock, like [`ArchiveIdentity`].
pub struct ProvenanceSigner {
    inner: core_provenance::ProvenanceSigner,
}

impl std::fmt::Debug for ProvenanceSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ProvenanceSigner(<opaque>)")
    }
}

impl ProvenanceSigner {
    /// Enrollment-time derivation from a BIP-39 mnemonic. UTF-8 bytes (the
    /// mnemonic never touches the Java intern pool), like
    /// [`EnrollmentKit::from_mnemonic`].
    ///
    /// # Errors
    /// [`FfiError::InvalidMnemonic`] if not UTF-8; otherwise any derivation error.
    pub fn from_mnemonic(mnemonic: &[u8], passphrase: &[u8]) -> Result<Self, FfiError> {
        let mnemonic_s = std::str::from_utf8(mnemonic).map_err(|e| FfiError::InvalidMnemonic {
            detail: format!("mnemonic bytes are not valid UTF-8: {e}"),
        })?;
        let passphrase_s =
            std::str::from_utf8(passphrase).map_err(|e| FfiError::InvalidMnemonic {
                detail: format!("passphrase bytes are not valid UTF-8: {e}"),
            })?;
        core_provenance::ProvenanceSigner::from_mnemonic(mnemonic_s, passphrase_s)
            .map(|inner| Self { inner })
            .map_err(FfiError::from)
    }

    /// Recording-time reconstruction from the persisted 32-byte seed (unsealed
    /// from the PIN store at unlock).
    ///
    /// # Errors
    /// [`FfiError::InvalidBlob`] if `seed` isn't 32 bytes; [`FfiError::DerivationFailed`]
    /// on an mlock failure.
    pub fn from_seed(seed: &[u8]) -> Result<Self, FfiError> {
        let arr: [u8; 32] = seed.try_into().map_err(|_| FfiError::InvalidBlob {
            detail: format!("provenance seed must be 32 bytes, got {}", seed.len()),
        })?;
        core_provenance::ProvenanceSigner::from_seed(&arr)
            .map(|inner| Self { inner })
            .map_err(FfiError::from)
    }

    /// Lot 4b (OPTION B) — seal the provenance seed with the held PIN-session
    /// key, all in-crate. Returns the sealed blob; the 32-byte seed never crosses
    /// the FFI (the enrollment seed-seal path — the secret never touches the JVM;
    /// the old `seed_bytes()` export was retired in P6).
    ///
    /// # Errors
    /// [`FfiError::Internal`] if no PIN session is active; seal errors forward.
    pub fn seal_with_session(&self) -> Result<Vec<u8>, FfiError> {
        self.inner.with_seed_bytes(|seed| {
            match with_pin_session(|key, salt| core_pin_store::seal_with_key(key, salt, seed)) {
                Some(res) => res.map_err(FfiError::from),
                None => Err(FfiError::Internal {
                    detail: "seal provenance seed: no active PIN session".into(),
                }),
            }
        })
    }

    /// §10.11 Phase B — derive the per-recording OTS commitment salt for
    /// `recording_id` (16 bytes, the manifest's recording id). Re-derived at
    /// rescue from the phrase to export into the disclosure bundle so a verifier
    /// can recompute the salted commitment. Never sent to the relay; not secret
    /// once the witness chooses to disclose it.
    ///
    /// # Errors
    /// [`FfiError::InvalidBlob`] if `recording_id` isn't 16 bytes; derivation
    /// errors forward from core.
    pub fn ots_salt(&self, recording_id: &[u8]) -> Result<Vec<u8>, FfiError> {
        let rid: [u8; 16] = recording_id.try_into().map_err(|_| FfiError::InvalidBlob {
            detail: format!("recording_id must be 16 bytes, got {}", recording_id.len()),
        })?;
        self.inner
            .ots_salt(&rid)
            .map(|s| s.to_vec())
            .map_err(FfiError::from)
    }
}

// ============================================================================
// Report capability keyring (Phase C relay-blind reports)
// ============================================================================

/// Lowercase hex encoding without a hex dependency — used to render a
/// `report_id` (16 bytes) into the 32-char URL path component.
fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        // write! to a String is infallible; `let _` silences the Result
        // without an .unwrap() (matches core's identity::hex_encode).
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// FFI wrapper for `core::report::ReportKeyring` — the witness's per-report
/// capability keyring (Phase C relay-blind reports). Derives a per-report key
/// `R_n` from the BIP-39 seed under a dedicated HKDF context; the relay stores
/// `report_id → report_pk`, never the identity. Immutable after construction
/// (`report_master` stays mlock'd inside) → no lock, like [`ProvenanceSigner`].
pub struct ReportKeyring {
    inner: core_report::ReportKeyring,
}

impl std::fmt::Debug for ReportKeyring {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ReportKeyring(<opaque>)")
    }
}

impl ReportKeyring {
    /// Enrollment-time derivation from a BIP-39 mnemonic. UTF-8 bytes (the
    /// mnemonic never touches the Java intern pool), like
    /// [`ProvenanceSigner::from_mnemonic`]. The caller PIN-seals the master
    /// in-crate afterwards via [`Self::seal_with_session`] (no secret crosses).
    ///
    /// # Errors
    /// [`FfiError::InvalidMnemonic`] if not UTF-8; otherwise any derivation error.
    pub fn from_mnemonic(mnemonic: &[u8], passphrase: &[u8]) -> Result<Self, FfiError> {
        let mnemonic_s = std::str::from_utf8(mnemonic).map_err(|e| FfiError::InvalidMnemonic {
            detail: format!("mnemonic bytes are not valid UTF-8: {e}"),
        })?;
        let passphrase_s =
            std::str::from_utf8(passphrase).map_err(|e| FfiError::InvalidMnemonic {
                detail: format!("passphrase bytes are not valid UTF-8: {e}"),
            })?;
        core_report::ReportKeyring::from_mnemonic(mnemonic_s, passphrase_s)
            .map(|inner| Self { inner })
            .map_err(FfiError::from)
    }

    /// Recording-time reconstruction from the persisted 32-byte `report_master`
    /// (unsealed from the PIN store at unlock).
    ///
    /// # Errors
    /// [`FfiError::InvalidBlob`] if `report_master` isn't 32 bytes;
    /// [`FfiError::DerivationFailed`] on an mlock failure.
    pub fn from_seed(report_master: &[u8]) -> Result<Self, FfiError> {
        let arr: [u8; 32] = report_master
            .try_into()
            .map_err(|_| FfiError::InvalidBlob {
                detail: format!(
                    "report_master must be 32 bytes, got {}",
                    report_master.len()
                ),
            })?;
        core_report::ReportKeyring::from_seed(&arr)
            .map(|inner| Self { inner })
            .map_err(FfiError::from)
    }

    /// Lot 4b (OPTION B) — seal the report master with the held PIN-session key,
    /// all in-crate. Returns the sealed blob; the 32-byte master never crosses
    /// the FFI (the enrollment master-seal path — the secret never touches the
    /// JVM; the old `master_bytes()` export was retired in P6).
    ///
    /// # Errors
    /// [`FfiError::Internal`] if no PIN session is active; seal errors forward.
    pub fn seal_with_session(&self) -> Result<Vec<u8>, FfiError> {
        self.inner.with_master_bytes(|master| {
            match with_pin_session(|key, salt| core_pin_store::seal_with_key(key, salt, master)) {
                Some(res) => res.map_err(FfiError::from),
                None => Err(FfiError::Internal {
                    detail: "seal report master: no active PIN session".into(),
                }),
            }
        })
    }

    /// `report_id_n` as 32 lowercase hex chars — the identity-free URL address
    /// of report `n` (`PUT`/`GET /file/{report_id}/...`).
    ///
    /// # Errors
    /// Derivation errors forward from core.
    pub fn report_id_hex(&self, n: u32) -> Result<String, FfiError> {
        let id = self.inner.report_id(n).map_err(FfiError::from)?;
        Ok(hex_lower(&id))
    }

    /// `report_pk_n` (32 bytes) — the `X-Report-PK` header value (the relay
    /// binds `report_id == H(report_pk)` at creation).
    ///
    /// # Errors
    /// Derivation errors forward from core.
    pub fn report_pk(&self, n: u32) -> Result<Vec<u8>, FfiError> {
        self.inner
            .report_pk(n)
            .map(|pk| pk.to_vec())
            .map_err(FfiError::from)
    }

    /// `create_sig` (64 bytes) = `Ed25519(R_n, 0x07 ‖ report_id ‖ report_pk)`.
    /// The `X-Report-Create-Sig` header on the first chunk PUT.
    ///
    /// # Errors
    /// Derivation errors forward from core.
    pub fn sign_create(&self, n: u32) -> Result<Vec<u8>, FfiError> {
        self.inner
            .sign_create(n)
            .map(|s| s.to_vec())
            .map_err(FfiError::from)
    }

    /// `write_sig` (64 bytes) = `Ed25519(R_n, 0x08 ‖ report_id ‖ filename ‖
    /// body_sha256)`. The `X-Report-Write-Sig` header on every chunk PUT.
    /// `body_sha256` is the 32-byte SHA-256 of the sealed `.strm` the relay
    /// stores (must match the relay's streaming hash byte-for-byte).
    ///
    /// # Errors
    /// [`FfiError::InvalidBlob`] if `body_sha256` isn't 32 bytes; derivation
    /// errors forward from core.
    pub fn sign_write(
        &self,
        n: u32,
        filename: &str,
        body_sha256: &[u8],
    ) -> Result<Vec<u8>, FfiError> {
        let hash: [u8; 32] = body_sha256.try_into().map_err(|_| FfiError::InvalidBlob {
            detail: format!("body_sha256 must be 32 bytes, got {}", body_sha256.len()),
        })?;
        self.inner
            .sign_write(n, filename.as_bytes(), &hash)
            .map(|s| s.to_vec())
            .map_err(FfiError::from)
    }

    /// `report_id` of the report DIRECTORY (the singleton, phrase-derived report
    /// whose blob names are the allocated report indices) as 32 lowercase hex —
    /// the identity-free address the rescue device fetches to learn `n_max`, and
    /// the device writes one entry to per session. The directory's `report_pk` +
    /// create/write sigs are derived + applied INSIDE
    /// [`upload_put_directory_entry`], so they never cross the FFI separately.
    ///
    /// # Errors
    /// Derivation errors forward from core.
    pub fn directory_id_hex(&self) -> Result<String, FfiError> {
        let id = self.inner.directory_id().map_err(FfiError::from)?;
        Ok(hex_lower(&id))
    }

    /// The opaque blob NAME (32 lowercase hex) of directory entry `n` (M-1) — the
    /// relay-visible filename the writer PUTs for session `n`'s directory entry,
    /// and the value the rescue device re-derives + matches to recover `n_max`.
    /// Hex of [`frappuccino_crypto_core::report::ReportKeyring::directory_entry_name`]
    /// (secret-derived from `report_master`, so the relay cannot enumerate it).
    /// Replaces the old plain `%010d` index, which fingerprinted the directory and
    /// leaked the session count/cadence off the names.
    ///
    /// # Errors
    /// Derivation errors forward from core.
    pub fn directory_entry_name_hex(&self, n: u32) -> Result<String, FfiError> {
        let name = self.inner.directory_entry_name(n).map_err(FfiError::from)?;
        Ok(hex_lower(&name))
    }
}

/// SHA-256 of a plaintext chunk file, computed in Rust (heap-0: the plaintext
/// is read into a `Zeroizing` buffer and never crosses to the JVM). Returns the
/// 32-byte hash, to be accumulated into `chunk_hashes`.
///
/// # Errors
/// [`FfiError::Io`] on a read failure.
pub fn provenance_hash_plaintext_file(path: &str) -> Result<Vec<u8>, FfiError> {
    use zeroize::Zeroizing;
    let data = Zeroizing::new(std::fs::read(path).map_err(|e| FfiError::Io {
        detail: format!("read {path}: {e}"),
    })?);
    Ok(core_provenance::hash_plaintext_chunk(&data).to_vec())
}

/// §10.11 (lean "hash + Bitcoin", 2026-06-25) — compute the salted OTS commitment
/// over the media Merkle root for one recording:
/// `SHA-256(salt ‖ chunk_merkle_root(chunk_hashes))`, with
/// `salt = HKDF(provenance seed, recording_id)`. This is now the ONLY provenance
/// artifact the device produces — no manifest, no signature, no sealing. The
/// 32-byte commitment is what the device submits to the relay for trustless
/// timestamping; the root is recomputable from the disclosed chunks at verify
/// time, so nothing has to be stored or sealed. Attribution is on-demand at
/// disclosure, never committed here.
///
/// # Errors
/// [`FfiError::InvalidBlob`] on a wrong-length `recording_id` or chunk hash;
/// salt-derivation errors forward from core.
#[allow(clippy::needless_pass_by_value)]
pub fn provenance_ots_commitment(
    chunk_hashes: Vec<Vec<u8>>,
    recording_id: &[u8],
    signer: Arc<ProvenanceSigner>,
) -> Result<Vec<u8>, FfiError> {
    let rid: [u8; 16] = recording_id.try_into().map_err(|_| FfiError::InvalidBlob {
        detail: format!("recording_id must be 16 bytes, got {}", recording_id.len()),
    })?;
    let mut hashes = Vec::with_capacity(chunk_hashes.len());
    for (i, h) in chunk_hashes.iter().enumerate() {
        let hash: [u8; 32] = h.as_slice().try_into().map_err(|_| FfiError::InvalidBlob {
            detail: format!("chunk_hashes[{i}] must be 32 bytes, got {}", h.len()),
        })?;
        hashes.push(hash);
    }
    let root = core_provenance::chunk_merkle_root(&hashes);
    let salt = signer.inner.ots_salt(&rid).map_err(FfiError::from)?;
    Ok(core_provenance::ots_media_commitment(&salt, &root).to_vec())
}

// ============================================================================
// V2 relay client (enroll / challenge / verify / rotate / status)
// ============================================================================

/// Outcome of an enrollment call — UDL `[Enum] interface`, maps to a Kotlin
/// sealed class (`EnrollResult.Success`, `EnrollResult.AlreadyEnrolled`,
/// `EnrollResult.Failed`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnrollResult {
    Success,
    AlreadyEnrolled,
    Failed { code: u16, body: String },
}

impl From<frappuccino_crypto_stream::EnrollResult> for EnrollResult {
    fn from(e: frappuccino_crypto_stream::EnrollResult) -> Self {
        match e {
            frappuccino_crypto_stream::EnrollResult::Success => Self::Success,
            frappuccino_crypto_stream::EnrollResult::AlreadyEnrolled => Self::AlreadyEnrolled,
            frappuccino_crypto_stream::EnrollResult::Failed { code, body } => {
                Self::Failed { code, body }
            }
        }
    }
}

/// Kotlin view of `stream::ChallengeValue` — `nonce` is a 32-byte `Vec<u8>`
/// so the UDL `bytes` type carries it across without extra conversions.
#[derive(Debug, Clone)]
pub struct ChallengeValue {
    pub nonce: Vec<u8>,
    pub timestamp: u64,
}

// =============================================================================
// §10.6 (2026-06-13) — upload-session bearer held in Rust, never a long-lived
// Kotlin String. `StreamServerClient::verify` stashes the JWT here on success;
// the Kotlin upload path pulls a transient copy per request via
// `upload_auth_header()`; lock / panic-wipe / drain-complete call
// `upload_auth_clear()` to zeroize it. Process-global (a `static`) because the
// auth round-trip and the chunk PUTs run in different Android components — this
// mirrors the old Kotlin `UploadAuthHolder` object, moved into Rust.
// =============================================================================
static UPLOAD_JWT: std::sync::Mutex<Option<zeroize::Zeroizing<String>>> =
    std::sync::Mutex::new(None);

fn upload_jwt_guard() -> std::sync::MutexGuard<'static, Option<zeroize::Zeroizing<String>>> {
    // Recover from a poisoned lock rather than panic across the FFI: the
    // critical sections are trivial, and `upload_auth_clear` MUST always be
    // able to zeroize (the whole point of the holder).
    UPLOAD_JWT
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Internal — stash the upload bearer in the process-global Zeroizing holder.
/// Only `StreamServerClient::verify` calls this, so the JWT never crosses the
/// FFI as a Kotlin-supplied argument.
fn upload_auth_store(bearer: String) {
    *upload_jwt_guard() = Some(zeroize::Zeroizing::new(bearer));
}

/// Transient `"Bearer <jwt>"` for a single authenticated request, or `None`
/// if no session is active. The JWT itself stays in the Rust holder
/// (`Zeroizing`); Kotlin only ever sees a short-lived per-call copy.
#[must_use]
pub fn upload_auth_header() -> Option<String> {
    upload_jwt_guard().as_ref().map(|z| z.as_str().to_owned())
}

/// Zeroize and drop the stored upload bearer AND tear down the Rust upload
/// client's pooled connections (which may still carry the bearer) — the
/// Rust-transport equivalent of `OkHttp`'s `connectionPool.evictAll()`. Called
/// on 401 / lock / panic-wipe / auto-lock / drain-complete, so every JWT clear
/// also resets the transport, inheriting the same drain-deferral as the clear.
/// Idempotent.
pub fn upload_auth_clear() {
    // Dropping the `Zeroizing<String>` wipes its heap buffer in place.
    *upload_jwt_guard() = None;
    // Phase 1 M3 fix — drop the process-global upload client so connections
    // carrying the (now-cleared) bearer are closed. Coupling the reset here
    // covers ALL clear sites (UploadAuthHolder.clear + direct panicWipe +
    // V2LockTimeoutController) in one place, and the drain-deferral that gates
    // the clear (V2LockTimeoutController defers during an active drain) gates
    // the reset too. No-op if the upload client was never built.
    frappuccino_crypto_stream::reset_upload_client();
    // Phase 3a — same coupling for the QUIC transport: tear down the connection
    // (its session keys + any buffered request data) on every clear. No-op if
    // the QUIC client was never built / the feature is off.
    #[cfg(feature = "quic")]
    frappuccino_crypto_stream::reset_quic_client();
}

/// Whether an upload session bearer is currently held. Lets the upload path
/// gate on auth presence WITHOUT pulling a transient copy of the bearer into
/// the JVM — for the Rust transport (Phase 1) only the existence bit crosses
/// the FFI, never the bearer itself (heap-0 on the chunk path).
#[must_use]
pub fn upload_auth_present() -> bool {
    upload_jwt_guard().is_some()
}

// =============================================================================
// Lot 4b P1 (2026-06-27) — PIN-session holder (R-CR-1 no-export).
//
// Caches the Argon2id-derived key + salt for the unlocked session so the
// ratchet fast-reseal and the secondary-secret reload/seal can run WITHOUT the
// derived key ever crossing the FFI. Mirrors the upload-bearer holder above
// (`UPLOAD_JWT`): a process-global `Zeroizing` static, cleared by lock /
// panic-wipe / drain-safe auto-lock — but, unlike the bearer, NEVER on a 401
// (this key is not re-derivable without the PIN; clearing it mid-recording
// would strand chunks). No FFI fn ever returns the key: the P2+ combined calls
// (open+deserialize / serialize+seal) consume it strictly in-crate via
// `with_pin_session`.
//
// P1 lands this as DORMANT internal infrastructure (no FFI/UDL surface, no
// Kotlin caller) with an in-crate roundtrip test. The `#[allow(dead_code)]`
// markers below are removed in P2 when the combined-call FFI fns wire the
// callers.
// =============================================================================

/// Cached `(derived_key, salt)` for the current unlocked session. `derived_key`
/// is the Argon2id master that decrypts every PIN-sealed blob — held in
/// `Zeroizing` so it wipes in place on drop (clear / replace).
struct PinSessionState {
    derived_key: zeroize::Zeroizing<[u8; 32]>,
    salt: [u8; 16],
}

static PIN_SESSION: std::sync::Mutex<Option<PinSessionState>> = std::sync::Mutex::new(None);

fn pin_session_guard() -> std::sync::MutexGuard<'static, Option<PinSessionState>> {
    // Poison-recover rather than panic across the FFI — same rationale as
    // `upload_jwt_guard`: the critical sections are trivial and the clear MUST
    // always be able to zeroize.
    PIN_SESSION
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Internal — stash the Argon2id-derived key + salt for the session. The P2
/// combined unlock/populate paths call this after an in-crate `open_extended`,
/// so the key is never a Kotlin-supplied argument and never crosses back out.
/// Replacing an existing entry drops (zeroizes) the old key first.
fn pin_session_store(derived_key: &[u8], salt: &[u8]) -> Result<(), FfiError> {
    let key: [u8; 32] = derived_key.try_into().map_err(|_| FfiError::InvalidBlob {
        detail: format!(
            "pin-session derived_key must be 32 bytes, got {}",
            derived_key.len()
        ),
    })?;
    let salt_arr: [u8; 16] = salt.try_into().map_err(|_| FfiError::InvalidBlob {
        detail: format!("pin-session salt must be 16 bytes, got {}", salt.len()),
    })?;
    *pin_session_guard() = Some(PinSessionState {
        derived_key: zeroize::Zeroizing::new(key),
        salt: salt_arr,
    });
    Ok(())
}

/// Internal — borrow the cached `(derived_key, salt)` to run an in-crate seal /
/// open WITHOUT copying the key out of the holder. Returns `None` when no
/// session is active. The key reference never escapes the closure, so it never
/// reaches the FFI boundary — this is the heap-0 accessor the P2 combined calls
/// build on.
fn with_pin_session<R>(f: impl FnOnce(&[u8; 32], &[u8; 16]) -> R) -> Option<R> {
    pin_session_guard()
        .as_ref()
        .map(|s| f(&s.derived_key, &s.salt))
}

/// Internal — drop + zeroize the cached session key. Wired (P5) to the same
/// drain-safe events as the ratchet wipe (lock / panic-wipe / `fireRatchetLock`),
/// NEVER to a 401. Idempotent.
fn pin_session_clear_internal() {
    *pin_session_guard() = None;
}

// --- Lot 4b P2 combined calls: open/seal happen IN-CRATE via the holder; no
//     secret (derived key, ratchet 50-sk plaintext, provenance seed, report
//     master) ever crosses the FFI. These replace the raw `pin_store_*` exports
//     for the StreamUploadManager paths (the raw exports are retired in P6).

/// FFI — clear the cached PIN-session key (zeroize-on-drop). Called from Kotlin
/// `lock()` / `panicWipe()` and, drain-safe, from the auto-lock ratchet timeout
/// (P5). NEVER from a 401 (the key is not re-derivable without the PIN).
/// Idempotent.
pub fn pin_session_clear() {
    pin_session_clear_internal();
}

/// FFI — enrollment: run Argon2id once on `sealed_blob` and stash the derived
/// key + salt in the holder. The ratchet is already in memory from the
/// `EnrollmentKit`, so the plaintext is dropped (wiped) here; only the derived
/// key is retained, inside Rust. Nothing secret crosses back out.
///
/// # Errors
/// [`FfiError::WrongPin`] on a bad PIN / tampered blob, [`FfiError::InvalidBlob`]
/// on a structurally invalid blob.
pub fn pin_session_populate(pin: &[u8], sealed_blob: &[u8]) -> Result<(), FfiError> {
    let (_plaintext, derived_key, salt) =
        core_pin_store::open_extended(pin, sealed_blob).map_err(FfiError::from)?;
    pin_session_store(derived_key.as_slice(), &salt)
    // _plaintext + derived_key (Zeroizing) drop here → wiped.
}

/// FFI — unlock: run Argon2id once, stash the derived key + salt in the holder,
/// AND deserialize the ratchet, all in-crate. Returns the ratchet handle.
/// Neither the derived key nor the 50-key plaintext blob crosses the FFI
/// (replaces `pin_store_open_extended` + `EphemeralRatchet.deserialize`).
///
/// # Errors
/// [`FfiError::WrongPin`] on a bad PIN, [`FfiError::InvalidBlob`] on a malformed
/// ratchet blob.
pub fn pin_session_open_ratchet(
    pin: &[u8],
    sealed_blob: &[u8],
) -> Result<Arc<EphemeralRatchet>, FfiError> {
    let (plaintext, derived_key, salt) =
        core_pin_store::open_extended(pin, sealed_blob).map_err(FfiError::from)?;
    pin_session_store(derived_key.as_slice(), &salt)?;
    let ratchet =
        core_ratchet::EphemeralRatchet::deserialize(&plaintext).map_err(FfiError::from)?;
    Ok(Arc::new(EphemeralRatchet {
        inner: Mutex::new(ratchet),
    }))
    // plaintext + derived_key (Zeroizing) drop here → wiped.
}

/// FFI — unlock reload (OPTION B): unseal the provenance seed with the held
/// PIN-session key and reconstruct the signer, all in-crate. The 32-byte seed
/// never crosses the FFI (replaces `pin_store_open_with_key` +
/// `ProvenanceSigner::from_seed`, still the Rust function called just below but
/// no longer exported to Kotlin since 2026-09-03).
///
/// # Errors
/// [`FfiError::WrongPin`] on a bad blob, [`FfiError::Internal`] if no PIN session
/// is active (call `pin_session_open_ratchet` first).
pub fn pin_session_open_provenance_signer(
    sealed_blob: &[u8],
) -> Result<Arc<ProvenanceSigner>, FfiError> {
    let seed = match with_pin_session(|key, _salt| core_pin_store::open_with_key(key, sealed_blob))
    {
        Some(res) => res.map_err(FfiError::from)?,
        None => {
            return Err(FfiError::Internal {
                detail: "open provenance signer: no active PIN session".into(),
            })
        }
    };
    let signer = ProvenanceSigner::from_seed(seed.as_slice())?;
    Ok(Arc::new(signer))
    // seed (Zeroizing) drops here → wiped.
}

/// FFI — unlock reload (OPTION B): unseal the report master with the held
/// PIN-session key and reconstruct the keyring, all in-crate. The 32-byte master
/// never crosses the FFI (replaces `pin_store_open_with_key` +
/// `ReportKeyring.from_seed`).
///
/// # Errors
/// [`FfiError::WrongPin`] on a bad blob, [`FfiError::Internal`] if no PIN session
/// is active.
pub fn pin_session_open_report_keyring(sealed_blob: &[u8]) -> Result<Arc<ReportKeyring>, FfiError> {
    let master =
        match with_pin_session(|key, _salt| core_pin_store::open_with_key(key, sealed_blob)) {
            Some(res) => res.map_err(FfiError::from)?,
            None => {
                return Err(FfiError::Internal {
                    detail: "open report keyring: no active PIN session".into(),
                })
            }
        };
    let keyring = ReportKeyring::from_seed(master.as_slice())?;
    Ok(Arc::new(keyring))
    // master (Zeroizing) drops here → wiped.
}

/// Transport selector for [`upload_put_report_chunk`] and
/// [`upload_put_directory_entry`].
#[derive(Debug, Clone, Copy)]
pub enum TransportMode {
    /// Pinned TLS-over-TCP transport (`reqwest::blocking`) — Phase 1.
    DirectTls,
    /// Pinned HTTP/3-over-QUIC transport (`quinn` + `h3` + BBR) — Phase 3a, with
    /// an automatic QUIC->`DirectTls` fallback (Phase 3b brick 3): a QUIC
    /// transport-establishment failure routes the chunk over `DirectTls` for the
    /// same bearer, and latches so subsequent chunks skip QUIC until the next
    /// auth clear. A `.so` built without the `quic` feature behaves as
    /// `DirectTls`.
    ObfQuic,
}

/// Result of [`upload_put_report_chunk`] and [`upload_put_directory_entry`].
/// `http_status == 0` means no HTTP response
/// (connect / TLS / timeout / IO, or no bearer); `error_detail` is a short
/// machine tag (`no_bearer`, `file_missing`, `timeout`, `network`,
/// `client_build`). The Kotlin worker maps `http_status` through its existing
/// status-code branches unchanged.
#[derive(Debug, Clone)]
pub struct PutOutcome {
    /// HTTP status, or `0` when no response was obtained.
    pub http_status: u16,
    /// Wall-clock duration of the attempt, milliseconds.
    pub upload_ms: u64,
    /// Phase 3.49 (2026-06-23) — signal-A goodput. Transfer-only duration in
    /// ms (`send`/`do_put`, excluding setup + connect); `0` on failure / no
    /// transfer. Logging-only: the Kotlin worker emits `goodputKbps` from it
    /// but the adaptive decision still rides `upload_ms`. See
    /// [`frappuccino_crypto_stream::PutResult::transfer_ms`].
    pub transfer_ms: u64,
    /// Short machine tag when `http_status == 0`, else `None`.
    pub error_detail: Option<String>,
    /// Which transport actually delivered this chunk (Lot 3 B observability):
    /// `"obfquic"` (Salamander/QUIC established + delivered), `"directtls"`
    /// (release path or a no-`quic` `.so`), `"directtls_fallback"` (QUIC tried
    /// but failed to deliver → this chunk re-PUT over TLS), `"directtls_degraded"`
    /// (QUIC latched degraded this session → skipped), or `"none"` (failed before
    /// any PUT: no bearer / missing blob). Surfaced in the `StreamMetrics`
    /// `transport=` field so a field-test SHOWS whether the wire is obfuscated or
    /// silently fell back to the classifiable direct path (D-1).
    pub transport_used: String,
}

// `upload_put_chunk` REMOVED (2026-09-03). It was the Phase 1 chunk PUT, taking
// only a bearer, and it lost its last caller when Phase C made every write carry
// a per-report capability signature (`upload_put_report_chunk` /
// `upload_put_directory_entry` below). It had no Kotlin caller left, in
// production or in any harness.
//
// It went with `stream::put_chunk` and `stream::put_chunk_quic`, of which it was
// the sole caller. That second half is the part worth remembering: both are
// `pub` and re-exported from the stream crate, so removing only this function
// would have left them with zero callers and NO dead-code warning, and the
// shipped .so would have carried two unreachable transport entry points while
// the FFI surface looked smaller. Reducing a surface means reducing what the
// binary contains, not what the header advertises.

/// Streaming SHA-256 of a file (the ciphertext `.strm`) — byte-identical to the
/// relay's `hashlib.sha256(body)` over the streamed request body. Returns `None`
/// on a missing / empty / unreadable file (the concurrent-upload race the
/// transport reports as `file_missing`). Streamed in 8 KiB reads so a large
/// media PUT never materializes the whole blob in RAM.
const SHA256_STREAM_BUF: usize = 8 * 1024; // 8 KiB — bounded RAM regardless of blob size.
fn sha256_file(path: &str) -> Option<[u8; 32]> {
    use sha2::{Digest, Sha256};
    use std::io::Read as _;
    let mut file = std::fs::File::open(path).ok()?;
    if file.metadata().ok()?.len() == 0 {
        return None;
    }
    let mut hasher = Sha256::new();
    let mut buf = [0u8; SHA256_STREAM_BUF];
    loop {
        let read = file.read(&mut buf).ok()?;
        if read == 0 {
            break;
        }
        hasher.update(&buf[..read]);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&hasher.finalize());
    Some(out)
}

/// Phase C (relay-blind reports) — PUT one already-encrypted `.strm` chunk over
/// the pinned Rust transport, authorized by the per-report capability key `R_n`
/// (`core::report`) instead of by the identity. EVERY chunk carries
/// `X-Report-PK` + `X-Report-Write-Sig` (`0x08`, over `report_id ‖ filename ‖
/// sha256(body)`); ONLY the creating chunk additionally carries
/// `X-Report-Create-Sig` (`0x07`) + the stream JWT bearer (proof of enrollment;
/// the relay discards the identity after its anti-abuse counter).
///
/// The `.strm` is hashed IN Rust (streaming, ciphertext) so the body hash signed
/// here is byte-identical to the relay's hash over the request body. The keyring
/// re-derives `report_pk` / `report_id` / signatures from `n` internally
/// (`report_id == H(report_pk)` by construction); no secret crosses the FFI.
/// Never throws — every failure is reported in the [`PutOutcome`]
/// (`file_missing` on a concurrent-upload race, `no_report_sk` if signing fails,
/// `no_bearer` if a creating chunk has no held bearer).
// `keyring` is taken by value (`Arc<ReportKeyring>`): UniFFI passes interface
// handles as an owned `Arc`, so the scaffolding requires this signature even
// though the body only calls `&self` methods (same as
// `provenance_ots_commitment`). The lint can't see the FFI ABI constraint.
#[must_use]
#[allow(clippy::needless_pass_by_value)]
pub fn upload_put_report_chunk(
    url: &str,
    blob_path: &str,
    mode: TransportMode,
    keyring: Arc<ReportKeyring>,
    n: u32,
    filename: &str,
    is_creation: bool,
) -> PutOutcome {
    let fail = |detail: &str| PutOutcome {
        http_status: 0,
        upload_ms: 0,
        transfer_ms: 0,
        error_detail: Some(detail.to_owned()),
        transport_used: "none".to_owned(),
    };

    // Hash the .strm (streaming, ciphertext) — byte-identical to the relay's
    // streaming hash over the request body. Missing/empty = the concurrent-
    // upload race the transport reports as `file_missing` (caller treats as
    // success); surface the same tag without sending anything.
    let Some(body_sha256) = sha256_file(blob_path) else {
        return fail("file_missing");
    };

    // Derive + sign inside Rust (the keyring re-derives report_pk/report_id from
    // n; no secret crosses the FFI).
    let (Ok(report_pk), Ok(write_sig)) = (
        keyring.report_pk(n),
        keyring.sign_write(n, filename, &body_sha256),
    ) else {
        return fail("no_report_sk");
    };
    let report_pk_hex = hex_lower(&report_pk);
    let write_sig_hex = hex_lower(&write_sig);

    // Owned holders for the creation-only headers (empty when not creating).
    let mut create_sig_hex = String::new();
    let mut bearer = zeroize::Zeroizing::new(String::new());
    if is_creation {
        let Ok(cs) = keyring.sign_create(n) else {
            return fail("no_report_sk");
        };
        create_sig_hex = hex_lower(&cs);
        // The bearer is read inside Rust from the holder; it never crosses the
        // FFI. TOCTOU: if it was cleared between the gate and here, fail cleanly
        // (the chunk stays on disk, the worker retries).
        match upload_jwt_guard().as_ref() {
            Some(z) => bearer = zeroize::Zeroizing::new(z.as_str().to_owned()),
            None => return fail("no_bearer"),
        }
    }

    let mut headers: Vec<(&str, &str)> = vec![
        ("X-Report-PK", report_pk_hex.as_str()),
        ("X-Report-Write-Sig", write_sig_hex.as_str()),
    ];
    if is_creation {
        headers.push(("X-Report-Create-Sig", create_sig_hex.as_str()));
        headers.push(("Authorization", bearer.as_str()));
    }

    dispatch_capability_put(url, blob_path, mode, &headers)
}

/// Shared transport dispatch for the capability PUT paths
/// ([`upload_put_report_chunk`] / [`upload_put_directory_entry`]): the same mode
/// selection + QUIC->DirectTls fallback over a pre-built header set, so the two
/// entry points stay byte-for-byte identical on the wire and the transport logic
/// has one home.
fn dispatch_capability_put(
    url: &str,
    blob_path: &str,
    mode: TransportMode,
    headers: &[(&str, &str)],
) -> PutOutcome {
    let (r, transport_used) = match mode {
        TransportMode::DirectTls => (
            frappuccino_crypto_stream::put_chunk_with_headers(url, blob_path, headers),
            "directtls",
        ),
        TransportMode::ObfQuic => {
            #[cfg(not(feature = "quic"))]
            {
                (
                    frappuccino_crypto_stream::put_chunk_with_headers(url, blob_path, headers),
                    "directtls",
                )
            }
            #[cfg(feature = "quic")]
            {
                if frappuccino_crypto_stream::quic_is_degraded() {
                    (
                        frappuccino_crypto_stream::put_chunk_with_headers(url, blob_path, headers),
                        "directtls_degraded",
                    )
                } else {
                    let q = frappuccino_crypto_stream::put_chunk_quic_with_headers(
                        url, blob_path, headers,
                    );
                    let transport_failed = q.http_status == 0
                        && !matches!(q.error_detail.as_deref(), Some("file_missing" | "bad_url"));
                    if transport_failed {
                        let mut tls = frappuccino_crypto_stream::put_chunk_with_headers(
                            url, blob_path, headers,
                        );
                        if tls.http_status == 0 {
                            let qt = q.error_detail.as_deref().unwrap_or("quic");
                            let tt = tls.error_detail.as_deref().unwrap_or("network");
                            tls.error_detail = Some(format!("quic_fallback:{qt}->{tt}"));
                        }
                        (tls, "directtls_fallback")
                    } else {
                        (q, "obfquic")
                    }
                }
            }
        }
    };
    PutOutcome {
        http_status: r.http_status,
        upload_ms: r.upload_ms,
        transfer_ms: r.transfer_ms,
        error_detail: r.error_detail,
        transport_used: transport_used.to_owned(),
    }
}

/// Phase C (relay-blind reports) — PUT one report-DIRECTORY entry: a tiny blob
/// whose `filename` is the opaque [`ReportKeyring::directory_entry_name_hex`] of
/// an allocated report index (M-1 — secret-derived, not the plain index), written
/// to the witness's singleton directory report so the rescue device can recover
/// the authoritative `n_max` by re-deriving + matching the entry names
/// (derive-and-match) and enumerate reports EXACTLY rather than guessing where to
/// stop. The body carries no index (it is stored unsealed; M-1). Identical capability contract +
/// transport as [`upload_put_report_chunk`], but addressed/signed by the
/// directory key (`keyring.inner.directory_*`) rather than a per-index key.
/// `is_creation` is true only for the entry that lazily creates the directory
/// report (the first one to land; subsequent entries 425-retry until then).
/// Never throws — failures are reported in the [`PutOutcome`].
#[must_use]
#[allow(clippy::needless_pass_by_value)]
pub fn upload_put_directory_entry(
    url: &str,
    blob_path: &str,
    mode: TransportMode,
    keyring: Arc<ReportKeyring>,
    filename: &str,
    is_creation: bool,
) -> PutOutcome {
    let fail = |detail: &str| PutOutcome {
        http_status: 0,
        upload_ms: 0,
        transfer_ms: 0,
        error_detail: Some(detail.to_owned()),
        transport_used: "none".to_owned(),
    };

    let Some(body_sha256) = sha256_file(blob_path) else {
        return fail("file_missing");
    };

    // Derive + sign with the DIRECTORY key inside Rust (no secret crosses the FFI).
    let (Ok(report_pk), Ok(write_sig)) = (
        keyring.inner.directory_pk(),
        keyring
            .inner
            .sign_directory_write(filename.as_bytes(), &body_sha256),
    ) else {
        return fail("no_report_sk");
    };
    let report_pk_hex = hex_lower(&report_pk);
    let write_sig_hex = hex_lower(&write_sig);

    let mut create_sig_hex = String::new();
    let mut bearer = zeroize::Zeroizing::new(String::new());
    if is_creation {
        let Ok(cs) = keyring.inner.sign_directory_create() else {
            return fail("no_report_sk");
        };
        create_sig_hex = hex_lower(&cs);
        match upload_jwt_guard().as_ref() {
            Some(z) => bearer = zeroize::Zeroizing::new(z.as_str().to_owned()),
            None => return fail("no_bearer"),
        }
    }

    let mut headers: Vec<(&str, &str)> = vec![
        ("X-Report-PK", report_pk_hex.as_str()),
        ("X-Report-Write-Sig", write_sig_hex.as_str()),
    ];
    if is_creation {
        headers.push(("X-Report-Create-Sig", create_sig_hex.as_str()));
        headers.push(("Authorization", bearer.as_str()));
    }

    dispatch_capability_put(url, blob_path, mode, &headers)
}

/// Re-arm the QUIC transport at the start of a recording (Phase 3b brick 3).
///
/// When a chunk PUT cannot ESTABLISH a QUIC connection (UDP-blocked network,
/// endpoint down) the transport latches to `DirectTls` so the following chunks
/// do not each re-pay the connect timeout. That latch has to be released once
/// per recording, otherwise a network that recovers stays on `DirectTls` until
/// the next lock or auth clear, which can be many recordings away. Since the
/// data plane is what the obfuscation protects, staying latched needlessly
/// re-exposes the direct-IP signal for the whole session.
///
/// This used to be a side effect of `upload_create_report`, which stopped being
/// called when report creation became lazy (minted by the seq-0 PUT), so the
/// re-arm silently stopped firing. It is its own entry point now: a side effect
/// nobody invokes is not a behaviour, and the previous shape hid that.
///
/// Clears the latch ALONE, never a full `reset_quic_client`: a previous
/// recording may still be draining chunks over the live QUIC connection, and a
/// teardown would disrupt them. Idempotent, cheap, never throws. A `.so` built
/// without the `quic` feature has no latch and this is a no-op.
pub fn upload_transport_rearm() {
    #[cfg(feature = "quic")]
    frappuccino_crypto_stream::clear_quic_degraded();
}

/// FFI wrapper around `frappuccino_crypto_stream::StreamServerClient`. The
/// inner client is cheap to clone (`Arc` internal state) so we keep it by
/// value — no lock needed.
pub struct StreamServerClient {
    inner: frappuccino_crypto_stream::StreamServerClient,
}

impl std::fmt::Debug for StreamServerClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "StreamServerClient(<opaque>)")
    }
}

impl StreamServerClient {
    /// # Errors
    /// [`FfiError::Network`] if rustls can't build (missing crypto provider,
    /// pin parse).
    pub fn new(base_url: &str) -> Result<Self, FfiError> {
        frappuccino_crypto_stream::StreamServerClient::new(base_url)
            .map(|c| Self { inner: c })
            .map_err(FfiError::from)
    }

    /// # Errors
    /// [`FfiError::Network`] on connect / TLS / framing failure.
    pub fn enroll(
        &self,
        identity_pk_hex: &str,
        batch0_public_keys: &[Vec<u8>],
        batch0_signature: &[u8],
    ) -> Result<EnrollResult, FfiError> {
        if batch0_public_keys.len() != core_ratchet::BATCH_SIZE {
            return Err(FfiError::InvalidBlob {
                detail: format!(
                    "batch_0 must have exactly {} keys, got {}",
                    core_ratchet::BATCH_SIZE,
                    batch0_public_keys.len()
                ),
            });
        }
        let mut keys_fixed = [[0u8; 32]; core_ratchet::BATCH_SIZE];
        for (i, k) in batch0_public_keys.iter().enumerate() {
            let arr: [u8; 32] = k.as_slice().try_into().map_err(|_| FfiError::InvalidBlob {
                detail: format!("batch_0[{i}] must be 32 bytes, got {}", k.len()),
            })?;
            keys_fixed[i] = arr;
        }
        let sig_fixed: [u8; 64] = batch0_signature
            .try_into()
            .map_err(|_| FfiError::InvalidSignature)?;
        self.inner
            .enroll(identity_pk_hex, &keys_fixed, &sig_fixed)
            .map(EnrollResult::from)
            .map_err(FfiError::from)
    }

    /// # Errors
    /// [`FfiError::Network`] on HTTP / TLS failure, [`FfiError::InvalidBlob`]
    /// if the server's nonce isn't 32 bytes of hex or the timestamp is
    /// missing from the response.
    pub fn challenge(&self) -> Result<ChallengeValue, FfiError> {
        self.inner
            .challenge()
            .map(|cv| ChallengeValue {
                nonce: cv.nonce.to_vec(),
                timestamp: cv.timestamp,
            })
            .map_err(FfiError::from)
    }

    /// §10.6 — on success, stashes the bearer in the process-global Rust
    /// holder (pull it transiently via [`upload_auth_header`]) and returns
    /// `true`; the JWT is never returned to Kotlin. A server refusal is
    /// `Ok(false)`.
    ///
    /// # Errors
    /// Only the network layer — rejected signatures return `Ok(false)`.
    #[allow(clippy::needless_pass_by_value)]
    pub fn verify(
        &self,
        identity: Arc<StreamIdentity>,
        sig: RatchetSignature,
        nonce_hex: &str,
        timestamp: u64,
    ) -> Result<bool, FfiError> {
        let core_sig = core_ratchet::RatchetSignature {
            signature: sig
                .signature
                .as_slice()
                .try_into()
                .map_err(|_| FfiError::InvalidSignature)?,
            ephemeral_public_key: sig
                .ephemeral_public_key
                .as_slice()
                .try_into()
                .map_err(|_| FfiError::InvalidSignature)?,
            batch_number: sig.batch_number,
            key_index: sig.key_index,
        };
        match self
            .inner
            .verify(&identity.inner, &core_sig, nonce_hex, timestamp)
            .map_err(FfiError::from)?
        {
            // §10.6 — stash the bearer in the Rust-side holder rather than
            // hand it to Kotlin. The upload path pulls a transient copy via
            // `upload_auth_header()`; lock / panic / drain call
            // `upload_auth_clear()` to zeroize it.
            Some(bearer) => {
                upload_auth_store(bearer);
                Ok(true)
            }
            None => Ok(false),
        }
    }

    /// # Errors
    /// Network-layer failures. Server refusals return `Ok(false)`.
    #[allow(clippy::needless_pass_by_value)]
    pub fn rotate_batch(
        &self,
        identity_pk_hex: &str,
        proof: RotationProof,
    ) -> Result<bool, FfiError> {
        if proof.new_batch_public_keys.len() != core_ratchet::BATCH_SIZE {
            return Err(FfiError::InvalidBlob {
                detail: format!(
                    "new_batch must have exactly {} keys",
                    core_ratchet::BATCH_SIZE
                ),
            });
        }
        let mut new_pks = [[0u8; 32]; core_ratchet::BATCH_SIZE];
        for (i, k) in proof.new_batch_public_keys.iter().enumerate() {
            new_pks[i] = k.as_slice().try_into().map_err(|_| FfiError::InvalidBlob {
                detail: format!("new_batch[{i}] must be 32 bytes"),
            })?;
        }
        let core_proof = core_ratchet::RotationProof {
            new_batch_number: proof.new_batch_number,
            new_batch_public_keys: new_pks,
            signer_public_key: proof.signer_public_key.as_slice().try_into().map_err(|_| {
                FfiError::InvalidBlob {
                    detail: "signer_public_key must be 32 bytes".to_string(),
                }
            })?,
            signer_batch_number: proof.signer_batch_number,
            signer_key_index: proof.signer_key_index,
            signature: proof
                .signature
                .as_slice()
                .try_into()
                .map_err(|_| FfiError::InvalidSignature)?,
        };
        self.inner
            .rotate_batch(identity_pk_hex, &core_proof)
            .map_err(FfiError::from)
    }

    // =========================================================================
    // Phase 4.4.2 (rescue device client, 2026-05-19) — archive retrieval FFI.
    //
    // Mirror of the four `frappuccino_crypto_stream::StreamServerClient`
    // archive methods, plus a combined download+decrypt-to-file convenience
    // that keeps the ciphertext in Rust memory only (never lands on disk
    // before decryption). The Android client (ArchiveModeActivity) drives
    // the full rescue flow through these four entry points.
    //
    // Phase C relay-blind reports — reads are **identity-free**: the
    // phrase-derived `report_id` IS the capability, so no bearer, no
    // `archive_auth`, no `archive_list_reports`. The rescue device enumerates
    // its own `report_id`s by derivation (ReportKeyring.report_id_hex(n)) and
    // probes each via `archive_list_blobs` (None = 404 = a hole). The relay
    // stores `report_id → report_pk` and never the identity.
    // =========================================================================

    /// `GET /api/v2/archive/reports/{report_id}/blobs` — list every blob in a
    /// report. **Phase C relay-blind: identity-free** — no bearer; the
    /// phrase-derived `report_id` is the capability.
    ///
    /// Returns `None` on **404** (no record at this `report_id` — a *hole* in
    /// the rescue enumeration: an index allocated but never uploaded, or the
    /// end of the range), `Some(blobs)` when the report exists.
    ///
    /// # Errors
    /// [`FfiError::Network`] on real transport failures (5xx / TLS / DNS),
    /// which the caller retries and NEVER mistakes for a hole.
    pub fn archive_list_blobs(
        &self,
        report_id: &str,
    ) -> Result<Option<Vec<ArchiveBlobInfo>>, FfiError> {
        self.inner
            .archive_list_blobs(report_id)
            .map(|opt| opt.map(|v| v.into_iter().map(ArchiveBlobInfo::from).collect()))
            .map_err(FfiError::from)
    }

    /// `GET /api/v2/archive/reports/{report_id}/{filename}` then
    /// [`strm_decrypt_to_file`] would do, in one shot — though it calls
    /// [`strm_core_decrypt`] directly rather than that function, which is why
    /// the latter never acquired a Kotlin caller and left the FFI surface on
    /// 2026-09-03. The encrypted blob is
    /// streamed into a `Zeroizing<Vec<u8>>` buffer in Rust, decrypted
    /// against `archive`, and the plaintext is written directly to
    /// `output_path`. The encrypted blob **never touches disk** — it only
    /// exists in Rust memory for the duration of the call, which is wiped
    /// on drop.
    ///
    /// Why combined : mirrors the security shape of [`strm_encrypt_file`]
    /// on the upload side — plaintext only ever lands on disk after the
    /// crypto layer says it's authentic. If we exposed download and
    /// decrypt as separate FFI calls, the encrypted blob would land on
    /// disk as a STRM file even when the recipient is wrong — a Red
    /// Team-style attacker swapping STRM payloads would have a one-frame
    /// window to read pre-decrypt bytes via heap dump / file-system race.
    ///
    /// Returns the [`BlobMetadata`] (non-secret) plus the number of
    /// plaintext bytes written.
    ///
    /// # Errors
    /// [`FfiError::Network`] on HTTP failure (incl. 401 token expired),
    /// [`FfiError::WrongPin`] if the blob wasn't sealed for `archive`,
    /// [`FfiError::InvalidBlob`] for structural issues, [`FfiError::Io`]
    /// on the final write step.
    #[allow(clippy::needless_pass_by_value)]
    pub fn archive_download_and_decrypt(
        &self,
        report_id: &str,
        filename: &str,
        output_path: &str,
        archive: Arc<ArchiveIdentity>,
    ) -> Result<ArchiveDownloadResult, FfiError> {
        use zeroize::Zeroizing;
        // M-1 (WP-C): the relay supplies `filename`; the caller derives the local
        // write target (output_path) from it. Reject anything that is not a single
        // safe path component before any network/disk work, so a coerced relay
        // cannot path-traverse the rescue device. Defence in depth with the
        // Kotlin-side pre-check (archive_blob_filename_is_safe) and the relay's
        // own upload-time guard.
        if !frappuccino_crypto_stream::is_safe_blob_filename(filename) {
            return Err(FfiError::InvalidBlob {
                detail: format!("unsafe relay blob filename: {filename:?}"),
            });
        }
        // Download the encrypted blob into a Zeroizing<Vec<u8>> so the
        // ciphertext (which contains the nonce + sealed envelope — non-
        // secret per se but worth defensive zeroize) is wiped on drop.
        let mut buf: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::new());
        let downloaded = self
            .inner
            .archive_download_blob(report_id, filename, &mut *buf)
            .map_err(FfiError::from)?;
        // Decrypt into Zeroizing<Vec<u8>>, write plaintext to disk.
        let (plaintext_z, meta) =
            strm_core_decrypt(&buf, &archive.inner).map_err(FfiError::from)?;
        if let Err(e) = std::fs::write(output_path, plaintext_z.as_slice()) {
            // Same best-effort cleanup pattern as `strm_decrypt_to_file`.
            let _ =
                frappuccino_crypto_stream::secure_delete_file(std::path::Path::new(output_path));
            return Err(FfiError::Io {
                detail: format!("write {output_path}: {e}"),
            });
        }
        let plen = u64::try_from(meta.plaintext_len).map_err(|_| FfiError::Internal {
            detail: "plaintext_len overflows u64 (impossible)".to_string(),
        })?;
        Ok(ArchiveDownloadResult {
            downloaded_bytes: downloaded,
            plaintext_bytes: plen,
            metadata: BlobMetadata {
                version: meta.version,
                mode: meta.mode,
                grant_count: meta.grant_count,
                plaintext_len: plen,
            },
        })
    }

    /// `GET /api/v2/archive/reports/{report_id}/{filename}` and write the raw
    /// blob bytes to `output_path` **as-is, with NO STRM decryption**.
    ///
    /// §10.11 (provenance durability, 2026-06-24) — the provenance manifest
    /// (`<sessionId>.fpm`) is a `crypto_box_seal` envelope, **not** a STRM
    /// blob, so it must be fetched raw and unsealed/verified offline by the
    /// recipient (against the published provenance pubkey). Routing it through
    /// [`Self::archive_download_and_decrypt`] would fail the STRM header parse
    /// and abort the rescue batch. The bytes written are exactly the sealed
    /// envelope as stored on the relay — non-secret (the relay is blind; only
    /// the recipient's X25519 secret can open it), so no `Zeroizing` buffer is
    /// warranted here unlike the decrypt path.
    ///
    /// Returns the number of bytes written.
    ///
    /// # Errors
    /// [`FfiError::Network`] on HTTP failure (incl. 401 token expired),
    /// [`FfiError::Io`] on the final write step.
    pub fn archive_download_raw(
        &self,
        report_id: &str,
        filename: &str,
        output_path: &str,
    ) -> Result<u64, FfiError> {
        // M-1 (WP-C): validate the relay-supplied filename before any disk write
        // (see archive_download_and_decrypt for the rationale).
        if !frappuccino_crypto_stream::is_safe_blob_filename(filename) {
            return Err(FfiError::InvalidBlob {
                detail: format!("unsafe relay blob filename: {filename:?}"),
            });
        }
        let mut buf: Vec<u8> = Vec::new();
        let downloaded = self
            .inner
            .archive_download_blob(report_id, filename, &mut buf)
            .map_err(FfiError::from)?;
        if let Err(e) = std::fs::write(output_path, &buf) {
            // Best-effort cleanup of any partial write, mirroring the
            // decrypt path's failure handling.
            let _ =
                frappuccino_crypto_stream::secure_delete_file(std::path::Path::new(output_path));
            return Err(FfiError::Io {
                detail: format!("write {output_path}: {e}"),
            });
        }
        Ok(downloaded)
    }
}

/// Per-blob metadata returned by [`StreamServerClient::archive_list_blobs`].
/// Mirrors [`frappuccino_crypto_stream::ArchiveBlobInfo`].
#[derive(Debug, Clone)]
pub struct ArchiveBlobInfo {
    pub filename: String,
    pub size: u64,
    pub last_modified: Option<String>,
}

impl From<frappuccino_crypto_stream::ArchiveBlobInfo> for ArchiveBlobInfo {
    fn from(b: frappuccino_crypto_stream::ArchiveBlobInfo) -> Self {
        Self {
            filename: b.filename,
            size: b.size,
            last_modified: b.last_modified,
        }
    }
}

/// Result returned by [`StreamServerClient::archive_download_and_decrypt`].
/// Carries both the network-side download size and the decrypted plaintext
/// size so the caller can detect a partial download (rare given the FFI
/// surfaces an error before this returns, but cheap to expose).
#[derive(Debug, Clone)]
pub struct ArchiveDownloadResult {
    pub downloaded_bytes: u64,
    pub plaintext_bytes: u64,
    pub metadata: BlobMetadata,
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    const MN_FIXED: &str = "abaisser abandon abdiquer abeille abolir aborder aboutir aboyer abrasif abreuver abriter abroger";

    // §10.6 — the process-global upload-bearer holder: store -> header copy ->
    // clear -> empty. A single test owns the static for its whole sequence (no
    // other test touches UPLOAD_JWT), so there is no cross-test interference.
    #[test]
    fn upload_auth_holder_roundtrip_then_clear() {
        upload_auth_clear();
        assert_eq!(upload_auth_header(), None);
        upload_auth_store("Bearer eyJhbGciOiJIUzI1Ni.test".to_string());
        assert_eq!(
            upload_auth_header().as_deref(),
            Some("Bearer eyJhbGciOiJIUzI1Ni.test")
        );
        // A second read still returns it (header is a copy, not a take).
        assert!(upload_auth_header().is_some());
        upload_auth_clear();
        assert_eq!(upload_auth_header(), None);
        // Clear is idempotent.
        upload_auth_clear();
        assert_eq!(upload_auth_header(), None);
    }

    // Both PIN-session tests mutate the process-global PIN_SESSION static; this
    // guard serializes them (the harness runs tests in parallel threads).
    static PIN_SESSION_TEST_GUARD: std::sync::Mutex<()> = std::sync::Mutex::new(());
    fn pin_session_test_guard() -> std::sync::MutexGuard<'static, ()> {
        PIN_SESSION_TEST_GUARD
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    // Lot 4b P1 — the PIN-session holder: store -> borrow -> replace -> clear.
    // The key is borrowed via `with_pin_session` and never copied out — mirrors
    // how the P2 combined calls seal/open in-crate.
    #[test]
    fn pin_session_holder_store_borrow_replace_clear() {
        let _g = pin_session_test_guard();
        pin_session_clear_internal();
        // Empty: the accessor yields None.
        assert!(with_pin_session(|_, _| ()).is_none());

        // Wrong lengths are rejected (no panic across the FFI).
        assert!(pin_session_store(&[0u8; 31], &[0u8; 16]).is_err());
        assert!(pin_session_store(&[0u8; 32], &[0u8; 15]).is_err());
        assert!(with_pin_session(|_, _| ()).is_none());

        // Store, then borrow the exact bytes back (no copy escapes the closure).
        let key_a = [7u8; 32];
        let salt_a = [3u8; 16];
        pin_session_store(&key_a, &salt_a).unwrap();
        let seen = with_pin_session(|k, s| (*k, *s));
        assert_eq!(seen, Some((key_a, salt_a)));

        // Replace drops the old key and installs the new pair.
        let key_b = [9u8; 32];
        let salt_b = [5u8; 16];
        pin_session_store(&key_b, &salt_b).unwrap();
        assert_eq!(with_pin_session(|k, s| (*k, *s)), Some((key_b, salt_b)));

        // Clear zeroizes + drops; the accessor is empty again, idempotently.
        pin_session_clear_internal();
        assert!(with_pin_session(|_, _| ()).is_none());
        pin_session_clear_internal();
        assert!(with_pin_session(|_, _| ()).is_none());
    }

    // Lot 4b P2 — the combined no-export calls: a full enroll/unlock/reseal +
    // secondary-seed seal/reload roundtrip, all in-crate. Proves the holder
    // drives open+deserialize / serialize+seal, and that every holder-backed
    // call fails with `Internal` once the session is cleared.
    #[test]
    fn pin_session_combined_calls_roundtrip() {
        let _g = pin_session_test_guard();
        pin_session_clear();

        // No active session: the fast-reseal path surfaces Internal.
        let kit = Arc::new(EnrollmentKit::from_mnemonic(MN_FIXED.as_bytes(), b"").unwrap());
        let ratchet = EphemeralRatchet::from_kit(kit).unwrap();
        assert!(matches!(
            ratchet.reseal_session_blob().unwrap_err(),
            FfiError::Internal { .. }
        ));

        // Seal the initial ratchet blob with a PIN, in-crate (Argon2id #1) —
        // the enrollment path; the 50-sk plaintext never leaves Rust.
        let pin = b"123456";
        let sealed0 = ratchet.seal_with_pin(pin).unwrap();
        assert_eq!(ratchet.batch_number().unwrap(), 0);

        // Unlock via the combined call: populates the holder + returns a handle.
        let unlocked = pin_session_open_ratchet(pin, &sealed0).unwrap();
        // Fast-reseal now works and round-trips back to the same batch.
        let resealed = unlocked.reseal_session_blob().unwrap();
        let reopened = pin_session_open_ratchet(pin, &resealed).unwrap();
        assert_eq!(
            reopened.batch_public_keys().unwrap(),
            unlocked.batch_public_keys().unwrap()
        );

        // Enrollment path: populate primes the holder for the seed seals.
        pin_session_clear();
        pin_session_populate(pin, &sealed0).unwrap();

        // Provenance (OPTION B): seal + reload in-crate; seed never crosses.
        let signer = ProvenanceSigner::from_mnemonic(MN_FIXED.as_bytes(), b"").unwrap();
        let prov_sealed = signer.seal_with_session().unwrap();
        let prov_reloaded = pin_session_open_provenance_signer(&prov_sealed).unwrap();
        let rid = [9u8; 16];
        assert_eq!(
            prov_reloaded.ots_salt(&rid).unwrap(),
            signer.ots_salt(&rid).unwrap()
        );

        // Report keyring (OPTION B): seal + reload in-crate; master never crosses.
        let keyring = ReportKeyring::from_mnemonic(MN_FIXED.as_bytes(), b"").unwrap();
        let rep_sealed = keyring.seal_with_session().unwrap();
        let rep_reloaded = pin_session_open_report_keyring(&rep_sealed).unwrap();
        assert_eq!(
            rep_reloaded.report_id_hex(0).unwrap(),
            keyring.report_id_hex(0).unwrap()
        );

        // After clear, every holder-backed call fails (no session).
        pin_session_clear();
        assert!(matches!(
            signer.seal_with_session().unwrap_err(),
            FfiError::Internal { .. }
        ));
        assert!(matches!(
            pin_session_open_report_keyring(&rep_sealed).unwrap_err(),
            FfiError::Internal { .. }
        ));
    }

    #[test]
    fn hello_world_is_expected() {
        assert_eq!(hello_world(), "hello from rust via uniffi (S0)");
    }

    #[test]
    fn core_version_non_empty() {
        let v = core_version();
        assert!(!v.is_empty());
        assert!(v.contains('.'));
    }

    #[test]
    fn report_keyring_derivation_deterministic_and_pk_binding() {
        let mn = MN_FIXED.as_bytes();
        let k1 = ReportKeyring::from_mnemonic(mn, b"").unwrap();
        let k2 = ReportKeyring::from_mnemonic(mn, b"").unwrap();
        // Deterministic per index (re-derivable at rescue from the phrase).
        assert_eq!(k1.report_id_hex(0).unwrap(), k2.report_id_hex(0).unwrap());
        assert_eq!(k1.report_pk(4).unwrap(), k2.report_pk(4).unwrap());

        // report_id_hex shape: exactly 32 lowercase hex chars.
        let id = k1.report_id_hex(0).unwrap();
        assert_eq!(id.len(), 32);
        assert!(id
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()));

        // report_pk shape: 32 bytes; and report_id == H(report_pk) (the binding
        // the relay re-checks at creation).
        let pk = k1.report_pk(0).unwrap();
        assert_eq!(pk.len(), 32);
        let pk_arr: [u8; 32] = pk.as_slice().try_into().unwrap();
        assert_eq!(id, hex_lower(&core_report::report_id_from_pk(&pk_arr)));

        // The master -> from_seed roundtrip is now exercised end-to-end in-crate
        // (no secret crosses the FFI) by `pin_session_combined_calls_roundtrip`
        // via `seal_with_session` + `pin_session_open_report_keyring`; the raw
        // `master_bytes()` export was retired in Lot 4b P6.
    }

    #[test]
    fn report_keyring_signature_shapes_and_input_errors() {
        let k = ReportKeyring::from_mnemonic(MN_FIXED.as_bytes(), b"").unwrap();
        assert_eq!(k.sign_create(1).unwrap().len(), 64);
        assert_eq!(k.sign_write(1, "blob.strm", &[0u8; 32]).unwrap().len(), 64);
        // Different index => different create signature.
        assert_ne!(k.sign_create(1).unwrap(), k.sign_create(2).unwrap());
        // Different filename / body => different write signature.
        assert_ne!(
            k.sign_write(1, "a.strm", &[0u8; 32]).unwrap(),
            k.sign_write(1, "b.strm", &[0u8; 32]).unwrap()
        );

        // from_seed with a wrong-length master => InvalidBlob (not a panic).
        let err = ReportKeyring::from_seed(&[0u8; 31]).unwrap_err();
        assert!(matches!(err, FfiError::InvalidBlob { .. }));
        // sign_write with a wrong-length body hash => InvalidBlob.
        let err = k.sign_write(1, "blob.strm", &[0u8; 16]).unwrap_err();
        assert!(matches!(err, FfiError::InvalidBlob { .. }));
    }

    #[test]
    fn sha256_file_is_byte_identical_to_known_digest() {
        // The write-sig the relay verifies covers sha256(body); the device must
        // hash the .strm to the EXACT same digest the relay computes streaming.
        use sha2::{Digest, Sha256};
        let path = std::env::temp_dir().join("frap_sha256_file_test.bin");
        let content = b"relay-blind report chunk ciphertext bytes";
        std::fs::write(&path, content).unwrap();
        let got = sha256_file(path.to_str().unwrap()).unwrap();
        let expected: [u8; 32] = Sha256::digest(content).into();
        assert_eq!(got, expected);
        // Empty file => None (the file_missing race tag, treated as success).
        std::fs::write(&path, b"").unwrap();
        assert!(sha256_file(path.to_str().unwrap()).is_none());
        let _ = std::fs::remove_file(&path);
        // Missing file => None.
        assert!(sha256_file("/no/such/frap/blob.strm").is_none());
    }

    #[test]
    fn upload_put_report_chunk_missing_file_is_file_missing() {
        // A missing blob (concurrent-upload race) is reported as file_missing
        // WITHOUT contacting the network — no server needed for this path.
        let keyring = ReportKeyring::from_mnemonic(MN_FIXED.as_bytes(), b"").unwrap();
        let outcome = upload_put_report_chunk(
            "https://relay/file/aa/c.strm",
            "/no/such/frap/blob.strm",
            TransportMode::DirectTls,
            std::sync::Arc::new(keyring),
            0,
            "c.strm",
            false,
        );
        assert_eq!(outcome.http_status, 0);
        assert_eq!(outcome.error_detail.as_deref(), Some("file_missing"));
    }

    #[test]
    fn bip39_generate_produces_12_words() {
        // Phase 6.1.4-B : bip39_generate_fr() retourne Vec<u8>. On reconvertit
        // en str pour le split_whitespace test (UTF-8 valid by construction).
        let mn = bip39_generate_fr();
        let s = std::str::from_utf8(&mn).expect("generate must return valid UTF-8");
        assert_eq!(s.split_whitespace().count(), 12);
    }

    #[test]
    fn bip39_validate_accepts_freshly_generated() {
        let mn = bip39_generate_fr();
        bip39_validate_fr(&mn).expect("freshly-generated mnemonic must validate");
    }

    #[test]
    fn bip39_validate_rejects_garbage() {
        let err = bip39_validate_fr(b"xyzzy plugh wibble wobble").unwrap_err();
        // Any non-None error is fine — we only care it didn't silently pass.
        assert!(!matches!(err, FfiError::Internal { .. }));
    }

    #[test]
    fn bip39_normalize_round_trips() {
        let w = bip39_normalize_word_fr("abaisser").unwrap();
        assert_eq!(w, "abaisser");
    }

    #[test]
    fn pin_store_roundtrip() {
        let plaintext = b"top secret";
        let blob = pin_store_seal(b"123456", plaintext).unwrap();
        let out = pin_store_open(b"123456", &blob).unwrap();
        assert_eq!(&out[..], plaintext);
    }

    #[test]
    fn pin_store_wrong_pin() {
        let blob = pin_store_seal(b"123456", b"x").unwrap();
        let err = pin_store_open(b"999999", &blob).unwrap_err();
        assert!(matches!(err, FfiError::WrongPin));
    }

    #[test]
    fn pin_store_empty_pin_rejects() {
        let err = pin_store_seal(b"", b"x").unwrap_err();
        assert!(matches!(err, FfiError::EmptyInput));
    }

    #[test]
    fn enrollment_kit_sign_verify_roundtrip() {
        let kit = EnrollmentKit::from_mnemonic(MN_FIXED.as_bytes(), b"").unwrap();
        let identity = kit.identity().unwrap();
        let msg = b"hello";
        let sig = kit.sign_enrollment(msg).unwrap();
        identity
            .verify(
                &frappuccino_crypto_core::signature_domain::SignatureDomain::Enrollment
                    .prefixed(msg),
                &sig,
            )
            .unwrap();
    }

    #[test]
    fn enrollment_kit_matches_archive_identity() {
        let kit = EnrollmentKit::from_mnemonic(MN_FIXED.as_bytes(), b"").unwrap();
        let archive = ArchiveIdentity::from_mnemonic(MN_FIXED.as_bytes(), b"").unwrap();
        assert_eq!(
            kit.identity().unwrap().ed25519_pk(),
            archive.identity().ed25519_pk()
        );
        assert_eq!(
            kit.identity().unwrap().x25519_pk(),
            archive.identity().x25519_pk()
        );
    }

    #[test]
    fn enrollment_kit_close_invalidates() {
        let kit = EnrollmentKit::from_mnemonic(MN_FIXED.as_bytes(), b"").unwrap();
        kit.wipe();
        let err = kit.sign_enrollment(b"x").unwrap_err();
        assert!(matches!(err, FfiError::AlreadyConsumed { .. }));
    }

    #[test]
    fn ratchet_from_kit_sign_and_advance() {
        let kit = Arc::new(EnrollmentKit::from_mnemonic(MN_FIXED.as_bytes(), b"").unwrap());
        let identity = kit.identity().unwrap();
        let ratchet = EphemeralRatchet::from_kit(kit).unwrap();

        let pks = ratchet.batch_public_keys().unwrap();
        assert_eq!(pks.len(), 50);
        assert_eq!(pks[0].len(), 32);

        let sig = ratchet.sign_and_advance(b"challenge-1").unwrap();
        assert_eq!(sig.batch_number, 0);
        assert_eq!(sig.key_index, 0);
        assert_eq!(sig.signature.len(), 64);
        assert_eq!(sig.ephemeral_public_key, pks[0]);
        // Sanity: the identity's public key is NOT equal to the ephemeral one
        // (different derivation tree).
        assert_ne!(identity.ed25519_pk(), sig.ephemeral_public_key);
    }

    #[test]
    fn ratchet_serialize_deserialize_roundtrip() {
        let kit = Arc::new(EnrollmentKit::from_mnemonic(MN_FIXED.as_bytes(), b"").unwrap());
        let ratchet = EphemeralRatchet::from_kit(kit).unwrap();
        let _ = ratchet.sign_and_advance(b"msg").unwrap();
        let blob = ratchet.serialize().unwrap();

        let resumed = EphemeralRatchet::deserialize(&blob).unwrap();
        let pks_a = ratchet.batch_public_keys().unwrap();
        let pks_b = resumed.batch_public_keys().unwrap();
        assert_eq!(pks_a, pks_b, "batch pub keys must survive round-trip");
    }

    #[test]
    fn ratchet_remaining_in_batch_starts_full_then_decrements() {
        // RT-07 regression: previously the Kotlin caller had no way to
        // observe slot consumption (the FFI didn't expose it), so
        // auto-rotate was permanently disabled. With this method live,
        // every sign_and_advance is observable.
        let kit = Arc::new(EnrollmentKit::from_mnemonic(MN_FIXED.as_bytes(), b"").unwrap());
        let ratchet = EphemeralRatchet::from_kit(kit).unwrap();
        assert_eq!(ratchet.remaining_in_batch().unwrap(), 50);

        ratchet.sign_and_advance(b"first").unwrap();
        assert_eq!(ratchet.remaining_in_batch().unwrap(), 49);

        ratchet.sign_and_advance(b"second").unwrap();
        assert_eq!(ratchet.remaining_in_batch().unwrap(), 48);
    }

    #[test]
    fn ratchet_remaining_in_batch_resets_after_rotation() {
        let kit = Arc::new(EnrollmentKit::from_mnemonic(MN_FIXED.as_bytes(), b"").unwrap());
        let ratchet = EphemeralRatchet::from_kit(kit).unwrap();
        for _ in 0..5 {
            ratchet.sign_and_advance(b"x").unwrap();
        }
        assert_eq!(ratchet.remaining_in_batch().unwrap(), 45);

        // advance_batch consumes one slot of the OLD batch to sign the new
        // one, then installs the fresh batch — counter resets to 50.
        ratchet.advance_batch().unwrap();
        assert_eq!(ratchet.remaining_in_batch().unwrap(), 50);
    }

    #[test]
    fn ratchet_advance_batch_emits_proof_with_50_keys() {
        let kit = Arc::new(EnrollmentKit::from_mnemonic(MN_FIXED.as_bytes(), b"").unwrap());
        let ratchet = EphemeralRatchet::from_kit(kit).unwrap();
        let proof = ratchet.advance_batch().unwrap();
        assert_eq!(proof.new_batch_number, 1);
        assert_eq!(proof.new_batch_public_keys.len(), 50);
        assert!(proof.new_batch_public_keys.iter().all(|k| k.len() == 32));
        assert_eq!(proof.signature.len(), 64);
    }

    #[test]
    fn ratchet_from_wiped_kit_fails() {
        let kit = Arc::new(EnrollmentKit::from_mnemonic(MN_FIXED.as_bytes(), b"").unwrap());
        kit.wipe();
        let err = EphemeralRatchet::from_kit(kit).unwrap_err();
        assert!(matches!(err, FfiError::AlreadyConsumed { .. }));
    }

    // =========================================================================
    // S8b: STRM + StreamServerClient
    // =========================================================================

    #[test]
    fn strm_encrypt_decrypt_roundtrip() {
        let kit = EnrollmentKit::from_mnemonic(MN_FIXED.as_bytes(), b"").unwrap();
        let author = kit.identity().unwrap();
        let archive = Arc::new(ArchiveIdentity::from_mnemonic(MN_FIXED.as_bytes(), b"").unwrap());

        let plaintext = b"S8b FFI roundtrip payload".to_vec();
        let blob = strm_encrypt(&plaintext, author).unwrap();
        let out = strm_decrypt(&blob, archive).unwrap();

        assert_eq!(out.plaintext, plaintext);
        assert_eq!(out.metadata.version, 3, "encoder emits VERSION_V3 (F-C1)");
        assert!(matches!(out.metadata.mode, 1 | 2));
        assert_eq!(out.metadata.grant_count, 0);
        assert_eq!(out.metadata.plaintext_len, plaintext.len() as u64);
        // F-C1: BlobMetadata no longer carries any author identity field.
    }

    #[test]
    fn strm_decrypt_to_file_roundtrip() {
        // Phase H2-B.18 (Red MED-4) — roundtrip via the path-based
        // variant. Encrypts a plaintext to a tmp file using
        // strm_encrypt_file, then decrypts it back via
        // strm_decrypt_to_file, and asserts the recovered file matches
        // the original bytes + the metadata stays consistent.
        let kit = EnrollmentKit::from_mnemonic(MN_FIXED.as_bytes(), b"").unwrap();
        let author = kit.identity().unwrap();
        let archive = Arc::new(ArchiveIdentity::from_mnemonic(MN_FIXED.as_bytes(), b"").unwrap());

        // Use a unique tmp dir per test to avoid CI races.
        let tmpdir = std::env::temp_dir().join(format!(
            "frappuccino-test-decrypt-to-file-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&tmpdir).unwrap();
        let plaintext_in = tmpdir.join("plaintext-in.bin");
        let blob_path = tmpdir.join("blob.strm");
        let plaintext_out = tmpdir.join("plaintext-out.bin");

        let payload = b"H2-B.17 Red MED-4 plaintext-to-file roundtrip".to_vec();
        std::fs::write(&plaintext_in, &payload).unwrap();

        // Encrypt via file path (Phase 6.1.4-C path).
        let blob_len = strm_encrypt_file(
            plaintext_in.to_str().unwrap(),
            blob_path.to_str().unwrap(),
            author,
        )
        .unwrap();
        assert!(blob_len > 0);

        // Decrypt to file (Phase H2-B.17 path under test).
        let meta = strm_decrypt_to_file(
            blob_path.to_str().unwrap(),
            plaintext_out.to_str().unwrap(),
            archive,
        )
        .unwrap();
        assert_eq!(meta.version, 3);
        assert!(matches!(meta.mode, 1 | 2));
        assert_eq!(meta.plaintext_len, payload.len() as u64);
        assert_eq!(meta.grant_count, 0);
        // F-C1: BlobMetadata no longer carries any author identity field.

        // Recovered file must match the original byte-for-byte.
        let recovered = std::fs::read(&plaintext_out).unwrap();
        assert_eq!(recovered, payload);

        // Cleanup.
        let _ = std::fs::remove_dir_all(&tmpdir);
    }

    #[test]
    fn strm_decrypt_to_file_rejects_wrong_recipient() {
        // Phase H2-B.18 — wrong archive identity must return WrongPin
        // and NOT write to the output path (the file should NOT exist
        // after a failed decrypt).
        let attacker_mn = "bambin bambou banane bandeau banlieue banque banquise bassin bastion bataille bateau batterie";
        let Ok(archive) = ArchiveIdentity::from_mnemonic(attacker_mn.as_bytes(), b"") else {
            eprintln!("skip: decoy mnemonic unknown-words on this wordlist");
            return;
        };
        let kit = EnrollmentKit::from_mnemonic(MN_FIXED.as_bytes(), b"").unwrap();
        let author = kit.identity().unwrap();

        let tmpdir = std::env::temp_dir().join(format!(
            "frappuccino-test-decrypt-to-file-wrong-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&tmpdir).unwrap();
        let plaintext_in = tmpdir.join("plaintext-in.bin");
        let blob_path = tmpdir.join("blob.strm");
        let plaintext_out = tmpdir.join("plaintext-out.bin");

        std::fs::write(&plaintext_in, b"sealed-for-author-only").unwrap();
        strm_encrypt_file(
            plaintext_in.to_str().unwrap(),
            blob_path.to_str().unwrap(),
            author,
        )
        .unwrap();

        let err = strm_decrypt_to_file(
            blob_path.to_str().unwrap(),
            plaintext_out.to_str().unwrap(),
            Arc::new(archive),
        )
        .unwrap_err();
        assert!(matches!(err, FfiError::WrongPin));
        // The output file must not have been written.
        assert!(
            !plaintext_out.exists(),
            "plaintext_out should not exist after a failed decrypt — found {plaintext_out:?}"
        );

        let _ = std::fs::remove_dir_all(&tmpdir);
    }

    #[test]
    fn strm_decrypt_rejects_wrong_recipient() {
        let attacker_mn = "bambin bambou banane bandeau banlieue banque banquise bassin bastion bataille bateau batterie";
        // Guard: the decoy mnemonic must at least parse — if Kotlin's wordlist
        // rejects it the test becomes trivially green on parse fail.
        let Ok(archive) = ArchiveIdentity::from_mnemonic(attacker_mn.as_bytes(), b"") else {
            eprintln!("skip: decoy mnemonic unknown-words on this wordlist");
            return;
        };
        let kit = EnrollmentKit::from_mnemonic(MN_FIXED.as_bytes(), b"").unwrap();
        let author = kit.identity().unwrap();
        let blob = strm_encrypt(b"secret", author).unwrap();
        let err = strm_decrypt(&blob, Arc::new(archive)).unwrap_err();
        // decrypt_session_key → WrongPin when the sealed envelope can't unseal.
        assert!(matches!(err, FfiError::WrongPin));
    }

    #[test]
    fn strm_encrypt_rejects_malformed_author() {
        // Sanity: the author must match the archive for the roundtrip to work.
        // This test just covers the public API — a wrong pubkey produces a
        // blob that the *right* archive still can't decrypt.
        let author_kit = EnrollmentKit::from_mnemonic(MN_FIXED.as_bytes(), b"").unwrap();
        let author = author_kit.identity().unwrap();
        let other_mn = bip39_generate_fr();
        let other_archive = Arc::new(ArchiveIdentity::from_mnemonic(&other_mn, b"").unwrap());

        let blob = strm_encrypt(b"x", author).unwrap();
        let err = strm_decrypt(&blob, other_archive).unwrap_err();
        assert!(matches!(err, FfiError::WrongPin));
    }

    #[test]
    fn stream_server_client_build_succeeds() {
        // Just build — no network. Failure would indicate TLS wiring broke.
        let c = StreamServerClient::new("https://relay.shake-document-protect.org:8443")
            .expect("client build");
        // Debug print shouldn't leak internals.
        let dbg = format!("{c:?}");
        assert!(dbg.contains("<opaque>"));
    }

    #[test]
    fn enroll_result_conversion_roundtrips() {
        use frappuccino_crypto_stream::EnrollResult as CoreER;
        assert_eq!(EnrollResult::from(CoreER::Success), EnrollResult::Success);
        assert_eq!(
            EnrollResult::from(CoreER::AlreadyEnrolled),
            EnrollResult::AlreadyEnrolled
        );
        let f = EnrollResult::from(CoreER::Failed {
            code: 500,
            body: "oops".into(),
        });
        assert!(matches!(f, EnrollResult::Failed { code: 500, .. }));
    }

    #[test]
    fn stream_server_client_enroll_rejects_wrong_batch_size() {
        let c = StreamServerClient::new("https://relay.shake-document-protect.org:8443").unwrap();
        // 3 keys instead of 50 → InvalidBlob before any network call.
        let bad_keys = vec![vec![0u8; 32]; 3];
        let err = c
            .enroll("f3".repeat(32).as_str(), &bad_keys, &[0u8; 64])
            .unwrap_err();
        assert!(matches!(err, FfiError::InvalidBlob { .. }));
    }
}
