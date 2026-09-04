//! `frappuccino-crypto-stream` — STRM blob format and V2 server protocol
//! client.
//!
//! ## Layout (V3 — current)
//!
//! ```text
//! header:
//!   [0..4]    MAGIC = "STRM"
//!   [4]       VERSION = 0x03
//!   [5..85]   sealed_session_key        (80 bytes, crypto_box_seal)
//!   [85..87]  grant_count = 0           (big-endian u16, always 0)
//! body:
//!   [87]      MODE  = 0x01 SINGLE | 0x02 CHUNKED
//!   ...       mode-specific payload (see below)
//! ```
//!
//! V3 carries NO author identity at rest (F-C1 fix): the 32-byte
//! `author_ed25519_pk` that V1/V2 wrote at offset 5 is gone, so a relay-disk
//! seizure can no longer map `report_id -> identity` from the blob bytes. The
//! field was dead (never used to decrypt, no consumer) so this is a pure
//! removal.
//!
//! ## Legacy layout (V1/V2 — read-only)
//!
//! ```text
//!   [0..4]    MAGIC = "STRM"
//!   [4]       VERSION = 0x01 (Kotlin) | 0x02 (previous Rust encoder)
//!   [5..37]   author_ed25519_pk         (32 bytes)
//!   [37..117] sealed_session_key        (80 bytes)
//!   [117..119] grant_count = 0          (big-endian u16)
//!   [119]     MODE
//! ```
//!
//! * **SINGLE**: `nonce(24) || ct_with_tag(plaintext + 16)`
//! * **CHUNKED**: `nonce_prefix(20) || chunk_count(u32 BE) || chunk*`,
//!   where each chunk = `total_len(u32 BE) || nonce(24) || ct_with_tag`.
//!   `nonce = nonce_prefix || chunk_index(u32 BE)`.
//!
//! AEAD = `XChaCha20-Poly1305-IETF(session_key, nonce, aad)`.
//!
//! **AAD semantics:**
//! * SINGLE — `aad = header_bytes` (the version-resolved header).
//! * CHUNKED V1 — `aad = header_bytes` (Kotlin legacy — REJECTED at decrypt,
//!   RT-02: the unbound `chunk_count` was a silent-truncation primitive).
//! * CHUNKED V2/V3 — `aad = header_bytes ‖ MODE ‖ nonce_prefix ‖
//!   chunk_count_BE_u32`. Binding `chunk_count` in the AAD rejects a truncation
//!   attack (dropping trailing chunks + patching `chunk_count`).
//!
//! The encoder emits V3 exclusively. What the DECODER accepts depends on the
//! build: V3 only by default, which is the configuration the Android `.so`
//! ships, and V1 (SINGLE only) + V2 as well under the `legacy-strm` feature,
//! which only `frappuccino-cli` enables. A witness with an archive written by an
//! older encoder reads it on a desktop; the app carries no legacy parser at all.
//! Same shape as the ratchet blob, where `deserialize` refuses V1 and
//! `migrate_from_v1` is an explicit CLI escape hatch.
//!
//! The isolation does not rest on the build command. Cargo unifies features
//! across a shared graph, so a workspace-wide build would hand the FFI a stream
//! crate that still parses V1/V2; [`LEGACY_STRM_MARKER`] exists in the linked
//! binary only under the feature, and both `build-android.sh` and the Gradle
//! `checkRustSoFresh` gate refuse a `.so` that carries it.

pub use frappuccino_crypto_core as core;

/// Whether this build carries the legacy STRM decoder (V1/V2).
pub const LEGACY_STRM_COMPILED_IN: bool = cfg!(feature = "legacy-strm");

/// A string that exists in the linked binary **only** when the legacy STRM
/// decoder was compiled in, so a shipped artefact can be checked rather than
/// trusted.
///
/// The Android `.so` must decode V3 only, and today it does because
/// `build-android.sh` builds `-p frappuccino-crypto-ffi`. That is a property of
/// how a command happens to be invoked, not of the code: Cargo unifies features
/// across a shared build graph, so a workspace-wide build hands every consumer a
/// stream crate that still parses V1/V2, and the shipped binary would quietly
/// regain the surface this feature exists to remove.
///
/// A compile-time assertion in the FFI crate would catch that, and would also
/// break `cargo test --workspace`, which legitimately builds the CLI and the
/// `.so` in one graph. So the check moved to the artefact: `build-android.sh`
/// greps each produced `.so` for this marker and refuses to ship one that has
/// it, and the Gradle `checkRustSoFresh` gate does the same before packaging,
/// next to the SPKI-pin and QUIC-feature byte-greps that already live there.
///
/// `#[used]` keeps the linker from dropping a static nothing reads.
#[cfg(feature = "legacy-strm")]
#[used]
pub static LEGACY_STRM_MARKER: &[u8] = b"FRAPPUCCINO_LEGACY_STRM_COMPILED_IN";

pub mod decrypt;
pub mod encrypt;
pub mod header;
pub mod pathsafe;
pub mod secure_delete;

// Kani bounded-model-checking proof harnesses. Compiled ONLY when Kani drives
// the build (`--cfg kani`) — invisible to `cargo build`, `cargo test`, and
// `cargo clippy`. See `kani_proofs.rs` for what is proven and the run command.
#[cfg(kani)]
mod kani_proofs;

// The V2 relay client and its TLS-pinning glue live behind the `protocol`
// feature (on by default). Fuzz builds disable it to keep `cargo fuzz build`
// from dragging reqwest + rustls + hyper through the sanitizer toolchain
// (~3 GiB of RAM).
#[cfg(feature = "protocol")]
pub mod pin;
#[cfg(feature = "protocol")]
pub mod protocol;
#[cfg(feature = "protocol")]
pub mod upload;

// Phase 3a HTTP/3 upload transport (quinn + h3 + BBR). Behind the `quic`
// feature (which implies `protocol`): only the shipped Android `.so` and the
// local h3 integration test compile the quinn/tokio/h3 tree. Transport plan
// §10.9 / m4.
#[cfg(feature = "quic")]
pub mod quic;
// Phase 3b brick 1 — Salamander packet obfuscation (XOR keystream under the
// QUIC datagram layer). NOT gated on `quic`: the server-side de-obfuscation
// proxy (frappuccino-obfs-proxy) depends on this crate with default features
// only and must share this EXACT transform (byte-identical client + server, the
// whole point of one shared module). It's tiny (blake2 + ~80 lines). ROADMAP §10.9.
pub mod salamander;
// Phase 3b brick 1 — the `AsyncUdpSocket` shim that applies `salamander` under
// quinn (injected by `quic::build_connection` when a target carries an obfs PSK).
#[cfg(feature = "quic")]
pub mod salamander_socket;

pub use decrypt::{decrypt, BlobMetadata, DecryptError};
pub use encrypt::{encrypt_chunked, encrypt_single, EncryptError};
pub use pathsafe::is_safe_blob_filename;
#[cfg(feature = "protocol")]
pub use protocol::{
    ArchiveBlobInfo, ChallengeValue, EnrollResult, ProtocolError, StreamServerClient,
};
#[cfg(feature = "quic")]
pub use quic::{
    clear_quic_degraded, put_chunk_quic_to, put_chunk_quic_with_headers, quic_is_degraded,
    reset_quic_client, QuicTarget,
};
pub use secure_delete::{secure_delete_file, SecureDeleteError};
#[cfg(feature = "protocol")]
pub use upload::{put_chunk_with_headers, reset_upload_client, PutResult};
