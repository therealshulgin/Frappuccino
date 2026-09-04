//! STRM header constants and byte-layout helpers.

/// Magic bytes at the start of every STRM blob.
pub const MAGIC: [u8; 4] = *b"STRM";
/// Legacy STRM format (produced by Kotlin `SovereignEncryptor` pre-S9).
///
/// AAD semantics:
///   * SINGLE = header bytes.
///   * CHUNKED = header bytes (truncation of trailing chunks was undetectable
///     — fixed in V2). V1 CHUNKED is now REJECTED at decrypt (RT-02); only
///     V1 SINGLE fixtures still decrypt.
///
/// Layout: carries a 32-byte `author_ed25519_pk` at offset 5 (see
/// [`LEGACY_OFF_AUTHOR_PK`]). The decoder reads it for introspection only.
pub const VERSION_V1: u8 = 0x01;
/// Previous Rust STRM format (S9-pre-audit until the F-C1 fix).
///
/// AAD semantics:
///   * SINGLE = header bytes (unchanged from V1, but the version byte is V2
///     so the decoder stays honest about which writer produced the blob).
///   * CHUNKED = `header ‖ MODE ‖ nonce_prefix ‖ chunk_count_be_u32` —
///     includes `chunk_count` so a truncation attack that drops trailing
///     chunks is rejected (would need to forge an AEAD tag under a different
///     AAD).
///
/// Layout: same as V1 — a 32-byte `author_ed25519_pk` at offset 5.
pub const VERSION_V2: u8 = 0x02;
/// Current STRM format (F-C1 fix, pre-publication): identical to V2 EXCEPT the
/// 32-byte `author_ed25519_pk` is GONE from the header. The witness's
/// long-term identity is no longer written at rest, so a relay-disk seizure
/// can no longer map `report_id -> identity` from the blob bytes alone — the
/// motto ("a seizure exposes nothing"). The author field was dead (never used
/// to decrypt, no consumer anywhere) so this is a pure removal, not a feature
/// loss.
///
/// AAD semantics: same shape as V2 (SINGLE = header bytes; CHUNKED =
/// `header ‖ MODE ‖ nonce_prefix ‖ chunk_count_be_u32`). The header is simply
/// 32 bytes shorter; a V3 blob is a distinct wire object from a V2 blob of the
/// same body, and they never share an AEAD tag.
pub const VERSION_V3: u8 = 0x03;
/// Version written by the current encoder. The decoder additionally accepts
/// `VERSION_V1` (legacy Kotlin SINGLE fixtures) and `VERSION_V2` (the previous
/// Rust encoder) for backward read compatibility.
pub const VERSION_CURRENT: u8 = VERSION_V3;
/// Mode byte for in-one-piece encryption.
pub const MODE_SINGLE: u8 = 0x01;
/// Mode byte for chunked encryption (1 MiB chunks).
pub const MODE_CHUNKED: u8 = 0x02;

/// Size of the session key that's sealed in the header.
pub const SESSION_KEY_BYTES: usize = 32;
/// Overhead of `crypto_box_seal` over the 32-byte session key = 48 bytes.
/// Full sealed envelope = 32 + 48 = 80 bytes.
pub const SEALED_BOX_OVERHEAD: usize = 48;
/// Size of the sealed session key inside the header.
pub const SEALED_ENVELOPE_SIZE: usize = SESSION_KEY_BYTES + SEALED_BOX_OVERHEAD;

/// `XChaCha20` nonce length for mode SINGLE and the full nonce computed for
/// each chunk in mode CHUNKED.
pub const NONCE_BYTES: usize = 24;
/// Length of the shared `nonce_prefix` written once at the start of a
/// CHUNKED body. Each chunk appends a 4-byte chunk index to form its nonce.
pub const NONCE_PREFIX_BYTES: usize = NONCE_BYTES - 4;
/// Poly1305 tag length (always appended in XChaCha20-Poly1305-IETF).
pub const AEAD_TAG_BYTES: usize = 16;

/// Ed25519 public key length.
pub const ED25519_PK_BYTES: usize = 32;
/// X25519 public key length (target of the sealed envelope).
pub const X25519_PK_BYTES: usize = 32;

/// Default chunk size used by the encoder for mode CHUNKED payloads.
pub const CHUNK_SIZE: usize = 1024 * 1024;
/// Size threshold below which the encoder picks mode SINGLE over CHUNKED.
pub const CHUNK_THRESHOLD: u64 = 10 * 1024 * 1024;

/// Hard caps applied by the decoder (prevents memory `DoS` on crafted blobs).
pub const MAX_CHUNK_COUNT: u32 = 1_000_000;
/// Max size of a single chunk's full `total_len` field.
pub const MAX_CHUNK_LEN: u32 = 2 * 1024 * 1024;

/// Hard cap on the bytes a single archive-blob download may stream into the
/// caller's buffer (M-2 / WP-C). One archive blob = one uploaded unit (a ~5 s
/// recording chunk, or a `<= 10 MiB` single-mode STRM, or a small
/// manifest/proof) — a few MiB in practice. A compromised relay could otherwise
/// stream unbounded bytes into the rescue device's RAM (the FFI buffers the
/// encrypted blob before decrypting) or disk, an OOM/disk-fill `DoS`. 64 MiB is
/// ~6-10x the largest legitimate single blob, so it never truncates a real
/// rescue, while bounding the hostile case hard. The relay-advertised `size`
/// from the listing is itself relay-controlled, so it cannot serve as the
/// bound — this absolute cap is independent of anything the relay claims.
pub const MAX_ARCHIVE_BLOB_BYTES: u64 = 64 * 1024 * 1024;

/// Hard cap on an archive-blob *listing* JSON read into RAM (M-2 / WP-C). The
/// listing endpoint is unauthenticated (addressed by `report_id`), so a hostile
/// relay could return a multi-GiB `blobs` array to OOM the rescue device, which
/// buffers the whole body before serde parses it. A real listing is a few dozen
/// small entries; 4 MiB is orders of magnitude above any legitimate case.
pub const MAX_LISTING_BYTES: u64 = 4 * 1024 * 1024;

/// Hard cap on a control-plane response body read into RAM (challenge / verify /
/// enroll-error / create-report id). These are tiny JSON objects; 64 KiB bounds
/// a hostile relay's response hard without ever truncating a legitimate one.
pub const MAX_CONTROL_BODY_BYTES: u64 = 64 * 1024;

// ── Byte offsets — CURRENT (V3) layout ───────────────────────────────────────
// V3 = MAGIC(4) ‖ VERSION(1) ‖ sealed_session_key(80) ‖ grant_count(BE u16).
// These are the canonical constants the encoder and current-format tests use.
// Legacy V1/V2 offsets (which insert a 32-byte author key after the version)
// live below as `LEGACY_*`. `parse_header` dispatches on the version byte so a
// reader never mixes the two.
pub const OFF_MAGIC: usize = 0;
pub const OFF_VERSION: usize = 4;
/// V3: the sealed session key sits immediately after the version byte (no
/// author key precedes it).
pub const OFF_SEALED: usize = OFF_VERSION + 1;
/// V3: big-endian `grant_count`, right after the sealed envelope.
pub const OFF_GRANT_COUNT: usize = OFF_SEALED + SEALED_ENVELOPE_SIZE;
/// V3: no-grants header size (== offset of the mode byte when `grant_count == 0`).
pub const HEADER_SIZE_NO_GRANTS: usize = OFF_GRANT_COUNT + 2;

// ── Byte offsets — LEGACY (V1/V2) layout ─────────────────────────────────────
// V1/V2 = MAGIC(4) ‖ VERSION(1) ‖ author_ed25519_pk(32) ‖ sealed(80) ‖
//         grant_count(BE u16). Read-only: the current encoder never emits these.
/// V1/V2-only: offset of the 32-byte author Ed25519 key (REMOVED in V3).
pub const LEGACY_OFF_AUTHOR_PK: usize = OFF_VERSION + 1;
/// V1/V2-only: offset of the sealed session key (after the author key).
pub const LEGACY_OFF_SEALED: usize = LEGACY_OFF_AUTHOR_PK + ED25519_PK_BYTES;
/// V1/V2-only: offset of the big-endian `grant_count`.
pub const LEGACY_OFF_GRANT_COUNT: usize = LEGACY_OFF_SEALED + SEALED_ENVELOPE_SIZE;
/// V1/V2-only: no-grants header size.
pub const LEGACY_HEADER_SIZE_NO_GRANTS: usize = LEGACY_OFF_GRANT_COUNT + 2;

/// Size in bytes of one grant entry: recipient X25519 pk + sealed session key.
///
/// No blob has ever carried one. The encoder always writes `grant_count = 0`, and
/// since the multi-recipient sharing this field was reserved for does not exist,
/// the decoder now REJECTS any blob claiming a grant ([`HeaderError::GrantsNotSupported`])
/// instead of walking `grant_count` entries of untrusted input. The constant stays
/// because the field itself stays on the wire (always zero, so no version bump) and
/// because it bounds the Kani harness that proves the rejection.
pub const GRANT_ENTRY_SIZE: usize = X25519_PK_BYTES + SEALED_ENVELOPE_SIZE;

/// Assemble an unsigned 16-bit big-endian value from its two bytes.
#[must_use]
pub const fn be_u16(hi: u8, lo: u8) -> u16 {
    ((hi as u16) << 8) | (lo as u16)
}

/// Resolved byte-layout of a header for one specific version. `parse_header`
/// does the version dispatch in exactly one place ([`layout_for_version`]) so
/// no reader ever hard-codes the wrong offsets for a blob's version.
struct HeaderLayout {
    /// Offset of the author Ed25519 key, or `None` when the version omits it
    /// (V3 and later).
    author_offset: Option<usize>,
    /// Offset of the sealed session key.
    sealed_offset: usize,
    /// Offset of the big-endian `grant_count`.
    grant_count_offset: usize,
    /// No-grants header size (offset of the mode byte when `grant_count == 0`).
    base_size: usize,
}

/// Map a version byte to its [`HeaderLayout`], or `None` for an unknown version.
const fn layout_for_version(version: u8) -> Option<HeaderLayout> {
    match version {
        VERSION_V3 => Some(HeaderLayout {
            author_offset: None,
            sealed_offset: OFF_SEALED,
            grant_count_offset: OFF_GRANT_COUNT,
            base_size: HEADER_SIZE_NO_GRANTS,
        }),
        // Legacy layouts exist only when the crate is built with `legacy-strm`
        // (the CLI). Without it this arm is absent, `layout_for_version` returns
        // None for V1/V2, and `parse_header` turns that into the pointed error
        // below rather than a bare "unsupported version".
        #[cfg(feature = "legacy-strm")]
        VERSION_V1 | VERSION_V2 => Some(HeaderLayout {
            author_offset: Some(LEGACY_OFF_AUTHOR_PK),
            sealed_offset: LEGACY_OFF_SEALED,
            grant_count_offset: LEGACY_OFF_GRANT_COUNT,
            base_size: LEGACY_HEADER_SIZE_NO_GRANTS,
        }),
        _ => None,
    }
}

/// Byte-layout summary of a well-formed STRM header. Produced by
/// [`parse_header`] so callers (the decoder, the CLI `--inspect`, and the
/// fuzz target) share the same cursor arithmetic — and, crucially, the same
/// version-resolved offsets, so a legacy (V1/V2) blob is never read with the
/// V3 layout or vice versa.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedHeader {
    /// Raw version byte (`VERSION_V1`, `VERSION_V2`, or `VERSION_V3`).
    pub version: u8,
    /// Raw mode byte (`MODE_SINGLE` or `MODE_CHUNKED`).
    pub mode: u8,
    /// Author's Ed25519 public key — `Some` for legacy V1/V2 blobs (which
    /// embed it at rest), `None` for V3 (the identity is no longer written;
    /// F-C1 fix). Informational only — never used to decrypt.
    pub author_ed25519_pk: Option<[u8; ED25519_PK_BYTES]>,
    /// Big-endian `grant_count`.
    pub grant_count: u16,
    /// Offset of the sealed session key, resolved for this blob's version.
    pub sealed_offset: usize,
    /// Offset of the first byte past the header (== start of the mode byte).
    pub header_end: usize,
    /// Start offset of the mode-specific body (past the mode byte itself).
    pub body_start: usize,
}

/// Parsing errors produced by [`parse_header`]. These are reconstitutable
/// from `HeaderError::to_string`, so the decoder can forward them without
/// leaking internal state.
#[derive(Debug, thiserror::Error)]
pub enum HeaderError {
    /// Buffer too short to hold the (version-resolved) header + mode byte.
    #[error("blob too short: {got} (minimum {min})")]
    TooShort { got: usize, min: usize },
    /// First four bytes are not `"STRM"`.
    #[error("invalid magic bytes")]
    BadMagic,
    /// Version byte not in `{VERSION_V1, VERSION_V2, VERSION_V3}`.
    #[error("unsupported version {version:#x}")]
    BadVersion { version: u8 },
    /// A V1 or V2 blob was handed to a build that decodes V3 only. Distinct from
    /// [`Self::BadVersion`] on purpose: the blob is well-formed and readable, just
    /// not here. Someone holding a July archive should be told where to read it,
    /// not that their file is corrupt. Mirrors the ratchet blob, which rejects V1
    /// in the app and points at `frappuccino-cli migrate-v1-ratchet`.
    #[error(
        "legacy STRM version {version:#x} is not decoded by this build \
         (V3 only) — read it with `frappuccino-cli decrypt`"
    )]
    LegacyVersionNotSupported { version: u8 },
    /// The header declares at least one grant. The format reserves the field but
    /// nothing has ever emitted a grant, so rather than parse `grant_count`
    /// entries of attacker-chosen input for a feature that does not exist, the
    /// decoder refuses. Re-opening this means implementing multi-recipient
    /// sharing, not relaxing the check.
    #[error("grants are not supported: header declares {grant_count}")]
    GrantsNotSupported { grant_count: u16 },
}

/// Parse the STRM pre-body header. Pure function — no secrets involved, no
/// allocation beyond the small `ParsedHeader` struct. Used by the decoder,
/// the CLI `--inspect` mode, and the `fuzz_parse_strm_header` target.
///
/// The version byte is read first (after magic) and selects the byte layout
/// via [`layout_for_version`]: V3 has no author key (sealed at offset 5),
/// V1/V2 carry one (sealed at offset 37). Every returned offset is resolved
/// for that version, so downstream slicing is always in-bounds and correct.
///
/// # Errors
/// See [`HeaderError`].
pub fn parse_header(blob: &[u8]) -> Result<ParsedHeader, HeaderError> {
    // Need magic(4) + version(1) before we can dispatch on the version byte.
    if blob.len() < OFF_VERSION + 1 {
        return Err(HeaderError::TooShort {
            got: blob.len(),
            min: OFF_VERSION + 1,
        });
    }
    if blob[OFF_MAGIC..OFF_MAGIC + 4] != MAGIC[..] {
        return Err(HeaderError::BadMagic);
    }
    let version = blob[OFF_VERSION];
    let layout = match layout_for_version(version) {
        Some(l) => l,
        // Unreachable with `legacy-strm` on, where V1/V2 resolve above.
        None if matches!(version, VERSION_V1 | VERSION_V2) => {
            return Err(HeaderError::LegacyVersionNotSupported { version })
        }
        None => return Err(HeaderError::BadVersion { version }),
    };

    // Now require the full no-grants header (for this version) + the mode byte.
    let min = layout.base_size + 1;
    if blob.len() < min {
        return Err(HeaderError::TooShort {
            got: blob.len(),
            min,
        });
    }
    let author_ed25519_pk = layout.author_offset.map(|off| {
        let mut pk = [0u8; ED25519_PK_BYTES];
        pk.copy_from_slice(&blob[off..off + ED25519_PK_BYTES]);
        pk
    });
    let grant_count = be_u16(
        blob[layout.grant_count_offset],
        blob[layout.grant_count_offset + 1],
    );
    if grant_count != 0 {
        return Err(HeaderError::GrantsNotSupported { grant_count });
    }
    // With no grants the header ends at the version-resolved base size, and the
    // `min` check above already required `base_size + 1` bytes, so the mode-byte
    // read below is in bounds by construction. Kani proves it over the whole
    // bounded input space (`check_parse_header_rejects_any_grant`).
    let header_end = layout.base_size;
    let mode = blob[header_end];
    Ok(ParsedHeader {
        version,
        mode,
        author_ed25519_pk,
        grant_count,
        sealed_offset: layout.sealed_offset,
        header_end,
        body_start: header_end + 1,
    })
}
