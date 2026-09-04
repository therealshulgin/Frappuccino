//! Exact-boundary + grant-path coverage for `stream::header::parse_header`.
//!
//! `header_errors.rs` pins each error VARIANT, but every blob it builds has
//! `grant_count = 0` and stops one byte short of (or exactly at) the no-grants
//! header. That leaves a cluster of mutants alive on `stream/src/header.rs`
//! (ROADMAP 8.4.4):
//!
//!   * the grant section (`grant_count * GRANT_ENTRY_SIZE`, `be_u16`'s high
//!     byte) is never exercised — with `grant_count == 0` every arithmetic
//!     variant collapses to the same offsets;
//!   * the `header_end + 1` off-by-one and the `need:` field of
//!     `TruncatedWithGrants` are never asserted; and
//!   * the size constants (`GRANT_ENTRY_SIZE`, `CHUNK_SIZE`, …) aren't pinned
//!     by a known-answer test, so flipping the `+`/`*` inside them survives.
//!
//! These tests parse a header WITH a grant, sit a blob exactly on the
//! `header_end` boundary, and KAT-pin the wire constants.
//!
//! Known equivalent survivor: in `be_u16`, `hi << 8` and `lo` occupy disjoint
//! bit ranges, so `|` -> `^` yields an identical value and CANNOT be killed.
//! It is expected to remain a (provably-equivalent) survivor.

use frappuccino_crypto_stream::header::{
    be_u16, parse_header, HeaderError, CHUNK_SIZE, CHUNK_THRESHOLD, GRANT_ENTRY_SIZE,
    HEADER_SIZE_NO_GRANTS, LEGACY_HEADER_SIZE_NO_GRANTS, MAX_CHUNK_COUNT, MAX_CHUNK_LEN,
    MODE_SINGLE, NONCE_PREFIX_BYTES, OFF_GRANT_COUNT, OFF_VERSION, SEALED_ENVELOPE_SIZE,
    VERSION_V3,
};

/// Structurally-parseable header carrying `grants` grant entries (zero-filled —
/// `parse_header` validates their SIZE, not their contents) + the mode byte.
/// Length = `HEADER_SIZE_NO_GRANTS + grants * GRANT_ENTRY_SIZE + 1`.
fn scaffold_with_grants(grants: u16) -> Vec<u8> {
    let grants_len = usize::from(grants) * GRANT_ENTRY_SIZE;
    let mut v = vec![0u8; HEADER_SIZE_NO_GRANTS + grants_len + 1];
    v[..4].copy_from_slice(b"STRM");
    v[OFF_VERSION] = VERSION_V3;
    v[OFF_GRANT_COUNT..OFF_GRANT_COUNT + 2].copy_from_slice(&grants.to_be_bytes());
    v[HEADER_SIZE_NO_GRANTS + grants_len] = MODE_SINGLE; // mode byte sits at header_end
    v
}

// ── be_u16: high byte must land in bits 8..16 (`<<` not `>>`) ─────────────────

#[test]
fn be_u16_assembles_big_endian() {
    // A `<<`->`>>` mutant makes `hi >> 8 == 0` for every u8, collapsing the
    // result to `lo`. Any nonzero-high-byte case catches it.
    assert_eq!(be_u16(0x12, 0x34), 0x1234);
    assert_eq!(be_u16(0xff, 0x00), 0xff00); // lo == 0 => mutant returns 0
    assert_eq!(be_u16(0x00, 0xff), 0x00ff);
    assert_eq!(be_u16(0xab, 0xcd), 0xabcd);
    // `|`->`^` is equivalent here (disjoint bits) and is not asserted against.
}

// ── grant path: any declared grant is refused, whatever the blob size ────────
//
// The blobs below are WELL-FORMED for the old parser: they carry a full grant
// section and the mode byte in the right place, so before the grants were
// rejected they parsed cleanly. That is deliberate. Tests that only fed
// truncated grant blobs would still pass if the refusal were replaced by a
// length check, and would prove nothing about the decision.

#[test]
fn parse_header_rejects_one_declared_grant() {
    let blob = scaffold_with_grants(1);
    match parse_header(&blob).unwrap_err() {
        HeaderError::GrantsNotSupported { grant_count } => assert_eq!(grant_count, 1),
        other => panic!("expected GrantsNotSupported, got {other:?}"),
    }
}

#[test]
fn parse_header_rejects_two_declared_grants() {
    // A second value so a mutant that special-cases 1 does not survive, and so
    // the reported count is shown to come from `be_u16` and not a constant.
    let blob = scaffold_with_grants(2);
    match parse_header(&blob).unwrap_err() {
        HeaderError::GrantsNotSupported { grant_count } => assert_eq!(grant_count, 2),
        other => panic!("expected GrantsNotSupported, got {other:?}"),
    }
}

#[test]
fn parse_header_rejects_the_maximum_declared_grant_count() {
    // u16::MAX grants declared on a blob that carries none. The old code
    // multiplied this by GRANT_ENTRY_SIZE before any bound applied; nothing
    // multiplies it now, and the refusal does not depend on the blob being
    // large enough to hold what it claims.
    let mut blob = scaffold_with_grants(0);
    blob[OFF_GRANT_COUNT..OFF_GRANT_COUNT + 2].copy_from_slice(&u16::MAX.to_be_bytes());
    match parse_header(&blob).unwrap_err() {
        HeaderError::GrantsNotSupported { grant_count } => assert_eq!(grant_count, u16::MAX),
        other => panic!("expected GrantsNotSupported, got {other:?}"),
    }
}

// ── header_end off-by-one: blob exactly header_end bytes is truncated ─────────

#[test]
fn parse_header_blob_exactly_header_end_is_truncated() {
    // A grant-free header truncated to EXACTLY header_end bytes (the mode byte
    // is missing). header_end + 1 bytes are required, so header_end must be
    // rejected with min == header_end + 1. Kills the `+ 1` off-by-one in the
    // length check: a `- 1` mutant would index blob[header_end] out of bounds,
    // a `* 1` mutant would wrongly accept.
    let mut blob = scaffold_with_grants(0);
    blob.truncate(HEADER_SIZE_NO_GRANTS); // drop the mode byte
    match parse_header(&blob).unwrap_err() {
        HeaderError::TooShort { got, min } => {
            assert_eq!(got, HEADER_SIZE_NO_GRANTS);
            assert_eq!(min, HEADER_SIZE_NO_GRANTS + 1);
        }
        other => panic!("expected TooShort, got {other:?}"),
    }
}

// ── size constants: KAT the wire contract (mutated `+`/`*` inside them) ───────

#[test]
fn size_constants_are_pinned() {
    // Wire contract (this crate's `header.rs`, version-branched V1/V2/V3 / crypto-rs/README.md
    // "Invariants"). Any divergence breaks byte-compat with enrolled identities
    // and archived streams. Literal expectations so a mutated const expression
    // in the source diverges from the (un-mutated) test value.
    assert_eq!(SEALED_ENVELOPE_SIZE, 80);
    assert_eq!(GRANT_ENTRY_SIZE, 112);
    assert_eq!(HEADER_SIZE_NO_GRANTS, 87); // V3: no author key (was 119 in V1/V2)
    assert_eq!(LEGACY_HEADER_SIZE_NO_GRANTS, 119); // V1/V2 read-only legacy
    assert_eq!(NONCE_PREFIX_BYTES, 20);
    assert_eq!(CHUNK_SIZE, 1_048_576);
    assert_eq!(CHUNK_THRESHOLD, 10_485_760);
    assert_eq!(MAX_CHUNK_COUNT, 1_000_000);
    assert_eq!(MAX_CHUNK_LEN, 2_097_152);
}
