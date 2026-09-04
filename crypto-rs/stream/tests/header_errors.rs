//! Error-path coverage for `stream::header::parse_header`.
//!
//! The fuzz target exercises these branches too, but `cargo tarpaulin`
//! doesn't count fuzz runs — this file pins each variant deterministically.
//!
//! Two scaffolds: `scaffold_v3()` builds a current (V3) header (no author key,
//! 87-byte no-grants header), and `scaffold_legacy(version)` builds a V1/V2
//! header (32-byte author key at offset 5, 119-byte no-grants header). The
//! decoder must accept all three versions and resolve the right layout for
//! each.

use frappuccino_crypto_stream::header::{
    parse_header, HeaderError, ED25519_PK_BYTES, HEADER_SIZE_NO_GRANTS,
    LEGACY_HEADER_SIZE_NO_GRANTS, LEGACY_OFF_AUTHOR_PK, OFF_GRANT_COUNT, OFF_VERSION, VERSION_V1,
    VERSION_V2, VERSION_V3,
};

/// Structurally-parseable CURRENT (V3) header: magic + V3 + 80 B sealed
/// envelope + 2 B `grant_count` (0) + mode byte. No author key.
fn scaffold_v3() -> Vec<u8> {
    let mut v = vec![0u8; HEADER_SIZE_NO_GRANTS + 1];
    v[..4].copy_from_slice(b"STRM");
    v[OFF_VERSION] = VERSION_V3;
    // sealed envelope, grant_count=0 are already zero-filled.
    v[HEADER_SIZE_NO_GRANTS] = 0x01; // MODE_SINGLE
    v
}

/// Structurally-parseable LEGACY (V1/V2) header: magic + version + 32 B author
/// pk + 80 B sealed envelope + 2 B `grant_count` (0) + mode byte.
fn scaffold_legacy(version: u8) -> Vec<u8> {
    let mut v = vec![0u8; LEGACY_HEADER_SIZE_NO_GRANTS + 1];
    v[..4].copy_from_slice(b"STRM");
    v[OFF_VERSION] = version;
    v[LEGACY_HEADER_SIZE_NO_GRANTS] = 0x01; // MODE_SINGLE
    v
}

#[test]
fn parse_header_rejects_blob_shorter_than_header() {
    // Valid magic + V3 version, truncated to exactly the no-grants header (the
    // mode byte is missing) → TooShort, NOT BadMagic.
    let mut blob = scaffold_v3();
    blob.truncate(HEADER_SIZE_NO_GRANTS); // drop the mode byte
    let err = parse_header(&blob).unwrap_err();
    assert!(matches!(err, HeaderError::TooShort { .. }), "got {err:?}");
}

#[test]
fn parse_header_rejects_bad_magic() {
    let mut blob = scaffold_v3();
    blob[0] = b'X';
    let err = parse_header(&blob).unwrap_err();
    assert!(matches!(err, HeaderError::BadMagic), "got {err:?}");
}

#[test]
fn parse_header_rejects_bad_version() {
    let mut blob = scaffold_v3();
    blob[OFF_VERSION] = 0x42; // none of V1/V2/V3
    let err = parse_header(&blob).unwrap_err();
    match err {
        HeaderError::BadVersion { version } => assert_eq!(version, 0x42),
        other => panic!("expected BadVersion, got {other:?}"),
    }
}

#[test]
fn parse_header_accepts_v1_v2_v3() {
    assert!(parse_header(&scaffold_legacy(VERSION_V1)).is_ok());
    assert!(parse_header(&scaffold_legacy(VERSION_V2)).is_ok());
    assert!(parse_header(&scaffold_v3()).is_ok());
}

#[test]
fn parse_header_rejects_a_declared_grant() {
    let mut blob = scaffold_v3();
    // Claim 3 grants. The buffer is not extended to carry them, and that no
    // longer matters: the refusal is on the declaration, not on the size.
    let grant_count: u16 = 3;
    blob[OFF_GRANT_COUNT..OFF_GRANT_COUNT + 2].copy_from_slice(&grant_count.to_be_bytes());
    match parse_header(&blob).unwrap_err() {
        HeaderError::GrantsNotSupported { grant_count: gc } => assert_eq!(gc, 3),
        other => panic!("expected GrantsNotSupported, got {other:?}"),
    }
}

#[test]
fn parse_header_v3_has_no_author() {
    // F-C1: the current format carries no author identity at rest.
    let parsed = parse_header(&scaffold_v3()).unwrap();
    assert_eq!(parsed.version, VERSION_V3);
    assert_eq!(
        parsed.author_ed25519_pk, None,
        "V3 must not surface any author identity"
    );
    assert_eq!(parsed.grant_count, 0);
    assert_eq!(parsed.body_start, parsed.header_end + 1);
}

#[test]
fn parse_header_legacy_roundtrips_author_pk() {
    // Legacy V1/V2 blobs DO embed the author — the decoder still surfaces it
    // (for migration/inspection), so the read path stays intact.
    let mut blob = scaffold_legacy(VERSION_V2);
    for (i, slot) in blob[LEGACY_OFF_AUTHOR_PK..LEGACY_OFF_AUTHOR_PK + ED25519_PK_BYTES]
        .iter_mut()
        .enumerate()
    {
        *slot = u8::try_from(i).unwrap_or(0);
    }
    let parsed = parse_header(&blob).unwrap();
    let author = parsed
        .author_ed25519_pk
        .expect("legacy V2 blob must surface its embedded author");
    assert_eq!(author[0], 0);
    assert_eq!(author[31], 31);
    assert_eq!(parsed.grant_count, 0);
    assert_eq!(parsed.body_start, parsed.header_end + 1);
}
