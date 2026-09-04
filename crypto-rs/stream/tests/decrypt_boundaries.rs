//! Exact-boundary coverage for `stream::decrypt` on UNTRUSTED ciphertext.
//!
//! `decrypt_malformed.rs` already exercises each `Err(Malformed(…))` branch,
//! but with values FAR from the limit (`chunk_count` = `2_000_000` vs a cap of
//! `1_000_000`; a 10-byte body vs a 40-byte minimum). That leaves every
//! comparison / threshold unpinned AT the edge — which `cargo mutants`
//! surfaced as survivors on `stream/src/decrypt.rs` (ROADMAP 8.4.1):
//! mutating `<`↔`<=`, `>`↔`>=`, and the `+`s inside the size constants all
//! survived because no test distinguishes `value == limit` from
//! `value == limit ± 1`.
//!
//! Each test below sits a crafted blob EXACTLY on a boundary (accepted, i.e.
//! it passes that check and fails later) and one step past it (rejected with
//! that check's message). Together they flip at least one assertion under
//! every boundary mutation.
//!
//! Construction: encrypt a real blob (valid header + sealed session key for
//! `archive()`), keep its 88-byte `header ‖ mode` prefix (V3: 87-byte header +
//! 1 mode byte), and append a hand-built body. The body-level guards we target
//! all fire BEFORE the AEAD, so the crafted (un-authenticated) body reaches
//! them.

use frappuccino_crypto_core::identity::ArchiveIdentity;
use frappuccino_crypto_stream::decrypt::decrypt;
use frappuccino_crypto_stream::encrypt::{encrypt_chunked, encrypt_single};
use frappuccino_crypto_stream::header::{
    AEAD_TAG_BYTES, CHUNK_THRESHOLD, HEADER_SIZE_NO_GRANTS, MAX_CHUNK_COUNT, MODE_CHUNKED,
    MODE_SINGLE, NONCE_BYTES, NONCE_PREFIX_BYTES,
};

const MN: &str = "abaisser abandon abdiquer abeille abolir aborder aboutir aboyer abrasif abreuver abriter abroger";

fn archive() -> ArchiveIdentity {
    ArchiveIdentity::from_mnemonic(MN, "").expect("archive identity")
}

/// `header ‖ mode` (88 bytes, V3) whose sealed envelope unseals for
/// `archive()`, mode forced to CHUNKED. Each test appends its own body.
fn chunked_prefix() -> (ArchiveIdentity, Vec<u8>) {
    let archive = archive();
    let author = archive.identity().clone();
    let blob = encrypt_chunked(&vec![0u8; 2 * 1024 * 1024 + 1], &author).unwrap();
    let mut prefix = blob[..=HEADER_SIZE_NO_GRANTS].to_vec();
    prefix[HEADER_SIZE_NO_GRANTS] = MODE_CHUNKED;
    (archive, prefix)
}

/// Same, mode forced to SINGLE.
fn single_prefix() -> (ArchiveIdentity, Vec<u8>) {
    let archive = archive();
    let author = archive.identity().clone();
    let blob = encrypt_single(b"x", &author).unwrap();
    let mut prefix = blob[..=HEADER_SIZE_NO_GRANTS].to_vec();
    prefix[HEADER_SIZE_NO_GRANTS] = MODE_SINGLE;
    (archive, prefix)
}

// ── :161  CHUNKED minimum length: `body.len() < NONCE_PREFIX_BYTES + 4` ──────

#[test]
fn chunked_min_length_exact_is_accepted() {
    // body == NONCE_PREFIX_BYTES + 4 (= 24): a 20-byte prefix + chunk_count 0.
    // The loop runs zero times → empty plaintext, NOT "too short". A
    // `<`→`<=` mutant rejects this exact length.
    let (archive, mut blob) = chunked_prefix();
    let mut body = vec![0u8; NONCE_PREFIX_BYTES];
    body.extend_from_slice(&0u32.to_be_bytes()); // chunk_count = 0
    assert_eq!(body.len(), NONCE_PREFIX_BYTES + 4);
    blob.extend_from_slice(&body);
    let (pt, meta) = decrypt(&blob, &archive).expect("min-length CHUNKED body must decrypt");
    assert!(pt.is_empty());
    assert_eq!(meta.mode, MODE_CHUNKED);
}

#[test]
fn chunked_one_under_min_length_is_rejected() {
    // 23 bytes → "CHUNKED body too short". Pins the other side of `<`; also
    // kills `+`→`-` (which loosens the guard to 16, then indexes past 23).
    let (archive, mut blob) = chunked_prefix();
    blob.extend_from_slice(&[0u8; NONCE_PREFIX_BYTES + 3]); // 23
    let err = decrypt(&blob, &archive).unwrap_err();
    assert!(
        format!("{err:?}").contains("CHUNKED body too short"),
        "got {err:?}"
    );
}

// ── :170  chunk_count cap: `chunk_count > MAX_CHUNK_COUNT` ────────────────────

#[test]
fn chunk_count_at_cap_passes_cap_check() {
    // chunk_count == MAX is the last legal value: it must PASS the cap check
    // and reach the loop (failing on missing chunk data), NOT "exceeds cap".
    // A `>`→`>=` mutant rejects it.
    let (archive, mut blob) = chunked_prefix();
    let mut body = vec![0u8; NONCE_PREFIX_BYTES];
    body.extend_from_slice(&MAX_CHUNK_COUNT.to_be_bytes());
    blob.extend_from_slice(&body);
    let msg = format!("{:?}", decrypt(&blob, &archive).unwrap_err());
    assert!(
        !msg.contains("exceeds cap"),
        "cap must pass at == MAX, got {msg}"
    );
    assert!(
        msg.contains("missing len"),
        "expected to reach the loop, got {msg}"
    );
}

#[test]
fn chunk_count_one_over_cap_is_rejected() {
    // MAX + 1 → "exceeds cap". Pins the boundary (and kills `>`→`==`).
    let (archive, mut blob) = chunked_prefix();
    let mut body = vec![0u8; NONCE_PREFIX_BYTES];
    body.extend_from_slice(&(MAX_CHUNK_COUNT + 1).to_be_bytes());
    blob.extend_from_slice(&body);
    let msg = format!("{:?}", decrypt(&blob, &archive).unwrap_err());
    assert!(msg.contains("exceeds cap"), "got {msg}");
}

// ── :218  per-chunk length field present: `body.len() < cursor + 4` ───────────

#[test]
fn chunk_len_field_exactly_present_is_read() {
    // chunk_count = 1, body carries EXACTLY the 4-byte chunk_len (cursor + 4
    // total). The presence guard must pass and the code read chunk_len (then
    // fail on the missing frame data), NOT "missing len". `<`→`<=` rejects it.
    let (archive, mut blob) = chunked_prefix();
    let mut body = vec![0u8; NONCE_PREFIX_BYTES];
    body.extend_from_slice(&1u32.to_be_bytes()); // chunk_count = 1
    let chunk_len = u32::try_from(NONCE_BYTES + AEAD_TAG_BYTES).unwrap(); // 40, in range
    body.extend_from_slice(&chunk_len.to_be_bytes());
    blob.extend_from_slice(&body); // body.len() == 28 == cursor(24) + 4
    let msg = format!("{:?}", decrypt(&blob, &archive).unwrap_err());
    assert!(
        !msg.contains("missing len"),
        "len present at == cursor+4, got {msg}"
    );
    assert!(
        msg.contains("truncated body"),
        "expected the data check, got {msg}"
    );
}

#[test]
fn chunk_len_field_one_byte_short_is_missing() {
    // cursor + 3 → "chunk 0: missing len". Pins the boundary (and kills the
    // `+`→`-` mutant on `cursor + 4`).
    let (archive, mut blob) = chunked_prefix();
    let mut body = vec![0u8; NONCE_PREFIX_BYTES];
    body.extend_from_slice(&1u32.to_be_bytes());
    body.extend_from_slice(&[0u8; 3]); // only 3 of the 4 len bytes
    blob.extend_from_slice(&body);
    let msg = format!("{:?}", decrypt(&blob, &archive).unwrap_err());
    assert!(msg.contains("missing len"), "got {msg}");
}

// ── :227  chunk_len range: `(NONCE_BYTES + AEAD_TAG_BYTES) ..= MAX_CHUNK_LEN` ──

#[test]
fn chunk_len_at_lower_bound_is_in_range() {
    // chunk_len == NONCE_BYTES + AEAD_TAG_BYTES (= 40) is the smallest legal
    // frame: passes the range check and proceeds to the nonce/AEAD, NOT "out
    // of range". `+`→`*` raises the bound to 384 and rejects 40.
    let (archive, mut blob) = chunked_prefix();
    let chunk_len = u32::try_from(NONCE_BYTES + AEAD_TAG_BYTES).unwrap(); // 40
    let mut body = vec![0u8; NONCE_PREFIX_BYTES];
    body.extend_from_slice(&1u32.to_be_bytes());
    body.extend_from_slice(&chunk_len.to_be_bytes());
    body.extend_from_slice(&vec![0u8; chunk_len as usize]);
    blob.extend_from_slice(&body);
    let msg = format!("{:?}", decrypt(&blob, &archive).unwrap_err());
    assert!(
        !msg.contains("out of range"),
        "len == lower bound is valid, got {msg}"
    );
    assert!(
        msg.contains("nonce mismatch") || msg.contains("WrongPin"),
        "expected to reach nonce/AEAD, got {msg}"
    );
}

#[test]
fn chunk_len_one_under_lower_bound_is_out_of_range() {
    // chunk_len == 39 (one below nonce+tag) → "out of range". Kills `+`→`-`
    // (which lowers the bound to 8 and would accept 39).
    let (archive, mut blob) = chunked_prefix();
    let chunk_len = u32::try_from(NONCE_BYTES + AEAD_TAG_BYTES).unwrap() - 1; // 39
    let mut body = vec![0u8; NONCE_PREFIX_BYTES];
    body.extend_from_slice(&1u32.to_be_bytes());
    body.extend_from_slice(&chunk_len.to_be_bytes());
    body.extend_from_slice(&vec![0u8; chunk_len as usize]);
    blob.extend_from_slice(&body);
    let msg = format!("{:?}", decrypt(&blob, &archive).unwrap_err());
    assert!(msg.contains("out of range"), "got {msg}");
}

// ── :133-135  SINGLE size cap: `body.len() > CHUNK_THRESHOLD + NONCE + TAG` ───

#[test]
fn single_body_at_cap_passes_size_guard() {
    // A SINGLE body of EXACTLY the cap is the largest legal size: it must
    // pass the DoS guard and reach the AEAD (failing WrongPin), NOT "too
    // large". `>`→`>=`, and the `+`s in the cap, reject this exact size.
    let (archive, mut blob) = single_prefix();
    let cap = usize::try_from(CHUNK_THRESHOLD).unwrap() + NONCE_BYTES + AEAD_TAG_BYTES;
    blob.extend_from_slice(&vec![0u8; cap]);
    let msg = format!("{:?}", decrypt(&blob, &archive).unwrap_err());
    assert!(
        !msg.contains("too large"),
        "body == cap must pass, got {msg}"
    );
    assert!(msg.contains("WrongPin"), "expected AEAD failure, got {msg}");
}

#[test]
fn single_body_one_over_cap_is_rejected() {
    let (archive, mut blob) = single_prefix();
    let cap = usize::try_from(CHUNK_THRESHOLD).unwrap() + NONCE_BYTES + AEAD_TAG_BYTES;
    blob.extend_from_slice(&vec![0u8; cap + 1]);
    let msg = format!("{:?}", decrypt(&blob, &archive).unwrap_err());
    assert!(msg.contains("too large"), "got {msg}");
}
