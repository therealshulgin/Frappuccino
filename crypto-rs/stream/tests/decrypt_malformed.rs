//! Error-path coverage for `stream::decrypt::decrypt` — every branch of
//! the malformed-input handling, reached via hand-crafted blobs.
//!
//! Complements `parity_strm.rs` (happy path) and the `fuzz_decrypt_blob`
//! harness (random bytes). This file deliberately constructs each
//! structural failure mode so `cargo tarpaulin` lights up every `return
//! Err(Malformed(…))` branch.

use frappuccino_crypto_core::identity::ArchiveIdentity;
use frappuccino_crypto_stream::decrypt::decrypt;
use frappuccino_crypto_stream::encrypt::encrypt_chunked;
use frappuccino_crypto_stream::encrypt::encrypt_single;
use frappuccino_crypto_stream::header::{
    ED25519_PK_BYTES, HEADER_SIZE_NO_GRANTS, NONCE_PREFIX_BYTES, OFF_SEALED, VERSION_V1,
};

const MN: &str = "abaisser abandon abdiquer abeille abolir aborder aboutir aboyer abrasif abreuver abriter abroger";

fn archive() -> ArchiveIdentity {
    ArchiveIdentity::from_mnemonic(MN, "").expect("archive identity")
}

#[test]
fn decrypt_rejects_unknown_mode_byte() {
    let archive = archive();
    let author = archive.identity().clone();
    let mut blob = encrypt_single(b"hello", &author).unwrap();
    // Header ends at HEADER_SIZE_NO_GRANTS (= 87 in V3 for grant_count=0). The
    // next byte is the mode — flip it to something invalid.
    blob[HEADER_SIZE_NO_GRANTS] = 0x7f;
    let err = decrypt(&blob, &archive).unwrap_err();
    assert!(
        format!("{err:?}").contains("unknown mode byte"),
        "expected 'unknown mode byte', got {err:?}"
    );
}

#[test]
fn decrypt_single_rejects_body_too_short() {
    let archive = archive();
    let author = archive.identity().clone();
    let mut blob = encrypt_single(b"hello", &author).unwrap();
    // Chop the body down to fewer than NONCE_BYTES + AEAD_TAG_BYTES
    // (= 40 bytes) while keeping the header + mode byte intact.
    let mode_off = HEADER_SIZE_NO_GRANTS; // 87 in V3
    blob.truncate(mode_off + 1 + 10); // 10-byte body ≪ 40
    let err = decrypt(&blob, &archive).unwrap_err();
    assert!(
        format!("{err:?}").contains("SINGLE body too short"),
        "expected 'SINGLE body too short', got {err:?}"
    );
}

#[test]
fn decrypt_single_rejects_tampered_ciphertext() {
    let archive = archive();
    let author = archive.identity().clone();
    let mut blob = encrypt_single(b"the quick brown fox", &author).unwrap();
    // Flip one byte in the ciphertext (past the mode + nonce).
    let ct_start = HEADER_SIZE_NO_GRANTS + 1 + 24;
    let ct_byte = ct_start + 3;
    blob[ct_byte] ^= 0x01;
    let err = decrypt(&blob, &archive).unwrap_err();
    // AEAD failure surfaces as `CryptoError::WrongPin` (by design — the
    // caller must not distinguish "wrong recipient" from "tampered blob").
    assert!(
        format!("{err:?}").contains("WrongPin"),
        "expected WrongPin after AEAD tag failure, got {err:?}"
    );
}

#[test]
fn decrypt_chunked_v1_rejected_rt02() {
    // RT-02 regression: V1 CHUNKED blobs (Kotlin pre-S5 legacy format) bound
    // their AEAD AAD to the header bytes only — `chunk_count` was NOT in
    // the AAD. An attacker who controlled the wire could drop trailing
    // chunks, mutate `chunk_count` accordingly, and have the receiver
    // accept the truncated stream silently (every per-chunk AEAD tag
    // remained valid). V2 fixed this in the encoder by binding `MODE ‖
    // nonce_prefix ‖ chunk_count` into the AAD; this test guards the
    // companion change in the decoder which now rejects V1 CHUNKED at
    // parse-time. V1 SINGLE remains accepted (no truncation surface there).
    //
    // The test forges a genuine V1 CHUNKED blob by encoding a 3-chunk
    // plaintext as V3 CHUNKED (real sealed envelope for `archive`) and
    // re-framing it into the LEGACY V1 layout: insert a 32-byte (zeroed)
    // author key before the sealed envelope and stamp the version byte V1.
    // (A bare V3->V1 version flip no longer works: V3 keeps the sealed
    // envelope at offset 5, but a V1 reader looks for it at offset 37 — so
    // the re-frame is required to keep the envelope unsealable.) The sealed
    // envelope still unseals, so decrypt reaches decrypt_chunked, where the
    // V1 CHUNKED branch rejects before any AAD/AEAD work.
    let archive = archive();
    let author = archive.identity().clone();
    let plaintext = vec![0u8; 2 * 1024 * 1024 + 1]; // forces 3 chunks
    let v3 = encrypt_chunked(&plaintext, &author).unwrap();
    // v3[OFF_SEALED..] = sealed(80) ‖ grant_count(2) ‖ mode ‖ body.
    let mut blob = Vec::with_capacity(v3.len() + ED25519_PK_BYTES);
    blob.extend_from_slice(b"STRM");
    blob.push(VERSION_V1);
    blob.extend_from_slice(&[0u8; ED25519_PK_BYTES]); // legacy author slot
    blob.extend_from_slice(&v3[OFF_SEALED..]);

    let err = decrypt(&blob, &archive).unwrap_err();
    let msg = format!("{err:?}");

    // The forged blob is the same in both builds; what refuses it is not, and
    // each refusal is worth its own assertion.
    //
    // Shipped build (no `legacy-strm`): `parse_header` refuses the V1 version
    // byte outright, so the blob never reaches `decrypt_chunked`. That is the
    // stronger position and the one the `.so` is in.
    #[cfg(not(feature = "legacy-strm"))]
    assert!(
        msg.contains("LegacyVersionNotSupported"),
        "expected the V1 blob to be refused at parse in a V3-only build, got {msg}"
    );

    // CLI build (`legacy-strm`): V1 parses, so the RT-02 guard in
    // `decrypt_chunked` is what stands between a witness and a silently
    // truncated archive. Keeping this assertion alive under the feature is the
    // point of testing both configurations: gating the format out of the app
    // must not gate its guard out of the evidence.
    #[cfg(feature = "legacy-strm")]
    assert!(
        msg.contains("V1 CHUNKED rejected"),
        "expected V1 CHUNKED rejection (RT-02), got {msg}"
    );
}

#[test]
fn decrypt_chunked_rejects_body_too_short() {
    let archive = archive();
    let author = archive.identity().clone();
    let plaintext = vec![0u8; 2 * 1024 * 1024 + 1]; // 3 chunks
    let mut blob = encrypt_chunked(&plaintext, &author).unwrap();
    // Truncate right after the mode byte — body now < NONCE_PREFIX_BYTES + 4.
    let mode_off = HEADER_SIZE_NO_GRANTS;
    blob.truncate(mode_off + 1 + 5);
    let err = decrypt(&blob, &archive).unwrap_err();
    assert!(
        format!("{err:?}").contains("CHUNKED body too short"),
        "expected 'CHUNKED body too short', got {err:?}"
    );
}

#[test]
fn decrypt_chunked_rejects_chunk_count_over_cap() {
    let archive = archive();
    let author = archive.identity().clone();
    let plaintext = vec![0u8; 2 * 1024 * 1024 + 1];
    let mut blob = encrypt_chunked(&plaintext, &author).unwrap();
    // chunk_count lives at body[NONCE_PREFIX_BYTES..+4] = blob[header+1+20..+4].
    let cc_off = HEADER_SIZE_NO_GRANTS + 1 + NONCE_PREFIX_BYTES;
    let bogus: u32 = 2_000_000; // > MAX_CHUNK_COUNT = 1_000_000
    blob[cc_off..cc_off + 4].copy_from_slice(&bogus.to_be_bytes());
    let err = decrypt(&blob, &archive).unwrap_err();
    assert!(
        format!("{err:?}").contains("exceeds cap"),
        "expected 'exceeds cap', got {err:?}"
    );
}

#[test]
fn decrypt_chunked_rejects_missing_chunk_len() {
    let archive = archive();
    let author = archive.identity().clone();
    let plaintext = vec![0u8; 2 * 1024 * 1024 + 1];
    let mut blob = encrypt_chunked(&plaintext, &author).unwrap();
    // Keep the prefix + chunk_count = 3 intact, but drop everything
    // after. Decoder loops 0..3 and fails reading the first chunk_len.
    let cc_off = HEADER_SIZE_NO_GRANTS + 1 + NONCE_PREFIX_BYTES;
    blob.truncate(cc_off + 4 + 2); // only 2 stray bytes where u32 len sits
    let err = decrypt(&blob, &archive).unwrap_err();
    assert!(
        format!("{err:?}").contains("chunk 0: missing len"),
        "expected 'chunk 0: missing len', got {err:?}"
    );
}

#[test]
fn decrypt_chunked_rejects_chunk_len_over_cap() {
    let archive = archive();
    let author = archive.identity().clone();
    let plaintext = vec![0u8; 2 * 1024 * 1024 + 1];
    let mut blob = encrypt_chunked(&plaintext, &author).unwrap();
    // Patch the first chunk's total_len to 0xffff_ffff (> MAX_CHUNK_LEN).
    let first_chunk_len_off = HEADER_SIZE_NO_GRANTS + 1 + NONCE_PREFIX_BYTES + 4;
    blob[first_chunk_len_off..first_chunk_len_off + 4].copy_from_slice(&u32::MAX.to_be_bytes());
    let err = decrypt(&blob, &archive).unwrap_err();
    assert!(
        format!("{err:?}").contains("out of range"),
        "expected 'out of range', got {err:?}"
    );
}

#[test]
fn decrypt_chunked_rejects_chunk_reorder() {
    // Regression test for the chunk-reorder finding closed by
    // `fix(security): chunk reorder detection in V2 CHUNKED decrypt`.
    //
    // Given two equal-length chunk frames, swapping them used to pass
    // every per-chunk AEAD tag (each frame carries its own nonce_prefix
    // ‖ original_index) even though the reconstructed plaintext would
    // emerge scrambled. V2 now reconstructs `expected_nonce = prefix ‖ i`
    // at loop-index `i` and rejects when the frame's stored nonce doesn't
    // match.
    //
    // The test crafts a 2-chunk payload of exact-same ciphertext length
    // (chunk_len == chunk_len), swaps frame 0 with frame 1 in the bytes,
    // and expects `decrypt` to bail with "nonce mismatch".
    use frappuccino_crypto_stream::header::{AEAD_TAG_BYTES, NONCE_BYTES};

    let archive = archive();
    let author = archive.identity().clone();

    // Exactly 2 full 1-MiB chunks → both frames have identical total_len.
    let plaintext = vec![0x37u8; 2 * 1024 * 1024];
    let blob = encrypt_chunked(&plaintext, &author).unwrap();
    let (_, meta) = decrypt(&blob, &archive).expect("original blob must decrypt");
    assert_eq!(meta.version, 3);

    // Locate the two frames. Body layout after the header + MODE byte:
    //   [prefix(20) ‖ chunk_count(4)] [frame0: len(4) ‖ nonce(24) ‖ ct+tag]
    //                                 [frame1: len(4) ‖ nonce(24) ‖ ct+tag]
    let frames_off = HEADER_SIZE_NO_GRANTS + 1 + NONCE_PREFIX_BYTES + 4;
    let frame_header = 4; // u32 total_len prefix

    // Both chunks have the same total_len because their plaintexts are same-size.
    let chunk0_total_len =
        u32::from_be_bytes(blob[frames_off..frames_off + 4].try_into().unwrap()) as usize;
    let chunk1_total_len = u32::from_be_bytes(
        blob[frames_off + frame_header + chunk0_total_len
            ..frames_off + frame_header + chunk0_total_len + 4]
            .try_into()
            .unwrap(),
    ) as usize;
    assert_eq!(
        chunk0_total_len, chunk1_total_len,
        "test assumption: equal-length frames"
    );
    // Sanity: total_len = NONCE_BYTES + ct + tag
    assert!(chunk0_total_len >= NONCE_BYTES + AEAD_TAG_BYTES);

    // Byte ranges for the two entire frames (including the len prefix).
    let frame_size = frame_header + chunk0_total_len;
    let frame0 = frames_off..frames_off + frame_size;
    let frame1 = frames_off + frame_size..frames_off + 2 * frame_size;

    // Build a swapped blob: [header][prefix|count][frame1][frame0][...]
    let mut swapped = blob.clone();
    swapped[frame0.clone()].copy_from_slice(&blob[frame1.clone()]);
    swapped[frame1].copy_from_slice(&blob[frame0]);

    let err = decrypt(&swapped, &archive).unwrap_err();
    let msg = format!("{err:?}");
    assert!(
        msg.contains("nonce mismatch"),
        "expected 'nonce mismatch (reorder or tampering detected)', got {msg}"
    );
}

#[test]
fn decrypt_chunked_rejects_trailing_bytes() {
    // B-CR-5 (audit 2026-06-26): a well-formed CHUNKED blob has
    // `cursor == body.len()` once every declared chunk is consumed. Appending
    // stray bytes after the last frame must be rejected rather than silently
    // ignored. `chunk_count` is AAD-bound so the tail can never carry
    // authenticated data — this is parser strictness (defense-in-depth),
    // symmetric with the SINGLE upper-bound check.
    let archive = archive();
    let author = archive.identity().clone();
    let plaintext = vec![0u8; 2 * 1024 * 1024 + 1]; // 3 chunks
    let blob = encrypt_chunked(&plaintext, &author).unwrap();
    // Sanity: the pristine blob decrypts.
    decrypt(&blob, &archive).expect("pristine CHUNKED blob must decrypt");

    let mut tainted = blob.clone();
    tainted.extend_from_slice(b"\x00\x01\x02\x03trailing-garbage");
    let err = decrypt(&tainted, &archive).unwrap_err();
    assert!(
        format!("{err:?}").contains("trailing bytes after last chunk"),
        "expected 'trailing bytes after last chunk', got {err:?}"
    );
}

#[test]
fn decrypt_chunked_rejects_truncated_chunk_body() {
    let archive = archive();
    let author = archive.identity().clone();
    let plaintext = vec![0u8; 2 * 1024 * 1024 + 1];
    let mut blob = encrypt_chunked(&plaintext, &author).unwrap();
    // Cut the blob mid-ciphertext inside the first chunk (past the
    // first chunk's total_len + nonce but before the ct ends).
    let first_chunk_data_off = HEADER_SIZE_NO_GRANTS + 1 + NONCE_PREFIX_BYTES + 4;
    // Leave only 50 bytes of the first chunk body (< declared total_len).
    blob.truncate(first_chunk_data_off + 4 + 50);
    let err = decrypt(&blob, &archive).unwrap_err();
    assert!(
        format!("{err:?}").contains("truncated body"),
        "expected 'truncated body', got {err:?}"
    );
}
