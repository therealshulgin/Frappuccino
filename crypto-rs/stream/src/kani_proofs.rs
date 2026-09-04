//! Kani bounded-model-checking proof harnesses for the STRM parsing surface
//! (ROADMAP 8.4 item ③).
//!
//! Compiled ONLY when Kani drives the build (`--cfg kani`); invisible to
//! `cargo build`, `cargo test`, and `cargo clippy`. Run from `crypto-rs/`
//! in a Linux / WSL environment:
//!
//! ```text
//! cargo kani -p frappuccino-crypto-stream --no-default-features
//! ```
//!
//! These complement the §8.4.1 / §8.4.4 boundary unit tests: instead of
//! probing the parser at hand-picked ±1 edges, Kani proves the property over
//! the WHOLE bounded input space. `parse_header` is loop-free and crypto-free,
//! so it is exhaustively model-checkable. The AEAD-bearing decrypt paths
//! (`decrypt_single` / `decrypt_chunked`) are intentionally out of scope —
//! XChaCha20-Poly1305 over symbolic data cannot be modeled tractably, and the
//! per-chunk loop ranges over `chunk_count` up to `MAX_CHUNK_COUNT` (1e6) — and
//! stay covered by the boundary unit tests plus the `cargo fuzz` targets.

use crate::header::{
    be_u16, parse_header, GRANT_ENTRY_SIZE, HEADER_SIZE_NO_GRANTS, SEALED_ENVELOPE_SIZE,
};

/// Largest blob the harnesses reason over: the V3 no-grants header + one grant
/// entry + the mode byte = 87 + 112 + 1 = 200. This lets the symbolic
/// `grant_count` drive every branch — `grant_count` 0 and 1 both reach the
/// final mode-byte read, and `grant_count >= 2` exercises the truncated path.
/// The proofs run without `legacy-strm`, i.e. in the configuration the Android
/// `.so` ships: V3 is the only layout `layout_for_version` resolves, and a V1/V2
/// version byte is refused. That is deliberate — the property proven is the
/// property of the shipped binary, not of a superset build.
const N: usize = HEADER_SIZE_NO_GRANTS + GRANT_ENTRY_SIZE + 1;

/// A fully symbolic blob of symbolic length in `0..=N`.
fn symbolic_blob() -> ([u8; N], usize) {
    let buf: [u8; N] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= N);
    (buf, len)
}

/// No accepted blob carries a grant. The multi-recipient section is a reserved
/// wire field that nothing has ever emitted, so the parser must refuse rather
/// than walk `grant_count` entries of attacker-chosen input. Stated as a
/// postcondition on the accept path because that is what callers rely on:
/// `decrypt` slices from `header_end` assuming there is no grant section
/// between the header and the mode byte.
///
/// `N` still spans one full grant entry, so the symbolic `grant_count` reaches
/// values the old code would have parsed: the proof explores the blobs that
/// used to be accepted and shows they are now refused, rather than proving a
/// property over inputs that can no longer occur.
#[kani::proof]
fn check_parse_header_rejects_any_grant() {
    let (buf, len) = symbolic_blob();
    if let Ok(p) = parse_header(&buf[..len]) {
        assert!(p.grant_count == 0);
    }
}

/// `parse_header` never panics — no out-of-bounds index, no arithmetic
/// overflow, no failed `unwrap`/`expect` — for any input up to `N` bytes.
/// (Kani's default checks cover all of these; the harness just has to reach
/// the call with symbolic input.)
#[kani::proof]
fn check_parse_header_never_panics() {
    let (buf, len) = symbolic_blob();
    let _ = parse_header(&buf[..len]);
}

/// When `parse_header` accepts a blob, its reported (version-resolved) offsets
/// are internally consistent AND in-bounds — so the slicing `decrypt()`
/// performs immediately afterwards can never panic:
///   * `blob[sealed_offset .. sealed_offset + SEALED_ENVELOPE_SIZE]`
///   * `blob[.. header_end]`
///   * `blob[body_start ..]`
/// This machine-checks the parser->use contract that the §8.4.4 boundary tests
/// probe only at the ±1 edges. Holds for both the V3 layout (sealed at 5) and
/// the legacy V1/V2 layout (sealed at 37) — the proof reads the resolved
/// offsets off `ParsedHeader`, never a hard-coded constant.
#[kani::proof]
fn check_parse_header_postconditions_make_caller_slices_safe() {
    let (buf, len) = symbolic_blob();
    let blob = &buf[..len];
    if let Ok(p) = parse_header(blob) {
        // Offsets are internally consistent for whichever version was parsed.
        assert!(p.body_start == p.header_end + 1);
        // The sealed envelope lives wholly inside the header.
        assert!(p.sealed_offset + SEALED_ENVELOPE_SIZE <= p.header_end);
        // In-bounds for every slice `decrypt()` takes right after parsing.
        assert!(p.header_end < blob.len());
        assert!(p.body_start <= blob.len());
        // The actual index/slice operations decrypt() performs — these must not
        // panic. Ties the proof to the real use site, not just the asserts.
        let _sealed = &blob[p.sealed_offset..p.sealed_offset + SEALED_ENVELOPE_SIZE];
        let _aad = &blob[..p.header_end];
        let _body = &blob[p.body_start..];
    }
}

/// `be_u16` is big-endian, and the `|` in its definition is equivalent to `^`
/// (the two operand bit-ranges are disjoint: `hi << 8` occupies bits 8..16,
/// `lo` occupies bits 0..8). This machine-confirms the §8.4.4 "equivalent
/// mutant" verdict — `be_u16:77 | -> ^` is unkillable because OR == XOR here —
/// rather than relying on the hand argument in `header_boundaries.rs`.
#[kani::proof]
fn check_be_u16_big_endian_and_or_equals_xor() {
    let hi: u8 = kani::any();
    let lo: u8 = kani::any();
    let v = be_u16(hi, lo);
    assert!(v == u16::from(hi) * 256 + u16::from(lo));
    assert!(v == (u16::from(hi) << 8) ^ u16::from(lo));
}

/// `salamander::deobfuscate_in_place` never panics on a hostile datagram
/// (ROADMAP §10.10 T2). It de-obfuscates untrusted UDP at the obfs proxy's
/// internet-facing edge, so a panic is a remote DoS. The only panic-relevant
/// operations are the slice indexing `buf[..SALT_LEN]`, `buf[SALT_LEN..n]`,
/// `buf.copy_within(SALT_LEN..n, 0)` and the `n - SALT_LEN` subtraction; all
/// depend ONLY on the relation `SALT_LEN <= n <= buf.len()`, never on byte
/// values nor on the specific buffer length. So a small fixed concrete buffer is
/// representative: symbolic `n` drives both branches (`n < SALT_LEN` early-return
/// and the slice path), and the concrete content keeps the `BLAKE2b` `keystream`
/// concrete (out of the symbolic state). `#[kani::unwind(130)]` bounds CBMC's
/// loop unwinding (the `xor_in_place` loop trips `<= len - SALT_LEN` = 8; the
/// bound also clears `BLAKE2b`'s concrete internal loops) so the harness
/// terminates instead of unwinding the slice loop unboundedly (which OOMs CBMC).
#[kani::proof]
#[kani::unwind(130)]
fn check_deobfuscate_in_place_never_panics() {
    let mut buf = [0x5au8; 16];
    let n: usize = kani::any();
    kani::assume(n <= buf.len()); // the recv() contract; SALT_LEN..=len is the live range
    let psk = [1u8, 2, 3, 4];
    let _ = crate::salamander::deobfuscate_in_place(&mut buf, n, &psk);
}
