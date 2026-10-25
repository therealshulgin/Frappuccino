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

/// Longest filename the decoder harness reasons over. Each extra byte adds a
/// whole decoder run to the harness, and a costlier one; 4 keeps it within a
/// few minutes. The reserved name `manifest` (8 bytes) is beyond this bound:
/// its refusal is covered by the unit tests of `envelope.rs`, not here.
const TRAILER_NAME_N: usize = 4;

/// Largest queue-envelope trailer plaintext the decoder harness reasons over:
/// the fixed fields plus a filename of up to `TRAILER_NAME_N` bytes. With the
/// short-input harness, every length up to this one is covered, and these
/// lengths reach each other refusal (a filename length byte larger or smaller
/// than what follows, invalid kind, a byte outside the relay alphabet, `.`,
/// `..`, per-kind payload rules) and the accept path.
const TRAILER_N: usize = crate::envelope::TRAILER_FIXED_BYTES + TRAILER_NAME_N;

/// Where the filename starts in the trailer plaintext: after kind(1),
/// report_id(16), report_pk(32), signature(64), create_sig(64), seq_limit(4)
/// and filename_len(1).
const TRAILER_NAME_AT: usize = 1 + 16 + 32 + 64 + 64 + 4 + 1;

/// Every decrypted trailer shorter than the fixed fields is refused, without
/// a panic. The decoder checks the length of its input before anything else,
/// so none of these inputs reaches a loop, and a symbolic length stays cheap.
/// `#[kani::unwind(2)]` is enough for that reason only: a loop that these
/// inputs did reach and run more than once would fail its unwinding check, so
/// a decoder that started looping before its length check would make this
/// harness fail, not pass.
#[kani::proof]
#[kani::unwind(2)]
fn check_envelope_trailer_decode_refuses_short_input() {
    use crate::envelope::{decode_plain, TRAILER_FIXED_BYTES};
    let buf: [u8; TRAILER_FIXED_BYTES - 1] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= buf.len());
    assert!(decode_plain(&buf[..len]).is_err());
}

/// `envelope::decode_plain` never panics (no out-of-bounds slice, no
/// overflow, no failed unwrap) for any decrypted trailer from
/// `TRAILER_FIXED_BYTES` to `TRAILER_N` bytes (shorter ones are the harness
/// above), and on a trailer it accepts the declared filename length accounts
/// for every byte of the input, the filename has that length, and the bytes
/// at its place form a name the relay accepts (none for a closure). The
/// decoder runs on bytes that passed the AEAD, so this is the property that
/// matters if the queue key leaks or a trailer is forged with it; the
/// filename postconditions are what a sender relies on when it puts the name
/// in a URL.
///
/// That the filename is those bytes unchanged is not stated here. Read back
/// through the decoder's merged result, the comparison of the content alone
/// costs several times the rest of the harness. It is the exhaustive unit
/// test of the conversion in `envelope.rs`, over every byte value, instead.
///
/// Each of these lengths is checked in turn, each over fully symbolic bytes,
/// rather than one symbolic length. With a concrete length every loop of the
/// decoder has a concrete bound, and the model checker unrolls each one
/// exactly; with a symbolic length the filename loops are unrolled to the
/// global bound, each step behind a symbolic guard, and the harness does not
/// finish. The decoder is written to keep it that way (see `decode_plain`
/// and `filename_from_bytes`): it derives the filename length from the
/// length of its input before anything else, it stops each refusal with
/// `let ... else` rather than `ok_or(..)?`, and it builds the string byte by
/// byte rather than through `str::from_utf8`. `#[kani::unwind(70)]` is above
/// the longest loops on the path, the comparisons of the 64-byte `create_sig`
/// with zeros; a loop that needed more would fail its unwinding check.
///
/// Once the decoder has returned, its result merges every way it can return,
/// so a length read back from it is no longer concrete. The postconditions
/// are therefore stated over the length the input implies (`name_len`),
/// asserted equal to the filename's length first, and the result is
/// forgotten rather than dropped: dropping it would run the wipe loops of a
/// trailer over such a merged length, on the refusals too, which the model
/// checker cannot tell apart from an accepted trailer at that point. The
/// wipe on drop is therefore outside this harness. The decoder itself drops
/// no trailer: it assembles one only once the rules hold.
#[kani::proof]
#[kani::unwind(70)]
fn check_envelope_trailer_decode_never_panics() {
    use crate::envelope::{decode_plain, EnvelopeKind, TRAILER_FIXED_BYTES};
    let buf: [u8; TRAILER_N] = kani::any();
    for len in TRAILER_FIXED_BYTES..=TRAILER_N {
        let plain = &buf[..len];
        let decoded = decode_plain(plain);
        if let Ok(trailer) = &decoded {
            let name_len = len - TRAILER_FIXED_BYTES;
            let name = trailer.filename().as_bytes();
            assert!(name.len() == name_len);
            assert!(usize::from(plain[TRAILER_NAME_AT - 1]) == name_len);
            let at_place = &plain[TRAILER_NAME_AT..TRAILER_NAME_AT + name_len];
            if trailer.kind() == EnvelopeKind::Closure {
                assert!(name_len == 0);
            } else {
                assert!(crate::pathsafe::is_relay_object_name_bytes(at_place));
            }
        }
        core::mem::forget(decoded);
    }
}

/// The envelope framing (`u32_be(sealed_len) ‖ "FQE1"` at the end of a file)
/// never panics, and when it accepts a tail the slice it returns is the
/// sealed trailer right before the footer, within the allowed size range, and
/// the payload length it derives accounts for the whole file. The tail is up
/// to `MAX_TAIL_BYTES` long and the file length is fully symbolic, which
/// covers every relation between the two.
#[kani::proof]
fn check_envelope_framing_accounts_for_the_whole_file() {
    use crate::envelope::{
        locate_sealed_trailer, FOOTER_BYTES, MAX_SEALED_TRAILER_BYTES, MAX_TAIL_BYTES,
        MIN_SEALED_TRAILER_BYTES,
    };
    let buf: [u8; MAX_TAIL_BYTES] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= MAX_TAIL_BYTES);
    let file_len: u64 = kani::any();
    let tail = &buf[..len];
    if let Ok((sealed, payload_len)) = locate_sealed_trailer(file_len, tail) {
        assert!(sealed.len() >= MIN_SEALED_TRAILER_BYTES);
        assert!(sealed.len() <= MAX_SEALED_TRAILER_BYTES);
        assert!(sealed.len() + FOOTER_BYTES <= tail.len());
        assert!(payload_len + (sealed.len() + FOOTER_BYTES) as u64 == file_len);
        assert!(tail[len - 4..] == crate::envelope::ENVELOPE_MAGIC);
    }
}
