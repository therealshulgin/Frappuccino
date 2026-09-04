//! Fuzz target: `stream::header::parse_header(blob)`.
//!
//! Pure cursor-arithmetic path — no crypto calls, no allocation beyond the
//! small `ParsedHeader` struct. Very fast per iteration so it's the right
//! surface to exhaust with libfuzzer's coverage-guided mutation.
//!
//! Invariant: every input returns `Err` or a well-formed `ParsedHeader`;
//! never a panic, never an out-of-bounds slice.

#![no_main]

use frappuccino_crypto_stream::header::parse_header;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = parse_header(data);
});
