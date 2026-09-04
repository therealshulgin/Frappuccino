# Kani proofs — STRM parser (8.4 ③) + transport de-obfs (§10.10)

**Date:** 2026-09-03 · **Result: 5/5 harnesses verified, 0 failures.**

> **Re-vérifié 2026-06-29** (HEAD `fc1560c`, post WP-E4/F/G ; cargo-kani 0.67.0 via WSL) :
> **4/4 harnesses SUCCESSFUL, 0 failure** — `check_parse_header_postconditions_make_caller_slices_safe`,
> `check_parse_header_never_panics`, `check_deobfuscate_in_place_never_panics`,
> `check_be_u16_big_endian_and_or_equals_xor`. Ce bloc est le compte rendu d'un run
> DATÉ et il reste à quatre : le cinquième harnais (rejet des grants) n'existait pas
> encore. Le compte courant est **5**, asséré par `run-kani.sh`. Une passe du
> 2026-09-04 avait remplacé ce 4/4 par 5/5 sans regarder qu'elle réécrivait un
> compte rendu ; restauré le jour même. **Important :** `header.rs` / `parse_header` ont changé
> APRÈS le run 2026-06-23 — STRM **V3** (`e1f8a9d`, en-tête sans `author_pk`) + clamp rescue WP-C
> (`2d09846`) — donc ce re-run re-prouve la sûreté no-panic du parser **sur le format V3** ; le trou de
> fraîcheur (preuve antérieure au changement qu'elle couvre) est fermé.

## What this adds over the boundary tests

§8.4.1 / §8.4.4 closed the parser's mutation gaps with unit tests at hand-picked
±1 edges. Kani goes further: it **bounded-model-checks** the parser over the
*entire* symbolic input space (every byte and every length up to a bound at
once), so "no panic / no overflow / no out-of-bounds" becomes a machine proof
rather than a finite sample. Where a fuzzer searches and a unit test spot-checks,
Kani is exhaustive within the bound.

The target is the untrusted-input attack surface: `stream/src/header.rs`
`parse_header`, which is loop-free and crypto-free and therefore tractable.

## Harnesses (`stream/src/kani_proofs.rs`, `#[cfg(kani)]`)

| Harness | Proves |
|---|---|
| `check_parse_header_never_panics` | `parse_header` never panics — no OOB index, no arithmetic overflow, no failed `unwrap`/`expect` — for any input up to 200 bytes. (86 automatic checks, all SUCCESS.) |
| `check_parse_header_postconditions_make_caller_slices_safe` | When `parse_header` returns `Ok(p)`, the offsets are internally consistent (`header_end == HEADER_SIZE_NO_GRANTS`, since a declared grant is refused outright, and `body_start == header_end+1`) **and** in-bounds, so the three slices `decrypt()` takes right after (`blob[OFF_SEALED..OFF_SEALED+SEALED_ENVELOPE_SIZE]`, `blob[..header_end]`, `blob[body_start..]`) can never panic. The harness performs those exact slices to tie the proof to the real use site. |
| `check_parse_header_rejects_any_grant` | No accepted blob carries a grant: when `parse_header` returns `Ok(p)`, `p.grant_count == 0`. The multi-recipient section is a reserved wire field nothing has ever emitted, so the parser refuses rather than walking `grant_count` entries of attacker-chosen input (2026-09-03). The bound `N` still spans a full grant entry, so the proof explores the blobs the old code accepted and shows they are now refused, rather than proving a property over inputs that can no longer occur. |
| `check_be_u16_big_endian_and_or_equals_xor` | `be_u16(hi,lo) == hi*256 + lo` **and** `== (hi<<8) ^ lo`. The second equality machine-confirms the §8.4.4 "equivalent mutant" verdict — `be_u16:77 \| -> ^` is unkillable because the operand bit-ranges are disjoint, so OR ≡ XOR — replacing the hand argument with a proof. |
| `check_deobfuscate_in_place_never_panics` (§10.10) | The Salamander de-obfuscation parser (`stream/src/salamander.rs`), the obfs proxy's internet-facing **untrusted-UDP** edge, never panics on **any** datagram, for every symbolic `n` in the `recv` contract `SALT_LEN <= n <= buf.len()`. See the note below on why a small concrete buffer + `#[kani::unwind]` is a complete no-panic proof here despite the `BLAKE2b` call. |

### Counting the harnesses is part of the proof

`run-kani.sh` asserts that **exactly `EXPECTED_HARNESSES` (5)** come back verified,
not merely that none failed. `cargo kani` already exits non-zero on a FAILING
proof, so that half was covered; what an exit code cannot see is a proof that
stopped EXISTING. Delete a harness, rename it, drop its `#[kani::proof]`, or cfg
it out, and the run stays green with less proven, while every report keeps saying
"Kani: verified".

The runner also has a `selftest` mode that exercises the summary parser without
Kani installed (so it runs on Windows too), including the case that matters: a
summary reading `4 successfully verified harnesses, 0 failures, 4 total` is
perfectly well-formed and internally consistent, and only an expected count tells
it apart from success. Negative control, 2026-09-03: comment out one
`#[kani::proof]` and the runner fails with `expected 5 harnesses, got 4`.

Same rule as `run-tamarin.sh`, one file over, and for the same reason.

### Why the bound `N = 200` is complete

`N = HEADER_SIZE_NO_GRANTS + GRANT_ENTRY_SIZE + 1 = 87 + 112 + 1`, the value the
harness computes from the constants themselves. This document said 232 until
2026-09-04, which was the V1/V2 figure: 119 is `LEGACY_HEADER_SIZE_NO_GRANTS`.
The bound moved when the container went to V3 and the author key left the header;
the prose did not follow. With a fully
symbolic buffer of symbolic length in `0..=N`, the symbolic `grant_count` drives
every branch: `grant_count` 0 and 1 both reach the final mode-byte read (the
deepest path), and `grant_count >= 2` makes `header_end` exceed the buffer and
exercises the `TruncatedWithGrants` path. `parse_header` has no loops, so a
larger buffer adds no new control flow — the bound is complete for branch
coverage, not a truncation of it.

### Why a concrete buffer is complete for `deobfuscate_in_place`

Unlike `parse_header`, this function calls `BLAKE2b` (`keystream`) and loops
(`xor_in_place`) — a naive fully-symbolic harness chokes on both (symbolic hash
input is intractable; the symbolic-length slice loop unwinds unboundedly and
OOMs CBMC, observed). But the property is **no-panic**, and the only
panic-relevant operations — the slices `buf[..SALT_LEN]`, `buf[SALT_LEN..n]`,
`buf.copy_within(SALT_LEN..n, 0)` and the subtraction `n - SALT_LEN` — depend
**solely** on the relation `SALT_LEN <= n <= buf.len()`, never on byte values nor
on the specific buffer length (`keystream`/`xor_in_place` are total). So fixing
the content concrete (which constant-folds `BLAKE2b` out of the symbolic state)
and bounding the loop with `#[kani::unwind(130)]`, while `n` stays symbolic over
the whole `recv` range, proves no-panic for **all** content and length. This is
the same "keep the crypto out of the symbolic state" discipline as the parser
harnesses, applied to a hash-bearing function — it proves no-panic, *not* hash
correctness (which is what the proptest round-trip + the shared-module parity
cover instead).

## Out of scope (and why)

- **The AEAD-bearing decrypt paths** (`decrypt_single`, `decrypt_chunked`):
  XChaCha20-Poly1305 over symbolic data cannot be model-checked tractably, and
  `decrypt_chunked`'s per-chunk loop ranges over `chunk_count` up to
  `MAX_CHUNK_COUNT` (1e6). The *parsing* gateway they sit behind (`parse_header`
  + the caller slicing) is proven here; the AEAD/length paths stay covered by
  the §8.4.1 boundary unit tests and the `cargo fuzz` targets.
- **The ratchet** (`core`): `deserialize` authenticates a V2 blob with HMAC-SHA256
  before parsing, and the pure parse ranges over a 4844-byte payload — both
  intractable for Kani. The ratchet's zeroization is instead proven at the
  compiler-IR level (see `docs/ZEROIZE_AUDIT_RATCHET.md`) and its
  serialize/Debug/zeroize invariants by mutation testing (§8.4.2/§8.4.3).

## How to run

Kani needs Linux or macOS — there is no Windows build. On Windows, run from WSL.
One-time prereqs in the Linux/WSL env: install rustup, then
`cargo install --locked kani-verifier && cargo kani setup`. Then, from the
workspace root:

```bash
crypto-rs/run-kani.sh
# or a single harness:
crypto-rs/run-kani.sh --harness check_be_u16_big_endian_and_or_equals_xor
```

`run-kani.sh` verifies against a throwaway copy of the workspace with
`rust-toolchain.toml` removed — the project pins Rust 1.88, which would otherwise
override Kani's own bundled toolchain. The real tree is never modified. The
harnesses are `#[cfg(kani)]`-gated, so they are invisible to `cargo build`,
`cargo test`, and `cargo clippy` (the `kani` cfg is registered in the workspace
`Cargo.toml` `check-cfg` so `-D warnings` stays green).

Baseline: **5 harnesses verified, 0 failures** (Kani 0.67.0, CBMC backend) — the 3
parser harnesses (2026-06-06), the Salamander de-obfs no-panic proof (2026-06-23,
§10.10 T2), and the grant-rejection proof (2026-09-03). `run-kani.sh` asserts this
count, so a harness cannot quietly stop existing; if the two numbers ever disagree,
the runner is right and this line is stale.

## Status

ROADMAP **8.4 item ③ (Kani)** — Done for the parser surface. The machine-checked
no-panic proof of `parse_header` + the caller-slice-safety contract + the
`be_u16` equivalent-mutant confirmation are the deliverable. ROADMAP **§10.10 T2**
extends the same technique to the transport: the obfs proxy's
`deobfuscate_in_place` parser is now machine-checked no-panic on hostile UDP.
