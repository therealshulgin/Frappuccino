# frappuccino-fuzz

Coverage-guided fuzz harnesses for the Rust crypto core. Targets are built
on top of `libfuzzer-sys`, which requires **nightly Rust on Linux or macOS**
— this crate will not build on Windows MSVC.

## Targets

| Target                      | Surface fuzzed                                               |
|-----------------------------|--------------------------------------------------------------|
| `fuzz_decrypt_blob`         | `stream::decrypt::decrypt(bytes, &archive)`                  |
| `fuzz_parse_strm_header`    | `stream::header::parse_header(bytes)` (cursor arithmetic)    |
| `fuzz_ratchet_deserialize`  | `core::ratchet::EphemeralRatchet::deserialize(bytes)`        |
| `fuzz_pin_store_open`       | `core::pin_store::open(pin, bytes)` (slow: Argon2id per iter)|

The invariant every target enforces is **no panic** — every byte slice,
regardless of length or contents, must either return `Ok` or `Err`, never
unwind.

## Seed corpus

Seed blobs live under `corpus/<target>/0000_seed` and are committed. They
give libfuzzer a known-good starting point so coverage-guided mutation
reaches meaningful branches in minutes rather than hours.

Regenerate them whenever a format evolves (post S9-pre-audit: STRM v2,
ratchet V2, PIN store v1):

```sh
# From the workspace root (crypto-rs/), stable toolchain:
cargo run --release -p frappuccino-cli --bin generate_fuzz_seeds
```

## Running (standard path: nightly + Docker)

The workspace is pinned to stable 1.88 via `rust-toolchain.toml`. The fuzz
crate is deliberately excluded from that workspace (own `[workspace]` in
its `Cargo.toml`) so it can use nightly independently.

One-shot via Docker (reproducible, no host toolchain pollution):

```sh
docker run --rm -it \
  -v "$(pwd):/work" -w /work/crypto-rs/fuzz \
  rustlang/rust:nightly \
  bash -c '
    cargo install --locked cargo-fuzz && \
    cargo fuzz run fuzz_decrypt_blob --sanitizer none -- -runs=10000
  '
```

Replace `fuzz_decrypt_blob` with any target name. `-- -runs=10000` caps at
10k iterations — plenty for a smoke test. Drop the `-runs` cap for an
unbounded run (Ctrl-C when satisfied) or use `-max_total_time=3600` for a
one-hour budget.

> **Note on `--sanitizer none`** : ASan + libfuzzer's `sancov` together
> trip a known linker issue on recent nightlies
> (`undefined symbol: __sancov_gen_.*`). We disable ASan and keep
> coverage-guided mutation only — the memory-safety side is already
> covered by `cargo miri test` and the Rust borrow checker. See
> [rust-fuzz/cargo-fuzz#423](https://github.com/rust-fuzz/cargo-fuzz/issues/423)
> for the upstream tracking issue.

### Audit-grade run (100M iterations)

The pre-audit target from `SESSION_CONTEXT_COMPACT_V4 §11 Option B` is
100M iterations per harness on the non-slow targets (decrypt, header,
ratchet). `fuzz_pin_store_open` is Argon2id-bounded at ~1 iter/s per core,
so budget it in hours rather than iteration count:

```sh
# 100M iter on the fast targets (≈ 30–60 minutes each on an 8-core box)
cargo fuzz run fuzz_parse_strm_header   --sanitizer none -- -runs=100000000 -jobs=8
cargo fuzz run fuzz_ratchet_deserialize --sanitizer none -- -runs=100000000 -jobs=8
cargo fuzz run fuzz_decrypt_blob        --sanitizer none -- -runs=100000000 -jobs=8

# pin_store_open: cap by wall time (~4h)
cargo fuzz run fuzz_pin_store_open      --sanitizer none -- -max_total_time=14400 -jobs=8
```

### Smoke test validated (2026-04-19)

Run on the Vultr dev box (Ubuntu 20.04, 1 GiB RAM + 2 GiB swap, Docker
`rustlang/rust:nightly` tagged rustc 1.97.0-nightly):

| Target                      | Runs  | RSS (MB) | New units | Result  |
|-----------------------------|-------|----------|-----------|---------|
| `fuzz_parse_strm_header`    | 2 000 | 34       | 24        | clean   |
| `fuzz_decrypt_blob`         | 2 000 | 34       | 39        | clean   |
| `fuzz_ratchet_deserialize`  | 2 000 | 34       | 39        | clean   |
| `fuzz_pin_store_open`       |    30 | 283      |  2        | clean (Argon2id bound, ~1 iter/s) |

If libfuzzer prints `Done N runs` without any `ERROR:` line in the last
hour and no new unique crash under `fuzz/artifacts/<target>/`, the run is
clean.

## Triaging a crash

Any crash reproducer is written under `fuzz/artifacts/<target>/crash-*`.
Replay it from a stable toolchain to get a normal stack trace:

```sh
# In the fuzz crate (still nightly, but shrunk to a single iter):
cargo fuzz run fuzz_decrypt_blob fuzz/artifacts/fuzz_decrypt_blob/crash-<hash>
```

Attach the reproducer byte-for-byte to the bug report — it's the smallest
artifact that demonstrates the issue.

## CI integration (future)

The intent is to run a short-budget version (10–30 min per target) on
every PR via a GitHub Actions job pinned to Linux + nightly. The 100M
iter audit-grade run stays on-demand, triggered before an auditor round.
