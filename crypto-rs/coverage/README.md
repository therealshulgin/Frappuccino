# Coverage — crypto-rs core + stream

**Current**: 90.39 % line coverage (922 / 1020) on `frappuccino-crypto-core`
and `frappuccino-crypto-stream`. Produced by `cargo-tarpaulin 0.34.0` under
Rust 1.88 on Linux (ptrace-based, Docker container).

The target from `AUDIT_SCOPE_RUST.md §7` is ≥ 90 % on `core/` and `stream/`;
FFI wrappers and the CLI are glue and not counted.

## Regenerate

```sh
# From crypto-rs/, on a Linux / macOS host (Windows MSVC has no ptrace):
docker run --rm \
  -v "$(pwd):/work" -w /work \
  --cap-add=SYS_PTRACE --security-opt seccomp=unconfined \
  --network=host \
  rust:1.88 \
  bash -c '
    cargo install --locked cargo-tarpaulin --version 0.34.0
    cargo tarpaulin \
      -p frappuccino-crypto-core \
      -p frappuccino-crypto-stream \
      --lib --tests --ignored --implicit-test-threads \
      --out Stdout --out Html --output-dir /work/coverage \
      --timeout 600
  '
```

`--ignored` runs the `#[ignore]` E2E tests against the live Vultr relay
(see `crypto-rs/stream/tests/e2e_protocol.rs`). Without them, `pin.rs`
and `protocol.rs` drop to ~7 % and overall coverage is ~77 %.

## Per-file breakdown (tarpaulin 2026-04-20)

| File                              | Covered | Total | Percent |
|-----------------------------------|---------|-------|---------|
| `core/src/bip39.rs`               | 87      | 98    | 88.8 %  |
| `core/src/hkdf.rs`                | 7       | 8     | 87.5 %  |
| `core/src/identity.rs`            | 99      | 109   | 90.8 %  |
| `core/src/pin_store.rs`           | 80      | 88    | 90.9 %  |
| `core/src/ratchet.rs`             | 190     | 205   | 92.7 %  |
| `core/src/seal.rs`                | 34      | 35    | 97.1 %  |
| `core/src/secret.rs`              | 41      | 50    | 82.0 %  |
| `stream/src/decrypt.rs`           | 69      | 74    | 93.2 %  |
| `stream/src/encrypt.rs`           | 80      | 88    | 90.9 %  |
| `stream/src/header.rs`            | 23      | 23    | 100 %   |
| `stream/src/pin.rs` (TLS SPKI)    | 57      | 77    | 74.0 %  |
| `stream/src/protocol.rs` (HTTP)   | 65      | 72    | 90.3 %  |

## Known gaps (documented, not counted against 90 % target)

* **`stream/src/pin.rs` (TLS verifier) — 74 %**: the remaining 20 lines are
  error branches in `verify_server_cert` (malformed cert chain, CA
  mismatch, missing extensions). Triggering them would require a
  black-hat-style mock TLS peer; the SPKI-pin path is fully covered by
  the `e2e_wrong_spki_pin_rejects_handshake` test.
* **`stream/src/protocol.rs` — 90 %**: the 7 uncovered lines are the
  JSON deserialization error branches (server returning a malformed
  response body). Would need a mock HTTP server fixture to exercise.
* **`core/src/secret.rs` — 82 %**: uncovered lines are the `memsec::mlock`
  failure paths on systems where mlock isn't permitted (CI containers
  without `IPC_LOCK` cap). Caught at runtime; not practical to test.
* **Pure-"unreachable" defensive branches** (covered by
  `cargo-fuzz` but not tarpaulin):
  * `core/src/seal.rs:71` — `crypto_box encrypt` panic-to-error mapping;
    XSalsa20-Poly1305 can't actually fail at encrypt time.
  * `core/src/hkdf.rs:49` — `hk.expand` failure; the guard at line 41
    (`length <= MAX_OUTPUT_BYTES`) already gates this.

Re-running tarpaulin after `cargo fuzz run` on the four harnesses would
likely close these residuals, but tarpaulin doesn't merge fuzz coverage
today.

## Audit-grade run cost

On the Vultr dev box (1 GiB RAM + 2 GiB swap, ptrace through Docker):

* Core + stream with `--ignored`: ~70 minutes wall-clock.
* `frappuccino_crypto_core` binary dominates (~12 min) — 20 of the 58 core
  unit tests are Argon2id-bounded (~1.5 s each under ptrace).

CI-grade runs (~15 min) are possible if `--ignored` is dropped, at the
cost of dropping pin.rs + protocol.rs coverage to ~7 %.
