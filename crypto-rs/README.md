# crypto-rs — Frappuccino Rust crypto core

Pure-Rust port of `stream-crypto/` (Kotlin) exposed to Android via UniFFI and
to desktop via a CLI binary. The port is complete and live — these crates back
the production app. For the current architecture see
[`docs/ARCHITECTURE_TECHNIQUE_COMPLETE.md`](../docs/ARCHITECTURE_TECHNIQUE_COMPLETE.md) and
[`AUDIT_SCOPE_RUST.md`](../AUDIT_SCOPE_RUST.md). (The earlier `ARCHITECTURE_TECHNIQUE_26-05.md`
snapshot is superseded and archived under `OLD/`.) The original migration strategy
and sprint plan are archived under
[`docs/archive/PORT_RUST_OPTION_B.md`](../docs/archive/PORT_RUST_OPTION_B.md) and
[`docs/archive/PLAN_RUST_EXEC.md`](../docs/archive/PLAN_RUST_EXEC.md).

## Workspace layout

| Crate | Purpose | Sprint introducing it |
|---|---|---|
| `core/` | BIP-39, identity derivation, ratchet, PIN store, secure memory | S1–S5 |
| `stream/` | STRM blob format, server V2 client | S6–S7 |
| `ffi/` | UniFFI surface for Android Kotlin bindings | S0 (smoke), S8 (full API) |
| `cli/` | Desktop CLI binary `frappuccino-cli` | S9 |

The full crypto stack is implemented across these crates (the "Sprint" column
is historical, from the original port plan). Kotlin↔Rust byte-parity is enforced
by the parity tests under `core/tests/`.

## Prerequisites

Install once per dev environment:

```bash
# 1. Rust toolchain — pinned to 1.88.0 by rust-toolchain.toml (auto-selected
#    on first `cd` into crypto-rs). Install rustup if you don't have it:
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# 2. cargo-ndk for Android cross-compilation
cargo install cargo-ndk

# 3. Code quality gates
cargo install cargo-deny cargo-audit

# 4. (S9+) fuzzing
cargo install cargo-fuzz
```

Android-specific:

```bash
# Install NDK r26+ via Android Studio → SDK Manager → SDK Tools → NDK (side by side)
# Then export:
export ANDROID_NDK_HOME="$HOME/AppData/Local/Android/Sdk/ndk/26.2.11394342"
# Or equivalent on macOS/Linux.
```

## Building

```bash
# Host build (Linux/macOS/Windows) — fast iteration, runs tests
cargo build --workspace
cargo test --workspace
cargo clippy --all-targets -- -D warnings
cargo fmt --all -- --check
cargo deny check

# Android build (produces .so per ABI + Kotlin bindings)
./build-android.sh
# Or for a single ABI during dev:
TARGETS=arm64-v8a ./build-android.sh
```

The Android build drops `.so` files into `../mobile/src/main/jniLibs/<abi>/`
and Kotlin bindings into `../mobile/build/generated/source/uniffi/...`.

## Testing against the Kotlin reference

Parity vectors live in `parity-vectors/` and are produced by
`stream-crypto/src/androidTest/.../ParityVectorsDumper.kt`.

```bash
# After pulling fresh vectors:
cargo test -p frappuccino-crypto-core --test parity_bip39
```

See [`docs/archive/PLAN_RUST_EXEC.md`](../docs/archive/PLAN_RUST_EXEC.md) §5 for the dumper and fixture format.

## Mutation testing (cargo-mutants)

Mutation testing injects small faults (flip a comparison, delete a line,
replace a return value) and checks the test suite actually CATCHES them. A
*surviving* mutant marks a behaviour the tests don't pin down — a real gap
that line coverage hides. The audit goal is to raise the caught/total ratio.

```bash
cargo install cargo-mutants --locked            # one-time
cargo mutants                                    # full core + stream sweep
cargo mutants -f stream/src/header.rs            # one trust-boundary at a time
cargo mutants --in-diff <(git diff origin/main)  # only a PR's changed lines
```

Config (per-mutant timeout, `exclude_globs` for ffi/cli/fuzz/tests) lives in
[`.cargo/mutants.toml`](.cargo/mutants.toml); CI runs a weekly + manual sweep
([`.github/workflows/mutants.yml`](../.github/workflows/mutants.yml)). Use
`--no-shuffle` for run-to-run comparability.

**Baseline 2026-06-05 → gaps closed 2026-06-06.** Two trust-boundary parsers
on the untrusted-ciphertext path were swept and their gaps closed (ROADMAP
8.4.1 / 8.4.4):

- `stream/src/decrypt.rs`: **67 / 67 viable caught (100%)** after
  `tests/decrypt_boundaries.rs` (was 56/67 — 11 survivors sat at the `±1`
  edges of the length / cap / range checks; `decrypt_malformed.rs` only tested
  values far from each limit).
- `stream/src/header.rs`: **48 / 49 viable caught (98%)** after
  `tests/header_boundaries.rs` (was 39/49 — the three gaps below). The one
  remaining survivor is a **provably-equivalent** mutant: `be_u16`'s `|`→`^`,
  where `hi << 8` (bits 8..16) and `lo` (bits 0..8) occupy disjoint ranges, so
  OR and XOR are identical for every input and no test can distinguish them.

The original three header gaps — multi-recipient grants untested
(`grant_count > 0` never parsed, so `grant_count * GRANT_ENTRY_SIZE` and
`be_u16`'s high byte were unverified), the `header_end` off-by-one (and the
unasserted `need:` field of `TruncatedWithGrants`), and unpinned chunk-size
constants — are now pinned by the boundary fixtures. See
[`../docs/methodologie-securite-code.md`](../docs/methodologie-securite-code.md)
and [`../docs/invariants-ratchet-verification.md`](../docs/invariants-ratchet-verification.md)
Part 3 for the audit-pass dashboard this feeds.

## Invariants (DO NOT CHANGE)

All constants below are contract between Kotlin and Rust implementations. Any
divergence breaks wire-compat with enrolled identities and archived streams.

| Constant | Value |
|---|---|
| BIP-39 PBKDF2 iterations | `2048` |
| BIP-39 seed length | `64 B` |
| HKDF context (identity) | `"stream.identity.ed25519.v1"` |
| HKDF context (encryption) | `"stream.encryption.x25519.v1"` |
| HKDF context (chain_0) | `"stream.ratchet.chain0.v2"` |
| Ratchet batch size | `50` |
| Ratchet blob V2 size | `4876 B` (4844 payload + 32 MAC) |
| Ratchet MAC HKDF ctx | `"frappuccino-v2-ratchet-blob-mac"` |
| Argon2id params | `m=256 MiB, t=4, p=1, taglen=32` |
| PinStore AAD | `"frappuccino-v2-pin-store-v1"` |

Canonical wire contract: [`stream/src/header.rs`](stream/src/header.rs) (the code is the contract — version-branched V1/V2/**V3**); prose overview in [`docs/ARCHITECTURE_TECHNIQUE_COMPLETE.md`](../docs/ARCHITECTURE_TECHNIQUE_COMPLETE.md). (The old `ARCHITECTURE_TECHNIQUE_26-05.md §4.2` described the **V2** format only — superseded, archived under `OLD/`.)
