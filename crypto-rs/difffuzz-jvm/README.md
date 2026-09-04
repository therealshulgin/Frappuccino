# difffuzz-jvm — Kotlin↔Rust differential-fuzz harness

ROADMAP **8.4 item 3**. Replays a corpus through the generated **UniFFI Kotlin
bindings** (Kotlin → JNA → Rust) and diffs each outcome against the reference
outcome the Rust side produced by calling the FFI functions directly.

There is no live Kotlin reference crypto (all crypto goes through UniFFI since
6.1.4), so this is a **boundary** differential: it exercises the marshalling
glue (`ByteArray`↔`Vec<u8>`, error→exception, the UniFFI codegen + JNA) — the
HIGH-severity surface flagged by the 8.1 audits — at desktop-JVM fuzz speed.
The desktop JVM uses the **same JNA codegen as Android**, so a divergence here
is a divergence on-device.

What a run proves:
- **match** → the marshalling preserved the result;
- **mismatch** → a Kotlin↔Rust glue bug;
- **`throw:` line** → a non-`FfiException` escaped the binding (glue bug);
- **JVM dies with no summary** → an uncaught Rust panic crossed the boundary
  (must be impossible — the workspace pins `panic = "unwind"`).

## Run

From the repo root (uses the Android project's `gradlew` for its Gradle 8.6):

```bash
cd crypto-rs

# 1. Build the host FFI cdylib (uniffi_frappuccino.dll/.so in target/debug).
cargo build -p frappuccino-crypto-ffi

# 2. Regenerate the Kotlin bindings (NOT committed — see .gitignore).
cargo run -p frappuccino-crypto-ffi --bin uniffi-bindgen -- \
  generate ffi/src/frappuccino.udl --language kotlin \
  --out-dir difffuzz-jvm/src/main/kotlin

# 3. Emit a corpus (deterministic; args: seed, cases-per-api).
cargo run -p frappuccino-cli --bin frappuccino-difffuzz-dump -- 0x5EED_2026 150 \
  > /tmp/difffuzz-corpus.jsonl

# 4. Replay it through the Kotlin bindings and diff.
../gradlew -p difffuzz-jvm run --args="/tmp/difffuzz-corpus.jsonl"
```

`build.gradle.kts` wires `jna.library.path` to `../target/debug` so JNA finds
the cdylib. Exit code is non-zero if any case mismatched.

## Scope (v1)

Deterministic, raw-bytes-in APIs (the untrusted-input → marshalling → Rust-parse
surface): `bip39_validate_fr`, `StreamIdentity.fromPublicKeys`→`readableFingerprint`,
`EphemeralRatchet.deserialize`→`serialize`, `pin_store_open`,
`ArchiveIdentity.fromMnemonic`. Randomised APIs (`strm_encrypt`) need a
round-trip oracle — a follow-up corpus mode. `pin_store_seal` used to be listed
here too; it left the FFI surface on 2026-09-03 (no caller ever crossed the
boundary for it, this harness included), so it can no longer be reached from
Kotlin at all. The Rust function stays and the corpus dumper still uses it to
BUILD the blob this harness then opens.

Baseline 2026-06-06: **759/759 matched** (seed `0x5EED_2026`, 150/api).
