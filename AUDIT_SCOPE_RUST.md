# AUDIT_SCOPE_RUST — Frappuccino crypto core

> Scope document for an external cryptographic audit of the Frappuccino V2
> Rust crypto stack. Written by the dev team as the entry brief for the
> auditor — read this first.
>
> **Repo** : the public repository, `github.com/therealshulgin/Frappuccino`.
> Read this against that repository's tree, not against a pinned SHA. This brief
> used to pin `86cd387` on a private branch: a commit no external reader can
> resolve, which is worse than no reference at all.
> **Last reviewed against the code** : 2026-09-03.

---

## 1. Context

Frappuccino is an Android streaming app for activists and journalists — a
fork of Tella FOSS, re-engineered around an Algorand-inspired V2 design:

* Identities are derived from a **12-word French BIP-39** mnemonic. What the
  device actually holds is narrower than that sentence used to say: the
  long-term Ed25519 key is one-shot (`EnrollmentKit`), wiped on drop once
  enrollment is signed (`core/src/identity.rs`); the X25519 key is re-derived
  from the phrase on demand (`ArchiveIdentity::from_mnemonic`). What persists on
  the device is the **public** pair (`StreamIdentity`) plus the ephemeral ratchet
  (batches of 50 Ed25519 slots, of which 49 are usable — the last is reserved so
  a rotation is always possible, `core/src/ratchet.rs`).
* The device **cannot decrypt its own past streams** — only the paper
  phrase (archive mode) recovers the session keys.
* A **self-signed TLS relay** with SPKI-pinning ferries blobs between the
  phone and a future recipient. The server is a blind relay; it never sees
  plaintext.
* License Apache-2.0 (inherited from Tella FOSS; see `LICENSE`). A move to AGPL
  is a publication decision, not the current state of the tree.

This document scopes the **Rust cryptographic layer** only. The Kotlin UI,
the Python relay, and the Tella FOSS legacy code are out of scope.

See `docs/ARCHITECTURE_TECHNIQUE_COMPLETE.md` for the current architecture,
and `crypto-rs/stream/src/header.rs` for the authoritative wire contract.
Where a document and the code disagree, the code is authoritative.

## 2. Scope

### In scope — Rust workspace at `crypto-rs/`

| Crate                       | Role                                               |
|-----------------------------|----------------------------------------------------|
| `crypto-rs/core/`           | BIP-39, HKDF, identities, ratchet, PIN store, seal, signature domains, provenance, report keys |
| `crypto-rs/stream/`         | STRM blob format, relay client + TLS pin, QUIC transport, Salamander obfuscation, path safety, secure delete |
| `crypto-rs/ffi/`            | `UniFFI` surface exposed to Kotlin                 |
| `crypto-rs/cli/`            | Offline tooling (identity, decrypt, parity, probe, archive fetch, provenance verify) |
| `crypto-rs/obfs-proxy/`     | Server-side Salamander de-obfuscation of hostile UDP |
| `crypto-rs/quic-spike/`     | Throwaway QUIC spike; a workspace member, **not** shipped in the `.so` |
| `crypto-rs/fuzz/`           | `cargo-fuzz` harnesses (**not** a workspace member) |

The compiled `.so` ships inside the Android APK under
`mobile/src/main/jniLibs/<abi>/libuniffi_frappuccino.so`. All crypto
primitives used by the app are reachable through these crates, with **one
named exception**: `recordingIdFor` computes a SHA-256 in Kotlin, truncated to
16 bytes, and feeds it to the Rust provenance derivation
(`StreamRecordingService.kt`, `ArchiveDownloader.kt`, then `ffi/src/lib.rs`).
It is a hash of a session id, not a key operation, but it is a wire-affecting
derivation computed outside Rust and duplicated in two Kotlin files, so it is
named rather than covered by a blanket claim. Two more Kotlin-side uses of
`java.security` exist and are named for the same reason: `generateSessionId`
draws the 16 bytes from `SecureRandom` (so the input to the derivation above is
itself produced outside Rust), and `readableFingerprint` computes a SHA-256 over
the **public** Ed25519 key for the string the user reads back to check their
phrase, duplicated in `StreamIdentity.kt` and `ArchiveIdentity.kt`. Device
storage uses `EncryptedSharedPreferences` (AES-256-GCM / AES-SIV), which is
Android's, not ours.

The accurate claim, and the one to audit against, is narrower than "no
Kotlin-side cryptography": **no key derivation, no content encryption and no
signature happens outside Rust**, and there is no hidden JNI path (post S8c.5,
2026-04-17).

### Explicitly out of scope

* Tella FOSS legacy vault code (`mobile/src/main/java/rs/readahead/…`).
  Tracked for deletion under point 7.4 of `ROADMAP.md` (Phase 5 itself closed
  2026-05-09). Any dead code found
  in transit is welcome as a PR; not part of this audit's engagement.
* The Python relay at `server/`. Audits the V2 endpoints as a black box
  — the contract is documented in §5 below but the implementation is not
  scoped here.
* The UniFFI-generated Kotlin bindings (`stream-crypto/build/generated/…`).
  Regenerated deterministically from the UDL at every build.
* CameraX wiring, UI, Gradle config.

## 3. Threat model

| Capability                                        | Must protect ?       | How                                                        |
|---------------------------------------------------|----------------------|------------------------------------------------------------|
| Passive network observer                          | Yes                  | TLS 1.2+, SPKI pin, XChaCha20-Poly1305 on every blob       |
| Active MITM with valid CA chain                   | Yes                  | SPKI pin (pin mismatch ⇒ reject before cert chain check)   |
| Server operator reads blobs                       | Yes (confidentiality)| `crypto_box_seal` → only archive key x25519_sk unseals     |
| Server operator tampers with blobs                | Yes                  | XChaCha20-Poly1305 tag, AAD binds header + chunk_count v2  |
| Device seizure (PIN known)                        | No                   | App unlocks; this is the explicit DI path                  |
| Device seizure (PIN unknown)                      | Partial              | Argon2id 256 MiB × 4 gates the sealed ratchet; ≠ phrase    |
| Device seizure (wipe button mashed)               | Yes                  | Ratchet file wiped; archive recovers via paper phrase only |
| Attacker replays a captured verify signature      | Yes                  | Nonce atomic-pop + ±30 s timestamp skew (S9-pre-audit pt2) |
| Attacker truncates a CHUNKED blob at rest         | Yes                  | AAD binds `chunk_count` (STRM CHUNKED, V2/V3)             |
| Attacker forges a self-addressed STRM blob        | **Partial** — §6.1   | `crypto_box_seal` gates recipient-side; V3 carries no author at rest (field removed) |
| Cold-boot RAM dump of locked device               | Best-effort          | `zeroize` on secrets, `mlock` on the `LockedSecret` types only; the ratchet's 50 private keys are a bare array, zeroized on drop but never `mlock`ed (scoped decision: Android swaps to zram, not to disk). FLAG_SECURE on screens |
| JIT retention of wiped secrets                    | Best-effort          | `zeroize` at the call sites **and** a hand-written `impl Drop` on each secret-bearing type (`EphemeralRatchet`, `EnrollmentKit`, `SecretBytes`, `LockedSecret`); the discipline is real, but it is written by hand, with exactly one `#[derive(ZeroizeOnDrop)]` in the tree (`core/src/bip39.rs`). Audit the `Drop` impls, not the derive |
| Compiler/linker inserts wipe-avoiding optimisation| Best-effort          | `zeroize` with compiler fences; gates via cargo-fuzz       |

The V2 design explicitly does **not** try to protect against an attacker
who has both the device and the PIN. Beyond that, every decryption path
should require either the ratchet (device-local, forward-secret) or the
paper phrase (archive mode).

## 4. Cryptographic invariants

Drift on any of these breaks byte-level compatibility with enrolled
identities on production devices. `crypto-rs/stream/src/header.rs` (the wire
contract — version-branched V1/V2/**V3**) is the canonical reference — the
historical `OLD/ARCHITECTURE_TECHNIQUE_26-05.md §4.2` (V2-only snapshot) and
`docs/archive/PLAN_RUST_EXEC.md §1` are kept for history; the summary below is
what the auditor should spot-check.

### 4.1 BIP-39

* PBKDF2-HMAC-SHA512, 2048 iterations, salt = `"mnemonic" ‖ passphrase`,
  output 64 bytes.
* French wordlist (2048 entries, NFD-encoded). `normalize_word` throws
  on unknown words — there is no silent fuzzy match.
* `mnemonic_to_seed` is a pure function; no RNG involved.

Fixtures: `crypto-rs/parity-vectors/bip39/seed.json` (12 seeds across
4 mnemonic × 3 passphrase combos).

### 4.2 HKDF-SHA256 contexts

Exact UTF-8 bytes — **never change these strings**:

* `"stream.identity.ed25519.v1"` — Ed25519 seed
* `"stream.encryption.x25519.v1"` — X25519 seed
* `"stream.ratchet.chain0.v2"`  — initial ratchet chain
* `"frappuccino-v2-ratchet-batch-seeds"` — 50 × 32-byte batch seeds
* `"frappuccino-v2-ratchet-next-chain"`  — chain_{N+1}
* `"frappuccino-v2-ratchet-blob-mac"`     — HMAC key for the V2 blob
* `"stream.provenance.ed25519.v1"`       — provenance signer seed
* `"stream.provenance.ots-salt.v1"`      — per-recording OTS blinding salt
* `"stream.report.master.v1"`            — report master secret
* `"stream.report.key.v1"`               — per-report capability key `R_n`
* `"stream.report.id.v1"`                — domain prefix hashed **directly by
  SHA-256**, not an HKDF context: `report_id = SHA-256(ctx ‖ report_pk)[..16]`
* `"stream.report.directory.v1"`         — directory report
* `"stream.report.directory.entry.v1"`   — directory entry names

### 4.3 Identity derivation

* Ed25519 seed → `SigningKey` via RFC 8032.
* X25519 seed → libsodium-style `sk = SHA-512(seed)[..32]` + clamping.
  **Not** Ed→X conversion. Validated against Kotlin enrollment identities
  in production.

Fixtures: `crypto-rs/parity-vectors/identity/derive.json`.

### 4.4 Ephemeral ratchet (V2)

* Batch size 50. Each slot = 32 B pk + 64 B sk (libsodium layout: seed ‖ pk).
* Serialized blob **4876 bytes** : `version(1) ‖ batch_number(BE u32) ‖ consumed_mask(7) ‖ next_chain_key(32) ‖ 50 × (pk ‖ sk) ‖ HMAC-SHA256(32)`.
* `consumed_mask` LSB = slot 0 (little-endian bit order inside the mask).
* V1 legacy blobs (4844 bytes, no MAC) are **REJECTED** on read since the RT-03
  fix (`CryptoError::InvalidBlob`, `core/src/ratchet.rs`): they predate the MAC,
  so accepting one would accept an unauthenticated ratchet. This document, and
  the UDL comment, both said "accepted on read, auto-migrated to" — the code has
  contradicted that since RT-03, and an architecture review left the question
  open. It is settled here against the code. Historically they were migrated to
  V2 on next serialize.
* HMAC key = `HKDF(chain_key, CTX_BLOB_MAC, 32)`.

### 4.5 PIN-protected store

* Argon2id: `m = 262 144 KiB (256 MiB), t = 4, p = 1, tag = 32 B`.
* AEAD: XChaCha20-Poly1305-IETF.
* AAD: the fixed byte string `"frappuccino-v2-pin-store-v1"`.
* Layout: `version(1)=0x01 ‖ salt(16) ‖ nonce(24) ‖ ct+tag`.
* Wrong PIN and tampered blob both yield `CryptoError::WrongPin` — the
  two are indistinguishable by design.

### 4.6 STRM blob

* Magic `"STRM"`, **VERSION_CURRENT = VERSION_V3 = 0x03** (current Rust
  encoder). Legacy read-only: **VERSION_V1 = 0x01** (Kotlin legacy SINGLE),
  **VERSION_V2 = 0x02** (previous Rust encoder).
* Header (V3, current): `MAGIC(4) ‖ VERSION(1) ‖ sealed_session_key(80) ‖ grant_count(BE u16) = 0`.
  `grant_count` is a reserved field: the encoder always writes 0 and the decoder
  **rejects** any blob declaring a grant (`GrantsNotSupported`) rather than walking
  the entries, so the multi-recipient section is not a parsing surface. Kani proves
  no accepted blob carries one.
  **No `author_ed25519_pk` at rest** — the 32-byte author key of V1/V2 was
  removed in V3 (F-C1/WP-A); a relay-disk seizure can no longer map
  `report_id → identity` from the blob bytes alone (the motto). Legacy V1/V2
  inserted `author_ed25519_pk(32)` after the version byte (read-only; the
  current encoder never emits it). Source: `crypto-rs/stream/src/header.rs`, symbols `VERSION_V1` / `VERSION_V2` /
  `VERSION_V3` / `VERSION_CURRENT` and `parse_header` (cited by name: line ranges
  in this document have already rotted once).
* Sealed envelope: `crypto_box_seal` = ephemeral X25519 pk(32) + Blake2b
  nonce + XSalsa20-Poly1305 ciphertext(48) = 80 bytes.
* MODE_SINGLE (0x01): `nonce(24) ‖ ct+tag`. AAD = header.
* MODE_CHUNKED (0x02): `nonce_prefix(20) ‖ chunk_count(BE u32) ‖ (u32_len ‖ nonce(24) ‖ ct+tag)*`.
  * V1 AAD = header (**vulnerable to silent truncation**, legacy only).
  * V2/V3 AAD = `header ‖ MODE ‖ nonce_prefix ‖ chunk_count_BE_u32` — binds
    chunk count so truncation is rejected.
* Encoder always writes V3. The decoder accepts **V3 only** in the shipped
  library: V1/V2 live behind the `legacy-strm` Cargo feature, which only
  `frappuccino-cli` enables, so a witness reads an older archive on a desktop
  while the Android `.so` carries no legacy parsing surface. Cargo unifies
  features across a build graph, so the isolation is checked on the artefact
  rather than assumed from the build command: `LEGACY_STRM_MARKER` is linked in
  only under the feature, and `build-android.sh` plus the Gradle
  `checkRustSoFresh` gate both refuse a `.so` containing it.

### 4.7 V2 relay protocol

* Endpoint base: `https://relay.shake-document-protect.org:8443`. The migration
  off the raw IP happened 2026-06-27; the Rust host-check requires this exact
  name (`PINNED_HOST`, `crypto-rs/stream/src/pin.rs`), so the SNI now goes out in
  clear on the control plane. The certificate is still self-signed: the Let's
  Encrypt cutover has not happened.
* TLS: pinned self-signed cert. **Three** SPKI SHA-256 pins are embedded and
  accepted as a union (`PinnedCertVerifier::new`, `pin.rs`). Probe the relay and
  you will get `PIN_NEXT_B64`, which is the **second** constant declared in `pin.rs` but is
  listed **first** below, because it is the live one. Read the two orders separately:
  * `AmIDSglLpedq4J2LANgQ6s5+uKFEuuaNSGLjHOZkhok=` — **the cert the relay
    actually serves today.** Pre-seeded 2026-06-27 as a break-glass key, it is
    the only one with a dual SAN (domain + IP), so it is the only one that can
    pass host-name verification under the pinned domain. Its private half lives
    on the relay.
  * `QnGK0KvRC1vt2C4rrxwHIj0/pUbogVtTCesBK3sZXKY=` — the historical primary
    (rotated 2026-05-14). Its cert has an **IP-only SAN**, so since the domain
    migration it can no longer be presented under `PINNED_HOST`. Still pinned,
    key backed up on the relay.
  * `MUb4HHlUfj3c6cCQYuQMeeiWkcHga46OCZqVLuY9eCk=` — dormant, domain-only SAN,
    private half kept **off-host and never placed on the relay**: the recovery
    path for a seized relay, since a seizure compromises the two keys above
    together.

  The pin this document used to name (`mGGCWQ…`) was two rotations behind, not
  one: it was replaced in May, and its successor (`zgsMr0…`) is the one `pin.rs`
  records as dead with the old VM.
* The certificate itself is **not** in the shipped binary, and that is the
  point: the three `include_str!` of the PEM files in `pin.rs` are under
  `#[cfg(test)]` and exist only so the tests can check a real certificate against
  its pin. What ships is the three SPKI fingerprints. The PEMs live at
  `crypto-rs/stream/assets/frappuccino_ca*.crt` and, for the Android trust
  anchors, `mobile/src/main/res/raw/` (must match byte-for-byte). This entry read
  "cert embedded in-binary" until 2026-09-04.
* `/auth/challenge` → `{nonce, timestamp}`. Client signs
  `0x01 ‖ nonce_bytes ‖ timestamp_BE_u64` (**41** bytes) via the ratchet. The
  leading byte is the domain-separation tag (audit R-C-1); every signing context
  in the system has one, and the relay mirrors them byte-identically. The
  complete frozen set of eight tags, including the reserved-but-retired 0x04,
  0x05 and 0x06, lives in `crypto-rs/core/src/signature_domain.rs`.
* `/auth/v2/verify` enforces `|now - timestamp| ≤ 30 s` + atomic
  nonce pop (S9-pre-audit pt2, post-audit replay window = 30 s worst-case).

### 4.8 STRM envelope

`crypto_box_seal` = pure-Rust `crypto_box` + `blake2`. Ephemeral key
generated per-seal; nonce deterministic = `Blake2b(epk ‖ pk, 24)`. No
RNG state shared between blobs.

## 5. External contracts

These are the contracts the auditor should treat as **external** — they
are enforced by tests, not by the Rust code alone. Breaking them would
orphan every device currently in the field.

* **BIP-39 language**: French. Switching to English or mixing wordlists
  orphans the installed base.
* **Kotlin binding stability**: the UDL surface
  (`crypto-rs/ffi/src/frappuccino.udl`) is the ABI between Rust and
  Kotlin. Adding fields is fine; renaming or reordering breaks UniFFI
  bindings. Never ship a Rust change that regenerates bindings with
  different field names without a coordinated Kotlin-side update.
* **Server wire format**: fields in `VerifyBody`, `EnrollBody`,
  `RotateBody` match the Python server's Pydantic models byte-for-byte
  (`server/app/models.py`). Parity fixtures under
  `crypto-rs/parity-vectors/protocol/` lock this down.

## 6. Known issues deferred to post-audit

These are documented so the auditor can flag any they consider blocking
for their engagement.

### 6.1 STRM blob authorship is not signed — RESOLVED in V3 (field removed)

**Resolution (F-C1 / WP-A, pre-publication)**: the `author_ed25519_pk`
field was **removed** from the STRM header in V3 (`VERSION_CURRENT =
0x03`). There is therefore no longer any authorship — signed or not — at
rest. The field was dead (never used to decrypt, no consumer anywhere),
so this is a pure removal, not a feature loss.

**Residual (unchanged, by design)**: a blind relay can still fabricate
self-addressed blobs (it knows the recipient's x25519 pk, published at
enrollment) — but they now carry **no identity** at all. The practical
impact is "spam in the archive," not data compromise; confidentiality is
preserved (`crypto_box_seal`).

**Status**: the deferred "sign the author" question is moot — there is no
author field left to sign. Legacy V1/V2 blobs retain the field read-only.

### 6.2 Ratchet per-batch salt

**Current state**: the ratchet blob's HMAC key is derived from
`chain_N+1` (the chain *after* the batch). Two devices that accidentally
share a chain (e.g. a backup restore followed by concurrent use on the
original device) would produce colliding MACs.

**Impact**: unlikely outside a deliberate backup/restore race. Would
allow an attacker with both ratchet blobs to notice they share a chain,
not to recover a secret.

**Why deferred**: the hardening is a salt injection step. Low reward
for the format churn unless the auditor sees a real scenario.

### 6.3 Batch chain TTL

**Current state**: the server has no upper bound on how long a batch
can stay active. If a device falls off the network for a year, it comes
back with the same batch and keeps signing with it.

**Impact**: forward-secrecy window widens indefinitely for that device.

**Why deferred**: implementable server-side without a Rust change. Of the two
Python-side items it was queued behind, one landed and one did not: JWT
revocation is live (`server/app/jwt_blacklist.py` + `POST /auth/v2/logout`),
while the Redis nonce cache was never built — the nonce cache is still a
process-local dict persisted to JSON (`server/app/auth.py`), which is what the
atomic-pop replay defence in §5 rests on. The batch-TTL gap itself is still
open.

## 7. Tooling and hygiene gates

Every merge to `main` must pass:

* `cargo test --workspace --all-features`: 254 passing, 3 `#[ignore]`d (the e2e trio
  needs a live relay; run them with `-- --ignored`). Measured 2026-09-04. The count moves
  with the feature set, so treat the command as the oracle rather than this number.
  `#[ignore]` e2e tests are run manually before a deploy.
* **Machine-checked proofs**, replayed by `.github/workflows/proofs.yml` on
  changes to `crypto-rs/` (not on every merge — check the workflow's triggers
  before relying on that). They are the most verifiable thing in this repository,
  which is why they belong in the entry brief rather than an appendix:
  * **Kani** (bounded model checking) — 5 harnesses over the real parser code,
    `crypto-rs/run-kani.sh`, which asserts the harness *count* so a proof cannot
    quietly stop existing.
  * **Tamarin** (Dolev-Yao) — `crypto-rs/core/proofs/RatchetProtocol.spthy`.
  * **TLA+/TLC** — `crypto-rs/core/proofs/EphemeralRatchet.tla`, including the
    `RotationAlwaysPossible` invariant behind the reserved slot.
* `cargo clippy --workspace --all-targets -- -D warnings` — zero warnings.
* `cargo fmt --check` — zero diff.
* `cargo deny check` — advisory + license allowlist (`crypto-rs/deny.toml`).

Additional gates for the audit window:

* **Fuzzing** : `crypto-rs/fuzz/` runs four `cargo-fuzz` targets
  (`fuzz_decrypt_blob`, `fuzz_parse_strm_header`,
  `fuzz_ratchet_deserialize`, `fuzz_pin_store_open`). Target 100M
  iterations on the non-Argon2id harnesses and ≥ 4 h wall-time on
  `fuzz_pin_store_open`. Any crash is a blocker. Run instructions in
  `crypto-rs/fuzz/README.md`. The smoke test (2000–30 runs per target) is replayable from that README; the
  commit it used to be pinned to is on a private branch and unresolvable.
* **Coverage** : **90.39 %** (922 / 1020) on `core/` + `stream/`, measured by
  `cargo-tarpaulin 0.34.0` with the `#[ignore]` e2e tests included. Treat this as
  an **April 2026 snapshot, not revalidated**: it predates roughly 135 of the 260
  tests that exist today, and it was anchored to a private commit. Re-measure
  before relying on it. Per-file breakdown and known gaps in
  `crypto-rs/coverage/README.md`; the committed HTML report at
  `crypto-rs/coverage/tarpaulin-report.html` is the authoritative
  artifact. FFI wrappers and the CLI are glue and not counted.
* **CLI** : `frappuccino-cli` (`crypto-rs/cli/`) is the standalone desktop tool,
  now six subcommands: `identity`, `decrypt`, `parity-test`, `protocol-probe`,
  `fetch-archive`, `verify-provenance` — shipping it without Python cuts the
  auditor's dependency surface.
* **No `unsafe`** outside of `crypto-rs/core/src/secret.rs` (memsec mlock
  wrapper). Every `unsafe` block has a `// SAFETY:` comment documenting
  the invariants it requires.

## 8. Test matrix

| Layer                | Harness                                                  |
|----------------------|----------------------------------------------------------|
| BIP-39               | `core/src/bip39.rs` unit + `parity_bip39` against Kotlin |
| Identity             | `core/src/identity.rs` unit + `parity_identity` fixtures |
| HKDF                 | `core/src/hkdf.rs` RFC 5869 test vectors + fixtures      |
| PIN store            | `core/src/pin_store.rs` + `parity_pin_store` + `pin_store_errors` |
| Ratchet              | `core/src/ratchet.rs` + `parity_ratchet` (V1 + V2) + `ratchet_errors` |
| `crypto_box_seal`    | `core/src/seal.rs` unit (roundtrip + tamper)             |
| STRM blob            | `stream/tests/parity_strm.rs` + `decrypt_malformed` + `header_errors` |
| Server protocol      | `stream/tests/parity_protocol.rs` byte-exact request bodies    |
| Relay live E2E       | `stream/tests/e2e_protocol.rs` `#[ignore]` against Vultr       |
| UDL surface          | `ffi/src/lib.rs` unit tests — NOT one per exposed function, the coverage is partial and deliberately so; read the UDL for the surface and this file for what is exercised |
| Fuzz (libfuzzer)     | `crypto-rs/fuzz/` — 4 targets, smoke-tested on Vultr           |
| Python server        | `server/tests/` — 98 pytest green (auth KAT, rotation oracle + replay, relay-blind reports, write-once, route surface). Three files are excluded from collection and run by hand as standalone scripts (`conftest.py` names them); known gap: `POST /auth/v2/verify` is exercised only by one of those |
| Device smoke         | `mobile/src/androidTestRust/.../RustSmokeTest.kt` (Seeker)        |

## 9. Pointers for the auditor

* **Start here** : `docs/ARCHITECTURE_TECHNIQUE_COMPLETE.md` (current
  architecture) → `crypto-rs/core/src/identity.rs` (central data types) →
  `crypto-rs/stream/src/decrypt.rs` (integrates everything).
* **Threat model in code** : `crypto-rs/stream/src/pin.rs` for the TLS pin logic
  (`PinnedCertVerifier`, the three pins, the host check); `protocol.rs` only
  imports it; `crypto-rs/core/src/secret.rs` for the
  mlock-protected secret types.
* **Cross-language parity** : the `parity-vectors/` tree mirrors the
  pre-S8c.5 Kotlin reference. Everything there is frozen; any change
  must be accompanied by a documented migration.
* **Hardening history** : deliberately not a commit list any more. The SHAs this
  section used to cite are all on a private branch and unresolvable from the
  public repository, and one of them pointed at a review document
  (`STREAM_REVIEW_CHATGPT_CRITIQUE.md`) that is not in the tree at all. Read the
  history from the published repository instead; `ROADMAP.md` is the dated
  narrative and `docs/ARCHITECTURE_TECHNIQUE_COMPLETE.md` the current state.

## 10. How to report findings

Format expected in the final report:

```
FINDING-<ID>
Severity: CRITICAL | HIGH | MEDIUM | LOW | INFO
Title: <short>
Location: <path>:<line> (git SHA)
Description: …
Reproduction: …
Recommendation: …
```

We'll triage each finding into:

* **Blocker** — fix before any user ships (halts rollout).
* **Major** — fix before publication (tracked at point 8.2.5 of `ROADMAP.md`;
  there is no phase 8.7).
* **Documented** — acknowledged, mitigated by design, not fixed. Captured
  here in §6 with the auditor's rationale.

---

*End of scope document. Contact : see the top of `README.md`. There is no
`CODEOWNERS` file in this repository; this line used to point at one.*
