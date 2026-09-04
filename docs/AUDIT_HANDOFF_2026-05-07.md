# Audit handoff — Frappuccino V2 (S9 audit-ready snapshot)

**Date** : 2026-05-07
**Branch** : `main` (merged from `claude/xenodochial-morse`)
**HEAD** : `4928220`
**Author** : therealshulgin, solo dev
**Contact for the audit team** : therealshulgin directly via email.

> ⚠️ **Ceci est un instantané du 2026-05-07 ; son corps n'est pas réécrit.** Il n'est plus
> le seul briefing nécessaire : les trois canons (`ROADMAP.md`,
> `docs/ARCHITECTURE_TECHNIQUE_COMPLETE.md`, `docs/GUIDE_AUDITEUR.md`) et le code
> l'emportent sur lui. Quatre points où le suivre à la lettre égarerait :
>
> - **Endpoints V2** : la route `status` a été **débranchée** ; `auth_v2.py` ne déclare
>   plus que `enroll`, `verify`, `rotate-batch` et `logout`. Le module `invite.py` listé
>   dans l'arborescence n'existe plus non plus.
> - **ABI natives** : trois ABI sont construites et empaquetées par défaut
>   (`arm64-v8a`, `armeabi-v7a`, `x86_64`), et le gate de build les vérifie toutes les
>   trois. Le « seul arm64-v8a » du §Out-of-scope annonce le tiers du périmètre réel.
> - **Deux renvois morts** dans la table « quoi lire en premier » :
>   `ARCHITECTURE_TECHNIQUE.md` a été archivé (lire `_COMPLETE` à la place) et
>   `BLUE_TEAM_COUNTERAUDIT_2026-04-21.md` n'a pas été conservé au dépôt.
> - **Volumétrie** : `AUDIT_SCOPE_RUST.md` a grossi depuis les « 336 lignes » annoncées.

---

## 1. What you're looking at

Frappuccino is a fork of Tella FOSS (Horizontal.org) re-purposed as a
**streaming video documentation tool for activists and journalists** in
authoritarian or seizure-risk contexts. The threat model is one where the
**device gets confiscated** with the user under coercion — so the design
deliberately makes past content unrecoverable from the device alone. Only
the **paper BIP-39 phrase** can re-derive the archive identity to read
historical streams.

V2 is the protocol generation we want you to audit. The legacy Tella V1
crypto stack has been migrated out (port to Rust completed in S8c.5), but
the legacy code still lives in-tree under non-audited paths — see §11.

This document gets you from `git clone` to "I know what to attack" in 30
minutes.

**Precedence, corrected 2026-09-04.** This brief long carried the sentence
"if anything in another file disagrees with this brief, this brief wins". That
was true on 2026-05-07 and is not any more: this is a dated snapshot, and it has
been overtaken on several points (STRM V3, a reduced FFI surface, the relay's
routes, the reserved last ratchet slot). **Where it disagrees with the current
canons, the canons win**: `docs/ARCHITECTURE_TECHNIQUE_COMPLETE.md` for the
architecture, `AUDIT_SCOPE_RUST.md` for the scope, and **the code above all**.
Use this brief for orientation and intent, not as an arbiter.

---

## 2. Repository layout (what to read)

| Path | Role | Read first? |
|---|---|---|
| `AUDIT_SCOPE_RUST.md` | **Authoritative scope + invariants + threat model** (336 lines, 10 sections) | YES |
| `ARCHITECTURE_V2.md` | High-level V2 design (16 sections, model + flows + cartography) | YES |
| `CRYPTOGRAPHIE.md` | Crypto reference (BIP-39, HKDF contexts, STRM blob format, sealed envelopes) | YES |
| `ARCHITECTURE_TECHNIQUE.md` | Implementation details (modules, classes, interactions) | If you need detail |
| `ROADMAP.md` | Project plan with finding remediation phases linearly numbered (this audit = Phase 8.2.2) | Skim — context only |
| `BLUE_TEAM_COUNTERAUDIT_2026-04-21.md` | Triage of the four pre-audit AI passes (15 findings → 14 actionable, 1 stale) | Skim — informs §8 below |
| `docs/UI_FINGERPRINT_AUDIT_2026-05-07.md` | Closes the §6.1 "STRM blob authorship not signed" caveat | If you go after that surface |
| `.semgrep/AUDIT_2026-05-07.md` | Manual semgrep audit on the RT-09 PIN-tracker pattern | If you go after that surface |
| `docs/archive/` | Superseded planning docs — historical only, do not trust | Skip |

---

## 3. In-scope crates / modules

**Audit these. Everything else is out of scope unless it touches one of them.**

### 3.1 Rust workspace `crypto-rs/` (100% of the crypto)

```
crypto-rs/
├── core/        # BIP-39, HKDF, identity, ratchet, pin_store, secret/LockedSecret
├── stream/      # STRM blob encrypt/decrypt + V2 server client + cert pinning
├── ffi/         # UniFFI surface to Kotlin (frappuccino.udl + lib.rs)
├── cli/         # frappuccino-cli + frappuccino-migrate-v1-ratchet
└── fuzz/        # 4 cargo-fuzz targets (out-of-workspace nightly)
```

Pinned exact versions per `Rust_guidelines.md` (workspace-level Cargo.toml).
Rust 1.88.0 toolchain. `clippy -D warnings` clean, `cargo fmt --check`
clean. **Zero `unsafe` outside the UniFFI scaffold** (which we explicitly
exclude — generated code from a third party we don't control).

### 3.2 Python server `server/app/`

```
server/app/
├── auth.py                 # challenge/verify/JWT, persistent nonce cache
├── auth_v2.py              # V2 endpoints (enroll, verify, rotate-batch, status)
├── ratchet_registry.py     # thread-safe in-memory + JSON persistence
├── invite.py, models.py    # supporting code
├── routes/                 # FastAPI route handlers
└── storage.py              # MinIO client wrapper
```

FastAPI + uvicorn `--workers 1` (RT-12 — the nonce cache is in-process).
MinIO for blob storage. JWT for post-auth API access.

### 3.3 Kotlin upload manager `stream-crypto/` + `mobile/.../activity/`

Thin wrappers over the Rust UniFFI bindings. Read-relevant surface:
- `stream-crypto/.../upload/StreamUploadManager.kt` — orchestrates
  enrollment / unlock / sign / rotate / fast-reseal.
- `mobile/.../views/activity/PinUnlockActivity.kt` — only legitimate
  call-site of `PinAttemptTracker.recordFailure`.
- `mobile/.../views/activity/StreamRecordingService.kt` — coordinator
  for recording + chunk encryption + upload.
- `mobile/.../util/jobs/ChunkUploadWorker.kt` — WorkManager-backed
  upload retry loop.

---

## 4. Threat model (TL;DR — full version in `AUDIT_SCOPE_RUST §3`)

| Attacker capability | In scope? | Mitigation |
|---|---|---|
| Network MITM (hostile WiFi, ISP, BGP hijack) | YES | TLS + SPKI pin + (post-RT-01) `CertificateVerify` validated |
| Active server compromise | Partial | Blind relay design — server can DoS but cannot decrypt blobs |
| Device seized, user under coercion (rubber-hose) | YES | "Zero on disk" — no sk_x25519 persisted; archive mode requires paper phrase |
| Device seized, PIN unknown | YES | Argon2id 256 MiB × 4 + 6-digit PIN = ~1.2s/attempt × 10⁶ = ~14 days brute-force baseline |
| Device seized, PIN known | Partial | Attacker can sign with remaining slots in current batch only — past streams unrecoverable |
| Cold-boot RAM dump of locked device | Best-effort | `LockedSecret` (`mlock`) + `Zeroizing` on hot paths |
| Compromised Android system (root) | OUT | Game over, documented |
| Cellebrite / GrayKey / firmware extraction | OUT | Game over, documented — paper phrase remains the only recovery |
| Supply-chain compromise of dependencies | OUT | Pin exact versions in Cargo.toml + Cargo.lock committed |

---

## 5. Cryptographic invariants (must not change)

`AUDIT_SCOPE_RUST §4` is authoritative. Highlights:

- **BIP-39 FR**: 12 words from the official French wordlist, NFD + lowercase
  + canonical-prefix normalization. Empty passphrase by default.
- **HKDF context strings (locked byte-exact)**:
  `"stream.identity.ed25519.v1"`, `"stream.encryption.x25519.v1"`,
  `"stream.ratchet.chain0.v2"`, `"frappuccino-v2-ratchet-batch-seeds"`,
  `"frappuccino-v2-ratchet-next-chain"`, `"frappuccino-v2-ratchet-blob-mac"`.
  Drift = orphan every enrolled identity. Lockstep test:
  `crypto-rs/core/tests/hkdf_contexts_lockstep.rs`.
- **X25519** : libsodium `crypto_box_seed_keypair` derivation —
  `sk = SHA-512(seed)[..32]` (no Ed25519→X25519 birational conversion).
- **Ratchet** : 50 ephemeral Ed25519 keys per batch, derived from
  `chain_N` via HKDF. Each `sign_and_advance` zeroizes the consumed slot.
  `advance_batch` rolls forward to `chain_{N+1}` with `RotationProof`.
  V2 blob = 4876 bytes (44 header + 4800 slots + 32 HMAC). V1 (no MAC)
  is rejected at runtime since RT-03 fix; only the dedicated CLI migrator
  reads V1.
- **STRM blob V2** : magic+version+author_pk+sealed_envelope+grant_count
  +mode+payload. AAD for CHUNKED includes `MODE ‖ nonce_prefix ‖
  chunk_count_BE_u32` (RT-02 fix prevents silent truncation).
  Per-chunk nonce reconstruction `prefix ‖ i.to_be_bytes()` rejects
  reorder attacks (ultrareview bug_001).
- **Sealed envelope** : `crypto_box_seal` (X25519 + blake2 nonce
  derivation + ChaCha20-Poly1305) over the 32-byte session key.
- **PIN store** : Argon2id m=256 MiB / t=4 + XChaCha20-Poly1305-IETF.
  Salt persisted with the blob; fast-reseal API caches the derived key.
- **TLS** : rustls 0.23 with custom `PinnedCertVerifier` checking SPKI
  SHA-256 (currently `zgsMr0+XCoQ0gy/MTEVCbqZC0NsvR+LQgWdS0w1JWUI=`).
  Post-RT-01 fix the `CertificateVerify` signature is delegated to
  `rustls::crypto::verify_tls1[23]_signature` so the pin is no longer
  trivially bypassable by an attacker with the public cert.

---

## 6. Test surface

`cargo test --workspace --release` from `crypto-rs/` runs the full Rust
suite. As of HEAD `4928220`:

- **165 Rust tests passing**, 0 failed, 3 ignored (live-network E2E
  against the prod relay; can be run on-demand).
- **`cargo tarpaulin --workspace --release --ignored
  --implicit-test-threads`** measured 90.39% line coverage at S9.3.
  HTML report under `crypto-rs/coverage/`.
- **4 cargo-fuzz targets** under `crypto-rs/fuzz/` (nightly + Linux):
  `fuzz_decrypt_blob`, `fuzz_parse_strm_header`,
  `fuzz_ratchet_deserialize`, `fuzz_pin_store_open`. ≥ 1 M iterations
  each, zero crashes.
- **Parity vectors** : Kotlin-produced reference fixtures under
  `crypto-rs/parity-vectors/{strm_blobs,ratchet}/` — Rust must decrypt
  byte-exact. Includes `chunked_3mb.strm` retained as an RT-02
  regression guard.
- **Server tests** : `pytest server/tests/` — auth_v2 endpoint coverage
  + 4 new concurrency tests (ThreadPoolExecutor races on
  `consume_ephemeral_key` / `rotate_batch` / `enroll`).
- **HKDF lockstep** : `crypto-rs/core/tests/hkdf_contexts_lockstep.rs`
  asserts SHA-256 of every HKDF context string against committed hex.

---

## 7. Audit history (what's already been thrown at this code)

Four AI-assisted audit passes have been consumed pre-handoff:

1. **ultrareview cloud pass** (~April 19, 2026) — found 3 issues,
   fixes committed atomically:
   - `506a1b4` security fix : V2 CHUNKED chunk-reorder detection
     (per-chunk nonce binds `prefix ‖ i`).
   - `cc7fa03` cleanup : dead PEM loader removed, additional
     `seed.zeroize()` in `derive_batch_into`.
   - `a911080` regression test for chunk reorder.

2. **Red Team cloud pass** (`modest-bardeen` worktree, April 20) —
   produced 15 findings.

3. **Blue Team cloud pass** (`amazing-payne` worktree, April 20) —
   triaged the RT findings.

4. **Counter-Blue Team local pass** (`xenodochial-morse`, April 21) —
   re-verified each finding by reading the actual source. Result:
   14 confirmed valid, **RT-13 stale** (Blue Team confirmed dead
   code that ultrareview had already removed in `cc7fa03`). Output:
   `BLUE_TEAM_COUNTERAUDIT_2026-04-21.md`.

The remediation lives in two waves:

- **Phase 4.1** (FIX NOW, completed) — 7 atomic commits, each with
  regression tests. See §8 below.
- **Phase 4.2** (coverage gaps, completed) — 4 surfaces previously
  un-audited, now covered by tests + audited manually. See §9.

Phase 4.3 (FIX SOON) and Phase 4.4 (archive retrieval feature) are
intentionally deferred to **post your audit** — see §10.

---

## 8. Findings closed pre-audit (Phase 4.1)

All seven findings from the Blue Team triage with `bucket = FIX NOW`
are closed. Each commit is atomic, includes its own regression test,
and gates on `cargo test + clippy + fmt`.

| Finding | Severity | Title | Commit | File touched |
|---|---|---|---|---|
| RT-01 | **BLOCKER** | TLS `CertificateVerify` not verified → trivial MITM | `cd9b794` | `crypto-rs/stream/src/pin.rs` |
| RT-07 | MAJOR | Auto-rotate silently disabled (UDL didn't expose `remaining_in_batch`) | `ee82f33` | `crypto-rs/ffi/{frappuccino.udl,lib.rs}`, `StreamUploadManager.kt` |
| RT-02 | MAJOR | V1 CHUNKED accepted → silent chunk truncation | `f071c42` | `crypto-rs/stream/src/decrypt.rs` |
| RT-03 | MINOR | V1 ratchet blobs accepted with no MAC | `9f987e4` | `crypto-rs/core/src/ratchet.rs` + new CLI `frappuccino-migrate-v1-ratchet` |
| RT-11 | MINOR | Stack copies of Ed25519 seeds not zeroized (3 sites) | `6f9e35d` | `crypto-rs/core/{ratchet.rs,identity.rs}` |
| RT-08 | MINOR | `decrypt_chunked` accumulator: bare `Vec::new()` leaked plaintext on realloc | `2842c6f` | `crypto-rs/stream/src/decrypt.rs` |
| RT-10 | INFO | `vk.verify` lax (vs server-side strict) → asymmetry | `fbcab3e` | `crypto-rs/core/src/identity.rs` |

The TLS CertificateVerify fix (RT-01) deserves special attention because
the previous stub was a regression that silently broke the threat model.
The full E2E MITM mock test that would exercise the rejection path is
deferred to Phase 4.1.5 (rustls 0.23 makes `DigitallySignedStruct::new`
`pub(crate)`, so direct unit-test construction is blocked). The unit
test in place
(`pin.rs::tests::rt01_verifier_initializes_with_signature_algorithms`)
guards against future regressions of the "stub returns Ok blindly"
flavour. **An auditor with rustls expertise is encouraged to validate
the signature-verification delegation by reading `pin.rs` and tracing
into `rustls::crypto::verify_tls1[23]_signature`.**

---

## 9. Coverage gaps closed (Phase 4.2)

Four surfaces flagged in the counter-Blue Team report §5.4 as
"not exercised by any of the four prior audit passes":

| # | Surface | Coverage added | Outcome |
|---|---|---|---|
| 4.2.1 | HKDF context strings byte-exact | `crypto-rs/core/tests/hkdf_contexts_lockstep.rs` (6 tests) | Drift on any of the 6 strings now fails the build |
| 4.2.2 | `ratchet_registry.py` concurrent access | `server/tests/test_ratchet_registry_concurrency.py` (4 tests, ThreadPoolExecutor) | Existing `threading.Lock` confirmed end-to-end |
| 4.2.3 | RT-09 PIN-tracker miswiring across Kotlin sources | `.semgrep/frappuccino-pin-tracker.yaml` + manual audit `.semgrep/AUDIT_2026-05-07.md` | Zero matches at HEAD; `PinUnlockActivity` is the sole legitimate `recordFailure` call-site |
| 4.2.4 | UI fingerprint label honesty (`§6.1` deferral) | `docs/UI_FINGERPRINT_AUDIT_2026-05-07.md` | No on-screen attribution claim — the deferral holds. Phase 4.4 (archive retrieval) follow-up constraint documented |

---

## 10. Tracked post-audit (FIX SOON + features)

Intentionally **not** addressed before this audit, to avoid widening the
attack surface inside a closing window:

### 10.1 Phase 4.3 — FIX SOON bucket

Cosmetic-or-defense-in-depth items where the cost/risk tradeoff of
adding more code in flight outweighed the audit-readiness gain.

| Finding | Severity | Title | Plan |
|---|---|---|---|
| RT-04 | MEDIUM | `derived_key` Argon2id crosses FFI as `Vec<u8>` (not `mlock`-able in Kotlin) | Refactor UDL to opaque `FfiFastReseal` handle, key stays Rust-side |
| RT-05 | MEDIUM | `PinAttemptTracker` counters in plaintext SharedPreferences | HMAC-sign with HKDF(chain_0, …) so adb-write erases-and-detects |
| RT-06 | MEDIUM | `/auth/v2/rotate-batch` body has no timestamp → front-run DoS | Sign `concat ‖ ts_BE_u64`, server enforces ±30 s skew |
| RT-09 | LOW | AEAD failure mapped to `WrongPin` (overloads PIN unlock failure) | Distinct `CryptoError::BlobAuthFailed` → `FfiError::InvalidBlob` |

### 10.2 Phase 4.4 — Archive retrieval feature

Today the archive mode UI ends at "phrase matches identity" — there's no
download path for retrieving streams from the server. The feature is
fully designed but deliberately not built before this audit. See
[`ROADMAP.md`](../ROADMAP.md) §6.4.4.

### 10.3 Known-deferred (`AUDIT_SCOPE_RUST §6`)

Three design choices the team has consciously taken:

- **§6.1** — STRM blob `author_ed25519_pk` not signed. Confidentiality
  guaranteed by `crypto_box_seal`; an attacker can only forge a "from
  X" label on content **they wrote themselves**. Validated by §4.2.4
  UI audit — no on-screen attribution.
- **§6.2** — Ratchet per-batch salt absent. MAC key
  `HKDF(chain_{N+1}, CTX_BLOB_MAC)` is identical across devices that
  share `chain_{N+1}` — only relevant on concurrent backup/restore,
  which doesn't exist as a code path.
- **§6.3** — Batch chain TTL not enforced server-side. Combined with
  RT-07 (auto-rotate silently disabled, now fixed), the
  forward-secrecy window was unbounded. Post-RT-07 fix the client
  rotates at slot ≤ 5 left; a server-side TTL is the belt-and-braces
  follow-up.

---

## 11. Out of scope

| Surface | Status |
|---|---|
| Tella legacy V1 vault (`tella-vault/`, `tella-keys/`) | Will be migrated in `ROADMAP.md` Phase 5 ; live in tree but the V2 paths don't touch it. Out of scope for this audit. |
| Demo / marketing materials | The mid-May 2026 demo was dropped from scope; no demo code exists. |
| iOS / Swift bindings | Not built yet (Phase 9 desktop is also not built). |
| Native Android library targets other than `arm64-v8a` | Only arm64-v8a is shipped in the Seeker debug APK. |
| Existing Tella forms / ODK / Uwazi UI | Manifest entries live but unreachable in V2 launcher. |

---

## 12. How to build and run

### 12.1 Rust workspace

```bash
cd crypto-rs/
cargo test --workspace --release      # 165 tests
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
cargo tarpaulin --workspace --release --ignored --implicit-test-threads --timeout 600
```

Fuzz targets (Linux + nightly only):

```bash
cd crypto-rs/fuzz/
cargo +nightly fuzz run fuzz_decrypt_blob -- -max_total_time=60 --sanitizer none
# (the `--sanitizer none` workaround is for a known nightly sancov link
#  bug; ASan-equivalent guarantees come from Miri + the borrow checker.)
```

### 12.2 Server

```bash
cd server/
docker compose up -d
curl -ksf https://136.244.101.236:8443/health
# → {"status":"ok"}
pytest tests/                          # 30+ tests including 4 concurrency
```

The Vultr Ubuntu 24.04 relay at `136.244.101.236:8443` is operational
**for the duration of the audit**. Self-signed cert; SPKI pin
`zgsMr0+XCoQ0gy/MTEVCbqZC0NsvR+LQgWdS0w1JWUI=`. Migration to
Greenhost / 1984 is planned post-audit.

### 12.3 Android

```bash
cd crypto-rs/
TARGETS=arm64-v8a ./build-android.sh   # builds .so + regenerates Kotlin bindings
cd ..
./gradlew :mobile:assembleDebug
adb install -r mobile/build/outputs/apk/debug/mobile-debug.apk
```

JDK 17 required (Android Studio JBR 21 breaks KAPT — see
`gradle.properties` for the explicit pin).

---

## 13. Suggested attack surfaces (where to start)

If you only have a couple of days, the highest-leverage starting points:

1. **`pin.rs` — TLS pinning + signature verification.** RT-01 fix is
   the most security-critical change of this remediation cycle. The
   delegation to `rustls::crypto::verify_tls1[23]_signature` was added
   on 2026-05-07 (`cd9b794`); we'd value an external sanity check.

2. **`decrypt.rs` — STRM blob deserialization.** Multiple legacy paths
   removed (RT-02 V1 CHUNKED, ultrareview reorder fix). Worth fuzzing
   with an extended corpus + checking the `parse_header` /
   `decrypt_chunked` interaction for off-by-one bugs.

3. **`ratchet.rs` — `migrate_from_v1` escape hatch.** RT-03 fix
   introduces a crate-public function that skips MAC verification by
   design. We've audited the only call-site (CLI tool), but a
   rigorous review of "can `migrate_from_v1` be reached from any
   other path" would be welcome.

4. **`server/app/auth.py` — nonce cache + JWT.** Persistent
   `.nonce_cache.json` is a recent addition (BT-HIGH-13 remediation).
   Cross-process / multi-worker behaviour is a known gap (RT-12);
   deployment is gated to `--workers 1`.

5. **UniFFI surface in `crypto-rs/ffi/`.** Generated scaffolding has
   `unsafe` blocks (UniFFI 0.28.3 internal). Worth confirming the
   generated `extern "C"` boundary matches what we declare in the UDL.

---

## 14. Out-of-band

- **GitHub repo** : will be made public AGPLv3 post-audit; right now
  the worktree on `claude/xenodochial-morse` is the working copy,
  merged into local `main`. Audit team gets a tarball or a private
  push as preferred.
- **Reproducible builds** : Cargo.lock committed, exact versions
  pinned. Android build is debug-keystore only at this stage.
- **Communication** : email is fine; no urgent SLA needed unless the
  audit blocks. The dev (therealshulgin) is solo, time-zone Europe.

Thank you for reviewing.

— Frappuccino team, 2026-05-07
