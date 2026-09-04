# Frappuccino — Accepted residuals register (WP-G, audit 2026-06-28)

> **Artifact type:** risk-acceptance register, external-auditor handoff. **Status:**
> deliverable of **WP-G** of the pre-publication remediation plan
> ([`PLAN_REMEDIATION_2026-06-28.md`](PLAN_REMEDIATION_2026-06-28.md)). This is **not**
> a list of bugs to fix — it is the explicit, falsifiable record of the bounded residuals
> we *accept* before 8.2.5, why each is bounded, what (if anything) would close it, and
> where the authoritative analysis already lives. **In case of divergence, the code and
> the linked source-of-truth win, not this index.**

## How to read this

Each row is a residual the 3-layer audit (design-review / red-team / audit-code, all dated
2026-06-28) surfaced and the remediation plan classified as *accept + document* rather than
*fix*. The remediation FIXED everything CRITICAL/HIGH/MEDIUM-with-leverage (WP-A..E, WP-B1..B4)
and the on-device LOW hygiene (WP-F). What remains here is, by construction, either
**by-design** (unavoidable given the architecture + motto) or **out-of-threat-model** (e.g.
a rooted, live, unlocked device). The register exists so no reader over-trusts the system and
so the next dev does not "re-fix" something that was a deliberate trade-off.

The motto bounds the whole register: **everything leaves the phone, and a seizure exposes
nothing — not identity, not content.** Every residual below is checked against that. None of
them expose *content* (E2E STRM) or bind an *identity* to a *report at rest*; they leak, at
most, bounded *metadata* (counts, timing, sizes) or require an adversary already outside the
model (root on a live unlocked phone, or a global passive network observer).

---

## Register

| ID | Sev | Residual (one line) | Why bounded / why accepted | Authoritative source | Status |
|----|-----|---------------------|----------------------------|----------------------|--------|
| **F-C2** | MED (design-cosmetic) | A report's MinIO directory is **singularisable**: object name (`<report_id>/…`), per-chunk **size**, a ~1-byte directory sentinel, and upload **cadence** distinguish one report's traffic from another. | **Anonymous** leak only — a counter/cadence/volume fingerprint per `report_id`, never an identity. `report_id` is a 128-bit phrase-derived capability, not a pk; Phase C removed the `pk ↔ report` join at rest. Closing it (pad bodies, `.strm`-shaped sentinel names, coarsen `last_modified`) is cosmetic hardening with a real rescue-UX cost. | [`METADATA_EXPOSURE_MAP.md`](METADATA_EXPOSURE_MAP.md) #6, §4(B); design-review M-1. | Accepted; optional padding noted in METADATA_EXPOSURE_MAP §7-P2. |
| **PSK-extract** | INFO (by design) | The Salamander obfuscation **PSK is extractable from the APK**, and the keystream period is 32 bytes. | Salamander is **obfuscation, not confidentiality** — it de-classifies the QUIC flow ("this is not Frappuccino") for a DPI that lacks the PSK; it never protects content (STRM E2E does) and is *under* the pinned TLS. A reverse-engineer with the APK was never in the confidentiality boundary. PSK is re-provisioned at publication (gated step). | `crypto-rs/stream/src/salamander.rs:51-55`; audit-code findings inventory (internal report, not published). | Accepted (by design). |
| **secdel-flash** | INFO | `secure_delete_file` is **best-effort on flash** (wear-levelling can retain copies). | **FBE (file-based encryption) is the real at-rest defense**, not the overwrite — the overwrite is defense-in-depth. The Kotlin `delete()` fallback fires only when `secureDeleteFile` *throws* (rare I/O) — strictly better than leaving the file — and a fallback on a plaintext chunk is now surfaced via `StreamMetrics` (F-06 observability), not swallowed. **F-01 fixed (2026-06-30 cross-audit)**: `CaptureScratchCleaner.purgeOrphanChunks` now secure-deletes **non-empty** orphan MP4 chunks too — a chunk finalized but not yet encrypted when the process died abnormally (kill/OOM/battery) or a panic fired mid-encrypt — at service start (pre-bind, race-free), `onDestroy` (post-drain) and `panicWipe` (nuke-all). The old purge caught only 0-byte files, leaving such a chunk recoverable in cleartext on a seized **unlocked** device. Not adversary-reachable on a locked device (FBE). | `crypto-rs/stream/src/secure_delete.rs:65-99`; `CaptureScratchCleaner.purgeOrphanChunks`; `StreamChunkEncryptor.kt:87-95`; design-review 07 §2.12. | Accepted; FBE is the load-bearing control; non-empty orphan window closed (F-01). |
| **pin-expiry** | INFO | The pinned SPKI certs **expire** (LE ~90 d; self-signed to 2036); a botched rotation can brick the fleet. | Managed, not ignored: three pins are pinned at once (live + two pre-seeded break-glass), a rotation runbook exists, and **WP-F5** now adds a render-time guard that refuses a cert whose SPKI is not in the client pin set or whose key does not match — **and (2026-06-29) also the cert's expiry** (`openssl checkend`: already-expired → refuse to render; <30 d → WARN to renew; SPKI pins the **key**, not the validity dates, so `certbot --reuse-key` renews without changing the pin). The Rust verifier (`pin.rs`) is the primary enforcement and never expires by date. | [`TLS_PINNING_ROTATION_RUNBOOK.md`](TLS_PINNING_ROTATION_RUNBOOK.md); `crypto-rs/stream/src/pin.rs`; `server/deploy/nginx/render-relay-conf.sh` (WP-F5 + checkend). | Accepted; brick-risk reduced by WP-F5 + cert-expiry check. **Fix-later**: the NSC half is **done** — the `<pin-set expiration>` attribute was dropped and the config now forbids putting it back, because an expired pin-set silently stops enforcement. What remains is a certbot `--reuse-key` renew hook (operator gesture). |
| **HEAD-oracle** | ~~INFO~~ → **RÉSOLU (2026-06-29)** | `HEAD <report_id>/<chunk>` was an **existence/size oracle**. | **Removed, not merely accepted**: the HEAD route `file_status` was dead code (the client only ever PUTs chunks + archive-GETs them back, never HEAD — verified by grep across `mobile/` + `crypto-rs/`), so it was **deleted** and the oracle no longer exists at all. (Previously: capability-gated by the unguessable `report_id` + rate-limited 120/min.) | `server/app/routes/upload.py` (route removed); `test_head_identity_free` removed. | **RESOLVED** — route deleted. |
| **R-D-1** | RISK-ACCEPTED | **Live heap-dump of an unlocked, rooted device** can recover the *current* session's secrets (current ratchet batch / PIN-session) while recording. | **Out of threat model.** Userspace cannot defeat root. The design invests where it pays: forward secrecy keeps *past* rushes unreachable regardless; long-lived secrets are kept out of the JVM heap (§2.7) — the only transient JVM residuals are the `String` PIN (imposed by the legacy `PinLockView` listener) and the session-metadata `ByteArray`, wiped in `finally` where possible, named instances of the `GUIDE_AUDITEUR §4` zeroize frontier; the unlocked window is shrunk by auto-lock; the wipes are proven real. The residual is the intrinsic "unlocked session" surface, documented not hidden. **WP-F2 tightens this**: it removes a livelock (`Thread.start()` throw leaving `encryptionsInFlightCounter` > 0) that would otherwise defer the auto-lock ratchet wipe forever, turning the unlocked window from "until idle" into "until reboot." **Honesty gap (R-D-1 audit, 2026-06-29)**: the live `EphemeralRatchet.private_keys` (~3.2 KB, the largest resident secret while recording) is `Zeroize`-on-drop but **not `mlock`'d**, unlike `ProvenanceSigner`/`ReportKeyring` (`LockedSecret`) — so the design-review §2.6 claim "all long-lived keys are mlock'd" is over-broad for the ratchet. This is a swap-to-disk surface (≠ R-D-1's live-root dump), marginal on Android (zram, no disk swapfile on Seeker/Snapdragon). | design-review [`05-key-management-and-on-device-secrets.md`](design-review-2026-06-28/05-key-management-and-on-device-secrets.md) §2.6/§2.10; the 2026-06-26 crypto red-team report (internal, not published); `crypto-rs/core/src/ratchet.rs` (private_keys not mlock'd). | Accepted; window bounded; WP-F2 closed the livelock. **Resolved (2026-06-30) by scoping**: design-review §2.6 now caveats the ratchet batch as `Zeroize`-on-drop-not-`mlock`'d, bounded by Android having no disk swapfile (zram); mlock-ing the hot-path batch buys ~nothing on-device and would touch the ratchet, so it is deliberately kept `Zeroize`-only. |
| **R-C-2** | RISK-ACCEPTED | Companion to R-D-1 (subsumes the FFI-era R-CR-1/R-CR-3): the active-session secret surface on a live device. | Same posture as R-D-1 — the claim is forward secrecy of *past* rushes, not protection of a live unlocked session. | design-review 05 §2.10; design-review [`06-rust-crypto-and-ffi-boundary.md`](design-review-2026-06-28/06-rust-crypto-and-ffi-boundary.md) §"Assumptions & residual". | Accepted (documented posture). |
| **relay-auth-registry** | INFO (by design) | The relay persists, per pseudonymous Ed25519 identity, the **current batch + consumed slots + a current-batch creation counter** in `.ratchet_registry.json` at rest. *(Completeness entry, 2026-06-30 cross-audit: disclosed in `_COMPLETE §8.1/§8.5` but had no own register line.)* | **Pseudonym, not a person.** The Ed25519 pk is a device-generated pseudonym with no civil binding; a seizure yields "pseudonym #X is at slot Y, made Z reports this batch" — never the *who*, never a `report → identity` link (the JWT `sub` is used once for anti-abuse then discarded, never written — `upload.py:166`), no per-identity timestamps (F-C4 removed `enrolled_at`), no inter-batch history (M-2 purges it at rotation). Removing it needs anonymous/blind tokens that break the batch lineage + ratchet — out of scope of the motto, which assumes relay seizure and promises only no *who/what*, not pseudonym-unlinkability. | `server/app/ratchet_registry.py:117-124`; `server/app/routes/upload.py:153-187`; `_COMPLETE §8.1/§8.5`. | Accepted (by design); motto holds (no person, no report link). |
| **pk-device-local** | INFO | The device persists its **public** identity (`ed25519_pk`, `x25519_pk`) in `EncryptedSharedPreferences` (Android Keystore), removed only at `panicWipe`. On a seized AFU/unlocked device (or with the Keystore extracted) it correlates to the relay enrollment registry (join with **relay-auth-registry**). *(Completeness entry, 2026-06-30 cross-audit.)* | **Public** key — no decryption, forward secrecy intact (the private ratchet is PIN-wrapped + Keystore). The "no identity at rest" claim is scoped to the **STRM blob on relay disk** (V3, `author_ed25519_pk` removed), **not** the device. The device surface is the already-accepted R-D-1/R-C-2 posture (seized/rooted/live device out of model); Keystore + FBE + lockscreen is the load-bearing OS barrier. A raw Ed25519 pk is neither a testimony nor a named person. | `StreamPreferences.kt:97-116`; `StreamUploadManager.kt:166-172`; `_COMPLETE §4.6/§7.3`. | Accepted; covered by R-D-1/R-C-2. **Hardening-later** (optional, peer of ratchet-mlock): derive the public id on demand from the PIN-wrapped state instead of caching the hex pk. |

---

## Residuals surfaced *by* WP-F (new, 2026-06-28)

WP-F fixed five LOW on-device items; three of them have an irreducible bounded residual that
belongs in this register (the fix made the residual **honest/observable**, not zero):

- **F1 / L-1 — mnemonic bytes cross UniFFI un-wiped.** `bip39GenerateFr()` returns the BIP-39
  phrase as a `ByteArray`. The Rust *source* is a `Zeroizing<String>` (wiped on drop), but the
  returned bytes are a plain copy: **UniFFI has no zeroize hook on a byte return** — it copies
  into a RustBuffer and drops the source un-wiped. The returned `ByteArray` + that RustBuffer are
  a transient, bounded residual, **inevitable to display the phrase on screen**. Defense: the
  Kotlin caller `SecureWipe`s its `ByteArray` (regen + `onDestroy`), and the on-screen `String`
  exists only ~ms for the render. WP-F1 corrected the previously-false Kotlin doc that claimed
  "the Rust buffer is wiped on drop." *(File: `OnBoardMnemonicGenerateFragment.kt`.)*

- **F3 / L-8 — the control-plane rides DirectTls by design.** Auth/enroll/status/rotate and the
  `/health` reachability probe all speak **DirectTls (`:8443`)**; only the bulk **chunk PUT
  data-plane** is ObfQuic (`:8445`, Salamander). So ObfQuic obfuscates *when and how much you
  upload* (the high-value timeline signal), **not** the fact that a device talks to the relay —
  that fact is exposed by the control-plane TLS anyway. The `/health` probe leaks no IP/SNI class
  the imminent auth does not already. This is the same wire residual as
  [`METADATA_EXPOSURE_MAP.md`](METADATA_EXPOSURE_MAP.md) #1 / §4(A), scoped precisely:
  **the data-plane is obfuscated; the control-plane is not, by design.** WP-F3 corrected a false
  comment claiming the probe "consumes a ratchet slot" (it does not — `challenge()` fails before
  `signAndAdvance`). *(File: `StreamRecordingService.kt`.)*

- **F4 / L-9 — codec output buffer plaintext cannot be scrubbed in place.**
  `MediaCodec.getOutputBuffer()` returns a **read-only** ByteBuffer by contract, so the
  forensic-#3 in-place scrub of the compressed (not-yet-encrypted) HEVC frame is a **no-op on a
  compliant device** — writing through a read-only view is impossible without fragile reflection
  on the codec's native memory (a band-aid we refuse). The residual is bounded: the codec
  overwrites that pool buffer with the next frame, nothing is written **at rest**, and it lives
  only in a transient native codec buffer. WP-F4 made the skip **observable** (`wipe` now returns
  a Boolean; the encoder logs once per session that the scrub is unavailable) instead of a silent
  no-op we falsely believed was running. *(Files: `SecureWipe.kt`, `HevcMediaCodecEncoder.kt`.)*

---

## Residuals from the 2026-07-02 adversarial pass (Fable 5 inter-model audit + review)

The 2026-07-02 pass **fixed** everything with motto/ratchet leverage — the `rotate-batch`
identity→activity oracle (LOT A), the rust-core secret-hygiene set (LOT C), the ratchet
overflow (LOT D), the hostile-relay OOM (LOT E), the path/regex hardening (LOT F), and the
full capture fail-closed watchdog (LOT B1/B2/B3, incl. the teardown-GL-wedge motto hole the
adversarial review itself caught). What is accepted-and-documented below is, by construction,
INFO/LOW with no content leak, no identity-at-rest, and no ratchet break.

- **STRM-SINGLE-AAD (#25)** — INFO, *wire*. In SINGLE mode the one-byte `MODE` is **not bound
  in the AEAD AAD** (asymmetric with CHUNKED, which does bind it). **Non-exploitable**: the two
  AAD constructions diverge structurally (distinct lengths — CHUNKED AAD = header+25 B — plus a
  random per-blob session key), so a `MODE` flip fails the tag with zero cross-mode plaintext
  recovery; `MODE` is already bound *implicitly*. Closing it is a **wire change** (a V3 SINGLE
  blob's tag changes) requiring a V4 version bump + fixtures + Kotlin/Python mirror updates —
  and the wire is deliberately **frozen** (anti-derive gate, `signature_domain_surface_is_frozen`
  + `proofs.yml`). Accepting is the correct call; a bump would be gratuitous for a nil-impact
  cohesion nit. *(Source: `crypto-rs/stream/src/decrypt.rs` / `encrypt.rs`; audit `03-deep-findings.md` #25.)*

- **enqueue-cross-partition-fsync (#12)** — LOW-MED. On devices where `cacheDir` and `filesDir`
  sit on **distinct mount points** (adopted storage, some Samsung A / custom ROMs), the
  `ChunkUploadQueue.enqueue` fallback copy path fsyncs only the **directory**, not the dest
  **content** → a battery/kill in the narrow dir-fsync→data-writeback window can leave a torn or
  0-byte blob while the source `.strm` is already secure-deleted = irreversible loss of that one
  encrypted chunk. **Bounded**: requires cross-partition hardware (minority) AND a crash in a
  narrow window; the blob is **encrypted** throughout (no clear at rest, no motto break) — the
  cost is one lost chunk, not exposure. **Fix available** (`FileOutputStream(dest).fd.sync()`
  before secure-deleting the source, symmetric with the Rust `sync_all()`), deferred pending
  whether the closed test (15 volunteers) includes such devices. *(Source: `stream-crypto/.../upload/ChunkUploadQueue.kt`; audit #12.)*

- **aac-pcm-drop (#15)** — LOW. `AacEncoderSession.onPcm` drops PCM samples when
  `dequeueInputBuffer(10ms) < 0` (muxer back-pressure at a chunk boundary/swap). Already analyzed
  and accepted in ROADMAP §3.6 (field-measured sub-perceptible, ±34 ms mean, `chunkStartSkew`
  tripwire; bounded gap, zero drift via absolute `CLOCK_BOOTTIME` PTS). Real fix = a bounded PCM
  ring-buffer (the "true fix (a)" of §3.6), planned, not urgent, no motto/ratchet contact.
  *(Source: `AacEncoderSession.kt`; ROADMAP §3.6.)*

- **audio-gap-on-retry (MINEUR-1, from the LOT B review)** — LOW. If `rotateChunk`/`swapVideoConfig`
  throws at the GL-swap step *after* the PCM sink was switched to `next` (which `onRotationFailure`
  then stops) and `old`'s audio was already EOS'd, the in-flight chunk records **no audio** — and,
  since a mid-swap `setOutputSurface` throw leaves `eglSurface = EGL_NO_SURFACE`, no video either —
  for the ~1-interval retry window until the next successful rotation reroutes the sink. **Not a
  motto break**: `old` is still finalized+encrypted+delivered (the fail-closed watchdog guarantees
  it), nothing clear is stranded at rest — the cost is a transient A/V gap on a failure retry. The
  clean fix (reorder the audio handoff to `setSink(next)` only *after* the GL swap is confirmed)
  conflicts with the proven H2-B.14 lossless-handoff ordering; deferred as > risk than reward.
  *(Source: `RollingChunkRecorder.kt` failure path; LOT B review, run `w2jmnq1xt`.)*

- **seal_open-pk-param (#24)** — INFO, API hygiene. `core::seal::seal_open(blob, recipient_pk,
  recipient_sk)` takes `recipient_pk` **not bound** to `recipient_sk` (it only re-derives the
  nonce). **No security impact**: the sole prod caller (`ArchiveIdentity::decrypt_session_key`)
  passes a coherent pair (both from the same `x_sk_bytes`), `seal_open` is **absent from the UDL**
  (the Kotlin/untrusted boundary cannot supply a mismatched pk), and a mismatched pk **fails
  closed** (Poly1305 → `WrongPin`), never a silent wrong-plaintext. Fix (drop the param,
  re-derive pk from sk internally = pit-of-success) is polish, deferred. *(Source: `crypto-rs/core/src/seal.rs`; audit #24.)*

- **archive-404-message (#28)** — INFO, cosmetic. `archive.py` returns distinct `404 "Report not
  found"` vs `404 "Blob not found"`. This micro-oracle is visible **only** to a holder of the
  128-bit `report_id` — an actor already authorized to list every blob of that report — so it
  grants nothing an attacker without the capability could use (`report_id` is unguessable in
  2^128). It is **intentional** (blob-first rescue invariant: the rescue client distinguishes "no
  such report" from "report present, this file absent"; docstring `archive.py`). **Recommendation:
  leave as-is** — uniformizing would remove a legitimate client signal for zero adversary benefit.
  *(Source: `server/app/routes/archive.py`; audit #28, LOT B-review-adjacent triage.)*

---

## What is NOT in this register (because it was fixed, not accepted)

For the auditor's orientation: the at-rest identity leak (STRM header `author_pk` → STRM **V3**,
WP-A), the FastAPI public-bind (WP-B1), the rescue path-traversal/OOM (WP-C), the `.strm`
power-loss durability gap (WP-D), the cross-language signature KAT + build gate (WP-E), the
slowapi no-op rate-limiting (WP-B2), MinIO container hardening (WP-B3), and supply-chain digest
pinning (WP-B4) were all **fixed and field-validated**, not accepted. See
[`PLAN_REMEDIATION_2026-06-28.md`](PLAN_REMEDIATION_2026-06-28.md) and `ROADMAP.md`.

The off-host backup (1.8) and its mandatory `age` encryption (WP-A3 / R-SRV-8) are operator
*gestes*, not accepted residuals — the relay already refuses to write a plaintext state dossier
(`backup-state.sh` requires `FRAPPUCCINO_BACKUP_AGE_RECIPIENT`).
