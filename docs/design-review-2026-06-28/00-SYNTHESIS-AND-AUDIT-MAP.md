# Frappuccino — Design rationale review: synthesis & audit map (2026-06-28)

> Model: claude-opus-4-8[1m]. A first formalized reflection layer to seed a future adversarial audit.
>
> This document does not re-argue the eight per-domain reports; it composes them. It states how the
> eight domains fit together to serve the motto, names the load-bearing bets the whole system rests on,
> surfaces the cross-cutting strengths and the honest residuals, and consolidates every per-domain
> "questions for the future audit" into one deduplicated, leverage-ranked audit map. The governing motto
> throughout: *tout quitte le téléphone & une saisie n'expose rien ; le téléphone est un relais, pas un
> coffre* — everything leaves the phone fast; a seizure exposes nothing; the phone is a relay, not a vault.
>
> One meta-rule the reports share and this synthesis adopts: **where prose docs and live code diverge,
> the code is authoritative** (`docs/METADATA_EXPOSURE_MAP.md:10`). Two such divergences were found and
> are flagged below — they are gold for the next auditor.

---

## 1. Index

| # | Domain | File | One line |
|---|--------|------|----------|
| 01 | Threat model, motto & trust boundaries | [`01-threat-model-and-motto.md`](01-threat-model-and-motto.md) | What is defended, against whom, and what is deliberately out of scope (phone-as-relay, scoped "n'expose rien", hostile relay, paper-phrase root, the single pinned-TLS channel). |
| 02 | Ephemeral ratchet & forward secrecy | [`02-ephemeral-ratchet-forward-secrecy.md`](02-ephemeral-ratchet-forward-secrecy.md) | Batched use-once Ed25519 lineage (50/batch), HKDF chain advance, one-shot long-term key, self-signed rotation, domain tags, and the 5 machine-checked proofs. |
| 03 | Relay-blind reports & capability addressing | [`03-relay-blind-reports-and-capability-addressing.md`](03-relay-blind-reports-and-capability-addressing.md) | `report_id = H(report_pk)` capability address, per-report independent keys, identity discarded at creation, blob-first lazy creation, the directory, the anti-sybil count. |
| 04 | Transport: obfuscation, pinning & break-glass | [`04-transport-obfuscation-and-pinning.md`](04-transport-obfuscation-and-pinning.md) | Salamander/QUIC obfuscation, SPKI pinning that bypasses CA, the 3-pin off-host break-glass, the QUIC→DirectTls fallback, the domain/SNI trade-off, Tor excluded. |
| 05 | Key management & on-device secrets | [`05-key-management-and-on-device-secrets.md`](05-key-management-and-on-device-secrets.md) | Sovereign BIP-39 root never stored, role-split HKDF, V2 lifecycle asymmetry, Argon2id PIN-seal, mlock/Zeroizing, no-export FFI, zeroize audit, auto-lock, accepted residuals. |
| 06 | 100% Rust crypto & the UniFFI boundary | [`06-rust-crypto-and-ffi-boundary.md`](06-rust-crypto-and-ffi-boundary.md) | One Rust cdylib perimeter, secrets never cross, minimized surface, diff-fuzz/KAT parity, server-mirrored domain tags, `.so` freshness gate, panic=unwind scrub-on-crash. |
| 07 | Capture pipeline & data-loss resilience | [`07-capture-pipeline-and-data-loss-resilience.md`](07-capture-pipeline-and-data-loss-resilience.md) | Stream-and-delete chunking, crash-durable queue, idempotent PUT, circuit breaker, 507 handling, adaptive quality/concurrency, data-loss trio, secure-delete's honest limits. |
| 08 | Server / relay architecture | [`08-server-relay-architecture.md`](08-server-relay-architecture.md) | Thin semi-trusted FastAPI+MinIO+nginx relay, identity-free reports, ephemeral-ratchet auth, HS256 JWT, persisted nonce anti-replay, write-once blobs, single-worker, deploy posture. |

---

## 2. The design as a coherent whole

The eight domains are not eight features; they are one sentence (the motto) re-expressed at eight
altitudes. The motto contains two clauses that *pull against each other* — data must **leave the phone
fast** (so a seized phone yields nothing) and yet **wherever it lands must also expose nothing** (so a
seized relay yields nothing). Every domain is a move to satisfy both at once:

- **The root never lives on a machine.** The 12-word BIP-39 phrase (domain 01 C5, 05 §2.1) is the sole
  read path; the X25519 private half "exists on no machine" (`docs/POSITIONNEMENT.md:147-148`). This is
  what makes the blind relay (08, 03) *structural* rather than policy — the relay cannot betray what it
  cannot read.
- **Authority is ephemeral and forward-secure.** The long-term signing key is used once at enrollment
  then wiped (02 C4, 05 §2.4); day-to-day auth is a use-once Ed25519 slot (02 C1/C2), so a seizure
  forges nothing past. The relay mirrors this with use-once nonces and consumed slots (08 §2.4/2.6).
- **The at-rest surface is engineered down to "numbers, not maps."** Capability addressing replaces the
  account table (03 C3), identity is discarded at report creation (03 C4), and the only identity residual
  (the enrollment registry) is "a count, never a card" (03 C8, 08 §2.3).
- **The perimeter for secrets is one auditable Rust `.so`.** Plaintext and keys never cross to the JVM
  heap (06 C2/C3, 05 §2.7); even a crash scrubs before surfacing (06 C8).
- **Footage is destroyed continuously, not at the end.** Stream-and-delete chunking (07 §2.1) bounds the
  on-disk plaintext window to ~5 s; the relay is the drain.

**The 3–4 load-bearing bets the whole system rests on.** If any one of these is wrong, large parts of the
guarantee fall — these are where the next audit should concentrate:

1. **BET A — The paper phrase is the sole root, and it is genuinely off-device.** Sovereignty, recovery,
   blind-relay, and identity-free reports all reduce to this one secret living only in the witness's head
   /on paper (01 C5, 05 §2.1, 02 C4, 03 C2). It is simultaneously the system's greatest strength (nothing
   on the phone or server can be coerced into yielding the past) and its single point of total failure
   (phrase coerced/lost = complete defeat or unrecoverable archive). The whole design is a bet that
   concentrating failure on *one offline human-held artifact* beats diffusing it across software.

2. **BET B — Forward secrecy is real at the byte level, so a *seized* device exposes no past.** The motto's
   "n'expose rien" is scoped to a *seized-then-examined* (locked/AFU/wiped) device, not a live unlocked
   one. This rests on: wipes actually executing (proven at the IR level, 02 C2/C8, 05 §2.8), the chain
   being one-way (02 C3, *assumed* not proven — computational gap), and no current-session secret being
   able to reach an already-uploaded archive (05 §2.10, the negative claim). If a wipe is elided, a chain
   key is recoverable, or a current secret unlocks a past blob, the central claim cracks.

3. **BET C — The relay is blind at rest, and the at-rest identity residual is "just a number."** A disk +
   RAM image of the relay yields ciphertext and opaque ids, with no `identity → report → when` join (08,
   03). This rests on identity being discarded within the request handler (03 C4), the enrollment registry
   holding only counters (03 C8), and — critically — *nothing leaking via logs/exceptions* the one
   transient moment identity and report co-exist (03 C4, 08 §2.10). This channel was *missed by two prior
   audit passes* (`docs/RELAY_BLIND_REPORTS.md:44,187`).

4. **BET D (operational, weaker) — The shipped artifact is the audited artifact, and the channel stays
   up.** The `.so` freshness gate proves currency + pin presence but **not provenance** (06 C7); the
   transport's obfuscation holds **only while UDP is open** and degrades to a self-identifying TLS flow a
   state can force (04 §2.6/2.7); the off-host break-glass recovery is **written but unrehearsed** (04 §2.5).
   This bet is the one the project itself rates lowest-assurance, and it is where operational reality
   (no remote/dormant CI, manual gates, undeployed backup timer) most diverges from the design intent.

---

## 3. Cross-cutting strengths

Defenses that reinforce each other *across* domains, with evidence:

- **One root, many unlinkable capabilities — recovery AND blindness from the same primitive.** Role-split
  HKDF from one seed (05 §2.3) yields independent per-report keys (03 C2) that make reports mutually
  unlinkable at the relay (08 §2.2) *and* let a blank rescue device re-derive every report address with no
  server-side list (03 C1, 08 §2.2 `archive.py:5-8`). The same derivation tree serves sovereignty,
  unlinkability, and recovery — three goals, one mechanism, no escrow.

- **Domain-separated signatures span crypto + reports + server in one discipline.** The one-byte tag scheme
  (02 C7, 03 C6, 05 §2.3, 06 C5) closes the Tamarin "separation depends on length" finding everywhere a
  slot key signs — auth/rotation/enrollment (0x01–0x03), provenance (0x05/0x06), and report capabilities
  (0x07/0x08) — and the FFI never lets the caller choose the tag (06 C5, `lib.rs:400-402`), so misuse is
  structurally impossible. The negative control NC2 *re-falsifies* rotation when tags collapse (02 C5),
  proving the separation is load-bearing, not decorative.

- **The heap-0 contract is enforced top-to-bottom.** Plaintext never reaches the JVM heap at capture
  (07 §2.1 `StreamChunkEncryptor`), at decrypt (06 C2 `strm_decrypt_to_file`), or for the bearer
  (06 C2/C3 `UPLOAD_JWT`, the chunk path sets the header inside Rust); the master key never crosses the
  FFI (05 §2.7 no-export). The same principle — keep the secret in scrubbable Rust memory — is applied
  identically by the key-management, FFI, and capture domains. `panic=unwind` extends it to crashes
  (06 C8), so the perimeter holds even on failure.

- **Forward secrecy is the universal backstop for every "live device" concession.** The accepted residuals
  in 05 (§2.10 R-D-1 live heap dump), 02 (current batch on a non-locked heap), and 07 (auto-lock defers
  during recording) all rely on the *same* downstream guarantee: even the worst in-model case exposes only
  the *current* session, never the past, because past slots are wiped and the archive key is
  phrase-only (05 §2.10, 02 C1, `00_DESIGN_CRITIQUE.md:17`). One proven property absorbs three otherwise-
  uncomfortable concessions.

- **The "buy-back without re-introducing the forbidden edge" pattern.** Every place the relay needs
  something an identity model usually provides — anti-sybil, exact rescue enumeration — it buys it back in
  a way that stays in the *same residual class* the relay already holds (a count, an opaque blob name)
  rather than re-creating the `identity → report` join (03 §3, C7/C8). The directory (03 C7) buys exact
  recovery using the *same* relay-blind primitives (`report_id → report_pk`, write-once).

- **Empirically hardened, not speculatively designed.** The capture domain in particular annotates nearly
  every constant with the dated field incident that produced it (O(N²) workers, 57 s starvation, 39%
  no_auth_token loss, 55 s quality oscillation, the split-report bug — 07 §3). This is a strength an auditor
  can lean on: the resilience logic has met reality.

- **Negative controls everywhere proofs exist.** TLA+ deleting the use-once guard re-falsifies AntiReplay;
  Tamarin NC1/NC2 falsify auth/rotation; the zeroize tripwire fails on a regressed `=[0;N]`; the KAT has
  wrong-domain/tampered-filename negative vectors (02 C8, 05 §2.8, 03 C6). Green is not vacuous — each
  proof is shown to be able to go red.

---

## 4. Internal tensions & honest residuals

This is the section most useful to the next auditor: where two good choices trade against each other, what
is accepted-risk, and what the design explicitly does **not** claim. The reports are candid; this
consolidates their candor.

### 4.1 The two doc-vs-code divergences (read these first)

1. **The SNI / no-SNI divergence (01 C7, 04 §2.7).** The live code pins a *domain*
   (`relay.shake-document-protect.org`, `crypto-rs/stream/src/pin.rs:69`,
   `network_security_config.xml:29`) and puts a cleartext hostname in every DirectTls ClientHello. But
   `docs/METADATA_EXPOSURE_MAP.md:28,82` and `docs/POSITIONNEMENT.md` still present a **raw-IP, no-SNI**
   design as a *current* anti-metadata control and frame the SNI leak as a *future* regression. As of HEAD
   the regression is already shipped. The migration itself is reasoned (it enables the off-host break-glass
   recovery, 04 §2.5), but the threat-model prose has not caught up, so an auditor reading the metadata map
   would draw a false conclusion about what is on the wire. **Action: reconcile the docs, or confirm it as
   an accepted regression.**

2. **The release-transport comment drift (04 §2.1/§3).** `StreamPreferences.kt:725-726` still says release
   stays DirectTls by default; the code defaults release to `OBF_QUIC` (`RustUploadTransport.kt:46`).
   Behavior is correct; the comment is stale and could mislead a reviewer.

### 4.2 Tensions where two good choices trade against each other

- **Availability vs. obfuscation (the sharpest transport tension, 04 §2.6/§3).** ObfQuic exists to make
  the wire unclassifiable, but the no-data-loss invariant forces a fallback to *fully classifiable*
  DirectTls whenever UDP is blocked — and a state adversary can *trigger* that downgrade at will by
  dropping UDP/443. There is no obfuscated-TCP fallback yet (RealityTcp stayed a stub). The honest claim
  is therefore **"obfuscation holds only when UDP is open."** Worse, on that same degraded path the SNI
  (4.1 #1) self-identifies — a UDP-blocking adversary gets a *double* win.

- **Resilience vs. the security controls (07 §2.11/§3, 05 §2.9).** The no_auth_token fix and
  auto-lock-defers-during-recording deliberately *delay* the ratchet/JWT wipe so the last (often most
  critical) chunk is not stranded. This softens the auto-lock guarantee: a busy pipeline keeps the ratchet
  warm, and an adversary could keep it busy. Reconciled only by the claim that **explicit panic-wipe
  preempts unconditionally** — which must be *verified*, not assumed (see audit map Q3).

- **Relay-not-vault vs. retry-forever (07 §2.3/2.5/§3).** Every failure path chooses retry over fail, so a
  hostile or broken relay (or a permanently-broken `.so`) turns "relay" back into "vault" for up to the
  48 h TTL. The motto degrades gracefully (everything *tries* to leave; if refused, the device holds it
  ≤48 h then destroys it and tells the user), and panic-wipe is the pressure valve — but the on-device
  retention window under a hostile relay is real and accepted.

- **Single root vs. blast radius (05 §2.3/§3, 01 §3).** The HKDF tree is elegant for recovery but means
  root (phrase) compromise is *total* — and cannot be softened without re-introducing an online key that
  weakens the blind-relay guarantee (01 §3 calls C5↔C3 "one coupled decision, not two"). The optional
  BIP-39 passphrase ("25th word") is the only compartmentalization lever and is *under-surfaced* in
  onboarding (05 §2.1).

- **Anti-abuse vs. identity-freedom (08 §3, 03 §3).** The report path achieves true identity-freedom; the
  *auth* path cannot (replay + sybil prevention need per-identity state). The enrollment registry keeps the
  long-term pk + `enrolled_at`/`updated_at` + per-batch creation counts. Counters are dropped on rotation
  to avoid a longitudinal curve, but the **absolute timestamps** are arguably more than replay/sybil
  strictly require — the single most questionable at-rest residual on the server.

- **Live vs. at-rest is a hard boundary, repeatedly.** Identity is discarded at rest but visible at the
  creation instant (03 C4); reports are unlinkable at rest but correlatable by IP/session live (03 C2);
  blob-first removes `createdAt` but MinIO `last_modified` remains (03 C5, 07, 08 §2.2). The design is
  internally consistent in defending *the disk at rest* and openly conceding *the live/active axis*;
  multi-relay/Tor is named as the only real defense for the conceded parts, and Tor was measured and
  rejected for the upload workload (04 §2.8).

- **Type-level vs. structural enforcement (05 §2.4/§3, 02 C4).** `take_chain_zero` is type-enforced
  single-shot, but `sign_once` is only *structurally* one-shot (the kit drops promptly in the live path).
  The one-shot long-term-key promise is a convention verified in one path, not a type invariant.

### 4.3 What the design explicitly does NOT claim (the honest non-claims)

- **Not** network anonymity / destination-hiding (04 §2.7/2.8, 01 C6). "You talk to *a/this* relay" is
  always visible; obfuscation buys *inclassifiability, not invisibility*.
- **Not** traffic-analysis resistance: volume + cadence + a fixed destination + a 6-month retention window
  reconstruct a per-`report_id` "when/how-long/how-much" timeline (01 C2, 03 §3, 08 §2.2). "n'expose rien"
  is explicitly redefined to mean *no identity, no testimony content* — not *no signal*.
- **Not** protection of a live, unlocked, *rooted* device's current session (R-D-1, 05 §2.10, 06 §2).
- **Not** protection against phrase coercion/loss (01 C5, 02 C4, 05 §2.1) — "a seizure is of the phone."
- **Not** post-compromise security / healing — only forward secrecy of the *past* (02 C1, explicitly).
- **Not** court-grade chain of custody, OS-integrity-at-capture, or survival of a fully burned domain
  without an APK push (01 C6, 04 §2.5).
- **Not** binary provenance (no reproducible-build/signed-hash) — only `.so` freshness + pin presence
  (06 C7), risk-accepted per §8.4.
- **Not** computational (concrete-bound) crypto proofs — the chain one-wayness is *assumed* (HKDF a PRF),
  assigned to an out-of-scope CryptoVerif layer (02 C3/C8).
- **Not** multi-worker safety on the relay (anti-replay correctness depends on `--workers 1`, 08 §2.6/2.10).
- **Not** cryptographic flash erasure (secure-delete is best-effort; FBE is the real defense, 07 §2.12).

---

## 5. The audit map: prioritized questions for the future adversarial audit

Consolidated and deduplicated from all eight reports' "questions for the future audit," ranked by
**leverage** (how much of the guarantee turns on the answer) under the state-adversary threat model. Each
item names the domain(s) it touches and why it matters.

### Tier 1 — Highest leverage (a wrong answer breaks a load-bearing bet)

**Q1. Can a state adversary force the unobfuscated, self-identifying downgrade at will — and should a
high-risk profile fail-closed?**
*Domains: 04 (transport), 01 (threat model).* Blocking UDP/443 collapses ObfQuic to classifiable DirectTls
(04 §2.6) *and* exposes the cleartext SNI `relay.shake-document-protect.org` (04 §2.7, 01 C7) — with no
obfuscated-TCP fallback. This is the single cheapest move a state has to defeat the whole obfuscation
story. Probe: what fraction of real field networks already block UDP; should a high-risk profile keep the
blob on disk rather than send it legibly; and reconcile the SNI doc-vs-code drift (4.1 #1). *Matters
because* it converts an "inclassifiable relay" into "this user is a Frappuccino uploader, by name," for
exactly the on-path adversary in scope.

**Q2. Is the blind-relay at-rest boundary airtight against the transient identity moment and the
exception/log channel?**
*Domains: 03 (reports), 08 (server), 01 (threat model).* The 1st-PUT carries a `sub=pk` JWT the relay sees
live (03 C4, 08 §2.3), and a pk/IP leak via exception/`repr`/positional log arg was **missed by two prior
audit passes** (`docs/RELAY_BLIND_REPORTS.md:44,187`). Verify on the *deployed* wheel (not the doc) that no
identity or IP reaches any persistent log under *any* error path, that `sub` is never co-logged with a
`report_id`, and that nginx/MinIO access logs are genuinely off. *Matters because* this is the one channel
that would silently re-create the `identity → report` edge the entire report design exists to destroy.

**Q3. Does explicit panic-wipe / lock unconditionally preempt every resilience deferral, and can a leaked
counter strand auto-lock forever?**
*Domains: 07 (capture), 05 (key mgmt).* The no_auth_token fix and auto-lock both *defer* the ratchet/JWT
wipe while the pipeline is busy (07 §2.11, 05 §2.9). Confirm — and bound the window for — that an *explicit*
panic-wipe ignores `encryptionsInFlight`/`isRunning`/`isShuttingDown`/queue-pending, and that a
stuck/crashed encryption thread (leaked in-flight counter) or a "always something pending" livelock cannot
defer auto-lock indefinitely (defeating the only shrink-the-unlocked-window control). *Matters because* a
coerced witness's wipe being delayed by a busy/wedged pipeline is the difference between R-D-1 being a
narrow window and being "until reboot."

**Q4. Produce the negative proof that no current-session secret can reach an already-uploaded past
archive, and is the live signing material protected at rest?**
*Domains: 05 (key mgmt), 02 (ratchet).* The forward-secrecy backstop (BET B) rests on the claim that
cracking the PIN / dumping the unlocked session yields only the *current* session — the archive key is
X25519-from-phrase-only (05 §2.4/2.5/2.10). Demand the *negative* proof: no PIN-session key, ratchet,
report master, or provenance seed suffices to decrypt or re-address a past blob. Separately: the 50
*current* ephemeral private keys live in a **plain heap array (not mlock'd)** and are serialized **in
cleartext** inside the MAC'd-but-unencrypted-at-that-layer V2 blob (02 C2/C6) — confirm the PIN/seal layer
encrypts it before disk and that the live batch can't be swapped/coredumped before wipe. *Matters because*
the whole "seizure exposes nothing" claim is exactly this negative property plus a clean present-tense
surface.

### Tier 2 — High leverage (a silent regression here voids a defense without anyone noticing)

**Q5. Is the cross-language signature-domain contract drift-proof for the non-report tags, and verified by
an *executed* test?**
*Domains: 06 (FFI), 02 (ratchet), 03 (reports).* The report sigs (0x07/0x08) have a byte-pinned Rust↔Python
KAT, but auth/rotation/enrollment (0x01/0x02/0x03) appear protected only by per-language tests that sign
with each side's own constants — which (the KAT file itself warns) *cannot* catch one-sided drift (06 C5,
02 C7). Test: does a deliberate one-byte change to `SIG_DOMAIN_ENROLLMENT` on only one side make any test
go red? Confirm every server verify site prepends the tag, and that retired `0x04` is truly unreachable.
*Matters because* a one-sided drift either 403s the whole fleet (DoS) or silently weakens verification,
and there is no machine gate.

**Q6. Is the audited artifact the shipped artifact — bindings/`.so` fresh, parity machinery live, and any
binary provenance at all?**
*Domains: 06 (FFI), 04 (transport).* Three coupled gaps: (a) `checkRustSoFresh` proves currency + pin
*presence* but **not provenance** — a stale-branch/hand-built/substituted `.so` embedding the right pin
strings sails through (06 C7); (b) the 759/759 diff-fuzz and the KAT are only meaningful if run against
*freshly regenerated* bindings, not `../target/debug` leftovers, and the repo has no remote/dormant CI
(06 C6); (c) the release `.so` must actually be built with the `quic` feature so the obfuscation+ratchet
code in the *same address space* is the one audited (04 §2.1). *Matters because* every formal proof and
parity check is only as strong as "the bytes on the phone are the bytes we checked," and that link is
currently operator-trusted.

**Q7. How tightly can kept metadata be timing-joined to reconstruct the "discarded" identity → report@T
edge, and can the directory be singled out?**
*Domains: 03 (reports), 08 (server), 01 (threat model).* Identity is discarded from the report (03 C4) but
the relay still retains, per enrolled pk, a current-batch creation count with `updated_at`
(`ratchet_registry.py:284`), alongside MinIO `last_modified` and `reports.json` mutation times. Can these
timestamps be correlated to approximate the removed edge? And the **report directory** aggregates *every*
session under one phrase-derived id (03 C7) — the design's single biggest linkability concentrator; can a
traffic-shape/growth-pattern analysis re-identify it (constant-length opaque names, regular append cadence,
distinct from `<sid>_NNNNNN.strm`) and thereby leak session count + cadence? *Matters because* this is
where the at-rest identity-stripping could be quietly undone by correlation the design does not store but
also does not prevent.

**Q8. Is the registry's at-rest identity residual minimal — are the absolute timestamps necessary, and can
two state files be re-joined?**
*Domains: 08 (server), 03 (reports).* The auth registry is the *one* place the relay is not identity-free
(long-term pk + `enrolled_at`/`updated_at` + per-batch counts, 08 §2.4). Are the absolute wallclock
timestamps required for replay/sybil (consumed-index sets + counts would seem to suffice), or can they be
coarsened/dropped? On joint seizure of `.ratchet_registry.json` + `reports.json`, is there *any* timing/
ordering/count correlation that re-joins identity to reports? *Matters because* it bounds exactly how much
"une saisie n'expose rien" concedes on the server's hardest surface.

### Tier 3 — Important (bounded scope, but real data-loss or assurance gaps)

**Q9. Is the encrypted `.strm` durable before its plaintext source is destroyed?**
*Domains: 07 (capture).* Does `strmEncryptFile` (Rust) `sync_all` the output `.strm` before `encryptChunk`
secure-deletes the plaintext MP4 (07 §2.2 Q1, §2.12 Q1)? If not, a power-loss/crash in that window
destroys the only copy of that chunk — the one place the "never silently lose a chunk" invariant could
break *by construction*. *Matters because* it is a pure-correctness flaw that would lose irreplaceable
testimony with no adversary involved.

**Q10. Can the client detect a relay that acks-and-drops, or a permanently-broken `.so`, before the TTL
eats the evidence?**
*Domains: 07 (capture), 08 (server).* Retry-never-fail assumes the relay is honest about 2xx/507 and a
healthy build will eventually run. There is no client-side read-back confirming persistence (07 §2.5 Q1,
08 §2.1), no covert-mode signal that uploads are stuck (notifications off, 07 §2.5 Q2), and a permanently-
broken binding retries into the 48 h TTL (07 §2.3). *Matters because* the witness can believe evidence was
safely relayed when it was silently dropped.

**Q11. Is the off-host break-glass recovery real and rehearsed?**
*Domains: 04 (transport), 08 (server).* Verify the `MUb4HH` private key is genuinely absent from
repo/relay/on-relay backups, that the dormant break-glass cert validates when served (EKU/keyUsage/
SAN=domain), and that the seizure cutover (new relay + DNS re-point) has been *rehearsed end-to-end*, not
just written (04 §2.5). *Matters because* its first real use is under maximum pressure (post-seizure), and
the deploy domain's backup timer was **never actually deployed on Vultr** (08 §2.9) — operational reality
lags the runbook.

**Q12. Single-worker as correctness anchor and availability single-point — and the unrate-limited PUT.**
*Domains: 08 (server).* Audit for any hot-path blocking I/O left on the event loop (which under one worker
stalls *all* clients, 08 §2.10), and confirm the app-layer-unauthenticated `PUT /file/...` is bounded only
by nginx + the write-sig gate such that a flood of invalid-sig PUTs is rejected cheaply before any MinIO
round-trip (write-once read-back amplification, 08 §2.7). *Matters because* the drain being a single
process is a DoS magnet for a tool whose point is "get data off the phone fast."

**Q13. PIN brute-force economics and the lockout's tamper-resistance.**
*Domains: 05 (key mgmt).* A 6-digit PIN is ~20 bits; Argon2id (256 MiB, t=4) is a speed bump, and the
*real* defense is the Kotlin `PinAttemptTracker` lockout — can it be reset by clearing SharedPreferences /
reinstalling while the sealed blobs survive (05 §2.5)? Could a TEE-sealed salt make an *offline* blob
(relay backup, exfiltrated `filesDir`) uncrackable without the device, without re-introducing the
"TEE owns the key" anti-pattern? *Matters because* an offline-crackable sealed blob plus Android
auto-backup (R-C-2) turns a local speed bump into a remote one.

### Tier 4 — Worth probing (mostly confirm-the-claim)

- **Q14. Promote the BIP-39 passphrase ("25th word") to optional onboarding** for the high-coercion user —
  what is the UX/data-loss trade (05 §2.1)? The only compartmentalization lever, currently under-surfaced.
- **Q15. Are all HKDF context strings byte-identical** across Rust core, Kotlin, the CLI rescue tool, and
  the server (05 §2.3)? A silent drift is an *unrecoverable-archive* bug, not just a verify failure.
- **Q16. Plaintext-on-flash residue.** Quantify the true max plaintext-on-disk window under encryption-
  thread backlog (07 §2.1 Q1), confirm FBE is active (not FDE/legacy) on the device matrix (07 §2.12 Q2),
  and confirm no chunk MP4 is finalized but never secure-deleted (07 §2.1 Q2).
- **Q17. Re-run the zeroize tripwire on the exact shipped toolchain + fat-LTO** (02 C2, 05 §2.8), and is it
  actually run before each release given dormant CI? Extend the IR check to the other five secret types.
- **Q18. MAX_RETRIES=3 + 48 h TTL risk posture for irreplaceable evidence** (07 §2.9) — coercion wants fast
  deletion, "only copy of a war-crime recording" wants near-infinite retention; these conflict and the
  trade is currently fixed, not configurable.
- **Q19. Salamander wire realism + PSK rotation.** Does uniform-random-XOR'd QUIC survive a modern
  statistical/ML classifier, or does packet-size/timing still betray it (04 §2.2)? What is the post-launch
  PSK rotation cadence/delivery (it needs an APK push), and does the server front accept overlapping PSKs
  (04 §2.3)?
- **Q20. Process-global session-secret state machine.** Dedicated review of the clear-trigger matrix
  (lock/panic/auto-lock, never-on-401) for `PIN_SESSION`/`UPLOAD_JWT` — any reallocation that copies the
  old key before wiping, any poison-recovery path leaving a stale key (05 §2.7, 06 C3).
- **Q21. JWT_SECRET blast radius + backup reachability** (08 §2.5) — confirm a forged HS256 stream JWT
  (no per-report key) can do no more than budget-bounded report creation, and that `JWT_SECRET` is never in
  the state tarballs / off-host backups (which for the identity-bearing registry are themselves a privacy
  surface the README defers encrypting, 08 §2.9).
- **Q22. Model↔code fidelity at the proof seams** (02 C8) — TLA+ BatchSize=3 "structural ⇒ 50" is informal
  (worth a one-off TLC at 50); Tamarin's server oracle is hand-transcribed from `auth_v2.py` (timestamp
  skew, consumed-index enforcement on rotation signers); Kani does *not* cover the ratchet.

---

## 6. Suggested audit methodology

Given this rationale layer already exists, an external auditor should *not* re-derive the threat model or
re-discover the design intent — that work is done and cited. Spend the days differently:

1. **Audit the code at HEAD, not the prior findings lists.** The reports flag that the 2026-06-26 audit's
   R-CR-1/R-CR-3 cite `pin_store_open_extended` / `ratchetDerivedKey` that the *later* Lot 4b no-export
   migration **retired** (05 §3). Several "accepted residual" citations point at code that no longer
   exists. Treat every prior finding as a hypothesis to re-test against current source, not a fact.

2. **Start by reconciling the two doc-vs-code divergences (4.1).** The SNI/no-SNI drift and the release-
   transport comment are the cheapest high-value findings: they tell you the threat-model *documentation*
   is not fully synced to the *implemented* boundary, which calibrates how much to trust every other prose
   claim. Adopt the project's own rule — code wins — and grep the live config rather than reading the doc
   (08 §2.1 Q1, 03 C3 Q2).

3. **Verify the bets, don't re-list features.** The four load-bearing bets (§2) are the audit's spine.
   Tier-1 audit questions (Q1–Q4) map one-to-one onto BETs A–D. If those four hold, the design holds; if
   one cracks, a whole stratum falls. Allocate the majority of effort there.

4. **Attack the seams between domains, not the centers.** The per-domain reports already steelman each
   choice in isolation. The unexplored surface is the *intersections*: the metadata seam (C2↔C6 in 01: a
   fixed destination + an upload envelope tracking the recording envelope re-derives a per-`report_id`
   timeline); the C4+C8 timing join on the server (Q7/Q8); the obfuscation↔fallback↔SNI triple on the
   degraded path (Q1); resilience-defers-the-wipe vs panic-wipe (Q3). Cross-domain correlation is where
   "n'expose rien" most plausibly leaks.

5. **Distinguish "proven model" from "shipped binary," and check the proofs are *executed*.** The crypto
   has five machine-checked proofs (02 C8) — but TLA+ uses BatchSize=3, Tamarin one slot + perfect crypto +
   a hand-transcribed server oracle, Kani doesn't cover the ratchet, and *none runs in CI* (no remote). Do
   not re-prove what is proven; instead pressure-test the **seams** (Q22) and confirm the **execution
   context** (Q6): are diff-fuzz/KAT/`checkRustSoFresh`/zeroize-tripwire actually run against fresh
   artifacts on the path that builds the published APK, or are they green-once-locally?

6. **Treat the operational layer as the weakest stratum (BET D).** No reproducible build (binary
   provenance, Q6); dormant CI so every gate is a manual discipline (Q5/Q6/Q17); the off-host backup timer
   never deployed and the break-glass cutover unrehearsed (Q11, 08 §2.9). For a state-adversary tool, the
   gap between "the design is sound" and "the shipped/deployed instance matches the design" is the realistic
   attack surface. Spend real time on the build/deploy pipeline, not just the algorithms.

7. **Demand the negative proofs.** The honest residuals (§4.3) are accepted *because* of downstream
   guarantees — forward secrecy makes R-D-1 past-safe; the archive key being phrase-only makes a cracked
   PIN past-safe. These are *negative* claims ("X cannot reach the past"). Ask for them explicitly (Q4):
   enumerate every current-session secret and show none decrypts/re-addresses a past blob; enumerate every
   `with_bytes`/`.to_vec()` exit from a `LockedSecret`/`Zeroizing` and show each destination is wiped
   (05 §2.10 Q1). A residual is only honest if its backstop is provable.

8. **Where the design concedes, weigh the concession against the *real* user population, not the abstract
   threat.** Several conceded residuals (destination visibility / Tor exclusion, 04 §2.8; metadata
   timeline, 01 C2; 6-digit PIN, 05 §2.5; MAX_RETRIES=3, 07 §2.9) are defensible *for some* users and wrong
   *for others*. The auditor's value-add is to say *which field profiles* the concessions endanger — the
   reports cannot, because they steelman the design as built, not the user as situated.

---

### Plain-text recap

The load-bearing bets the whole system rests on: (A) the 12-word paper phrase is the sole root and
genuinely off-device — strength and single-point-of-total-failure at once; (B) forward secrecy is real at
the byte level, so a *seized* (locked/wiped) device exposes no past (wipes proven not-DSE'd, chain
one-wayness assumed); (C) the relay is blind at rest and its only identity residual is a count, not a map;
(D, weakest) the shipped artifact equals the audited artifact and the channel stays up — but there is no
binary provenance, CI is dormant, obfuscation holds only while UDP is open, and the off-host backup/
break-glass are unrehearsed. Two doc-vs-code divergences were found: the docs still sell a raw-IP/no-SNI
design while the code ships a cleartext-SNI domain, and a stale comment claims release uses DirectTls when
it defaults to ObfQuic.

Top-5 consolidated audit questions, ranked by leverage:
1. Can a state force the unobfuscated, self-identifying downgrade by blocking UDP/443 (collapses ObfQuic +
   leaks the SNI), and should a high-risk profile fail-closed?
2. Is the blind-relay at-rest boundary airtight against the transient `sub=pk` creation moment and the
   exception/log channel that two prior audits missed?
3. Does explicit panic-wipe unconditionally preempt every resilience deferral, and can a leaked in-flight
   counter / livelock strand auto-lock forever?
4. Produce the negative proof that no current-session secret reaches a past archive, and confirm the live
   50-key batch is sealed (not cleartext-on-disk, not swappable) before wipe.
5. Is the audited artifact the shipped artifact — bindings/`.so` fresh, parity machinery executed against
   fresh artifacts, and is there any binary provenance at all (vs pin-string presence only)?
