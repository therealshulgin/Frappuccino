# Tamarin — ratchet enrollment/rotation/auth protocol (ROADMAP 8.4 item ⑤)

**Date:** 2026-06-06 · **refreshed 2026-06-12 (R-C-1)** · **Phase C relay-blind
(3.4b): archive-scope flow removed** · **Result: all 10 lemmas verified**
(tamarin-prover 1.12.0, Maude 3.5.1), ~4–6 s, terminating. Two negative controls
falsify as expected. (Was 11 lemmas + 3 controls before Phase C retired the
archive-auth flow — see the §2 finding below.)

> **Re-vérifié 2026-06-29** (HEAD `fc1560c`, WSL ; tamarin-prover 1.12.0 / Maude 3.5.1) :
> **les 10 lemmes vérifiés (7.40 s, terminating) + les 2 contrôles négatifs falsifient**
> (NC1 `auth_slot_origin` falsified, NC2 `rotation_authentic` falsified) — identique à la baseline.

## What this proves and where it sits

The formal-methods plan (`docs/invariants-ratchet-verification.md`, Partie 2)
assigns the **protocol layer (sections A / B / E)** to a symbolic Dolev-Yao
prover. Tamarin is the gold standard there — the Signal analyses (Cohn-Gordon et
al.) are in Tamarin. It models the protocol under an **active network attacker**
that controls scheduling, can inject/modify/replay messages, and can compromise
state on demand, then checks secrecy / authentication / anti-replay / forward
secrecy as **trace properties**.

This is the last of the four complementary §8.4 proofs — *each layer proves a
different thing* (the *model→code gap*):

| Layer | Tool | Proves |
|---|---|---|
| Compiler | zeroize-audit ① | the secret wipe is not dead-store-eliminated (LLVM IR) |
| Marshalling | diff-fuzz ② | Kotlin↔Rust byte-parity (759/759) |
| Code | Kani ③ | `parse_header` never panics; offsets keep caller slices in-bounds |
| State machine | TLA+ ④ | monotone batch / use-once mask / anti-replay (2800 states) |
| **Protocol** | **Tamarin ⑤** | **unforgeable enrollment, authenticated challenge-response, rotation lineage, key secrecy, forward secrecy — under an active attacker** |

Model: `crypto-rs/core/proofs/RatchetProtocol.spthy`. Sources of truth:
`core/src/ratchet.rs` (`sign_and_advance`, `advance_batch`/`RotationProof`),
`core/src/identity.rs` (`sign_once(message, domain)`),
`core/src/signature_domain.rs` (R-C-1: the explicit domain tags),
`stream/src/protocol.rs` (enroll / challenge / verify / rotate-batch), and the
**verifier** `server/app/routes/auth_v2.py` (the acceptance conditions = the
security oracle).

## The protocol that is modelled

The V2 design is a **batched forward-secure signature lineage** (Algorand-style
ephemeral keys), not a textbook DH double-ratchet — so the whole thing is
bespoke and worth proving. One long-term Ed25519 identity signs the batch-0
ephemeral keys *once* at enrollment; thereafter every batch is authenticated by
a signature from a slot of the **previous** batch (`RotationProof`), and every
upload/login is a fresh ephemeral signature over a server challenge.

| Step | Wire | Modelled rule |
|---|---|---|
| Enroll | `sign(concat(batch0_pks), ltk)` → server records batch-0 slots | `Device_Enroll` / `Server_Enroll` |
| Challenge | server → fresh `nonce` (+ stamped `ts`) | `Server_Challenge` |
| Verify | `sign(nonce‖ts, ephemeral)` → consume slot, issue JWT | `Device_AuthSign` / `Server_Verify` |
| Rotate | `sign(concat(new_batch_pks), current_slot)` → install next batch | `Device_Rotate` / `Server_Rotate` |
| Compromise | extract on-device ratchet state / identity key | `Reveal_Slot` / `Reveal_Ltk` |

Every signed message above carries an explicit **one-byte domain tag** (R-C-1,
`signature_domain.rs`): `0x01` AuthChallenge, `0x02` BatchRotation, `0x03`
Enrollment. The ephemeral slot is dual-use — it signs AuthChallenge **and**
BatchRotation — so the tag is what keeps one use from being replayed as the other
(see finding 2 below). **Phase C relay-blind retired `0x04` ArchiveAuth**: the
rescue device's archive reads are now identity-free (the phrase-derived
`report_id` is the capability), so the long-term key signs **only** enrollment —
it is no longer dual-use, and the `Device_ArchiveSign` / `Server_ArchiveAuth`
rules were removed.

## Lemmas (all verified)

| Lemma | §A/B/E | Property |
|---|---|---|
| `auth_reachable`, `rotation_reachable` | — | executability sanity (the honest flows can run) |
| `slotkey_secrecy` | A/B | an honest ephemeral slot key is never learned by the attacker unless that slot's state was revealed |
| `ltk_secrecy` | E | the long-term identity key stays secret unless revealed |
| `auth_slot_origin` | B/E | a JWT is issued only against a genuine signature by the slot-key holder (unless the slot was compromised) — **authentication** |
| `nonce_use_once` | C/E | a server challenge authenticates **at most one** session — **anti-replay** |
| `rotation_authentic` | B/E | an accepted batch rotation was actually produced by the device holding the current slot key — **`RotationProof` unforgeability** |
| `rotation_lineage` | B/E | every accepted rotation's signer was itself already authorized (root or prior rotation) — by induction, **no rogue batch** |
| `root_authentic` | B/E | a root authorization of an honest identity implies that device's genuine enrollment (unless its ltk was revealed) — the **base anchor** of the lineage |
| `forward_secrecy_auth` | B | an auth accepted while its slot is uncompromised stays genuine even if that slot is revealed **later** — **forward secrecy** |

(Phase C removed `archive_auth_origin` together with the archive-scope flow — the
long-term key now signs only enrollment, so there is no archive JWT to anchor.)

Composed: `root_authentic` + `rotation_lineage` + `rotation_authentic` give the
headline guarantee — **every authorized batch of an honest identity chains back,
by genuine device-held signatures, to that device's own enrollment; an active
attacker cannot inject a forged or rogue batch.**

## Two findings the model surfaced

Formal modelling is most useful when it *refuses* an over-broad claim. Two did:

**1. Authentication is on the slot key, not the (identity, slot) pair (UKS).**
The first `auth_slot_origin` / `root_authentic` attempts were *falsified*: an
attacker can always enroll and authenticate **its own** identity (keys it
generated itself), so not every `ServerAccept` corresponds to an *honest*
device. The textbook fix — scope authentication lemmas to **honestly-generated
keys** — makes them hold. Note a residual unknown-key-share: nothing stops an
attacker from re-registering an honest device's *public* ephemeral key inside
its own batch. This transfers **no authority**: the challenge nonce is one-shot
(`nonce_use_once`) and only the slot's holder can produce signatures, so the
attacker gains nothing it could not already do as itself. Authentication is
therefore proven on the **slot key holder** (`auth_slot_origin`'s `idpk2`), which
is the meaningful guarantee.

**2. Signature safety depends on cross-context message separation — now explicit
(R-C-1), and on the long-term key removed entirely (Phase C).** With each batch
abstracted to one slot, the model first *falsified* `rotation_authentic`: one
ephemeral key signs both the auth challenge (`nonce‖ts`) and the rotation proof
(`concat(new_pks)`), so — if those two messages can coincide — an **auth
signature can be replayed as a rotation proof**. The same shape clash originally
existed on the **long-term key**, which signed both the enrollment (`concat(pks)`)
and the archive challenge (`nonce‖ts`). Originally the protocol separated each
pair only *implicitly*, by message length (40-byte `nonce‖ts` vs 1600-byte
`concat`); the model flagged that as the open finding.

> **Ephemeral pair closed by R-C-1 (commit `da56da4`); long-term pair removed by
> Phase C (3.4b).** Each signed message now carries an explicit one-byte domain
> tag (`core/src/signature_domain.rs`: `0x01` AuthChallenge / `0x02`
> BatchRotation / `0x03` Enrollment), prepended before signing and mirrored
> byte-for-byte by the server before verifying. The model's symbolic tags
> (`'auth'`/`'rotate'`/`'enroll'`) are a faithful 1:1 representation of that
> on-the-wire mechanism rather than a proxy for length, and **NC2** (collapse the
> ephemeral auth/rotate tags) re-falsifies `rotation_authentic`, proving the
> separation is genuinely load-bearing on the dual-use ephemeral key. The
> long-term half is closed even more strongly: **Phase C relay-blind made archive
> reads identity-free**, removing the `0x04` ArchiveAuth context entirely, so the
> long-term key now signs only enrollment — there is no second long-term context
> to replay into. The old NC3 control (which collapsed `'enroll'`/`'archive'` and
> falsified `root_authentic`) is therefore retired: the surface it demonstrated
> is gone by construction, and `root_authentic` still verifies.

## The proofs are not vacuous (negative controls)

`run-tamarin.sh negative` runs two controls; each removes a real mechanism and
the prover catches it (same discipline as the zeroize guard, the Kani break, and
the TLA+ anti-replay control):

| Control | Edit | Result |
|---|---|---|
| NC1 | drop the Ed25519 signature check in `Server_Verify` | `auth_slot_origin` **falsified** (9 steps) |
| NC2 | collapse the `'auth'`/`'rotate'` (ephemeral) domain tags | `rotation_authentic` **falsified** (8 steps) |

(NC3 — collapse the `'enroll'`/`'archive'` long-term tags → `root_authentic`
falsified — was retired in Phase C 3.4b along with the archive-scope flow: with
the long-term key signing only enrollment, there is no second context to
collapse.)

## How to run

Tamarin needs **Linux or macOS** (Haskell + Maude) — on Windows use **WSL**
(unlike TLA+ ④ which is pure-JVM Windows-native). From the repo, inside WSL:

```bash
crypto-rs/core/proofs/run-tamarin.sh            # prove every lemma
crypto-rs/core/proofs/run-tamarin.sh negative   # + the negative controls (NC1, NC2)
```

It downloads `tamarin-prover` 1.12.0 + Maude 3.5.1 into `.tools/` (gitignored) on
first run. GraphViz (`dot`) is not needed for batch proving. Baseline (refreshed
2026-06-12 for R-C-1; **Phase C 3.4b removed the archive flow**): **all 10 lemmas
verified**, processing time ~3–6 s.

## Scope / limits

- **One representative slot per batch.** The 50-slot multiplicity and the
  `consumed_mask` / `MAX_SKIP` bookkeeping are the finite-state concern proven
  exhaustively by **TLA+ ④** (2800 states). Here every slot key is an
  independent Ed25519 key — exactly what the Dolev-Yao layer needs.
- **Slot use-once is not a result of this model.** The claim "a slot is consumed by
  either an auth or a rotation, at most once" is stated by **no lemma**:
  `ConsumeSlot` appears in none of them, and the property survives only because
  `SlotAvail` is a *linear* fact. Make it persistent and all ten lemmas still verify
  while the server rotates one slot forever. On the rotation path it is outright
  falsifiable - three formulations were written and Tamarin falsified all three, the
  counter-example being rotate-to-self, which the relay reproduces. The `OPEN ITEM`
  block of `RatchetProtocol.spthy` records it in full, including the two ways to
  close it. `nonce_use_once` is a different property: it stops the same *nonce* from
  being accepted twice, not the same slot from being spent twice.
- **Symbolic, not computational.** Tamarin assumes perfect cryptography
  (signatures unforgeable, no hash collisions). Concrete reduction bounds on the
  KDF/AEAD are the CryptoVerif/EasyCrypt layer (not in scope for §8.4).
- **The ±30 s timestamp skew window** (`auth_v2.py`) only *tightens* an already
  one-shot nonce; it is a replay-window refinement with no symbolic content and
  is not modelled.
- **Not modelled here:** the symmetric chain-key one-wayness and AEAD
  associated-data binding (§A/§C in `invariants-ratchet-verification.md`) — those
  are the KAT/boundary tests and remain a CryptoVerif concern; this file covers
  the **signature-lineage protocol** (sections A/B/E).

## Status

ROADMAP **8.4 item ⑤ (Tamarin)** — Done; **refreshed 2026-06-12** to model the
explicit domain separation shipped in **R-C-1** (`da56da4`), then **Phase C 3.4b
(2026-06-26)** removed the archive-scope flow (identity-free relay-blind reads):
`Device_ArchiveSign` / `Server_ArchiveAuth`, the `archive_auth_origin` lemma, and
the NC3 long-term-tag control are gone, since the long-term key now signs only
enrollment. The audit's open "separation depends on message length" finding stays
closed — the ephemeral half by the explicit R-C-1 tag (NC2 load-bearing), the
long-term half by removal of the dual-use entirely. **10 lemmas verified, 2
negative controls falsify** (re-run 2026-06-26, WSL). This completes the
prioritised formal-methods suite ①→⑤ (zeroize-audit, diff-fuzz, Kani, TLA+,
Tamarin).
