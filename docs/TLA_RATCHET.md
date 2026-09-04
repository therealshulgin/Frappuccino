# TLA+/TLC — ratchet FSM (ROADMAP 8.4 item ④)

**Date:** 2026-08-28 · **Result: model checking completed, no error, 2800 distinct states, exhaustive.**

> **Re-vérifié 2026-06-29** (HEAD `fc1560c`, TLC natif Java 17) : **model checking completed, no error —
> 4680 états distincts** (7605 générés, 0 en file), exhaustif — identique à la baseline.

## What this proves and where it sits

The formal-methods plan (`docs/invariants-ratchet-verification.md`, Partie 2) assigns
the **state-machine layer (§C)** to TLA+/TLC: model the ratchet's finite-state
machine and check, *exhaustively over every interleaving*, the ordering invariants
— monotone counters, no rollback, bounded slots, anti-replay. This is a **design**
proof (the model), complementary to the **code** proofs already shipped: Kani ③
(`parse_header` no-panic) and the zeroize-audit ① (compiler-IR wipe). The
*model→code gap* principle: each layer proves a different thing.

`crypto-rs/core/proofs/EphemeralRatchet.tla` models the `EphemeralRatchet`
(`crypto-rs/core/src/ratchet.rs`): batches of `BatchSize` ephemeral Ed25519 slots,
each slot signed at most once (its private key wiped on use), `advance_batch`
rotating to a fresh batch (wiping the outgoing private keys + old chain key,
incrementing `batch_number`).

## The state machine

| Element | Model | ratchet.rs |
|---|---|---|
| `batch` | current batch number (monotone) | `batch_number` |
| `consumed` | set of slot indices used in the current batch | `consumed: [bool; 50]` |
| `signCount` | per-`(batch, slot)` sign count (history) | (implicit: a wiped slot can't re-sign) |
| `Sign(i)` | guard `i ∉ consumed` → consume + record | `sign_and_advance` → `consume_index` wipes `private_keys[i]` |
| `Advance` | `batch' = batch+1`, `consumed' = {}` | `advance_batch` (wipes old keys + chain) |

## Invariants checked (all hold)

| Invariant | §C/§D property | Meaning |
|---|---|---|
| `MonotoneBatch` (temporal `[][batch'>=batch]`) | monotonicité des compteurs / d'epoch | `batch_number` never decreases on any step. |
| `AntiReplay` | anti-rejeu | No `(batch, slot)` pair is ever signed twice. |
| `NoRollback` | absence de rollback | Every signed pair belongs to a batch ≤ the current one — no reaching back into a past batch (nor ahead into a future one). |
| `BoundedBatch` | gestion bornée | At most `BatchSize` slots consumed per batch (the real ratchet must `advance_batch` once the 50 are exhausted). |
| `ConsumedWiped` | effacement / use-once | The `consumed` mask faithfully records every sign in the current batch — the bookkeeping the anti-replay guard relies on. |

TLC explores **2800 distinct states** (`BatchSize = 3`, `MaxBatch = 3`) and finds no
violation. The bounds are small on purpose — the invariants are *structural* (they
do not depend on the slot count), so holding at 3 means holding at the real 50.

### The check is not vacuous (negative control)

Deleting the use-once guard (`i ∉ consumed`) from `Sign` — i.e. allowing a slot to
be signed while its key should already be wiped — makes TLC immediately report
`Invariant AntiReplay is violated` with a concrete counterexample trace. The guard
restored, the model passes. So the green result reflects the guard actually doing
its job, not an under-constrained model. (Same discipline as the zeroize negative
test and the cargo-mutants spot-checks.)

## How to run

TLC is pure Java, so this runs anywhere with a JRE — **Windows, Linux, macOS; no
WSL needed** (unlike Kani ③ and Tamarin ⑤). From the repo:

```bash
crypto-rs/core/proofs/run-tlc.sh
```

It downloads `tla2tools.jar` (the TLC model checker, ~2 MB) into `.tools/` on first
run (gitignored), then checks `EphemeralRatchet.tla` against `EphemeralRatchet.cfg`.
Baseline 2026-08-28: **no error, 2800 distinct states** (TLC 2.19).

The count dropped from the 4680 of the 2026-06-06 baseline, and the drop is the
point rather than a regression. `Sign` gained the RESERVE guard
(`Cardinality(consumed) < BatchSize - 1`), which mirrors `sign_and_advance`
refusing the last slot of a batch, so the states where a batch is signed to
exhaustion are no longer reachable. Fewer reachable states because the code
reaches fewer states.

The invariant that guard buys is `RotationAlwaysPossible`: a batch is never
consumed to the point where `Advance` is disabled, so the device can always
rotate out of the batch it is in. Before the reserve, a run of failed
authentications could drain all the slots (a failure consumes its slot anyway),
and a device with none left can neither authenticate nor rotate while the relay
refuses to re-enroll a known identity. Negative control, run 2026-08-28: remove
the guard from `Sign` and TLC reports `Invariant RotationAlwaysPossible is
violated`, so the invariant is load-bearing and not vacuously true.

## Scope / limits

- **State-machine only.** TLA+/TLC here proves the *ordering / use-once / monotonicity*
  discipline of the FSM. It does **not** model the cryptography — secrecy, forward
  secrecy, post-compromise security, key authentication under an active attacker —
  which is the Dolev-Yao symbolic layer assigned to **Tamarin (item ⑤)**.
- `CHECK_DEADLOCK FALSE`: the bounded model's terminal state (`batch = MaxBatch` with
  every slot consumed) has no enabled action — that is the finite cap, not a
  liveness bug; the real ratchet would just `advance_batch` again.
- The model abstracts the chain-key derivation and the AEAD; those are covered by
  the KAT parity tests, the boundary tests, and (for the chain/derivation one-wayness)
  remain a Tamarin/CryptoVerif concern.

## Status

ROADMAP **8.4 item ④ (TLA+/TLC)** — Done for the ratchet FSM. Next: **⑤ Tamarin**
(protocol-level secrecy/FS/PCS/auth under Dolev-Yao — needs Linux/macOS).
