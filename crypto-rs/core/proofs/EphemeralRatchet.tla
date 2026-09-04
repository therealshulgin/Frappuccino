-------------------------- MODULE EphemeralRatchet --------------------------
(***************************************************************************)
(* Bounded TLA+ model of Frappuccino's EphemeralRatchet finite-state       *)
(* machine (crypto-rs/core/src/ratchet.rs) — ROADMAP 8.4 item 4.           *)
(*                                                                         *)
(* The ratchet publishes batches of `BatchSize` ephemeral Ed25519 slots.   *)
(* Within a batch a slot is signed AT MOST ONCE — its private key is wiped  *)
(* on use (`sign_and_advance` -> consume_index zeroizes private_keys[i]).   *)
(* When the batch is exhausted, `advance_batch` derives the next batch from *)
(* the chain key, wipes the outgoing batch's private keys + the old chain   *)
(* key, and increments `batch_number`.                                     *)
(*                                                                         *)
(* TLC checks, exhaustively over every interleaving up to the bounds, the   *)
(* §C/§D state-machine invariants from                                      *)
(* docs/invariants-ratchet-verification.md:                                *)
(*   MonotoneBatch  - batch_number never decreases (temporal).             *)
(*   AntiReplay     - no (batch, slot) pair is ever signed twice.          *)
(*   NoRollback     - a slot is only ever signed in the current batch;     *)
(*                    you can never return to a past (or jump to a future)  *)
(*                    batch.                                                *)
(*   BoundedBatch   - at most BatchSize slots are consumed per batch.       *)
(*   ConsumedWiped  - the consumed mask faithfully records every sign in    *)
(*                    the current batch (the use-once / erase mechanism).   *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS BatchSize,   \* slots per batch (real ratchet = 50; small here so TLC is exhaustive)
          MaxBatch     \* finite bound on batch_number for model checking

ASSUME BatchSize \in Nat /\ BatchSize >= 1
ASSUME MaxBatch  \in Nat /\ MaxBatch  >= 0

Slots   == 0 .. (BatchSize - 1)
Batches == 0 .. MaxBatch
Pairs   == Batches \X Slots

VARIABLES
  batch,        \* current batch_number (must only ever increase)
  consumed,     \* set of slot indices consumed (signed + key-wiped) in the CURRENT batch
  signCount     \* [Pairs -> 0..2]: number of times each (batch, slot) was signed

vars == << batch, consumed, signCount >>

TypeOK ==
  /\ batch \in Batches
  /\ consumed \subseteq Slots
  /\ signCount \in [Pairs -> 0 .. 2]   \* 0..2 so a (forbidden) double-sign is representable;
                                       \* AntiReplay is what asserts it never exceeds 1.

Init ==
  /\ batch = 0
  /\ consumed = {}
  /\ signCount = [p \in Pairs |-> 0]

\* Sign with (consume) a fresh slot of the current batch. The `i \notin consumed`
\* guard is the use-once mechanism: once a slot is signed its private key is wiped
\* (consume_index), so it can never be signed again within the batch.
\*
\* The second guard is the RESERVE (sign_and_advance, 2026-08-28): the last slot of
\* a batch cannot be signed, it is held for Advance. A failed authentication
\* consumes its slot anyway, so without this a run of failures drains the batch to
\* nothing, and at nothing the device can neither sign nor rotate while the relay
\* refuses to re-enroll a known identity. RotationAlwaysPossible below is the
\* property this guard buys; drop the guard and TLC falsifies it.
Sign(i) ==
  /\ i \in Slots
  /\ i \notin consumed
  /\ Cardinality(consumed) < BatchSize - 1
  /\ consumed' = consumed \cup {i}
  /\ signCount' = [signCount EXCEPT ![<<batch, i>>] = @ + 1]
  /\ UNCHANGED batch

\* Rotate to the next batch (advance_batch): increment batch_number, reset the
\* consumed mask. The outgoing batch's private keys and the old chain key are
\* wiped; in the model the outgoing batch becomes a *past* batch that Sign — which
\* only ever acts on the current `batch` — can never touch again, so its secrets
\* are forward-secure erased.
Advance ==
  /\ batch < MaxBatch              \* finite bound for exhaustive checking
  /\ batch' = batch + 1            \* strictly increasing
  /\ consumed' = {}
  /\ UNCHANGED signCount

Next == (\E i \in Slots : Sign(i)) \/ Advance

Spec == Init /\ [][Next]_vars

------------------------------------------------------------------------------
\* Invariants (state predicates) and the monotonicity property (temporal).

\* §C anti-rejeu — no (batch, slot) is ever signed more than once.
AntiReplay == \A p \in Pairs : signCount[p] <= 1

\* §C absence de rollback — every pair that was ever signed belongs to a batch
\* number <= the current one. Combined with MonotoneBatch this means a slot is
\* only ever signed in the then-current batch: no reaching back to a past batch,
\* no signing ahead into a future one.
NoRollback == \A p \in Pairs : (signCount[p] > 0) => (p[1] <= batch)

\* The consumed mask faithfully records every sign in the CURRENT batch — the
\* use-once / erase bookkeeping the anti-replay guard relies on.
ConsumedWiped == \A i \in Slots : (signCount[<<batch, i>>] > 0) => (i \in consumed)

\* §C/§D bornage — at most BatchSize slots consumed per batch (anti-DoS bound;
\* the real ratchet must call advance_batch once the 50 slots are exhausted).
BoundedBatch == Cardinality(consumed) <= BatchSize

\* The reserve — a batch is never signed to exhaustion, so Advance is enabled in
\* every reachable state and the device can always rotate out of the batch it is
\* in. This is the liveness-shaped guarantee the ratchet was missing: signing
\* could previously consume the last slot, and a device with no slot left can
\* neither authenticate nor rotate, which strands the enrollment for good (the
\* relay answers 409 to a re-enrollment of an identity it already knows).
\*
\* Stated as a safety invariant rather than a temporal property on purpose: TLC
\* checks it on every reachable state, and it is exactly the state predicate the
\* Rust guard enforces (`remaining_in_batch() <= 1` refuses).
\*
\* SCOPE, and read this before quoting the invariant as a device-level promise.
\* It is about `ratchet.rs`, not about the device. The Kotlin client adds a guard
\* this model does not have: it refuses to call `advance_batch` when its queue of
\* unconfirmed rotation proofs is full (MAX_PENDING_ROTATIONS = 8, in
\* StreamUploadManager). A device sitting on the reserve WITH a full queue can
\* therefore neither sign nor rotate: the very deadlock this invariant excludes,
\* reintroduced one storey up and outside the model. Reaching it takes roughly
\* 400 answered-but-failed authentications without a single success, so the
\* enrollment is lost by then anyway, and the guard only stops the ratchet
\* burning further batches for nothing. It is a documented residual (2026-09-03,
\* ARCHITECTURE_TECHNIQUE_COMPLETE section 4.2), not a proven property. If that
\* queue cap ever changes, this paragraph is what has to be re-read.
RotationAlwaysPossible == Cardinality(consumed) < BatchSize

\* §C/§D monotonicité — batch_number never decreases on any step.
MonotoneBatch == [][batch' >= batch]_vars
=============================================================================
