//! Property-based tests for the ephemeral ratchet — round-trip identity of the
//! serialized form, and state-machine invariants over random operation
//! schedules.
//!
//! Where this sits among the existing checks:
//! - The **TLA+ model** (`docs/TLA_RATCHET.md`) proves the *abstract* FSM
//!   (monotone batch / use-once / anti-replay) exhaustively. These proptests
//!   check the *real Rust code* obeys that same discipline over randomized
//!   schedules — the model→code bridge.
//! - The **KAT parity tests** (`tests/parity_ratchet.rs`) pin fixed vectors.
//! - The **deserialize fuzz target** checks no-crash on arbitrary bytes.
//!
//! proptest adds the randomized *round-trip correctness* invariant with
//! deterministic shrinking to a minimal reproducer on any failure.

use frappuccino_crypto_core::ratchet::{EphemeralRatchet, BATCH_SIZE};
use proptest::prelude::*;

/// One scripted ratchet operation.
#[derive(Debug, Clone)]
enum Op {
    Sign,
    Advance,
}

fn op_strategy() -> impl Strategy<Value = Op> {
    prop_oneof![Just(Op::Sign), Just(Op::Advance)]
}

fn ops_strategy() -> impl Strategy<Value = Vec<Op>> {
    proptest::collection::vec(op_strategy(), 0..64)
}

fn fresh(chain0: [u8; 32]) -> EphemeralRatchet {
    let mut seed = chain0;
    let mut r = EphemeralRatchet::new();
    r.initialize(&mut seed).expect("initialize");
    r
}

proptest! {
    // Deterministic (fixed seed); any failure is persisted to
    // proptest-regressions/ and shrunk to a minimal reproducing case. Cases are
    // kept modest because each `advance` derives a fresh 50-key batch (Ed25519
    // keygen) in a debug build; bump via PROPTEST_CASES for a deeper sweep.
    #![proptest_config(ProptestConfig { cases: 64, ..ProptestConfig::default() })]

    /// The real ratchet's observable state machine matches the modelled FSM:
    /// `sign_and_advance` consumes the next slot of the current batch (index =
    /// number already consumed) and decrements the remaining count;
    /// `advance_batch` rotates to a fresh full batch and increments the batch
    /// number; operating on an exhausted batch errors and never panics.
    #[test]
    fn ratchet_state_machine_invariants(chain0 in any::<[u8; 32]>(), ops in ops_strategy()) {
        let mut r = fresh(chain0);
        prop_assert_eq!(r.batch_number(), 0);
        prop_assert_eq!(r.remaining_in_batch(), BATCH_SIZE);

        for op in &ops {
            match op {
                Op::Sign => {
                    let rem = r.remaining_in_batch();
                    let batch = r.batch_number();
                    let res = r.sign_and_advance(b"message");
                    if rem == 0 {
                        prop_assert!(res.is_err(), "sign on an exhausted batch must error");
                    } else {
                        let sig = res.expect("sign on a non-empty batch must succeed");
                        prop_assert_eq!(sig.batch_number, batch);
                        // First available slot = number already consumed this batch.
                        let idx = BATCH_SIZE - rem;
                        prop_assert_eq!(sig.key_index, u32::try_from(idx).unwrap());
                        prop_assert_eq!(r.remaining_in_batch(), rem - 1);
                        prop_assert!(r.is_consumed(idx).unwrap());
                    }
                }
                Op::Advance => {
                    let rem = r.remaining_in_batch();
                    let batch = r.batch_number();
                    let res = r.advance_batch();
                    if rem == 0 {
                        // advance_batch must consume one slot to sign the rotation,
                        // so a fully-exhausted batch cannot rotate (by design).
                        prop_assert!(res.is_err(), "advance on an exhausted batch must error");
                    } else {
                        let proof = res.expect("advance on a non-empty batch must succeed");
                        prop_assert_eq!(proof.signer_batch_number, batch);
                        prop_assert_eq!(proof.new_batch_number, batch + 1);
                        prop_assert_eq!(r.batch_number(), batch + 1);
                        // A fresh batch is full again.
                        prop_assert_eq!(r.remaining_in_batch(), BATCH_SIZE);
                    }
                }
            }
        }
    }

    /// `serialize` → `deserialize` preserves the full observable state, and the
    /// re-serialization is byte-identical: the round-trip is a true identity on
    /// the wire form. Exercises the consumed-mask bit-packing across every bit
    /// position (the off-by-one class that 8.4.3 mutation testing surfaced).
    #[test]
    fn ratchet_serialize_roundtrip(chain0 in any::<[u8; 32]>(), ops in ops_strategy()) {
        let mut r = fresh(chain0);
        for op in &ops {
            match op {
                Op::Sign => { let _ = r.sign_and_advance(b"m"); }
                Op::Advance => { let _ = r.advance_batch(); }
            }
        }

        let blob = r.serialize().expect("serialize");
        let r2 = EphemeralRatchet::deserialize(&blob).expect("deserialize must round-trip");

        prop_assert_eq!(r2.batch_number(), r.batch_number());
        prop_assert_eq!(r2.remaining_in_batch(), r.remaining_in_batch());
        for i in 0..BATCH_SIZE {
            prop_assert_eq!(
                r2.is_consumed(i).unwrap(),
                r.is_consumed(i).unwrap(),
                "consumed bit {} diverges after round-trip", i
            );
        }

        let blob2 = r2.serialize().expect("re-serialize");
        prop_assert_eq!(blob2, blob, "serialize must be idempotent across a round-trip");
    }
}
