# Zeroize audit — `EphemeralRatchet` secret wipe (ROADMAP 8.4.2 part 2)

**Date:** 2026-06-06 · **Verdict: PASS — no dead-store elimination of any secret wipe.**

> **Re-vérifié 2026-06-29** (HEAD `fc1560c`) : **PASS** — opt-level=s : 2 appels `zeroize::Zeroize`
> (wipe out-of-line) ; opt-level=2 : 36 `store volatile` (wipe inliné) ; 0 `llvm.memset` non-volatile
> aux deux niveaux. Aucune dead-store elimination du wipe secret.

## Why this exists

cargo-mutants leaves one inherent survivor on `EphemeralRatchet`: the `Drop::drop`
body mutated to a no-op (`drop -> ()`). It is **unkillable in safe Rust** — a `Drop`
body cannot be observed without reading freed memory (UB), so no unit test can
distinguish "wipes on drop" from "does nothing on drop". That gap is the *whole*
security property of the on-drop wipe. The only oracle that can close it is a
**deterministic compiler-IR check**: does the emitted machine code actually perform
the zeroization, and does the optimizer keep it?

This audit answers that with LLVM IR evidence, and ships an **executable regression
tripwire** so the answer stays true.

## What was audited

The `frappuccino-crypto-core` crate (the project's sensitive crypto is 100% Rust).
Run with the Trail of Bits `zeroize-audit` plugin (source pass → MIR/LLVM IR/ASM
pass at O0/O1/O2), then independently spot-checked by hand. Full plugin output is
archived under [`docs/archive/zeroize-audit-ratchet-2026-06-06/`](archive/zeroize-audit-ratchet-2026-06-06/)
(`final-report.md`, `findings.json`, compiler/source notes, sensitive-objects inventory).

Primary target: `core/src/ratchet.rs` — `EphemeralRatchet::zeroize_secrets()` (line
483), which wipes `private_keys: [[u8;64];50]` (3200 bytes) + `next_chain_key:
Option<[u8;32]>`. It is the single audited wipe path, shared by `wipe()` and
`Drop::drop` (drop tail-calls it).

## The decisive evidence

The crate wipes via the canonical `zeroize` crate (`Zeroize::zeroize`, `Zeroizing<T>`,
`ZeroizeOnDrop`), which lowers to `ptr::write_volatile(0)` + `compiler_fence(SeqCst)` —
volatile stores are **never** dead-store-eliminated by LLVM, by contract.

**At opt-level=2** (the methodology's DSE-aggressive diagnostic) the whole `zeroize`
chain inlines into `zeroize_secrets`, and the volatile stores not only survive but
*multiply* with optimization — the inverse of a DSE signature:

| `store volatile i8 0` | O0 | O1 | O2 |
|---|---|---|---|
| module-wide (independently grep-verified) | 2 | 58 | **2440** |
| inside `zeroize_secrets` body | 0¹ | — | **36** |
| non-volatile `memset` on any secret byte | 0 | 0 | **0** |

¹ At O0 the wipe is out-of-line in `core::ptr::write_volatile` (2 shared stores via a
loop). At O2 `zeroize_secrets` emits a nested **volatile** loop over `private_keys`
(outer bound `icmp eq i64 …, 3200`; inner over 64 bytes, unrolled ×4) plus 32 unrolled
`store volatile i8 0` for `next_chain_key`, each followed by `fence syncscope("singlethread")
seq_cst`. `Drop::drop` `tail call`s the same function. (Verified by reading the emitted
`.ll` directly, not just the analyzer's count.)

All six sensitive objects pass: `SO-5001 EphemeralRatchet`, `SO-5002 EnrollmentKit`,
`SO-5003 ArchiveIdentity`, `SO-5004 LockedSecret`, `SO-5005 SecretBytes`, `SO-5006 Seed`
— every one wiped with `store volatile`, zero non-volatile memset on any secret byte.

### Shipping-profile nuance (not covered by the plugin's O0/O1/O2 run)

The APK ships `[profile.release]` with **`opt-level = "s"`** (size) + `lto = "fat"`,
**not** O2. At `opt-level=s` the picture looks alarmingly different at first glance:
`zeroize_secrets`'s body has **zero** inlined `store volatile` and the crate-wide
volatile-store count is **0**. That is **not** elimination — size-opt declines to
inline/unroll the wipe, so the body instead holds out-of-line **calls** to
`<core::slice::iter::IterMut<Z> as zeroize::Zeroize>::zeroize` (for `private_keys`) and
`<[Z; N] as zeroize::Zeroize>::zeroize` (for `next_chain_key`, `dereferenceable(32)`).
The actual `store volatile` lives in the leaf `write_volatile`, emitted in another
codegen unit and linked in by LTO. Still a real volatile wipe; still un-DSE-able. There
is **zero** non-volatile `memset` on the secret at `opt-level=s` either.

The consequence matters for tooling: a naive `grep 'store volatile'` would **false-fail
on the very profile that ships**. The guard below checks the profile-robust invariant.

## Executable oracle (regression tripwire)

[`crypto-rs/core/audit/assert_zeroize_not_dse.sh`](../crypto-rs/core/audit/assert_zeroize_not_dse.sh)
— stable toolchain, no nightly (`--emit=llvm-ir` is stable). Run from anywhere:

```bash
bash crypto-rs/core/audit/assert_zeroize_not_dse.sh
```

It re-emits the core crate's LLVM IR at **opt-level=s** (what ships) and **opt-level=2**
(DSE-aggressive) and asserts the profile-robust invariant on `zeroize_secrets`'s body:

> the wipe is via `zeroize::Zeroize`  ⇔  the body contains **either** inlined
> `store volatile` (aggressive-opt form) **or** a `call` to a
> `zeroize::Zeroize::zeroize` monomorphization (size-opt form).

A regression that swaps `.zeroize()` for `= [0; N]` / `.fill(0)` lowers to a
non-volatile memset / plain stores with **neither** signature → the invariant fails →
exit non-zero.

**Validated both ways (2026-06-06):**
- On the real code: `PASS` — `opt=s` body has `zeroize-calls=2`; `opt=2` body has
  `store-volatile=36`; both `non-volatile-memset=0`.
- Negative control: temporarily regressing `zeroize_secrets` to `*sk = [0u8; N]` makes
  the compiler eliminate the function entirely (`defined=0`, all counts 0) at both
  levels → guard `FAIL` (exit 1), then reverted. The tripwire fires.

## Findings triage

**0 confirmed, 0 likely.** The plugin emitted 29 `needs_review` advisories; all are
MIR-pattern hints ("verify cleanup on unwind/Err path") on short-lived **stack** locals
in key *derivation* (`bip39::mnemonic_to_seed` `seed_bytes`; `identity` `sha256` closure
`ed_seed_arr`/`x_seed`) — **not** the ratchet wipe. Each local is `Zeroizing`-wrapped in
source (so its drop glue runs the volatile wipe on every path, unwind included) and each
advisory is explicitly contradicted by the decisive IR PASS layer. The MIR text matcher
doesn't model that `Zeroizing::drop` runs on unwind; they are retained only for auditor
traceability. PoC generation was therefore skipped (no confirmed/likely finding to
prove, and a safe-Rust PoC cannot observe post-drop stack memory without UB).

## Scope / honest limits

- Evidence is **per-crate LLVM IR**, pre-LTO. Final-binary DSE is precluded by the LLVM
  volatile contract (LTO preserves volatile), not separately dumped here.
- The guard proves the wipe is *present and volatile-or-out-of-line-call*; it is a
  regression tripwire, not a proof the bytes are unreachable from elsewhere in the
  address space (stack/register copies of derived material are a separate, source-level
  concern, covered by the `Zeroizing` temporaries and the clean source pass).
- ASM-level findings were not promoted (`rustfilt` absent → corroboration-only).

## Status

ROADMAP **8.4.2 part 2** (zeroize-audit plugin / formal-suite item ①) — **Done**. Closes
the compiler-level coverage of the inherent cargo-mutants `drop -> ()` survivor.
