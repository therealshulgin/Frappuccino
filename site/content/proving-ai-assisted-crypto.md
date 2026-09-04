+++
title = "I don't fully trust my AI pair programmer, so no security claim rests on its word"
description = "Formal methods as the compensating control for AI-written cryptography: how a security-critical, AI-assisted app anchors every claim to a replayable, non-AI oracle."
path = "writeups/proving-ai-assisted-crypto"
+++

> *Formal methods as the compensating control for AI-written cryptography.*

Frappuccino's cryptographic core is heavily AI-assisted and **not yet audited by
an external party.** Every number below is produced by a reproducible runner, and the
repository that holds them is public: [github.com/therealshulgin/Frappuccino](https://github.com/therealshulgin/Frappuccino). This piece is the argument for
why the code is worth auditing, and an invitation to do it.

## The uncomfortable premise

I build [Frappuccino](@/_index.md): an Android app for encrypted video testimony,
forked from Tella (Apache 2.0), for activists and journalists whose phone may be
seized, searched, or destroyed. A bug in the crypto here does not corrupt a
shopping cart. It can expose the identity of a witness. It is about as
security-critical as a solo project gets.

And it is heavily AI-assisted. Not "I autocompleted a few functions": the
cryptographic core, the protocol design, and the internal audits were all built
with an AI model as the primary pair programmer. I say this openly, because
hiding it would make everything else I claim untrustworthy.

So here is the question: **why would you trust security-critical code written
this way?**

My answer is one design rule, and then the machinery that enforces it:

> **No security claim rests on the model's judgment.** Every property that
> matters is anchored to a deterministic, replayable, non-AI oracle: a theorem
> prover, a model checker, a compiler-IR check, a differential test. The AI
> writes code and arguments; the oracle decides whether they hold.

Formal methods are usually sold as extra assurance on top of trusted code. Here
they play a different role. They are the *compensating control* for a generator
whose output cannot be trusted on faith. That reframing is the whole article.

## The tool, in two paragraphs

The phone is a transmitter, not a safe. Recording is cut into short chunks, each
end-to-end encrypted on-device and uploaded immediately to a **blind relay** that
stores only opaque blobs. It holds no key that can decrypt them and cannot read a
byte of content. The only secret that ever decrypts testimony is derived from a
twelve-word BIP-39 phrase, shown once and never stored on any machine. After
enrollment the device can encrypt and sign but can never decrypt its own past:
authentication uses a ratchet of single-use Ed25519 keys, each wiped right after
signing, so an adversary who seizes the unlocked phone gets at most a *bounded,
server-detectable window of future signatures* (every slot use is tracked;
revocation cuts it off), never past content.

The threat model and the honest list of what it does **not** protect live
[on the positioning page](@/positioning.md); this piece is about how the crypto
is verified, not what it is. The cryptographic core is 100% Rust with zero
hand-written `unsafe` outside one isolated, commented memory module
(`mlock`/`munlock` for long-term identity secrets, via `memsec`). The UniFFI glue
is generated code and carries its own lint allowance; the vetted dependencies
contain `unsafe`, as any crypto stack does. Primitives are standard and
pure-Rust: Ed25519 and X25519 (dalek), XChaCha20-Poly1305 for chunks and
XSalsa20-Poly1305 for the sealed session key (RustCrypto's NaCl-compatible
`crypto_box`), Argon2id, HKDF-SHA256, HMAC-SHA256, BLAKE2b. **I did not invent a
primitive.** What is new is the way they are composed, and that is what the proof
stack goes after.

## The proof stack, layer by layer

A cryptographic system can fail at three levels: the protocol design, the
implementation, and the compiler. Each level gets a tool with a deterministic
verdict. And the model-level and compiler-level proofs each ship with a
**negative control**: I break the mechanism on purpose and the tool *must* catch
it, because a proof that cannot fail proves nothing.

Throughout, "proven" means machine-checked in a stated model, not a computational
theorem. Where the model idealizes reality, the limits section below says so.

### 1. The protocol, Tamarin (symbolic, Dolev-Yao)

The model is `RatchetProtocol.spthy`. The adversary is full Dolev-Yao: controls
the network, injects, modifies and replays messages, and compromises device state
on demand.

**10 lemmas machine-checked**, 8 security properties plus 2 executability sanity
checks (a model whose honest flows cannot run would vacuously "prove" anything).
The load-bearing ones:

- `forward_secrecy_auth`: an authentication accepted *before* its signing slot is
  compromised stays authentic even if that slot is revealed *later*. This is
  forward security for *authentication*, the property the design exists for. It
  is not confidentiality forward secrecy; past *content* is unreadable for a
  different reason: the device never *persists* the X25519 reading key. It is derived
  from the phrase, in locked memory, only while an archive session is open, and the
  phone that did the recording never holds it at all.
- `rotation_authentic`, and `rotation_lineage` (proved by induction): a rogue
  batch cannot be injected; every accepted rotation traces back through a chain
  of authorized signers to the original enrollment.
- `nonce_use_once`: a server challenge authenticates at most one session
  (anti-replay, a linear fact consumed exactly once).
- `slotkey_secrecy`, `ltk_secrecy`, `root_authentic`, `auth_slot_origin`: slot
  and long-term key secrecy, and the anchoring of authorization to a real
  enrollment.

**2 negative controls**: remove the Ed25519 signature check in the server's
verify rule and `auth_slot_origin` is falsified in 9 steps; collapse the one-byte
domain-separation tags for auth versus rotation and `rotation_authentic` is
falsified in 8 steps. Both mechanisms are load-bearing, and the prover proves it
by breaking when they are removed.

Tamarin targets the **authentication and rotation protocol** specifically. The
data-format composition (chunking, truncation resistance, the nonce schedule) is
not a Tamarin lemma; it is covered by boundary tests, fuzzing and mutation
(below). What Tamarin deliberately leaves out and hands to the next layer is the
50-slot bookkeeping: in the symbolic model one representative slot per batch is
enough for the Dolev-Yao argument. Whether the real 50-slot consumed-mask can
ever reuse a key is a state-machine question, which is TLC's job.

### 2. The state machine, TLA+ / TLC (exhaustive within bounds)

`EphemeralRatchet.tla` models the ratchet as it behaves: `Sign(i)` consumes a
fresh slot of the current batch (guarded by `i ∉ consumed`), `Advance` rotates to
the next batch, increments the batch number and clears the mask. TLC explores
**2800 distinct states**: every interleaving up to the model bounds, exhaustively,
zero errors. The count came *down* from an earlier 4680, and the drop is the point:
`Sign` gained a guard mirroring the real ratchet's refusal to spend the last slot of a
batch, so the states where a batch is drained to exhaustion are no longer reachable.

Six state invariants hold across all of them. `AntiReplay` (no `(batch, slot)`
pair ever signed twice), `NoRollback` (no jump to a past or future batch),
`ConsumedWiped` (the mask faithfully records every signature), `BoundedBatch`
(at most `BatchSize` slots per batch), `RotationAlwaysPossible` (a batch is never
drained to the point where rotating out of it is disabled - the invariant the
reserved last slot buys), and `TypeOK`. A seventh property, `MonotoneBatch` (the
batch number never decreases), is checked as a temporal action property.

The config uses `BatchSize = 3`. TLC only proves the bounds it explores; the lift
to the real 50 is an *argument, not a machine check*: the invariants quantify over
slots and nothing in the transition relation does arithmetic on `BatchSize`, so if
use-once holds at 3 it holds at 50. That extrapolation is exactly the kind of gap
a human auditor should attack, and closing it with a parameterized proof
(TLAPS/Apalache) is future work, not done.

Negative control: delete the `i ∉ consumed` guard in `Sign` and TLC immediately
reports `AntiReplay violated` with a concrete counterexample trace. Restore the
guard, the model passes. Pure Java, no WSL.

### 3. The real implementation, Kani (bounded model checking)

Tamarin and TLC prove models. Kani proves the *actual Rust that ships*. Five proof
harnesses in `kani_proofs.rs`:

- `check_parse_header_rejects_any_grant`: no accepted header carries a grant. The
  multi-recipient section is reserved, not implemented, and this proves the parser
  *refuses* it rather than walking into it - the machine-checked counterpart of a
  design decision that would otherwise rest on a code review.

- `check_parse_header_never_panics`: over symbolic blobs of 0..=200 bytes, the STRM
  wire-format parser is panic-free, with no out-of-bounds, no arithmetic overflow,
  no `unwrap`/`expect` panic. This function touches attacker-controlled bytes
  first, so it is the one that must never panic on hostile input. The harnesses
  run **without** the `legacy-strm` feature, that is, in the configuration the
  Android `.so` ships: V3 is the only layout that resolves and a V1/V2 version
  byte is refused, so the property proven is the property of the shipped binary
  rather than of a superset build.
- `check_parse_header_postconditions_make_caller_slices_safe`: the parser's
  postconditions guarantee the three slices `decrypt()` later takes are in bounds.
  The proof carries safety across a function boundary.
- `check_deobfuscate_in_place_never_panics`: the Salamander transport
  de-obfuscation is panic-free for any claimed datagram length, proved over a
  fixed representative buffer (the harness documents why the panic surface depends
  only on the length relation, not on buffer size or content).
- `check_be_u16_big_endian_and_or_equals_xor`: a mutation-equivalence proof that a
  specific `|`-to-`^` mutant is unkillable (the bit ranges are disjoint), so a
  mutation-testing "survivor" there is provably a false alarm, not a gap.

Kani and the differential fuzzer do not ship a scripted negative control the way
the model-level and compiler-level proofs do; their assurance is the exhaustive
symbolic run and the corpus match, respectively.

### 4. The Kotlin/Rust boundary, differential fuzzing

The crypto is Rust, the app is Kotlin over UniFFI. A marshalling bug at that
boundary would be invisible to any single-language test. So the same five public
APIs are driven from both sides: a Rust dumper (`difffuzz_dump.rs`) and a Kotlin
harness over the real UniFFI bindings. Their outputs are compared: **759/759
outcomes identical** (5 APIs × 150 random inputs + 9 fixed edge cases: BIP-39
validation, identity fingerprint, ratchet serialize/deserialize, PIN-store unlock,
archive-from-mnemonic). Comparison is byte-for-byte for byte outputs and
field-by-field for error variants; the two languages' `Display` strings are
deliberately excluded, since they render independently.

### 5. The compiler, LLVM IR zeroization audit

This is the layer that best shows why the compiler is its own trust level.
Secret-wiping code is a dead store from the optimizer's point of view: the memory
is never read again, so LLVM is *entitled* to delete it. And when I handed it a
naive wipe as a negative control, it did exactly that. Swap `.zeroize()` for a
plain `.fill(0)` and the optimizer erases the entire wipe function from the IR.

`assert_zeroize_not_dse.sh` exists so the shipped wipe can never silently regress
to that. It re-emits the ratchet's `zeroize_secrets` LLVM IR at two optimization
levels and checks the wipe survives as either a `store volatile` or an out-of-line
call to `zeroize::Zeroize::zeroize`. The shipped code wipes through `zeroize`'s
volatile stores, which survive by contract; the audit confirms they actually do,
at the `opt-level=s` profile that ships. Honest scope: this is per-crate IR on the
host triple, pre-LTO. LTO preserves volatile stores by the same contract, but the
final aarch64 `.so` is not separately disassembled here.

### 6. The shipped binary, provenance gates

Proofs about source are worthless if a different binary ships. Two Gradle gates
bind the `.so` to its origin: `checkRustSoFresh` verifies the compiled library
actually contains the current TLS-pin values and QUIC PSK from source (no stale
rebuild), and `checkSoProvenance` recomputes the SHA-256 of each ABI's `.so`
against the `PROVENANCE.txt` manifest that the build itself writes. Swap in a
binary that does not match its commit and the build fails.

That manifest is deliberately not committed: it describes binaries that are not
tracked either, so a committed copy could only ever describe whichever machine
last built, which is exactly how the first public snapshot came to ship one
naming a private, dirty commit. The release workflow builds from a clean public
commit and publishes the manifest beside the `.so` it describes. Since signing
an APK does not alter its entry contents, the digests survive it: unzip
`lib/<abi>/libuniffi_frappuccino.so` out of a signed APK and it still matches.

This is commit-to-binary provenance, not reproducible-build provenance. A
from-source rebuild by a third party is the F-Droid track, and it is not done
yet.

Around all of this: property-based tests on the real ratchet, cross-language
known-answer vectors for every relay-verified signature domain (the Rust signer
and the Python relay agree byte-for-byte on all five), `cargo-fuzz` targets, and
`cargo-mutants`.

## The workflow that made it survivable

The proof stack is the *what*. The discipline is the *how*, and it is the part
most transferable to anyone shipping AI-assisted code: **the code is the source of
truth, never the agent.** Every finding from every automated review, including the
AI ones, is re-verified against the actual code before a single line changes.

This is not a slogan; it is a rule that earned its keep, because the AI reviews
caught real bugs *and* invented plausible-sounding ones at a rate that would sink
you if you acted on confidence instead of code. Concrete cases from real sessions:

- A finding was "confirmed" by two successive review passes, targeting code that
  had been deleted months earlier. Re-reading the tree, not the reviewer, killed
  it.
- An adversarial pass flagged a "50-second" timeout as a stall risk. The code:
  `dequeueInputBuffer(50_000L)`, which takes **microseconds**. 50 ms, not 50 s.
  Rejected on the code.
- The *same* adversarial pass surfaced a genuine motto-breaking bug I had missed:
  a GL-pipeline teardown path whose wait was unbounded, which could strand the
  last video chunk *in clear* before it was encrypted. That one was real, and it
  was fixed. Note what it proves: the proof stack covers the crypto core, and the
  worst bug was in the Kotlin capture pipeline *around* it, outside every oracle.
  That is why the adversarial-review layer exists, and why its output is
  re-verified rather than trusted.
- A separate cross-vendor pass (my assistant's work red-teamed by a different
  vendor's model, and the reverse) caught two real bugs of its own: plaintext
  chunks that could survive an abnormal process death, and a client still probing
  a dead endpoint, burning a ratchet slot on each failed auth. Three of its
  "critical" findings were downgraded on arbitration against the code.

The transferable lesson: adversarial review by a *different* model finds things
the author-model misses, but its base rate of confident-wrong is high enough that
a deterministic re-check is not optional.

## What none of this is

Honesty is the only currency a tool for at-risk people has, so the limits get the
same care as the features.

- **This is not an external audit.** Everything above is *self*-verification,
  however adversarial. An independent human review (Cure53 / Trail of Bits class,
  or an academic protocol analysis) is planned and actively sought; it has not
  happened. Concretely: until it does, do not stake your safety on this tool.
- **Nothing machine-checks that the models match the code.** The Tamarin and TLA+
  models are hand-written abstractions of the Rust; that correspondence is exactly
  the judgment this stack cannot eliminate. An auditor's first job is to attack it.
- **The formal tools have boundaries.** Tamarin assumes signatures unforgeable and
  hashes collision-free (symbolic, not computational). TLC checks the state
  machine at small bounds. Kani bounds input sizes. The models are honest about
  what they idealize, and those idealizations are where a real auditor earns the
  fee.
- **Documented residuals exist.** The metadata envelope (*that* and *when* you
  upload) is not hidden; the paper phrase is a deliberate single point of total
  failure; a compromised OS at capture time sees what the sensor sees. These are
  written down and risk-accepted, not buried under the proof stack.

## If you want to break it

The single thing that would most help this project is an adversarial read by
someone who does this for a living. The proof runners (Tamarin, TLC, Kani, the
zeroize audit, the differential fuzzer) replay from a clean clone, alongside an
auditor's guide and a scope-and-invariants document. The residuals list says where
I already think the soft spots are.

The "don't roll your own crypto" reflex is correct, and it is why I did not roll my
own primitives, only the composition, with a proof obligation attached to every
claim. If the composition is wrong, the fastest way to find out is for you to look.
The repository is public at [github.com/therealshulgin/Frappuccino](https://github.com/therealshulgin/Frappuccino); the proofs and the honest
limits are the invitation.

*Built with an AI as the primary pair programmer. No claim here rests on that AI's
judgment: each is anchored to a runner you can replay yourself.*
