# Ephemeral ratchet & forward secrecy — Design rationale (adversarial steelman)

> Model: claude-opus-4-8[1m]. Date: 2026-06-28. Scope: the batched Ed25519 forward-secure signature lineage (`EphemeralRatchet`), its forward-secrecy / anti-replay / anti-rollback guarantees, the domain-separated signatures, and the decision to back all of it with machine-checked proofs.

This is a **design-defense** document, not a vulnerability hunt. For each choice it makes the affirmative case, justifies *this* implementation against the alternatives, states the sharpest hostile objection and either rebuts or concedes it, then surfaces the assumptions and the questions a real adversarial audit should probe. Every claim is cited to the code.

---

## 1. Scope & the choices under review

The motto governs: *everything leaves the phone fast; a seizure exposes nothing; the phone is a relay, not a vault.* For the **authentication / signing** layer this translates to: a device seizure at time T must not let the adversary forge anything the device already did. The ratchet is how that is achieved without storing a long-lived signing key on the device. The concrete choices:

- **C1 — A batched ephemeral Ed25519 ratchet (50 keys/batch) instead of a long-lived signing key or per-message DH.** `crypto-rs/core/src/ratchet.rs:155-165` (the struct), `:63` (`BATCH_SIZE = 50`).
- **C2 — Use-once-then-wipe per slot; the consumed slot's private key is zeroized at sign time.** `ratchet.rs:283-284` (sign-and-wipe), `:345-354` (rotation wipes the whole outgoing batch).
- **C3 — Chain advance by one-way HKDF: `chain_{N+1} = HKDF(chain_N)`, old chain wiped.** `ratchet.rs:328-330` and `:354`; HKDF in `crypto-rs/core/src/hkdf.rs:35-51`.
- **C4 — Long-term identity key used *once*, at enrollment only, then wiped; thereafter the device cannot sign with it.** `crypto-rs/core/src/identity.rs:182-190`, `:309-322` (`EnrollmentKit` drop), doc `:11-13`.
- **C5 — Batch rotation is a self-signed lineage: a slot of batch N signs `concat(50 new pk)` to authorize batch N+1 (`RotationProof`).** `ratchet.rs:131-144`, `:304-371`.
- **C6 — MAC-authenticated serialized state (V2 blob), V1 (unauthenticated) rejected on read.** `ratchet.rs:382-450`, `:660-674` (constant-time MAC verify).
- **C7 — Explicit one-byte domain-separation tags on every signature (R-C-1).** `crypto-rs/core/src/signature_domain.rs:59-119`; consumers at `ratchet.rs:277`, `:341`, `identity.rs:289`.
- **C8 — The decision to *formally verify* the design (TLA+ FSM, Tamarin protocol, Kani parser, zeroize-IR audit, proptest) rather than rely on tests alone.** `crypto-rs/core/proofs/EphemeralRatchet.tla`, `proofs/RatchetProtocol.spthy`, `docs/TLA_RATCHET.md`, `docs/TAMARIN_RATCHET.md`, `docs/KANI_PROOFS.md`, `docs/ZEROIZE_AUDIT_RATCHET.md`, `core/tests/proptest_ratchet.rs`.

---

## 2. Choice-by-choice rationale

### C1 — Batched ephemeral Ed25519 ratchet (50/batch)

- **What it is.** The device holds, at any time, one batch of 50 ephemeral Ed25519 keypairs derived from the current chain key (`ratchet.rs:622-647` `derive_batch_into`). Each slot signs at most one server interaction; when the batch is exhausted the device rotates to a fresh batch derived from the next chain key (`ratchet.rs:304-371`). The long-term identity signs the *first* batch once (`identity.rs:270-292`) and is then gone.

- **Affirmative case.** This is the literal mechanism of the motto for the auth layer. The only key on the device that can authenticate is an ephemeral slot key whose lifetime is a single use. A seizure at T captures only the *current* batch's unconsumed slots and the current chain key — it captures **nothing** about past authentications, because the keys that produced them are wiped (C2) and cannot be re-derived from forward state (C3). The "phone is a relay, not a vault" claim holds for signing keys, not just for video.

- **Why this implementation.** Alternatives the design explicitly rejects (doc `ratchet.rs:1-19`, `docs/TAMARIN_RATCHET.md:41-46`):
  - *Long-lived Ed25519 signing key on device.* Simplest, but a seizure forges the holder's identity forever, including impersonation to the relay — a direct motto violation. Rejected.
  - *Per-message Diffie-Hellman double-ratchet (Signal-style).* Gives forward secrecy *and* post-compromise security, but it is a two-party stateful protocol designed for confidentiality of an interactive conversation. Here the relationship is device→relay one-way *authentication of uploads*, and the relay is explicitly an untrusted blob-store ("relay, not a vault"). A DH ratchet would force shared mutable state and DH key agreement with the relay for a property (message confidentiality between two endpoints) that is not the threat being defended — uploads are sealed-box encrypted to the *witness's own* identity (`identity.rs:410-427`), not to the relay. Over-engineered for the auth need. Rejected.
  - *Batched forward-secure signatures (the choice).* This is an Algorand-style ephemeral-key lineage (`docs/TAMARIN_RATCHET.md:41`): cheap (Ed25519 keygen is fast), stateless on the relay side beyond "which slot is authorized", and gives exactly the forward-secrecy property wanted with no DH round-trips. Batching (50, not 1) amortizes the rotation signature + chain derivation across 50 interactions, so the common path (`sign_and_advance`) is a single Ed25519 sign + a memory wipe, no HKDF.

- **Adversarial stress.** *"50 unconsumed keys sit on the device at once; a seizure with the current chain key lets you forge up to 50 future signatures **and** derive every future batch (the chain is on the device). Calling this forward-secure oversells it."* — **Partial concession, correctly scoped.** Forward secrecy is a claim about the **past**, and that claim holds: extraction at T forges only the *remaining* slots of the current batch, never a past upload (`ratchet.rs:9-11`, Tamarin `forward_secrecy_auth` `RatchetProtocol.spthy:262-267`). The design never claims **post-compromise security** — `docs/TLA_RATCHET.md:69-72` and `TAMARIN_RATCHET.md:13` both explicitly mark PCS/healing as *out of scope*. A seized device's future is forfeit; that is honest and matches the threat model (a seized device is gone, the point is the rushes already left and past auth can't be retroactively forged). The "derive every future batch from the chain" point is true and is the residual below.

- **Assumptions & residual.** Rests on: Ed25519 unforgeability; HKDF-SHA256 being a PRF; the device actually wiping (C2/C3, and the zeroize-audit C8 closes the compiler-DSE gap). Does **not** claim: PCS, confidentiality of uploads (that is the seal layer), or protection of the *current* batch under seizure.

- **Questions for the future audit.**
  1. Is 50 the right batch size against the seizure model — i.e. is the window of "up to 50 forgeable future slots + full future chain on device" acceptable, or should the chain key itself be sealed at rest behind the PIN so a powered-off seizure can't advance it?
  2. The forward-secrecy guarantee depends on the *old* chain key being unrecoverable after advance. Confirm `old_chain.zeroize()` (`ratchet.rs:354`) plus the V2 blob never persisting a past chain — verify there is no backup/swap path that retains `chain_{N-1}`.

### C2 — Use-once-then-wipe per slot

- **What it is.** `sign_and_advance` finds the first unconsumed slot, copies its seed into a `Zeroizing` stack buffer, signs, then `self.private_keys[idx].zeroize(); self.consumed[idx] = true` (`ratchet.rs:263-291`). Rotation wipes the entire outgoing batch's private and public keys and resets the consumed mask (`ratchet.rs:345-354`).

- **Affirmative case.** This *is* forward secrecy at the byte level: the moment a slot is used, the material that could reproduce its signature is gone from RAM. There is no "signed messages log" key that survives. Combined with the relay's own use-once enforcement (`server/app/routes/auth_v2.py:244-254` `consume_ephemeral_key`, `:316-317` "Signer key already consumed") it is a **two-sided** anti-replay: even if the device's wipe were defeated, the relay refuses a slot index twice.

- **Why this implementation.** The seed is held in `Zeroizing` (`ratchet.rs:270-272`) specifically because `SigningKey::from_bytes` makes a stack copy that dalek's own `ZeroizeOnDrop` does not cover — the local 32-byte buffer would otherwise survive to scope-end (comment `:266-269`). Alternative: rely on dalek's zeroize alone — rejected as insufficient for the stack copy. Alternative: overwrite with `[0;N]`/`.fill(0)` — rejected because the compiler dead-store-eliminates it (this is exactly what the zeroize-audit C8 proves, `docs/ZEROIZE_AUDIT_RATCHET.md:94-99` negative control). The canonical `zeroize` crate lowers to `write_volatile`, which LLVM may not elide.

- **Adversarial stress.** *"A `Drop`-body wipe is unobservable from safe Rust; how do you know it isn't optimized away? And a register/stack copy of the seed could outlive the wipe."* — **Rebutted for the heap field, conceded-and-mitigated for stack copies.** The heap-field wipe is centralized in one mutation-covered function `zeroize_secrets` (`ratchet.rs:492-499`) called by both `wipe` and `Drop` (`:601`), and the un-killable `drop→no-op` mutant is closed at the compiler-IR level: the zeroize-audit shows `store volatile` survives and even multiplies at O2 (`ZEROIZE_AUDIT_RATCHET.md:38-52`) and the shipping `opt=s` profile uses out-of-line volatile calls, with an executable tripwire guarding it (`crypto-rs/core/audit/assert_zeroize_not_dse.sh`). Stack copies of the seed are wrapped in `Zeroizing` at every signing site (`ratchet.rs:270`, `:313`, `identity.rs:285`); the honest residual (`ZEROIZE_AUDIT_RATCHET.md:117-120`) is that register spills and other address-space copies are a source-level concern not separately dumped.

- **Assumptions & residual.** Rests on: `zeroize`'s volatile-store contract holding through LTO; no compiler/codegen change silently dropping it (guarded by the tripwire). Does **not** claim: that no transient copy of a seed ever exists in a CPU register or a swapped page (mlock covers the long-term/locked secrets in `identity.rs` via `LockedSecret`, but the ratchet's per-batch private keys live in a plain heap array, not mlock'd).

- **Questions for the future audit.**
  1. The ratchet's `private_keys: [[u8;64];50]` is a plain heap array, **not** in an mlock'd page (unlike `EnrollmentKit`/`ArchiveIdentity` which use `LockedSecret`). Can the 50 live private keys be swapped to disk or land in a coredump before wipe? Should the whole batch live in a locked page?
  2. Re-run the zeroize tripwire on the exact shipped toolchain + LTO settings; confirm the O2 vs `opt=s` divergence still resolves to a real volatile wipe after fat-LTO link.

### C3 — One-way chain advance (`chain_{N+1} = HKDF(chain_N)`)

- **What it is.** Each batch derives the next chain key by `hkdf::sha256(old_chain, None, CTX_NEXT_CHAIN, 32)` and wipes the old chain (`ratchet.rs:328-330`, `:354`; init path `:547-554`). Batch keys come from a *separate* HKDF context `CTX_BATCH_SEEDS` over the same chain (`ratchet.rs:99-101`, `:627-632`).

- **Affirmative case.** One-wayness is the structural root of forward secrecy across batches: given `chain_N` you cannot recover `chain_{N-1}` (HKDF is a PRF), so a seizure at batch N reveals nothing about the batch-(N-1) keys that signed past uploads — they're both wiped *and* underivable. The two distinct HKDF contexts (`batch-seeds` vs `next-chain`) mean the published batch keys leak nothing about the next chain.

- **Why this implementation.** HKDF-SHA256 is reused as the project's single KDF primitive (RFC-5869, byte-exact with the Kotlin reference, `hkdf.rs:1-10`), keeping one audited derivation primitive rather than inventing a chain-specific construction. Distinct context strings are the domain-separation discipline mandated by the invariants doc §A (`docs/invariants-ratchet-verification.md:18`). The context strings are flagged immutable ("drift = lose all enrolled identities", `ratchet.rs:42-47`).

- **Adversarial stress.** *"One-wayness of the chain is asserted, never proven — neither TLA+ nor Tamarin model the KDF; it's symbolic-perfect-crypto there."* — **Honest concession.** Correct: TLA+ abstracts derivation (`TLA_RATCHET.md:76-78`), Tamarin assumes perfect crypto (`TAMARIN_RATCHET.md:169-171`), and the invariants doc explicitly assigns chain-key one-wayness to a *CryptoVerif/computational* layer that is **not in scope for §8.4** (`invariants-ratchet-verification.md:16`, `TAMARIN_RATCHET.md:175-178`). The defense rests on HKDF-SHA256 being a standard PRF, which is reasonable but unproven here. KATs pin the byte output (`hkdf.rs` RFC test vectors) — that's correctness, not a one-wayness reduction.

- **Assumptions & residual.** Rests on: HKDF-SHA256 PRF security; SHA-256 preimage resistance. Does **not** claim a machine-checked computational proof of chain one-wayness.

- **Questions for the future audit.**
  1. Is the computational gap (no CryptoVerif/EasyCrypt proof that the chain KDF is one-way / the batch-seed and next-chain outputs are independent) acceptable for the threat model, or should at least the independence of the two HKDF contexts get a game-based argument?

### C4 — Long-term identity key used once, at enrollment only

- **What it is.** `EnrollmentKit` holds the long-term Ed25519 secret in an mlock'd `LockedSecret`, signs the batch-0 keys once at enrollment, and drops the secret (`identity.rs:182-190`, `:270-292`, `:309-322`). After that the device *cannot* sign with the long-term key (doc `identity.rs:11-13`). The X25519 archive secret is re-derivable from the BIP-39 phrase on demand but not the Ed25519 signing half.

- **Affirmative case.** This is the single point where the lineage is anchored to a durable identity, and it is open for the minimum possible time. Everything downstream (every batch) is authenticated transitively (C5) without the long-term key ever being on the device again. A seizure after enrollment never finds the identity signing key — only the phrase (in the user's head) can reconstruct the *archive* X25519 secret, and that cannot sign auth/rotation. This bounds the blast radius of a seizure precisely.

- **Why this implementation.** Type-level consume-once: the secret is `Option<LockedSecret>` so post-consumption re-use returns `AlreadyConsumed` (`identity.rs:186-189`, `:301-305`). Alternative: keep the long-term key derivable on demand from the phrase like the archive key — rejected, because then a coerced phrase disclosure would let an adversary mint a *new* enrollment / rogue batch lineage; keeping the Ed25519 signing path one-shot-and-gone means even the phrase can only re-derive the *archive* (read) capability, not re-anchor the signing lineage. (Honest nuance: re-typing the phrase *can* re-derive `chain_0` and thus re-run the lineage; see stress.)

- **Adversarial stress.** *"The long-term key is deterministic from the BIP-39 seed (`identity.rs:201`, `CTX_IDENTITY`). 'Cannot sign anymore' is only true for *this device instance* — anyone with the phrase re-derives the identity key and can sign a fresh enrollment. Coercion of the phrase defeats the whole anchor."* — **Conceded as an inherent property of deterministic key derivation, and it is the intended design.** The phrase *is* the root of trust; the witness chose a recoverable identity so a destroyed/seized phone can be recovered from the phrase on a new device (`identity.rs:343-347` archive re-derivation). The "used once then wiped" claim is about *this running process's RAM* (motto: a live seizure of *this* device exposes nothing), not about the seed's reproducibility. The server's `EnrollOncePerIdentity` (modelled `RatchetProtocol.spthy:69-71`, real 409 "Identity already enrolled") prevents a *second* enrollment of an already-known identity, which blunts a re-enrollment fork while the original lineage is alive.

- **Assumptions & residual.** Rests on: the BIP-39 phrase staying secret (out of crypto scope — a coercion/rubber-hose concern); the relay enforcing one-enrollment-per-identity. Does **not** claim protection against an adversary who obtains the phrase.

- **Questions for the future audit.**
  1. What exactly happens on the relay if a re-enrollment is attempted (409) **while the lineage has already rotated** — can a phrase-holder fork the lineage on a fresh device, and does the relay's "consumed index" state make the two forks mutually exclusive or merely racy? (Probe `auth_v2.py` enroll vs rotate interaction.)

### C5 — Self-signed batch-rotation lineage (`RotationProof`)

- **What it is.** To rotate, a slot of the current batch signs `concat(50 new pk)` under the `BatchRotation` domain; the proof carries the signer pk, its batch/index, and the 50 new keys (`ratchet.rs:131-144`, `:304-371`). The relay verifies the signature under a slot it already knows, consumes that slot, and installs the new batch as authorized (`auth_v2.py:294-319`, modelled `RatchetProtocol.spthy:146-152`).

- **Affirmative case.** This chains authority forward without ever reusing the long-term key: every batch is vouched for by the previous one, recursively back to the enrollment root. An active network attacker cannot inject a rogue batch, because doing so requires a private slot key from the authorized predecessor (Tamarin `rotation_authentic` + `rotation_lineage` + `root_authentic`, `RatchetProtocol.spthy:229-255`). It keeps the relay stateless-ish: it only tracks "current authorized slot set + consumed indices", not a key history.

- **Why this implementation.** A custom forward-secure signature lineage was chosen over a standard certificate chain or a stateful hash-based signature (e.g. XMSS) because it reuses the *same* ephemeral slot keys already present for auth — no extra key type — and the rotation cost is one Ed25519 sign amortized over a 50-use batch. The lineage is exactly what Tamarin proves unforgeable, so the bespoke scheme earns its formal proof (`TAMARIN_RATCHET.md:42-45`).

- **Adversarial stress.** *"Rotation safety was originally only protected by *message length* — a 40-byte `nonce‖ts` auth message vs a 1600-byte `concat(50 pk)` rotation message. Tamarin falsified `rotation_authentic` when batches collapse to one slot, because the same ephemeral key signs both. That's a forgery surface."* — **Conceded historically; closed by C7.** This is the model's most valuable finding (`TAMARIN_RATCHET.md:104-129`, `RatchetProtocol.spthy:38-53`). The ephemeral slot is genuinely **dual-use** (auth *and* rotation), so before R-C-1 the only separation was the length gap — fragile against any future endpoint that signs a short blob with a slot key. R-C-1 made it explicit (domain tags, C7), and the negative control **NC2** (collapse the auth/rotate tags) *re-falsifies* `rotation_authentic`, proving the separation is load-bearing, not decorative (`TAMARIN_RATCHET.md:138-140`). So the objection is real but the mitigation is verified.

- **Assumptions & residual.** Rests on: Ed25519 unforgeability; the relay correctly consuming the signer slot so a rotation proof can't be replayed; domain tags being honored on both ends (C7). The unknown-key-share residual (`TAMARIN_RATCHET.md:91-102`): an attacker can re-register an honest device's *public* ephemeral key inside its own batch, but this transfers no authority (the nonce is one-shot, only the holder can sign).

- **Questions for the future audit.**
  1. The Tamarin model abstracts a batch to **one representative slot** (`RatchetProtocol.spthy:24-30`). The 50-slot multiplicity + consumed-mask is proven separately by TLA+. Probe the *seam*: does the real relay's per-batch `consumed_indices` (`auth_v2.py:294-319`) correctly forbid using a *consumed* slot as a rotation signer, matching the model's single-consume assumption?

### C6 — MAC-authenticated serialized state, V1 rejected

- **What it is.** The V2 blob appends `HMAC-SHA256(HKDF(chain, CTX_BLOB_MAC), payload)` (`ratchet.rs:382-411`); `deserialize` verifies it in constant time (`ratchet.rs:660-674` `ct_eq`) and **rejects** legacy V1 (unauthenticated) blobs outright (`ratchet.rs:441-445`). A dedicated `migrate_from_v1` escape hatch exists for historical backups only (`ratchet.rs:465-482`).

- **Affirmative case.** The on-disk ratchet state is integrity-protected with a key derived from the chain itself, so an attacker who can write the inner blob (e.g. some post-PIN-seal path) cannot substitute a forged ratchet state — a tampered payload fails the MAC (`ratchet.rs:818-837` tests). Rejecting V1 closes the RT-03 issue where an unauthenticated blob was indistinguishable from a legitimate one (`ratchet.rs:419-424`).

- **Why this implementation.** Constant-time `ct_eq` (`subtle` crate) avoids a MAC-comparison timing oracle. The MAC key is HKDF'd from the chain under a distinct context (`CTX_BLOB_MAC`), not the raw chain, so the integrity key is domain-separated from derivation. Alternative: trust the OS file permissions / PIN-seal alone — rejected because the threat model is a *forensic seizure*, where the attacker may have the file and (in some paths) write access.

- **Adversarial stress.** *"The MAC key is derived from the chain key that is stored *in the same blob* (`ratchet.rs:397`, `:661-664`). An attacker who recovers the chain can forge the MAC. This authenticates against corruption, not against an attacker who has the chain."* — **Conceded, and correctly so.** This is integrity-against-tampering-by-a-party-without-the-chain, not authentication-against-the-chain-holder. But that is the right property: a party with the chain key *already owns the ratchet* (they can sign), so MAC-forging it adds nothing. The MAC defends the realistic case — a blob substituted/corrupted by a process that does not hold the live chain. The honest limit is documented (`ratchet.rs:419-424`).

- **Assumptions & residual.** Rests on: HMAC-SHA256 security; the chain key not being separately exposed. Does **not** claim confidentiality of the blob (it isn't encrypted at this layer — the private keys are in cleartext inside it; at-rest secrecy is the PIN-seal layer's job, outside this domain).

- **Questions for the future audit.**
  1. The serialized blob contains the 50 private keys **in cleartext** (`ratchet.rs:403`). Confirm the at-rest PIN/seal layer actually encrypts this blob before it touches disk — the MAC here is *not* encryption, so if the seal layer ever stored it raw, a seizure would read live signing keys.

### C7 — Explicit one-byte domain-separation tags (R-C-1)

- **What it is.** Every V2 signature prepends a one-byte domain tag to the signed message (`signature_domain.rs:101-118` `prefixed`). Tags: `0x01` AuthChallenge, `0x02` BatchRotation, `0x03` Enrollment, `0x04` ArchiveAuth (now **retired/reserved**), `0x05/0x06` provenance, `0x07/0x08` Phase-C report capabilities (`signature_domain.rs:62-98`). The relay mirrors the bytes (`server/app/signature_domain.py:28-37`).

- **Affirmative case.** This is defense-in-depth that closes the exact forgery surface Tamarin surfaced (C5 stress). A signature minted for one context can never be replayed in another even if the message bytes — or their length — coincide (`signature_domain.rs:1-11`). It future-proofs against new endpoints: any new signing context must take a new tag (`signature_domain.rs:55-57`), so the next person adding a slot-signed blob can't accidentally create a cross-context replay.

- **Why this implementation.** A one-byte prefix is the minimal, wire-stable mechanism; tags are a `#[repr(u8)]` enum discriminant (`signature_domain.rs:60-62`) so the value *is* the wire byte. Client (Rust) and server (Python) keep byte-identical mirrors, and a test pins the values stable (`signature_domain.rs:126-147`). Alternative considered and rejected: rely on the emergent length separation (40-byte vs 1600-byte) — the audit's open finding precisely because it breaks the moment a new endpoint signs a different-length message with the same key class (`signature_domain.rs:6-10`, `TAMARIN_RATCHET.md:110-114`).

- **Adversarial stress.** *"This is a two-place constant duplicated across two languages (Rust enum + Python bytes). A drift between them silently re-opens the forgery surface, and nothing in the build *enforces* byte-identity."* — **Conceded as an operational risk; partially mitigated.** The Rust side has a pinned test (`signature_domain.rs:126-147`) and the Python side has the same table in comments, but there is **no automated cross-language equality gate** in this domain's artifacts — keeping them in sync is a documented discipline (`signature_domain.py:1-7` "MUST stay byte-identical… deployed together"), not a CI assertion. The memory note records this was field-validated end-to-end at runtime (enroll 0x03 / verify 0x01 / rotate 0x02 against the live relay), which catches a current drift but not a future one.

- **Assumptions & residual.** Rests on: the human/CI discipline of keeping the two mirrors equal; every *future* signing context taking a fresh tag. Does **not** claim the 0x05–0x08 contexts (provenance, reports) are in scope here — they belong to other domains, but they share the tag namespace, so a collision there would matter.

- **Questions for the future audit.**
  1. There is no machine-checked gate that the Rust `SignatureDomain` enum and `server/app/signature_domain.py` agree byte-for-byte (and that the *server's verifier code paths* actually prepend the tag at all four/six live sites). Add a cross-stack parity check; until then, audit every `verify(` call on the server for a missing/ wrong prefix.
  2. `ArchiveAuth = 0x04` is retired but still a live enum variant and a `SIG_DOMAIN_ARCHIVE_AUTH` constant (`signature_domain.rs:75`, `signature_domain.py:35`). Confirm **no** code path still *signs or verifies* under 0x04 (it should be unreachable, reserved-only).

### C8 — The decision to formally verify

- **What it is.** The ratchet/auth design is backed by five complementary machine checks (`TAMARIN_RATCHET.md:22-28`): zeroize-IR audit ① (wipe not DSE'd), diff-fuzz ② (Kotlin↔Rust byte parity 759/759), Kani ③ (parser no-panic), TLA+ ④ (FSM: monotone batch / use-once / anti-replay, 4680 states exhaustive), Tamarin ⑤ (Dolev-Yao protocol: secrecy, auth, rotation lineage, forward secrecy, 10 lemmas + 2 negative controls), plus proptest bridging model↔code (`core/tests/proptest_ratchet.rs`).

- **Affirmative case.** The ratchet is a **bespoke** scheme (not an off-the-shelf, already-analyzed primitive), so the design's correctness cannot be borrowed from the literature — it has to be earned. The proofs target the things tests *cannot* reach: an exhaustive FSM check rules out every interleaving of sign/rotate (not a sample, `TLA_RATCHET.md:41-43`); a Dolev-Yao prover rules out an active attacker forging the lineage; the IR audit closes the un-killable `drop→no-op` mutant that no safe-Rust unit test can observe (`ZEROIZE_AUDIT_RATCHET.md:8-15`). Each layer proves a *different* thing — the "model→code gap" principle (`TLA_RATCHET.md:12-14`).

- **Why this implementation.** The tool split follows the invariants doc's layering (`invariants-ratchet-verification.md:52-83`): protocol→Tamarin, FSM→TLA+, code→Kani, compiler→zeroize-audit. Crucially, **every proof carries a negative control** so green is not vacuous: TLA+ deleting the use-once guard re-falsifies `AntiReplay` (`TLA_RATCHET.md:45-52`); Tamarin's NC1/NC2 falsify auth/rotation (`TAMARIN_RATCHET.md:132-140`); the zeroize tripwire fails on a regression to `=[0;N]` (`ZEROIZE_AUDIT_RATCHET.md:94-99`). This is the discipline that prevents a "proof" that proves nothing.

- **Adversarial stress.** *"Proofs of *models* are not proofs of *the shipped binary*. TLA+ uses BatchSize=3 not 50; Tamarin uses one slot per batch and perfect crypto; Kani doesn't cover the ratchet at all; none of this runs in CI (the repo has no remote). The reassurance may exceed what's proven."* — **Largely conceded; the design is honest about each gap.**
  - TLA+ small bounds: defended because the invariants are *structural* (count-independent), so holding at 3 implies holding at 50 (`TLA_RATCHET.md:41-43`) — a reasonable but informal argument, not itself machine-checked.
  - Tamarin one-slot abstraction + perfect crypto: explicitly scoped (`TAMARIN_RATCHET.md:164-171`); the multiplicity is delegated to TLA+, the computational reduction to an out-of-scope CryptoVerif layer.
  - Kani does **not** cover the ratchet (`KANI_PROOFS.md:62-67`): `deserialize` is HMAC-gated + 4844-byte payload = intractable; the ratchet leans on the zeroize-audit + mutation testing instead. This is a real coverage hole the doc states plainly.
  - CI dormancy: per the project memory, §8.4 was *closed by decision* with CI gates judged marginal ROW without a remote — the proofs are reproducible on demand (`run-tlc.sh`, `run-tamarin.sh`, `run-kani.sh`, `assert_zeroize_not_dse.sh`) but not continuously enforced. That is a maintenance risk, not a soundness one.

- **Assumptions & residual.** Rests on: the models faithfully reflecting the code (the diff-fuzz ② and proptest bridge this for marshalling/FSM, but the Tamarin↔`auth_v2.py` acceptance-condition correspondence is *by hand*); the tools themselves being sound. Does **not** claim: a computational (concrete-bound) proof, a proof of the FSM at the literal 50, or continuous regression enforcement.

- **Questions for the future audit.**
  1. The Tamarin model's security oracle is the *server's acceptance conditions* (`auth_v2.py`), transcribed by hand. Is there drift between the modelled `Server_Verify`/`Server_Rotate` rules and the real route code (e.g. the timestamp-skew window the model omits, `TAMARIN_RATCHET.md:172-174`)? A mechanized extraction (hax/Verus) would close this; absent that, line-by-line correspondence is the audit's job.
  2. The "structural ⇒ 50 from 3" argument for TLA+ is informal. Worth a one-off TLC run at BatchSize=50 (or an inductive argument) to retire any doubt that the count is truly irrelevant.

---

## 3. Domain coherence & tensions

The choices form a single coherent story: **C4** anchors a durable identity for the minimum time; **C5** chains authority forward from it without ever reusing it; **C1/C2/C3** make each link of that chain ephemeral, use-once, and forward-secure; **C6** protects the chain's serialized state at rest; **C7** stops the ephemeral keys' dual use from collapsing into a forgery; **C8** proves the bespoke construction actually has these properties. The forward-secrecy claim is precisely scoped throughout — it is always about the *past*, never PCS, and the docs are consistent and honest about that boundary.

Internal tensions worth flagging for the next audit:

- **Recoverable identity vs. "wiped" long-term key (C4 vs C1).** The phrase deterministically re-derives the identity *and* `chain_0`. "Forward-secure / wiped" is a statement about this *device process's RAM*, not about the irreproducibility of the secret. Both claims are true under their own scopes, but a reader could conflate them. The defense is sound only because the phrase lives in the user's head, not the device — a coercion threat the crypto explicitly does not address.

- **Live batch on a non-locked heap (C2) vs. mlock'd long-term/archive secrets (C4).** The 50 *current* private keys are in a plain heap array while `EnrollmentKit`/`ArchiveIdentity` use `LockedSecret`. The forward-secrecy story is airtight for *past* batches, but the *current* batch's at-rest/swap exposure is weaker than the long-term key's. This is the sharpest internal asymmetry.

- **Cross-language constants (C7) with no automated gate.** The single biggest "silent regression" risk: the security of C5/C7 depends on two hand-mirrored tag tables (Rust + Python) staying byte-identical, with only a one-sided pinned test and field-validation, not a build gate.

- **Proof scope seams (C8).** TLA+ (multiplicity) ↔ Tamarin (crypto) ↔ Kani (parser, *not* ratchet) ↔ computational (out of scope) compose by *argument*, not by a single mechanized chain. The seams (50-vs-3, one-slot abstraction, hand-transcribed server oracle) are where a real auditor should push.

---

## 4. Top-3 questions this domain hands to the future adversarial audit

1. **At-rest exposure of live signing material.** The 50 *current* ephemeral private keys live in a plain heap array (not mlock'd) and are serialized **in cleartext** inside the (MAC'd but unencrypted-at-this-layer) V2 blob. Does the PIN/seal layer encrypt that blob before disk, and can the live batch be swapped/coredumped before wipe? Forward secrecy protects the past; this is the present-tense seizure gap.

2. **Cross-stack domain-tag integrity has no machine gate.** The forgery-prevention of R-C-1 (C7) and the rotation lineage (C5) depend on the Rust `SignatureDomain` enum and `server/app/signature_domain.py` being byte-identical **and** on the server prepending the tag at every verify site. There is only a one-sided pinned test, no automated parity check. Audit every server `verify()` for the correct prefix, and confirm retired `0x04` is truly unreachable.

3. **Model↔code fidelity at the proof seams.** The reassurance rests on TLA+ (BatchSize=3, "structural ⇒ 50" informal), Tamarin (one slot/batch, perfect crypto, server acceptance conditions hand-transcribed from `auth_v2.py`), and Kani (which does **not** cover the ratchet). Probe whether the modelled `Server_Verify`/`Server_Rotate` match the live route code (timestamp skew, consumed-index enforcement on rotation signers), and whether the chain-KDF one-wayness — assigned to an out-of-scope computational layer — deserves at least a game-based argument.
