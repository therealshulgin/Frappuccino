+++
title = "Frappuccino"
+++

**Shake. Document. Protect.** Frappuccino turns an Android phone into a transmitter of end-to-end encrypted video testimony: footage leaves the device **while it is being filmed**, toward a relay that **cannot read it**, and the only key that can ever decrypt it is a **twelve-word phrase on paper**, in the witness's pocket.

Seizing the phone - before, during, or after recording - no longer yields anything to read.

## In thirty seconds

- **What it is for:** filming a high-risk situation when the phone may be seized, searched, or destroyed.
- **How:** the video is split into fragments, encrypted, and sent *while* recording, never left in the clear on the device.
- **The relay cannot read it** and logs no IP address.
- **The phone cannot reopen the past:** a fragment that has left is beyond its reach.
- **One key only: twelve words on paper,** held by the witness alone. No one, us included, can restore it.
- **Where the project stands:** ready for field testing and audit, not yet for use where lives depend on it.

## The problem

An activist films an abuse. A journalist documents a sealed-off site. A lawyer records an arrest. Three things tend to happen, often in this order: the phone is **seized**, the PIN is **coerced**, and the hardware goes to **forensic extraction** (Cellebrite, GrayKey). For testimony to survive that, three properties must hold at once:

1. **Survive seizure and wiping** - the content must exist elsewhere, recoverable by the witness alone, even from a brand-new phone: no account, no cloud, no third party.
2. **Stay unreadable by the server** - a seized or hostile relay must have nothing to hand over but opaque bytes.
3. **Hold even if the phone is snatched mid-recording** - footage encrypted "at the end" protects nothing if capture is cut short by force.

A local encrypted vault fits this poorly: a safe can be opened - by brute force, by coercion, by an OS exploit. As long as the data and its key are both on the phone, the phone is the single point of failure, and it is exactly what the adversary holds. The goal is not a better safe. It is to **stop being a safe.**

## Why it's different

- **Footage leaves the device during capture.** Recording is cut into 5-second chunks, each end-to-end encrypted on-device and uploaded immediately. Snatch the phone at minute 12: the first 12 minutes are already out of reach.
- **A blind relay that cannot betray.** The server stores opaque blobs only, encrypted to a key whose private half exists on **no machine**. It verifies signatures, enforces anti-replay, stores and returns bytes; it never sees an image and does not log IP addresses.
- **A sovereign key: twelve words on paper.** At enrollment the device generates a BIP-39 phrase, shown once and never stored. It is the only path to reading the streams or recovering the identity - no account, and no authority (us included) can reset it.
- **The past is out of reach, provably.** Authentication uses an Algorand-inspired ratchet of single-use keys, each destroyed right after signing. An adversary with the phone, the PIN, and even a RAM dump gets at worst a few bounded **future** signatures - never one byte of past content. This forward secrecy is proven in **Tamarin**, model-checked in **TLA+**, and the key wipe is verified at the compiled-code level.
- **100% Rust crypto core.** Public, battle-tested primitives (Ed25519, X25519, XChaCha20-Poly1305, Argon2id, HKDF, rustls), assembled by protocol logic that is what we get verified. Video plaintext is sealed file-to-file by Rust: it does not cross the JVM heap.
- **Pinned TLS.** A custom rustls verifier reduces trust to the relay's key fingerprint (a small constant-time set of keys we control, so a cert rotation or a seized-relay recovery does not require a new app); a man-in-the-middle holding a valid CA-signed certificate is still rejected.
- **Upload traffic that resists fingerprinting.** Chunks go up over QUIC (HTTP/3), wrapped in a Salamander obfuscation layer that masks every datagram with a pre-shared key: to deep-packet inspection the flow carries no QUIC or TLS markers to classify. If that path is throttled or blocked, the client falls back transparently to pinned TLS, so footage keeps leaving the device. Field-validated, and honest about its limit: this is inclassifiability, not anonymity (see the limits below).

## Threat model in brief

| If the adversary… | Then… |
|---|---|
| Seizes the phone after recording | Nothing readable on the device; the footage is on the relay, encrypted |
| Snatches the phone mid-recording | Everything up to seconds before the snatch is already encrypted and off the device |
| Coerces the PIN | At worst bounded **future** signing capacity: not one byte of past content |
| Runs Cellebrite / GrayKey | No decryption key exists on the device; the ratchet blob is sealed under Argon2id |
| Intercepts the network, even with a rogue CA | Per-blob XChaCha20-Poly1305 inside SPKI-pinned TLS |
| Seizes or maliciously operates the relay | Only opaque blobs and pseudonymous keys: nothing to read, nothing to leak |

What Frappuccino does **not** protect, stated plainly: the **fact of emitting** is still visible. On the obfuscated transport the upload is inclassifiable as QUIC to signature DPI, but it is not invisible: the timing and volume envelope is unchanged and the destination is a known relay. When that path is blocked (no UDP), the client falls back to pinned TLS, whose handshake carries the relay's **domain name in clear (SNI)** - so a network-positioned adversary can then see *that* and *where* you are uploading. Frappuccino hides **who** you are and **what** you film; it does not promise to hide **that** or **when** you upload, and it is **not a network anonymizer** (combine it with Tor or a VPN if the metadata itself endangers you). A **compromised OS at capture time** sees what the sensor sees; it offers **no court-grade chain of custody** (that is ProofMode's and eyeWitness's territory); and the **paper phrase is a deliberate single point of total failure**.

## Assurance - trust is verified, not declared

A cryptographic system can fail at the design, the implementation, or the compiler level, so each is checked by a tool whose verdict depends on no one's judgment. Every proof ships with a reproducible runner and a negative control - break the mechanism on purpose and the tool must catch it, because a proof that cannot fail proves nothing.

| Layer | Tool | Result |
|---|---|---|
| Protocol vs active network attacker | Tamarin (Dolev-Yao) | 10/10 lemmas + 2 negative controls |
| Ratchet state machine | TLA+/TLC | 2800 states explored, 0 error |
| Untrusted-input parsing (the real Rust) | Kani (bounded model checking) | header parser provably panic-free |
| Kotlin/Rust boundary | Differential fuzzing | 759/759 vectors byte-identical |
| Compiler output | LLVM IR zeroize audit | the secret wipe is never dead-store-eliminated |
| Shipped binary | sha256 manifest + build gate | the crypto `.so` is bound to its commit and toolchain - no swapped binary |

Plus mutation testing, cargo-fuzz, property-based testing, and adversarial AI audits arbitrated by independent re-verification against the code. This prepares an external human audit; it does not replace it.

## Status - read this before relying on it

**Field-test ready. Audit-ready. Not production-ready.**

- Validated in multi-day real-world use on two reference devices (one MediaTek-based, one Snapdragon 8 Gen 3-based); the test relay is operational.
- **No external security audit yet.** The proof suite and the auditor dossier make the project *audit-ready*; an independent human audit (Cure53 / Trail of Bits class) is planned, not done.
- An **on-device forensic validation pass has been performed** (heap, native crash tombstones, filesystem after each scenario); a broader device matrix and production infrastructure remain.
- One test relay, reached by a domain name and TLS-pinned to a small set of keys we control (so a key rotation or seized-relay recovery needs no app update); **Android only**, UI in French and English.

> If lives depend on your footage today, do not make Frappuccino your only line of defense. The known limits are documented with the same care as the features.

## Built to be verified

Frappuccino is developed by a solo developer with an AI as the primary pair programmer - including for the cryptographic code and the internal audits. This is stated up front because it is the condition of trust in everything else: **no security claim rests on an AI's judgment.** Every important property is anchored to a deterministic, replayable, non-AI oracle, and the code is published to be attacked.

A deeper look at the problem, the design choices, and where Frappuccino sits among existing tools - Tella, Signal, ProofMode, eyeWitness - is on the [positioning page](@/positioning.md).
