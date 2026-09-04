+++
title = "Positioning"
description = "The problem Frappuccino answers, how, and where it sits among existing tools - Tella, Signal, ProofMode, eyeWitness."
+++

> **What this is:** the problem Frappuccino answers, how it answers it, and where it sits next to existing tools. The register is the same as the rest of the project - transparency: what the tool does, what it does not, and what the others do well. Where this page and the code diverge, **the code is authoritative.**

## In one sentence

**Frappuccino turns an Android phone into a transmitter of encrypted video testimony: the video leaves while it is being filmed, toward a relay that cannot read it, and the only key is a twelve-word phrase written on paper.** Seizing the phone - before, during, or after recording - no longer yields anything to read.

## 1. The problem

A militant films an abuse. A journalist documents a sealed-off site. A lawyer records an arrest. Three things can happen to them, often in this order: the **phone is seized** (checkpoint, border, custody, or snatched mid-capture); the **PIN is coerced**; and the hardware goes to **forensic extraction** (Cellebrite, GrayKey - storage imaged, local vaults brute-forced offline). At the other end of the chain, the server that receives the footage is itself a target: legal seizure, intrusion, a disloyal operator. And in between, the network can be intercepted.

For testimony to survive that scenario, three requirements must hold **simultaneously**:

- **(a) Survive seizure and wiping of the device.** The content must exist somewhere other than the phone, and stay recoverable by the witness - including from a brand-new device, with no account, no cloud, no third party.
- **(b) Be unreadable by the server.** If the relay is seized or hostile, it must have nothing to hand over but opaque bytes. A server cannot betray what it cannot read.
- **(c) Hold even if the phone is snatched mid-recording.** A local file encrypted "at the end" protects nothing if capture is interrupted by force. The video must leave the device as it is captured, already encrypted.

The classic answer - encrypt the files on the device - fits this poorly: **a safe can be opened.** By brute-forcing the code, by coercing its holder, by exploiting the OS. As long as the data is *on* the phone and the reading key is there too, the phone stays the single point of failure - and it is exactly what the adversary holds. The problem is not to lock the safe better. It is to **stop being a safe.**

## 2. Our answer

> *"The phone is a transmitter. Not a safe."*

Frappuccino is a fork of Tella FOSS (Horizontal.org): the Android documentation base for activists is kept; the core - cryptography, capture, transport, trust model - is replaced. Five choices structure the answer.

- **The video leaves while it is filmed.** Recording is cut into 5-second chunks, each end-to-end encrypted **on the device** then uploaded immediately. Snatch the phone at minute 12 and the first 12 minutes are already out of reach. The pipeline is built for the field: hardware **HEVC** (≈35-45% less bitrate than H.264, automatic H.264 fallback), network-adaptive quality, a **persistent** upload queue that survives network loss, reboot, and process death, screen-off recording, shake-to-stream, a stealth black screen one gesture away. Uploads run over QUIC (HTTP/3) wrapped in a Salamander obfuscation layer, with a transparent fallback to pinned TLS, so the flow resists DPI fingerprinting and keeps moving under a degraded or hostile network.
- **A relay that cannot betray: the blind server.** It stores only **opaque blobs**, encrypted before leaving the device to a key whose private half exists on **no machine**. It verifies signatures, enforces anti-replay, stores and returns bytes; it never sees an image and does not log IPs. Server seizure is a **design input, not a failure mode**, and the operator - us included - is treated as potentially hostile.
- **The key is not in the phone: twelve words on paper.** At enrollment the device generates a 12-word BIP-39 phrase, shown once, never stored - the **sovereign key**. Phone seized, destroyed, wiped? On a new device: archive mode, type the twelve words, "recover my streams." No authority - us included - can restore or reset it. An optional 13th word derives a disjoint identity. The flip side, stated plainly: **whoever holds the phrase holds everything**, and a lost phrase means permanently unreadable archives.
- **The past is out of reach - and it is proven.** After enrollment the phone can encrypt and sign but can **never decrypt its own past**. The X25519 reading key is never persisted on the device - it is derived from the phrase, in locked memory, only for the duration of an archive session; authentication uses an **ephemeral-key ratchet** inspired by Algorand's forward security - batches of 50 single-use signing keys, each destroyed immediately after use, each batch authenticated by the previous one back to the original identity. An adversary with the phone, the PIN, and a memory dump gets at worst a few bounded **future** signatures - never one byte of past content. This forward secrecy is proven in **Tamarin** (Dolev-Yao), the state machine is model-checked in **TLA+/TLC**, and the key wipe is verified at the **compiled-code (LLVM IR)** level.
- **Trust is verified, not declared.** All sensitive cryptography is in **Rust** (zero `unsafe` outside one isolated, commented memory module; exact-pinned dependencies; self-wiping secrets) - no homemade primitives, only public battle-tested building blocks assembled by protocol logic that is what we get verified, with a reproducible runner and a negative control per proof.

## 3. Next to other tools

None of the tools below is an adversary: several are **complementary**, and each does better than Frappuccino on its own turf. The table situates the combination; the notes add nuance.

| Capability | Frappuccino | Tella | Signal | ProofMode | eyeWitness |
|---|---|---|---|---|---|
| Built for field video testimony | **Yes** | Yes | No (messaging) | Yes (photo/video) | Yes |
| Content leaves the device **during** capture, encrypted | **Yes** | No (sent afterward) | No | No | No (sent after capture) |
| Server structurally unable to read (blind relay) | **Yes** | No¹ | N/A² | N/A | No (the institution reads - that is its function) |
| Device seized: nothing readable locally | **Yes** | Partial (local vault = target) | Partial | No | Partial (after sending) |
| Device compromised: the past stays unreadable (forward secrecy) | **Yes, formally proven** | No | Yes (messages) | N/A | Not documented³ |
| Sovereign recovery with no third party (12-word phrase) | **Yes** | No | No | No | No (via the institution) |
| Authenticity / chain of custody for a court | **No (not the goal)** | Partial (metadata) | No | **Yes** | **Yes** |
| Maturity, community, external audits | **Not yet** | Yes | Yes | Yes | Yes |

¹ The destination server (Tella Web, Uwazi) receives and reads the reports - by design; the militant's own organization operates it.
² Signal does not store content server-side; it simply offers no archival function.
³ To our knowledge; institutional trust model, code not public.

**Tella - the upstream, and what we owe it.** A field-proven documentation app by Horizontal, translated into 17 languages, on Android, iOS, and F-Droid: local encrypted vault, app camouflage, structured collection (ODK forms) toward an organization's servers. For an NGO coordinating a collection with its own server, **Tella remains the right tool** - and its scope (iOS, forms, multilingual) exceeds ours. Frappuccino inverts the model: real-time encrypted streaming to a blind relay, nothing readable left on the device, recovery by the twelve words. We also **removed** the calculator camouflage and ODK forms on purpose - our bet is different: rather than *hide* the app, make an app that, found, opened, and unlocked, **has nothing to show.**

**Signal - coordination, not archival.** A remarkable encrypted messenger: to **communicate**, it is the tool. But the video does not leave encrypted *during* capture, history lives on the device, and recovering content from a destroyed or confiscated phone is not its purpose. Signal protects the conversation; Frappuccino protects the **capture and the archive.** On the ground you typically need both.

**ProofMode - authenticity, our natural complement.** ProofMode (Guardian Project / WITNESS) answers the symmetric question: not "how to put testimony out of reach" but "how to prove it is authentic" - cryptographic signatures, capture metadata, verifiability. That is precisely what Frappuccino does **not** do today. The two approaches are complementary; a provenance integration is a conceivable horizon, not a promise.

**eyeWitness to Atrocities - the institutional path.** eyeWitness (International Bar Association) captures with verified metadata and transmits to an institution that **keeps, certifies, and can testify** to integrity in court. To build a judicial case with a trusted third party, that model is strong - stronger than ours. Its flip side is structural: the server is not blind (it *must* read to certify), and trust rests on the institution. Frappuccino makes the opposite choice: no one but the witness can read, and no one has to be trusted.

## 4. What Frappuccino does not claim

The credibility of a tool for people at risk is decided in this list (detail in the architecture document, sections 2 and 10):

- **The content is protected; the fact of emitting is not.** Sizes, timing, and the destination seen by the operator let a network-positioned adversary establish *that* someone is streaming. The app does ship an obfuscated transport (Salamander-wrapped QUIC, field-validated) that makes the upload inclassifiable as QUIC to signature DPI, but that buys inclassifiability, not invisibility: the timing and volume envelope is unchanged. When UDP is blocked the client falls back to pinned TLS, whose handshake now carries the relay's **domain name in clear (SNI)**, so on that path *that* and *where* you upload are visible. Frappuccino hides **who** and **what**, not necessarily **that** or **when**; it is not a network anonymizer, and an adversary able to block UDP/443 can force the classifiable TLS fallback (and its SNI) - an accepted residual, not a future fix. If the metadata itself endangers you, combine it with an appropriate network layer (Tor/VPN).
- **A compromised OS at capture time sees what the sensor sees.** Encryption starts downstream of the camera; no app can defeat malware that reads the screen.
- **No court-grade chain of custody** (see ProofMode / eyeWitness above).
- **The paper phrase is a deliberate single point of total failure:** coercion on the phrase is a complete defeat; a lost phrase means unreadable archives.
- **Android only**, French/English, one test relay so far (reached by domain, pinned to a small set of keys we control).
- **Not yet audited by an external human party.**

## 5. Status and trajectory

**Field-test ready, audit-ready - not production-ready.** Validated in multi-day real-world use on several devices, with a test relay operational and an assurance dossier (formal proofs, reproducible runners, auditor guide) unusual for a project this size. But for the threat model it targets - seizure, Cellebrite, coercion - high-risk deployment still waits on the external cryptographic audit, the broader device matrix, and production infrastructure.

The positioning itself fits in three lines:

> **Not "better than everything." A combination nothing else offers, to our knowledge: video testimony that leaves the device during capture, encrypted toward a relay unable to read it, whose past is out of reach of the device itself - with formal proof - and whose only key is twelve words on a piece of paper, in the witness's pocket.**

## A personal note

*Beyond Frappuccino, there is the question of what AI becomes - the asymmetry of force and power, of the exploited and the trillionaires. AIs are tools dressed in a particular culture, and their human and environmental costs are not in doubt. That culture is what makes their adoption feel natural in tech circles and liberal persuasions. And yet tools they remain - and more than tools: they are weapons. With these tools, I decided to see how far I could go, and whether, with a little luck and a lot of patience, I could put out code that is available, free, and open - ready to be audited, and solid enough for others to make it better, and make it useful to everyone.*
