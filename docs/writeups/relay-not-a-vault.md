# A relay, not a vault: designing an Android app for the moment it is seized

> *What a forensic examiner finds on a seized phone, and why the design starts
> from the assumption that the device is the adversary's.*

> **Draft - technical writeup, EN.** Companion to
> [the proof-stack writeup](proving-ai-assisted-crypto.md), which covers how the
> cryptography is verified. This one is the concrete Android attack surface under
> seizure. Status: not yet audited by an external party. The repository goes
> public with the 8.2.5 release.

## The scene

An activist films an abuse. Then the phone is taken: at a checkpoint, a border,
in custody, or snatched mid-recording. What follows is predictable: the device is
seized, the PIN is coerced, and the hardware goes to a Cellebrite or GrayKey
bench where storage is imaged and local vaults are brute-forced offline.

Most secure-capture apps answer this by encrypting files on the device. That
fits the threat poorly, because a safe can be opened: by brute-forcing the code,
by coercing the person who knows it, by exploiting the OS. As long as the data
and the key that reads it both live on the phone, the phone is a single point of
failure, and it is exactly the thing the adversary is holding.

[Frappuccino](https://shake-document-protect.org) (a fork of Tella FOSS, Apache
2.0) takes the other route: not a better safe, but no safe at all. The
architecture (chunked end-to-end upload to a blind relay while filming, a reading
key that exists only on paper, a device that can encrypt but never decrypt its
own past) is on [the positioning page](https://shake-document-protect.org/positioning/)
and proven in [the companion writeup](proving-ai-assisted-crypto.md). This piece
is only the forensic surface that design produces, on the phone and on the server,
and it is honest about what leaks.

## On the seized phone

### At rest: nothing readable without the paper

Whole-device File-Based Encryption is the load-bearing at-rest control, and the
design leans on it rather than reinventing it: a forensic image without the device
key is ciphertext. On top of that, even with the device unlocked there is no
content and no identity to read:

- **No reading key on the device.** The X25519 secret that decrypts archived
  streams is derived from the BIP-39 phrase on demand and never persisted. Without
  the paper phrase, the phone can seal but never unseal.
- **No identity at rest.** The current wire format (STRM V3) removed the author
  public key that older versions wrote into every blob header. The `report_id`
  the relay uses is `SHA-256("stream.report.id.v1" || report_pk)[..16]`, with no
  link to a person in the stored bytes; that link exists only through the paper
  phrase. A dump of the app's storage does not say *who*.
- **The ratchet blob is sealed under the PIN.** The single-use signing keys are
  persisted only inside an Argon2id-wrapped, XChaCha20-Poly1305-sealed blob.
  Coercing the PIN yields at worst a bounded, server-detectable window of *future*
  signatures (every slot use is tracked, revocation cuts it off), never past
  content.

### The plaintext window, and how it is closed

There is one unavoidable moment of plaintext: `MediaMuxer` writes each finished
chunk as a clear `chunk-NNN.mp4` in `cacheDir/stream_chunks/` before the Rust
layer encrypts it. After the chunk is finalized, the Rust layer reads it,
encrypts it (tens to ~100 ms), and secure-deletes it. Under normal load one clear
chunk exists at a time; if encryption threads back up, more than one can briefly
coexist, with the worst case bounded by the 5 s rotation cadence. The exact
maximum window is an open question in our own design review, not a number I will
invent. Closing that window cleanly is most of the on-device engineering:

- **Secure deletion, not just `remove_file`.** After encryption the clear file
  goes through `secure_delete_file`: overwrite with `OsRng` bytes, `fsync` to force
  the page cache to disk, truncate, unlink (single pass, per NIST SP 800-88). On
  flash this is best-effort: wear leveling can leave a residual copy in a remapped
  block, which the module documents as an accepted residual. FBE makes that
  residual unreadable to a disk-image attacker without the device key. Against an
  examiner who already has the coerced PIN, the residual is exactly why secure
  deletion is defense-in-depth and not the whole answer.
- **Orphan purge, any size.** If the process dies abnormally mid-encrypt, a
  finished-but-unencrypted `.mp4` could otherwise survive. `CaptureScratchCleaner.purgeOrphanChunks`
  secure-deletes every orphan `.mp4` regardless of size. An earlier version only
  swept zero-byte files, which left exactly that clear chunk recoverable; a
  cross-vendor audit found it and it was fixed. It runs at service start (before
  capture binds), on teardown, and on panic-wipe.
- **A fail-closed capture pipeline.** The 5 s rotation loop was hardened so no
  failure path can strand a clear chunk or wedge silently:
  - Media-codec drain threads swallow unexpected exceptions and log them, instead
    of aborting the process.
  - Every GL and muxer wait has a timeout. An unbounded GL-teardown wait could
    previously hang before the last chunk was finalized and encrypted; adversarial
    review caught it, and it is now bounded.
  - After repeated rotation failures the service stops itself through the same
    clean path as a storage-full condition.

  Field runs on two devices logged hundreds of rotations with `orphans=0` and no
  stranded plaintext. That metric is the app's own counter, not a raw flash image;
  confirming no remapped residual on physical NAND is the wear-leveling caveat
  above, not something the counter can see.

### Heap and crash forensics

A forensic examiner does not stop at the filesystem.

- **Secrets in the JVM heap.** An upload bearer token once survived in the JVM
  heap after lock, reachable with `am dumpheap`, because the Kotlin HTTP stack
  retained copies the app could not purge. Two changes close the worst case (a
  stolen post-lock token): the relay enforces write-once on blobs, so a stolen
  token cannot overwrite or corrupt an authentic chunk and there is no delete
  route; and the bearer is held on the Rust side in a `Zeroizing` buffer, wiped on
  lock. The token still lives in the JVM heap *during* an active upload; pushing it
  fully out (uploading from Rust) is deferred, and the writeup says so rather than
  claiming heap-zero.
- **Native crash tombstones.** A `SIGSEGV` writes a tombstone: a register and
  memory snapshot at crash time. Because the Rust secrets zeroize on `Drop` and the
  release profile unwinds (running those destructors before the process aborts),
  on-device tests across idle, archive, and mnemonic-on-screen states found zero
  plaintext, zero bearer token, and zero mnemonic words in the tombstones. That was
  a debuggable build on one device, and the purity is argued structurally
  (a tombstone is not a heap dump) more than proven exhaustively; a `SIGSEGV`
  *inside* a decrypt could still leave a bounded register-proximal fragment, which
  is listed in the accepted-residuals file.
- **One isolated `unsafe` module.** Long-term identity secrets (the Ed25519
  signing key, the archive X25519 key, report and provenance keys) live in a
  `LockedSecret` type that `mlock`s the pages against swap and zeroizes on drop.
  That `mlock`/`munlock` is the only hand-written `unsafe` in the crypto core, in
  one commented module (the vetted dependencies contain `unsafe`, as every crypto
  stack does). The ephemeral ratchet keys are zeroize-only by design: Android uses
  zram rather than disk swap, so `mlock` buys little there and would touch the hot
  path. That trade is in the design review.

## On the seized relay

The server is treated as an adversary from the start: legal seizure, intrusion, a
disloyal operator. So it is built to have nothing worth taking.

- **It holds no key that can decrypt content.** Be precise here, because it is the
  kind of claim a hostile reader checks: the relay *does* hold keys. A TLS private
  key, a JWT signing secret, object-store credentials, and the app-embedded
  obfuscation PSK. None of them decrypts a blob. Content is sealed to an X25519 key
  whose private half exists only on paper, off every machine.
- **The registry is identity-free.** It stores only `{report_id, report_pk}`; the
  source comment in `reports.py` states it plainly: *deliberately NO owner, NO
  author, NO createdAt, NO title... a seizure exposes nothing.* The ratchet
  registry holds a pseudonymous public key and per-batch slot counters, no content
  and no IP.
- **No decision leaks through an error.** The batch-rotation route verifies the
  request signature first, over caller-supplied data only, then folds every
  rejection into one byte-identical `401`. Before the fix, a rejection body leaked
  the target's `batch_number`, an oracle that turned an identity query into an
  activity signal. There is no status endpoint left to probe.
- **No IP logs.** The application does not log client IPs (access logging is off at
  the proxy and the app layer). What the hosting provider sees at the IP layer is a
  separate, documented residual the app does not claim to hide.

## On the wire, briefly

Uploads go over QUIC wrapped in a Salamander obfuscation layer: a stateless
per-packet XOR scrambler (an 8-byte salt plus a BLAKE2b keystream under a
pre-shared key), byte-compatible with Hysteria2, so signature-based DPI finds no
QUIC or TLS markers to classify. When UDP is blocked, the client falls back to a
custom rustls verifier pinned to a small SPKI set we control, which rejects a
man-in-the-middle holding a valid CA-signed certificate.

The honest limit, treated at length in the metadata analysis: obfuscation buys
inclassifiability, not invisibility. The size and timing envelope is unchanged,
and on the TLS fallback the relay's domain name rides in the clear in the SNI
field. Frappuccino hides who you are and what you filmed, not necessarily that or
when you uploaded. It is a transport, not a network anonymizer; if the metadata
itself endangers you, combine it with Tor or a VPN.

## What a seized phone still gives up

The device-specific residuals, stated with the same care as the features (the
full list, including the paper-phrase single point of failure and the absence of
court-grade chain of custody, is on [the positioning page](https://shake-document-protect.org/positioning/#4-what-frappuccino-does-not-claim)):

- **The metadata envelope is visible.** A network-positioned adversary can
  establish that someone is streaming, and the enrolled public key in the registry
  lets the relay count sessions per identity even though it cannot read them.
- **A compromised OS at capture time sees what the sensor sees.** Encryption starts
  downstream of the camera; no app defeats malware reading the screen.
- **Flash residue under a coerced PIN.** Secure deletion is best-effort on flash,
  and FBE only shields the residual from an attacker without the device key. Give
  an examiner the PIN and the two backstops that make the plaintext window small
  are the ones doing the work, not a guarantee that no byte ever remains.

## Come break it

The attack surface is deliberately small and written down: a brief per-chunk
plaintext window closed three ways, an at-rest state with no content and no
identity, a relay built to hold nothing that decrypts, and a transport honest
about the metadata it cannot hide. The residuals file says where I already think
the soft spots are (flash-residual secure deletion, the metadata envelope, the
JVM-heap token during upload). The auditor's guide and the scope-and-invariants
document are the place to start, and the proof runners replay from a clean clone.

The repository goes public with the 8.2.5 release. If the model is wrong about what
a seized phone gives up, the fastest way to find out is for a forensic examiner to
take one apart.
