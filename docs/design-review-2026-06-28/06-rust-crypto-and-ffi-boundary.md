# 100% Rust crypto & the UniFFI boundary — Design rationale (adversarial steelman)

> Model: claude-opus-4-8[1m]. Date: 2026-06-28. Scope: the choice to keep all sensitive crypto in one Rust crate behind a single UniFFI surface, how that surface is minimized (no key getters, combined seal/unseal), the cross-language parity defenses (diff-fuzz, KAT), the server-mirrored domain-separation table, and the `.so` freshness/pin-value gate.

This document is an **adversarial steelman**, not a findings list. For each design choice it makes the strongest affirmative case, justifies the specific implementation against the alternatives that were on the table, states the sharpest honest objection a hostile reviewer would raise (rebutting or conceding it), and surfaces the assumptions and the questions a future adversarial audit should probe. Every claim is grounded in the real code with `file:line` citations.

---

## 1. Scope & the choices under review

The motto governs: *everything leaves the phone fast; a seizure exposes nothing; the phone is a relay, not a vault.* The crypto/FFI domain is where that motto is enforced at the language boundary. The concrete choices:

- **C1 — All sensitive crypto in Rust behind one UniFFI cdylib.** A single `frappuccino-crypto-ffi` crate (`crypto-rs/ffi/src/lib.rs:1-49`) re-exporting `core` (BIP-39, identity, ratchet, PIN store, report keyring, provenance, signature domains) and `stream` (STRM seal/unseal, relay client). The UDL (`crypto-rs/ffi/src/frappuccino.udl:13-645`) is the *entire* contract the JVM may call.
- **C2 — The most sensitive plaintext / keys never cross the boundary at all.** STRM decrypt writes plaintext to a file inside Rust (`strm_decrypt_to_file`, `lib.rs:856-896`); the archive session key is unsealed and consumed in-Rust (`lib.rs:474-481`, the dead `decrypt_session_key` export was removed). The Argon2id-derived PIN key, the ratchet 50-key plaintext, the provenance seed and the report master live in process-global `Zeroizing` holders and are consumed via in-crate closures (`PIN_SESSION` + `with_pin_session`, `lib.rs:1372-1419`; `UPLOAD_JWT`, `lib.rs:1294-1351`).
- **C3 — Minimized FFI surface: no secret getters, combined open/seal calls.** Three families of "ferry the derived key across the FFI" exports were retired: `pin_store_{open_extended,seal_with_key,open_with_key}` (`lib.rs:263-271`, `udl:61-66`), `ArchiveIdentity.decrypt_session_key` (`lib.rs:474-481`), and `{ProvenanceSigner,ReportKeyring}` `seed_bytes()`/`master_bytes()` (`lib.rs:966-972`, `1075-1079`). Replacements seal/open entirely in-crate (`pin_session_open_ratchet`, `lib.rs:1464-1477`; `reseal_session_blob`, `lib.rs:614-626`; `seal_with_session`, `lib.rs:973-982`).
- **C4 — Secrets that must cross are byte buffers, not Java `String`s, with documented zeroization responsibility.** Mnemonic generation returns `Vec<u8>` not `String` (`bip39_generate_fr`, `lib.rs:199-205`); mnemonic/passphrase inputs are `&[u8]` (`EnrollmentKit::from_mnemonic`, `lib.rs:368-381`); the wire contract is documented in the UDL header (`udl:9-11`).
- **C5 — Domain-separated signatures, one byte per context, mirrored on the server.** `SignatureDomain` (`core/src/signature_domain.rs:59-119`) tags every Ed25519 signature; the relay keeps a byte-identical mirror (`server/app/signature_domain.py:28-37`). The FFI never lets the caller choose the tag (`sign_enrollment` hardcodes `Enrollment`, `lib.rs:400-402`).
- **C6 — Cross-language parity proofs: diff-fuzz (759/759) and a Rust↔Python KAT.** A Rust dumper emits a deterministic corpus (`cli/src/bin/difffuzz_dump.rs`), a JVM harness replays it through the real UniFFI→JNA bindings (`difffuzz-jvm/src/main/kotlin/Main.kt`); the report-capability sigs get a fixed-vector KAT pinned on both sides (`core/src/report.rs:608-680` ↔ `server/tests/test_report_sig_kat.py`).
- **C7 — `.so` freshness + pin-value byte-grep gate.** A Gradle task fails the build if the shipped `.so` is older than `pin.rs`, or if any ABI's `.so` does not literally embed every SPKI pin string declared in `pin.rs` (`mobile/build.gradle:30-93`).
- **C8 — `panic = "unwind"` on the release cdylib.** Forced so `uniffi_core`'s `catch_unwind` can turn a crypto panic into a catchable `FfiException` *and* run `Zeroizing` destructors during unwind (`crypto-rs/Cargo.toml:46-54`).

---

## 2. Choice-by-choice rationale

### C1 — All sensitive crypto in Rust behind one UniFFI cdylib

- **What it is.** One Rust workspace (`crypto-rs/Cargo.toml:1-14`) with `core` (primitives), `stream` (STRM + relay), and a single `ffi` cdylib (`crypto-rs/ffi/Cargo.toml`, `[lib] name = "uniffi_frappuccino"`, `crate-type = ["cdylib","staticlib","rlib"]`). The Kotlin app may only touch what the UDL exposes (`frappuccino.udl:13-645`). Crypto dependencies are exact-pinned (`core/Cargo.toml:14-35`: `=0.5.3` argon2, `=2.2.0` ed25519-dalek, `=0.10.1` chacha20poly1305, `=1.8.2` zeroize, etc.).

- **Affirmative case.** The motto requires that a *seizure exposes nothing*. Secrets in a JVM live on a GC heap that is copied around by the collector (no guaranteed wipe), interned for `String`s, and trivially dumped via `am dumpheap` or a rooted device. Concentrating every secret-touching operation in one Rust surface means there is exactly one place to reason about secret lifetime, exactly one place where zeroize-on-drop is the default (`zeroize` with `volatile_set_memory` resists LLVM dead-store elimination, `lib.rs:778-784`), and exactly one trust boundary to audit. The pinned, memory-safe, formally-modelled (Kani/TLA+/Tamarin per MEMORY) primitives replace the JVM's `javax.crypto` provider soup, whose behavior varies per OEM.

- **Why this implementation.** Alternatives considered:
  - *Kotlin/JCA crypto.* Rejected: no guaranteed memory wipe, OEM-dependent provider behavior, `String` immutability/interning leaks for the mnemonic/PIN, and no path to the machine-checked proofs the project relies on. The whole "phone is a relay" posture depends on scrubbable memory, which the JVM cannot promise.
  - *A split implementation (some crypto in Kotlin, some in Rust).* Rejected: doubles the audit surface and creates two code paths that can silently diverge — precisely the failure mode C6's diff-fuzz exists to catch. One surface = one oracle.
  - *Raw JNI by hand.* Rejected: UniFFI generates the marshalling deterministically from the UDL, so the boundary code is not hand-written (and the same codegen runs for the diff-fuzz JVM harness, `difffuzz-jvm/build.gradle.kts:10-16` — JNA, the same path as Android).

- **Adversarial stress.** *"The secret still lands in JVM memory the moment any byte crosses the boundary — you've moved the problem, not solved it."* Largely rebutted by C2/C3: the highest-value secrets (media plaintext, session key, derived PIN key, ratchet plaintext, seeds, JWT) are designed to **never cross**. The residual crossings are (a) PIN/mnemonic *inputs* (bytes, caller-zeroizable) and (b) a few public values. The honest concession: the FFI cannot *force* Kotlin to zeroize the input `ByteArray`s it constructs — the UDL only documents the contract (`udl:9-11`, `lib.rs:251`). A heap dump in the input window is a real residual (acknowledged in the code's own comments).

- **Assumptions & residual.** Rests on: UniFFI 0.28.3 generating correct marshalling (mitigated by C6); the `.so` being the one that was audited (mitigated by C7); the JVM caller actually zeroizing inputs (NOT enforced). Does **not** claim that a rooted, live device with the app unlocked is safe — forward secrecy of *past* rushes is the claim, not protection of the active session (consistent with the documented R-D-1/2 risk-accepted posture).

- **Questions for the future audit.**
  1. Are there any remaining FFI entry points whose Kotlin-side glue materializes a secret in a non-`Zeroizing` `ByteArray` even transiently (e.g. the PIN/mnemonic input path) that could be moved to a Rust-reads-the-file pattern like `strm_encrypt_file`?
  2. Does the pinned dependency set have a `cargo audit`/`cargo deny` gate wired to the publication CI (the `deny.toml` exists; is it enforced)?

### C2 — The most sensitive plaintext / keys never cross the boundary

- **What it is.** STRM decrypt reads ciphertext, decrypts into `Zeroizing<Vec<u8>>`, writes plaintext to disk, returns only non-secret `BlobMetadata` (`strm_decrypt_to_file`, `lib.rs:856-896`); on a write failure it best-effort `secure_delete_file`s the partial output (`lib.rs:877-886`). The encrypt mirror reads the file in Rust (`strm_encrypt_file`, `lib.rs:773-791`). The archive session key is unsealed and used only inside `stream::decrypt`; the FFI getter was deleted (`lib.rs:474-481`, `udl:414-422`). The derived PIN key lives in `PIN_SESSION` and is borrowed by closure (`with_pin_session`, `lib.rs:1417-1419`); the upload JWT lives in `UPLOAD_JWT` and only a per-call copy is handed out (`upload_auth_header`, `lib.rs:1316-1319`), with `upload_auth_present()` letting the chunk path gate on existence without pulling the bearer (`lib.rs:1348-1351`).

- **Affirmative case.** This is the literal implementation of "the phone is a relay, not a vault": the plaintext video exists in clear only on disk (where `secure_delete_file` can scrub it) and in a Rust `Zeroizing` buffer (wiped on drop), never on the GC heap where a dump would catch it. The chunk-upload hot path is **heap-0**: the bearer is read inside Rust and set on the header there (`upload_put_chunk`, `lib.rs:1580-1598`), so no JVM string ever holds the JWT during an active session.

- **Why this implementation.** The file-handoff pattern was chosen over returning a `Vec<u8>` precisely because the forensic finding #2 (`lib.rs:733-741`, `udl:115-120`) showed a returned plaintext lingers as a JVM `ByteArray` for the ms-scale read window. Alternative — a streaming/`AsyncRead` FFI — was avoided because UniFFI's callback-interface streaming is more complex glue (more diff-fuzz surface) for the same outcome; a disk file the caller secure-deletes is simpler and auditable. The process-global holder pattern (`static UPLOAD_JWT`/`PIN_SESSION`) mirrors the old Kotlin `UploadAuthHolder` moved into Rust (`lib.rs:1285-1293`), so the bearer's lifecycle is now in scrubbable memory.

- **Adversarial stress.** *"Plaintext on disk is worse than plaintext in RAM — disk survives a reboot and `secure_delete_file` is best-effort on flash (wear-levelling, F2FS copy-on-write)."* Honest partial concession: on flash, overwrite-in-place is not guaranteed; the defense is overwrite + fsync + truncate + unlink (`secure_delete_file`, `lib.rs:909-912`) which is the best a userspace app can do, plus the file's short lifetime. The rebuttal: the project's threat model already routes everything off-device fast, so the on-disk plaintext window is the consumption window of the *rescue* path (`archive_download_and_decrypt`, `udl:623-633`), not the steady state. Second objection: *"the global statics are process-wide — a second component could read the JWT."* Rebutted: the bearer never leaves Rust on the chunk path (only `upload_auth_header`'s transient copy, used by the legacy OkHttp arm), and `upload_auth_clear` also tears down the connection pool carrying it (`lib.rs:1327-1342`).

- **Assumptions & residual.** Rests on `Zeroizing` actually wiping (machine-proven 0-DSE per MEMORY's zeroize-audit), on the OS file delete behaving, and on the caller invoking `secure_delete_file` after consumption (the FFI documents but cannot force this — `udl:625-626`). Does not claim plaintext is unrecoverable from flash by a forensic lab.

- **Questions for the future audit.**
  1. On the target devices' filesystems (F2FS/ext4 on the OnePlus 13 / Seeker), does `secure_delete_file`'s overwrite actually hit the original blocks, or is the only real protection the short lifetime? Quantify the plaintext-on-disk window for the rescue path.
  2. Is there any code path (logging, crash reporter, `am`/`dumpsys`) where the transient `upload_auth_header` copy could be captured?

### C3 — Minimized FFI surface: no secret getters, combined open/seal calls

- **What it is.** The "derived-key-crosses-the-FFI" exports were systematically retired and replaced by in-crate combined calls: `pin_session_open_ratchet` does Argon2id + stash + deserialize in one in-Rust call (`lib.rs:1464-1477`); `pin_session_open_{provenance_signer,report_keyring}` unseal a secondary secret with the held key and rebuild the object without the seed crossing (`lib.rs:1487-1527`); `reseal_session_blob`/`seal_with_session` serialize-and-seal in-crate (`lib.rs:614-626`, `973-982`, `1082-1091`). The removals are documented inline with their rationale (`lib.rs:263-271`, `udl:61-66`, `lib.rs:474-481`). The only surviving raw `pin_store_seal`/`pin_store_open` exist *solely* for the diff-fuzz parity harness and have 0 prod callers (`lib.rs:269-271`).

- **Affirmative case.** Every export is an attack-surface item and a marshalling-bug opportunity. A getter that returns a 32-byte key turns a Rust-resident secret into a JVM `ByteArray` — exactly the class of leak (R-CR-1) this domain exists to eliminate. Replacing N getters with one combined call shrinks both the leak surface and the diff-fuzz surface, and makes the *secure* path the *only* path (no footgun where a future dev calls the getter by mistake).

- **Why this implementation.** Combined calls were chosen over a "secret handle" object (where Kotlin holds an opaque ref and passes it back) because the holder-static pattern (`PIN_SESSION`) already exists for the JWT and gives the same opacity with a simpler ABI and a single clear point wired to lock/panic/auto-lock (`pin_session_clear`, `lib.rs:1437-1439`; deliberately NOT wired to a 401, `lib.rs:1356-1364`, because the key is not re-derivable without the PIN and clearing mid-recording would strand chunks). Verified end-to-end: the only Kotlin caller of any `*_pk()` getter is `ArchiveIdentity.kt:115-116`, which pulls the **public** Ed25519/X25519 keys (non-secret); the comment at `ArchiveIdentity.kt:42` confirms the secret `decryptSessionKey` getter is gone.

- **Adversarial stress.** *"The combined calls just hide the secret inside Rust statics — a process-global mutable secret is itself a smell, and the `with_pin_session` closure could leak the key via a panic or a captured reference."* Rebuttal: the closure receives `&[u8;32]` by reference and the doc explicitly notes "the key reference never escapes the closure" (`lib.rs:1412-1419`); the static is `Zeroizing` so replacement/drop wipes (`lib.rs:1376-1378`, `1405-1408`); poisoned-lock recovery (`lib.rs:1382-1389`) guarantees `clear` can always zeroize. The real residual: a global secret lives for the whole *unlocked* session by design (it must, to reseal the ratchet without re-prompting). That's the documented forward-secrecy-of-past-rushes-only posture, not a regression.

- **Assumptions & residual.** Rests on the clear points (lock/panic/auto-lock) firing before a heap dump; on no future export reintroducing a getter (the diff-fuzz corpus would not catch a *new* leaky export — it only covers the 5 listed APIs). Does not claim the active-session key is safe from a live root.

- **Questions for the future audit.**
  1. Is there a CI gate (grep/lint) that fails if any new FFI fn returns a secret-shaped `Vec<u8>` / takes a derived key as an argument, or is "no getters" a convention enforced only by review?
  2. Trace every `pin_session_clear`/`upload_auth_clear` trigger against the recording state machine — is there a window (e.g. background recording + screen-off + auto-lock-deferred) where the global key outlives its intended lifetime?

### C4 — Secrets that must cross are byte buffers, not Java `String`s

- **What it is.** `bip39_generate_fr` returns `Vec<u8>` (UTF-8) so the mnemonic never becomes an immutable interned `String` (`lib.rs:198-205`, `udl:20-25`); mnemonic/passphrase inputs are `&[u8]` validated once to UTF-8 inside Rust (`EnrollmentKit::from_mnemonic`, `lib.rs:368-381`; same for `ArchiveIdentity`, `ProvenanceSigner`, `ReportKeyring`); PIN is `bytes` not `string` (`udl:44-59`). The single-word autocomplete helper stays `string` with an explicit risk note (one word does not reveal the phrase, `lib.rs:207-218`, `udl:30-33`).

- **Affirmative case.** A Java `String` is immutable and may be interned — it cannot be wiped and may persist in the string pool. A `ByteArray` is mutable and caller-zeroizable. Returning/accepting bytes is the only way the JVM side *can* scrub the most sensitive secret (the mnemonic) at all.

- **Why this implementation.** The obvious alternative (keep `String` for ergonomics) was rejected for the mnemonic/PIN specifically; the autocomplete word keeps `String` as a deliberate, documented exception where ergonomics win and the secrecy cost is bounded. This is a measured trade, not blanket dogma.

- **Adversarial stress.** *"You return a `Vec<u8>` for the mnemonic, but UniFFI copies it into a JVM `ByteArray` you don't control — and the UTF-8 validation in Rust briefly holds the `&str` view too."* Concession: the JVM `ByteArray` is still the caller's responsibility to wipe (documented, not enforced). The Rust-side `&str` view is over the borrowed input, dropped at function end; the derived secret is what matters and that stays in mlock'd core types. Net: this choice removes the *worst* leak (interned immutable `String`) and leaves the residual the project already accepts.

- **Assumptions & residual.** Rests on Kotlin callers wiping their `ByteArray`s (the `SecureWipe` helper referenced at `lib.rs:17`). Does not claim the mnemonic is unrecoverable if the caller forgets to wipe.

- **Questions for the future audit.** Confirm every Kotlin call site that receives `bip39_generate_fr()` / passes a mnemonic actually zeroizes its `ByteArray` in a `finally`, and that no `String(bytes)` conversion happens en route to the UI.

### C5 — Domain-separated signatures, one byte per context, server-mirrored

- **What it is.** `SignatureDomain` enum, `#[repr(u8)]`, tags 0x01–0x08 (`signature_domain.rs:59-99`); `prefixed()` builds `[tag] ‖ message` (`signature_domain.rs:113-118`). The server keeps a byte-identical mirror (`signature_domain.py:28-37`). The FFI never exposes the tag as a caller argument — `sign_enrollment` hardcodes `Enrollment` (`lib.rs:400-402`), `sign_create`/`sign_write` hardcode 0x07/0x08 inside `core::report`. A test pins the exact tag set and pairwise-distinctness (`signature_domain.rs:126-147`); the retired 0x04 (ArchiveAuth) stays RESERVED so the value is never reused (`signature_domain.rs:69-75`, `.py:31-35`).

- **Affirmative case.** This closes the Tamarin finding that "rotation safety depended on the 40-byte vs 1600-byte length gap" between auth and rotation messages (`signature_domain.rs:7-10`). With explicit tags, a signature minted for one context can never verify in another even if the message bytes coincide — defense-in-depth that survives a future endpoint/length change. Because the tag is *not* a caller argument across the FFI, Kotlin cannot accidentally (or be tricked into) signing under the wrong domain — the secure choice is the only choice.

- **Why this implementation.** A one-byte enum prefix was chosen over (a) per-context distinct keys only (the prior *emergent* separation, flagged as fragile), and (b) a richer structured-prefix (length-prefixed context string) — the single byte is the minimal change that makes separation explicit and cheap to mirror exactly on the Python side. Hardcoding the domain inside the signing fn (rather than passing it) is the misuse-resistant choice.

- **Adversarial stress.** *"A byte-identical hand-maintained mirror across Rust and Python is a drift waiting to happen — the comment even says 'must be kept byte-identical' by hand."* This is the sharpest real objection, and it is the precise gap C6's KAT was built to close for 0x07/0x08 (`report.rs:614-621`). But note the residual: the KAT covers the *report* tags; 0x01/0x02/0x03 parity rests on the route tests, which (the KAT file itself warns, `test_report_sig_kat.py:11-15`) sign in Python with the server's own constants and so *cannot* catch a one-sided drift on those tags. The 0x05/0x06 provenance tags have no server mirror at all (offline verify), reducing their drift blast radius.

- **Assumptions & residual.** Rests on the two source files staying in sync; partially mechanized for 0x07/0x08 only. Does not claim 0x01–0x03 have an automated cross-language drift gate.

- **Questions for the future audit.**
  1. **Top candidate.** Is there a cross-language KAT (like the report one) for the 0x01/0x02/0x03 *auth/rotation/enrollment* signatures, or is their Rust↔Python byte-parity still only protected by tests that sign on one side? A deliberate one-byte change to `SIG_DOMAIN_ENROLLMENT` on only one side — does any test go red?
  2. Confirm the relay's verify sites prepend the tag for *every* of the 4+ verify paths the domain table lists, with no path verifying a raw (untagged) message.

### C6 — Cross-language parity proofs: diff-fuzz (759/759) + Rust↔Python KAT

- **What it is.** *Diff-fuzz:* a Rust dumper (`difffuzz_dump.rs`) emits a deterministic JSONL corpus (splitmix64 PRNG, `difffuzz_dump.rs:43-68`) recording the *reference* outcome of calling the FFI fn directly in Rust for 5 deterministic APIs (bip39 validate, identity-from-pubkeys, ratchet deserialize→serialize round-trip, pin_store_open, archive-from-mnemonic, `difffuzz_dump.rs:121-164`). The JVM harness replays each case through the **real generated UniFFI bindings → JNA → the same Rust fn** (`Main.kt:66-91`) and diffs the canonicalized outcome (`Main.kt:53-59`), comparing *field values* not Display strings (`difffuzz_dump.rs:73-90`). 759/759 matched, 0 crashes (ROADMAP.md:583). *KAT:* fixed report-capability vectors produced by Rust (`report.rs:643-680`) and verified byte-for-byte by the relay (`test_report_sig_kat.py:42-110`), including negative cases (wrong domain, tampered filename must NOT verify).

- **Affirmative case.** The split-implementation failure mode (Kotlin glue diverges from Rust on the same input) is invisible to single-language tests. Diff-fuzz makes it an *oracle*: a divergent value = a marshalling bug; a JVM crash instead of an `FfiException` = an uncaught Rust panic crossing the boundary (which C8 makes impossible). The JNA path is the *same codegen as Android* (`difffuzz-jvm/build.gradle.kts:10-13`), so a desktop pass faithfully exercises on-device glue. The KAT closes the one contract (relay-blind report sigs) where parity was only hand-checked, with both positive and negative vectors.

- **Why this implementation.** A deterministic seeded corpus (vs live property-based fuzzing on two runtimes) was chosen so a failing case is replayable from the file alone (`difffuzz_dump.rs:40-42`). Comparing field values not Display strings avoids false diffs from `thiserror` vs Kotlin `toString` rendering independently (`difffuzz_dump.rs:73-77`) — a thoughtful choice that keeps the oracle precise. The KAT pins exact hex on both sides so either-side drift breaks a test (`report.rs:670-675`).

- **Adversarial stress.** *"759 cases over 5 deterministic APIs is thin — it omits the randomized seal/encrypt APIs, the whole report/upload/relay surface, and any panic-injection. A 'parity proof' that covers ~20% of the UDL oversells."* Largely **conceded**, and the code concedes it too: the dumper's own scope note (`difffuzz_dump.rs:13-17`) says randomized APIs (`strm_encrypt`, `pin_store_seal`) "need a round-trip oracle — a follow-up corpus mode," and ROADMAP marks round-trip mode as "suite" (future). So this is a *baseline* parity check on the untrusted-input→parse surface, not a whole-boundary proof. The rebuttal to the harshest framing: the 5 APIs chosen are exactly the audit-flagged untrusted-input marshalling surface (`difffuzz_dump.rs:13-16`), which is where a glue bug is most dangerous; the rest is lower-risk (public values, or covered by the KAT for the report sigs).

- **Assumptions & residual.** Rests on the bindings under test being regenerated from the current UDL (the harness uses `../target/debug`, `build.gradle.kts:31-36`; stale bindings would test the wrong thing). Does not claim parity for the randomized/upload/relay APIs, nor panic-resistance beyond what C8 guarantees structurally.

- **Questions for the future audit.**
  1. **Top candidate.** Does the diff-fuzz corpus run in CI against *freshly regenerated* bindings, or is 759/759 a one-time local result? A stale-bindings run would be green-but-meaningless.
  2. What is the parity story for `strm_encrypt`/`pin_store_seal`/the report-upload FFI fns — is the round-trip oracle mode built, or is the only protection for those the (hand-maintainable) KAT + single-language tests?

### C7 — `.so` freshness + pin-value byte-grep gate

- **What it is.** A Gradle `checkRustSoFresh` task (`mobile/build.gradle:30-93`), wired into `preBuild` (`build.gradle:91-93`), that: (a) fails if the `.so` is missing (`build.gradle:39-46`); (b) fails if the arm64 `.so` mtime predates `pin.rs` (`build.gradle:47-57`); (c) parses every `PIN_(SHA256|NEXT|NEXT2)_B64` constant out of `pin.rs`, asserts there are ≥3 (the primary + 2 break-glass invariant, `build.gradle:65-71`), and **byte-greps each ABI's `.so` for every pin string** (reading the `.so` as ISO-8859-1 so the search is an exact byte match, `build.gradle:79-87`).

- **Affirmative case.** The `.so` and its bindings are **not git-tracked** (regenerated by `build-android.sh`) — so the single most dangerous silent failure is shipping a stale binary built against an old SPKI pin, which manifests as a runtime TLS handshake failure (observed for ~a day, `build.gradle:20-29`). The mtime check catches "forgot to rebuild"; the value-grep catches the case the mtime check *cannot* — a `.so` rebuilt from a *different* pin value (stale branch, hand-built, a dropped break-glass pin, `build.gradle:58-64`). Together they make "the shipped binary trusts exactly the declared pin set" a build invariant, not a hope.

- **Why this implementation.** Byte-grepping the `.so` for the literal base64 pin string was chosen over (a) mtime-only (proven insufficient, `build.gradle:58-64`) and (b) a full symbol/hash manifest of the `.so` (heavier, and the pin strings are ASCII so a substring search *is* an exact byte-grep). The ≥3 count assert encodes the break-glass 2-pin TLS rotation design as a gate so a rotation can never silently drop the break-glass key.

- **Adversarial stress.** *"This proves the pin *strings* are present in the binary; it proves nothing about whether the `.so` is the one built from the audited source. A malicious or buggy `.so` that embeds the right pin strings sails through."* **Conceded** — this is a *freshness/consistency* gate, not a *provenance* gate. It defends against the operational footgun (stale binary), not against a supplied-binary attack. The right complement (reproducible builds / a signed `.so` hash) is, per MEMORY, explicitly a risk-accepted non-goal for now (§8.4 closed: repro-builds not pursued). Second objection: the grep is a substring match, so a pin value that happens to be a substring of another would false-pass — low risk for 44-char base64 SPKI hashes but worth noting.

- **Assumptions & residual.** Rests on the build being run from a trusted checkout with the real `build-android.sh`; the gate is mtime + content-presence only. Does not claim the `.so` matches the source (no hash/repro-build), and the gate is dormant without a remote/CI (it runs at local `preBuild`).

- **Questions for the future audit.**
  1. Is there *any* check that the shipped `.so` corresponds to the current `crypto-rs` source (a content hash committed alongside, a reproducible-build attestation), or is "the `.so` is what the source produces" entirely operator-trusted? This is the provenance gap the freshness gate explicitly does not cover.
  2. The bindings (`stream-crypto/.../uniffi/frappuccino/frappuccino.kt`) are generated from the UDL, not the `.so` — is there a gate that the *bindings* are fresh vs the UDL? A stale-bindings/fresh-`.so` mismatch would diverge silently (and would also invalidate C6's harness).

### C8 — `panic = "unwind"` on the release cdylib

- **What it is.** `[profile.release] panic = "unwind"` with an explicit security comment (`Cargo.toml:46-54`); `opt-level = "s"`, `lto = "fat"`, `codegen-units = 1`, `strip = "symbols"`.

- **Affirmative case.** `uniffi_core` wraps every exported fn in `catch_unwind`. With `unwind`, a crypto panic becomes a catchable `FfiException` *and* — critically — runs every `Zeroizing` destructor during the unwind, scrubbing decrypted plaintext before the error surfaces. With `abort`, the process SIGABRTs before any unwind: the whole host app dies *and* the decrypted plaintext stays live in the abort tombstone (a forensic artifact). This directly serves "a seizure exposes nothing."

- **Why this implementation.** `abort` is the common size-optimization default for cdylibs; it was *deliberately rejected* here for the destructor-during-unwind guarantee, accepting a few tens of KB of unwind tables as a security cost (`Cargo.toml:53`). This is a considered trade documented at the point of decision.

- **Adversarial stress.** *"Unwinding across an FFI boundary is itself UB-adjacent, and a panic mid-crypto could leave a global static (`PIN_SESSION`) in a torn state."* Rebuttal: `catch_unwind` at the UniFFI boundary is the supported pattern (the panic is caught before it crosses into JNA); the global holders use poison-recovery (`lib.rs:1303`, `1387`) so a poisoned lock still allows the clear to zeroize. The destructors that run during unwind are the *point*, not a hazard.

- **Assumptions & residual.** Rests on `uniffi_core` actually wrapping every export in `catch_unwind` (true for 0.28.3) and on no `panic = "abort"` creeping into a dependency's final link. Does not claim panics are impossible — it claims they are caught and scrubbed.

- **Questions for the future audit.** Confirm no transitively-linked crate or build profile re-imposes `abort`, and that the diff-fuzz harness's "JVM dies, no summary" detection (`Main.kt:11-12`) has actually been exercised against an intentional panic to prove the unwind path works end-to-end.

---

## 3. Domain coherence & tensions

The choices form a coherent, layered defense around one idea: **the secret-handling perimeter is the Rust `.so`, and that perimeter is kept thin, verified, and fresh.**

- C1 (one Rust surface) + C3 (minimize it) + C2 (keep secrets inside) are the same principle at three altitudes: concentrate, shrink, and don't leak. C4 handles the unavoidable crossings (inputs) as scrubbable bytes. C8 makes even a *crash* respect the perimeter (scrub-on-unwind).
- C5 (domain separation) is orthogonal protocol hardening, but it interacts with C3's misuse-resistance: hardcoding the tag inside the signing fn means the thin FFI surface also can't be misused to cross-sign.
- C6 (parity) and C7 (freshness) are the *meta* layer: they defend the boundary itself. C6 says "the glue is faithful," C7 says "the shipped binary is the current one." They are complementary and both partial.

**Internal tensions worth flagging to the next audit:**

1. **Hand-maintained Rust↔Python mirrors vs. partial mechanization.** C5's domain table and the report crypto are mirrored by hand; only the 0x07/0x08 tags have a cross-language KAT (C6). The 0x01–0x03 auth/rotation/enrollment tags rely on tests that, by the KAT file's own admission (`test_report_sig_kat.py:11-15`), can't catch one-sided drift. This is the single most coherent gap: the defense *exists for one tag family and not the others.*

2. **Freshness without provenance.** C7 proves the `.so` is current and embeds the right pin *strings*, but nothing proves the `.so` was built from the audited source (no repro-build/hash). Given the threat model (state adversary, seizure), an auditor will reasonably ask why binary provenance is risk-accepted while everything else is belt-and-suspenders. The answer (per MEMORY: §8.4 repro-builds judged marginal ROI without CI/remote) is defensible but should be re-litigated at publication.

3. **Parity coverage vs. claimed strength.** 759/759 reads as a strong number but covers 5 deterministic APIs; the randomized seal/encrypt and the entire upload/relay FFI are out of scope. The code is honest about this (`difffuzz_dump.rs:13-17`); the *presentation* (a headline "759/759") could mislead a reader into over-trusting boundary coverage.

4. **Global session secrets vs. forward secrecy.** C2/C3's process-global `PIN_SESSION`/`UPLOAD_JWT` must live for the unlocked session to avoid re-prompting — a deliberate, documented trade that protects *past* rushes but not the *active* session against a live root. Coherent with the stated posture, but the clear-trigger matrix (lock/panic/auto-lock, never-on-401) deserves a dedicated state-machine review.

---

## 4. Top-3 questions this domain hands to the future adversarial audit

1. **Cross-language drift for the non-report signatures.** The report capability sigs (0x07/0x08) have a byte-pinned Rust↔Python KAT, but the auth/rotation/enrollment sigs (0x01/0x02/0x03) appear protected only by per-language tests that sign with each side's own constants — which the KAT file itself says cannot catch one-sided drift. *Does a deliberate one-byte change to `SIG_DOMAIN_ENROLLMENT` (or the signed-message layout) on only the Rust **or** only the Python side make any test go red?* If not, every real enroll/auth/rotate would 403 in production while CI stays green — extend the KAT pattern to these tags.

2. **Is the parity/freshness machinery actually live, and against fresh artifacts?** The 759/759 diff-fuzz and the `.so` freshness gate are only as good as their execution context. *Does the diff-fuzz corpus run in CI against freshly regenerated bindings (not `../target/debug` leftovers), and is `checkRustSoFresh` plus the bindings-vs-UDL freshness actually enforced on the path that produces the published APK?* A stale-bindings green run, or a freshness gate that's dormant without a remote, would void both defenses.

3. **Binary provenance, not just freshness.** C7 proves the `.so` is current and embeds the declared pins, but nothing ties the shipped `.so` to the audited source. For a state-adversary threat model, *what prevents a stale-branch, hand-built, or substituted `.so` (that happens to embed the right pin strings) from shipping* — i.e., is reproducible-build / signed-hash attestation a publication blocker, or permanently risk-accepted? This is the one place the otherwise belt-and-suspenders perimeter has only a single, presence-based check.
