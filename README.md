# Frappuccino

> **The phone is a transmitter. Not a safe.**

Frappuccino turns an Android phone into a transmitter of end-to-end encrypted video
testimony. Footage leaves the device **while it is being filmed**, toward a relay that
**cannot read it**, and the only key that can ever decrypt it is a **12-word phrase on
paper**, in the witness's pocket. Seizing the phone, before, during, or after recording,
no longer yields anything to read.

It is a deeply reworked fork of [Tella FOSS](https://github.com/Horizontal-org/Tella-Android)
by Horizontal: the Android shell is inherited, the core (cryptography, capture, transport,
trust model) is replaced, and all sensitive cryptography is in **100% Rust**.

> **Status: field-tested, audit-ready, NOT production-ready.**
> No external security audit yet. Read [Status](#status) before relying on it.

---

## Repository layout

| Path | Language | Contents |
|---|---|---|
| `crypto-rs/` | Rust | Cryptographic core, including the report writer that encrypts and signs each chunk as it is recorded, and the rescue that verifies before decrypting. No key derivation, no content encryption and no signature happens outside it. Kotlin keeps three named exceptions, all over public data: a truncated SHA-256 recording id, a SHA-256 key fingerprint shown to the user, and `SecureRandom` for the session id (`AUDIT_SCOPE_RUST.md` §2 names them). |
| `stream-crypto/` | Kotlin | Capture pipeline (CameraX, OpenGL ES wedge, HEVC MediaCodec), upload queue, UniFFI call sites. |
| `mobile/` | Kotlin | Android application: UI, lock gate, foreground recording service, WorkManager orchestration. |
| `server/` | Python | Blind relay (FastAPI + MinIO). Deliberately small; treated by the client as a hostile black box. |
| `server-tools/` | Python | Desktop recovery tooling. |
| `docs/` | FR/EN | Architecture, auditor's guide, threat model, audit reports. |

The Rust workspace declares six crates. Four ship in the app or alongside it:

- **`core`** identity, ratchet, key derivation, PIN store
- **`stream`** the STRM wire format, blob sealing, header parsing, TLS pinning
- **`ffi`** the UniFFI boundary exposed to Kotlin
- **`cli`** `frappuccino-cli`, a desktop tool that fetches and decrypts archives from the phrase alone

Two do not ship in the app: **`obfs-proxy`** (server-side traffic de-obfuscation) and
**`quic-spike`** (an explicitly throwaway transport experiment, kept for the record).
Outside the workspace, `difffuzz-jvm/`, `fuzz/`, and `parity-vectors/` hold the
differential-fuzzing harness, the cargo-fuzz targets, and the cross-implementation vectors.

## Architecture at a glance

```
[ Android app (Kotlin: mobile/, stream-crypto/) ]
  CameraX -> OpenGL ES wedge -> HEVC MediaCodec -> 5 s MP4 chunks
      |
      |  UniFFI bindings (sensitive material crosses as wiped byte arrays)
      v
[ Rust core (crypto-rs/) ]
  BIP-39 identity, ephemeral signature ratchet, STRM blob sealing,
  Argon2id PIN store, SPKI-pinned TLS client
      |
      |  HTTPS, pinned certificate
      v
[ Blind relay (server/, FastAPI + MinIO) ]
  opaque STRM blobs, signature verification, anti-replay,
  single-use slots, strict rotation monotonicity, no IP in logs
```

Video plaintext is read, sealed, and written file to file by Rust: it does not cross the
JVM heap. Deep dive:
[docs/ARCHITECTURE_TECHNIQUE_COMPLETE.md](docs/ARCHITECTURE_TECHNIQUE_COMPLETE.md).

## Building

Prerequisites: Rust pinned to **1.88.0** by `crypto-rs/rust-toolchain.toml` (rustup selects
it automatically), `cargo-ndk`, Android NDK r26+, a JDK for the Gradle wrapper, Docker for
the relay.

```bash
# 1. Rust core: tests and lint gate
cd crypto-rs
cargo test --workspace
cargo clippy --all-targets -- -D warnings

# 2. Android .so + Kotlin bindings.
#    Required BEFORE the app build: generated artifacts are not tracked in git, and a
#    Gradle guard (checkRustSoFresh) refuses stale or missing native libraries.
./build-android.sh                       # arm64-v8a, armeabi-v7a, x86_64
# TARGETS=arm64-v8a ./build-android.sh   # single ABI during development

# 3. Android app
cd ..
./gradlew :mobile:assembleDebug

# 4. Blind relay, test deployment
cd server
docker compose up -d
pytest tests/
```

Release builds are signed only when `mobile/keystore.properties` is present; a checkout
without it configures cleanly and leaves the release variant unsigned.

## Verifying the claims

The project's doctrine is that **trust is verified, not declared**. A cryptographic system
can fail at the design level, the implementation level, or the compiler level, so each
level answers to a tool whose verdict does not depend on anyone's judgment. Every proof
ships with a reproducible runner and a negative control, because a proof that cannot fail
proves nothing.

| Layer | Tool | Result |
|---|---|---|
| Protocol vs active network attacker (Dolev-Yao) | Tamarin | **10 lemmas** verified: eight security lemmas (secrecy of the ephemeral slot keys and of the long-term key, slot-holder authentication, nonce anti-replay, rotation unforgeability, rotation lineage, root anchoring, forward security of authentication) and two executability checks. The model covers the authentication ratchet; the report closure has no formal model yet and rests on tests and cross-language vectors. Signature domain separation is not one of the lemmas: it is shown to be **load-bearing** by negative control NC2, which collapses the two ephemeral tags and re-falsifies `rotation_authentic`. Both negative controls must falsify. |
| Ratchet state machine | TLA+/TLC | State space explored exhaustively, 0 error: monotonicity, anti-replay, anti-rollback, single-use keys. |
| Untrusted-input parsing, on the real Rust code | Kani (bounded model checking) | **8 proof harnesses**, all verified in the last dated run (`docs/KANI_PROOFS.md`); the header parser is provably panic-free over the bounded input space, and provably refuses the reserved multi-recipient section rather than parsing it. The three newest cover the queue envelope written by the report rework. The runner asserts the harness count, so a proof cannot quietly stop existing. |
| Kotlin/Rust boundary | Differential fuzzing through the real UniFFI bindings | **759/759** vectors byte-identical. |
| Compiler output | LLVM IR zeroize audit | The secret wipe is never dead-store-eliminated at the shipped optimization profile, with an executable guard. |

```bash
crypto-rs/core/proofs/run-tlc.sh                      # TLA+/TLC (JVM: Windows, Linux, macOS)
crypto-rs/core/proofs/run-tamarin.sh                  # Tamarin (Linux or WSL)
crypto-rs/core/proofs/run-tamarin.sh negative         # the negative controls, which MUST falsify
crypto-rs/run-kani.sh                                 # Kani (Linux or WSL)
bash crypto-rs/core/audit/assert_zeroize_not_dse.sh   # zeroize guard (LLVM IR)
cargo mutants                                         # mutation testing (slow; scope with -f)
```

On top of the formal suite: **mutation testing** (100% of viable mutants caught on the
decrypt parser, 98% on the header parser, the lone survivor proven equivalent),
**cargo-fuzz** (4 targets, 0 crash; the committed run is a smoke test, and the
million-iteration figure in `AUDIT_SCOPE_RUST.md` §7 is a target, not a result),
**property-based
testing**, **cross-implementation known-answer vectors** (any drift of a frozen constant
fails the build), and **adversarial AI audits across distinct models**, arbitrated by
re-verification against the code rather than on an agent's word.

Each proof guarantees one precise thing and abstracts the rest. The boundaries of every
guarantee are documented as carefully as the guarantees themselves, with the exact replay
command for each claim and a register of accepted risks, in
[docs/GUIDE_AUDITEUR.md](docs/GUIDE_AUDITEUR.md).

## Threat model in brief

Built for activists, journalists, and lawyers operating in hostile contexts.

| If the adversary | Then |
|---|---|
| Seizes the phone after recording | Nothing readable on the device; the footage is on the relay, encrypted. Footage recovered on the phone in Archive mode stays encrypted inside the app, is decrypted only a few chunks at a time while you watch, and is erased when you close the rescue and by the emergency wipe; only an export you make yourself, after a warning, leaves that protection |
| Snatches the phone mid-recording | Everything up to a few seconds before the snatch is already encrypted and off the device |
| Coerces the PIN, or extracts the phone's state | Not one byte of past content: no decryption key exists on the device. A **closed** report cannot be extended or rewritten: its key is erased from the phone when the recording stops, the state the phone keeps cannot re-derive it, and the relay refuses any new object once it holds the report's signed closure (one caveat: an older copy of that sealed state left on flash, against which the PIN is only a delay). What the adversary does get: the ability to sign the report being recorded at that moment, every report opened after it, and entries in the report directory, with no time limit, and no channel that alerts you. A report forged at a future index cannot be told apart cryptographically; the rescue shows each report's date range so you can spot what postdates a loss. The way out is re-enrolling with a new phrase |
| Seizes or controls the relay | No content: opaque blobs only, and the private half of the content key exists on no machine. No IP is logged. The one artifact that is **not** opaque is the authentication registry, kept in the clear on disk: per pseudonymous identity, the current batch number, its 50 public keys, which slots have been consumed, and a report-creation counter for that batch. No civil identity, no link from a report to an identity, but it is an activity signal per pseudonym, and we would rather name it than let an auditor find it |
| Controls the relay **while you are uploading** | Still no content, and nothing at rest ties an identity to a report. But a live operator sees your IP on each connection, and the pseudonymous key once, when a report is first created. The blind relay is blind at rest, not invisible in the moment |
| Orders you to delete what you sent | There is no delete. Blobs are write-once until the retention window ends, and the app exposes no way to remove them, so there is nothing you can be made to undo |
| Adds, swaps, or drops objects in a report on the relay | Each object is signed when it is recorded, and the rescue checks every signature against the key it re-derives from your phrase, never against one the relay supplies. For a closed report, the signed closure lists the exact objects, so anything foreign, missing, or extra is shown and excluded. A report that was never closed has its objects checked one by one, but its end is not certified. Withholding a whole report remains undetectable with a single relay |
| Holds a valid CA-signed certificate | Rejected: the TLS verifier trusts three SPKI fingerprints we control, not the system CA store. Three, not one, so a certificate rotation is an overlap instead of a flag-day brick; all three are ours, so it does not weaken the check |
| Obtains the 12-word phrase | Everything. This is stated without euphemism; the phrase is the whole trust model |

Full model, including what is explicitly **not** claimed:
[docs/ARCHITECTURE_TECHNIQUE_COMPLETE.md](docs/ARCHITECTURE_TECHNIQUE_COMPLETE.md).

## Status

**Field-tested. Audit-ready. NOT production-ready.**

- Validated in multi-day real-world use on two reference devices, one MediaTek-based and
  one Snapdragon 8 Gen 3-based. The test relay is operational.
- **No external security audit yet.** The proof suite and the auditor dossier make the
  project audit-ready; an independent human audit is planned, not done.
- **One test relay**, TLS-pinned to a single key and an IP address. Rotating the server key
  today would require an APK rebuild; persistent-key Let's Encrypt plus DNS migration is on
  the roadmap.
- The on-device forensic validation campaign has been run (heap, native-crash tombstones,
  filesystem state after each scenario), so "no secret leaks outside Rust" is backed
  on-device and not only statically.
- **Android only.** UI in French and English; the device test matrix needs broadening.

If lives depend on your footage today, do not make Frappuccino your only line of defense.
The known limits are documented with the same care as the features.

### Pre-release test builds send diagnostic logs

Builds whose version ends in `-testN` (currently 2.12.0-test2) go to a closed group of
testers. Unlike any other version, they send diagnostic logs to the **test** relay, so that a
problem tied to one phone model, such as a camera that does not start, can be diagnosed
without the phone at hand. This is temporary. The code that collects and sends these logs is
compiled only into a `-testN` version, and CI checks that a build with any other version
number contains none of it.

What a test build sends, through the app's pinned HTTPS client and without any account,
token or identity key:

- the app's own log lines and crash traces, and the app's share of the system log (camera
  and video encoder messages), each with its time;
- a description of the phone: manufacturer and model, the full build fingerprint, Android
  version and security patch level (and One UI on Samsung), chipset, what each camera
  advertises (frame-rate ranges, zoom range, lenses), the video encoders available, whether
  camera and microphone access and the battery exemption are granted, the thermal status,
  and the app's version.

What it is not meant to send: the recovery phrase, the PIN, keys, tokens, report or session
identifiers, the identity's fingerprint, its batch number or slot counts, or any video. The
app does not log these. As a second line of defence, every line is filtered on the phone
before it is stored or sent: long hexadecimal identifiers, grouped hex, UUIDs, tokens, IP and
e-mail addresses are replaced, a line holding a run of recovery-phrase words is dropped, and
in file paths and URLs only the identifiers are replaced, so directories and chunk numbers
remain. This filter works on patterns. It is not a proof: a short secret such as a PIN would
pass it, which is why the first line of defence is not logging them. Uploads are grouped
under a random identifier drawn on the phone and reset by the emergency wipe, which also
erases the logs waiting to be sent. Nothing is sent from the Android Emulator.

On the relay, the logs are kept apart from the testimony blobs and out of the relay's backups
(a snapshot of the whole disk taken by the host would still hold them), with no client IP,
and deleted after 30 days. What a test build still gives a relay operator:

- **The logs can be tied to the phone's pseudonymous identity.** They reach the same relay
  as the phone's authentication and testimony uploads, from the same address, and they hold
  timed events such as authentications and batch rotations. A live operator can therefore
  match a phone's logs with its identity and its uploads, even though nothing in the logs
  names the identity.
- **The random identifier does not fully separate a phone's life before and after an
  emergency wipe.** The description of the phone is the same, and the wipe clears the app's
  share of the system log only as far as the phone allows, so the first upload after a wipe
  can repeat lines already sent under the previous identifier.

For a test build, a relay operator therefore holds one more thing than the threat model
above describes: a timeline of app events per test phone, attributable to its pseudonymous
identity.

## Documentation map

The deep-dive documents are in French; the Rust workspace documentation and the audit scope
are in English.

| Document | Contents |
|---|---|
| [docs/POSITIONNEMENT.md](docs/POSITIONNEMENT.md) (FR) | The problem, our answer, honest comparison vs Tella / Signal / ProofMode / eyeWitness |
| [docs/ARCHITECTURE_TECHNIQUE_COMPLETE.md](docs/ARCHITECTURE_TECHNIQUE_COMPLETE.md) (FR) | Complete architecture: V2 cryptography, Rust core, HEVC pipeline, blind relay, assumed limits |
| [docs/GUIDE_AUDITEUR.md](docs/GUIDE_AUDITEUR.md) (FR) | Auditor's guide: proof suite, replay commands, risk register, where to attack |
| [AUDIT_SCOPE_RUST.md](AUDIT_SCOPE_RUST.md) (EN) | External audit scope and frozen cryptographic invariants |
| [docs/FORK_VS_TELLA.md](docs/FORK_VS_TELLA.md) (FR) | Technical deltas vs upstream Tella |
| [ROADMAP.md](ROADMAP.md) (FR) | Single source of truth for project state |
| [crypto-rs/README.md](crypto-rs/README.md) (EN) | Rust workspace: layout, build, invariants, mutation testing |
| [README_TELLA.md](README_TELLA.md) (EN) | Preserved upstream Tella README |

Where any document and the code diverge, **the code is authoritative**, and we want to hear
about the gap.

## Fork lineage and license

Frappuccino is a fork of **[Tella](https://github.com/Horizontal-org/Tella-Android)** by
**Horizontal**: a field-proven documentation app for activists, translated into 17
languages, available on Android, iOS, and F-Droid. We started from Tella because it does
its job well. If your use case is structured evidence collection toward your own
organization's server (Tella Web, Uwazi), **Tella remains the right tool**, and its scope
exceeds ours.

What Frappuccino changes is the model. Tella is a vault at rest; Frappuccino is real-time
encrypted streaming to a blind relay, with the cryptography entirely rewritten and the video
pipeline rebuilt for real-time HEVC. Some Tella features were deliberately removed
(calculator camouflage, ODK forms): rather than hiding the app, we make an app that, found,
opened, and unlocked, **has nothing to show**. The two postures defend against different
searches.

**License:** this tree carries the upstream license, **Apache License 2.0** (Copyright 2018
Horizontal), retained in [LICENSE](LICENSE) with the third-party notices in
[NOTICE.txt](NOTICE.txt). The public release is planned under **AGPLv3**; until that
relicensing lands, the inherited Apache 2.0 terms are what applies.

## Co-written with an AI, built to be verified

Frappuccino is developed by a solo developer with an AI as the primary pair programmer,
including for the cryptographic code and the internal audits. This is stated up front
because it is the condition of trust in everything else.

The risk is real and named: a language model can produce plausible wrong code and overrate
its own review. The countermeasure structures the entire project. **No security claim rests
on an AI's judgment.** Every important property is anchored to a non-AI, deterministic,
replayable oracle (model checkers, compiler-IR analysis, mutation testing, differential
fuzzing), and the internal audits pit distinct models against each other, with conclusions
that only count once re-proven against the code.

## Reporting security issues

Until a formal security policy lands, please report suspected vulnerabilities privately
through GitHub private vulnerability reporting rather than in a public issue. Adversarial
review is the most valuable contribution this project can receive right now.
