# Frappuccino — Forensic Validation Plan (ROADMAP audit item 8.1.1)

**"No secret / plaintext leaks outside Rust" — evidence pack for external review**
Worktree `xenodochial-morse` · HEAD `d84ee2b` · 2026-05-31
Status: **AUDIT-CANDIDATE, NOT PRODUCTION-READY.** This is a falsifiable test plan plus an honest leak-surface inventory, not a clean bill of health. Eight surfaces were code-reviewed against source; several mitigations were then **weaker than the design intent claims** and flagged PROVEN-GAP below — **most have since been fixed or validated on-device** (see the banner below + the REPORT).

> **⚠️ MAJ 2026-06-14 — à lire avec [`FORENSIC_VALIDATION_REPORT.md`](FORENSIC_VALIDATION_REPORT.md).** Ce plan (31-05) a depuis été **exécuté on-device**. Plusieurs items `PROVEN-GAP` sont **corrigés ou validés** — notamment surface 4 (tombstones, validé B5), surface 6 (panicWipe câblé `19672ed`), surface 9 (codec wipe + EGL `glFinish`/black-clear **déjà faits**), et le finding JWT-en-heap (worst-case fermé par le write-once serveur). Le rapport donne le **verdict par surface** + les **rectificatifs** des claims devenus périmés. **En cas de divergence, le rapport et le code priment sur ce plan.**

---

## 1. Scope + threat model

The adversary is a **device-seizure / Cellebrite-class forensic operator** in a militant/activist context: they obtain the physical phone (possibly unlocked, possibly in a brief post-unlock window, possibly cold), can run `adb` with a debuggable build or root, can pull `/data`, can force ANR/crash to harvest tombstones, can image flash, and have lab tools for NAND-level recovery and JVM/native heap analysis. The claim under test is narrow and specific: **all V2-sensitive cryptographic material (BIP-39 mnemonic, X25519/Ed25519 private keys, ratchet chain/derived keys, session keys) and all decrypted media plaintext live only transiently, are confined to Rust-owned `Zeroizing`/`mlock`'d memory wherever feasible, and leave no recoverable copy at rest on disk or in persisted databases (WorkManager DB, SharedPreferences).** Out of scope: the server relay, the TEE/KeyStore master-key extraction primitive itself, the OS-level FBE key, and **intentional** plaintext exports the user explicitly requests (recovered MP4s in public Downloads — see §4). This plan tests the claim by direct code-reading (done, file:line below) and prescribes runnable on-device procedures with explicit *leak signatures* that would falsify each mitigation.

---

## 2. Leak-surface inventory

`adjustedRisk` is taken from the per-surface adversarial verdict where present, else the surface's stated residual. **PROVEN-GAP** = a verdict refutation re-confirmed against source in this pass; **ASSERTED** = mitigation plausible but not yet validated on-device by this exercise; **PROVEN-OK** = code confirms the control as described.

| # | Surface | Secrets at risk | Current mitigation (file:line) | Residual (adjusted) | Status |
|---|---------|-----------------|-------------------------------|---------------------|--------|
| 1 | **JVM heap** — mnemonic ByteArray, JWT Strings, RAM holders, `ratchetDerivedKey` | mnemonic, JWT bearer, x25519_sk handle, ratchet-derived key, passphrase | `SecureWipe.kt:60-86` (2-pass wipe vs JIT DSE); `MnemonicHolder` ByteArray; `ArchiveSession.kt:318-321` wipes cachedMnemonic; `ratchetDerivedKey`/`serialized`/`UnsealedBlob.derivedKey` **routés via `SecureWipe.wipe()`** (bare `fill(0)` corrigé) ; le JWT d'upload résiduel = le **finding** (worst-case fermé par le write-once serveur, §5/REPORT) | LOW (JWT accepté) | **RÉSOLU / calibré §2.4** |
| 2 | **Rust/native heap + UniFFI boundary** — secrets crossing FFI as `Vec<u8>` | x25519_sk, ed25519_sk, chain_0, Argon2id derived_key, ephemeral ratchet keys, session keys, STRM plaintext | Rust `Zeroizing`+`mlock` sound (`secret.rs`); `strm_decrypt_to_file` keeps plaintext Rust-only (`ffi/src/lib.rs:808-848`); le legacy `strm_decrypt`→JVM a **0 appelant** (`strm_decrypt_to_file` = seul chemin vif, plaintext Rust-only) ; `UnsealedBlob.derivedKey` wipé | LOW | **RÉSOLU** |
| 3 | **Timber/logcat & exception messages** | mnemonic, JWT, keys, decrypted metadata | `MyApplication.java:120-121` DebugTree planted **only** under `BuildConfig.DEBUG`; release plants only `MetricsFileLogger` (`:131`) which tag-filters to `StreamMetrics`; no mnemonic/JWT value found in any Timber call | **LOW** | **PROVEN-OK** |
| 4 | **Native crashes (SIGSEGV/ANR), tombstones, post-kill memory** | plaintext MP4, mnemonic, session keys, JWT, partial blobs | Rust zeroize-on-drop; decrypt-to-file; `secure_delete.rs`; `codecLock` (AacEncoder UAF, B.19); FGS prevents bg-kill; `panic="unwind"` drope les `Zeroizing` avant tombstone ; **B5 (3 crashes : idle / archive-actif / mnémo-affiché) = 0 plaintext / 0 JWT / 0 mnémo** ; tombstone ≠ heap dump | LOW (résidu #7 borné) | **VALIDÉ on-device (B5)** |
| 5 | **Filesystem temp & scratch** — cacheDir chunks, archive_recovery, debug_raw | plaintext MP4 chunks, session metadata JSON, partial .strm, ephemeral derived keys | `strmEncryptFile`/`strm_decrypt_to_file` keep plaintext off-heap; `secure_delete.rs` (1-pass rand+fsync+truncate+unlink); `ArchiveDownloader` finally-sweep; debug_raw double-gated; `debug_raw` gaté `BuildConfig.DEBUG` (§8.2.8) ; scratch **vide post-stop** (B9 : 0 `.mp4` / 0 `.strm`) ; metadata JSON String = résidu accepté (#6) | LOW | **OK / résidu accepté** |
| 6 | **panicWipe coverage + post-reboot/low-storage** | plaintext MP4 (debug_raw), STRM ciphertext+nonce | `panicWipe:240-256` → `lock()` + `wipeAll` + `CaptureScratchCleaner.purgeAll`; **+ `ChunkUploadQueue.clear()` câblé** (`19672ed`, les `.strm` en attente sont purgés au wipe) ; handler low-storage (analogue 507) ajouté | LOW | **CORRIGÉ (`19672ed`)** |
| 7 | **WorkManager DB + EncryptedSharedPreferences** | JWT, ratchet blob, mnemonic, pubkeys, invite codes, server URLs | `UploadAuthHolder` RAM-only `AtomicReference` (Phase 3.13); `ChunkUploadWorker.buildInputData` stores only filePath/serverUrl/reportId; `StreamPreferences` = EncryptedSharedPreferences (AES-256-GCM, KeyStore master key); ratchet blob PIN-wrapped (Argon2id+XChaCha20) before storage; mnemonic never persisted | LOW | **VALIDÉ on-device (Phase A)** |
| 8 | **MediaStore Downloads + system thumbnails** | plaintext MP4, session manifests JSON, .m3u, **thumbnail cache**, MediaStore metadata | `secure_delete` on cacheDir source (`ArchiveDownloader.kt:275,294`); IS_PENDING 1→0 (`:261,271`); `resolver.delete(uri)` purge l'entrée MediaStore **et sa miniature** ; l'export plaintext est une action **délibérée** (mode archive) | LOW (caches galerie tierce hors contrôle) | **ACCEPTÉ (LOW)** |
| 9 | **MediaCodec output buffers / gralloc / GPU VRAM** | decoded plaintext video frames, session key (heap), ratchet state | `SecureWipe` (heap keys); `CaptureScratchCleaner` (disk); buffer codec **zéro-ié** `SecureWipe.wipe(outBuf)` avant release (8.1.6-#3) ; EGL `glClear` noir + **`glFinish()`** avant `eglDestroy*` ; OES `glDeleteTextures` ; B9 = libération encodeur au stop + disque propre | résidu **firmware** (zéro gralloc/VRAM = pilote, hors app) accepté | **APP-SIDE OK / résidu firmware (B9)** |

**Bilan (MAJ 14-06 — campagne exécutée on-device, voir [`FORENSIC_VALIDATION_REPORT.md`](FORENSIC_VALIDATION_REPORT.md)) :** des 6 surfaces `PROVEN-GAP HIGH` du diagnostic initial (31-05), **#1/#2/#4/#6 résolues ou validées**, **#5 OK + résidu accepté**, **#9 app-side corrigé / résidu firmware accepté** ; **#8 requalifiée LOW** (plaintext intentionnel) ; **#7 validée on-device**. La couche glu Kotlin↔UniFFI, point faible désigné par ce plan, est **assainie** ; le cœur crypto Rust reste sain. Les seuls résidus = **RAM in-window** (calibré, cf. `ARCHITECTURE §2.4`) + **gralloc/VRAM firmware**.

---

## 3. Runnable validation plan

Package `org.hzontal.tellaFOSS`. Use a **release** APK for any claim about release behavior; use a debuggable build only where `run-as` is required and noted. `<pkg>` = `org.hzontal.tellaFOSS`, `<pid>` = `adb shell pidof <pkg>`.

> **MAJ 14-06 :** les verdicts « Confirmed gap » des sous-sections ci-dessous datent du diagnostic du 31-05. Le **statut courant** est la table §2 + [`FORENSIC_VALIDATION_REPORT.md`](FORENSIC_VALIDATION_REPORT.md) (plusieurs sont corrigés/validés). Les procédures restent valides comme **mode de rejeu**.

### Surface 1 — JVM heap (mnemonic / JWT / ratchetDerivedKey)
**Steps**
1. Enroll with a **known test mnemonic** and PIN. Unlock, start recording → `UploadAuthHolder.set(jwt)` and `ratchetDerivedKey` populated.
2. `adb shell am dumpheap <pid> /data/local/tmp/h1.hprof` → `adb pull` → open in MAT.
3. Search heap for: the 12 known mnemonic words; the JWT (`eyJ…`); the 32-byte derived-key test vector.
4. Call `lock()` (lock screen / auto-lock), then `System.gc()` via profiler, re-dump (`h2.hprof`).
5. Frida hook on `org.stream.crypto.SecureWipe.wipe([B)` and on `kotlin.collections.ArraysKt___ArraysKt.fill` to log the post-state of the buffers at `StreamUploadManager` lines 227 and 681.

**Expected-clean:** post-`lock()`+GC, no mnemonic, no JWT, no derived-key bytes; every SecureWipe'd ByteArray reads all-`0x00`.
**Leak signature (falsifies):**
- Derived-key 32-byte vector still present at the `ratchetDerivedKey` backing array address after `lock()` (line 227 used bare `fill(0)` — **JIT may have elided it; this is the confirmed gap**). Same for `serialized` at line 681.
- `UnsealedBlob` object reachable in `h1.hprof` with a non-zero `derivedKey` field after `enrollFromMnemonic`/`initializeWithPin` returned.
- Full JWT recoverable in `h2.hprof` (String char[] — acknowledged unwipeable, exposure = token TTL).

### Surface 2 — Rust/native heap + UniFFI boundary
**Steps**
1. `cat /proc/<pid>/maps` while unlocked → grep for locked pages; cross-check `VmLck`/`VmPin` in `/proc/<pid>/status` is non-zero (proves `mlock` on `LockedSecret`).
2. Decrypt one blob via the **legacy** `strm_decrypt` path and one via `strm_decrypt_to_file`; `am dumpheap` immediately after each.
3. Search both dumps for the known plaintext (MP4 `ftyp`/`mdat`) and for the derived-key vector.

**Expected-clean:** `strm_decrypt_to_file` dump has **no** plaintext ByteArray (only metadata); `mlock` pages present; EnrollmentKit ed25519_sk never appears.
**Leak signature (falsifies):**
- Plaintext media ByteArray in the heap after `strm_decrypt` (**confirmed**: `ffi/src/lib.rs:764` `plaintext_z.to_vec()` produces an unprotected JVM-bound copy — any caller still on this path leaks; migrate all callers to `strm_decrypt_to_file`).
- `VmLck`=0 (mlock not effective on this device/kernel).

### Surface 3 — Timber / logcat (release)
**Steps**
1. `./gradlew :mobile:assembleRelease`; install; `adb logcat -c && adb logcat > log.txt &`.
2. Full cycle: onboard (known mnemonic) → record to a STREAM server → stop → wait for chunk workers → trigger a 401 (offline mid-upload).
3. `grep -Ei 'eyJ[A-Za-z0-9_-]+\.eyJ|Bearer [A-Za-z0-9_-]{30,}|<word1>.*<word2>.*<word3>' log.txt`.
4. Confirm DebugTree absent: dex of release APK should not retain a planted DebugTree (R8 folds `BuildConfig.DEBUG=false`).

**Expected-clean:** zero matches; only `StreamMetrics`-tagged lines; auth exceptions show status codes (401/404), never token/nonce.
**Leak signature (falsifies):** any BIP-39 phrase, any JWT, or a `Timber.e(exception,…)` whose message carries nonce/signature/challenge bytes; or `metrics.log` pullable from a release build (means `debuggable=true` shipped).

### Surface 4 — Native crashes / ANR / tombstones
**Steps**
1. Start a decrypt-heavy archive download. Mid-decrypt, force a native crash (`adb shell kill -SEGV <pid>`) and separately force an ANR (block main thread under load).
2. Pull `/data/tombstones/*` and `/data/anr/traces.txt` (root or debuggable).
3. Scan tombstone memory excerpts + ANR thread dumps for STRM magic `0x53545200`, MP4 `ftyp`, the JWT, BIP-39 words.
4. Post-kill: `cat /proc/<pid>/mem` via `/proc/<pid>/maps` offsets (root) before the process is reaped.

**Expected-clean:** no plaintext / mnemonic / key bytes in tombstone or ANR dump; plaintext was Rust-`Zeroizing` and dropped.
**Leak signature (falsifies):** STRM/MP4/HEVC NAL (`0x00000001`) fragments or the full JWT in a tombstone or world-readable `data/anr/` dump. **Confirmed structural gap:** no `SIGABRT`/panic signal handler scrubs plaintext before the tombstone snapshot; JWT String char[] is captured verbatim.

### Surface 5 — Filesystem temp & scratch
**Steps**
1. Baseline FS walk: `adb shell run-as <pkg> find files cache -type f` (debuggable) or root.
2. Record 10 s (default `isDebugBitrateEnabled=false`), stop. Walk `cache/stream_chunks/`.
3. Toggle debug bitrate ON (debuggable build only), record, stop. Walk `files/debug_raw/`. Rebuild release, repeat — expect skip.
4. Start an archive download, `am kill` mid-way. Walk `cache/archive_recovery/`.
5. Frida-hook `StreamChunkEncryptor.encryptMetadata` and dump the incoming `metadataJson` String; `am dumpheap` during its lifetime.

**Expected-clean:** post-stop `cache/stream_chunks/` holds only `.strm` (or empty); `debug_raw` empty/absent in release; `archive_recovery` empty after kill (finally-sweep ran).
**Leak signature (falsifies):** any plaintext `.mp4` with `ftyp` in cache post-stop; `debug_raw` MP4 created in a release build (gate bypass); **session-metadata JSON String (sessionId/startedAt/timestamps) recoverable on heap after `encryptMetadata` returned — confirmed: the ByteArray copy is wiped but the source immutable String is not.**

### Surface 6 — panicWipe + post-reboot
**Steps**
1. Enroll, record 5 min across 2 sessions, **stop mid-drain** to leave `.strm` orphans in `files/stream_chunk_queue/`. Snapshot FS + hex-dump one `.strm` header as a signature.
2. Trigger **Panic Wipe**. Watch logcat: `PANIC WIPE — all local crypto state erased`, `debugRawPurged`, `zeroByteChunksPurged`.
3. Immediate (<10 s) FS re-walk; diff against snapshot. Inspect `shared_prefs/stream_identity_v2.xml` for `KEY_*` removal.
4. `adb reboot`; before opening the app, FS-walk `files/stream_chunk_queue/`.

**Expected-clean (per design):** identity + ratchet blob + session mappings gone from EncryptedSharedPreferences; `debug_raw` and 0-byte chunks gone.
**Leak signature (falsifies the "panicWipe clears local state" reading):** **`files/stream_chunk_queue/*.strm` still present after panicWipe — confirmed: `panicWipe` calls `CaptureScratchCleaner.purgeAll` (debug_raw + 0-byte only) and never `ChunkUploadQueue.clear()`.** These ciphertext+nonce blobs persist until the *next* recording session's 48 h TTL sweep, or indefinitely if the user never records again. A cold seizure immediately post-reboot also exposes blobs up to 48 h old (TTL sweep runs on `StreamRecordingService.onCreate`, requires app launch).

### Surface 7 — WorkManager DB + EncryptedSharedPreferences
**Steps**
1. Record → chunk workers enqueue. `adb shell run-as <pkg> sqlite3 databases/androidx.work.workdb "SELECT input_merger_class_name, output FROM WorkSpec;"` and inspect `input` blobs.
2. `cat shared_prefs/stream_identity_v2.xml`; `cat shared_prefs/pin_attempt_tracker.xml`.
3. Base64-decode `ratchet_blob_b64`; entropy-check (expect ≥7.5 bits/byte; no ASCII protocol markers).
4. `am dumpheap` during recording — JWT in heap (`UploadAuthHolder`) is expected; same JWT in `workdb` is the regression.

**Expected-clean:** WorkSpec input holds only `filePath`/`serverUrl`/`reportId`; identity XML values opaque/encrypted; ratchet blob high-entropy; `pin_attempt_tracker.xml` plaintext integers only.
**Leak signature (falsifies):** `Bearer `/`eyJ…`/64-hex key in WorkSpec input (R-01 regression); recognizable ed25519/x25519 hex or readable ratchet markers in the XML; JWT surviving in `workdb` post-reboot.

### Surface 8 — MediaStore Downloads + thumbnails
**Steps**
1. Perform an archive rescue (1 report, several blobs).
2. `adb shell run-as <pkg> find cache/archive_recovery -type f` → expect 0.
3. `adb shell content query --uri content://media/external/downloads --where "relative_path LIKE '%Frappuccino%'"` → rows IS_PENDING=0.
4. **Thumbnail hunt:** `adb shell find /data/media/0/Android/data/com.android.providers.media* -type f -newer <marker>` and query `external.db` `video`/`thumbnails` tables for `_data LIKE '%Frappuccino%'`; carve any JPEG/WebP for the rescued footage.
5. `photorec`/`testdisk` on the cache partition for recoverable `.mp4`/`.strm`.

**Expected-clean:** cache swept; Downloads entries IS_PENDING=0 (these are **intentional** plaintext — see §4).
**Leak signature (falsifies the "only-intentional-plaintext" reading):** **system thumbnail JPEG/WebP previewing rescued video in the media-provider cache — confirmed: no IS_HIDDEN / no scanner exclusion / no thumbnail purge; thumbnails persist outside app control until device reset.** Also: recoverable playable MP4 from cacheDir (secure_delete skipped/failed via plain-`delete()` fallback).

### Surface 9 — MediaCodec / gralloc / GPU VRAM
**Steps**
1. Record a calibration pattern (known pixels). Mid-record, dump GPU/ION (`dumpsys gralloc` / `/sys/kernel/debug/ion` / vendor tool; root) and `dumpsys SurfaceFlinger`.
2. Frida-log `HevcMediaCodecEncoder` output-buffer addresses before `releaseOutputBuffer`; after `stop()`, read `/proc/<pid>/mem` at those offsets.
3. After `stop()`+2 s, re-scan VRAM/gralloc for the final frame.
4. FS-walk `cache/stream_chunks` + `files/debug_raw` post-stop.

**Expected-clean (best achievable today):** MediaCodec buffers freed; OES texture deleted (`glDeleteTextures`, `GlVideoPipeline.kt:233`); EGL surfaces/context destroyed; no plaintext chunk on disk.
**Leak signature (falsifies "no decoded-frame residue"):** YUV420/RGBA8 matching the final frame, or HEVC NAL fragments, in VRAM/gralloc/codec buffer after `stop()`. **Confirmed structural gaps:** the codec `ByteBuffer` is never zeroed (SecureWipe has no ByteBuffer overload); `eglDestroySurface`/`eglDestroyContext` (lines 247-265) run with **no preceding `glFinish()`/black `glClear()` on the sensitive surface**; `purgeZeroByteChunks` uses plain `delete()` (filename + inode metadata recoverable). Residual is also firmware-dependent (MediaTek Seeker / OnePlus 13 not observed to zero gralloc on free).

---

## 4. Known-limits / non-claims (honest)

The project does **not** claim these are protected; an auditor should treat them as designed-in plaintext, not findings:

1. **Recovered MP4s in public Downloads (`Downloads/Frappuccino/<reportId>/`).** Phase 4.4.8 archive rescue **intentionally** writes decrypted, playable MP4 + JSON manifest + `.m3u` to user-owned public storage. This is the feature. Plaintext-at-rest here is expected; the user chose to export. *Caveat that IS a finding:* the **system thumbnail cache** derived from these files (surface 8) is an *unintended* secondary copy outside app control.
2. **Active-session RAM secrets.** While unlocked and recording/downloading, the mnemonic (if `keepForReauth=true`, up to the user-determined download duration), `ratchetDerivedKey`, and JWT live in RAM by necessity. A heap dump of a **live, unlocked** device recovers them. Mitigations (SecureWipe, mlock, FLAG_SECURE) shrink but cannot eliminate this window. `ArchiveSession.kt:71-78` states this trade-off explicitly.
3. **JWT String char[].** Kotlin/JVM Strings are immutable; `UploadAuthHolder` and `ArchiveSession.bearerToken` can null the reference but cannot zero the backing char[] without reflection. Exposure = token TTL (5 min archive / up to session length recording). Acknowledged at `ArchiveSession.kt:322-325`. **Non-claim:** JWTs are not wiped, only nulled.
4. **Encrypted `.strm` blobs surviving panicWipe.** By design, `panicWipe` does **not** delete `files/stream_chunk_queue/*.strm` (they are ciphertext, decryptable only by the now-erased identity). This is defensible *for the confidentiality claim* but means **panicWipe is not a full disk-clean** — see top residual risk #4. Stated honestly: ciphertext + plaintext nonces remain on a seized device.
5. **NAND wear-leveling vs single-pass secure_delete.** `secure_delete.rs` does 1-pass random + fsync + truncate + unlink. On wear-leveled flash this does not guarantee physical-block destruction. The real at-rest defense is Android FBE; secure_delete is defense-in-depth for live-RAM/logical-recovery, not a guarantee against NAND-level lab forensics.
6. **PIN-attempt tracker & vault prefs** store non-sensitive plaintext (counter, timestamp, `is_migrated_vault_db`) — intentional, not secrets.

---

## 5. Top residual risks for the external audit (prioritized)

1. **[RÉSOLU 14-06] Kotlin-side key wiping — bare `fill(0)` corrigé.** `StreamUploadManager` (`ratchetDerivedKey`, `serialized` ratchet state) et le wrapper `UnsealedBlob.derivedKey` sont **désormais routés via `SecureWipe.wipe()`** (le primitif JIT-résistant ; `fill(0)` nu retiré). *(Diagnostic initial 31-05 : `fill(0)` nu = élision JIT possible, clés en heap.)*
2. **[RÉSOLU 14-06] `strm_decrypt` legacy → heap JVM : 0 appelant.** L'énumération des callers est faite : **aucun** ne reste sur le chemin de decrypt vif ; `strm_decrypt_to_file` (fix Red MED-4) est le seul chemin, plaintext Rust-only. *(Diagnostic initial : `plaintext_z.to_vec()` copiait le clair via FFI vers une ByteArray JVM.)*
3. **[RÉSOLU app-side / résidu firmware — B9 14-06] MediaCodec `ByteBuffer` + frames GPU.** Les gaps app sont **fermés** : la surcharge `SecureWipe.wipe(ByteBuffer)` existe, le buffer de sortie codec est **zéro-ié** avant `releaseOutputBuffer` (8.1.6-#3), et `GlVideoPipeline` fait `glClear` noir + **`glFinish()`** avant `eglDestroy*`. Reste le seul résidu **firmware** : zéro-isation gralloc/VRAM par le pilote (hors contrôle app, non-mesurable sans root, probablement inconclusif sur Mali) — **accepté** ; FBE = défense at-rest. *(Diagnostic initial : buffer codec non zéro-ié, pas de glFinish.)*
4. **[HIGH — addressed 2026-06-03] panicWipe chunk-queue + device low-storage.** Two sub-parts. **(a, the forensic HIGH)** panicWipe left `files/stream_chunk_queue/*.strm` (ciphertext + plaintext nonces) on disk — only `debug_raw`+0-byte chunks were purged. **Fixed:** `ChunkUploadQueue.clear()` is now wired into `panicWipe` (commit `19672ed`), so the seized-device wipe secure-deletes the pending blobs too. **(b, reclassified availability — not a leak)** no device low-storage handling. **Fixed:** `StreamRecordingService.refreshNotification` watches `filesDir.usableSpace` (the /data partition, covering both the in-progress MP4 in cacheDir and the `.strm` queue in filesDir), surfaces a heads-up below 400 MB, and stops the recording **cleanly** below 100 MB (finalizing + encrypting the current chunk) — the device-side analog of the HTTP 507 server-full path. (b) is availability/data-loss, **not** a forensic leak: `StreamChunkEncryptor.encryptChunk` already secure-deletes the plaintext MP4 in its `finally`, so a full disk loses a chunk but never leaves plaintext behind.
5. **[LOW — requalified 2026-06-03, was HIGH] System MediaStore thumbnails of rescued plaintext MP4s.** Two corrections to the original finding: (a) it is **not** true that `ArchiveDownloader` "never purges" — `clearReportFolder` deletes rescued entries via `resolver.delete(uri)` on Android 10+, which the media provider uses to drop the entry **and** its derived thumbnail; (b) the rescue/decrypt path is a **deliberate** user action — the user decrypts their own footage with the BIP-39 key at a self-chosen safe moment — so the plaintext (and any thumbnail) exists by choice, not as a capture-time leak. Preventing generation / hiding from galleries (`.nomedia`, app-private storage) is therefore low-value and would break the intended in-Photos playback. The one residual that survives this model is a thumbnail **outliving the user's own deletion** (delete-believed-erased → a later seizure recovers a preview) — a secure-delete-completeness concern, already covered on Q+ by the URI delete and now hardened on the pre-Q legacy path (`clearReportFolder` purges the MediaStore entry by path before the raw delete). **Accepted residual:** a third-party gallery's private cache, or a deletion performed via an external file manager, remain outside app control.
6. **[MEDIUM — assessed 2026-06-03, accepted] Immutable Strings carrying secrets/metadata.** JWT bearer (`UploadAuthHolder`, nulled on clear), session-metadata JSON (`StreamChunkEncryptor.encryptMetadata` / `StreamRecordingService.buildSessionMetadata`), transient `EditText`→String mnemonic window. **Decision: not reliably wipeable on Android — accept + minimize, do not refactor.** Java/Kotlin Strings are immutable, and reflective `char[]` zeroing does **not** work on Android P+: `java.lang.String.value` is a non-SDK field blocked by hidden-API enforcement (and modern ART may back it with `byte[]`, not `char[]`). The dead `String.zero()` helper that pretended to do this (never called, silent no-op on every target device) has been **removed** to avoid a false sense of security. Session metadata (sessionId + timestamps) is judged low-sensitivity and **not** worth a CharArray-pipeline refactor; the actual secrets already avoid String entirely — PIN via `PinPadView` + `SecureWipe`, mnemonic/ratchet/keys via Rust `Zeroizing` + `SecureWipe.wipe(ByteArray)`. Mitigation in place = prompt nulling of references (`UploadAuthHolder.clear`, `ArchiveSession`) so the String is GC-eligible at once. **Accepted residual:** a secret-bearing String may linger in heap until GC, bounded by token TTL (5 min archive / 24 h upload) and the one-shot enrolment window.
7. **[MEDIUM — addressed 2026-06-03] Plaintext in crash dumps.** Root cause found: the crypto crates shipped with `panic = "abort"` (release profile), which (a) defeated `uniffi_core::rust_call`'s `catch_unwind` (verified present at `uniffi_core-0.28.3/src/ffi/rustcalls.rs:177`) — a Rust panic in crypto code SIGABRTed the **whole host app** instead of returning a catchable `FfiException` — and (b) skipped every `Zeroizing`/`SecureWipe` destructor, leaving decrypted plaintext live in the abort tombstone. **Fixed → `panic = "unwind"`:** a panic now unwinds, running the `Zeroizing` drops (scrubbing plaintext) before `catch_unwind` converts it to an error at the FFI boundary — no plaintext reaches a tombstone, and the host app survives a crypto-side panic. **Signal handler deliberately NOT added:** an async-signal-safe SIGSEGV/SIGABRT scrubber can do almost nothing safely from signal context and would have to interpose on ART's own tombstone machinery; decrypt/encrypt also run on service/worker threads, not the main-thread ANR window. **Accepted residual:** a hard native SIGSEGV (memory-unsafe crash, not a Rust panic) mid-decrypt could still snapshot the transient `Zeroizing` buffer before it drops — a narrow window, and the Rust core warns-on-unsafe with none in our code, so such a crash should not originate here.
8. **[VALIDÉ on-device — Phase A] WorkManager DB / EncryptedSharedPreferences (R-01).** Confirmé **par dump on-device** (Phase A), pas seulement en revue de code : `workdb` = 0 JWT/clé ; `stream_identity_v2.xml` = Tink/AES-256-GCM opaque ; ratchet blob PIN-wrappé. La boucle code↔device est fermée.

**Bottom line (MAJ 14-06) :** le cœur crypto Rust (Zeroizing/mlock/secure_delete, AEAD, ratchet) est sain, et le récit at-rest tient **en revue de code ET on-device**. La marge exploitable que ce plan pointait (glu Kotlin↔UniFFI + surfaces media/graphics) est **fermée** : #1/#2/#3/#4 corrigés, #5/#8 requalifiés/validés. Les seuls résidus restants — **JWT in-window en heap** (combo-1 write-once ferme le worst-case) et **gralloc/VRAM firmware** — sont **calibrés hors de la garantie centrale** (cf. `ARCHITECTURE_TECHNIQUE_COMPLETE.md` §2.4 + [`FORENSIC_VALIDATION_REPORT.md`](FORENSIC_VALIDATION_REPORT.md)). Procédures de rejeu = §3.