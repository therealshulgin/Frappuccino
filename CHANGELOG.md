# Changelog

All notable changes to Frappuccino are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project tries to honour [Semantic Versioning](https://semver.org/)
once it has a stable public surface (currently pre-1.0).

Categories used: **Added**, **Changed**, **Removed**, **Fixed**, **Security**,
**Breaking** (anything that changes the on-disk or on-wire surface).

## [Unreleased]

### Security — Phase 3.39 (metrics.log en stockage interne, FRAG-R1-3)

- **`MetricsFileLogger` écrit désormais dans `filesDir`**, le stockage privé
  de l'application, et non plus sous `getExternalFilesDir`. Un `adb pull`
  lit le dossier externe sans root : le fichier de métriques y révélait
  l'activité d'enregistrement sur un téléphone saisi. La commande de
  récupération de l'entrée 3.34 ci-dessous ne fonctionne donc plus ; il
  faut passer par `adb exec-out run-as`.

### Added — Phase 3.34 (file logger, 2026-05-14)

- **`MetricsFileLogger`** — Timber.Tree custom qui mirror le tag
  `StreamMetrics` vers un fichier persistant
  `<externalFilesDir>/metrics.log`. Rotation à 4 MiB (rename → .1,
  cap ~8 MiB total). Thread-safe via synchronized lock. Best-effort
  sur IOException. Critique pour les tests terrain : le buffer
  logcat in-RAM rotate trop vite (~min sur système chatty). Plant
  dans `MyApplication.onCreate`. Pull via :
  ```
  adb pull /storage/emulated/0/Android/data/org.hzontal.tellaFOSS/files/metrics.log
  ```

### Changed — Phase 3.35 (drain post-stop, 2026-05-14)

- **`UploadAuthHolder.clear()` retiré de `StreamRecordingService.
  onDestroy`**. Le JWT survit maintenant un stop service → les
  chunks WorkManager pending peuvent finir leur upload. Avant ce
  fix (Phase 3.13 trop agressif), un stop précoce laissait les
  chunks pending bloqués en `retry reason=no_auth_token`. Repro
  in-vivo 2026-05-14 : 5 chunks bloqués sur stop 2 s après
  forced_downgrade.

  Le clear est désormais déclenché uniquement sur les actions
  user-explicit :
  - `StreamSettingsActivity.confirmLock` (bouton Lock)
  - `StreamSettingsActivity.confirmPanicWipe` (bouton Wipe)
  - Process death (AtomicReference statique, automatique)

  L'invariant audit R-01 (JWT jamais persisté disque) reste intact.

### Added — Phase 3.7→3.33 (Upload resilience sprint, 2026-05-11 → 2026-05-14)

Massive upload pipeline robustness sweep driven by two parallel Opus
4.7 sub-agent audits 2026-05-10 (12 cross-confirmed findings) +
in-vivo therealshulgin testing on degraded networks (5G hotspot, marginal
box). 27 commits.

- **`UploadHttpClient` singleton** (Phase 3.11) — HTTP/2 negotiation,
  `ConnectionPool(4, 5min)`, `callTimeout=120s`, `CertificatePinner`
  explicit (defense-in-depth alongside `network_security_config.xml`),
  `retryOnConnectionFailure=false` (WorkManager handles retry). Solves
  R-02 + S-01 from the audit (per-call OkHttpClient was costing a full
  TLS handshake + connection pool loss per chunk).
- **`UploadAuthHolder` RAM-only JWT** (Phase 3.13) — replaces passing
  the bearer token through `Data.Builder` (WorkManager persisted it in
  clear in `androidx.work.workdb` SQLite). Audit R-01 high-severity
  pre-external fix.
- **`UploadConcurrencyLimiter`** (Phase 3.10) — `Semaphore` global cap
  prevents 4 parallel PUTs from saturating slow uplinks.
- **Adaptive concurrency cap 1–6** (Phase 3.21) — rolling-median
  `uploadMs` adjusts the cap, climbs on fast links / shrinks on slow.
- **`OrphanSweepWorker`** (Phase 3.26) — PeriodicWorker (30 min) that
  picks up orphan blobs from previous recording sessions whose queue
  didn't drain. Uses persisted `{sessionId → reportId}` mapping
  (Phase 3.26-A). Yields to live recording, skips when ratchet locked
  or no network, max 3 retries per session. Default ON, user toggle
  in Settings.
- **`enqueueUniqueWork(filename, KEEP)`** (Phase 3.27) — dedupes
  ChunkUploadWorkers; eliminates the triangular `1+2+...+N` worker
  enqueue effect that produced 300 workers for 24 chunks pre-fix.
- **Force quality downgrade on backlog** (Phase 3.28 + 3.32) — at
  `FORCE_DOWNGRADE_BACKLOG=6` (30 s of capture lag), bypasses the
  SLOW-tick path (which can't fire when workers are stuck on
  concurrency-cap retry) and steps quality down immediately.
- **Bitrate caps** (Phase 3.30) — `setTargetVideoEncodingBitRate`
  set to FHD 4 Mbps / HD 2 Mbps / SD 1 Mbps. Phase 3.22 had values
  too aggressive (500 kbps SD tripped the Seeker codec floor →
  `ERROR_NO_VALID_DATA`). 3.30 values stay below the observed Seeker
  default (~10 Mbps for HD!) while remaining above the codec floor.
- **HUD `uploaded/encrypted`** (Phase 3.7) — counter derived from
  `chunksEncrypted - pendingCount` instead of a quadratically-growing
  `AtomicInteger`. Real-time updates piggybacked on the 1 Hz
  notification refresher.
- **`StreamMetrics` structured logging** (Phase 3.31 + 3.33) —
  filterable via `adb logcat -s StreamMetrics:I`:
  - `chunk seq=N quality=… sizeBytes=… uploadMs=… ratio=… cap=…
    backlog=… networkType=… bitrateBps=…` per successful upload
  - `qualityTransition from=X to=Y reason={slow_hyst|fast_hyst|
    forced_backlog} backlog=…`
  - `networkEvent type={onAvailable|onLost} transportType=…`
  - `retry reason={circuit_open|concurrency_cap|no_auth_token|
    network_error exception=…}`
  - `snapshot t=Xs quality=… cap=… backlog=… orphans=… encrypted=…
    uploaded=… networkType=…` every 30 s

### Changed — Phase 3.7→3.33

- **PUT idempotent** server-side (`storage.upload_blob` overwrite-only,
  Phase 3.12) — removed the silent append-on-existing path that
  doubled the blob on retry-after-cancel.
- **Reconnect handling** (Phase 3.8 + 3.12) — `NetworkCallback.
  onAvailable` resets the circuit breaker, cancels ENQUEUED workers
  only (preserves RUNNING ones whose PUT may already be at the server),
  prunes terminal WorkInfo entries, then re-schedules.
- **POST finalize dropped** (Phase 3.14) — server route was a 204
  no-op; saves one RTT per chunk.
- **Backlog freezes upgrades** (Phase 3.9) at `BACKLOG_FREEZE_THRESHOLD
  =5` to prevent quality from climbing right before the queue grows.
- **`FAST_HYSTERESIS` 5 → 10** (Phase 3.31) — requires ~50 s of
  sustained fast network before an upgrade (vs 25 s previously),
  reduces premature upgrades that happen right before a dropout.
- **TTL sweep 7 d → 48 h** (Phase 3.25) — orphan blobs decay faster
  to shrink the forensic surface.
- **Per-session blob filter** (Phase 3.25) —
  `ChunkUploadQueue.getPendingForSession(sessionId)`. Orphans from
  previous sessions stay on disk (rescuable by OrphanSweepWorker) but
  don't pollute the current session's HUD or scheduleUpload.

### Fixed — Phase 3.7→3.33

- **fsync queueDir after rename** (Phase 3.17) — forced shutdown
  preserves the directory entry, no more orphan ciphertext bytes
  invisible to `listFiles()`. Audit R-06.
- **Jitter on enqueue** (Phase 3.15) — `setInitialDelay(rand[0, 3s))`
  decorrelates worker cohorts; eliminates thundering-herd retries.
  Audit R-08.
- **Concurrency-cap acquire timeout** (Phase 3.16) — 2 s → 5 s.
  Absorbs PUT bursts after a reconnect without bouncing workers
  through WorkManager exponential backoff.
- **Reachability probe before auth** (Phase 3.18) — quick GET
  `/health` (3 s timeout) before `authenticateV2()` ; saves a ratchet
  slot when the network is technically validated but the relay is
  actually unreachable (captive portal scenario). Audit R-09.

### Security — Phase 3.7→3.33

- **JWT no longer persisted on disk** (Phase 3.13) — only lives in
  `UploadAuthHolder` AtomicReference (RAM). A device-seizure
  adversary (Cellebrite-class) dumping `androidx.work.workdb` no
  longer recovers 24 h of upload privileges.
- **nginx `ssl_session_tickets on`** (Phase 3.20) — saves 1 RTT on
  short-reconnect handshakes ; PFS preserved by nginx auto-rotation
  of the ticket key. 0-RTT (early data) stays off.

### Added — Phase 3 (Adaptive quality)
- **AdaptiveQualityManager** (`stream-crypto`) observes per-chunk upload time
  and switches recording quality between **FHD/HD/SD** to keep the upload
  pipeline caught up with capture. Hysteresis: 3 slow ticks → downgrade,
  5 fast ticks → upgrade, mid-band ticks fully neutral. Default initial
  quality: HD (720p). Phase 3.1 + 3.2 + 3.3.
- **CameraX live restart** on quality change. The chunk in flight at
  switch time is lost (its partial MP4 is secure-deleted); subsequent
  chunks record at the new quality. Phase 3.4.
- **HUD quality indicator** ("1080p" / "720p" / "480p") on the recording
  screen, broadcast-driven. Phase 3.5.

### Added — Phase 7 (UX/Polish)
- **REC button pulse animation** (idle 0.97↔1.03 / 1.5s, recording 1.0↔1.10
  / 0.8s). Phase 7.6.
- **i18n FR/EN** — 35+ user-facing strings extracted from layouts and
  Kotlin into `values/strings.xml` (default EN) + `values-fr/strings.xml`.
  Phase 7.5.
- **Settings ABOUT section** — version, commit hash (`BuildConfig.GIT_HASH`
  resolved at build time), AGPLv3 license link. Phase 7.3-A.

### Added — Phase 6 (Security)
- **JWT revocation** via SHA-256 hashed blacklist + `/auth/v2/logout`
  endpoint (Phase 6.1.1).
- **HSTS** header on all server responses + `MINIO_SECURE=true` doc
  (Phase 6.1.2).
- **Server `--workers 1`** explicit until Redis migration (Phase 6.1.3).
- **Crypto 100 % Rust** (Phase 6.1.4): PIN, mnemonic and plaintext chunks
  never enter the JVM heap as `String`. PIN/mnemonic are passed as
  `ByteArray` straight to FFI Rust which wraps them in `Zeroizing<Vec<u8>>`.
  Plaintext chunks (`*.mp4`) are read via Rust I/O directly into a
  `Zeroizing<Vec<u8>>` (no Kotlin `readBytes()`). Sensitive temp files
  are removed via `secure_delete_file` (overwrite + fsync + truncate +
  unlink) instead of plain `unlink()`.
- **JSON audit logging** without IPs (Phase 6.1.6).
- **24 h blob cleanup** asyncio task on the server (Phase 6.1.15).

### Fixed
- **MnemonicHolder cleared after enrollment failure** caused
  "Phrase perdue" on the second attempt; clear now scoped to local-success
  paths only (Phase 7.16, commit `ead260d`).
- **Adaptive quality upgrade never firing** when network recovered:
  mid-band ticks (ratio 0.60..0.80) reset both counters, erasing fast
  streaks. Mid-band is now fully neutral (Phase 3.3 follow-up,
  commit `4f70028`).
- **NetworkCallback double V2 auth** burning two batch slots at start
  (commit `3aaaa21`).
- **Circuit breaker false positive on FNF** (chunk deleted by another
  worker mid-upload) — now caught specifically (commit `2ce548f`).

### Changed — Phase 7.4 (Tella legacy cleanup, sprint 2026-05-10)
Sweeping removal of dead code inherited from Tella FOSS that the V2
streaming pipeline never touched: ~1107 files, −43 313 lines across
16 atomic commits (`7.4-A` → `7.4-M`). Highlights:
- Dropped Tella `:tella-vault` module entirely (Phase 5).
- Dropped 9 dead navigation XML, 144 dead layouts, 14 dead menus, 775
  dead drawables/mipmaps, 19 dead locales (kept `en` + `fr`), 1770 dead
  string entries, 10 dead `values/*.xml`.
- Dropped 48 dead Java/Kotlin sources from `mobile/`, 11 from
  `tella-locking-ui` and `shared-ui`, 6 dead activities (calculator
  camouflage, lock-type settings).
- Dropped ~25 dead Gradle dependencies (osmdroid, glide, sqlcipher,
  cachewordlib, retrofit, exoplayer, image-cropper, etc.); restored
  okhttp + gson + rxjava2 + joda-time as direct deps (were transitive
  via retrofit).

### Changed — Phase 5 (Vault migration)
- **PBEKeyWrapper** hardened: PBKDF2-SHA1/10 K → PBKDF2-SHA256/600 K,
  AES-128 → AES-256, IvParameterSpec → GCMParameterSpec. Backward
  compatible with v1 wrappers via stored `algorithm`/`keyLengthBits`
  fields (commit `d847f74`).
- **Removed** `UnencryptedUnlocker` + `UnencryptedKeyWrapper` (commit
  `4e9cbfa`).

### Breaking — Phase 4 (Audit-driven crypto remediation)
- **V1 chunked-mode blobs are rejected** on decrypt. The protocol moved
  to a per-chunk-keyed AEAD; any blob produced by a pre-Phase-4 client
  must be re-encrypted server-side or re-uploaded (no migration path —
  the V1 stream had auth failures the new format closes).
- **V1 ratchet payloads are rejected** on auth: the V2 auth flow uses
  per-batch ephemeral keys with a salt-derived ratchet. Pre-Phase-4
  clients cannot authenticate against a Phase-4+ server.

### Security
Audit handoff for an external review (Cure53/Trail of Bits) prepared at
[`docs/AUDIT_HANDOFF_2026-05-07.md`](docs/AUDIT_HANDOFF_2026-05-07.md).
The security-critical surface (`crypto-rs`, `server`, `stream-crypto`,
auth + storage protocol) is at `audit-ready` quality at the time of
writing.

---

The full per-phase task list, including in-progress and deferred work,
lives in [`ROADMAP.md`](ROADMAP.md).
