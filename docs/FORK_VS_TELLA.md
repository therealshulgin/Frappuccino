# Frappuccino vs Tella FOSS — Deltas techniques & reste à faire

*Mémo de synthèse. État au 2026-05-25 — HEAD `6cf2872`, build field test `b58a9f3`.*
*Pour le détail commit-par-commit : `ROADMAP.md` (source unique) + mémoire projet.*

---

## 0. Positionnement

**Tella FOSS** (Horizontal) = app de documentation sécurisée pour activistes/journalistes :
coffre-fort chiffré **au repos**, formulaires ODK, envoi de rapports vers serveurs
(Uwazi / Tella Web), capture photo/vidéo/audio.

**Frappuccino** = fork qui le transforme en **outil de streaming vidéo chiffré
end-to-end, temps réel, vers un relais aveugle**. On conserve la coquille Android
(`applicationId org.hzontal.tellaFOSS`, onboarding, lifecycle keystore) et on remplace
le cœur : crypto, capture, transport, branding.

**Threat model** : porteur sous coercition, saisie device + Cellebrite/GrayKey,
rubber-hose. Le serveur ne doit jamais voir le clair ; le device ne doit jamais
exposer de secret en cas de saisie.

---

## 1. Ce qu'on a MODIFIÉ / AJOUTÉ vs Tella

### 1.1 Crypto — réécriture complète en Rust (protocole V2)
- Workspace `crypto-rs/` (5 crates : core / stream / ffi / cli / fuzz), deps pinnées,
  exposé à Kotlin via **UniFFI**.
- **Identité** dérivée d'une phrase **BIP-39 (12 mots FR)** → Ed25519 (signature) +
  X25519 (ECDH), style libsodium. Paper backup = la phrase.
- **Forward secrecy** : batch ratchet (50 clés éphémères / batch), rotation auto.
- **Conteneur STRM v2** : magic + version + author + sealed + mode + body, AAD
  anti-troncature, binding `chunk_count`, nonce anti-réordonnancement.
- **PIN** : Argon2id (256 MiB × 4) + XChaCha20-Poly1305, fast-reseal (~1,2 s Seeker),
  deny-list anti-bruteforce.
- **Zéro secret sur le heap JVM** : `SecureWipe` / `Zeroizing`, jamais de String Java
  pour PIN / mnemonic / plaintext.

### 1.2 Streaming chiffré temps réel → blind relay
- Recording **chunké 5 s** → blobs STRM chiffrés → upload temps réel (vs envoi de
  rapports a posteriori chez Tella).
- **Upload résilient** (WorkManager) : queue offline persistante, backoff exponentiel,
  PUT idempotent, concurrence adaptative (1-6), dedup `enqueueUniqueWork`, JWT
  **RAM-only** (jamais sur disque), auth V2 challenge/verify (signe `nonce‖timestamp`).
- **Relais aveugle** : FastAPI + MinIO. Les blobs sont E2E-chiffrés → le serveur ne
  voit jamais le contenu, seulement des octets opaques + des métadonnées minimales.
- **Pinning TLS** : SPKI cert pin côté client via **verifier rustls custom** (rustls
  0.23), pas de confiance au CA store système.

### 1.3 Pipeline recording HEVC (sprint H2-B)
- Sortie de `CameraX Recorder` (bitrate = soft-hint ignoré, pas de choix de codec) →
  **MediaCodec direct via wedge OpenGL ES** (pattern Snapchat / OBS / Larix).
- HEVC hardware (gain combiné ~35-45 % vs H.264), **fallback runtime H.264**, adaptive
  **VBR↔CBR** (piloté par le backlog réseau), rolling chunks 5 s avec swap atomique
  (<10 ms, sans rebind caméra).
- Preview on-screen en double-draw (encodeur + écran depuis la même OES texture).
- Fix aspect ratio B.20→B.24 (letterbox + 4:3 natif + correction anamorphique). Le
  fudge `0.75` reste à root-causer → **H2-B.25** (cf §2).

### 1.4 Résilience terrain
- Foreground service + `PARTIAL_WAKE_LOCK`, recording **écran éteint**, exemption
  battery optimization.
- Enrollment retry (cas onboarding offline → online), résilience réseau
  (NetworkCallback + retry auth), fix `no_auth_token` sur lock écran éteint.
- Trio anti data-loss : report **idempotent** (anti-split sur retry), **sweep** des
  reports zombies côté serveur, **HTTP 507** disk-full + circuit breaker client.

### 1.5 Archive mode / récupération
- Phrase BIP-39 → fingerprint match → **download des streams chiffrés** depuis le
  relais, manifest JSON + playlist `.m3u`, « tout télécharger » + busy guard +
  anti-doublon MediaStore.

### 1.6 UX / branding OSINT
- Wordmark FRAPPUCCINO (typo Coffee Amore), dark rouge `#CC1A1A` / noir, écran REC
  style Blackmagic, animation bouton REC.
- Stealth black screen (overlay noir immédiat + tap-to-exit), 5 écrans PIN harmonisés,
  retrait complet des visuels/logo Tella, i18n FR.

### 1.7 Hardening sécurité
- ProGuard obfuscation, serveur **non-root**, validators Hex, rate-limit, atomic JSON
  save, healthcheck Docker + auto-restart.
- Fuzzing (cargo-fuzz, 4 targets, ≥1 M iter), coverage ~90 %, passes d'audit Red /
  Blue team + contre-audit.
- **RT-01** (MITM via CertificateVerify non vérifié) → **fixé + test de régression
  MITM**. **RT-07** (auto-rotation morte) → **fixé**.

### 1.8 Vault & code Tella retirés
- **Vault Tella retiré entièrement** (= Phase 5, ✅ close 2026-05-09) : c'était du
  **code mort** en V2 (le pipeline streaming le bypasse, `EncryptedFileProvider` sans
  call site) → plutôt que migrer du code mort, on a supprimé le vault + durci le seul
  composant encore vivant `PBEKeyWrapper` (SHA1→SHA256, 10 K→600 K iter, AES 128→256-bit,
  GCM).
- Coupés au manifest : vault gallery, forms, ODK, Uwazi, Reports legacy (source gardée).
  Reste un **cleanup Tella résiduel** (flow password/pattern legacy ~10 fichiers, pruning
  shared-ui) → c'est **Phase 7.4**, pas Phase 5.

---

## 2. Ce qui reste à faire

### Phase 1 — Infra prod 🟡
- **1.2 Let's Encrypt** (clé persistante entre rotations) + **1.3 DNS** propre →
  permet de **migrer le serveur sans rebuild APK** (aujourd'hui le SPKI pin est sur
  l'IP). Rentable **avant** que le disque grossisse (TTL blobs 6 mois).
- 1.1 choix / migration provider · 1.6 doc procédure rotation cert + grace period ·
  1.8 backup off-host (vraie DR) · 1.9 surveillance disk · **1.11 long-haul
  (← field test en cours)**.

### Phase 3 — Recording 🟡
- **3.6 gapless V2** : supprimer le gap résiduel (~200 ms) entre chunks.
- **H2-B.25 fix aspect principié** : root-cause du squish, **retirer le fudge `0.75`**.
  Approche (modèle jetpack-camera-app) : dimensionner le SurfaceTexture d'entrée à la
  résolution caméra négociée + dériver la transform du crop fourni, au lieu d'un facteur
  en dur. **Gated** sur le datum field test + l'A/B legacy-vs-HEVC.

### Phase 5 — Migration vault legacy Tella ✅ Close (2026-05-09)
- Le vault Tella s'est avéré **code mort** en V2 → retiré entièrement + `PBEKeyWrapper`
  durci. Détail en §1.8. (Le seul résiduel Tella = cleanup Phase 7.4.)

### Phase 6 — Sécurité restante + CI 🟡
- 6.1.1-3 / 4 / 6 + **6.2 CI hardening** (gates fmt / clippy / test reproductibles —
  cf le drift fmt/clippy local à régler avant l'audit).

### Phase 7 — UX / Polish 🟡 (15/17 livrés)
- 7.1 icône custom · 7.2 thème dark complet · 7.7 illustrations onboarding ·
  **7.15 caméra dim-screen** (ne pas freezer la preview au stop) ·
  **7.17 cadrage caméra** (4:3 plein-FOV vs 9:16 vidéo — décision après l'A/B).

### Phases 8-10 ⚪
- **8** Audit externe (Cure53 / Trail of Bits) + publication AGPLv3 + F-Droid — prêt
  mais **non prioritaire** (timing = ton choix ; focus solidité d'abord).
- **9** Client **desktop de secours** (rescue / download des streams).
- **10** Mode **photo** (1 capture = 1 blob STRM SINGLE), post-publication.

---

## 3. À surveiller pendant le field test (Phase 1.11 long-haul)
- **`metrics.log`** : `no_auth_token` (doit être 0), splits de sessionId, retry reasons,
  et surtout le **datum aspect `hevcPreviewNegotiated`** — `ratio=1.778` = la demande
  4:3 a été ignorée ; `1.333` = bug HAL anamorphique. Ce datum **décide** le fix H2-B.25.
- **Serveur** : `audit-reports-vs-blobs.sh` (survival ratio, zombies, orphans) + le CSV
  horaire `/var/log/frappuccino-audit.csv`.
- **Crashes** : `dumpsys activity exit-info` (le fix audio H2-B.19 devrait tenir).
- ⚠️ **Couper `BITRATE FIXE`** si tu ne veux pas accumuler des copies `debug_raw/*.mp4`
  **non chiffrées** sur le device pendant le voyage.

---

## 4. Carte mentale (où vit quoi)
- **Crypto V2** : `crypto-rs/` (Rust) → UniFFI → Kotlin.
- **Capture / recording** : `stream-crypto/.../capture/` (`GlVideoPipeline`,
  `RollingChunkRecorder`, `HevcMediaCodecEncoder`) + `mobile/.../service/StreamRecordingService`.
- **Upload / transport** : `mobile/.../util/jobs/` (`ChunkUploadWorker`, `UploadHttpClient`,
  `UploadAuthHolder` RAM-only, `UploadConcurrencyLimiter`, `OrphanSweepWorker`).
- **Serveur** : `server/app/` (FastAPI : routes upload/reports/auth, storage MinIO,
  cleanup loops) + `deploy/` (nginx TLS, backup, audit, monitoring).
- **Doc** : `ROADMAP.md` (source unique, 10 phases).
