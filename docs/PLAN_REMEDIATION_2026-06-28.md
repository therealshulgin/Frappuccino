# Frappuccino - Plan de remédiation pré-publication (2026-06-28)

> **Statut : plan FIGÉ — ✅ REMÉDIATION COMPLÈTE (WP-A..G + B1..B4 LIVRÉS, 2026-06-28/29).** Identité au repos
> éradiquée (A1 `e1f8a9d` STRM V3, A2 `e6c7948` FFI/UDL, A3+A4 `31d93ac` backups age + registre ;
> + vérif complétude 0-manque ; + dead-code invite `5004847` / `KEY_ENROLLED_AT` `de7b86f` /
> index write-only `_authorized_keys` `254df7f`) ; bord relais durci (B1 `993a4ed` FastAPI
> loopback) ; frontière de confiance rescue close (WP-C `2d09846`) ; durabilité power-loss close
> (WP-D `e4d6d00` fsync `.strm`+metadata avant secure-delete) ; rate-limits réparés (B2 `309b42d`),
> MinIO durci (B3 `a83341c`), supply-chain pinné (B4 `91c55a5`), contrat/preuves/CI (WP-E `eb96b3e`),
> hygiène on-device (WP-F `dff9ae6`), résidus acceptés documentés (WP-G `docs/ACCEPTED_RESIDUALS_2026-06-28.md`).
> **Tous les WP déployés + field-validés sur le relais de test + 2 téls** (sauf field-test WP-F : en attente).
> **Reste hors-plan** : E4/E5 (différables) ; **gestes opérateur** (A3 activation timer backup, 1.2/1.3 LE+DNS,
> 1.8 off-host backup) ; **publication 8.2.5**. Source unique de vérité pré-8.2.5. En cas de divergence, **le code fait foi**.
>
> **Sources** (3 couches d'audit successives, convergentes) :
> - `docs/design-review-2026-06-28/` - steelman par domaine + 4 paris porteurs + carte de questions.
> - red-team par pari (Q1 hors-scope) + son plan de remédiation - **rapport interne, non publié**.
> - audit adverse profond par composant + son inventaire de findings - **rapport interne, non publié**.
>
> **Décisions verrouillées** (ne pas re-litiger) : Q1 (un État bloque l'UDP/443 → repli DirectTls
> classifiable + SNI en clair) = **hors-scope assumé** (pas de mode fail-closed ; Tor mesuré et écarté ;
> destination-non-fiable reportée au serveur de prod). Pari B (forward secrecy au niveau octet) = **TIENT**
> (preuve négative imbattable, ne pas re-traiter).

---

## 1. Pourquoi ce plan (convergence des 3 couches)

Les trois passes, de méthodes indépendantes (défense / cassure-de-pari / audit-par-composant),
**convergent** sur les directions porteuses et se **complètent** par l'altitude :
- Le **design** a affirmé le principe (« le relais ne porte aucune identité au repos ») et produit les
  questions ; le **red-team** a cassé le Pari C dessus ; l'**audit code** a localisé la cassure live et
  trouvé ses frères. Trois méthodes triangulent le même CRITIQUE ⇒ haute confiance, pas un faux positif.
- L'audit code a ajouté **3 HIGH nets** que la couche design ne pouvait pas voir (bord réseau,
  durabilité, frontière de confiance rescue).

**Le constat central (P-1)** : le défaut n'est pas un header isolé, c'est **l'identité long-terme du
témoin qui fuit au repos en plusieurs surfaces qui se composent** en graphe `identité → report → quand`.
Le bon fix est une **passe « retirer l'identité de TOUT le repos »**, pas un patch de header.

---

## 2. Carte findings → work-packages

| ID | Sév (ajustée) | Finding | WP |
|---|---|---|---|
| F-C1 | **CRITIQUE** | En-tête STRM stocke `author_ed25519_pk` (identité long-terme) en clair, joint à `report_id` au repos | **WP-A1** |
| H-1 | HIGH | FFI re-expose l'identité (`BlobMetadata.author_ed25519_pk`, `ByteArray` JVM non-Zeroizing) | **WP-A2** |
| H-4 | HIGH | Backups quotidiens en clair embarquant `.ratchet_registry.json` (roster d'identités) | **WP-A3** |
| H-5 / F-C4 | LOW (ajusté) | Registre : `enrolled_at`/`updated_at` absolus, aucun chemin sécu ne les lit | **WP-A4** |
| H-3 | HIGH | FastAPI sur `0.0.0.0:8000` → Docker DNAT bypass UFW → défait le contrat TLS/pin au bord | **WP-B1** |
| M-3 | MEDIUM | `PUT /file` non-rate-limité (DoS mono-worker / tmpfs) | **WP-B2** |
| M-5 | MEDIUM | Conteneur MinIO non-durci (root, full caps, rootfs writable) | **WP-B3** |
| M-4 | MEDIUM | Retention backup `*.tar.gz` saute `.tar.gz.age` (désarmée si chiffrement activé) | **WP-B4** |
| L-12/L-13/L-11 | LOW | nginx `server_tokens`, images sur tags flottants, systemd non-sandboxé | **WP-B4** |
| M-1 | MEDIUM | Path-traversal rescue : `filename` relais non validé = cible d'écriture locale | **WP-C1** |
| M-2 | MEDIUM | Download rescue non borné → OOM DoS du device de récupération | **WP-C2** |
| L-3 | LOW | Dense-probe rescue borné par le relais (100k round-trips via 1 entrée décimale) | **WP-C3** |
| H-2 | MEDIUM (ajusté) | `.strm` jamais fsync avant secure-delete du plaintext → power-loss = perte de chunk | **WP-D1** |
| M-6 / F-D1 | MEDIUM | Pas de KAT figé inter-langage pour les tags 0x01/0x02/0x03 | **WP-E1** |
| F-D4 | MEDIUM | Tests contrat/diff-fuzz/KAT ne tournent nulle part (CI dormante) | **WP-E2** |
| F-D3 | MEDIUM | Pas de gate « feature `quic` » : un `.so` no-quic ship DirectTls en silence | **WP-E3** |
| F-D2 | MEDIUM | `checkRustSoFresh` = présence de pins, pas provenance `.so` | **WP-E4** (différable) |
| F-07-2/3 | INFO | Preuves Tamarin (0x07/0x08) / TLA+ (rotation slot) ne couvrent plus la surface live | **WP-E5** (différable) |
| L-1 | LOW | `bip39_generate_fr` retourne le mnémonique en `Vec` non-Zeroizing + docs Kotlin fausses | **WP-F1** |
| F-B1/L-6/L-7 | LOW | Livelocks (compteurs `encryptionsInFlight`/`pendingChunks`/`hevcSwapInFlight` fuités sur `start()` throw / thread hung) | **WP-F2** |
| L-8 | LOW | Probe `/health` DirectTls re-expose le signal IP/SNI direct que l'ObfQuic cache | **WP-F3** |
| L-9 | LOW | `SecureWipe.wipe(ByteBuffer)` no-op silencieux sur buffer read-only | **WP-F4** |
| L-10 | LOW | Pas de garde cert↔clé / SPKI==pin au render/restore TLS (risque brick) | **WP-F5** |
| F-C2 | MEDIUM | Répertoire singularisable (nom/taille 1 o/cadence) - M-1 design cosmétique | **WP-G** (accepter/doc) |
| INFO | INFO | PSK Salamander extractable, secure-delete flash, pin expiry, etc. | **WP-G** (doc non-claims) |

---

## 3. Work-packages détaillés

### WP-A - Éradication de l'identité au repos (LE motto, priorité absolue) — ✅ LIVRÉ 2026-06-28
Une passe coordonnée : après WP-A, **une saisie du relais n'expose aucune identité**.

> **✅ Fait.** A1 `e1f8a9d` (STRM V3 : encodeur émet V3 sans author, décodeur lit V3+legacy
> V1/V2, AAD lockstep, test motto **binaire** Rust+Python, décodeur Python en 3e implémentation,
> cross-impl wire Python↔Rust vérifié SHA-identique). A2 `e6c7948` (champ author retiré de la
> `BlobMetadata` FFI + UDL ; 0 conso Kotlin confirmé par grep + assembleDebug). A3+A4 `31d93ac`
> (backup age **obligatoire** zéro-plaintext + service/runbook ; registre sans `enrolled_at`/
> `updated_at`). Gates : cargo test+clippy stream/ffi/cli, `.so` toutes-ABI, assembleDebug, py
> 36/36, pytest serveur 27. **En attente** : field-test Seeker (record=écrit V3 ; rescue=lit
> V3+legacy) + geste deploy A3 (poser le recipient age, clé privée hors relais).

- **A1 [CRITIQUE] STRM header → retrait `author_ed25519_pk` + `VERSION_V3`.**
  - Écriture : `crypto-rs/stream/src/encrypt.rs:191` (`write_header_prefix`), layout `header.rs:66` (`OFF_AUTHOR_PK=5`).
  - Fix : nouvel en-tête V3 `MAGIC ‖ V3 ‖ sealed_session_key(80) ‖ grant_count` (plus d'author_pk ;
    `OFF_SEALED` 37→5) ; `VERSION_CURRENT=V3` ; AAD = nouvel en-tête. **Décodeur garde V1/V2 en lecture**
    (legacy) ; `BlobMetadata.author_ed25519_pk` vide en V3. Champ **mort** (decrypt = enveloppe X25519
    anonyme `decrypt.rs:78` ; 0 consommateur, `UI_FINGERPRINT_AUDIT_2026-05-07:37`) ⇒ retrait propre.
  - **Test motto binaire (nouveau)** : grep des octets [5..37] de blobs réels (pas que l'ASCII de
    `reports.json`) au harnais d'acceptation serveur.
  - Legacy : blobs V1/V2 sur le relais de test = wipés à la migration prod (données de test).
  - ⚠️ Format wire, **GO requis** ; ne touche pas le ratchet.
- **A2 [HIGH] FFI → retirer `BlobMetadata.author_ed25519_pk`** (`crypto-rs/ffi/src/lib.rs:725-731` + UDL ;
  0 consommateur Kotlin). Supprime la fenêtre d'exfil heap JVM + le footgun de ré-introduction.
- **A3 [HIGH] Backups → age obligatoire**, jamais le registre en clair
  (`server/deploy/systemd/frappuccino-backup.service:41-43`, `backup-state.sh:129-138`). Refuser de tourner
  sans recipient age, ou ne jamais inclure `.ratchet_registry.json`/`.authorized_keys.json` en clair.
- **A4 [LOW] Registre → drop/day-bucket `enrolled_at`/`updated_at`** (`ratchet_registry.py:116-125`,
  écrits jamais lus par un chemin sécu) - minimise le résidu d'identité au repos.

### WP-B - Durcissement bord & relais (P-3 : durcissement appliqué à MinIO, pas aux frères)
- **B1 [HIGH] FastAPI → bind `127.0.0.1:8000`** — ✅ LIVRÉ `993a4ed` (compose loopback comme MinIO
  R-SRV-2 ; nginx hôte proxy 8443→127.0.0.1:8000 inchangé ; note anti-régression Dockerfile ;
  runbook vérif (e) + clarif UFW). **Effectif au `docker compose up -d` = geste opérateur.**
- **B2 [MEDIUM]** rate-limit `PUT /file/...` — ✅ LIVRÉ `309b42d`. `@limiter.limit("600/minute")` (généreux :
  flush de backlog single-device ≈ 360/min via `MAX_CAP=6`, 429 non-destructif → retry). **EN L'AJOUTANT,
  découverte que TOUTE la couche rate-limit était un no-op silencieux sauf `/health`** : 2 bugs slowapi —
  (1) chaque routeur construisait son propre `Limiter` ≠ `app.state.limiter` (slowapi n'applique que le
  limiter == `app.state.limiter`) ; (2) `key_style="url"` (défaut) cle sur le chemin REMPLI → une route à
  `{filename}` variable (chaque chunk = URL unique) ne s'accumulait jamais. Fix = `Limiter` partagé
  (`app/ratelimit.py`) + `key_style="endpoint"`. Active enfin enroll 5/min, verify 30/min, challenge 10/min,
  rotate 5/min, HEAD 120/min, archive 60/600/min (brute-force/anti-flood réels). Valeurs existantes gardées
  (généreuses vs pics client mesurés). Tests : `conftest` reset/test (anti-flake CI) + `test_rate_limit.py`
  (garde les 2 fix). `ChunkUploadWorker` 429 commentaire corrigé. pytest 86 vert ; enforcement prouvé en
  process. **⚠️ field-test : confirmer enroll/auth/record/rescue non throttlés** (limites jamais actives avant).
- **B3 [MEDIUM]** durcir le conteneur MinIO — ✅ LIVRÉ `a83341c`. `cap_drop ALL` + `no-new-privileges` +
  `read_only` + `tmpfs /tmp`, calque du service `server`. MinIO n'écrit que `minio_data` (config backend
  `/data/.minio.sys`) + `/tmp` ; healthcheck `mc ready local` = sonde read-only sur l'alias embarqué. Validé
  `docker compose config` (daemon local off). **Effectif au `docker compose up -d` (geste opérateur)** ;
  vérif `docker compose ps` healthy + fallback `MC_CONFIG_DIR: /tmp/.mc` + rollback documentés dans le compose.
- **B4 [LOW]** — ✅ LIVRÉ `91c55a5`. Pin MinIO par **digest** (`minio/minio@sha256:14cea…`, image
  vérifiée du relais) au lieu de `latest` ; nginx **`server_tokens off`** (2 blocks) ; **sandbox systemd**
  de `frappuccino-backup.service` (NoNewPrivileges/PrivateTmp/ProtectSystem=strict+ReadWritePaths/
  ProtectHome/Protect*/Restrict* — docker-safe) + `relay.service` NoNewPrivileges ; retention `.age` déjà
  en place. Server-side, **appliqué au prochain deploy**. Gates : `docker compose config`, `bash -n`.
  *(Caddy `caddy:2`@sha256:cfeb0b… connu, à pin quand sa compose entre au repo.)*

### WP-C - Frontière de confiance rescue (P-2 : le relais est l'adversaire) — ✅ LIVRÉ `2d09846`
> Garde partagé hissé au FFI + clamp à la frontière, hérité par les 3 clients (CLI/FFI/Android).
- **C1 [MEDIUM] path-traversal** — ✅ primitive partagée `crypto-rs/stream/src/pathsafe.rs`
  (`is_safe_blob_filename`) ; FFI prédicat `archive_blob_filename_is_safe` (UDL) ; les 2 downloads FFI
  la valident en dur (InvalidBlob) ; CLI réutilise ; `ArchiveDownloader` pré-check + skip+log.
- **C2 [MEDIUM] OOM** — ✅ cap absolu `MAX_ARCHIVE_BLOB_BYTES` (64 MiB) via `Read::take` dans
  `archive_download_blob` (point d'étranglement unique CLI+FFI) ; `ProtocolError::Io`→`FfiError::Io`.
  *Stream-to-file (C2-bis) différé* : le decrypt exige le blob entier en RAM, et le cap borne déjà ;
  marginal pour le raw (.ots/.fpm petits).
- **C3 [LOW] probe-amp** — ✅ clamp du dense-probe par `entries.len()+512` (CLI + `ArchiveSession`) ;
  doc-comments mensongers corrigés.

> Gates : cargo test stream(30)/ffi(34)/cli(7) + clippy `-D warnings`, `.so` toutes-ABI, assembleDebug.
> Field-test Seeker (rescue lit toujours, noms légitimes acceptés) en attente.

### WP-D - Durabilité (P-4 : destruction sync, création non-sync) — ✅ LIVRÉ `e4d6d00`
- **D1 [HIGH]** — ✅ `strm_encrypt_file` : `File::create`+`write_all`+`sync_all` (+ fsync best-effort
  du dir parent, `cfg(unix)`) **avant** de rendre ; l'ordre Kotlin secure-delete le plaintext APRÈS,
  donc la fenêtre power-loss = chunk perdu est close. `encryptMetadata` (blob seq-0) fsync aussi
  (`FileOutputStream`+`fd.sync()`, gap moindre — pas de plaintext en regard). **Note** : le « skip
  `len==0` » de `secure_delete.rs` n'était PAS un bug (fichier vide = rien à scrubber, unlink quand
  même, déjà testé) — laissé tel quel. Gates : cargo test ffi(34), clippy, `.so` toutes-ABI
  (`cfg(unix)` compilé Android), assembleDebug. Field-test Seeker en attente.

> **Hors-plan (bonus dead-code 2026-06-29)** : retrait de l'index V1 write-only `_authorized_keys`
> (`254df7f`) — mort depuis le drop de `is_key_registered` (`5004847`), redondant avec le ratchet
> registry. Touche enroll/revoke live (server-only) ; pytest 13 + test_server 14/14. Field-test :
> confirmer enroll/revoke device. (Corrige aussi le sur-classement « inherent to ratchet verify »
> du critique de complétude — la vérif lit le *registry*, pas authorized_keys.)

### WP-E - Contrat / preuves / CI (P-6, Pari D) — ✅ E1+E2+E3 LIVRÉS
- **E1 [MEDIUM]** — ✅ KAT figé inter-langage 0x01/0x02/0x03, miroir du report-sig 0x07/0x08.
  Producteur Rust `crypto-rs/core/tests/auth_sig_kat.rs` (rejoue le flux prod enroll→auth(slot 0)→
  rotate(slot 1) depuis `MN_FIXED` ; pin pk/sig + SHA-256 des concats 1600 o ; négatifs cross-domaine
  R-C-1) ⇄ vérificateur Python `server/tests/test_auth_sig_kat.py` (vérifie les octets exacts via le
  helper RÉEL du relais `auth_v2._verify_ed25519_sig` + reconstruit `nonce‖ts_be_u64` / `concat(50 pk)`
  comme la route ; SHA-256 lie le gros vecteur à la source Rust). Ferme le trou « parité à la main »
  (diff-fuzz = Kotlin↔Rust ; route-tests signent en Python avec leurs propres constantes ⇒ un drift
  one-sided passait vert des deux côtés). Gates : `cargo test -p frappuccino-crypto-core` (auth KAT vert)
  + clippy `-D warnings` ; `pytest server/tests` 83 vert.
- **E2 [MEDIUM]** — ✅ `.github/workflows/server.yml` (job pytest relais, déclenché sur `server/**` ET
  `crypto-rs/**` car le contrat KAT est miroir) + `rust.yml` élargi aux `server/**` (un changement de
  tag serveur re-run le producteur Rust). YAML validés ; `pytest tests -q` = 83 vert localement.
  **Dormant jusqu'au remote à la publi (8.2.5)** — fichiers prêts-à-tourner, l'activation = geste publi.
- **E3 [MEDIUM]** — ✅ gate `--features quic` dans `checkRustSoFresh` (`mobile/build.gradle`) : byte-grep
  du PSK ObfQuic **lu depuis** `crypto-rs/stream/src/quic.rs` (module quic-gated ⇒ présent dans le `.so`
  ssi quic compilé ; lu de la source ⇒ auto-actualisé à la rotation PSK, comme les pins SPKI). Un `.so`
  no-quic (ObfQuic→DirectTls silencieux, F-D3) casse le build. Validé : gate VERT sur les 3 ABI quic
  (PSK présent), extraction regex OK.
- **E4 [MEDIUM, différable]** provenance `.so` (repro-build ou digest signé) avant publication publique.
- **E5 [INFO, différable]** étendre Tamarin (0x07/0x08) + TLA+ (consommation slot rotation) à la surface live.

### WP-F - Hygiène on-device (LOW) — ✅ LIVRÉ (`dff9ae6`, 2026-06-29)
- **F1** ✅ doc mnemonic corrigée. Constat à l'implémentation : le Rust était DÉJÀ juste (seule la
  `Zeroizing<String>` source est wipe) ; **le faux doc était côté Kotlin** (`OnBoardMnemonicGenerateFragment`
  prétendait « le buffer Rust est wipe au drop »). Pas de fix Rust possible : **UniFFI n'a aucun hook de
  zeroize sur un retour de bytes** → le `ByteArray` rendu + le RustBuffer sont un résidu borné (cf WP-G).
  Doc remise à la réalité. (Aucun `.rs` touché ⇒ pas de rebuild `.so`.)
- **F2** ✅ livelocks fermés : `Thread.start()` gardé par try/catch dans `onChunkReady` (rollback
  `pendingChunks`/`encryptionsInFlightCounter` si throw — sinon `onDestroy` spin + V2LockTimeoutController
  wedge) ET `applyQualityHevc` (reset `hevcSwapInFlight` si throw — sinon tous les swaps qualité droppés).
  Incréments gardés AVANT start (anti-race onDestroy, intentionnel). **Resserre R-D-1** (cf WP-G).
- **F3** ✅ commentaire corrigé (pas de réécriture transport — ce serait hors-scope et l'auth fuirait la
  même IP). Constat : `authenticateV2()` ne consomme PAS de slot sur relais injoignable (`challenge()`
  échoue avant `signAndAdvance`) ; le control-plane (auth/enroll/status/health) est DirectTls **par design**,
  seul le PUT data-plane est ObfQuic. Scope documenté en WP-G.
- **F4** ✅ `SecureWipe.wipe(ByteBuffer)` renvoie `Boolean` : le no-op sur RO n'est plus silencieux.
  Révélation : `getOutputBuffer()` est read-only par contrat ⇒ le scrub plaintext forensic #3 était un
  **no-op silencieux**. L'encodeur HEVC log 1×/session quand le scrub est indispo (résidu borné, cf WP-G).
  + `SecureWipeTest` (6 cas JVM) fige le contrat.
- **F5** ✅ garde anti-brick TLS dans `render-relay-conf.sh` : refus si (a) cert↔clé ne matchent pas, ou
  (b) SPKI cert ∉ set de pins client (auto-chargés de `pin.rs` ou via `EXPECTED_SPKI_PINS`) ; skip+warn si
  cert non encore provisionné. Validé : `bash -n` + 5 cas fonctionnels (match/wrong-pin/mismatch/auto-pin.rs/multi-pin).
- **Gates** : `assembleDebug` OK (`checkRustSoFresh` vert, `.so` inchangé) ; `stream-crypto:testDebugUnitTest`
  100% (dont `SecureWipeTest` ×6). **Field-test device en attente** (F2 lifecycle, F4 encoder, F1 onboarding).

### WP-G - Accepter + documenter (résidus bornés) — ✅ LIVRÉ (registre `docs/ACCEPTED_RESIDUALS_2026-06-28.md`)
- Registre unique des résidus risque-acceptés (index avec renvois aux sources de vérité, **pas de duplication**) :
  **F-C2** répertoire singularisable (fuite anonyme compteur/cadence, pas d'identité) · **PSK** Salamander
  extractable (obfuscation ≠ confidentialité, by design) · **secure-delete flash** (FBE = la vraie défense) ·
  **pin-expiry** (3 pins + runbook + garde WP-F5) · **HEAD** size-oracle (capability-gated par `report_id`) ·
  **R-D-1/R-C-2** heap-dump device rooté déverrouillé (hors threat-model ; **WP-F2 resserre la fenêtre**).
- Résidus **nouveaux surfacés par WP-F** (F1 mnemonic via UniFFI, F3 control-plane DirectTls, F4 buffer codec
  read-only) intégrés au registre comme résidus bornés honnêtes.
- Cohérence : `METADATA_EXPOSURE_MAP.md` réconcilié (refs `authorized_keys.json` retirées — index V1 mort
  2026-06-29 ; note WP-A3 backup `age` obligatoire).

---

## 4. Ordre d'exécution pré-publication
1. **WP-A** (CRITIQUE - le motto) - en tête, GO requis pour A1 (format V3).
2. **WP-B1** (bypass bord, cheap, motto-relevant).
3. **WP-C** + **WP-D** (protègent la récupération & les témoignages face à un relais hostile / power-loss).
4. **WP-B2/B3/B4** + **WP-E1/E2/E3** (cheap, défense / intégrité de build).
5. **WP-F** (hygiène LOW) — ✅ LIVRÉ (`dff9ae6`).
6. **WP-G** (accepter / documenter) — ✅ LIVRÉ (`docs/ACCEPTED_RESIDUALS_2026-06-28.md`). **WP-E4/E5** restent différables.

## 5. Discipline de validation (par WP)
- **Rust** : `cargo test` (core+stream+ffi) + `clippy -D warnings` ; FFI/stream → `build-android.sh`
  toutes-ABI + bindings régénérés + `assembleDebug` (gate `checkRustSoFresh`).
- **Serveur** : `py_compile` + pytest (une fois WP-E2 en place) + smoke live en reads.
- **Format wire (A1)** : round-trip V3 + décode legacy V1/V2 + KAT re-pin + le nouveau test motto binaire.
- **Chaque WP** : vérif adversariale ciblée (workflow) avant commit ; field-test device pour les chemins
  device (A1 enregistrement+rescue, D1 durabilité, F2 lifecycle).
- **Gestes opérateur** (relais/deploy : B1, A3, B3, B4) = préparés par l'agent, **lancés par therealshulgin**.

## 6. Hors de ce plan (rappel)
1.2/1.3 LE (β suffit), 4.4.7 concat MediaMuxer, UX HUD, mode photo, desktop, D-1(2) destination-non-fiable
(serveur prod), nettoyage `Downloads/Keys_frappuccino`, R-SRV-8 backup age (opérateur), 8.2.5 publication AGPL.
