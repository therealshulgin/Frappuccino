# red_team.md — Brief d'audit offensif adverse

**Cible :** Frappuccino STREAM (fork Tella FOSS) — app Android de témoignage vidéo E2E pour militants/journalistes.
**Auditeur :** modèle Fable 5 (classe Mythos). Œil neuf, mandat adverse.
**Co-équipier :** `blue_team.md` (contre-audit). Tu attaques, il vérifie/réfute. Tu ne te valides pas toi-même.
**Enjeu réel :** un faux négatif ici = une vidéo de témoin déchiffrée par un État après saisie du téléphone, ou un témoin désanonymisé. La barre de rigueur est en conséquence (cf. §6).

---

## 0. Ton mandat

Trouver des **faiblesses réellement exploitables**, pas des observations de style. Chaque finding doit venir avec un **chemin d'exploitation concret** (qui est l'adversaire, ce qu'il contrôle, la séquence d'étapes), un **ancrage `fichier:ligne`**, et une **esquisse de PoC**. Les résultats négatifs (« j'ai tenté X, voici pourquoi ça tient ») ont de la valeur — documente-les.

Ce code a déjà subi : audit Red/Blue V2 (remédiations BT-HIGH), migration crypto 100 % Rust, une suite de preuves formelles (§3), un sweep de code mort (réduction de surface), et des field-tests multi-jours. **Ne refais pas ce travail. Attaque ce que ces couches NE couvrent PAS** (les frontières d'abstraction, les coutures, l'opérationnel).

---

## 1. Modèle de menace

### Adversaires (par capacité croissante)
1. **Saisie passive** — frontière, fouille, arrestation. L'adversaire obtient le téléphone **verrouillé**, fait une image forensique de `/data`, analyse l'APK. Ne connaît pas le PIN ni la phrase BIP-39.
2. **Coercition / unlock contraint** — l'adversaire **force** le déverrouillage (légalement ou physiquement). Obtient le PIN. Question : que protège encore la forward secrecy ? Que reste-t-il en RAM/au repos ?
3. **Réseau actif (Dolev-Yao)** — MITM total sur le lien client↔relay. Peut injecter, rejouer, retarder, downgrader.
4. **Relay compromis / hostile** — l'adversaire possède le serveur (ou le saisit chez l'hébergeur Vultr). Voit tous les blobs chiffrés, l'`identity↦batch` registry, peut mentir au client.
5. **Adversaire interne build/supply-chain** — dépendance empoisonnée, .so Rust altéré, build non reproductible.

### Actifs à protéger (par ordre de gravité)
| Actif | Compromission = | Garanti par (à challenger) |
|---|---|---|
| **Confidentialité des rushes** | vidéo de témoin lisible par l'adversaire | STRM E2E (XChaCha20-Poly1305, clé scellée X25519) |
| **Forward secrecy** | une clé future compromise déchiffre le passé | ratchet éphémère 50-slots, batch use-once |
| **Anonymat/non-liaison du témoin** | relier device↔activité↔identité | blind relay, pas d'access-log, métadonnées minimales |
| **Intégrité d'authentification** | un tiers s'enrôle/poste à la place du témoin | challenge-response Ed25519, anti-rejeu nonce |
| **Déni plausible / discrétion** | la simple présence de l'app/preuve incrimine | (camouflage Tella largement retiré — voir §5) |

---

## 2. Architecture sous test (carte)

```
ANDROID (Kotlin, non prouvé)            RUST (crypto-rs, fortement prouvé)        RELAY (Python/FastAPI)
────────────────────────────           ───────────────────────────────          ──────────────────────
CameraX→GL→MediaCodec HEVC      ┐
  → MP4 chunk (cacheDir)        │  strm_encrypt_file(in,out,id) ──► STRM blob ──► PUT /file/{rid}/{fn}
  → secure_delete plaintext     │  (lecture disque, jamais heap JVM)             (JWT stream-scope + owner)
StreamUploadManager             │  EphemeralRatchet.sign_and_advance ──► /auth/v2/verify ──► JWT
  PIN → pin_store_open_extended │  (Argon2id m=256MiB) ──► ratchet déscellé      (HS256, nonce single-use)
  EncryptedSharedPreferences    │  pin_store_seal_with_key (reseal rapide)
  UploadAuthHolder (JWT RAM)    │  advance_batch ──► RotationProof ──► /auth/v2/rotate-batch
ArchiveAuthHolder (rescue)      ┘  archive_download_and_decrypt ──► /api/v2/archive/...
                                    strm_decrypt_to_file (plaintext→disque, jamais FFI)

Lien : OkHttp + CertificatePinner SPKI + network_security_config.xml ──► nginx :8443 (TLS) ──► :8000
```

**Frontière critique = la colonne du milieu.** Rust est prouvé ; Kotlin et Python ne le sont pas ; la **couture FFI** (UniFFI→JNA→.so) et la **couture HTTP** (client↔relay) sont les zones grises.

Pointeurs racine : `crypto-rs/` (workspace `core`/`stream`/`ffi`/`cli`), `mobile/src/main/java/...`, `stream-crypto/src/main/java/org/stream/crypto/...`, `server/app/...`, `server/deploy/`.

---

## 3. Ce qui est DÉJÀ prouvé — n'attaque pas l'invariant, attaque le GAP

La crypto Rust porte une suite formelle (§8.4 du ROADMAP). **Tu ne gagnes rien à re-prouver ces invariants ; tu gagnes à trouver où le modèle s'écarte du code.**

| Preuve | Ce qui est garanti | **Frontière = ta cible** |
|---|---|---|
| **TLA+** `core/proofs/EphemeralRatchet.tla` (≈4680 états, TLC exhaustif) | FSM ratchet : batch monotone, anti-rejeu, no-rollback, use-once, bornage | Abstrait les **octets**. Ne couvre PAS serialize/deserialize, HKDF, le signe Ed25519 réel, la zeroization machine, **ni la concurrence avec l'appelant Kotlin** (auto-rotate, threads upload). |
| **Tamarin** `core/proofs/RatchetProtocol.spthy` (10/10 lemmes, Dolev-Yao) | Secrecy éph.+ltk, authentification slot, anti-rejeu, inforgeabilité RotationProof, no-rogue-batch, forward secrecy | Crypto **parfaite** + keygen **honnête** ; 1 slot représentatif/batch. **2 trouvailles ouvertes** = ta porte d'entrée (voir §4-C). N'inclut pas le code serveur réel ni les canaux auxiliaires. |
| **Kani** `stream/src/kani_proofs.rs` (parse_header) | `parse_header` total/panic-free sur entrées bornées | Ne couvre PAS le chemin **decrypt complet**, l'AEAD, l'assemblage chunk au-delà du modèle, ni l'**encrypt**. |
| **zeroize-audit** `core/audit/assert_zeroize_not_dse.sh` (0 DSE @ opt=s) | Le wipe ratchet n'est pas dead-store-éliminé dans l'IR shippé | **Un seul secret** (ratchet). Ne couvre PAS la clé dérivée PIN, les session keys STRM, les `ByteArray` Kotlin, ni les spills de pile ailleurs. Nuance : prouvé à `opt=s`, ≠ O2. |
| **diff-fuzz** Kotlin↔Rust (759/759 via UniFFI→JNA) | Kotlin et Rust **concordent** sur 759 vecteurs | Concordance ≠ correction (un **bug partagé** passe). Hors espace testé = inconnu. |
| **proptest** `core/tests/`, `stream/tests/` | Round-trips STRM/ratchet + invariants FSM sur schedules aléatoires | Test, pas preuve ; borné à la distribution des générateurs. |
| **cargo-mutants** (decrypt 100 %, header 98 %) | Mutants logiques tués dans core/stream | Exclut `ffi/`, `cli/`, tests. Survivant `be_u16` prouvé équivalent. |

**Règle d'or :** si ton finding vit *à l'intérieur* d'un de ces périmètres, tu te trompes probablement (le blue te réfutera via la preuve). Si ton finding vit *dans une frontière* ci-dessus, tu tiens peut-être quelque chose de réel.

---

## 4. Surfaces prioritaires (attaque ici)

### A. Frontière FFI Rust↔Kotlin (UniFFI / JNA / .so) — **priorité haute**
Le seam entre prouvé et non-prouvé.
- **Durée de vie des secrets au passage FFI.** Tout export retourne des **copies `Vec<u8>`/`ByteArray`** ; le wipe côté Kotlin est *best-effort* (`SecureWipe.wipe`). Cherche : un secret (clé dérivée PIN via `pin_store_open_extended` → `UnsealedBlob.derived_key`, session key, ratchet déscellé) qui **survit sur le heap JVM** après usage. Le GC JVM peut copier/déplacer un `ByteArray` (compaction) → reliquats non wipés. Vérifie `StreamUploadManager.kt`, le pattern de wipe, et si un `String` PIN transite (interning = non-wipable).
- **Panics à la frontière.** `Cargo.toml` met `panic = "unwind"` pour que `catch_unwind` UniFFI piège et lance une `FfiException` (et que les `Drop`/Zeroizing tournent). **Challenge :** existe-t-il un chemin où un panic **abort**e quand même (double-panic dans un Drop ? allocation échouée ? `expect` dans `sign_and_advance:285`/`advance_batch:359`/`encrypt.rs`/`decrypt.rs`) ? Un abort = pas de Zeroizing = plaintext/clé dans un core-dump.
- **Chargement du .so.** `System.loadLibrary("uniffi_frappuccino")` + tâche gradle `checkRustSoFresh` (anti-binaire-périmé). **Challenge :** que se passe-t-il si le .so est absent/altéré/d'une autre ABI ? Y a-t-il un fallback qui dégrade la sécurité ? Le check de fraîcheur est-il contournable en build release ?
- **Confusion de type/longueur au passage.** Les exports font `try_into()` sur les tailles de clés. Cherche un appelant Kotlin qui passe une longueur inattendue (PK tronquée, signature 0-byte) menant à une erreur **silencieusement avalée** plutôt que rejetée.

### B. Format STRM & crypto de flux (au-delà de `parse_header`)
Kani couvre le header ; le **corps** et l'**encrypt** sont moins couverts.
- **Réutilisation de nonce.** SINGLE = nonce 24B aléatoire ; CHUNKED = préfixe 20B aléatoire ‖ index 4B. **Challenge :** sur un même `session_key`, deux chunks peuvent-ils partager (préfixe,index) ? Le préfixe est-il tiré d'un CSPRNG par blob ? Un `session_key` peut-il être réutilisé entre deux blobs (catastrophe XChaCha) ?
- **Troncation / réordonnancement.** V2 lie `chunk_count` + index dans l'AAD ; V1 CHUNKED est **rejeté** (attaque RT-02). **Challenge :** le rejet V1-CHUNKED est-il étanche (un blob forgé version=1 mode=2 est-il refusé *avant* toute allocation) ? Peut-on tronquer un V2 (dropper le dernier chunk) et le faire passer ? Cap `MAX_CHUNK_COUNT`/`MAX_CHUNK_LEN` — overflow d'allocation (DoS) avant vérif ?
- **Scellement de la session key.** Header `sealed_session_key` 80B via `crypto_box_seal` (X25519, nonce=zéros). **Challenge :** malléabilité de l'enveloppe ? Un relay hostile peut-il substituer un `author_ed25519_pk` du header sans casser le déchiffrement (le header est-il dans l'AAD partout) ?
- Cible mutation-survivante connue : header `be_u16` (prouvé équivalent) — ne perds pas de temps dessus, mais cherche d'**autres** survivants non documentés.

### C. Ratchet — gaps opérationnels (les 2 trouvailles Tamarin = or)
- **Séparation de domaine auth(40B) / rotation(1600B).** Tamarin signale que la **sûreté de rotation dépend de la séparation de taille** entre un message d'auth (signe le nonce, ~40B) et une preuve de rotation (signe 50 PKs, ~1600B). **Challenge frontal :** peux-tu fabriquer un message d'un type interprétable comme l'autre ? Existe-t-il un préfixe de domaine explicite, ou la sécurité repose-t-elle *uniquement* sur la longueur ? C'est la vuln la plus prometteuse du dossier — la reco « domain-sep explicite » n'est **pas encore implémentée**.
- **UKS (unknown-key-share).** Tamarin : l'auth est liée à la **clé de slot**, pas à une autorité transférée. **Challenge :** un adversaire peut-il faire accepter au serveur une signature comme provenant d'une autre identité (re-binding) ?
- **Persistance / rollback de l'état ratchet.** Le blob V2 (4876B, MAC HMAC-SHA256) est PIN-scellé puis stocké (`stream_identity_v2` EncryptedSharedPreferences). TLA+ prouve le no-rollback *en mémoire*. **Challenge :** au niveau **disque/process**, un adversaire qui restaure une **sauvegarde antérieure** du blob scellé (snapshot `/data`, ADB backup) peut-il **rejouer des slots déjà consommés** ? Le serveur rejette via `consumed_indices`, mais le *client* réutiliserait des privés censés wipés. Étudie la divergence état-client vs état-serveur après restauration.
- **Concurrence Kotlin.** `remaining_in_batch()` déclenche un auto-rotate côté Kotlin ; les `ChunkUploadWorker` consomment des slots. **Challenge :** course entre deux workers et l'auto-rotate → double-consommation d'un slot, ou rotation pendant une signature en vol. TLA+ ne modélise pas ces threads.

### D. Secrets en RAM & gate de verrouillage (Kotlin)
- **PIN en `String`.** `PinLockView` expose le PIN comme `String` (interning JVM → **non effaçable**). `OnBoardSetPinFragment` convertit en `ByteArray` puis wipe en `finally`. **Challenge :** le `String` intermédiaire laisse-t-il une copie dans le pool ? Combien de temps ? Récupérable par dump heap post-coercition ?
- **Clé dérivée cachée.** `pin_store_open_extended` retourne `derived_key` (32B) cachée pour les reseals rapides (`pin_store_seal_with_key`). **Challenge :** durée de vie ? Effacée par `lock()`/`panicWipe()` sur **tous** les chemins (crash, kill, timeout) ? Un dump heap pendant la session la donne-t-elle (= contournement d'Argon2) ?
- **Gates d'auto-lock.** `V2LockTimeoutController` (clear JWT, `lock_timeout` défaut 0=immédiat) et l'auto-lock ratchet (`ratchet_autolock_ms` défaut 15 min) **défèrent pendant un enregistrement/chiffrement**. **Challenge :** un adversaire peut-il maintenir l'app dans un état « occupé » (enregistrement zombie, queue non vide) pour **empêcher indéfiniment** le wipe et garder le ratchet déscellé en RAM ? Le `isLocked()→finish` est-il contournable (rotation d'écran, deep-link, intent externe, back-stack) ?
- **Pas de wipe sur N PIN ratés** — `PinAttemptTracker` ne fait que du lockout (délais 0/0/0/5s/.../10min). **Challenge stratégique :** pour le modèle de menace coercition, est-ce le bon choix ? Un adversaire avec le device temporise les lockouts et brute-force hors-ligne le blob scellé (Argon2id m=256MiB = coûteux mais fini si PIN court). Quantifie : entropie PIN × coût Argon2 = temps de cassage. Recommande (ou réfute) un wipe-after-N.

### E. Surface forensique au repos (saisie device) — **priorité haute**
C'est là que la confidentialité E2E peut être contournée **sans** casser la crypto.
- **MP4 plaintext en staging.** `cacheDir/stream_chunks/*.mp4` existe entre l'écriture HEVC et le `secure_delete_file`. **Challenge :** fenêtre de course sur **crash/force-kill/OOM mid-encrypt** → orphelins plaintext jusqu'au prochain `CaptureScratchCleaner`. Quantifie la fenêtre. Le `secure_delete` (overwrite+fsync+truncate+unlink) est-il efficace sur **stockage flash** (wear-leveling : l'overwrite n'écrase pas la cellule physique) ? — c'est une limite intrinsèque à exposer.
- **`debug_raw` plaintext.** `filesDir/debug_raw/*.mp4`, copies plaintext pour calibration. **Challenge (R-H1 historique) :** gating par `isDebuggable()` + toggle runtime. Le fix `purgeDebugRaw()`/`secureDeleteFile` (Phase H2-B.11) couvre-t-il **tous** les chemins ? Un adversaire qui obtient le device en lock peut-il **activer** le toggle (mode debug, intent, settings caché) et obtenir du plaintext **sans** BIP-39 ? **Lié au footgun §5.** Vérifie que c'est mort en build release.
- **WorkManager SQLite.** Les chemins de fichiers chunk sont stockés en clair dans `androidx.work.workdb` (le JWT, lui, est RAM-only). **Challenge :** ces chemins + timestamps = **métadonnées de timeline** liables au témoin, persistantes, non chiffrées. Que révèlent-ils exactement ?
- **Autres :** thumbnails (générés ?), buffers MediaCodec en heap (wipe `SecureWipe` post-mux — étanche ?), logcat (noms de chunk/report/session IDs en clair ?), reliquats de cache survivant à l'uninstall.

### F. Relay / serveur (Python) — hypothèses de confiance
- **JWT HS256, secret unique.** `JWT_SECRET` env, **pas de rotation**, même clé pour scope `stream` et `archive`. **Challenge :** fuite du secret (logs ? dump env ? image disque Vultr) = forge totale. Confusion d'algorithme (`alg:none`, RS/HS) — `jwt.decode` est-il pinné à `algorithms=["HS256"]` partout ? La séparation de scope (`require_stream_auth` rejette `archive` et vice-versa) est-elle appliquée sur **toutes** les routes ?
- **Enforcement d'ownership.** Upload/download vérifient `report.owner == user_id`. **Challenge :** IDOR — un témoin peut-il lister/télécharger les blobs d'un **autre** report (énumération `report_id` UUIDv4 — large mais à confirmer), ou poster dans le report d'autrui ?
- **Anti-rejeu nonce.** Nonce single-use, TTL 60s, skew ±30s, lié au timestamp signé. **Challenge :** course pop-then-verify ; un nonce peut-il être consommé deux fois sous concurrence (le worker unique + asyncio aide le défenseur — confirme) ? Le binding timestamp empêche-t-il vraiment de rejouer une signature sur un autre nonce ?
- **Confidentialité du registry.** `.ratchet_registry.json` (identity↦50 PKs↦consumed) sur disque serveur. La sécurité repose sur la vérif de **signature**, pas le secret du fichier — mais sa **lecture** désanonymise (qui est enrôlé, quelle activité). **Challenge :** un relay saisi livre-t-il la carte sociale des témoins ?
- **DoS / disponibilité.** `title`/`description` de report **non bornés** → croissance `reports.json`. JSON profond (pas de limite de récursion explicite). Flood `/auth/challenge` (rate-limit 10/min + cleanup nonce). Disk-full → 507 + circuit-breaker client. **Challenge :** un adversaire réseau peut-il remplir le disque, faire diverger état mémoire/disque sous crash, ou bloquer l'ingest des témoins légitimes ?
- **Traversal blob.** `report_id`/`filename` whitelist regex + strip `..`. **Challenge :** un encodage (double-URL, unicode, null-byte) franchit-il la regex côté FastAPI/nginx ?

### G. Downgrade / fallback / footguns de config
- **Footgun calibration « BITRATE FIXE » (§8.2.8).** Le mode DEBUG laissé ON **bypass silencieusement** le plafond qualité *et* l'adaptatif. **Challenge :** confirme l'exploitabilité en build debug et **vérifie que la section DEBUG est gatée derrière `BuildConfig.DEBUG`** (elle doit l'être avant publication ; si elle ne l'est pas, c'est un finding HIGH — un build release exposerait un bypass + potentiellement `debug_raw`).
- **Flag `DOMAIN` / TLS.** Mode IP = cert **auto-signé**, **HSTS off**, pin SPKI côté client. Mode domaine = LE + HSTS. **Challenge :** en mode IP, un MITM qui présente un cert auto-signé arbitraire est-il bloqué *uniquement* par le pin SPKI client (`network_security_config.xml` + `CertificatePinner`) ? Les deux couches sont-elles cohérentes ? Un build qui oublie une couche downgrade-t-il ? `MINIO_SECURE=false` interne — exposable ?
- **Fallback HEVC→H.264** (`onCodecError`, one-shot). **Challenge :** un downgrade forcé (déclencher l'erreur codec) change-t-il une propriété de sécurité, ou juste le codec ? (probablement bénin — confirme et passe).

### H. Supply chain & build
- **Deps restantes** après le sweep (joda/rxjava/rxandroid viennent d'être retirés). **Challenge :** CVE dans une dep transitive vivante (réseau : OkHttp ; média : ExoPlayer ; JNA ; desugaring). La couche réseau parse-t-elle de l'input hostile ?
- **Build non reproductible** (gap connu, non poursuivi). **Challenge :** rien à exploiter à distance, mais note l'écart de confiance pour le dossier auditeur (un .so altéré ne serait pas détecté par re-build).

---

## 5. Sharp edges connus à sonder (raccourcis)

- Reco **domain-sep ratchet** (Tamarin) **non implémentée** — §4-C.
- Footgun **calibration DEBUG** + **debug_raw** — §4-E, §4-G ; doit être mort en release.
- **Fenêtre plaintext MP4** sur crash — §4-E.
- **secure_delete sur flash** (wear-leveling) — limite intrinsèque, §4-E.
- **JWT secret unique, pas de rotation** — §4-F.
- **PIN en String** + **pas de wipe-after-N** — §4-D.
- **RT-08** (reliquats plaintext sur realloc CHUNKED decrypt) — accepté en defense-in-depth ; vérifie si exploitable au-delà de l'acceptation.
- **Camouflage Tella** : les layouts calculatrice/déni-plausible ont été **retirés** (sweep code mort). Si une doc/string suggère encore un mode caché, c'est un **signal trompeur** — flag-le (un militant pourrait croire à une protection inexistante).

---

## 6. Règles d'engagement & barre de preuve

- **Périmètre :** le code de ce repo. **N'attaque pas** le vrai serveur Vultr (136.244.101.236) ni une infra tierce — travaille depuis le code et un déploiement local si besoin.
- **Barre « absolument sûr » :** la discipline du projet (héritée du sweep code mort et des mini-audits) est : *un finding affirmé doit être démontré, pas plausible*. Pour chaque finding : adversaire + capacité, séquence d'exploitation, `fichier:ligne`, esquisse PoC ou test reproductible, et **pourquoi les preuves du §3 ne le couvrent pas**.
- **Sévérité :** note (1) gravité crypto/CVSS-like ET (2) **impact mission** (confidentialité rush / forward secrecy / anonymat / intégrité auth / disponibilité). Un bug « mineur » techniquement peut être « critique » mission (ex. une fuite de métadonnée désanonymisante).
- **Pas de hand-waving.** « Pourrait théoriquement » sans chemin concret = à classer toi-même en *spéculatif*, séparé des findings réels.
- **Diversité de lentilles** encouragée : attaque chaque surface sous l'angle correctness, crypto, forensique, opérationnel — ce ne sont pas les mêmes bugs.

---

## 7. Livrable attendu

Une table de findings + une section « ce que je n'ai pas pu casser ».

```
| ID | Titre | Surface (§4) | Adversaire | Sévérité (crypto / mission) | Exploitabilité | Actif touché | Repro/PoC | fichier:ligne | Hors-périmètre des preuves ? | Correctif suggéré |
```

- **ID** : `R-<surface>-<n>` (ex. `R-C-1` pour le domain-sep ratchet).
- **Exploitabilité** : Démontrée / Plausible-à-confirmer / Spéculative.
- **Hors-périmètre des preuves** : cite quelle frontière du §3 (sinon, justifie pourquoi tu n'es pas en contradiction avec une preuve).
- **Correctif suggéré** : doit, idéalement, **préserver les invariants prouvés** (le blue jugera).

Termine par un **classement Top-5** par impact-mission, et la liste des **hypothèses de confiance** que tu as dû accepter (elles deviennent des items pour le dossier auditeur 8.2.2).

> Rappel : ton output passe au `blue_team.md`, qui réfute par défaut. Un finding qui survit à la réfutation adverse vaut dix qui n'y survivent pas. Vise la qualité, pas le volume.
