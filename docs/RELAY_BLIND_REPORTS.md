# Relay-blind reports — design **v3** (Phase C, « une saisie n'expose rien »)

**Statut : IMPLÉMENTÉ ET DÉPLOYÉ EN PROD (cutover 2026-06-26), field-validé sur 2 devices.** Ce document a été rédigé comme spec de conception (v3, post-2-passes d'audit adverse Opus 4.8) ; **les 5 tranches du §11 sont toutes livrées**. Le corps ci-dessous reste un compte-rendu exact de la conception telle qu'**implémentée** — ne PAS le lire comme « à faire ».

> **Implémentation (un auditeur ne doit pas conclure « feature absente ») :** dérivation Rust `crypto-rs/core/src/report.rs` (report_master/key/id + tags `0x07`/`0x08`, miroir `server/app/signature_domain.py`) ; serveur `server/app/routes/{upload,reports,archive}.py` (`reports.json = {report_id, report_pk}` SEUL, archive id-free sans JWT, write-once + budget création + rollback) ; client `mobile/.../util/jobs/{ChunkUploadWorker,DirectoryEntryWorker}.kt` ; tests `server/tests/test_relay_blind_reports.py` + `test_report_sig_kat.py`. Commits porteurs : `ec4f9dc`, `45f1046`, `b4c214b` (+ durcissement post-cutover). Cutover + field-test = 2026-06-26.

v3 intègre les 2 passes adverses (2026-06-26) — faits porteurs re-vérifiés à la main. Voir §12 pour la traçabilité audit→disposition.

Objectif : retirer du relais, **au repos**, le lien `identité → ses reports → quand`, sans casser le ratchet, sans casser l'autorisation d'upload, sans casser le rescue.

Décisions verrouillées (therealshulgin) :
1. **Cutover = clean break** — wipe l'état de test du relais + re-enroll les devices + **retrait des chemins V1** (`/auth/verify`, `/auth/invite/verify` ; le module `auth_routes.py` reste monté pour `/auth/challenge`).
2. **Lectures = identité-free total** — le `report_id` (128 bits, dérivé de la phrase) EST la capability.
3. **Création = gatée par le ratchet** (anti-sybil) ; l'identité vérifiée est **jetée**, jamais persistée.
4. **Le ratchet ne doit PAS être cassé** (contrainte dure).

---

## 1. Modèle de menace + périmètre

**Adversaire** : saisit/contraint le **disque** du relais (`reports.json`, `.authorized_keys.json`, `_ratchet_registry.json`, **logs conteneur**, MinIO) **et/ou opère le relais** (peut dropper/tronquer). Cherche « quelle identité a enregistré quoi, quand ».

**Dans le périmètre (fermé par v3)** : la jointure au repos `report → identité` = `owner=pk` + `author=pk[:32]` + `createdAt` (`reports.json`) + **le pk dans les logs** (y compris via exceptions/`repr`, §9).

**Anti-troncature — 3 propriétés (§7)** :
- **Prévention** = impossible avec relais unique non-fiable (motto : « relais, pas coffre »). **Hors périmètre, inhérent.**
- **Détection** = fournie par `racine Merkle → OTS → Bitcoin` **UNIQUEMENT intra-report** (un chunk droppé dans un report tracké). ⚠️ **Un report ENTIER retenu n'est PAS détecté** (l'OTS est par-recording, pas un manifeste global) → **résiduel C1** (§7).
- **Disponibilité** = **redondance** (backup off-host **roadmap 1.8** / multi-relais), pas crypto.

**Hors périmètre (résiduels assumés, §6)** : corrélation **live**/Tor ; registre d'enrôlement (pk + compteurs, sans contenu) ; MinIO `last_modified` (timeline anonyme) ; ciphertext téléchargeable par qui tient un report_id ; **troncature d'un report entier** (C1).

**Invariant conservé** : contenu E2E (STRM scellé) — le relais ne déchiffre jamais rien.

---

## 2. État des lieux — TOUS les résidus pk au repos (exhaustif post-2-passes)

| Résidu pk-dérivé | Emplacement | Persisté | Disposition v3 |
|---|---|---|---|
| `owner = pk` (full) | `reports.py:210` → `reports.json` | disque | **Retiré** (§5) |
| `author = Author(id=pk[:32])` | `reports.py:201,209` ; sérialisé `:50` | disque | **Retiré explicitement** (§5) |
| `createdAt` | `reports.py:206` | disque | **Retiré** (création paresseuse §3.2) |
| `pk[:16]` enroll/rotate/verify/logout | `auth_v2.py:162,259-260,360-361,437-438` + `ratchet_registry.py` | logs disque | **Scrubbé** (§9) |
| **pk/IP via exception, `repr(obj)`, log positionnel** | pas de handler global (`main.py`), `uvicorn.error` non silencé, `exc_info` dumpé (`logging_setup.py:105-106`) | logs disque | **Scellé** (§9 : handler + lint) ⚠️ *raté par les 2 passes jusqu'ici* |
| **JWT `sub=pk` sans scope via V1** `auth_routes.py:70` | route montée `main.py` | non persisté | **Route retirée au cutover** (§10) |
| pk full = clé registre + `enrolled_at`/`updated_at`/`consumed_indices` **(+ compteur création §8)** | `_ratchet_registry.json` | disque | **Résiduel assumé §6** (anti-sybil, *nombre* pas carte) |
| ~~pk full = membre du set~~ `.authorized_keys.json` | — | — | **RETIRÉ le 2026-06-29** (index V1, devenu inutile au drop de `is_key_registered` ; la révocation vit dans le registre, `auth.py`). Cette ligne surestimait la surface pk au repos |
| JWT `sub=pk` (transient 1er PUT) | RAM/transit | non persisté | **Résiduel §6** ; durci §3.2 (jeté tôt, jamais loggé avec report_id) |
| MinIO `last_modified` | objet MinIO | disque | **Résiduel §6** (anonyme) |
| input pk malformé renvoyé en 422 | défaut FastAPI | transitoire | **Mineur** : handler 422 omettant `input` (§9) |

Le **ratchet ne lie rien aux reports** — il reste tel quel (sauf l'ajout d'un *compteur* de créations, §8, qui ne lie pas à un report précis).

---

## 3. Principe + protocole

Le relais stocke `report_id → report_pk` (une clé par report), jamais l'identité. Le ratchet garde la porte d'entrée (enrôlement + droit de créer). L'identité vue à la création est **jetée**.

### 3.1 Dérivation crypto (Rust core) — domain-tags 1 octet

Depuis le **même master seed BIP-39** que l'identité/provenance (contexte HKDF distinct) :

```
report_master = HKDF-SHA256(master_seed, info="stream.report.master.v1", L=32)
report_sk_n   = Ed25519_seed( HKDF-SHA256(report_master, info="stream.report.key.v1" || u32_be(n), L=32) )
report_pk_n   = Ed25519_public(report_sk_n)
report_id_n   = SHA-256("stream.report.id.v1" || report_pk_n)[..16]      # 128 bits → 32 hex
```

**Signatures = schéma domain-tag 1 octet existant** (`signature_domain.rs`) : nouveaux tags **`0x07 ReportCreate`**, **`0x08 ReportWrite`** (+ miroir `signature_domain.py` + Tamarin).
- `create_sig = Ed25519(report_sk, 0x07 || report_id || report_pk)`
- `write_sig  = Ed25519(report_sk, 0x08 || report_id || filename || sha256(body))`

`report_sk` = clé **dédiée** (jamais ratchet/identité/provenance) ⇒ pas de cross-protocole ; les tags = discipline maison.

**Index `n` (corrigé post-audit, anti-split-de-session)** : le client choisit `n` via un **compteur monotone persistant**, et persiste le mapping **`sessionId → n` atomiquement** (même garantie que l'idempotence Phase 1.15 `sessionId→reportId` actuelle). Un **retry** d'une session réutilise son `n` (jamais un 2ᵉ report). Au rescue (device neuf), le map n'existe pas — le client énumère par dérivation (§3.4).

### 3.2 Création (paresseuse, **VRAIMENT blob-d'abord**, gatée ratchet, identité jetée)

Pas d'endpoint `create_report`. Le report naît à la 1ʳᵉ écriture de chunk. **Ordre : store blob durable → PUIS record.** Plus de record provisional, plus de rollback, plus de zombie.

`PUT /file/{report_id}/{filename}` — headers : toujours `X-Report-PK` + `X-Report-Write-Sig` ; **seul le chunk de création** porte en plus `Authorization: Bearer <stream JWT>` + `X-Report-Create-Sig`.

Logique serveur :
1. Hash `sha256(body)` en streaming (`upload.py:74`). Vérifier `report_id == SHA-256("stream.report.id.v1"||report_pk)[..16]` (lie l'id au pk présenté).
2. **Branche selon l'existence du record** (lecture sous `_reports_lock`, rapide) :
   - **record existe** : vérifier `report_pk` présenté == stocké (sinon **409**), `write_sig` valide sous le pk stocké. → étape 3.
   - **record absent + headers de création présents** (JWT + create-sig) : vérifier (a) `create_sig` + `write_sig` valides sous `report_pk` ; (b) **JWT valide+enrôlé** ⇒ `sub` jeté immédiatement (jamais écrit ni loggé avec `report_id`) ; (c) **budget de création** non dépassé (§8). → étape 3 (le record n'est PAS encore écrit).
   - **record absent + pas de headers de création** (un chunk « suivant » arrivé avant son chunk de création — possible car l'enqueue WorkManager n'ordonne pas) : **425/409 « report pas encore créé, retry »** — **ne rien stocker**. WorkManager retente (le chunk de création finira par créer le record).
3. **Store le blob** (write-once, `storage.upload_blob_stream_write_once`). Échec (507/409) ⇒ retour d'erreur, **aucun record écrit**.
4. **Si c'était une création** (record absent en 2) : maintenant que le blob est **durable**, écrire le record sous `_reports_lock` en **create-or-verify** (si un autre worker l'a créé entre-temps, vérifier pk == stocké, idempotent ; sinon créer) + `_save_reports_locked`.

**Invariant garanti** : un record n'est écrit **qu'après** ≥1 blob durable ⇒ `record ⇒ ≥1 blob` **toujours vrai** ⇒ le rescue `404-sur-record-inconnu` (§3.4) est fiable, **sans** `sweep_empty_reports` ni `createdAt`. Un crash entre (3) et (4) laisse un **blob orphelin** (pas un record-zombie) — invisible au rescue (404, pas de record) et reapé par `blob_cleanup` (`last_modified`, §8). Race 2-workers : le store write-once est idempotent (mêmes octets), le create-or-verify (4) sous lock converge — **0 orphelin de record, 0 destruction concurrente.**

### 3.3 Autz upload — où vit `report_sk` (corrigé post-audit : **miroir du `provenanceSigner`**, PAS du JWT)

`report_sk` est **secret + seed-dérivé** (non re-dérivable sans PIN) ⇒ jamais dans le heap JVM (heap-0) **et** cycle de vie aligné sur un secret seed-dérivé qui survit au background recording :
- **Objet UniFFI tenu côté Kotlin** (`StreamUploadManager.reportKeyring`), rechargé au unlock par `pinSessionOpenReportKeyring`, qui ouvre le master scellé **en-crate** : ni le master ni la clé de session ne traversent la FFI. Cette puce décrivait un `static REPORT_SK_HOLDER` chargé par `pinStoreOpenWithKey` ; ni l'un ni l'autre n'existe, l'export ayant été retiré à la migration no-export R-CR-1.
- **Cycle de vie = celui du `provenanceSigner`** (`StreamUploadManager.kt:71` chargé `:269`, wipé **seulement à `lock()` `:294`**), **PAS** celui de `UPLOAD_JWT` (wipé au timer JWT défaut-0 = au background). Raison vérifiée : le JWT background-wipé est **re-dérivable** (`ensureFallbackReAuth`) ; `report_sk` **ne l'est PAS** ⇒ un wipe au background **casserait** la signature des chunks en capture écran-éteint (data-loss non-récupérable, régression Phase 1.14). Le `provenanceSigner` (même contrainte seed) est **field-prouvé** survivre au background recording.
- **Asymétrie documentée** : garder `report_sk` **strictement** jusqu'à `pending==0 && encryptionsInFlight==0` au drain post-stop (un wipe pendant le drain perd définitivement les chunks restants).
- `upload_put_report_chunk(...)` : lit `report_sk` du holder, **hashe le `.strm` dans Rust** (le hash **DOIT être byte-identique** au `hasher.update` serveur `upload.py:80` ; double-passe disque sur le fichier — 1 hash + 1 stream — négligeable < seuil, à documenter pour les PUT média 500 MB), signe `0x08||report_id||filename||sha256`, pose `X-Report-Write-Sig`. Aucun secret ne traverse le FFI. **TOCTOU** : si le holder est vidé entre le gate et l'usage, retourner un tag `no_report_sk` (retry), pas de panic.
- **1er PUT** : + `X-Report-PK` + `X-Report-Create-Sig` (calculés une fois/report) + bearer (holder `UPLOAD_JWT`).

### 3.4 Rescue (énumération + lecture, identité-free, anti-data-loss)

- **Lecture** : `GET …/reports/{report_id}/blobs` et `…/{filename}` — **identité-free**. `POST /api/v2/archive/auth` + `require_archive_auth` + scope archive supprimés.
- **Serveur 404 sur record inconnu** (pas sur prefix MinIO vide — sinon `list_blobs` renvoie `200+[]`). Record ⇒ ≥1 blob (invariant §3.2).
- **Énumération client EXACTE via le RÉPERTOIRE (réalisé tranche D, post-audit — remplace la devinette par tolérance de trous).** Le **répertoire** = un report **singleton dérivé de la phrase** (contexte HKDF dédié `stream.report.directory.v1`, distinct de l'indexé). **M-1 (audit 2026-06-26) : les noms de blobs sont des tokens OPAQUES** `directory_entry_name(n) = hex(HKDF(report_master, "stream.report.directory.entry.v1" ‖ u32_be(n))[..16])` — **PLUS l'index décimal `%010d`** (qui fingerprintait le répertoire en compteur de sessions et donnait `n_max`/cadence en clair). Dérivé du **secret `report_master`**, pas de `directory_pk`, **sinon le relais — qui voit `directory_pk` dans `X-Report-PK` — réénumérerait tous les `n`**. Le device append une entrée par session **à l'allocation d'index** (`DirectoryEntryWorker`, write-once ; `is_creation=(index==0)` crée le répertoire, les autres 425-retry ; **corps = 1 octet constant `0x01`** — M-1 : le corps part sur le fil mais ne porte **AUCUN index** (il était autrefois 4 o BE de l'index, ce qui re-fuyait count/cadence ; le rescue ne lit jamais le corps, seul le NOM opaque compte)). Au rescue (phrase seule) :
  1. **Distinguer 404 (record absent) de l'échec réseau/5xx** (corrigé tranche 3.4a : `archive_list_blobs→Option`, None=404). Réseau = retry (×3 puis abort), JAMAIS « fin ».
  2. **`n_max` autoritaire par DÉRIVE-ET-MATCH** : le rescue re-dérive `directory_entry_name(0..)` et matche chaque nom retourné à son index (termine dès que toutes les entrées opaques sont retrouvées — **exact, tolère les trous** ; garde-fou `DERIVE_MATCH_CAP` contre un nom-poubelle d'un relais hostile). **Dual-read** : les entrées legacy `%010d` (écrites avant M-1) sont aussi parsées en `u32` ⇒ un répertoire écrit à cheval sur une MAJ reste entièrement récupérable (schémas disjoints : un nom 32-hex ne parse jamais en `u32`). ⇒ énumérer les reports `0..n_max` **DENSE** (sonder CHAQUE index ; un 404 = trou sauté, **jamais un arrêt anticipé**) ⇒ **plus de constante K**, plus de troncature trous-milieu, plus de cap arbitraire.
  3. **Fallback** (répertoire absent en 404 — atteignable seulement si l'entrée index-0 n'a jamais uploadé ⇒ ~0 report) : sonde dense bornée `0..FALLBACK_CAP=512`, **toujours sans troncature-milieu** dans sa plage.
- ⚠️ **Résiduel C1 (réduit)** : un relais hostile qui **404 les DERNIÈRES entrées du répertoire** sous-estime `n_max` ⇒ tronque la **queue** (les reports les plus récents) sans détection. C'est le C1 inhérent « relais pas coffre » (un relais peut toujours retenir la donnée la plus récente, l'entrée répertoire **comme** ses chunks) — **non détectable avec un relais unique** (un chaînage ne sert à rien : la queue chaînée est droppée avec). Le cas **trous-milieu bénin** (sans adversaire), lui, est **fermé**. Défense réelle = multi-relais / backup off-host (§7).
- ⚠️ **Non-claim M-1 (liaison inter-sessions AU REPOS, réduite ≠ supprimée)** : le répertoire agrège **toutes** les entrées de sessions d'un témoin sous **un** `report_id`. Les noms opaques (M-1) suppriment le fingerprint trivial (le compteur `%010d` lisible) et rendent l'index **illisible depuis le nom** — un opérateur ne lit plus `n_max`/cadence d'un coup d'œil. Mais une saisie relais **n'expose toujours aucune identité ni contenu** (E2E, pas de pk au repos) ; ce qui subsiste, pour un opérateur qui aurait **identifié** le report-répertoire par corrélation temporelle, c'est le **nombre d'entrées** (= nb de sessions) et leur **cadence** (`last_modified`). C'est **inhérent** à l'existence d'un répertoire (le prix de l'énumération exacte au rescue). Coarsening `last_modified` = piste optionnelle non retenue (coût/bénéfice). Le motto strict (« une saisie n'expose rien » = pas d'identité, pas de témoignage) **tient**.
- Protections data-loss du rescue actuel (FGS + WifiLock + retry/chunk, secrets RAM) **conservées** ; seul le bearer disparaît.

---

## 4. Endpoints — avant / après (v3)

| Endpoint | Avant | Après v3 |
|---|---|---|
| `POST /project/{id}` (create_report) | crée `{owner,createdAt,author}` | **supprimé** (création paresseuse §3.2) |
| `PUT /file/{rid}/{name}` **création** | JWT + `owner==pk` | JWT(ratchet)+`X-Report-PK`+create-sig+write-sig ; **blob-d'abord** ; sub jeté ; budget §8 |
| `PUT /file/{rid}/{name}` **suivants** | JWT + `owner==pk` | `X-Report-Write-Sig` seul (pk stocké) ; **425/409 retry si record absent** |
| ~~`HEAD /file/{rid}/{name}`~~ | — | **ROUTE SUPPRIMÉE** (2026-06-29) : code mort, et un oracle d'existence gratuit. Le retrait est enregistré comme résolu dans `ACCEPTED_RESIDUALS` |
| `POST /file/{rid}/{name}` (finalize) | stub sous `_require_report_owner` | **supprimé** (les **4 usages** de `_require_report_owner` dans `upload.py:22,36,51,118` retirés, sinon KeyError `report["owner"]`) |
| `POST /api/v2/archive/auth` | sig identité → JWT archive | **supprimé** (+ `ArchiveAuthRequest/Response`, `create_archive_jwt`, `require_archive_auth`, **domaine 0x04** [→ purge Tamarin + 4 sites verify serveur], FFI `signArchiveChallenge`, `ArchiveSession.authenticate/reauthenticate`, CLI `fetch_archive` auth) |
| `GET /api/v2/archive/reports` | `list_user_reports(pk)` | **supprimé** (client énumère §3.4) |
| `GET …/reports/{rid}/blobs` ; `…/{name}` | JWT archive + `owner==pk` | **identité-free** + **404-record-inconnu** + **rate-limit IP §8** |
| `_validate_path(report_id)` (`upload.py:16`, `archive.py:97`) | `^[a-zA-Z0-9_-]+$` | **`^[a-f0-9]{32}$` strict** |
| `/auth/verify`, `/auth/invite/verify` (**V1**) | JWT `sub=pk` **sans scope** | **route retirée au cutover** (§10) — chemin de création non-ratchet, contredit décision #3 |
| `/auth/v2/enroll`,`/verify`,`/rotate-batch` | ratchet | **inchangés** (contrainte 4) |

---

## 5. Retiré / gardé

**Retiré** : `owner`, `author`, `createdAt`, `create_report`, `sweep_empty_reports`, `list_user_reports`, `POST /api/v2/archive/auth` (+ artefacts §4), `POST /file` finalize, le filtre owner (3 routes archive + 4 sites upload), **le pk de tous les logs** (§9), **les chemins V1** `/auth/verify` et `/auth/invite/verify` (au cutover). Attention à la formulation : c'est bien le **chemin** V1 qui est parti, pas le module. `auth_routes.py` reste monté dans `main.py`, parce qu'il porte `POST /auth/challenge`, que le flux V2 utilise : un nonce est un nonce, ce n'est pas un reliquat V1.

**Gardé intouché** : ratchet complet, STRM E2E, write-once, transport Rust upload (signature étendue §3.3), OTS provenance lean (détection **intra-report** §7), le JWT stream (gate de création seulement).

---

## 6. Résiduels assumés (honnête)

1. **Transient création** : 1er PUT porte le JWT (`sub=pk`) ⇒ serveur voit `pk` à T. Au repos, rien (record = `report_pk` ; sub jeté §3.2 ; jamais de log pk+report_id, §9). Axe live/Tor.
2. **Registre d'enrôlement** : `pk` + `enrolled_at`/`updated_at`/`consumed_indices` **+ compteur de créations §8** (anti-sybil + anti-abus). Existence + activité **grossière** (des *nombres*), **jamais quel report**. Option future : grossir `updated_at`.
3. **MinIO `last_modified`** : timeline d'upload **anonyme**.
4. **Lectures id-free** : qui obtient un `report_id` télécharge le ciphertext (inutile sans la phrase). DoS borné par rate-limit (§8).
5. **Blob orphelin** (crash entre store et record §3.2) : ciphertext sans record, invisible au rescue, reapé par `blob_cleanup` (`last_modified` 6 mois ; sweep court optionnel).
6. **Troncature d'un report entier (C1)** : un relais hostile retient un report complet ⇒ **non détecté** (voir §7).

**Non fermé, non prétendu** : corrélation réseau live, analyse de trafic, device saisi déverrouillé, **disponibilité** (un relais peut dropper — §7).

---

## 7. Complétude & anti-troncature (3 propriétés)

**Prévention** — impossible avec relais unique non-fiable. Postulat du motto. **Hors périmètre, inhérent.** La write-sig par chunk = intégrité d'un chunk présent, **pas** la complétude (couche autorisation ≠ couche complétude).

**Détection — partielle, via la provenance lean conservée.** `SHA-256(sel ‖ chunk_merkle_root(tous les hashes)) → OTS → Bitcoin` engage l'ensemble des chunks d'**un recording**. Au rescue : un chunk droppé **dans un report tracké** ⇒ racine recalculée ≠ ancre BTC ⇒ `verify-provenance` échoue ⇒ **troncature intra-report détectée**. **Limites** : exige l'OTS actif/ancré (dormant ⇒ déploiement = GO) ; async ; détecte ≠ récupère.
⚠️ **NE COUVRE PAS un report ENTIER retenu** : l'OTS est **par-recording**, il n'existe **aucun manifeste global** des reports d'un témoin, et le device de rescue n'a **aucun `n_max` indépendant** (`list_user_reports` supprimé) ⇒ un relais qui 404 un bloc terminal de report_ids **tronque la queue silencieusement** (caché dans le bruit légitime des `n` jamais-uploadés). **= résiduel C1, assumé (décision therealshulgin).**

**Disponibilité — redondance, pas crypto.** Seul vrai anti-perte. ⚠️ chunks **secure-deleted après `204`** ⇒ si le relais ment, copie locale perdue. Réponses : **backup off-host (roadmap 1.8)** + **multi-relais** (= la seule vraie défense contre C1 ET la perte). **Orthogonal au chantier.**

**▶ RÉALISÉ (tranche D, post-audit) = le RÉPERTOIRE (§3.4).** Le « manifeste-sentinelle scellant `n_max` » est implémenté comme un **report-répertoire append-only** (un blob/index, write-once ⇒ la tension *mutable vs write-once* est levée — on n'écrase jamais ; `n_max` recouvré par **derive-and-match** sur les noms opaques, M-1, pas par max des noms). Il **ferme la troncature trous-milieu bénigne** (énumération dense exacte `0..n_max`, sans adversaire). Le **C1 hostile** (relais qui drop les dernières entrées ⇒ `n_max` sous-estimé) **reste inhérent** : impossible à *prévenir* OU *détecter* avec un relais unique (la queue chaînée serait droppée avec) ⇒ défense réelle = **multi-relais / backup off-host**. Décision : le chaînage n'a PAS été ajouté (il ne détecterait que les drops-milieu, or l'énumération dense les rend inoffensifs).

**Reçus signés du relais** (accountability upload-time) = **noté futur, hors périmètre** (§13).

---

## 8. Anti-abus & GC (arbitrage Q1 + D1)

**Pas de slot ratchet par report** (couplerait la création à une opération réseau ⇒ casse heap-0/streaming, épuise le batch). Création gatée par **JWT stream** (borné par le ratchet).

**Anti-abus de stockage (D1, décision therealshulgin)** : un budget par-IP est contournable (rotation Tor/botnet) et l'identité jetée supprime le quota durable. ⇒ **compteur souple de créations dans le registre**, par identité enrôlée / par `batch_number` (« N reports créés sur ce batch ») — **un *nombre*, pas une carte report↔identité** ⇒ même classe de résidu que les compteurs ratchet existants (§6.2), n'introduit **pas** de jointure. Rejet au-delà du seuil. (+ rate-limit IP en défense de surface sur création + les 2 GET archive + **HEAD**.)

**GC de rétention** : `sweep_empty_reports` n'a plus lieu d'être (plus de 0-blob). La rétention (TTL 6 mois) bascule sur **`last_modified`** — `blob_cleanup.py` purge **déjà** par `last_modified` (≈ équivalent à `createdAt` : création et 1er upload à quelques secondes ⇒ **pas de régression**). `report_cleanup.py` recâblé sur `last_modified` du plus vieux blob.

---

## 9. Logs (scrubbing pk total + canal exception scellé)

Le formatter (`logging_setup.py`) blocklist les IP (champs `extra` **nommés**) mais **pas le pk dans le `msg`**, ni un `repr(obj)`/traceback. Logs → stderr → Docker json-file → disque.
- **Retirer le pk de tous les `logger.*`** : `auth_v2.py:162,259-260,360-361,437-438` ; `ratchet_registry.py` (enroll/rotate/revoke). Événement **sans identifiant** (compteur, ou id éphémère par-process random non-lié au registre).
- **Sceller le canal exception (A-1, raté par les 2 passes)** : (a) **exception-handler global** (`main.py` n'en a aucun hors rate-limit) loggant **sans identifiant** + désactivant `exc_info` côté json-file ; (b) **silencer/scrubber `uvicorn.error`** (aujourd'hui non silencé, `logging_setup.py:134-136` ne tue que `uvicorn.access`) ; (c) **lint/pre-commit** bannissant `request`, `request.client/headers/url`, et tout `%r`/`repr(` d'objet pydantic/record dans les args `logger.*`. ⚠️ **votre `docs/METADATA_EXPOSURE_MAP.md` P1-3 le signalait déjà.**
- **Handler 422** omettant/tronquant `input` sur les routes portant un pk (mineur).
- **Cutover** : purger les logs conteneur existants (§10).
- (Vérifié OK : nginx `access_log off` ; MinIO sans tag pk ; JWT blacklist = hash du token.)

---

## 10. Cutover (clean break — destructif, PROD, GO requis)

1. **Relais (SSH ; auto-guard ⇒ GO explicite + un-guard)** : wipe `reports.json`, `.authorized_keys.json`, `_ratchet_registry.json`, `.nonce_cache.json`, bucket MinIO, **logs conteneur**. **Retirer les chemins V1** (`/auth/verify`, `/auth/invite/verify` ; `auth_routes.py` reste monté pour `/auth/challenge`). État vierge.
2. **Devices (gestes therealshulgin)** : re-enroll Seeker + OnePlus.
3. **Scripts ops** à maj (présument `owner`/`createdAt`) : `deploy/audit-reports-vs-blobs.sh`, `deploy/backup-state.sh`.
4. Pré-publication, zéro vrai utilisateur ⇒ acceptable.

---

## 11. Tranches (re-scopées post-2-passes ; serveur écrit SANS déployer)

| # | Tranche | Fichiers | Gate |
|---|---|---|---|
| 1 | **Dérivation Rust** : report_master/key/id + **tags 0x07/0x08** (`signature_domain.{rs,py}` + Tamarin) + FFI `deriveReportId(n)`/`signReportCreate`/`signReportWrite` | `crypto-rs/core`, `ffi` | cargo test + clippy -D + régén `.so` + Tamarin (+ purge 0x04) |
| 2 | **Serveur** : PUT **blob-d'abord** create-or-verify + write-sig + 425-retry, drop owner/author/createdAt/create_report/sweep/finalize, archive id-free + 404-record-inconnu, **rate-limit + compteur création registre**, retrait archive-auth+0x04, **scrub logs + exception-handler + lint**, GC last_modified, `_validate_path` strict, **retrait V1** | `routes/{upload,reports,archive,auth_v2,auth_routes}.py`, `auth.py`, `models.py`, `logging_setup.py`, `main.py`, `*_cleanup.py`, `ratchet_registry.py` | pytest (réécrire autz) |
| 3 | **Client Kotlin + transport Rust** (la + lourde) : **holder Rust `report_sk` (miroir `provenanceSigner`)** + `upload_put_chunk` étendu (hash in-Rust byte-identique + TOCTOU) ; **index `n` persistant atomique (idempotence Phase 1.15)** ; création (1er PUT signé) ; **réécriture rescue** (énumération dérivée + tolérance K=32 + cap absolu + 404-distinct ; retrait 4 FFI bearer + `ArchiveSession` + reauth) | `StreamUploadManager`, `StreamRecordingService`, `ArchiveDownloader`, `ArchiveSession`, `crypto-rs/{ffi,stream}` | assembleDebug + compile |
| 4 | **Cutover** : wipe relais (GO) + purge logs + retrait V1 + re-enroll + maj scripts ops | runbook | — |
| 5 | **Field-test** : enroll→record (**dont background/écran-éteint**)→rescue ; **inspecter `reports.json`=0 identité ET logs=0 pk** | — | logcat + dump disque relais |

Estimé **~6–8 j** (slice 3 = le gros).

---

## 12. Audit adverse — findings → disposition (traçabilité)

**Passe 1 (v1) :**

| Finding | Sévérité | Disposition |
|---|---|---|
| C-1 pk dans les logs | MAJEUR | §9 scrub |
| C-2 `author=pk[:32]` | MAJEUR | §2/§5 retiré |
| C-3/F7 anti-abus + rate-limit | MAJEUR | §8 |
| F2 heap-0 `report_sk` | MAJEUR | §3.3 holder Rust |
| F4 race record-fantôme | MAJEUR | §3.2 blob-d'abord |
| F5 énumération 1er-404 | MAJEUR | §3.4 |
| F1 anti-troncature | MAJEUR | §7 |
| C-4/F6 domain-sep | MINEUR | §3.1 tags 0x07/0x08 |
| F8 `_validate_path` | MINEUR | §4 strict |
| C-6 1er PUT create+write-sig | INFO | §3.2 |

**Passe 2 (v2) :**

| Finding | Sévérité | Disposition v3 |
|---|---|---|
| **V2-A1 / D-1** §3.2 contradiction « blob-avant-record » + zombie + race (vérifié, 2 agents) | MAJEUR | §3.2 **réécrit vraiment blob-d'abord** + 425-retry → 0 zombie/0 race |
| **V2-B1** holder `report_sk` mauvais miroir → casse background (vérifié) | MAJEUR | §3.3 **miroir `provenanceSigner`** + asymétrie documentée |
| **A-1** scrub logs incomplet (exception/`repr`/IP) (vérifié) | MAJEUR | §9 handler + lint + uvicorn.error |
| **V2-C1** troncature d'un report entier non détectée (vérifié) | MAJEUR | §7 résiduel assumé + multi-relais ; mécanisme = **suivi séparé** |
| **V2-D1** anti-abus stockage (identité jetée) | MAJEUR | §8 **compteur création registre** |
| **V2-B2** index `n` non spécifié → split session | MOYEN | §3.1 `n` persistant atomique (idempotence 1.15) |
| **A-2** V1 `auth_routes.py` JWT non-ratchet (vérifié) | MOYEN | §10 **retiré au cutover** |
| **V2-A2** blob orphelin | MOYEN | §6 résiduel (blob_cleanup ; sweep court optionnel) |
| **V2-C2** auto-DoS énumération K=32 | MOYEN | §3.4 cap absolu + no-reset sur garbage |
| **V2-B1-bis** double-passe hash `.strm` + byte-identique | MINEUR | §3.3 documenté |
| **V2-E1** HEAD oracle de taille | MINEUR | §4/§8 rate-limit HEAD |
| **V2-F1** purge 0x04 → Tamarin + 4 sites | INFO | §4/§11 slice 1 |
| **E-1** 422 echo input | MINEUR | §9 handler 422 |
| **Confirmé solide** (2 passes) | — | ratchet intouché, tags 0x07/0x08 libres, author seul champ pk, F4/F5/F8 ciblés, GC sans régression, heap-0 dérivation OK |

---

## 13. Questions résiduelles

1. **Mécanisme de détection troncature-queue** (§7, C1) : **RÉSOLU pour le cas bénin** par le **répertoire** (tranche D, §3.4) — le manifeste-sentinelle est réalisé en append-only (`n_max` autoritaire ⇒ énumération exacte). Le C1 *hostile* (drop de la queue) reste inhérent au relais unique (multi-relais = la vraie défense).
2. **Reçus signés** (§7) : noté futur.
3. **Détection via OTS** : renforce l'intérêt de déployer l'OTS du relais (provenance **+** détection intra-report) → planifier en parallèle ?
