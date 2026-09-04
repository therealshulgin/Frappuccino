# Frappuccino — Forensic Validation **Report** (résultats exécutés, §10.6)

**Compagnon de résultats de [`FORENSIC_VALIDATION_PLAN.md`](FORENSIC_VALIDATION_PLAN.md).**
Worktree `xenodochial-morse` · HEAD `76cfb6b` · **2026-06-14**
Registre : transparence. Là où ce rapport et le code/les dumps divergent, **le code et les dumps l'emportent** — signalez l'écart.

> **Le plan** posait 9 surfaces de fuite avec, pour chacune, une *signature de fuite falsifiable*. **Ce rapport** dit, surface par surface, ce que la campagne on-device a réellement trouvé, et **corrige les affirmations du plan devenues périmées** depuis sa rédaction (31-05). Device : **Seeker SM02E406037868** (MediaTek/Mali, **non-rooté**, build app debuggable). Méthode = lecture de code (file:line) + procédures runnable on-device (heap dumps `am dumpheap`, tombstones, walk FS, `dumpsys meminfo`/`SurfaceFlinger`).

---

## 0. Verdict en une page

- **La garantie centrale tient.** Contre l'adversaire que le modèle vise — **saisie, coercition, destruction** — il n'y a, sur un device saisi/verrouillé/éteint, **rien de lisible** et **aucun moyen de détruire le passé** : le témoignage est déjà parti, chiffré, sur le relais aveugle, recouvrable par la **seule** phrase BIP-39. Validé en lecture de code **et** on-device (at-rest propre, DBs opaques, panicWipe).
- **Le cœur crypto Rust est sain** (Zeroizing/mlock/secure_delete/AEAD/ratchet) — confirmé par la suite de preuves ①→⑤ (zeroize-audit, diff-fuzz, Kani, TLA+, Tamarin) et non re-litigé ici.
- **La marge exploitable que le plan pointait (glu Kotlin↔UniFFI + surfaces media) est fermée**, sauf des **résidus RAM in-window** et un **résidu gralloc/VRAM firmware**, tous deux **calibrés hors de la garantie centrale** (§1, renvoi `ARCHITECTURE §2.4`).
- **Un finding a été trouvé et traité** : le **JWT d'upload survivait en heap JVM** (§3). Fermé au pire-cas par le write-once serveur (déployé), réduit côté client, résidu accepté ; le chemin heap-0 (Niveau 2) est différé post-audit (ROADMAP §10.7).

**Statut : AUDIT-CANDIDATE.** Pas un quitus : un rapport falsifiable + un inventaire honnête des résidus assumés.

---

## 1. Cadre — deux adversaires, deux portées

Toute faiblesse doit être jugée contre **la bonne** classe d'adversaire (détail : `ARCHITECTURE_TECHNIQUE_COMPLETE.md` §2.4) :

1. **Saisie / coercition / destruction** d'un device verrouillé/éteint/saisi — *la cible du modèle*. Garantie par construction (données déjà en ligne sur le relais aveugle + recouvrement seed-only).
2. **Lecture de la RAM d'un device vivant ET déverrouillé**, fenêtre étroite (TTL token / session active) — adversaire **distinct et de moindre portée**. C'est là, et seulement là, que vivent le finding §10.6 (§3) et les résidus ratchet device-dépendants (R-C-2/R-D-1/2).

Une lecture RAM dans la fenêtre **ne casse pas le modèle** : le témoignage est hors d'atteinte (sur le relais), un JWT lu est neutralisé serveur, la forward secrecy tient. ⇒ ces fuites sont du **durcissement / défense-en-profondeur**, pas des défauts qui rendraient la confiscation/destruction capables d'empêcher le témoignage.

---

## 2. Résultats par surface

| # | Surface | Statut plan (31-05) | **Verdict rapport (14-06)** | Évidence |
|---|---------|---------------------|------------------------------|----------|
| 1 | JVM heap (mnémo / JWT / ratchetDerivedKey) | PROVEN-GAP HIGH | **Résolu / calibré** : mnémo wipé post-enroll ; `ratchetDerivedKey` bare `fill(0)`→`SecureWipe.wipe()` **corrigé** ; **JWT = le finding §3** (worst-case fermé, résidu accepté) | Phase B/C heap dumps ; §3 |
| 2 | Rust/native heap + UniFFI | PROVEN-GAP HIGH | **Résolu** : legacy `strm_decrypt`→JVM = **0 appelant** ; `strm_decrypt_to_file` garde le plaintext Rust-only ; `mlock` effectif | Phase C ; revue callers |
| 3 | Timber / logcat (release) | PROVEN-OK LOW | **OK** : tree release = `MetricsFileLogger` tag-filtré ; aucun mnémo/JWT loggé | Phase A logcat |
| 4 | Tombstones / crash natif | PROVEN-GAP HIGH | **Validé on-device (B5)** : 3 SIGSEGV (idle / archive-actif / mnémo-affiché) = **0 plaintext, 0 JWT, 0/12 mots**. Tombstone ≠ heap dump ; `panic="unwind"` drope les `Zeroizing` ; résidu #7 borné | `B5_FINDINGS.md` + 3 tombstones |
| 5 | FS temp & scratch | PROVEN-GAP HIGH | **OK / résidu accepté** : scratch vide post-stop, **0 `.mp4`**, `debug_raw` gaté `BuildConfig.DEBUG` (§8.2.8) ; metadata JSON String = accepté #6 | Phase A + B9 walk |
| 6 | panicWipe + post-reboot | PROVEN-GAP HIGH | **Corrigé** : `ChunkUploadQueue.clear()` câblé au panicWipe (`19672ed`) ; handler low-storage ajouté | Plan #4 (adressé 03-06) |
| 7 | WorkManager DB + EncSharedPrefs | ASSERTED LOW | **Validé on-device** : `workdb` = 0 JWT/clé ; `stream_identity_v2.xml` = Tink opaque ; ratchet blob PIN-wrappé | Phase A DBs |
| 8 | MediaStore Downloads + thumbnails | PROVEN-GAP HIGH | **Requalifié LOW / accepté** : export **délibéré** par l'utilisateur (mode archive) ; `resolver.delete(uri)` purge l'entrée + sa miniature ; résidu = caches galerie tierces (hors contrôle) | Requalif. 03-06 ; §10 known-limit |
| 9 | MediaCodec / gralloc / VRAM | PROVEN-GAP HIGH | **App-side OK / résidu firmware accepté (B9)** : buffer codec **zéro-ié** + teardown EGL `glClear` noir+`glFinish` (gaps du plan **déjà corrigés**) ; libération surface encodeur au stop ; disque propre. Reste = zéro-isation gralloc/VRAM pilote (non-fixable app) | `B9_FINDINGS.md` |

**Bilan vs plan** : des **6 PROVEN-GAP HIGH** du plan — **#1, #2, #4, #6** résolus/validés ; **#5** OK + résidu accepté ; **#9** app-side corrigé, reste un résidu **firmware** accepté. **#8** requalifié LOW (plaintext **intentionnel**). **#7** passe d'ASSERTED à **validé on-device**. La couche glu Kotlin↔UniFFI, point faible désigné par le plan, est **assainie**.

---

## 3. Le finding — JWT d'upload résiduel en heap JVM

**Quoi.** Le bearer JWT d'**upload** (HS256, `sub`=pubkey d'identité, TTL 24 h) reste **joignable dans le heap JVM** après device-lock **et** après panic-wipe (dumps `am dumpheap`, marqueur `Bearer eyJ` persistant). Le mnémonique, l'état ratchet et l'identité-disque, eux, sont bien wipés.

**Pourquoi (archi).** Le client Rust fait l'**auth** (challenge→verify), mais les **PUT de chunks sont du Kotlin/OkHttp** ; le JWT reliait les deux via un holder global, et la couche HTTP/2 d'OkHttp (table HPACK + `Headers` par-requête sur la connexion poolée) en retient des copies que le code applicatif ne peut pas purger.

**Portée réelle (calibrée §1).** In-window, device vivant déverrouillé. Le scope est segregé (R-H2 ⇒ 403 sur l'archive : ni lecture ni déchiffrement) et **aucune route de delete** n'existe. Le seul abus résiduel d'un JWT volé = ré-écrire des chunks — **fermé** ci-dessous. **Confidentialité des rushes : intacte.**

**Fix livré.**
- **combo-1 — serveur write-once (`ab314a6`, DÉPLOYÉ).** Le relais refuse d'écraser un objet existant par un **contenu différent** (compare SHA-256 par read-back ; identique = no-op idempotent ; différent → **409**). **Ferme le pire-cas** : un JWT volé ne peut ni lire (403 scope), ni supprimer (pas de route), ni corrompre/détruire un chunk authentique. **C'est le fix qui compte.**
- **combo-2 — JWT en Rust, Niveau 1 + `evictAll()` (`eecd24b`).** Le JWT vit en `Zeroizing` côté Rust, en-tête transitoire par-PUT, zeroize + éviction des connexions au lock/panic. Retire les détenteurs applicatifs persistants ; **heap post-wipe 35 → 14** (mesuré on-device).
- **Limite prouvée (14-06).** Le Niveau 1 **ne peut pas** atteindre heap-0 : dès que le `Bearer` passe en String à OkHttp, HTTP/2 en garde des copies (14, **stables** sur 2 dumps). **Résidu accepté** — inoffensif vu combo-1, et calibré §1 (n'expose pas les rushes).
- **Niveau 2 (heap-0) — différé post-audit (ROADMAP §10.7).** Faire le **PUT en Rust** (reqwest) → le token n'entre jamais dans la pile HTTP JVM. Effort élevé (réimplémenter la logique anti-data-loss durcie), **non urgent** (combo-1 protège déjà).

---

## 4. Corrections au plan (claims devenus périmés)

Le plan (HEAD `d84ee2b`, 31-05) précède plusieurs fixes. À lire avec ces rectificatifs (le code fait foi) :

- **Surface 9 / résidu #3 — « MediaCodec ByteBuffer jamais wipé ; EGL teardown sans glFinish/black-clear ».** **Périmé.** Le buffer de sortie codec est zéro-ié `SecureWipe.wipe(outBuf)` avant `releaseOutputBuffer` ([HevcMediaCodecEncoder.kt:355](../stream-crypto/src/main/java/org/stream/crypto/capture/HevcMediaCodecEncoder.kt:355), la surcharge `ByteBuffer` **existe**) ; le teardown EGL fait `glClear` noir preview+backbuffer **puis `glFinish()`** avant `eglDestroySurface/Context` ([GlVideoPipeline.kt:261](../stream-crypto/src/main/java/org/stream/crypto/capture/GlVideoPipeline.kt:261)). Reste uniquement le résidu **firmware** (gralloc/VRAM).
- **Surface 6 / résidu #4 — « panicWipe ne purge pas `stream_chunk_queue/*.strm` ».** **Adressé** (`19672ed`) : `ChunkUploadQueue.clear()` est câblé au panicWipe. (Ces blobs sont du **ciphertext** ; leur survie ne brisait pas la confidentialité.)
- **Surface 4 / résidu #7 — « pas de signal handler ; JWT char[] capturé verbatim au tombstone ».** **Testé (B5)** : `panic="unwind"` fait dropper les `Zeroizing` avant le tombstone ; empiriquement **aucun JWT** dans 3 tombstones (et le JWT est désormais Rust-held, combo-2). Le résidu réel — un **vrai** SIGSEGV mémoire-unsafe *dans* le decrypt — est borné à un fragment proximal-registre (≤~256 o), jamais le buffer ; cœur Rust zéro-`unsafe`.
- **Surface 1 / résidu #1 — bare `fill(0)`.** Corrigé → `SecureWipe.wipe()`.
- **Surface 8 — « never purges thumbnails ».** Requalifié : `resolver.delete(uri)` purge l'entrée MediaStore et sa miniature ; l'export est **intentionnel** (mode archive).

---

## 5. Limites de méthode (honnêtes)

- **Device non-rooté.** Pas de `/proc/<pid>/mem` ni `/sys/kernel/debug/ion`. Cohérent avec un adversaire **sans exploit root** ; un adversaire root-avec-exploit relève des risques acceptés R-D/R-C (ARCHITECTURE §10.1-10.2). La caractérisation VRAM profonde a été **écartée délibérément** (ROI faible — gaps app déjà fermés — + probable inconclusivité sur Mali + destruction du baseline non-rooté).
- **B5 timing.** La fenêtre de decrypt (ms) n'a pas été attrapée *in flagrante* ; la propreté du tombstone est **structurelle** (tombstone ≠ heap dump), pas seulement empirique — un crash parfaitement timé rendrait 0 pour la même raison.
- **Résidus RAM in-window** (JWT 14 copies, ratchet courant) : **assumés et calibrés** (§1), non éliminés. Le Niveau 2 (heap-0) est la voie, différée.
- Les **preuves formelles** du cœur (①→⑤) ne sont pas re-jouées ici ; voir leurs runners/docs dédiés.

---

## 6. Reproduire

Procédures détaillées = [`FORENSIC_VALIDATION_PLAN.md`](FORENSIC_VALIDATION_PLAN.md) §3. Évidence brute de cette campagne dans `frappuccino-pointB-logs/` (hors repo) :
`B5_FINDINGS.md` + `B5_tombstone_0{1,2,3}_*` (.txt/.pb) ; `B9_FINDINGS.md`. Crash sans root = `adb shell run-as <pkg> kill -11 <pid>` ; tombstones world-readable sous `//data/tombstones/`. Heap = `am dumpheap <pid> //data/local/tmp/h.hprof`, marqueurs `Bearer eyJ` / `ftypisom`.

*Rapport de validation forensique — §10.6 — 14 juin 2026.*
