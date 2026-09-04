# Lot 4b — no-export R-CR-1 (PIN-session holder + combined Rust calls)

> **Statut : ✅ LIVRÉ (2026-06-27).** P1 `5a5f2ab` + P2 `e18c7f6` (absorbe P3+P4) + P5 vérifié 0-code
> + P6 `6982f87`. OPTION B, scope complet. **R-CR-1 entièrement clos** (no-export + exports nus
> supprimés). **Field-validé OnePlus** (unlock/auth/reseal/33 min-396 chunks/lock/re-unlock, 0 erreur).
> Source : audit adverse 2026-06-26 (R-CR-1) + workflow de planification 9 agents + arbitrage Opus.
> NB exécution : le design getter du workflow a été corrigé (la clé re-traversait) → combined-calls
> in-crate ; P2 a absorbé P3+P4 (call-sites partagés) ; P5 = 0 code (clear hérite de `lock()` drain-safe).

## 1. Objectif

Fermer **réellement** R-CR-1 (low, enveloppe R-D-1 acceptée) : les retours FFI de secrets
matérialisent une copie heap JVM non-Zeroizing. Lot 4 a déjà fermé la 6ᵉ surface par
suppression (B-CR-4, `decrypt_session_key`). Lot 4b ferme les surfaces **vivantes** restantes
en gardant le secret côté Rust derrière un handle / un holder process-global, et en combinant
`derive+seal` et `open+deserialize` en **un seul appel Rust** — de sorte que **seuls des
ciphertexts (non-secrets) traversent la frontière**.

Surfaces visées (toutes dans `crypto-rs/ffi/src/lib.rs`) :
- `pin_store_open_extended` → `derived_key` (clé maîtresse Argon2id) + `salt` + `plaintext` (blob ratchet, 50 sk)
- `pin_store_seal_with_key` / `pin_store_open_with_key` (reseal/reload rapides)
- `EphemeralRatchet.serialize` (blob 4876 o, 50 sk)
- `ReportKeyring.master_bytes` (report_master 32 o)
- `ProvenanceSigner.seed_bytes` (provenance seed 32 o)

## 2. Principe : pourquoi « getter » = faux, « combined call » = vrai

Le premier jet de design proposait des getters `pin_session_derive_key()` / `pin_session_salt()`
rappelés par Kotlin à chaque reseal puis passés à `pin_store_seal_with_key(...)`. **La revue
residue-closure l'a réfuté** : sous le lowering `RustBuffer` d'UniFFI, chaque appel d'un getter
**re-matérialise une copie de la clé sur le tas JVM** — exactement le résidu qu'on veut éliminer.
« Held in Rust » ≠ « never crosses the FFI ».

**Forme correcte = sceller / désceller À L'INTÉRIEUR de Rust.** Aucun getter de secret. Le secret
ne quitte jamais le crate ; l'entrée et la sortie de chaque appel sont des **ciphertexts** ou des
**handles opaques**. Effet de bord favorable : **moins** d'appels FFI qu'aujourd'hui (le reseal
passe de `serialize()` + `seal_with_key()` + 2 traversées de plaintext à **un** appel rendant le
blob scellé) ⇒ pas de régression perf (l'inquiétude de la revue tombe d'elle-même).

## 3. Le holder Rust `PIN_SESSION_HOLDER`

Calque **exact** du holder de bearer d'upload déjà en place (`upload_jwt_guard`, pattern
`UploadAuthHolder` migré dans Rust en §10.6). Adjacent dans `crypto-rs/ffi/src/lib.rs`.

```rust
// Cache (derived_key, salt) Argon2id pour la session déverrouillée — fast-reseal.
// Miroir du holder de bearer d'upload (UPLOAD_JWT / upload_jwt_guard).
static PIN_SESSION_HOLDER: std::sync::Mutex<Option<PinSessionState>> =
    std::sync::Mutex::new(None);

struct PinSessionState {
    derived_key: zeroize::Zeroizing<[u8; 32]>, // wipe-on-drop
    salt: [u8; 16],                            // non-secret, co-droppé
}
```

- **Populate** (unlock) : rempli **dans** la fonction combinée d'ouverture (jamais via un setter qui ferait traverser la clé).
- **Lecture** : **interne au crate uniquement** — aucune fonction FFI ne retourne `derived_key`.
- **Clear** : `pin_session_clear()` met `None` ⇒ `Drop` zeroïse.
- **Présence** : `pin_session_present() -> bool` (gate d'existence, heap-0).
- **Thread-safety** : `Mutex` + poison-recover identique à `upload_jwt_guard` (anti-pattern connu, déjà accepté pour le bearer, pas un risque neuf).

## 4. API par surface (corrigée — combined calls)

> Convention : tout ce qui traverse est **ciphertext** (`bytes`) ou **handle** ; jamais un secret en clair.

### 4.1 Fast-reseal du ratchet (chemin chaud, ~10×/enregistrement, ~50×/rotation)
- **Rust** : `impl EphemeralRatchet { pub fn reseal_session_blob(&self) -> Result<Vec<u8>, FfiError> }`
  → serialize **dans** Rust (plaintext reste Rust) + `seal_with_key` avec la clé du holder → rend le **blob scellé**.
- **UDL** : `[Throws=FfiError] bytes reseal_session_blob();` sur `interface EphemeralRatchet`.
- **Kotlin** (`persistRatchet`, [StreamUploadManager.kt:904-920](../stream-crypto/src/main/java/org/stream/crypto/upload/StreamUploadManager.kt)) :
  - **avant** : `val s = r.serialize(); val blob = pinStoreSealWithKey(key, salt, s); saveRatchetBlob(blob); SecureWipe.wipe(s)`
  - **après** : `val blob = r.resealSessionBlob(); saveRatchetBlob(blob)` — plus de `key/salt` Kotlin, plus de `serialize()` qui traverse, plus de wipe du plaintext (il n'existe plus côté JVM).

### 4.2 Unlock du ratchet (1×/session)
- **Rust** : `pub fn pin_session_open_ratchet(pin: &[u8], sealed_blob: &[u8]) -> Result<Arc<EphemeralRatchet>, FfiError>`
  → Argon2id (open_extended interne) + **stash `(derived_key, salt)` dans le holder** + open + deserialize **dans** Rust → rend le **handle ratchet**. Ni la clé ni le plaintext 50-sk ne traversent.
- **UDL** : fonction namespace `[Throws=FfiError] EphemeralRatchet pin_session_open_ratchet([ByRef] bytes pin, [ByRef] bytes sealed_blob);`
- **Kotlin** (`initializeWithPin`, [:292-299](../stream-crypto/src/main/java/org/stream/crypto/upload/StreamUploadManager.kt)) :
  - **avant** : `pinStoreOpenExtended` → `ratchetDerivedKey/Salt` (champs) + `deserialize(plaintext)` + wipe plaintext.
  - **après** : `this.ratchet = pinSessionOpenRatchet(pin, blob)` — une ligne ; le holder est rempli en interne.

### 4.3 Enrôlement du ratchet (1×, à la création)
À l'enrôlement le ratchet vient de l'`EnrollmentKit` (en mémoire), pas d'un blob disque. Flux actuel
([:180-184](../stream-crypto/src/main/java/org/stream/crypto/upload/StreamUploadManager.kt)) : sceller le blob initial (premier Argon2) puis `open_extended` pour récupérer `derived_key`.
- **Rust** : `pub fn pin_session_populate(pin: &[u8], sealed_blob: &[u8]) -> Result<(), FfiError>`
  → run open_extended, **stash `(key, salt)`**, **jette le plaintext côté Rust** (le ratchet est déjà en mémoire). Rien ne traverse.
- **UDL** : `[Throws=FfiError] void pin_session_populate([ByRef] bytes pin, [ByRef] bytes sealed_blob);`
- **Kotlin** : remplace l'assignation aux champs `ratchetDerivedKey/Salt` par `pinSessionPopulate(pin, sealed)`.

### 4.4 Report master (OPTION B)
- **Rust** :
  - enroll : `pub fn pin_session_seal_report_keyring(keyring: &ReportKeyring) -> Result<Vec<u8>, FfiError>` (lit `master_bytes` **dans** Rust + seal avec holder → blob scellé).
  - unlock : `pub fn pin_session_open_report_keyring(sealed_blob: &[u8]) -> Result<Arc<ReportKeyring>, FfiError>` (open avec holder + `from_seed` **dans** Rust → handle).
- **Kotlin** (enroll [:229-239], unlock [:335-340]) : `saveReportMasterBlob(pinSessionSealReportKeyring(keyring))` ; `this.reportKeyring = pinSessionOpenReportKeyring(blob)`. Plus de `masterBytes()`, plus de `fromSeed()`, plus de wipe.

### 4.5 Provenance seed (OPTION B) — identique au report master
- **Rust** : `pin_session_seal_provenance_signer(signer) -> bytes` ; `pin_session_open_provenance_signer(sealed_blob) -> ProvenanceSigner`.
- **Kotlin** (enroll [:203-214], unlock [:314-320]) : symétrique à 4.4.

### 4.6 Suppression finale des exports nus
Une fois 4.1–4.5 en place et leurs appelants migrés, retirer du FFI (UDL + impl, façon B-CR-4) :
`pin_store_open_extended`, `pin_store_seal_with_key`, `pin_store_open_with_key`,
`EphemeralRatchet.serialize`, `ReportKeyring.master_bytes`, `ProvenanceSigner.seed_bytes`
— **après** un `grep` confirmant 0 appelant restant (Kotlin + tests + CLI). Les primitives **core**
correspondantes restent (utilisées en interne). `pin_store_seal` (premier seal à l'enrôlement)
reste tant qu'un consommateur subsiste — à vérifier.

## 5. Invariants ratchet à préserver (NE PAS CASSER)

1. **Atomicité mutation→persist** : `signAndAdvance`/`advanceBatch` puis persist, **dans le même
   `synchronized(ratchetLock)`** ([:499-516, 725-729, 812-856](../stream-crypto/src/main/java/org/stream/crypto/upload/StreamUploadManager.kt)). 4b ne change pas l'ordre — seulement *qui* tient la clé (Rust). Le `reseal_session_blob()` doit être appelé au **même point**, sous le **même lock**.
2. **Crash entre mutation et persist** = blob disque périmé → au prochain unlock le device rejoue depuis l'état pré-mutation ; safe (slot déjà consommé, le serveur re-sync via rotation_proof). Inchangé.
3. **Jamais d'Argon2id pendant l'enregistrement** : la clé est dérivée 1× à l'unlock (~1,2 s) puis le holder sert tous les reseals en O(µs). Contrat de perf load-bearing.
4. **Survie en enregistrement de fond** : le holder + `reportKeyring` doivent **survivre au drain** post-stop (workers qui re-signent/uploadent). Les vider en plein drain = `no_auth_token` (régression 1.14).

## 6. Clearing wiring — **correction critique** (trouvée par la revue)

Le bearer JWT est **re-fetchable** (re-auth) ; la clé de reseal + `reportKeyring` + `provenanceSigner`
**ne sont PAS re-dérivables sans le PIN**. Donc `pin_session_clear()` **ne se câble PAS** comme
`UploadAuthHolder.clear()`.

| Événement | `UploadAuthHolder.clear()` (JWT) | `pin_session_clear()` (Lot 4b) |
|---|---|---|
| `lock()` explicite ([:372](../stream-crypto/src/main/java/org/stream/crypto/upload/StreamUploadManager.kt)) | oui | **oui** |
| `panicWipe()` ([:397-410]) | oui (via lock) | **oui** (via lock) |
| `V2LockTimeoutController.fireRatchetLock()` ([:201-234](../mobile/src/main/java/rs/readahead/washington/mobile/util/V2LockTimeoutController.kt), gate `isRunning\|\|isShuttingDown\|\|encryptionsInFlight\|\|pending>0`) | — | **oui — même gate que le wipe ratchet** |
| `V2LockTimeoutController.fire()` (clear JWT, [:141-169]) | oui | **NON** |
| HTTP 401 ([ChunkUploadWorker.kt:181-189](../mobile/src/main/java/rs/readahead/washington/mobile/util/jobs/ChunkUploadWorker.kt), `ProvenanceTimestampWorker.kt:133`, `DirectoryEntryWorker`) | oui | **NON** (le 401 = re-auth, la clé de reseal reste nécessaire) |

→ `pin_session_clear()` se gate **comme la destruction `reportKeyring`/le wipe ratchet** (drain-safe :
`fireRatchetLock` + `lock` + `panicWipe`), **jamais** sur `fire()` (JWT) ni sur un 401. Nouvel objet
Kotlin `PinSessionHolder` (calque `UploadAuthHolder`) avec `present()`/`clear()` ; câblé uniquement
aux 3 points ci-dessus. **Tout appel hors de ces 3 points = bug, à attraper en revue.**

## 7. Séquencement (lots build-vert, GO + field-test par phase)

1. **P1 — Holder Rust + tests in-crate** (`.so` seul) : `PIN_SESSION_HOLDER` + `PinSessionState` + `pin_session_present`/`pin_session_clear` + guard poison-recover ; test store→present→clear. Aucun changement Kotlin. **Réversible sans impact** (surface dormante).
2. **P2 — Ratchet : reseal + unlock + populate** (`.so` + Kotlin) : `reseal_session_blob`, `pin_session_open_ratchet`, `pin_session_populate` ; migrer `persistRatchet`/`initializeWithPin`/`enrollFromMnemonic` ; supprimer les champs `ratchetDerivedKey/Salt` + leur wipe `lock()` ; câbler `pin_session_clear()` dans `lock()`. **Field-test ratchet** (cf. §8). *C'est le cœur, le diff le plus sensible.*
3. **P3 — Report keyring OPTION B** (`.so` + Kotlin) : `pin_session_seal_report_keyring` + `pin_session_open_report_keyring` ; migrer enroll/unlock ; destruction `reportKeyring` inchangée (déjà drain-gated).
4. **P4 — Provenance signer OPTION B** (`.so` + Kotlin) : symétrique P3.
5. **P5 — Clearing wiring** : objet `PinSessionHolder.kt` + câblage `fireRatchetLock` (drain-safe). Test drain-deferral.
6. **P6 — Suppression exports nus + docs** (§4.6) : retrait `open_extended`/`seal_with_key`/`open_with_key`/`serialize`/`master_bytes`/`seed_bytes` après `grep` 0-appelant ; MAJ commentaires + UDL.

Chaque phase : `cargo clippy -D warnings` + `cargo test` (core `--lib`) + `build-android.sh arm64-v8a` + `assembleDebug`. Rollback = revert en ordre inverse (P1 le plus risqué côté surface, mais dormant tant que Kotlin n'appelle pas).

## 8. Matrice field-test (device, logcat oracle)

- **Enroll → unlock → record 10 chunks → 10 reseals → lock** : 0 crash, blob ratchet persiste, perf reseal O(µs) (Argon2id **non** rappelé par signature). Seeker + OnePlus.
- **Rotation de batch** (50 sign + advance) : `persistRatchet` lit la clé du holder, reseal OK, nouveau batch accepté serveur.
- **Lock mid-drain** : record 30 s → stop → background immédiat (timeout) → vérifier que `fireRatchetLock` **défère** `pin_session_clear()` tant que `pending>0`, puis clear net ; 0 `no_auth_token`.
- **panicWipe pendant record** : service s'arrête propre (0 NPE sur ratchet/holder), holder vidé.
- **401 mid-record** : `pin_session_clear()` **NON** appelé ; le reseal suivant ne crashe pas.
- **reportKeyring/provenance survie drain** : un chunk post-stop appelle `reportIdHex()` sans crash.
- **Round-trip réglages + force-stop** : unlock après kill, ratchet re-désérialisé via `pin_session_open_ratchet`.
- **Archive-restore CLI** : `fetch-archive`/`decrypt` n'utilisent **pas** le holder (one-shot par appel, pas de cache) — vérifier que le chemin Rust ne dépend pas du holder.
- *(option forensic)* heap-dump post-lock : 0 octet de `derived_key`/seed en clair (la clé ne traverse plus du tout).

## 9. Honnêteté résiduelle

- **Mnemonic à l'enrôlement** traverse 1× (ByteArray → Rust → `Zeroizing`), one-shot, hors session : accepté (entrée, pas cache de session).
- **`pin` (ByteArray)** : reste `ByteArray` partout (jamais `String`/`CharArray`), invariant à préserver dans toutes les phases.
- Après 4b : **aucun** secret de session ne traverse en clair. Reste la classe R-D-1 (heap-dump device vivant déverrouillé), intrinsèque au modèle « session ouverte » — n'expose pas les rushes passés.

## 10. Questions ouvertes (à trancher en P1-P2)

- **UniFFI 0.28 destroy** : confirmer si le `destroy()` Kotlin des handles (`ReportKeyring`/`ProvenanceSigner`/`EphemeralRatchet`) reste explicite (il l'est aujourd'hui [:356-369]) — on garde les `destroy()` explicites au `lock()`, gate drain inchangée.
- **`std::sync::Mutex` + `zeroize` sur NDK** : déjà déployé (bearer holder), confirmation triviale en P1.
- **Record UDL vs handle** pour le ratchet à l'unlock : on rend un **handle** `EphemeralRatchet` (pas un record) — cohérent avec l'interface existante.
