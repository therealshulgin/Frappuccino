# Spec PoC client QUIC (transport obfusqué)

> Document de **design / spec**, pas d'implémentation. Productionisation du transport
> pluggable décidé en `ROADMAP §10.9` (PoC **serveur** déjà fait, voir la table de
> résultats §10.9). Cette spec décrit le **PoC client** : faire transiter l'upload des
> chunks par un transport QUIC porté **dans le Rust**, en (1) préservant intégralement
> les filets anti-data-loss durcis aujourd'hui en Kotlin et (2) capturant au passage le
> gain heap-0 de `ROADMAP §10.7`.
>
> Statut : **LIVRÉ**, et c'est le mode par défaut. Cette ligne a dit « proposé,
> aucune ligne de code livrée » longtemps après le contraire. Aujourd'hui
> `RustUploadTransport.mode` vaut `OBF_QUIC`, `ChunkUploadWorker` pousse le chunk
> par la FFI Rust, la feature Cargo `quic` existe et une garde Gradle refuse un APK
> construit sans elle. Ce document garde sa valeur de **spécification d'origine** :
> lisez-le pour le raisonnement, pas pour l'état. Deux pièges de grep, du coup : le bloc
> Kotlin OkHttp du §5 n'est plus le chemin de production (le PUT passe par la FFI Rust),
> et l'esquisse UDL du §8 propose un `upload_put_chunk` qui a existé puis a été retiré le
> 2026-09-03 avec ses deux corps Rust ; l'export réel est `upload_put_report_chunk`.

---

## 1. But du PoC et ce qu'il ne couvre PAS

**But** : valider, **sur device réel**, que faire le PUT du chunk via un transport
QUIC porté dans le Rust :

1. **tient ou bat** l'upload direct (TCP/HTTPS actuel) sur réseau dégradé, sur les deux
   devices de référence (Seeker MTK + OnePlus 13) ;
2. **passe pour du QUIC/HTTP-3 générique** (inclassifiable comme « Frappuccino » par un
   DPI) ;
3. atteint **heap-0 du bearer sur le chemin chunk** (le JWT ne traverse plus la pile HTTP
   JVM/OkHttp) ;
4. **ne régresse aucun** des filets anti-data-loss field-critiques.

C'est le **gate** avant productionisation : si (1) ∧ (2) ∧ (3) ∧ (4) → on productionise ;
sinon on reconsidère (repli sur le stopgap `setsockopt(bbr)` où dispo, ou sur un
DirectTls-en-Rust pour le seul heap-0).

**Hors-scope explicite du PoC** (séquencé après) :

- L'UI Settings complète du toggle transport (`DirectTls` / `ObfQuic` / `RealityTcp` /
  `Vpn`). Le PoC se contente d'un toggle debug.
- Le fallback `RealityTcp` (VLESS+REALITY) **productionisé** : on prévoit seulement un
  **stub** + le point de bascule UDP→TCP. La vraie implémentation REALITY est un sprint
  séparé.
- `Vpn` (AmneziaWG / VPN OS) : option documentée, pas dans le PoC.
- La **matrice devices élargie** : le PoC se limite aux 2 devices de référence.
- Le **résidu « destination non-reliable »** (cf. §9) : l'obfuscation ne le résout pas,
  ce n'est pas l'objet du PoC.

---

## 2. Rappel du finding (le socle)

Mesuré au PoC serveur (`ROADMAP §10.9`, netem isolé, relais jamais touché) :

| Réseau simulé | TCP cubic | TCP BBR | QUIC Brutal |
|---|---|---|---|
| 40 ms / 1 % perte / 20 m | 3.13 | 18.5 | 19.6 |
| 80 ms / 5 % perte / 8 m | 0.62 | 7.07 | 7.87 |
| 150 ms / 10 % perte / 4 m | 0.21 | ~3.3 | 3.89 |

**Découverte décisive** : pour l'**upload**, c'est le contrôle de congestion (CC) de
l'**émetteur** (le téléphone) qui gouverne, pas le BBR du serveur (qui ne sert que le
download). Or **les deux devices uploadent en `cubic` par défaut** (Seeker : kernel
`reno cubic` only ; OnePlus : `reno bbr cubic`). Notre upload réel = la ligne `cubic` :
il **s'effondre sous la perte** (≈6 % du plafond à 10 % de perte). Un transport QUIC
porte son **propre CC en userspace**, contournant le stack cubic-only d'Android →
**×6 (1 % perte) à ×15 (10 % perte)** de goodput vs notre baseline réelle.

**Conséquence pour le client PoC** : le levier n'est pas « QUIC vs TCP » dans l'absolu,
c'est « **un CC userspace échappe au cubic-only d'Android** ». `quinn` expose des
contrôleurs de congestion en userspace (NewReno, **BBR**, Cubic), configurables via
`TransportConfig` (à confirmer dans la version épinglée). ⇒ même un `quinn` + BBR
userspace devrait reproduire le gain Brutal **sans dépendre du kernel** (BBR
indisponible sur le Seeker) ⇒ **fix uniforme toutes-devices**. Le protocole Hysteria2
(Brutal + obfuscation salamander) reste pertinent pour l'**inclassifiabilité** et la
résistance au blocage QUIC, pas pour le seul débit.

**Double gain** : fiabilité d'upload terrain (probable contributeur à la perte de chunks
en réseau dégradé, cf. data-loss 1.x) **+** obfuscation. Le PoC est justifiable sur le
seul axe fiabilité ; l'obfuscation devient le bonus.

---

## 3. Convergence avec §10.7 (heap-0) — LA synergie

`ROADMAP §10.7` (« PUT en Rust, heap-0 ») et `§10.9` (« transport QUIC dans le client »)
**exigent la même chose** : déplacer le PUT du chunk dans le Rust. Une seule
implémentation livre les deux.

État actuel du bearer (vérifié dans le code) :

- Le JWT vit déjà côté Rust dans un static `Zeroizing` : `UPLOAD_JWT`
  (`crypto-rs/ffi/src/lib.rs:962`), rempli par `upload_auth_store()` (`lib.rs:977`)
  uniquement depuis `StreamServerClient::verify()` (`lib.rs:1074-1110`).
- Mais le PUT du chunk est en **Kotlin/OkHttp** : `ChunkUploadWorker` appelle
  `UploadAuthHolder.get()` → `upload_auth_header()` (`lib.rs:985`) qui rend une **copie
  transitoire** du bearer à Kotlin, posée en en-tête `Authorization`
  (`ChunkUploadWorker.kt:148`). Dès que cette copie entre dans OkHttp, la couche HTTP/2
  (table HPACK + `Headers` par-requête sur connexion poolée) en garde **14 copies
  stables** que le code app ne peut pas purger (limite Niveau 1 prouvée, `§10.7`).

**Le PUT en Rust ferme ça** : si le chunk est poussé par un client HTTP/3 **dans le
Rust**, ce client lit le bearer **directement depuis `UPLOAD_JWT`**. `upload_auth_header()`
n'est plus jamais appelé pour le chemin chunk ⇒ **le bearer ne franchit plus la
frontière FFI pour l'upload** ⇒ heap-0 sur le chemin chunk (les 14 copies disparaissent).

**Portée exacte (honnêteté)** : le PoC vise le **chemin chunk** (haute fréquence, token à
24 h, le pire cas du finding §10.6). Restent hors du heap-0 du PoC, et le restent
volontairement :

- Le **POST de création de report** au démarrage de session
  (`StreamRecordingService.kt:2081-2090`) : un seul appel, lit encore
  `UploadAuthHolder.get()`. Migrable plus tard (faible volume).
- L'**archive retrieval** : périmé deux fois depuis. `archive_list_reports` a été
  supprimé avec la route `GET /api/v2/archive/reports` au cutover relais-aveugle, et
  les deux méthodes survivantes ne prennent plus de bearer : les lectures d'archive
  sont **sans identité**, la capacité étant le `report_id` de 128 bits lui-même.
  Aucun bearer ne traverse donc plus sur ce chemin.

⇒ **Une implémentation Rust = obfuscation + fiabilité + heap-0 chunk.** C'est l'argument
qui justifie de remonter ce chantier malgré l'effort.

**Heap-0 = frontière de secret à auditer en entier (pas seulement OkHttp).** Une revue
externe l'a justement rappelé : le bearer ne doit jamais apparaître en clair dans les
**logs, messages d'exception, crash reports, interceptors HTTP, analytics**. Frappuccino
n'a **ni analytics ni crash-reporter** (choix privacy), ce qui réduit la surface ;
restent les **logs et exceptions** (ne jamais logger le bearer, ne pas le laisser fuir
dans un message d'erreur). Le PoC doit traiter le PUT-en-Rust comme une vraie frontière
de secret, pas seulement « ne plus le passer à OkHttp ».

---

## 4. Design : trait `Transport` (§10.9)

Côté client Rust, derrière la couche upload, un trait qui abstrait le « comment » du PUT :

```rust
// crypto-rs/stream/src/transport.rs (nouveau module, feature-gated "quic")
//
// Esquisse — pas du code livré. Synchrone en surface (block_on interne, cf. §8),
// pour coller au modèle FFI existant (tout est sync aujourd'hui).

pub enum TransportMode {
    DirectTls,   // baseline : HTTPS/TCP, pin SPKI (le PUT actuel, porté en Rust)
    ObfQuic,     // primaire : QUIC/HTTP-3, CC userspace (BBR), endpoint obfusqué
    RealityTcp,  // fallback UDP-bloqué : VLESS+REALITY TCP/443 (stub au PoC)
    // Vpn : hors-scope PoC (confiance au VPN/AmneziaWG de l'OS)
}

pub struct PutOutcome {
    pub http_status: u16,     // 200/401/507/5xx... mappé tel quel par Kotlin
    pub upload_ms: u64,       // pour le metrics + le concurrency limiter
    pub transport: TransportMode,  // ce qui a réellement servi (après fallback)
    pub error_detail: Option<String>,
}

pub trait Transport {
    /// Pousse un blob .strm (déjà chiffré E2E) vers `url`, bearer lu en interne
    /// depuis UPLOAD_JWT (jamais passé en argument => heap-0 chunk).
    fn put_chunk(&self, url: &str, blob_path: &str) -> Result<PutOutcome, ProtocolError>;

    /// Équivalent de connectionPool.evictAll() : drop la connexion QUIC cachée
    /// et tout état porteur du bearer (appelé au 401 / lock / panic).
    fn reset(&self);
}
```

Mapping sur les variantes :

- **`DirectTls`** : aujourd'hui le PUT est **Kotlin-only**, donc même la baseline en Rust
  est **nouvelle**. Réutilise le `reqwest::blocking` + `PinnedCertVerifier` déjà en place
  pour enroll/verify/rotate/archive (`crypto-rs/stream/src/protocol.rs:112-152`,
  `pin.rs`). Sert de **filet** : si QUIC échoue, on retombe sur exactement le comportement
  actuel, mais le bearer reste Rust-side (heap-0 conservé).
- **`ObfQuic`** : `quinn` + couche HTTP/3 (`h3`), CC userspace **BBR**, vers un endpoint
  obfusqué self-hosté **devant** le relais. Voir §6 pour le staging (HTTP/3 nu d'abord,
  obfuscation Hysteria2 ensuite).
- **`RealityTcp`** : **stub** au PoC (renvoie `Unsupported`), + le point de bascule auto
  UDP→TCP quand le QUIC ne s'établit pas (réseau UDP-bloqué). Implémentation REALITY =
  sprint séparé.

Sélection au PoC = **toggle debug** (pref type `useObfQuicTransport`, défaut OFF, ignoré
hors `BuildConfig.DEBUG` ou gardé derrière la section debug existante). Fallback auto
ObfQuic→DirectTls si l'établissement QUIC échoue (timeout d'établissement court).

Où ça vit dans le workspace : nouveau module `stream/src/transport.rs` derrière une
**nouvelle feature `quic`** (comme `protocol` l'est pour reqwest), pour que les builds
fuzz/CI puissent sauter l'arbre tokio/quinn. Crates inchangées : `core` / `stream` /
`ffi` / `cli`.

---

## 5. Point d'intégration FFI : préserver les filets (le cœur du PoC)

Les filets anti-data-loss vivent en Kotlin et sont **field-validés**. Deux stratégies :

- **(A) FFI mince, filets Kotlin intacts** — **RETENUE pour le PoC.**
- (B) Porter les filets en Rust — effort élevé, risque data-loss élevé (`§10.7` le
  signale), **rejetée pour le PoC**.

### Stratégie A (retenue)

On **ne touche pas** à l'orchestration Kotlin (WorkManager worker, circuit breaker,
concurrency limiter, queue, secure-delete, metrics, orphan sweep). On remplace **une
seule chose** : l'appel réseau au cœur de `ChunkUploadWorker`.

Aujourd'hui (`ChunkUploadWorker.kt:142-152`) :

```kotlin
val putRequest = Request.Builder()
    .url("$serverUrl/file/$reportId/${blobFile.name}")
    .header("Authorization", authToken)              // <- bearer traverse le JVM
    .put(blobFile.asRequestBody("application/octet-stream".toMediaType()))
    .build()
val putResponse = UploadHttpClient.instance.newCall(putRequest).execute()
val code = putResponse.code
```

Sous stratégie A :

```kotlin
// authToken n'est plus pull pour le chunk : le bearer reste dans UPLOAD_JWT (Rust).
val outcome = uniffi.frappuccino.uploadPutChunk(
    url = "$serverUrl/file/$reportId/${blobFile.name}",
    blobPath = blobFile.absolutePath,
    mode = currentTransportMode,                      // DirectTls | ObfQuic
)
val code = outcome.httpStatus.toInt()
// ... outcome.uploadMs alimente le metrics + UploadConcurrencyLimiter ...
```

Le reste du worker est **inchangé** : le `when (code)` mappe 200/401/507/5xx vers les
mêmes branches qu'aujourd'hui :

| Code | Handler Kotlin (inchangé) | Fichier |
|---|---|---|
| 2xx | `UploadCircuitBreaker.reportSuccess()` + secure-delete différé | `ChunkUploadWorker.kt:241,294-349` |
| 401 | `UploadAuthHolder.clear()` + **reset transport** + `Result.retry()` | `:156-181` |
| 507 | `UploadCircuitBreaker.reportDiskFull()` + `Result.retry()` | `:192-211` |
| 5xx / réseau | `UploadCircuitBreaker.reportServerError(code\|0)` + `Result.retry()` | `:212-221,317-329` |
| 4xx≠401 | `Result.failure()` | `:182-191` |

⇒ **par construction**, tous les filets sont préservés : ils opèrent sur le **code HTTP
retourné** par le FFI, exactement comme sur le code OkHttp aujourd'hui. Le PUT est juste
poussé par un autre transport.

### Les DEUX seuls changements de comportement (à gérer)

1. **Source du bearer (chunk)** : plus de `UploadAuthHolder.get()` pour le chunk ; le
   bearer est lu en interne dans le Rust depuis `UPLOAD_JWT`. C'est **le** gain heap-0.
   `upload_auth_header()` reste pour le POST report (jusqu'à migration §3).
2. **Éviction des connexions** : aujourd'hui, au 401/lock, `UploadAuthHolder.clear()`
   appelle `UploadHttpClient.instance.connectionPool.evictAll()` pour purger les copies
   HPACK (`UploadAuthHolder.kt:44-48`). Avec le transport en Rust, c'est la **connexion
   QUIC côté Rust** qui détient le bearer/état → il faut une nouvelle FFI
   `uploadTransportReset()` (= `Transport::reset()`) appelée aux mêmes points (401, lock,
   panic). **C'est le seul filet nouveau** à ajouter. Le bearer en QUIC-state doit être
   `Zeroizing` et droppé par `reset()`.

### Invariants à respecter (issus de la carte du code)

- **Pas de persistance JWT** côté JVM/WorkManager (déjà l'esprit §10.6 ; renforcé ici).
- **Coordination circuit breaker** identique : 3×5xx → OPEN 60 s ; 507 → OPEN 300 s ;
  half-open probe (timeout 90 s) (`UploadCircuitBreaker.kt`).
- **Concurrency limiter** : `tryAcquire()` / `release()` inchangés ; alimenter
  `reportUploadTime(outcome.uploadMs)` pour l'adaptation du cap 1–6
  (`UploadConcurrencyLimiter.kt`).
- **Secure-delete différé** : wipe **après** `release()` du permit, via
  `secure_delete_file` (`ChunkUploadWorker.kt:342-349`). Inchangé (le blob est sur disque,
  le transport ne change rien).
- **Backoff WorkManager** : exponentiel base 10 s + jitter 0–3 s (live) / 0–30 s
  (orphans) (`StreamRecordingService.kt:1959-1973`). Inchangé.
- **Fallback re-auth single-slot** : `synchronized(authFallbackLock)`
  (`ChunkUploadWorker.kt:362-415`). Inchangé.
- **Pin SPKI** : `DirectTls` réutilise le `PinnedCertVerifier` Rust ; `ObfQuic` épingle le
  cert de l'**endpoint obfusqué** (le pin SPKI nginx actuel,
  `UploadHttpClient.kt:69` / `network_security_config.xml:24`, ne s'applique qu'au chemin
  direct ; QUIC a son propre pin sur l'endpoint).

---

## 6. Variante transport et endpoint serveur (staging)

Pour dé-risquer, on **étage** le PoC plutôt que de viser Hysteria2-complet d'emblée :

- **PoC-1 — débit + heap-0 + intégration (le plus de valeur, le moins de risque)** :
  `ObfQuic` = `quinn` + `h3` + **CC BBR userspace**, PUT HTTP/3 vers un endpoint
  **HTTP/3 générique** (Caddy ou nginx-quic) placé **devant** le relais de test, qui
  reverse-proxy en HTTPS vers le relais. Prouve : (a) le CC userspace bat cubic-Android
  sur réseau dégradé (le double gain), (b) l'intégration stratégie A marche, (c) heap-0
  chunk. Le trafic est du **QUIC/HTTP-3 générique** = déjà une bonne camouflage (un DPI
  voit « du web QUIC », pas « Frappuccino »).
- **PoC-2 — inclassifiabilité forte + anti-blocage** : envelopper avec **Hysteria2**
  (obfuscation salamander + Brutal) OU préparer le repli `RealityTcp` (TCP/443) pour les
  réseaux qui **bloquent tout l'UDP/QUIC**. Prouve la résistance DPI / anti-censure.

Côté serveur du PoC : endpoint obfusqué (Caddy-h3 pour PoC-1, sing-box/hysteria pour
PoC-2) **devant** le relais. Les blobs sont **déjà E2E** ⇒ l'endpoint ne fait que relayer
des octets (il ne déchiffre rien d'utile). À monter sur le relais de test **ou** une box
séparée ; **ne pas impacter le relais de prod** (même discipline d'isolement que le PoC
serveur : netns/box dédiée).

Note CC : le PoC serveur a utilisé Brutal *informé de la bande passante* (meilleur cas).
Pour le client, `quinn`+BBR ne triche pas sur l'estimation → on s'attend à un gain un peu
moindre que Brutal-informé, mais **le gain survit** (BBR ≈ Brutal dans la table §2 :
18.5 vs 19.6, etc.).

---

## 7. Plan de mesure on-device

Instrument déjà presque gratuit : la ligne `StreamMetrics:I` émise par chunk
(`ChunkUploadWorker.kt:272-292` : `seq` / `quality` / `sizeBytes` / `uploadMs` / `ratio`
/ `cap` / `backlog` / `networkType`). **Ajouter un champ `transport=quic|direct`** et on
a tout le télémétrie nécessaire via logcat.

**Devices** : Seeker (`SM02E406037868`, MTK, `cubic` only) + OnePlus 13 (`fe143e66`,
SD8 Gen3, `bbr` dispo). Les deux en `cubic` par défaut ⇒ les deux profitent du CC
userspace.

**Conditions réseau** :

1. **Wifi normal** (sanity : QUIC ne doit pas être *pire* que direct).
2. **Dégradé contrôlé (reproductible)** : téléphone derrière un AP Linux faisant `netem`
   (`delay/loss/rate`), miroir des 3 profils de la table §2. Méthode privilégiée car
   reproductible et comparable au PoC serveur.
3. **Dégradé réel (réalisme)** : cellulaire faible signal / wifi saturé. Indicatif.

**Protocole par condition** : une vraie session d'enregistrement+upload (record long, p.
ex. 10–20 min), une fois en `direct`, une fois en `quic` (A/B via le toggle), sur chaque
device. Relever : goodput moyen, `uploadMs` médian/p95, **retries/chunks perdus**,
profondeur de backlog, **delta batterie + data** (coût retransmissions mobile).

**Vérif inclassifiabilité** : pcap sur le chemin du PoC (côté AP/endpoint, pas sur le
device) + `nDPI`/Wireshark → le flux doit se classer en **QUIC/HTTP-3 générique**, pas en
signature applicative identifiable.

**Vérif heap-0 (le gain §10.7)** : rejouer la procédure §10.6 (`am dumpheap` après
lock/panic, en pleine session d'upload) et confirmer **0 copie `Bearer`** sur le chemin
chunk (le 14→0). Comparer au baseline direct (14 copies).

**Matrice data-loss à re-valider** (filet (4) du gate) : record long + réseau dégradé +
**disk-full 507** (remplir le store de test) + **401** (rotation JWT serveur) +
**lock pendant upload**. Zéro perte de chunk attendue (les filets Kotlin opèrent à
l'identique).

---

## 8. Async / runtime, dépendances, build

- **quinn exige async** ; aujourd'hui **aucun runtime tokio externe** n'est actif (reqwest
  cache un tokio interne et expose du **blocking** ; tous les exports FFI sont
  synchrones). On **reproduit ce pattern** : un runtime `tokio` **interne** (current- ou
  multi-thread) initialisé paresseusement dans `stream`, `block_on` à la frontière FFI.
  La FFI reste **synchrone** (le `ChunkUploadWorker` fournit déjà le thread de fond ;
  bloquer y est sain).
- **Dépendances** (pin exact, `Rust_guidelines.md`) : `quinn = "=0.11.x"`,
  `h3`/`h3-quinn` épinglés, `tokio = "=1.x"`. Derrière la **feature `quic`**
  (build fuzz/CI peut la couper, comme `protocol` coupe reqwest,
  `crypto-rs/stream/Cargo.toml:16-28`).
- **`panic = "unwind"`** est déjà fixé (`crypto-rs/Cargo.toml:35-48`) : nécessaire pour
  que `catch_unwind` du FFI déroule les `Drop` `Zeroizing` (le bearer en QUIC-state en
  bénéficie).
- **Build** : `crypto-rs/build-android.sh` (cargo-ndk) sort déjà arm64-v8a / armeabi-v7a /
  x86_64 ; ajouter la feature `quic` à la ligne `build`. **Régénérer les bindings UniFFI**
  (UDL → Kotlin) après ajout de `upload_put_chunk` / `upload_transport_reset` /
  `PutOutcome` / `TransportMode`. **`.so` toutes-ABI** à reconstruire (non git-trackés :
  régén via `build-android.sh`).
- **Mesurer le delta taille `.so`/APK** (quinn + tokio + h3 ne sont pas légers) : entrée
  du gate (acceptable ?).

**Esquisse UDL** (`crypto-rs/ffi/src/frappuccino.udl`, à côté du bloc §10.6 lignes
125-140) :

```
enum TransportMode { "DirectTls", "ObfQuic", "RealityTcp" };

dictionary PutOutcome {
    u16 http_status;
    u64 upload_ms;
    TransportMode transport;
    string? error_detail;
};

namespace frappuccino {
    // lit UPLOAD_JWT en interne ; blob_path = .strm déjà chiffré (pas de plaintext heap)
    [Throws=FfiError]
    PutOutcome upload_put_chunk([ByRef] string url, [ByRef] string blob_path, TransportMode mode);

    // équivalent connectionPool.evictAll() : drop conn QUIC + état porteur du bearer
    void upload_transport_reset();
};
```

Note : le blob est du **ciphertext `.strm`** (le plaintext ne touche jamais le JVM, ni
ici ni dans le PUT actuel) ⇒ le PUT-en-Rust n'introduit **aucun** nouveau risque
plaintext-heap ; le gain est **purement le bearer**.

---

## 9. Risques, mitigations, résidu

| Risque | Mitigation |
|---|---|
| Régression data-loss sur chemin field-critique | Stratégie A (filets restent Kotlin) ; toggle **défaut OFF** ; A/B vs direct ; re-validation device complète (matrice §7) ; `DirectTls`-en-Rust comme repli identique au comportement actuel |
| Réseau UDP/QUIC bloqué | Fallback auto UDP→TCP (`RealityTcp` stub au PoC, vrai REALITY plus tard) ; `DirectTls` toujours dispo |
| Coût batterie/data des retransmissions | **Mesuré** au §7 (entrée du gate) |
| Taille `.so`/APK (quinn+tokio+h3) | **Mesuré** ; feature-gated ; entrée du gate |
| Bearer désormais en QUIC-state Rust | `Zeroizing` + `upload_transport_reset()` aux mêmes points que `evictAll()` (401/lock/panic) |
| MTU / fragmentation UDP mobile | Couvert par quinn (PMTUD) ; à vérifier en mesure réelle |

**Résidu non résolu (et hors PoC)** : *destination non-reliable* (« on voit que le
téléphone parle à CET endpoint »). L'obfuscation rend le flux **inclassifiable** (objectif
1) mais ne cache pas **à qui** on parle (objectif 2). Pistes (à trancher selon la menace
réelle, `ROADMAP §10.9` / `METADATA_EXPOSURE_MAP §8`) : front CDN partagé, VPN
multi-tenant, rotation d'IP. **Pas de repas gratuit** : c'est un chantier distinct.

---

## 10. Découpage du PoC (livrables)

| Étape | Livrable | Prouve |
|---|---|---|
| **0** | Feature `quic` + runtime tokio interne + `quinn` « hello » ; `.so` all-ABI qui charge sur device | La plomberie async/FFI/build tient |
| **1** | `upload_put_chunk` en **`DirectTls`** (reqwest/h2 Rust) câblé dans `ChunkUploadWorker` derrière le toggle | Intégration stratégie A + **filets préservés** + **heap-0 chunk**, sans QUIC encore (dé-risque l'intégration seule) |
| **2** | `ObfQuic` via `quinn`+`h3`+BBR vers endpoint HTTP/3 devant le relais de test | **Double gain débit** sur réseau dégradé (les 2 devices) |
| **3** | Obfuscation Hysteria2 (salamander) **ou** stub `RealityTcp` + bascule UDP→TCP | **Inclassifiabilité** / anti-blocage |
| **4** | Campagne de mesure on-device (2 devices, normal+dégradé) + re-valid heap-0 + matrice data-loss | **Décision de gate** |

L'étape 1 est volontairement **avant** QUIC : elle isole le risque d'intégration (porter
le PUT en Rust + préserver les filets + heap-0) du risque transport (quinn/tokio). Si
l'étape 1 régresse un filet, on le voit **sans** le bruit de QUIC.

---

## 11. Critère de succès (gate)

**GO** pour productioniser **si et seulement si**, sur les **deux** devices :

1. **Débit** : goodput d'upload chunk via `ObfQuic` **≥** `DirectTls` sur réseau dégradé
   (cible ≥ ×3 ; attendu ×6–×15 d'après §2) ; et **pas pire** sur wifi normal.
2. **Inclassifiable** : le flux se classe en QUIC/HTTP-3 **générique** (nDPI/Wireshark ne
   fingerprint pas Frappuccino).
3. **Heap-0 chunk** : 0 copie `Bearer` post-lock/panic sur le chemin chunk (vs 14 en
   direct).
4. **Zéro régression data-loss** sur la matrice field-critique (record long + dégradé +
   507 + 401 + lock pendant upload).

**Sinon** → repli documenté : stopgap `setsockopt(bbr)` où dispo (faisabilité déjà
prouvée, `ROADMAP §10.9`, no-op sur Seeker) **et/ou** `DirectTls`-en-Rust pour le seul
gain heap-0 (sans le gain débit), en attendant.

---

## 12. Références code (ancres pour l'implémenteur)

**Kotlin (chemin upload, filets à préserver)** :

- `ChunkUploadWorker.kt` : PUT `:142-152` ; 401 `:156-181` ; 4xx `:182-191` ; 507
  `:192-211` ; 5xx `:212-221` ; succès `:241-251` ; secure-delete différé `:294-349` ;
  concurrency `:112-119` ; fallback re-auth `:362-415` ; metrics `:272-292`.
- `UploadCircuitBreaker.kt` : machine d'état (507→300 s, 3×5xx→60 s, half-open 90 s).
- `UploadConcurrencyLimiter.kt` : cap adaptatif 1–6, `reportUploadTime`.
- `UploadAuthHolder.kt` : `get/clear` + `evictAll` `:44-48`.
- `UploadHttpClient.kt` : pin SPKI `:60-119`.
- `StreamRecordingService.kt` : `scheduleUpload :1913-2003` ; backoff `:1959-1973` ;
  POST report `:2081-2090` ; refresh JWT `:1871-1899`.
- `ChunkUploadQueue.kt` / `OrphanSweepWorker.kt` : queue fsync + sweep orphelins.

**Rust** :

- `crypto-rs/ffi/src/lib.rs` : `UPLOAD_JWT :962` ; `upload_auth_store :977` ;
  `upload_auth_header :985` ; `upload_auth_clear :991` ; `verify (stash bearer)
  :1074-1110` ; archive (bearer en param) `:1220-1315`.
- `crypto-rs/ffi/src/frappuccino.udl` : bloc auth `:125-140` (lieu des ajouts).
- `crypto-rs/stream/src/protocol.rs` : `StreamServerClient` reqwest::blocking `:112-152`
  (base de `DirectTls`).
- `crypto-rs/stream/src/pin.rs` : `PinnedCertVerifier` (réutilisé par `DirectTls`).
- `crypto-rs/stream/Cargo.toml` : feature `protocol` `:16-28` (modèle pour la feature
  `quic`).
- `crypto-rs/Cargo.toml` : profils, `panic = "unwind" :35-48`.
- `crypto-rs/build-android.sh` : ABIs + bindgen UniFFI.

---

*Spec PoC client QUIC — 14 juin 2026. Référencée par `ROADMAP §10.9`. Aucune
implémentation livrée par ce document.*
