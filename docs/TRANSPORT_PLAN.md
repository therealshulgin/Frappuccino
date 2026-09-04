# Plan transport (stopgap BBR → heap-0 → QUIC obfusqué)

> Plan d'exécution **dé-risqué** pour le chantier transport (`ROADMAP §10.7` heap-0 +
> `§10.9` transport obfusqué). Découle de la spec `docs/TRANSPORT_QUIC_POC_SPEC.md` et de
> son évaluation critique indépendante (2026-06-14).
>
> **Principe** : gains sûrs et quasi gratuits d'abord, pari coûteux (QUIC) **validé par la
> mesure avant** de s'engager. Chaque phase finit sur un **gate GO/NO-GO** qui peut
> arrêter la dépense. Le `quoi` et le `comment` sont bons (cf. spec) ; ce plan corrige le
> `quand`.
>
> Statut : **proposé**. Aucune ligne de code livrée par ce document.

---

## Vue d'ensemble

| Phase | Livrable | Coût | Risque | Gate de sortie |
|---|---|---|---|---|
| **0** | Stopgap `setsockopt(bbr)` + instrumenter la perte réelle | Faible | Très faible | La perte d'upload est-elle CC-bound sur vrai réseau ? |
| **1** | Heap-0 via `DirectTls`-en-Rust (PUT Rust, pas encore QUIC) | Moyen | Faible | Heap-0 + zéro régression data-loss ? |
| **2** | **Spike jetable** quinn+CC userspace, mesuré sur device | Faible | n/a (mesure) | quinn-CC bat cubic-Android (≥ ×3) sur les 2 devices ? |
| **3** | QUIC obfusqué complet (seulement si Gate 2 = GO) | Élevé | Moyen | Débit + inclassifiable + heap-0 + zéro régression ? |

Chaque phase vaut le coup **même si la suivante est abandonnée** : la 0 améliore les
devices BBR-capables, la 1 livre le heap-0 (indépendant de QUIC), la 2 évite de gaspiller
le sprint, la 3 ajoute fiabilité-sous-perte + obfuscation.

---

## Phase 0 — Stopgap BBR + instrumentation de la perte

**But** : (a) capter immédiatement le gain BBR là où il est dispo (OnePlus et parc moderne)
sans aucune dépendance ni risque, et (b) **répondre à la question causale** que la spec
suppose : *la perte de chunks observée en terrain est-elle vraiment due au CC, ou au
disk-full / mort-de-process / wipe-JWT (causes root-causées en 1.12/1.14) ?*

**0a. Stopgap `setsockopt(TCP_CONGESTION, "bbr")`**
- Faisabilité **déjà prouvée** on-device (test NDK, uid 2000 non-privilégié sur OnePlus :
  `bbr` appliqué et relu ; contrôle négatif échoue). Voir `ROADMAP §10.9`.
- Implémentation : un `SocketFactory` OkHttp custom sur `UploadHttpClient`
  (`UploadHttpClient.kt:73-118`) qui, à la création du socket d'upload, tente
  `setsockopt(bbr)` via une petite fonction JNI sur le `fd` du socket (obtenu via le
  `FileDescriptor` du `Socket`), et **garde `cubic` en silence si ça échoue**
  (no-op inoffensif sur Seeker, gain BBR sur devices capables).
- **Point dur** : accéder au `fd` du socket OkHttp avant `connect()` est fiddly sur
  Android (le `SocketFactory` rend un `Socket` non connecté ; poser l'option dans un
  `connect()` surchargé avant `super.connect()`). C'est le seul risque d'implémentation de
  la phase, purement mécanique. **Zéro dep nouvelle, zéro surface d'audit, filets OkHttp
  100 % intacts.**

**0b. Instrumenter la perte réelle**
- Étendre le résumé `StreamMetrics` (déjà émis par chunk, `ChunkUploadWorker.kt:272-292`)
  d'un **résumé par session** : chunks produits / uploadés / retriés / perdus-au-TTL, +
  le **CC actif** (`getsockopt` : `cubic` vs `bbr`).
- Une session terrain sur réseau **réellement** dégradé (cellulaire faible / wifi saturé)
  sur les 2 devices.

**Validation** : la perte de footage écran-éteint et la matrice 507/401/lock ne bougent
pas (le stopgap ne touche que le CC du socket, pas les filets).

**Gate 0 (décision causale)** : sur OnePlus (BBR-capable), activer BBR **réduit-il
mesurablement** retries/pertes vs cubic sur vrai réseau ?
- **OUI** → lien causal soutenu, la justification fiabilité de QUIC tient, on continue.
- **NON** → la perte n'est **pas** CC-bound (elle est disk/process/wipe). La fiabilité ne
  justifie plus QUIC à elle seule ; restent **obfuscation + heap-0** comme moteurs. On
  re-priorise en conséquence (heap-0 via phase 1 reste valable ; QUIC redevient un
  chantier obfuscation, pas fiabilité).

Le stopgap se **ship dans tous les cas** (amélioration gratuite sur devices capables).

**Effort indicatif** : ~2-4 jours.

---

## Phase 1 — Heap-0 via `DirectTls`-en-Rust

**But** : porter le PUT du chunk dans le Rust en réutilisant le client **`reqwest::blocking`
existant** (pas encore de QUIC), derrière le toggle. Livre le **heap-0 chunk** (cible
`§10.7`) **et** dé-risque toute l'intégration stratégie-A **sans** la complexité
quinn/tokio. **Vaut le coup même si QUIC est ensuite abandonné.**

**Livrables Rust** (feature `protocol` existante, **aucune dep nouvelle**) :
- Surface FFI (UDL, à côté du bloc auth `frappuccino.udl:125-140`) :
  `upload_put_chunk(url, blob_path, mode) -> PutOutcome`, `upload_transport_reset()`,
  records `PutOutcome { http_status, upload_ms, transport, error_detail }` et enum
  `TransportMode`.
- `upload_put_chunk` lit le bearer **en interne** depuis `UPLOAD_JWT`
  (`ffi/src/lib.rs:962`) : il n'est **jamais** passé en argument ⇒ ne franchit plus la
  FFI ⇒ **heap-0 chunk**. Le blob est du `.strm` (déjà chiffré) ⇒ aucun plaintext en jeu.
- Un module `transport.rs` (variante `DirectTls` seule) au-dessus du
  `StreamServerClient`/`PinnedCertVerifier` existant (`stream/src/protocol.rs:112-152`,
  `pin.rs`), avec des **timeouts dimensionnés upload** (pas les 10s/15s de l'auth : un PUT
  de ~1 Mo sur lien lent + un **plafond par-appel** type `callTimeout`).

**Livrables Kotlin** :
- `ChunkUploadWorker` : remplacer le seul `client.newCall(putRequest).execute()`
  (`:142-152`) par l'appel FFI, derrière le toggle (défaut OFF / gardé `BuildConfig.DEBUG`).
  Le `when (code)` (`:154-222`) reste **inchangé** : 200/401/507/5xx mappés à l'identique ;
  `outcome.uploadMs` nourrit `UploadConcurrencyLimiter.reportUploadTime`.
- **`upload_transport_reset()` câblé aux 5 sites** (finding M3 de l'éval, sécu) là où
  `UploadAuthHolder.clear()`/`evictAll()` est appelé aujourd'hui :
  1. 401 worker (`ChunkUploadWorker.kt:179`)
  2. lock (`StreamSettingsActivity.kt:916`)
  3. panic (`StreamSettingsActivity.kt:947`)
  4. `panicWipe()` (`StreamUploadManager.kt:288`)
  5. auto-lock idle (`V2LockTimeoutController.kt:164`)
  ...avec **les mêmes gates « jamais pendant un drain/recording »** que le JWT clear
  (`V2LockTimeoutController.kt:142-168`), sinon on recrée la classe de bug 1.14 (couper la
  connexion sous les chunks suivants). Pour `DirectTls`, `reset()` = drop/rebuild du client
  reqwest (ferme les connexions idle porteuses du bearer).

**Validation (chemin field-critical, exhaustive)** :
- **Matrice data-loss complète** sur device : record long + réseau dégradé + **disk-full
  507** (remplir le store de test) + **401** (rotation `JWT_SECRET`) + **lock pendant
  upload**. **Zéro chunk perdu.**
- **Permit jamais gelé** : injecter un PUT qui stalle (endpoint qui accepte puis ne lit
  plus) → `upload_put_chunk` rend la main en ≤ plafond par-appel, le permit est relâché
  (`finally`, `:334`), le circuit-breaker ne se désynchronise pas (finding M2).
- **Re-validation heap-0** : `am dumpheap` après `panicWipe` en plein upload → **0 copie
  `Bearer`**, en vérifiant le heap **natif** (le bearer est désormais Rust-side) **et**
  dalvik. Compare au baseline direct (14 copies). Confirmer le 14→0 **après** câblage des
  5 sites de reset.
- A/B vs OkHttp direct (toggle) : pas de régression débit sur réseau normal.

**Gate 1** : heap-0 confirmé **ET** zéro régression data-loss **ET** intégration solide
(les 5 sites + le plafond par-appel). → on passe à QUIC. Sinon : corriger ici, **à peu de
frais**, avant d'ajouter quinn/tokio.

**Effort indicatif** : ~1 semaine (le PUT reqwest est petit ; le travail = les 5 sites de
reset + la matrice data-loss sur device).

---

## Phase 2 — Spike quinn + CC userspace (jetable, tranche le risque BBR)

**But** : une **mesure jetable** (pas un livrable produit) pour répondre, **avant**
d'engager le sprint QUIC : *est-ce que le CC userspace de quinn bat vraiment le
cubic-only d'Android, sur device réel ?* Ce gate tranche le **finding bloquant B1**.

**Pourquoi c'est un risque réel** : la table PoC (×6-15) a été mesurée avec **Hysteria2/
Brutal informé du débit**. Or quinn ne ship **pas** Brutal : il ship NewReno/Cubic + un
**BBR explicitement marqué « Experimental! Use at your own risk »** (version 0.11.9, déjà
dans notre `Cargo.lock`), avec une issue documentant **TCP+BBR kernel > 2× quinn+BBR**. Si
quinn+BBR plafonne, le gain ne se matérialise pas.

**Harnais** :
- Activer une feature **`quic`** (quinn + tokio + h3), plombée à travers **deux**
  `Cargo.toml` : déclarée dans `ffi/Cargo.toml` et **forwardée** à `stream`
  (`stream/Cargo.toml`), puis ajoutée à la ligne `build` de `build-android.sh:48` (finding
  m4 : ce n'est pas un one-liner). Note : `reqwest` tire déjà quinn/tokio dans le **lock**
  mais **non compilés** ; la feature les fait **compiler et shipper** dans le `.so`.
- Un client quinn+h3 minimal qui PUT vers un endpoint quinn/h3, CC réglé sur le **BBR de
  quinn**, **et** un test de repli avec NewReno/Cubic.
- **Plan B contre B1** : porter un **CC type Brutal** comme `CongestionController` quinn
  (Brutal est simple : il pace à un débit configuré et ne recule quasiment pas sous la
  perte) ⇒ **contourne entièrement le BBR immature de quinn**. Le vrai point dur devient
  alors l'**estimation de bande passante** sur mobile (le caveat « Brutal informé » du PoC
  serveur). Mesurer les deux : quinn-BBR **et** Brutal-porté.
- **Évaluer la maturité du CC sur plusieurs libs (apport revue externe), pas seulement
  quinn** : `s2n-quic` (AWS) et `quiche` (Cloudflare) embarquent un BBR **production** qui
  pourrait éviter à la fois le BBR expérimental de quinn ET l'effort de porter Brutal.
  **quinn reste le candidat naturel** pour notre intégration (async/tokio, UniFFI, même
  écosystème rustls/reqwest) ; cette éval est une **assurance** dans le spike, pas une
  réorientation.
- Mesurer le **delta taille `.so`** (×3 ABI) = entrée du gate (finding M4).

**Gate 2 (décisif)** : sur Seeker **ET** OnePlus, en netem (mêmes profils que le PoC
serveur), un CC quinn (BBR **ou** Brutal-porté) délivre-t-il un gain **net** (cible ≥ ×3)
vs cubic-Android ?
- **OUI** → phase 3, avec le CC gagnant figé.
- **NON** → **stop la piste fiabilité-QUIC.** On a déjà le heap-0 (phase 1) + le stopgap
  (phase 0). On reroute l'obfuscation vers `RealityTcp`/Hysteria2 (Brutal en Go, hors
  quinn) ou AmneziaWG, **ou** on acte que l'obfuscation est une piste séparée moins
  prioritaire. **On ne coule pas le sprint sur une brique expérimentale.**

**Effort indicatif** : ~3-5 jours (jetable, centré mesure).

---

## Phase 3 — QUIC obfusqué complet (seulement si Gate 2 = GO)

**But** : productioniser le transport `ObfQuic` avec le CC validé en phase 2, la couche
d'obfuscation et le fallback.

**Livrables** :
- `ObfQuic` dans `transport.rs` : quinn + h3 + CC choisi. **Modèle de connexion explicite
  et validé sous cap=6** (finding M1) : un `quinn::Endpoint` process-global + une
  connexion multiplexée (un stream HTTP/3 par PUT concurrent), runtime tokio dimensionné
  pour ne **pas** sérialiser les 6 `block_on` (sinon le cap adaptatif fausse ses décisions
  sur des `uploadMs` faussés). Mesurer `uploadMs` p95 par worker à cap=6 QUIC vs OkHttp.
- Cycle de vie : connexion process-globale, droppée par `reset()` (les 5 sites déjà câblés
  en phase 1). **Plafond par-appel + keep-alive/idle QUIC** comme invariants nommés
  (finding M2).
- **Obfuscation** : Hysteria2 (salamander) ou la décision issue du chantier métadonnées.
  Côté serveur : endpoint obfusqué (sing-box/hysteria/xray) **devant** le relais (blobs
  E2E ⇒ relaie des octets), monté en isolation (ne pas impacter la prod).
- **Fallback `RealityTcp` (stub) + bascule auto UDP→TCP** quand QUIC ne s'établit pas
  (réseau UDP-bloqué). `DirectTls` reste toujours dispo.
- **2ᵉ pin TLS** pour l'endpoint obfusqué dans `pin.rs` (finding m3) : paramétrer le
  verifier par-transport (`DirectTls`=cert nginx, `ObfQuic`=cert du front obfusqué, avec sa
  propre rotation).
- Toggle Settings (gardé debug jusqu'à field-validation).

**Validation** :
- **Matrice data-loss** à nouveau, avec QUIC.
- **Débit re-mesuré sur le transport de PROD** (Hysteria2 / quinn-CC-configuré), **pas** sur
  un Caddy-h3 par défaut (finding m2), sur mauvais réseau, les 2 devices.
- **Inclassifiabilité** : pcap côté endpoint + nDPI/Wireshark → QUIC/HTTP-3 générique, pas
  de signature Frappuccino.
- **Heap-0** tient toujours.
- **Delta batterie + data** mesuré (retransmissions mobiles).
- **Delta taille `.so`/APK ET surface d'audit** acceptables = critère de gate explicite,
  pas seulement les Ko (finding M4 : tokio multi-thread + quinn + h3 sous le `.so` qui
  contient la crypto sensible vérifiée formellement).

**Gate 3 (productionisation)** : débit ≥ direct sur mauvais réseau (2 devices) **ET**
inclassifiable **ET** heap-0 **ET** zéro régression data-loss **ET** taille/surface/batterie
acceptables. → activer par défaut. Sinon : garder derrière le toggle / reconsidérer.

**Effort indicatif** : ~1-2 semaines.

---

## Findings de l'évaluation pliés dans ce plan

| Finding | Sévérité | Traité en |
|---|---|---|
| B1 — BBR de quinn expérimental/sous-performant | Bloquant | Phase 2 (spike mesuré + plan B Brutal-porté) |
| M1 — concurrence cap=6 + connexion QUIC partagée sous-spécifiée | Majeur | Phase 3 (modèle de connexion explicite + mesure p95) |
| M2 — pas d'équivalent `callTimeout` → permit gelé | Majeur | Phase 1 (plafond par-appel) + Phase 3 (keep-alive QUIC) |
| M3 — `upload_transport_reset()` à 5 sites + gates drain | Majeur | Phase 1 (câblage exhaustif + défèrement) |
| M4 — surface d'audit + taille `.so` | Majeur (coût) | Phase 2 (mesure taille) + Phase 3 (critère de gate) |
| m1 — fiabilité prouvée en netem, pas radio ; causalité supposée | Mineur | Phase 0 (instrumentation terrain = la donnée manquante) |
| m2 — gate mélange Caddy-h3 et transport de prod | Mineur | Phase 3 (débit re-mesuré sur transport de prod) |
| m3 — 2ᵉ pin TLS pour l'endpoint obfusqué | Mineur | Phase 3 (`pin.rs` paramétré par-transport) |
| m4 — feature `quic` à plomber sur 2 `Cargo.toml` ; commentaires périmés | Mineur | Phase 2 (plomberie nommée) |

---

## Résidu hors-plan

**Destination non-reliable** (« on voit *à qui* on parle ») : non résolu par l'obfuscation.
Front CDN partagé / VPN multi-tenant / rotation d'IP = **chantier distinct**, à trancher
selon la menace réelle (`ROADMAP §10.9`, `METADATA_EXPOSURE_MAP §8`).

---

*Plan transport — 14 juin 2026. Spec technique : `docs/TRANSPORT_QUIC_POC_SPEC.md`.
Pourquoi : `docs/POURQUOI_QUIC.md`. Décision/résultats : `ROADMAP §10.9`.*
