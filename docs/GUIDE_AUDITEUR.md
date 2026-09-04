# Guide de l'auditeur - Frappuccino

> **À destination d'un auditeur de sécurité externe.** Ce document rassemble
> tout ce que l'équipe a mis en place pour **faciliter votre travail** et vous
> oriente explicitement : voici comment vérifier nos affirmations, voici ce qui
> est déjà prouvé et comment le rejouer, voici les limites que nous assumons, et
> voici où concentrer votre attention.
>
> **Registre :** transparence. Nous préférons un risque écrit noir sur blanc à un
> risque caché. Là où le code et les scripts contredisent une phrase de ce
> document, **le code et les scripts l'emportent** - et signalez-nous l'écart.
>
> **Dépôt :** `github.com/therealshulgin/Frappuccino`, public. Lisez ce guide
> contre l'arbre de ce dépôt, pas contre un SHA : cet en-tête a longtemps épinglé
> `8172ff2` sur une branche privée et déclaré « dépôt local sans remote », deux
> renvois qu'aucun lecteur externe ne pouvait résoudre.
> **Dernière relecture contre le code :** 2026-09-04.
> **Licence :** **Apache 2.0** partout dans l'arbre (héritée de Tella FOSS, alignée
> le 2026-09-02 : les métadonnées Cargo déclaraient encore l'AGPL). Un passage à
> l'AGPLv3 reste une décision de publication à venir, item 8.2.5 du ROADMAP, non
> réalisée.
>
> **Documents amont (à lire en parallèle) :** `AUDIT_SCOPE_RUST.md` (périmètre +
> invariants, autoritaire), `docs/AUDIT_HANDOFF_2026-05-07.md` (handoff initial),
> `docs/ARCHITECTURE_TECHNIQUE_COMPLETE.md` (architecture courante), et **nouveau :
> `docs/design-review-2026-06-28/`** (couche de réflexion design, à lire en premier
> pour amorcer votre passe - voir §0bis). Ce guide ne les duplique pas ; il les met
> en perspective et ajoute le **mode d'emploi de vérification**.

---

## 0. Résumé pour l'auditeur pressé

Frappuccino est un fork de Tella FOSS : une application Android de
**témoignage vidéo chiffré de bout en bout** pour militants et journalistes en
contexte de saisie ou de coercition. Le design rend délibérément le contenu
passé **irrécupérable depuis le seul appareil** - seule la phrase BIP-39 papier
ré-dérive l'identité d'archive.

- **Le cœur d'audit est la couche cryptographique V2, écrite à 100 % en Rust**
  (`crypto-rs/`). Aucune primitive cryptographique n'est écrite par nous : nous
  câblons des briques auditées (RustCrypto, `dalek`, `chacha20poly1305`,
  `argon2`, `rustls`) ; ce que nous avons écrit est la **logique de protocole**
  (ratchet, key schedule, gestion des nonces, scellement, parsing). C'est elle
  qu'il faut scruter.
- **Surface non-Rust = annexe.** Kotlin (UI, orchestration upload) et Python
  (relais aveugle) ne sont pas le centre de gravité ; ils sont décrits ici comme
  contexte et zone de frontière, pas comme objet d'audit prioritaire.
- **Une suite de cinq preuves formelles machine-vérifiées** ①→⑤ couvre le cœur
  (zeroize-audit, diff-fuzz, Kani, TLA+, Tamarin). Chacune a un **runner
  reproductible** et un **contrôle négatif** qui falsifie quand on retire le
  mécanisme. §4 vous donne la commande de rejeu par item.
- **Mutation testing** (`cargo-mutants`) et **property testing** (`proptest`)
  mesurent que les tests *valent quelque chose*, pas seulement qu'ils passent.
- **Anti-dérive modèle/code.** Les preuves formelles sont **rejouées en CI**
  ([`.github/workflows/proofs.yml`](../.github/workflows/proofs.yml) : TLC + Tamarin + Kani
  + guard zeroize, sur tout changement `crypto-rs/**`), et la surface protocole est **gelée**
  par un test à `match` exhaustif : un domaine de signature ajouté ou retiré casse le build
  tant que le modèle Tamarin, le miroir serveur et les docs ne sont pas mis à jour. Le
  *model→code gap* sémantique restant est borné par les ponts (proptest sur le vrai ratchet,
  parité, diff-fuzz).
- **Robustesse crash / mort anormale.** La récupération du ratchet à travers une
  interruption (consume / persist / reload, rotation) est verrouillée en tests Rust
  déterministes, et la durabilité de la file d'upload est validée **on-device**
  (`ChunkUploadQueueDurabilityTest`).
- **Deux audits adverses inter-modèles** (red+blue exécutés par un modèle
  distinct, arbitrés) ont précédé cette remise. Le premier (avril→juin) a produit
  **deux bloquants**, déjà corrigés, et un **registre de risque-accepté** ; le
  second (**2026-06-26, 7 agents Opus, lecture seule**) a produit une vague de
  durcissement (oracle d'activité retiré, no-export FFI, MinIO en loopback, purge
  d'activité, gate de la section DEBUG) **livrée** (§8.1). Nous vous livrons les
  deux registres intacts (§6, §8).
- **R-C-1** (séparation de domaine explicite des signatures) ferme la trouvaille que
  la modélisation Tamarin avait laissée ouverte. Validée *cross-stack en live* contre
  le relais. Le modèle en consigne une autre depuis, ouverte, sur l'usage unique du
  flux de rotation : §4 ⑤.
- **Une couche de réflexion design (`docs/design-review-2026-06-28/`)** a été
  écrite **pour amorcer votre travail** : 8 rapports de rationale par domaine +
  une synthèse (`00-SYNTHESIS-AND-AUDIT-MAP.md`). C'est notre premier filet de
  réflexion adverse formalisé. **Lisez la synthèse d'abord** (§0bis).

**Si vous n'avez qu'une heure :** lisez la synthèse design (§0bis), puis §7
(« où porter votre attention »), puis attaquez les **frontières d'abstraction**
que §3 cartographie - c'est là, et non à l'intérieur des invariants déjà prouvés,
que vit le risque résiduel.

---

## 0bis. La couche de réflexion design (`docs/design-review-2026-06-28/`) - lisez-la en premier

Nouveau depuis cette remise : un dossier de **rationale de design adverse**, écrit
explicitement **pour amorcer un audit externe**. Ce n'est pas une preuve ni un
gate ; c'est une auto-critique honnête, domaine par domaine - *pourquoi* chaque
choix de design est bon, *pourquoi* il est implémenté ainsi, ses **résidus
assumés**, et des **questions pour un futur auditeur**.

| Fichier | Domaine |
|---|---|
| `00-SYNTHESIS-AND-AUDIT-MAP.md` | **La synthèse** : paris porteurs, forces transverses, tensions internes, carte de questions priorisée |
| `01-threat-model-and-motto.md` | Modèle de menace, motto, frontières de confiance |
| `02-ephemeral-ratchet-forward-secrecy.md` | Ratchet éphémère + forward secrecy |
| `03-relay-blind-reports-and-capability-addressing.md` | Reports relais-aveugles + adressage par capability |
| `04-transport-obfuscation-and-pinning.md` | Transport : obfuscation, épinglage, break-glass |
| `05-key-management-and-on-device-secrets.md` | Gestion de clés + secrets on-device |
| `06-rust-crypto-and-ffi-boundary.md` | Crypto Rust 100 % + frontière UniFFI |
| `07-capture-pipeline-and-data-loss-resilience.md` | Pipeline de capture + résilience perte-de-données |
| `08-server-relay-architecture.md` | Architecture serveur / relais |

**Comment l'utiliser (ordre conseillé) :**

1. **Lisez d'abord `00-SYNTHESIS-AND-AUDIT-MAP.md`.** Il compose les 8 rapports :
   il nomme les **3-4 paris porteurs** dont dépend tout le système (BET A : la
   phrase papier est la racine unique et réellement hors-appareil ; BET B : la
   forward secrecy est réelle au niveau octet, donc un appareil *saisi* n'expose
   rien du passé ; BET C : le relais est aveugle au repos et le résidu d'identité
   au repos n'est « qu'un nombre » ; BET D, plus faible : l'artefact expédié est
   l'artefact audité et le canal reste up).
2. **Vérifiez les paris porteurs.** Un faux sur l'un d'eux casse de grandes
   parts de la garantie. Le doc dit explicitement où chacun s'ancre dans le code.
3. **Attaquez les coutures inter-domaines** que la synthèse §4 (tensions
   internes) expose - dont **deux divergences doc-vs-code** que nous signalons
   nous-mêmes comme « or pour le prochain auditeur » (la réalité SNI, §8.5
   ci-dessous ; et un commentaire `StreamPreferences.kt` périmé sur le transport
   release).
4. La synthèse §5 est une **carte de questions priorisée par levier** ; servez-vous
   en comme backlog, mais ne la traitez pas comme exhaustive - c'est *notre* vue.

> ⚠️ Ce dossier est notre propre steelman. Il vous oriente, il ne vous lie pas.
> Là où il contredit le code, **le code l'emporte**, et signalez-nous l'écart.

---

## 1. Périmètre et modèle de menace

### 1.1 Périmètre

**Dans le périmètre (le centre d'audit) - workspace Rust `crypto-rs/` :**

| Crate | Rôle |
|---|---|
| `crypto-rs/core/` | BIP-39 (FR), HKDF, dérivation d'identité, ratchet éphémère, PIN store, mémoire sécurisée (`secret.rs`), séparation de domaine (`signature_domain.rs`) |
| `crypto-rs/stream/` | Format de blob STRM (encrypt/decrypt), client relais V2, épinglage TLS (`pin.rs`) |
| `crypto-rs/ffi/` | Surface UniFFI exposée à Kotlin (`frappuccino.udl` + `lib.rs`) |
| `crypto-rs/cli/` | Outillage hors-ligne (`frappuccino-cli`, `frappuccino-difffuzz-dump`, migrateur V1) |
| `crypto-rs/obfs-proxy/` | Proxy UDP de dé-obfuscation côté relais, **internet-facing** (§10.10) ; partage le module `salamander` avec le client |
| `crypto-rs/fuzz/` | Cibles `cargo-fuzz` |
| `crypto-rs/quic-spike/` | **Hors périmètre** : spike jetable de la Phase 2, non expédié (son `Cargo.toml` le dit) |

Le `.so` compilé est embarqué dans l'APK sous
`mobile/src/main/jniLibs/<abi>/libuniffi_frappuccino.so`. **Toutes** les
primitives cryptographiques de l'app passent par ces crates - pas de chemin JNI
caché, plus aucune cryptographie côté Kotlin (depuis la migration S8c.5).

**Annexe (contexte, pas centre d'audit) :**

- **Kotlin** (`mobile/`, `stream-crypto/`) : UI, gate de verrouillage,
  orchestration d'upload. De fines enveloppes au-dessus des bindings UniFFI. La
  **frontière FFI** (UniFFI → JNA → `.so`) est la zone grise à examiner ; la
  cryptographie elle-même n'y est plus.
- **Python** (`server/`) : relais aveugle FastAPI + MinIO. À traiter comme une
  **boîte noire hostile** - sa compromission ne doit pas livrer de clair. Les
  contrats de fil (corps de requêtes signés) sont verrouillés par des vecteurs
  de parité et **mirrorés byte-pour-byte** par `signature_domain.py`.
- **Hors périmètre explicite :** code legacy Tella (en cours de retrait,
  Phase 5/6.1.16 du ROADMAP), bindings Kotlin générés par UniFFI (régénérés
  déterministement depuis l'UDL), câblage CameraX/HEVC, configuration Gradle.

### 1.2 Modèle de menace

L'actif souverain est la **confidentialité des rushes** (vidéo de témoin) et la
**non-liaison du témoin** (anonymat). Le design **n'essaie pas** de protéger
contre un adversaire qui détient *à la fois* l'appareil *et* le PIN - c'est le
chemin de déverrouillage assumé. Au-delà, tout chemin de déchiffrement doit
exiger soit le ratchet (local à l'appareil, forward-secret), soit la phrase
papier (mode archive).

| Capacité de l'adversaire | Protégé ? | Mécanisme |
|---|---|---|
| Observateur réseau passif (contenu) | Oui | TLS 1.2+, pin SPKI, XChaCha20-Poly1305 sur chaque blob |
| Observateur réseau passif (métadonnée : qui parle au relais) | **Non revendiqué** | Le transport release est **ObfQuic/Salamander** (inclassibilité DPI tant que l'UDP passe), mais le SNI en clair est visible sur le chemin de repli `DirectTls` ; voir §8.5 |
| MITM actif avec chaîne CA valide | Oui | Pin SPKI (rejet *avant* validation de chaîne) **et** vérification de la signature `CertificateVerify` (post-RT-01) |
| Opérateur serveur lit les blobs | Oui (confidentialité) | `crypto_box_seal` → seule la clé d'archive x25519 descelle |
| Opérateur serveur altère les blobs | Oui | Tag XChaCha20-Poly1305, AAD lie l'en-tête + `chunk_count` (AAD CHUNKED) |
| Saisie appareil, PIN **connu** | Non (chemin assumé) | L'app déverrouille ; voie de déni assumée |
| Saisie appareil, PIN **inconnu** | Partiel | Argon2id 256 MiB × 4 garde le ratchet scellé ; ≠ phrase |
| Saisie appareil, bouton wipe martelé | Oui | Fichier ratchet wipé ; archive récupère via phrase papier seule |
| Rejeu d'une signature de verify capturée | Oui | Nonce atomic-pop + skew timestamp ±30 s |
| Troncation d'un blob CHUNKED au repos | Oui | AAD lie `chunk_count` (AAD CHUNKED) |
| Dump RAM cold-boot d'un appareil verrouillé | Best-effort | `mlock` + `zeroize`, `FLAG_SECURE` sur les écrans sensibles |
| Système Android compromis (root) | **Hors** | Game over, documenté ; la phrase papier reste la seule récupération |
| Extraction firmware (Cellebrite/GrayKey) | **Hors** | Game over, documenté |
| Compromission supply-chain des dépendances | Best-effort | Versions épinglées exact + `Cargo.lock` commité + `cargo deny` |

La version autoritaire et détaillée est `AUDIT_SCOPE_RUST.md §3`. Les adversaires
gradués (saisie passive → coercition → Dolev-Yao → relais hostile →
supply-chain) sont décrits dans `red_team.md §1`.

### 1.3 Invariants cryptographiques (ne doivent jamais dériver)

Une dérive sur l'un de ces points casse la compatibilité byte-niveau avec les
identités enrôlées en production. La référence canonique est
`AUDIT_SCOPE_RUST.md §4` ; la table ci-dessous est ce qu'il faut **spot-checker**.

- **BIP-39 :** PBKDF2-HMAC-SHA512, 2048 itérations, wordlist **française** NFD.
  `normalize_word` lève sur mot inconnu (pas de fuzzy match silencieux).
- **Contextes HKDF-SHA256 (octets UTF-8 exacts, gelés) :**
  `"stream.identity.ed25519.v1"`, `"stream.encryption.x25519.v1"`,
  `"stream.ratchet.chain0.v2"`, `"frappuccino-v2-ratchet-batch-seeds"`,
  `"frappuccino-v2-ratchet-next-chain"`, `"frappuccino-v2-ratchet-blob-mac"`.
  Verrou de test : `crypto-rs/core/tests/hkdf_contexts_lockstep.rs`.
- **X25519 :** dérivation libsodium `sk = SHA-512(seed)[..32]` + clamping
  (**pas** de conversion Ed→X).
- **Ratchet :** batch de 50 clés Ed25519 éphémères. Blob V2 = **4876 octets**
  (44 en-tête + 4800 slots + 32 HMAC). V1 (sans MAC) rejeté à l'exécution ; seul
  le migrateur CLI dédié lit V1.
- **STRM v3 (format courant, `VERSION_CURRENT = 0x03`) :** magic `STRM` +
  version + enveloppe scellée (80 o) + `grant_count` (toujours 0 ; un blob qui en
  déclare est refusé) + mode + payload.
  **Aucune identité d'auteur au repos** : l'`author_ed25519_pk` des formats
  *legacy* V1/V2 a été retiré de l'en-tête (WP-A / F-C1) ; les blobs V1/V2 restent
  lisibles en read-only. AAD CHUNKED = `header ‖ MODE ‖ nonce_prefix ‖
  chunk_count_BE_u32`. Source de vérité : `crypto-rs/stream/src/header.rs:28-44`.
- **PIN store :** Argon2id `m=256 MiB, t=4, p=1, tag=32B` + XChaCha20-Poly1305-IETF.
- **TLS :** rustls 0.23, `PinnedCertVerifier` SPKI SHA-256. Pins et hôte courants
  sont la **seule** source de vérité dans `crypto-rs/stream/src/pin.rs` et doivent
  matcher `mobile/src/main/res/xml/network_security_config.xml` byte-pour-byte. Le
  verifier accepte désormais un **ensemble de 3 pins** (union en temps constant,
  `pins: Vec<[u8;32]>`, `pin.rs:99`) : `PIN_SHA256_B64` (primaire `QnGK0K`,
  `pin.rs:36`) + `PIN_NEXT_B64` (break-glass `AmIDSg`, le cert actuellement servi,
  `pin.rs:46`) + `PIN_NEXT2_B64` (break-glass **off-host** `MUb4HH`, dormant,
  `pin.rs:62`). L'hôte épinglé est un **domaine** : `PINNED_HOST =
  "relay.shake-document-protect.org"` (`pin.rs:69`), plus une IP brute. Le gate
  Gradle `checkRustSoFresh` exige la présence des **3** pins dans tout `.so`.

> ⚠️ **Note pin :** des documents d'archive plus anciens citent des pins
> périmés. La valeur autoritaire vit dans `pin.rs` et le `network_security_config.xml` ;
> ne vous fiez pas à un pin recopié dans un doc.

---

## 2. Comment builder et lancer les gates

### 2.1 Reproductibilité d'environnement

- **Toolchain Rust épinglée** par `crypto-rs/rust-toolchain.toml` (canal
  **1.88.0**, auto-sélectionné dès le `cd crypto-rs`). MSRV déclarée 1.80 ; CI/dev
  buildent en 1.88.
- **Versions de dépendances épinglées exact** (pas de plage `^`/`~`) : la règle est interne
  et non publiée, mais son application se vérifie sans elle, dans les `Cargo.toml` du
  workspace et dans `crypto-rs/deny.toml` ; `crypto-rs/Cargo.lock` est commité.
- **Zéro `unsafe`** hors d'un unique module isolé : `crypto-rs/core/src/secret.rs`
  (wrapper `mlock`/`munlock` via `memsec`). Ce fichier porte `#![allow(unsafe_code)]`
  localement ; chaque bloc `unsafe` a un commentaire `// SAFETY:`. Tout le reste
  du workspace est `unsafe`-free (le scaffold UniFFI généré est exclu, code tiers
  non contrôlé).

### 2.2 Gates Rust (à passer à chaque merge)

```bash
cd crypto-rs/
cargo test --workspace --release          # suite unit + parité + e2e (#[ignore] exclus)
cargo clippy --workspace --all-targets -- -D warnings   # zéro warning (gate dur)
cargo fmt --all -- --check                # zéro diff
cargo deny check                          # advisories RustSec + allowlist licences (deny.toml)
```

Pour la supply-chain, vous pouvez en complément exécuter `cargo audit` contre
`crypto-rs/Cargo.lock` (RustSec) - nous vous y invitons explicitement dans le
cadre de votre engagement.

### 2.3 Fuzzing (`cargo-fuzz`, Linux + nightly)

Quatre cibles : `fuzz_decrypt_blob`, `fuzz_parse_strm_header`,
`fuzz_ratchet_deserialize`, `fuzz_pin_store_open`. Toute panique = bloquant.

```bash
cd crypto-rs/fuzz/
cargo +nightly fuzz run fuzz_decrypt_blob -- -max_total_time=60 --sanitizer none
```

Instructions complètes dans `crypto-rs/fuzz/README.md`.

### 2.4 Serveur (boîte noire)

```bash
cd server/
docker compose up -d
curl -ksf https://relay.shake-document-protect.org:8443/health   # → {"status":"ok"}
pytest tests/
```

Déploiement gaté à `--workers 1` (le cache de nonce est in-process - voir §6,
hypothèse de confiance). Le relais Vultr est joignable par **domaine**
(`relay.shake-document-protect.org`, A-record → `136.244.101.236`) pour la durée
de l'audit ; cert **auto-signé épinglé par SPKI** (stratégie *bêta*, **pas**
Let's Encrypt) ; **pins et hôte = ceux de `pin.rs`** (les 3 pins de l'union, hôte
= le domaine). MinIO est désormais lié à **127.0.0.1:9000** (loopback uniquement,
durcissement R-SRV-2) ; l'`access_log` nginx est `off` et les logs Docker sont
bornés.

### 2.5 Android

```bash
cd crypto-rs/
TARGETS=arm64-v8a ./build-android.sh    # .so par ABI + régénère les bindings Kotlin
cd ..
./gradlew :mobile:assembleDebug
```

> ⚠️ Le `.so` et les bindings générés **ne sont pas trackés par git** (régénérés
> par `build-android.sh`). Deux gates distinctes s'appliquent, et il faut les
> séparer.
>
> `checkRustSoFresh` compare un `mtime` (le `.so` doit être plus récent que
> `pin.rs`, que `ffi/src/frappuccino.udl` et que `ffi/src/lib.rs` — la surface
> UniFFI a été ajoutée le 2026-09-04, parce qu'éditer l'UDL régénère les bindings
> Kotlin sans rebuilder le binaire, et que rien ne le signalait) **et**
> fait un **byte-grep** des 3 pins SPKI dans le `.so` de chaque ABI, plus le
> marqueur `--features quic` (un `.so` rebuildé d'une branche obsolète qui aurait
> perdu un pin break-glass est rejeté), **et** un byte-grep **négatif** du marqueur
> `FRAPPUCCINO_LEGACY_STRM_COMPILED_IN` : Cargo unifie les features sur un graphe de
> build partagé, si bien qu'un `.so` construit dans un graphe qui contient la CLI
> reviendrait en décodant V1/V2 ; le gate le refuse, pour que la surface d'en-tête
> legacy ne rentre jamais dans la librairie expédiée. Elle garantit la fraîcheur, la
> présence du jeu de pins et l'absence du décodeur legacy, **pas** que le `.so`
> corresponde à la source auditée.
>
> `checkSoProvenance` (WP-E4) fait ce que la première ne fait pas : elle recalcule
> le SHA-256 de chaque `.so` expedié et échoue s'il ne correspond pas à
> `crypto-rs/PROVENANCE.txt`, le manifeste que `build-android.sh` réécrit à chaque
> build. Ce manifeste **n'est pas tracké par git** : il décrit des binaires qui ne
> le sont pas non plus, donc une copie commitée ne décrirait jamais que la
> dernière machine ayant buildé. Voir §2bis pour ce qu'un tiers peut en tirer, et
> pour la limite qui reste.

---

## 2bis. Vérifier qu'une APK vient bien du commit public

Ce que la chaîne établit, et ce qu'elle n'établit pas. À lire avant de conclure
quoi que ce soit d'une empreinte.

**Le maillon vérifiable.** Le workflow `release.yml` part d'un tag, refuse de
builder si l'arbre ne correspond pas exactement à `HEAD`
(`STRICT_PROVENANCE=1`, qui bloque aussi sur un fichier non suivi : un fichier
présent ici et dans aucun clone est une entrée de build que vous n'avez pas),
compile les trois `.so` depuis cette source, écrit `PROVENANCE.txt` dans le même
run, puis vérifie que les `.so` empaquetés dans l'APK sont bien ceux du
manifeste. Le bundle publié contient les `.so`, le manifeste, l'APK et un
`SHA256SUMS`.

**Comment le contrôler vous-même**, sur l'APK signée qu'on vous a remise :

```bash
unzip -o app.apk 'lib/*/libuniffi_frappuccino.so' -d /tmp/apkx
for abi in arm64-v8a armeabi-v7a x86_64; do
  echo -n "$abi "
  sha256sum "/tmp/apkx/lib/$abi/libuniffi_frappuccino.so" | awk '{print $1}'
done
grep '^sha256:' PROVENANCE.txt
```

Les empreintes doivent coïncider. Elles survivent à la signature : signer une
APK n'altère pas le contenu de ses entrées. C'est ce qui rend le contrôle
possible alors même que l'APK publiée par la CI est **non signée** (la clé de
signature n'est pas un secret de CI, et l'APK distribuée est signée sur la
machine de release, donc son empreinte à elle diffère).

**La limite, et elle est réelle.** Rien de tout cela n'est de la
reproductibilité bit-à-bit. Vous pouvez établir *que ce binaire est sorti de ce
run public sur ce commit public*. Vous ne pouvez pas recompiler le commit chez
vous et retomber sur les mêmes octets : les chemins sources absolus entrent dans
le binaire et `SOURCE_DATE_EPOCH` n'est pas épinglé. Vous déplacez donc votre
confiance du développeur vers le runner GitHub, ce qui est un progrès, pas une
preuve. Un manifeste portant `strict_provenance=0` est un build de développement
et n'établit rien du tout : le commit qu'il nomme peut être privé, réécrit ou
sale.

---

## 3. Carte des garanties - et de leurs FRONTIÈRES (votre outil n°1)

C'est le principe directeur du dossier, ce que nous appelons le *model→code gap*.
Chaque preuve garantit **une chose précise** et **abstrait** le reste. Un finding
qui vit *à l'intérieur* d'un périmètre prouvé est probablement faux (la preuve le
réfute). Un finding qui vit *dans une frontière* est peut-être réel. **Attaquez
les frontières.**

> **⟳ Instantané daté du 2026-07-02** (HEAD `c9582a3`, après crash-safety Q2 + gate
> anti-dérive Q1 ; ces preuves sont désormais rejouées en CI, `.github/workflows/proofs.yml`).
> **Les chiffres ci-dessous sont ceux de ce run et ont bougé depuis** ; l'état courant suit
> le tableau. Les
> **preuves déterministes** ont été **re-jouées vertes** au commit courant : **① zeroize-audit** PASS
> (opt=s : 2 appels `zeroize::Zeroize` · opt=2 : 36 `store volatile`) · **③ Kani** **4/4 harnesses** (dont
> `parse_header` **re-prouvé sur le format STRM V3** — l'en-tête avait changé *après* le run du 2026-06-23,
> donc la preuve no-panic ne couvrait plus le format expédié ; c'est fermé) · **④ TLA+/TLC** **4680 états**
> exhaustif · **⑤ Tamarin** **10 lemmes + 2 contrôles négatifs** qui falsifient. En complément :
> **`cargo test`** 257/257 (workspace, `--all-features`), **`clippy -D warnings`** vert, **`pytest`** serveur 86/86.
> **État courant, mesuré le 2026-09-04** : Kani **5/5 harnais** (le cinquième prouve que
> `parse_header` **refuse tout en-tête portant un grant**), TLC **2800 états** sur **six
> invariants**, Tamarin 10 lemmes + 2 contrôles négatifs, `cargo test` **254 verts (plus 3 marqués `#[ignore]`, l'e2e exigeant un relais vivant)**, `pytest`
> serveur **98/98**. Le serveur a changé depuis l'instantané : il a perdu deux routes de
> compatibilité Tella le 2026-09-03. Dates
> par-preuve dans `docs/{ZEROIZE_AUDIT_RATCHET,KANI_PROOFS,TLA_RATCHET,TAMARIN_RATCHET}.md` ; les runners
> ci-dessous sont inchangés. *(② diff-fuzz Kotlin↔Rust et `crypto-rs/fuzz/` = recherche non-déterministe,
> hors de cette passe de re-vérification déterministe.)*

| Preuve | Périmètre garanti | **Frontière (le risque résiduel vit ici)** |
|---|---|---|
| **① zeroize-audit** (`assert_zeroize_not_dse.sh`) | Le wipe du ratchet n'est pas dead-store-éliminé dans l'IR, y compris au profil shippé `opt=s` | **Un seul secret** (ratchet Rust). Pas la clé dérivée PIN, ni les session keys STRM, ni les `ByteArray` Kotlin, ni les spills de pile ailleurs |
| **② diff-fuzz** Kotlin↔Rust (759/759) | Kotlin et Rust **concordent** sur l'espace testé | Concordance ≠ correction (un **bug partagé** passe). Hors espace testé = inconnu |
| **③ Kani** (`parse_header`) | `parse_header` total/panic-free + offsets in-bounds sur toute entrée ≤ 200 o | Pas le chemin **decrypt complet**, ni l'AEAD, ni l'**encrypt**, ni le ratchet (intraitables) |
| **④ TLA+/TLC** (FSM ratchet, 2800 états) | Monotonie `batch`, anti-rejeu, no-rollback, use-once, bornage - **en mémoire** | Abstrait les **octets** : pas serialize/deserialize, pas HKDF, pas le signe réel, **pas la concurrence Kotlin**, **pas le rollback au niveau disque** |
| **⑤ Tamarin** (protocole Dolev-Yao) | Secrecy éph.+ltk, authentification slot, anti-rejeu, inforgeabilité RotationProof, no-rogue-batch, forward secrecy, **séparation de domaine** | Crypto **parfaite** + keygen **honnête** ; 1 slot représentatif/batch. Pas le code serveur réel, pas les canaux auxiliaires |
| **proptest** | Round-trips STRM/ratchet + invariants FSM sur schedules aléatoires | Test, pas preuve ; borné à la distribution des générateurs |
| **cargo-mutants** (decrypt 100 %, header 98 %) | Mutants logiques tués dans `core`/`stream` | Exclut `ffi/`, `cli/`, tests. Survivant `be_u16` prouvé équivalent |

**Anti-pattern de réfutation que nous nous interdisons** (et que nous vous
signalons pour que vous nous teniez honnêtes) : *« TLA+ prouve le no-rollback,
donc le finding rollback-par-restore est faux. »* Non - TLA+ prouve le
no-rollback **logique en mémoire** ; un rollback par restauration d'image disque
est **hors périmètre**. Ne jamais sur-revendiquer la couverture d'une preuve.

La carte architecturale (Android non-prouvé | Rust prouvé | relais Python) et la
position exacte de la couture FFI/HTTP sont détaillées dans `red_team.md §2`.

---

## 4. La suite formelle ①→⑤ - quoi prouvé + commande de rejeu

Quatre couches, cinq preuves, chacune machine-vérifiée et **non-vacueuse** (un
contrôle négatif retire le mécanisme et le vérificateur le rattrape). Chaque
preuve a sa doc dédiée (lien) avec le détail.

> **Plateforme :** Kani ③ et Tamarin ⑤ exigent **Linux/WSL** ; TLA+/TLC ④ tourne
> en **JVM Windows-native** (pas de WSL). zeroize-audit ① et diff-fuzz ② tournent
> partout (toolchain stable, pas de nightly).

### ① zeroize-audit - le wipe du ratchet n'est pas éliminé par le compilateur

**Prouvé :** l'IR LLVM montre que `EphemeralRatchet::zeroize_secrets()` (wipe de
`private_keys: [[u8;64];50]` + `next_chain_key`) lowering vers
`ptr::write_volatile(0)` + `compiler_fence`, que le contrat LLVM garantit
**jamais** dead-store-éliminé. Au profil shippé `opt=s` le wipe est hors-ligne en
**appels** `zeroize::Zeroize::zeroize` (un `grep 'store volatile'` naïf
*false-failerait* sur le profil expédié - le guard vérifie l'invariant
profil-robuste). Ferme le survivant `cargo-mutants` inhérent `drop -> ()`, qui est
intuable en safe Rust (un `Drop` n'est pas observable sans lire de la mémoire
libérée = UB).

```bash
bash crypto-rs/core/audit/assert_zeroize_not_dse.sh
```

Ré-émet l'IR à `opt=s` **et** `opt=2`, asserte « corps de `zeroize_secrets` =
`store volatile` inliné **OU** appel à une monomorphisation `zeroize::Zeroize::zeroize` ».
**Contrôle négatif validé :** régresser le wipe en `*sk = [0u8; N]` fait que le
compilateur élimine la fonction entière → guard `FAIL` (exit 1). Détail :
`docs/ZEROIZE_AUDIT_RATCHET.md`.

### ② diff-fuzz Kotlin↔Rust - parité byte 759/759

**Prouvé :** sur 759 vecteurs générés (seed déterministe `0x5EED_2026`, 150 cas
par API), les implémentations Kotlin et Rust produisent des **octets identiques**.
Un dumper Rust (`frappuccino-difffuzz-dump`, dans la CLI) appelle les **mêmes
fonctions FFI** que l'app ; un harnais JVM (`crypto-rs/difffuzz-jvm`) rejoue via
UniFFI→JNA et compare. Valide la fidélité du port **et** trouve des divergences
qu'aucune des deux suites de tests ne couvrirait.

```bash
# 1. Dump des vecteurs Rust
cargo run -p frappuccino-cli --bin frappuccino-difffuzz-dump -- 0x5EED_2026 150 <out>
# 2. Rejeu + comparaison côté JVM
cd crypto-rs/difffuzz-jvm && ./gradlew run   # cf. crypto-rs/difffuzz-jvm/README.md
```

Baseline 2026-06-06 : **759/759 matched**. Re-confirmé post-R-C-1 (bindings
régénérés, checksums OK).

### ③ Kani - les parseurs ne paniquent jamais

**Prouvé :** par bounded-model-checking sur **tout l'espace symbolique** d'entrée
(chaque octet, chaque longueur ≤ 200 o - un en-tête V3 complet plus une entrée de grant, `HEADER_SIZE_NO_GRANTS + GRANT_ENTRY_SIZE + 1`), `parse_header` (`stream/src/header.rs`)
ne panique jamais - pas d'OOB, pas d'overflow arithmétique, pas d'`unwrap`/`expect`
échoué. Le nombre de checks automatiques n'est pas recopié ici : il bouge à chaque
évolution du parseur, et le runner le rapporte. Un second harnais prouve que les
postconditions gardent les **slices de l'appelant** (`decrypt()`) in-bounds. Un
troisième confirme par preuve que le mutant `be_u16 | → ^` est **équivalent**
(bits disjoints → OR ≡ XOR), remplaçant l'argument à la main du verdict
cargo-mutants 8.4.4. Un quatrième (§10.10, transport) prouve que
`deobfuscate_in_place` - le parseur de dé-obfuscation Salamander, surface UDP
**internet-facing** du proxy obfs - ne panique sur **aucun** datagramme hostile
(tout `n` symbolique du contrat `recv` ; contenu concret + `#[kani::unwind]`
tiennent `BLAKE2b` et la boucle XOR hors d'un dépliage non borné qui sinon fait
OOM CBMC).

```bash
crypto-rs/run-kani.sh
# ou un harnais isolé :
crypto-rs/run-kani.sh --harness check_be_u16_big_endian_and_or_equals_xor
```

Le runner verifie contre une copie jetable du workspace (pin 1.88 retiré pour ne
pas écraser la toolchain Kani) ; l'arbre réel n'est jamais modifié. Harnais
`#[cfg(kani)]`-gatés (invisibles à `cargo build/test/clippy`). Baseline : **5/5
vérifiés, 0 échec** (Kani 0.67, backend CBMC). Le runner **compte** les harnais et
échoue s'il n'en revient pas exactement cinq : `cargo kani` sort déjà non-zéro sur
une preuve qui échoue, mais rien ne voyait une preuve qui **cesse d'exister**
(harnais supprimé, renommé, attribut retiré, sorti du build). Un `selftest` éprouve
l'analyse du résumé sans Kani, y compris sur le cas qui compte : un résumé
`4 vérifiés, 0 échec, 4 au total` est parfaitement cohérent avec lui-même, et seul
un compte attendu le distingue d'un succès. Détail : `docs/KANI_PROOFS.md`.

### ④ TLA+/TLC - la FSM du ratchet, exhaustivement

**Prouvé :** sur **2800 états distincts** explorés exhaustivement (toutes
interleavings), la machine à états du ratchet respecte six invariants - `TypeOK`,
`AntiReplay` (aucun couple `(batch, slot)` signé deux fois), `NoRollback` (aucun
retour vers un batch passé), `BoundedBatch` (≤ 50 slots/batch), `ConsumedWiped` (le
masque enregistre fidèlement chaque signature) et `RotationAlwaysPossible` (il reste
toujours un slot pour tourner, ce qui encode la réserve du dernier slot du batch,
`ratchet.rs`) - plus une propriété temporelle, `MonotoneBatch` (le numéro de batch ne
décroît jamais). Réserve de portée à connaître : le modèle s'arrête au ratchet. La file
de preuves de rotation côté client vit un étage au-dessus et a sa propre borne - le
client refuse d'avancer le batch quand elle est pleine, plutôt que de produire une
preuve qu'il ne saurait plus regénérer. Le code place cet état après quelques centaines
d'authentifications répondues-mais-échouées d'affilée, ce qui veut déjà dire enrôlement
perdu ; TLC ne modélise ni cette file ni cette borne. Les bornes du modèle sont petites
*à dessein* - les invariants sont
**structurels** (indépendants du nombre de slots), donc tenir à 3 = tenir à 50.

```bash
crypto-rs/core/proofs/run-tlc.sh      # JVM, Windows/Linux/macOS, pas de WSL
```

Télécharge `tla2tools.jar` dans `.tools/` au premier run. **Contrôle négatif
validé :** retirer le garde use-once (`i ∉ consumed`) fait que TLC reporte
immédiatement `Invariant AntiReplay is violated` avec contre-exemple concret.
Baseline : **no error, 2800 états** (TLC 2.19 ; le compte a baissé depuis les 4680 de la
baseline de juin, `docs/TLA_RATCHET.md` dit pourquoi). Détail : `docs/TLA_RATCHET.md`.

### ⑤ Tamarin - le protocole sous attaquant actif (Dolev-Yao)

**Prouvé :** sous un attaquant réseau actif qui contrôle l'ordonnancement,
injecte/modifie/rejoue, et compromet l'état à la demande, le protocole
enrollment/rotation/auth satisfait **10 lemmes** (secrecy des clés
éphémères + long-terme, authentification du détenteur de slot, anti-rejeu de
nonce one-shot, inforgeabilité de `RotationProof`, lignée sans batch malhonnête,
ancrage racine, forward secrecy). Composés, `root_authentic` + `rotation_lineage` +
`rotation_authentic` donnent la garantie de tête : **tout batch autorisé d'une
identité honnête remonte, par signatures genuinement détenues par l'appareil,
jusqu'à son propre enrôlement ; un attaquant actif ne peut injecter de batch
forgé ou malhonnête.**

```bash
crypto-rs/core/proofs/run-tamarin.sh            # prouve les 10 lemmes
crypto-rs/core/proofs/run-tamarin.sh negative   # + les 2 contrôles négatifs
```

Exige **WSL** (Haskell + Maude) ; télécharge tamarin 1.12.0 + Maude 3.5.1 dans
`.tools/`. Baseline (rafraîchie 2026-06-12 pour R-C-1, puis ramenée à **10 lemmes
+ 2 contrôles négatifs** quand la Phase C *relais-aveugle* a retiré le flux
d'auth d'archive - les lectures d'archive sont désormais sans-identité, donc le
domaine `0x04 ArchiveAuth` et son lemme `archive_auth_origin` sont **retirés par
construction**) : **10/10 lemmes vérifiés**, ~4-6 s, terminant. **Deux contrôles
négatifs falsifient comme attendu** :

| Contrôle | Édition | Résultat |
|---|---|---|
| NC1 | Retirer la vérif de signature Ed25519 dans `Server_Verify` | `auth_slot_origin` **falsifié** (9 pas) |
| NC2 | Collapser les tags `'auth'`/`'rotate'` (clé éphémère) | `rotation_authentic` **falsifié** (8 pas) |

**Deux trouvailles** que la modélisation a fait remonter (le formel est le plus
utile quand il *refuse* une revendication trop large) :

1. **L'authentification porte sur la clé de slot, pas sur le couple (identité,
   slot)** - un unknown-key-share sans transfert d'autorité : le nonce one-shot
   et le fait que seul le détenteur du slot peut signer font que l'attaquant ne
   gagne rien qu'il ne pouvait déjà faire en tant que lui-même. Garantie prouvée
   sur le **détenteur du slot**, ce qui est le sens utile.
2. **La sûreté de signature dépendait de la séparation de contexte** - désormais
   **explicite via R-C-1** (§5). Fermée.

**Trouvaille ouverte, consignée dans le modèle** (bloc `OPEN ITEM` de
`RatchetProtocol.spthy`, juste après `nonce_use_once`) : l'usage unique d'un slot
n'est énoncé par **aucun** des dix lemmes. `ConsumeSlot` n'apparaît dans pas un seul,
et la propriété ne survit que par la **linéarité** du fait `SlotAvail` - rendez-le
persistant et les dix lemmes passent encore pendant que le serveur fait tourner un
slot indéfiniment. Sur le flux de rotation elle est carrément falsifiable : trois
formulations ont été écrites et **les trois ont été falsifiées**. Le contre-exemple est un
*rotate-to-self* : l'enrôlement étant ouvert, on enrôle une identité à soi et on
soumet une rotation dont le nouveau batch contient la clé du signataire, si bien que
le serveur réinstalle le slot qu'il vient de consommer. **Le relais fait la même
chose** : `rotate_batch` écrit les clés soumises telles quelles et remet
`consumed_indices` à vide sans vérifier que la clé du signataire est absente du
nouveau batch. Ce n'est pas un gain d'attaque - il faut déjà détenir un slot autorisé -
mais c'est une garantie que la documentation promettait et que le modèle ne délivre
pas. Le lemme a été retiré plutôt que plié ; les dix lemmes du modèle restent verts. C'est
exactement le genre de résidu que le registre du §8 s'engage à ne pas taire.

Détail : `docs/TAMARIN_RATCHET.md`. Le modèle (`RatchetProtocol.spthy`) cite ses
sources de vérité : `ratchet.rs`, `identity.rs`, `signature_domain.rs`,
`stream/src/protocol.rs`, et le **vérifieur** serveur (`auth_v2.py`) - car les
conditions d'acceptation du serveur *sont* l'oracle de sécurité.

### Synthèse de couverture par couche

| Couche | Outil | Prouve |
|---|---|---|
| Compilateur | zeroize-audit ① | le wipe secret n'est pas DSE (LLVM IR) |
| Marshalling | diff-fuzz ② | parité byte Kotlin↔Rust (759/759) |
| Code | Kani ③ | `parse_header` total ; offsets gardent les slices appelant in-bounds |
| Machine à états | TLA+ ④ | batch monotone / use-once / anti-rejeu (2800 états) |
| Protocole | Tamarin ⑤ | enroll inforgeable, challenge-response authentifié, lignée de rotation, secrecy, forward secrecy - sous attaquant actif |

---

## 5. R-C-1 - séparation de domaine explicite des signatures

C'est la remédiation cryptographique de tête issue de l'audit adverse, et la
clôture de la trouvaille Tamarin.

**Le problème (latent, pas un break actuel).** À l'origine, quatre contextes de
signature Ed25519 existaient : `/auth/v2/verify` (slot éphémère, `nonce‖ts`, 40 o),
`/api/v2/archive/auth` (clé long-terme, `nonce‖ts`, 40 o ; ce flux a depuis été
retiré, lectures d'archive sans-identité), `/auth/v2/rotate-batch` (slot éphémère,
`concat(50 pk)`, 1600 o), `/auth/v2/enroll` (clé long-terme, `concat(50 pk)`,
1600 o). Deux clés étaient **dual-use** (le slot signe auth ET rotation ; la
long-terme signait enroll ET archive). Avant R-C-1, la séparation entre les deux
usages d'une même clé reposait **implicitement** sur la longueur du message
(40 ≠ 1600) et sur la disjonction des arbres de clés - **aucun tag de domaine
explicite**. Tamarin a falsifié `rotation_authentic` et `root_authentic` sous
l'hypothèse que les deux messages puissent coïncider : une signature d'auth
rejouée comme preuve de rotation, une signature d'archive rejouée comme enrôlement
malhonnête.

**Le correctif (`da56da4`, refresh Tamarin `6b3701e`).** Chaque message signé
porte désormais un **tag de domaine d'un octet**, préfixé avant signature et
mirroré byte-pour-byte par le serveur avant vérification :

| Tag | Domaine | Clé | Message | Endpoint |
|---|---|---|---|---|
| `0x01` | `AuthChallenge` | slot éphémère | `nonce‖ts_be_u64` | `/auth/v2/verify` |
| `0x02` | `BatchRotation` | slot éphémère | `concat(50 pk)` | `/auth/v2/rotate-batch` |
| `0x03` | `Enrollment` | long-terme | `concat(50 pk)` | `/auth/v2/enroll` |
| `0x04` | `ArchiveAuth` (**RETIRÉ**, Phase C) | long-terme | (n/a) | (lectures d'archive sans-identité) |

> **Mise à jour 2026-06-28 - le schéma de tags a grandi.** Le domaine `0x04
> ArchiveAuth` est désormais **retiré par construction** : la Phase C
> *relais-aveugle* a rendu les lectures d'archive **sans-identité** (adressage par
> capability), donc il n'y a plus de signature de challenge d'archive par la clé
> long-terme. La valeur `0x04` reste **réservée** (jamais réutilisée) pour la
> stabilité du format de fil. `0x05`/`0x06` sont dans le **même état** : ils avaient
> été spécifiés pour un modèle de provenance à manifeste signé, supprimé par le recul
> métadonnées du 2026-06-25 au profit du modèle hash + Bitcoin, qui ne stocke ni
> manifeste ni signature. Rien ne les émet, rien ne les vérifie ; ne cherchez pas de
> signatures hors-ligne à auditer. Le seul **vrai** ajout au-delà des 4 tags d'origine
> est `0x07`/`0x08` (capabilities de report relais-aveugle Phase C, vérifiées par le
> relais sur `PUT /file/{rid}/{name}`). La table de
> référence vivante et autoritaire est l'en-tête de
> `crypto-rs/core/src/signature_domain.rs`.

- Source Rust : `crypto-rs/core/src/signature_domain.rs` (enum + `tag()` +
  `prefixed()`).
- Miroir serveur : `server/app/signature_domain.py` (mêmes octets pour les tags
  à miroir serveur).
- `sign_and_advance`/`advance_batch` **hardcodent** leur domaine en interne
  (zéro changement d'appelant Kotlin) ; à l'origine `sign_once` dual-use était
  scindé en deux méthodes FFI ; le chemin d'archive a depuis disparu côté
  serveur (lectures sans-identité).
- Sites de vérification serveur ajustés (puis l'oracle d'archive retiré, Phase C).
- Tests : cross-domaine in-crate (signer-domaine-A ne vérifie pas en B) + parité
  ratchet → **crypto-verify autoritaire et non-circulaire**.

**Pourquoi c'est de la defense-in-depth, pas un patch de vuln :** il n'y avait
**pas** de forge end-to-end sur l'ensemble d'endpoints actuel (le red l'a
lui-même déclassé en latent). Le risque cristallisait le jour où un 3ᵉ signeur
« blob court contrôlé par le serveur » serait ajouté, ou si la reconstruction de
longueur côté serveur dérivait. Le tag rend la séparation **structurelle** plutôt
que dépendante de longueurs qui ne se croisent jamais. Le correctif **renforce
strictement** les invariants prouvés - il ne peut invalider TLA+/Kani/diff-fuzz
(il opère au-dessus de la couche de composition de message, ou ils verraient
simplement la nouvelle constante).

**Validation cross-stack en live (2026-06-12).** Le serveur a été déployé
R-C-1 (marqueurs conteneur `SIG_DOMAIN` vérifiés). Le test E2E Rust passe **3/3
en live** contre le relais (TLS épinglé) : enroll `0x03`, verify `0x01`, rotate
`0x02`. (Le domaine d'archive `0x04` a depuis été retiré, Phase C relais-aveugle :
les lectures d'archive sont sans-identité, donc plus aucun challenge signé par la
clé long-terme.)

Vous pouvez rejouer l'E2E live (réseau requis) :

```bash
cargo test -p frappuccino-crypto-stream --test e2e_protocol --release -- --ignored
```

---

## 6. Mutation testing, property testing et autres filets

### cargo-mutants (le signal le plus fort)

Le mutation testing injecte des fautes (inverser une comparaison, supprimer une
ligne, remplacer une valeur de retour) et vérifie que la suite les **attrape**. Un
mutant *survivant* marque un comportement que les tests ne fixent pas - un vrai
gap que la couverture de ligne masque.

```bash
cargo install cargo-mutants --locked
cargo mutants                                    # sweep complet core + stream
cargo mutants -f stream/src/header.rs            # une frontière de confiance à la fois
cargo mutants --in-diff <(git diff origin/main)  # seulement les lignes d'un PR
```

Config (timeout par mutant, `exclude_globs` pour ffi/cli/fuzz/tests) dans
`crypto-rs/.cargo/mutants.toml`. Les deux parsers sur le chemin de
ciphertext-non-fiable sont à 100 % / 98 % :

- `stream/src/decrypt.rs` : **67/67 viables attrapés (100 %)** après
  `tests/decrypt_boundaries.rs` (les 11 survivants étaient aux bords `±1`).
- `stream/src/header.rs` : **48/49 viables (98 %)** ; le seul survivant est le
  mutant **prouvé équivalent** `be_u16 | → ^` (confirmé en preuve par Kani ③).
- `stream/src/salamander.rs` (transform obfs, §10.10) : **17/18** ; l'unique
  survivant `reserve(+→*)` est **équivalent** (`Vec::reserve` n'est qu'un hint de
  capacité, le contenu reste invariant - même classe que le `be_u16` ci-dessus).
- `obfs-proxy/src/lib.rs` (proxy de-obfs internet-facing, §10.10) : **21/39 viables**
  après le test `gate_requires_each_initial_marker` (qui fixe la logique de bits du
  gate anti-DoS, sinon non couverte par l'echo qui n'envoie qu'un Initial valide). Les
  18 survivants vivent **hors data-plane** : logger de stats (observabilité, 0 impact
  correction), reap idle + `run()` (timing / entrée, **field-validés** ; réclameraient
  injection d'horloge ou test d'intégration). Le **data-plane** - dé-obfuscation,
  forward, longueur **et** marqueurs du gate - est couvert par la mutation **et** Kani
  no-panic (③) **et** proptest.

> ⚠️ Le sweep complet est lent (~4 h sur ~195 mutants) ; il tourne en CI
> (`mutants.yml`, sweep hebdomadaire ; elle a longtemps été dormante faute de
> remote, ce n'est plus le cas depuis la publication du dépôt). En local, scopez
> par fichier `-f`.

### proptest (round-trip + invariants FSM)

Property-based testing déterministe (shrinking, sans nightly, pin `proptest=1.8.0`) :
round-trip encrypt/decrypt STRM + ratchet serialize + **invariants FSM** du
ratchet sur schedules aléatoires - c'est un pont avec TLA+ ④. §10.10 ajoute le
**round-trip + no-panic Salamander** (`stream/tests/proptest_salamander.rs`) et le
**no-panic du gate** internet-facing (`obfs-proxy`, complément échantillonné de la
preuve Kani sur `deobfuscate_in_place`).

```bash
cargo test   # inclut core/tests/proptest_ratchet.rs + stream/tests/proptest_roundtrip.rs
```

### Couverture

90,39 % de lignes (`cargo-tarpaulin`, e2e `#[ignore]` inclus) au moment du gate
S9.3 ; rapport HTML sous `crypto-rs/coverage/`. La couverture est **nécessaire
mais faible seule** - nous la couplons au score de mutation, qui est le vrai
juge.

La logique complète de « tableau de bord de passe d'audit déterministe »
(findings SARIF par CWE ↓ monotone, score de mutation ↑, etc.) est dans
`docs/invariants-ratchet-verification.md` Partie 3.

---

## 7. Où porter votre attention (recommandations explicites)

Vous avez l'œil neuf et adversarial qu'aucune boucle d'agents ne remplace. Notre
méthodologie (`docs/methodologie-securite-code.md`) réduit la surface ; elle ne
la ferme pas. Concentrez-vous **chirurgicalement** là où l'analyse statique est
la plus faible et le blast radius le plus grand : le crypto et les frontières de
confiance.

**0. Le relais aveugle l'est au repos, pas dans l'instant.** Prenez cette question
en premier, parce que c'est celle dont la réponse est la plus inconfortable et que
nous ne voulons pas que vous la trouviez seul. Sur le disque du relais il n'existe
aucun lien `identité → report` : les reports sont adressés par une capacité dérivée
de la phrase (§8.7 de l'architecture), et le `sub` du JWT n'est jamais écrit. Mais
un relais **compromis en vif** voit l'IP à chaque connexion, et voit une fois la
clé pseudonyme, au PUT qui crée un report (`server/app/routes/upload.py`, le JWT
sert au budget anti-abus puis est jeté). Rien dans l'architecture ne l'en empêche
aujourd'hui. Dépasser ce résidu demanderait de découpler l'anti-sybil de l'identité
(jetons aveugles ou credentials anonymes émis à l'auth ratchet, dépensés à la
création), ce qui touche la lignée de batches et le budget par identité. Nous ne
l'avons pas engagé. Dites-nous si vous jugez ce résidu acceptable pour la
population visée, et si le coût de la solution vaut sa complexité.

**1. La frontière FFI Rust↔Kotlin (la couture prouvé/non-prouvé).** Tout export
retourne des **copies** (`Vec<u8>`/`ByteArray`) ; le wipe côté Kotlin est
best-effort (le GC JVM peut copier/déplacer). Cherchez un secret (clé dérivée PIN,
session key, ratchet déscellé) qui **survit sur le heap JVM**. Vérifiez les
chemins de panique : `Cargo.toml` met `panic = "unwind"` pour que `catch_unwind`
UniFFI piège et que les `Drop`/`Zeroizing` tournent - existe-t-il un chemin où un
panic **abort**e quand même (double-panic dans un Drop, OOM d'allocation) ? Un
abort = pas de zeroize. (Nous avons cherché et n'avons pas trouvé de chemin ; voir
les résultats négatifs ci-dessous - challengez-les.)

> **Campagne forensique on-device.** Ces surfaces (heap JVM, tombstones, FS/scratch,
> panicWipe, MediaCodec/VRAM) ont été **exécutées sur device** : verdict par surface,
> le finding **JWT-en-heap** et son fix, et les résidus assumés sont dans
> [`FORENSIC_VALIDATION_REPORT.md`](FORENSIC_VALIDATION_REPORT.md) (méthodologie +
> signatures de fuite falsifiables dans
> [`FORENSIC_VALIDATION_PLAN.md`](FORENSIC_VALIDATION_PLAN.md)). Le finding JWT-en-heap
> est désormais **fermé par construction** (`cc833a3`, validé device 2026-06-15,
> ROADMAP §10.7) : le PUT du chunk, le POST du report **et** la recovery sont **tous
> en Rust** (`reqwest`, bearer lu côté Rust depuis le holder `UPLOAD_JWT`, jamais via
> la FFI), donc le `Bearer` n'entre **jamais** dans la pile HTTP JVM. Preuve : heap-dump
> **en session active = `eyJ=0` / `Bearer eyJ=0`** (le bearer ne vit que dans le holder
> `Zeroizing` natif, hors heap Dalvik). Le résidu RAM-in-window précédemment calibré en
> §2.4 est donc **supersédé** (résidu = 0). Depuis le **flip release 2026-06-19**, ce
> chemin Rust est le **défaut sur tous les builds** (`RustUploadTransport.enabled=true`)
> avec un **filet OkHttp** : un binding natif malsain en release (strip R8 / mismatch ABI,
> des `Error` que l'ancien catch ratait) désactive le transport Rust process-wide et
> bascule sur OkHttp - **blob jamais perdu**. Validé en **build release R8 réel** (OnePlus :
> `transport=rust` sur tous les chunks, filet jamais déclenché). La matrice réseau dégradé
> + l'A/B OnePlus (2026-06-16) montrent 0 perte de 0 à 20 % de perte. *(**Mise à jour Lot 3
> 2026-06-27 - le release vise désormais `ObfQuic`, plus `DirectTls`.** `RustUploadTransport.kt:46`
> met `mode = OBF_QUIC` pour **debug ET release** (commit `f3d648a`, fermeture D-1). Le bearer reste
> heap-0 sur les deux chemins. Le transport empile QUIC-BBR (×5-15 vs cubic sous perte) + obfuscation
> Salamander + un **fallback `DirectTls` par chunk** conservé (UDP bloqué → DirectTls, exposé par le
> marqueur `transport_used`), côté client `crypto-rs/stream/src/quic.rs` et `salamander*.rs`, côté
> serveur la crate `crypto-rs/obfs-proxy`. Détail transport + réalité SNI en §8.4 et §8.5. Ces fichiers
> sont dans le scope `crypto-rs/` et sont désormais sur le **chemin release** - lisez-les en priorité.)*

**2. Le corps de `decrypt.rs` (au-delà de `parse_header`).** Kani couvre le
header ; le corps et l'**encrypt** le sont moins. Réutilisation de nonce
(préfixe CHUNKED tiré d'un CSPRNG par blob ? session key jamais réutilisée entre
blobs ?), troncation/réordonnancement (le rejet V1-CHUNKED est-il étanche *avant*
allocation ?), malléabilité de l'enveloppe scellée.

**3. `pin.rs` - épinglage TLS + vérification de signature.** Le fix RT-01 délègue
la vérification du `CertificateVerify` à `rustls::crypto::verify_tls1[23]_signature`.
Un auditeur avec expertise rustls est explicitement invité à tracer cette
délégation et à confirmer que le pin n'est plus trivialement contournable par un
attaquant détenant le cert public.

**4. La surface forensique au repos (saisie appareil).** C'est là que la
confidentialité E2E peut être contournée **sans casser la crypto** : fenêtre de
plaintext MP4 en staging sur crash/force-kill, efficacité de `secure_delete` sur
flash (le wear-leveling échappe à l'overwrite physique - limite intrinsèque que
nous assumons), métadonnées de timeline. Ces surfaces vivent **entièrement sous
toutes les preuves** (qui sont Rust-scoped). Voir le registre §8.

**5. Le ratchet - gaps opérationnels.** Persistance/rollback au niveau
disque/process (TLA+ ne prouve le no-rollback qu'en mémoire), concurrence Kotlin
(auto-rotate vs workers d'upload). Et R-C-1 (§5), même si fermé, mérite votre
relecture du tag de domaine côté Rust **et** Python.

**6. Le relais Python (hypothèses de confiance).** JWT HS256 secret unique (pas
de rotation), confusion d'algorithme (`alg:none`), séparation de scope
stream/archive sur **toutes** les routes, IDOR sur les reports, anti-rejeu de
nonce sous concurrence. (Nous avons confirmé ces points fermés ; ils dépendent de
`--workers 1`.)

**Surfaces qu'aucune des passes précédentes n'avait couvertes** (signalées par le
contre-audit historique, `OLD/BLUE_TEAM_COUNTERAUDIT_2026-04-21.md §5.4`, et
depuis traitées mais qui méritent votre regard frais) : les contextes HKDF
byte-exact, l'atomicité de `ratchet_registry.py` sous concurrence, le câblage
AEAD-failure → `PinAttemptTracker` côté UI.

---

## 8. Registre des limites et risque-accepté (transparence)

Nous énonçons ces points **noir sur blanc** : un risque accepté tu = un risque
caché. Vous êtes libre de re-qualifier n'importe lequel comme bloquant pour votre
engagement.

### 8.1 Issu du premier audit adverse inter-modèle - état courant

L'audit a produit 7 findings, tous contre-vérifiés par une équipe blue distincte
(aucun faux-positif). Les deux rapports sont **internes et non publiés** : ils
énumèrent des faiblesses et se lisent comme une carte d'attaque. Communicables à
un auditeur sur demande. Deux étaient **bloquants**, **déjà
corrigés** ; un latent **corrigé** ; quatre sont **risque-accepté documenté**.

**Corrigés (ne sont plus des risques ouverts) :**

- **R-E-1 / R-G-1 (bloquants, corrigés `2b48610`).** La section DEBUG
  (« CALIBRATION ») était câblée **inconditionnellement** et expédiée en
  **release** ; le gate `isDebuggable()`/`debugRawAllowed()` documenté comme la
  protégeant était du **code mort (0 appelant)**. Conséquence : sur un build
  release, activer le toggle « BITRATE FIXE » faisait écrire la vidéo de témoin
  **déchiffrée** at-rest dans `filesDir/debug_raw*` - récupérable d'un appareil
  saisi **sans la phrase BIP-39** (l'E2E-at-rest tombait à la protection
  lockscreen-OS). Le contre-audit a trouvé un **frère sous-compté** : les
  répertoires `debug_raw_hevc/` et `debug_rolling/` que ni le cleaner ni le
  panicWipe ne touchaient. **Fix racine = gater toute la section DEBUG derrière
  `BuildConfig.DEBUG`** → ferme R-E-1 + son frère + R-G-1 d'un seul commit (R8
  strip le conteneur + findViewById + listeners). Build vert debug **et** release.
- **R-E-2 (corrigé `85a3c50`).** La base SQLite `androidx.work.workdb` de
  WorkManager retenait en clair les chemins de fichiers chunk + URL relais +
  report IDs (une timeline forensique liable au témoin), et **survivait au
  panicWipe**. Fix = `WorkManager.cancelAllWork()` + `pruneWork()` au panicWipe.
- **R-C-1 (corrigé `da56da4` + Tamarin `6b3701e`).** Voir §5.

**Risque-accepté documenté (réels, bornés, device-dépendants - ils n'exposent
PAS les rushes passés, la forward secrecy tient) :**

- **R-D-1 - PIN 6 chiffres, pas de wipe-after-N, binding Keystore faible.** Borné
  par Argon2id 256 MiB **et** par un premier gate `EncryptedSharedPreferences`/
  MasterKey (le blob ratchet est doublement enveloppé). Le brute-force offline
  exige **d'abord** l'extraction du MasterKey du Keystore - dur sur TEE non-rooté,
  faisable sur rooté/no-TEE. *Recommandation chiffrée :* wipe-after-N en **opt-in
  défaut OFF** (le risque de perte de témoignage sur fat-finger > le gain
  anti-coercition, déjà borné) ; offrir une passphrase alphanumérique ≥ 6 ;
  demander StrongBox + auth-binding où disponible.
- **R-D-2 - `ratchetDerivedKey` + ratchet vivants en RAM JVM tant qu'UNLOCKED ou
  en enregistrement.** L'auto-lock ne s'arme que `backgrounded` et **diffère**
  pendant un enregistrement (par design : ne jamais wiper pendant une capture).
  Exploit = heap dump (root/forensic live) sur appareil déverrouillé/en-cours.
  N'expose pas les rushes passés (session keys scellées par blob). Durcissement
  post-audit identifié : clé en Rust (mlock) derrière un handle opaque + timer
  idle foreground.
- **R-C-2 - rollback du blob ratchet par restore d'image disque.** Exploit =
  root + image + restore. Le serveur rejette la ré-utilisation via
  `consumed_indices` (pas de forge serveur) ; `allowBackup="false"` ferme la
  variante `adb backup`. Impact = érosion forward-secrecy **locale** des slots
  restants. Limite intrinsèque d'un état fichier sans compteur matériel monotone
  (RPMB pas toujours disponible) sur appareil pleinement rooté/saisi.

**Résultats négatifs (ont *tenu* sous attaque - listés pour que vous ne les
re-souleviez pas sans raison) :** réutilisation de nonce STRM (session key + nonce
frais par blob via `OsRng`, jamais injectables par l'appelant) ; troncation V1
CHUNKED (rejetée avant tout travail, V2 lie `chunk_count`) ; malléabilité
en-tête/enveloppe (tout l'en-tête est dans l'AAD ; le nonce de scellement dérive
de la clé du destinataire) ; confusion d'algorithme/scope JWT (`algorithms=[HS256]`
pinné partout, cloisonnement stream/archive réel) ; IDOR reports (adressage par
capacité relais-aveugle `report_id = H(report_pk)` 128 bits, lié par write-sig, plus
de `owner==user`) ; path traversal blob (double garde regex +
strip) ; downgrade/bypass TLS (trois couches - `pin.rs`, NSC, OkHttp - épinglent
le même jeu de pins SPKI) ; panic FFI →
abort → no-zeroize (pas de chemin double-panic trouvé) ; double-consommation de
slot (mutex côté Rust + `synchronized(ratchetLock)` côté Kotlin) ; race
pop-then-verify du nonce (lock + persistance avant verify, `--workers 1`). Détail
ligne-à-ligne dans les rapports red (§4) et blue, internes et non publiés,
communicables sur demande.

### 8.1bis Second audit adverse (2026-06-26, 7 agents Opus) - remédiation livrée

Une seconde passe adverse en **lecture seule** (1 critique-design + 3 duos
red/blue, 7 rapports) a précédé cette remise. La remédiation a été livrée en lots
(1, 2, 4, 4b). État courant :

**Corrigés (ne sont plus des risques ouverts) :**

- **H-1 / R-SRV-1 - oracle d'activité d'identité retiré.** La route
  `GET /auth/v2/status/{pk}` exposait l'état d'activité par clé publique (un oracle
  qui liait une identité à une présence/cadence). Elle est **supprimée**
  (chercher le commentaire `# GET /auth/v2/status/{ed25519_pk} — REMOVED` en fin de
  `server/app/routes/auth_v2.py`, et sa contrepartie dans `server/app/models.py` ; cités
  par marqueur et non par numéro de ligne, qui a déjà dérivé deux fois).
- **Section DEBUG « CALIBRATION » gatée (R-E-1, `2b48610`).** Voir §8.1 - le même
  fix racine ; en release la vidéo déchiffrée n'est plus écrite dans
  `filesDir/debug_raw*` (R8 strip les méthodes d'écriture en clair).
- **`metrics.log` gaté derrière `BuildConfig.DEBUG` (Lot 1, `f33938a`).** Le
  logger de debug était actif en **release** et **survivait au panicWipe** ; il est
  désormais debug-only.
- **M-2 - purge de la courbe d'activité par identité.** Le dict
  `report_creations` par identité est **purgé à la rotation de batch**
  (`server/app/ratchet_registry.py:238`), donc le relais n'accumule plus une
  courbe d'activité datée.
- **TOCTOU de budget serveur corrigé (R-SRV-3).** Réservation/libération atomiques
  (`reserve_report_creation` / `release_report_creation`,
  `server/app/ratchet_registry.py`).
- **MinIO en loopback (R-SRV-2).** Lié à **127.0.0.1:9000** uniquement ; logs
  Docker bornés ; `access_log` nginx `off`.
- **No-export FFI (Lot 4b, R-CR-1).** Les secrets sensibles (blob ratchet 50
  clés, master des reports, seed de provenance, clé de session Argon2) **ne
  traversent plus la FFI**. Ils restent en Rust derrière un handle ; scellement et
  descellement se font **dans Rust en un seul appel** (`pin_session_*` dans
  `crypto-rs/ffi/src/lib.rs` ; `StreamUploadManager.kt`). Field-validé sur OnePlus
  (33 min / 396 chunks, 0 erreur). C'est la version la plus forte du contrat
  « heap-0 » du §7 point 1.

**Les findings structurels D-1 / D-2 (transport, break-glass) sont traités au
§8.4 (transport) et §8.5 (réalité SNI) ; le finding M-1 (noms de répertoire de
report) est au §8.6.**

### 8.2 Hypothèses de confiance résiduelles (ce que l'audit formel ne garantit pas)

- **Le `.so` expédié correspond à la source Rust auditée.** Partiellement établi,
  et il faut être précis sur où s'arrête l'établissement. `checkSoProvenance` hashe
  bien le contenu, et le workflow `release.yml` publie le manifeste à côté des
  binaires issus du **même run** sur un commit public propre : vous pouvez donc
  relier une APK distribuée à un commit public (§2bis). Ce qui n'est **pas**
  établi, c'est la reproductibilité bit-à-bit : `build-android.sh` n'épingle ni
  `SOURCE_DATE_EPOCH` ni `--remap-path-prefix`, et les chemins sources absolus
  diffèrent d'une machine à l'autre. Rebuilder vous-même le même commit donnera
  d'autres empreintes. Vous pouvez vérifier *qu'un binaire vient de ce run-là*,
  pas *recréer ce binaire*.
- **Le Keystore est TEE-backed et non extractible.** R-D-1/R-C-2 en dépendent ;
  faible sur cibles sans StrongBox.
- **Le serveur tourne `--workers 1`.** Toute la sûreté concurrence nonce/slot en
  dépend ; un scale-out multi-worker la rouvrirait.
- **`OsRng` est un vrai CSPRNG** sur la cible ; **secret JWT confidentiel et
  jamais loggé** ; **isolation `/data`**. La perte d'une clé privée épinglée n'est
  plus un *flag-day* : le verifier porte un **jeu de 3 pins** (primaire + 2
  break-glass, dont un dont la clé est gardée **off-host** et **jamais déposée sur
  le relais**, `pin.rs:62`), donc une rotation, voire la récupération d'un **relais
  saisi**, est un recouvrement gracieux **sans push d'APK** (le pin étant déjà
  compilé). Limite résiduelle : un **domaine brûlé** (DNS/nom perdu), lui, exige
  toujours un rebuild d'APK. Runbook : `docs/TLS_PINNING_ROTATION_RUNBOOK.md` §6.
- **La force du lockscreen device + FBE** est désormais critique : c'est la
  barrière OS sous le plaintext applicatif. (Avec R-E-1 corrigé, le chemin
  `debug_raw` n'est plus atteignable en release, mais le principe « ce qui touche
  `filesDir`/`cacheDir` en clair n'est protégé que par FBE, pas par la crypto
  app » reste une frontière à connaître.)

### 8.3 Choix de design déférés (issus de `AUDIT_SCOPE_RUST §6`)

- **§6.1 - l'autorat du blob STRM (RÉSOLU en V3 : champ retiré).** Le format
  courant V3 a **retiré** l'`author_ed25519_pk` de l'en-tête (F-C1/WP-A) : il n'y
  a donc plus aucun autorat — signé ou non — au repos. Un relais aveugle peut
  toujours fabriquer des blobs auto-adressés, mais ils ne portent désormais
  **aucune identité** ; la confidentialité reste assurée (`crypto_box_seal`) et
  l'impact résiduel est « spam dans l'archive », pas une compromission. L'UI
  n'affiche aucune attribution d'auteur (audité,
  `docs/UI_FINGERPRINT_AUDIT_2026-05-07.md`). La question déférée (signer
  l'auteur) est sans objet : il n'y a plus de champ auteur à signer. Les blobs
  legacy V1/V2 conservent le champ en read-only.
- **§6.2 - pas de sel par-batch sur le MAC du ratchet** ; pertinent uniquement
  sur une course backup/restore concurrente, qui n'existe pas comme chemin de code.
- **§6.3 - pas de TTL serveur sur la durée de vie d'un batch.** Implémentable
  côté Python sans changement Rust.

### 8.4 Transport obfusqué (Lot 3, D-1) - le release vise désormais ObfQuic

**Mise à jour Lot 3 (2026-06-27, field-validé sur 2 chipsets).** Le transport
`ObfQuic` (QUIC/HTTP-3 + obfuscation Salamander) est désormais le transport
**release**, plus seulement debug : `RustUploadTransport.kt:46` met
`mode = OBF_QUIC` pour **debug ET release** (`f3d648a`, fermeture du finding
structurel D-1). C'est donc maintenant le **chemin audité par défaut** ; lisez-le
en priorité (`crypto-rs/stream/src/quic.rs`, `salamander*.rs`, crate `obfs-proxy`).
Un **fallback `QUIC → DirectTls`** par chunk est conservé (UDP bloqué → DirectTls),
exposé par le marqueur `transport_used`.

**Prouvé (§10.10) :** `deobfuscate_in_place` et `looks_like_quic_initial` - les deux
parseurs qui lisent de l'**UDP non-fiable** au bord internet-facing du proxy - ne
paniquent sur **aucun** datagramme (Kani exhaustif borné + proptest) ; round-trip
Salamander byte-exact (proptest) ; mutation `salamander.rs` **17/18** (le survivant
`reserve(+→*)` est un mutant **équivalent** : `Vec::reserve` n'est qu'un hint de
capacité, le contenu est invariant). La transform est **un seul module** partagé
client/serveur (parité par construction, 0 risque interop).

**Risque-accepté documenté :**

- **Salamander = obfuscation, PAS confidentialité.** XOR par keystream dérivé d'un PSK,
  ni authentification ni secret. La sécurité reste **TLS-épinglé + ratchet** (prouvés
  ①→⑤). Le PSK est un secret d'obfs **partagé, embarqué dans l'app** (comme le mot de
  passe obfs de Hysteria2), pas une clé par-utilisateur ; sa fuite dé-obfusque le fil
  mais ne révèle rien qu'un attaquant en position réseau (qui voit déjà tout le fil,
  hypothèse Dolev-Yao) n'ait déjà. Confidentialité et forward-secrecy intactes.
- **L'obfs achète l'inclassibilité, pas l'invisibilité.** Un flux UDP haute-entropie
  vers une **destination unique** (un domaine résolvant vers une IP) reste un signal
  d'analyse de trafic ; le padding qui masquerait timing/volume est **hors scope** (le
  débit prime pour du témoignage vidéo continu). Le backstop de disponibilité si l'UDP
  est bloqué = le **fallback DirectTls** (brique 3), field-validé - **mais ce repli est
  classifiable ET expose le SNI en clair** (§8.5, résidu assumé).
- **PSK non-zeroïsé côté proxy.** Le proxy garde le PSK en `Arc<Vec<u8>>` (non zeroïsé) ;
  secret d'obfuscation, pas de confidentialité, et présent de toute façon dans l'env du
  relais. Côté client il est en `Zeroizing`.
- **`quic.rs` = revu + field-validé, pas prouvé formellement.** quinn/h3 parsent
  QUIC/TLS (libs auditées upstream) ; pas de parseur d'input hostile maison. La logique
  (fallback par-chunk, latch `QUIC_DEGRADED`, heap-0) a été **revue Opus neutre +
  field-validée** sur device (briques 3 et 1).
- **Nouvelle surface d'attaque : proxy UDP `:8445` internet-facing.** Bornée par le gate
  **QUIC-Initial PSK-effectif** (un datagramme sans le PSK dé-obfusque en octets qui ne
  passent ~jamais le sniff Initial → 0 fd/tâche), un **cap `MAX_SESSIONS`** +
  `LimitNOFILE`, et le **no-panic prouvé** (T2). Le release **vise désormais ce
  proxy** (chemin par défaut) : c'est une surface internet-facing à examiner.

### 8.5 Réalité SNI et downgrade - non-revendication assumée (décision 2026-06-28)

> **Réconciliation doc-vs-code (à lire avec attention - c'est une dérive que la
> revue design a elle-même signalée comme « or pour l'auditeur »).**

D'anciennes proses (`docs/METADATA_EXPOSURE_MAP.md`, `docs/POSITIONNEMENT.md`)
vendaient un design **« IP brute, sans-SNI »** comme un contrôle anti-métadonnée
**courant**, et présentaient la fuite de SNI comme une **régression future**.
**Ce n'est plus vrai.** Le code épingle désormais un **domaine**
(`PINNED_HOST = "relay.shake-document-protect.org"`, `pin.rs:69`) ; le `ClientHello`
du chemin **`DirectTls` porte donc un nom d'hôte SNI en clair aujourd'hui**. Sur le
chemin **`ObfQuic`**, le SNI est **masqué par Salamander tant que l'UDP est ouvert**.

**État assumé (décision therealshulgin 2026-06-28, hors scope) :** un État peut bloquer
l'UDP/443 pour **forcer le downgrade vers le `DirectTls` classifiable** - qui
expose alors aussi le SNI. C'est un **résidu accepté**, pas un fix futur :

- **Pas de mode fail-closed** offert (le no-data-loss prime ; un témoignage ne doit
  pas être perdu parce qu'un État coupe l'UDP).
- **Tor a été mesuré et rejeté** (latence inadaptée à de l'upload vidéo continu).
- Le sous-objectif « destination non-fiable » est **déféré au serveur de
  production final**.

Formulé honnêtement : l'obfuscation achète **l'inclassibilité tant que l'UDP
passe, pas l'invisibilité ni la résistance au downgrade**. Sur le chemin dégradé,
un adversaire qui bloque l'UDP gagne **doublement** (flux classifiable **+** SNI en
clair). Voir la synthèse design §4.2 (« availability vs obfuscation »).

### 8.6 M-1 - noms d'entrées du répertoire de report rendus opaques (`075ec6b`)

Le **répertoire de report relais-aveugle** (utilisé pour qu'un appareil de secours
ré-apprenne `n_max` exactement) nommait ses entrées par l'**index décimal en clair**
(`%010d`), ce qui (a) **fingerprintait** le répertoire comme un compteur de
sessions et (b) laissait un opérateur de relais lire le **nombre de sessions du
témoin + sa cadence** dans les noms. Désormais chaque nom d'entrée est **opaque,
dérivé d'un secret** :

```
nom = hex( HKDF(report_master, "stream.report.directory.entry.v1" ‖ u32_be(n))[..16] )
```

- Dérivé du **secret `report_master`** (`crypto-rs/core/src/report.rs`,
  contexte `CTX_REPORT_DIR_ENTRY`), **jamais** du `directory_pk` public (sinon le
  relais pourrait ré-énumérer). Le relais voit `directory_pk`, pas `report_master`.
- Le **corps** de l'entrée ne porte plus l'index non plus (constant, 1 octet).
- La récupération retrouve `n_max` par **dérive-et-match**, en **dual-lisant** les
  éventuelles entrées legacy `%010d` (forward-compat).
- Field-validé Seeker (`n_max=6`, 7 reports mixte legacy/opaque, 0 erreur).

**Résidu honnête :** le répertoire **lie toujours au repos** les sessions d'un même
témoin (compteur + cadence) sous un seul `report_id`. Les noms opaques retirent le
**fingerprint trivial** et l'**index lisible**, mais **pas** la liaison
structurelle. Le motto strict (pas d'identité, pas de contenu) tient ; le résidu
est de la catégorie « un nombre, pas une carte » (synthèse design §4.3).

---

## 9. La méthodologie elle-même (méta - pertinent pour votre confiance)

Nous documentons notre processus pour que vous puissiez juger sa fiabilité, et
parce qu'une partie est méta-pertinente pour un audit assisté par IA.

### 9.1 Anti-dégradation et oracle externe

La littérature (IEEE-ISTAS) montre qu'une boucle d'agents qui « améliore » du code
peut converger vers quelque chose qui *paraît* corrigé sans l'être, le nombre de
vulnérabilités pouvant même augmenter. Notre parade : un **critère de terminaison
externe et non-LLM**. La sortie d'un agent est toujours un *candidat* ; ce qui
termine, c'est l'analyseur (mutation, fuzz, preuve), pas le jugement du modèle. La
confiance d'un agent (« j'ai audité, c'est clean ») est un signal **nul**.
Détail : `docs/methodologie-securite-code.md`.

### 9.2 Audit adverse inter-modèle avec vérification anti-fallback

**Deux** audits red/blue ont précédé cette remise (le premier avril→juin, le
second le **2026-06-26 à 7 agents Opus en lecture seule**, §8.1bis), conduits par
un **modèle distinct de l'arbitre**, avec deux disciplines (la description
ci-dessous vaut pour les deux passes ; le second audit a en outre alimenté la
couche de réflexion design `docs/design-review-2026-06-28/`, §0bis) :

- **Isolation de contexte :** le red attaque (« suppose ce code vulnérable,
  trouve l'exploit »), le blue **réfute par défaut** (« pars de l'hypothèse que le
  finding est faux »). Aucun ne se valide lui-même.
- **Vérification anti-fallback :** chaque agent **auto-déclare son identité-modèle
  réelle** en tête de rapport (le bloc d'identité est en première ligne de chaque
  rapport ; ceux-ci sont internes, communicables sur demande). Cela garantit que l'exercice inter-modèle a réellement eu
  lieu et qu'aucun fallback silencieux vers un autre modèle n'a contaminé le
  résultat. Nous mentionnons ce mécanisme parce qu'il est reproductible : si vous
  faites tourner vos propres passes assistées par IA, exiger une auto-déclaration
  d'identité-modèle est un garde-fou bon marché.
- **Arbitrage indépendant :** une passe d'arbitrage re-vérifie les **faits
  porteurs** par grep/lecture directe (jamais sur la parole des agents), et révèle
  les **« frères »** d'un bug - les chemins jumeaux qu'un finding initial
  sous-estime (ici : le frère `debug_raw_hevc`/`debug_rolling` de R-E-1, et le
  doc périmé sur le panicWipe). C'est l'étape qui a le plus de valeur.

Cette discipline a une histoire : le contre-audit
`OLD/BLUE_TEAM_COUNTERAUDIT_2026-04-21.md` a attrapé un finding « confirmé » par
deux passes successives sur du **code qui n'existait pas** (RT-13, supprimé par un
commit antérieur) - précisément parce qu'aucune des deux n'avait ouvert le fichier
à la ligne exacte. Leçon intégrée : *un verdict doit citer le code réel, pas la
parole de la passe précédente.*

### 9.3 Le piège de la fidélité du port

La parité byte-exact Kotlin→Rust est excellente contre les régressions, mais elle
**reproduit fidèlement les vulnérabilités du Tella d'origine**. Parité ≠ sécurité.
C'est pourquoi nous avons (a) traité la migration comme une occasion de corriger,
pas seulement de mirrorer, (b) ajouté du **differential fuzzing** (qui valide la
parité *et* trouve des crashes hors suite de tests), et (c) du property-based
testing sur les parsers et frontières crypto, qui vaut plus que 100 tests
d'exemple de plus.

---

## 10. Comment nous reporter vos findings

Format attendu (cf. `AUDIT_SCOPE_RUST §10`) :

```
FINDING-<ID>
Severity: CRITICAL | HIGH | MEDIUM | LOW | INFO
Title: <court>
Location: <chemin>:<ligne> (git SHA)
Description: …
Reproduction: …
Recommendation: …
```

Nous trierons chaque finding en : **Bloquant** (fix avant tout ship),
**Majeur** (fix avant publication F-Droid/GitHub), **Documenté** (acquitté,
mitigé par design, capté au registre §8 avec votre rationale). Un correctif que
nous appliquerons doit, idéalement, **préserver les invariants prouvés** (sinon :
bump de version + chemin de migration + rejet du legacy, comme le pattern V1→V2
existant) et re-déclencher la preuve concernée + le diff-fuzz + `cargo clippy
-D warnings`.

Contact : haut de `README.md` (il n'y a pas de `CODEOWNERS` dans ce dépôt ; cette
ligne en citait un). Dev solo, fuseau Europe, e-mail
suffit.

---

*Fin du guide. Merci pour votre relecture - et pour tout écart entre ce document
et le code, le code gagne ; dites-le-nous.*
