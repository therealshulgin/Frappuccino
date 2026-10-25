# Frappuccino - Architecture technique complète

> **Référence d'architecture courante et exhaustive de Frappuccino.** L'un des trois canons,
> avec [`../ROADMAP.md`](../ROADMAP.md) (source unique d'état et d'historique daté) et
> [`GUIDE_AUDITEUR.md`](GUIDE_AUDITEUR.md) (dossier de preuves). Il se veut **auto-suffisant** :
> tout le détail technique courant y figure, sans renvoyer à un autre document pour l'état
> présent. La provenance et les snapshots historiques (dont les détails crypto d'avril) sont
> listés en [§13](#13-références-internes).
> **En cas de divergence entre ce document et le code, le code fait foi.**
>
> *Dernière revue : 2026-10-25.*

---

## Table des matières

- [0. Résumé exécutif](#0-résumé-exécutif)
- [1. Contexte et positionnement](#1-contexte-et-positionnement)
- [2. Modèle de menace](#2-modèle-de-menace)
- [3. Principes de conception](#3-principes-de-conception)
- [4. Architecture cryptographique V2](#4-architecture-cryptographique-v2)
- [5. `crypto-rs/` - le cœur Rust](#5-crypto-rs--le-cœur-rust)
- [6. Pipeline de capture et de streaming HEVC](#6-pipeline-de-capture-et-de-streaming-hevc)
- [7. Application Android (`mobile/`)](#7-application-android-mobile)
- [8. Serveur relais aveugle (`server/`)](#8-serveur-relais-aveugle-server)
- [9. Assurance - preuves machine-vérifiées et audits adverses](#9-assurance--preuves-machine-vérifiées-et-audits-adverses)
- [10. Limites assumées](#10-limites-assumées)
- [11. État du projet et trajectoire](#11-état-du-projet-et-trajectoire)
- [12. Build, tests, déploiement](#12-build-tests-déploiement)
- [13. Références internes](#13-références-internes)
- [Annexe A - Constantes cryptographiques (contrat wire)](#annexe-a--constantes-cryptographiques-contrat-wire)

---

## 0. Résumé exécutif

Frappuccino est une application Android open-source (AGPLv3 visée) de **témoignage
vidéo chiffré de bout en bout, en temps réel**, destinée aux militants, journalistes et
avocats opérant en contexte hostile. C'est un fork profondément remanié de Tella FOSS
(Horizontal.org) : la coquille Android est conservée, le cœur - cryptographie, capture,
transport, modèle de confiance - est remplacé.

**Slogan technique** : *« Le téléphone est un émetteur. Pas un coffre. »*

Le principe central est une **asymétrie de capacités** entre le device et son détenteur
légitime : le téléphone peut **chiffrer** et **signer**, mais ne peut **jamais déchiffrer
son propre passé**, et il ne peut plus **étendre ni réécrire un rapport clos** : chaque
rapport est signé pendant l'enregistrement par une clé qui lui est propre, effacée de
l'appareil à la clôture, et le relais refuse tout nouvel objet dans un rapport dont il a
reçu la clôture signée (§8.7). Cette seconde propriété vaut pour les rapports **clos** ;
elle ne couvre ni le rapport en cours d'enregistrement, ni les rapports ouverts après une
extraction de l'état de l'appareil (§10.1). La capacité de lecture appartient
exclusivement à une phrase BIP-39 de 12 mots, écrite sur papier, qui ne touche jamais le
stockage du device après l'enrôlement. Le ratchet d'authentification est une adaptation
du mécanisme de forward security du consensus **Algorand** (clés de participation éphémères,
détruites séquentiellement après usage) au cas d'usage du témoignage de terrain.

Propriétés saillantes, dans l'état courant du code :

- **Cryptographie 100 % Rust** (`crypto-rs/` : six crates au workspace, soit `core`, `stream`, `ffi`, `cli`, `obfs-proxy` et `quic-spike`, plus la crate `fuzz` hors workspace ; **trois seulement partent dans le `.so`** : `core`, `stream`, `ffi`) exposée à Kotlin via UniFFI.
  Zéro `unsafe`, dépendances épinglées en version exacte, secrets en `Zeroizing`,
  `clippy -D warnings` en gate. Aucun secret *long-lived* ne réside dans la heap
  JVM ; les seuls résidus sont transitoires et bornés à quelques millisecondes (le
  `String` PIN/mnémonique imposé par le composant clavier legacy, le `ByteArray` de
  métadonnées de session wipé en `finally`), hors modèle de menace (R-D-1, heap-dump
  d'un device déverrouillé/rooté ; cf. §2.4 et `GUIDE_AUDITEUR §4` frontière zeroize).
- **Ratchet éphémère batché** : lignée de signatures Ed25519 forward-secure. Chaque
  authentification consomme une clé à usage unique, détruite immédiatement ; chaque
  batch de 50 clés est authentifié par une signature du batch précédent, remontant à
  l'identité long-terme. La forward security de **l'authentification** est **prouvée en
  Tamarin** (Dolev-Yao, lemme `forward_secrecy_auth`), la machine à états du ratchet
  **model-checkée en TLA+/TLC**. Ces preuves portent sur l'authentification, pas sur le
  contenu des rapports.
- **Rapports signés à la production, figés à la clôture** : chaque objet d'un rapport
  (métadonnées, chunk, clôture) est signé au moment où il est produit, et la signature
  voyage avec lui dans une enveloppe de file ; l'envoi ne signe jamais. À l'arrêt de
  l'enregistrement, la clôture (`0x09`) engage la liste exacte des objets, puis la clé
  du rapport est effacée ; l'état conservé par l'appareil ne permet plus de la redériver
  (§8.7).
- **Séparation de domaine explicite des signatures** (R-C-1, juin 2026) : tag d'un octet
  par contexte. Surfaces serveur-miroir : `0x01` AuthChallenge, `0x02` BatchRotation,
  `0x03` Enrollment (`0x04` ArchiveAuth est **réservé mais retiré** depuis le passage des
  archives en mode relais-aveugle, §8.7) ; capacités report relais-aveugles `0x07`
  ReportCreate / `0x08` ReportWrite / `0x09` ReportClose ; `0x05`/`0x06` sont **réservés
  et retirés** au même titre que `0x04` (le manifeste signé a été supprimé par le recul
  métadonnées du 2026-06-25, §4.4). Source Rust ⇄ miroir serveur byte-identiques.
- **Relais aveugle** : FastAPI + MinIO ne stockent que des blobs STRM opaques. Le serveur
  ne voit jamais de clair, ne logge pas d'IP, vérifie des signatures et impose
  anti-rejeu + anti-double-dépense + monotonie de rotation, et refuse tout nouvel objet
  dans un rapport clos.
- **Capture HEVC temps réel** via MediaCodec piloté par un wedge OpenGL ES (CameraX en
  amont), chunks de 5 s chiffrés et uploadés au fil de l'eau : la vidéo est à l'abri
  **même si le téléphone est saisi en cours d'enregistrement**.
- **Suite d'assurance machine-vérifiée** : zeroize-audit LLVM IR (zéro élimination du wipe
  par le compilateur), fuzzing différentiel Kotlin↔Rust (759/759), Kani (no-panic exhaustif
  du parseur d'en-tête), TLA+/TLC (2800 états), Tamarin (protocole complet) - complétée
  par mutation testing (100 %/98 % sur les frontières de confiance), cargo-fuzz, proptest,
  et un audit adverse inter-modèle avec arbitrage indépendant.

Et, dit sans détour : Frappuccino est **field-test ready, pas production-ready**. Le projet
est co-écrit avec une IA (posture assumée, §1.3), l'audit externe humain n'a pas encore eu
lieu, et la section 10 liste ce que le système **ne** protège **pas**.

---

## 1. Contexte et positionnement

### 1.1 Le problème

Un militant filme une exaction. Trois choses peuvent lui arriver, souvent dans cet ordre :
le téléphone est saisi, son détenteur est contraint de donner ses codes, le matériel part
en extraction forensique (Cellebrite, GrayKey). Les apps de « coffre-fort chiffré »
répondent mal à ce scénario : un coffre, ça s'ouvre - par brute-force du code, par
coercition, ou par exploitation de l'OS. Tant que les données sont *sur* le device,
le device est le point de défaillance.

Frappuccino inverse le problème : la donnée **quitte** le device au fil de la capture,
chiffrée vers une clé dont la moitié privée n'existe sur aucune machine. Ce qui reste sur
le téléphone après coup ne permet pas de relire le passé, ni de réécrire un rapport clos.
Ce qu'il permet encore est dit en §10.1 : signer le rapport en cours d'enregistrement au
moment de la saisie et les rapports ouverts après elle, sans limite de durée ; jamais lire
le contenu.

### 1.2 Fork de Tella FOSS

Tella (Horizontal.org) fournit la base Android : structure de projet, onboarding,
lifecycle, `applicationId org.hzontal.tellaFOSS` conservé. Ce qui a été remplacé ou retiré
est documenté en détail dans [`docs/FORK_VS_TELLA.md`](FORK_VS_TELLA.md) ; en synthèse :

| Domaine | Tella FOSS | Frappuccino |
|---|---|---|
| Modèle de données | Coffre chiffré **au repos** sur le device | **Streaming E2E temps réel** vers relais aveugle ; rien de lisible ne reste sur le device |
| Crypto | Java/Kotlin (vault AES, PBKDF2) | **100 % Rust** (`crypto-rs/`), protocole V2 ratchet éphémère |
| Capture | CameraX `Recorder` | MediaCodec **HEVC** via wedge GL ES, chunks roulants 5 s |
| Transport | Envoi de rapports a posteriori (Uwazi/Tella Web) | Upload chiffré continu, WorkManager, queue persistante, reprise |
| Verrouillage | PIN/pattern/password Tella (`tella-keys`, `tella-locking-ui`) | **Retirés** (Phase 6.1.16) ; gate PIN pur-V2 (Argon2id Rust) |
| Vault | `tella-vault` | **Retiré** (code mort en V2 - Phase 5.7, puis sweep 7.4) |

Le dé-Tella-isation est allée loin : modules `tella-vault`, `tella-keys`,
`tella-locking-ui` supprimés du build ; sweep de code mort outillé (rapport
[`docs/DEADCODE_SWEEP_2026-06-08.md`](DEADCODE_SWEEP_2026-06-08.md)) ayant retiré
**238 fichiers / −11 226 lignes** par lots gatés build-vert, avec validation terrain
après chaque lot sensible. Il reste une coquille `shared-ui` réduite et la structure
d'activités héritée - assumées comme dette d'origine contrôlée, pas comme surface crypto.

### 1.3 Posture de développement - co-écrit avec une IA, et conçu pour que ça tienne quand même

Ce point est assumé frontalement parce qu'il conditionne la confiance qu'on peut accorder
au reste du document : **Frappuccino est développé par un développeur solo avec une IA
(Claude) comme pair de programmation principal**, y compris pour le code cryptographique,
les audits internes et la rédaction de cette documentation.

C'est à la fois un levier et un risque, et l'architecture d'assurance du projet (§9) est
construite explicitement **contre** le risque :

- **Le risque** : un LLM peut produire du code plausible et faux, sur-noter ses propres
  passes de revue, et converger vers un faux « clean » par dégradation itérative. Aucune
  affirmation de ce projet ne repose donc sur le jugement d'un LLM seul.
- **La parade** : chaque propriété de sécurité importante est adossée à un **oracle
  non-LLM, déterministe et rejouable** - model-checkers (Tamarin, TLC, Kani), analyse
  d'IR compilateur, mutation testing, fuzzing différentiel à seeds figées, vecteurs
  cross-implémentation. Les audits IA internes sont menés en **adverse** (équipes
  rouge/bleue sur des modèles distincts, arbitrage par re-vérification indépendante sur
  le code, jamais sur la parole des agents) et leurs findings ne comptent que re-prouvés
  contre le code live. Le protocole complet est documenté dans
  [`docs/methodologie-securite-code.md`](methodologie-securite-code.md) et
  [`docs/invariants-ratchet-verification.md`](invariants-ratchet-verification.md).
- **La limite résiduelle** : tout cela ne remplace pas l'audit externe humain
  (Cure53 / Trail of Bits, Phase 8). Le dossier d'audit (preuves, runners reproductibles,
  handoff) est précisément conçu pour rendre cet audit efficace, pas pour s'y substituer.

### 1.4 Trois acteurs

| Acteur | Rôle | Ce qu'il détient / voit |
|---|---|---|
| **Device militant** | Capture + chiffre + signe + uploade | Clés **publiques** Ed25519/X25519, batch courant de 50 clés éphémères Ed25519, blob ratchet scellé par PIN, état de rapport scellé par la session PIN (maillon courant de la chaîne + graine d'annuaire, §8.7), clé de file sous Keystore, file d'enveloppes chiffrées |
| **Serveur relais** | Stocke des blobs opaques, vérifie les signatures, impose le protocole | Pks Ed25519 pseudonymes, batches publics, blobs chiffrés, tailles/timestamps |
| **Phrase BIP-39** (papier) | Seule capacité de lecture et de récupération | Tout - via `ArchiveModeActivity` (Android) ou `frappuccino-cli` (desktop) |

---

## 2. Modèle de menace

### 2.1 Adversaires considérés

| Adversaire | Capacités | Réponse V2 |
|---|---|---|
| Voleur opportuniste | Saisit le téléphone, regarde l'écran | App verrouillée, `FLAG_SECURE`, stealth screen, auto-lock du ratchet à l'inactivité |
| Police sans forensique | Exige le PIN, fouille la galerie | Le PIN n'ouvre que le ratchet (signatures futures) ; aucun contenu local lisible |
| Police avec **Cellebrite/GrayKey** | Extraction storage, brute-force PIN offline | Argon2id 256 MiB×4 + deny-list ; même PIN cassé : **aucun stream passé déchiffrable** (pas de clé privée X25519 sur le device) |
| Coercition sur le PIN (« rubber-hose » partiel) | PIN donné sous contrainte | L'adversaire peut s'authentifier et signer les rapports **ouverts après** ce moment, et écrire dans l'annuaire (§10.1) ; il ne lit pas le passé et ne peut plus étendre un rapport **clos** |
| Saisie **en cours d'enregistrement** | Device ouvert, session active | Les chunks déjà chiffrés/uploadés sont hors d'atteinte ; la clé du rapport en cours est en mémoire jusqu'à sa clôture, voir §10.1 |
| Saisie du serveur relais | Tout le stockage + registres | Blobs STRM opaques, pks pseudonymes, métadonnées (§8.5). Aucun plaintext, aucune clé privée |
| Serveur **+** device **+** PIN | Scénario cumulatif | Perd encore : la clé privée X25519 n'existe nulle part ailleurs que dans la phrase |
| Interception réseau / MITM | Position réseau active | TLS 1.2/1.3 avec **pin SPKI** par verifier rustls custom (pas de CA store système), **jeu de 3 pins** acceptés en union constant-time (primaire + 2 break-glass, dont une clé tenue off-host) ; test de régression MITM automatisé |
| DPI / classification de trafic | Inspection passive des paquets | Transport release **ObfQuic/Salamander** : chaque datagramme UDP ressemble à de l'aléa uniforme (relais = port mort sans le PSK). **Obfuscation, pas confidentialité** ; PSK embarqué dans l'APK (extractible). Sur le repli `DirectTls` (UDP bloqué) la classification redevient possible et le SNI fuit en clair (§10.4, résidu assumé) |
| Phrase BIP-39 compromise | Papier vu/volé | **Défaite totale** : identité, archives, capacité de forge. C'est le point de défaillance assumé du design (§10.5) |

### 2.2 Hypothèses

- L'utilisateur conserve la phrase hors device (papier, support métal) et choisit un PIN
  non trivial (≥ 6 chiffres).
- L'OS Android et le SoC ne sont pas activement hostiles **avant** la capture (pas de
  malware avec accès caméra/écran/mémoire - §10.1).
- Le serveur relais peut être saisi à tout moment : c'est une donnée d'entrée du design,
  pas un cas d'échec.
- Les primitives (libsodium-style en Rust : Ed25519, X25519, XChaCha20-Poly1305, Argon2id,
  HKDF-SHA256, BIP-39/PBKDF2) ne sont pas backdoorées - hypothèse standard.

### 2.3 Hors périmètre explicite

Compromission *live* du device pendant la capture (l'app chiffre en aval du capteur) ;
tracking réseau/baseband (IMSI-catcher, corrélation de trafic opérateur) ; side-channels
matériels (TEE/TrustZone compromis) ; supply-chain des libs système Android ; coercition
sur la phrase elle-même. Détail et conséquences : §10.

### 2.4 Calibrage de sévérité : un secret transitoire en RAM ne rend pas le modèle caduc

Les adversaires ci-dessus se répartissent en **deux classes de portée très différente** ;
les garder distinctes est nécessaire pour juger correctement toute faiblesse.

1. **L'adversaire que le modèle vise** : saisie, coercition, destruction d'un device
   verrouillé, éteint ou saisi. La garantie tient **par construction** : le témoignage est
   **déjà parti en ligne** sur le relais aveugle (chiffré, illisible du serveur) et **seule
   la phrase BIP-39 le ré-ouvre**. Cet adversaire n'obtient rien de lisible du device et
   **ne peut pas détruire le passé** : les rushes ne sont plus sur l'appareil.
2. **L'adversaire qui lit la RAM d'un device vivant *et* déverrouillé**, dans une fenêtre
   étroite (TTL d'un token, session active) : adversaire **distinct et de moindre portée**,
   traité en §10.1-§10.2. C'est là, et seulement là, que vivent les résidus ratchet
   device-dépendants (R-C-2, R-D-1/2). Le **finding §10.6 d'origine** (JWT d'upload résiduel
   dans le heap JVM) appartenait à cette classe ; il est désormais **fermé à 0 par
   construction** (§10.7 livré : PUT, report et recovery tous en Rust, le bearer ne touche
   plus jamais la pile HTTP JVM ; heap-dump en session active = `Bearer eyJ=0`).

**Une lecture RAM dans cette fenêtre ne casse pas le modèle :**

- le **témoignage n'est pas en jeu** : il est sur le relais, scellé à une clé dont la
  moitié privée n'existe sur **aucune machine** ; un dump RAM ne livre ni la clé d'archive
  (= la seed, absente de la RAM hors mode archive volontaire), ni le moyen de détruire le
  passé ;
- le **JWT d'upload** ne vit plus que dans le holder natif `Zeroizing` (`UPLOAD_JWT`,
  hors heap Dalvik) depuis que le PUT, le POST report et la recovery sont tous en Rust
  (§10.7 livré, heap-dump session active = `Bearer eyJ=0`) ; et même un bearer
  hypothétiquement lu reste **neutralisé côté serveur** (scope-segregé + **write-once**,
  combo-1 : ni lecture, ni suppression, ni écrasement des rushes) ;
- une fuite de l'état de l'appareil (ratchet, état de rapport) donne une **capacité de
  signature *future***, **jamais du contenu passé** : la confidentialité du passé tient à
  l'absence de `x25519_sk`, pas au ratchet. Cette capacité n'est **pas bornée dans le
  temps**, aucun canal ne la signale au témoin, et il n'existe pas de route de révocation
  d'identité ; elle porte sur le rapport en cours et sur ceux ouverts ensuite, pas sur les
  rapports déjà clos (§10.1).

⇒ Ces fuites RAM résiduelles sont des cibles de **durcissement / défense-en-profondeur**,
**pas** des défauts qui rendraient la confiscation ou la destruction capables d'empêcher le
témoignage. Le cas le plus visible (JWT d'upload) a d'ailleurs été **traité jusqu'à heap-0
par construction** (§10.7 : le bearer ne quitte plus le holder natif `Zeroizing`). Autrement
dit : **ce qui transite momentanément en RAM est aussi, et durablement, à l'abri sur le
relais - hors de portée de cet adversaire.**

---

## 3. Principes de conception

### 3.1 « Le téléphone est un émetteur. Pas un coffre. »

Tout le design dérive de cette phrase. Sur le device, après enrôlement :

```
✅ Clé publique X25519      → peut CHIFFRER (sceller des clés de session)
✅ Batch éphémère courant   → peut S'AUTHENTIFIER (49 slots, le dernier réservé à la rotation)
✅ Graine du batch suivant  → peut faire avancer le ratchet sans la seed
✅ État de rapport (i, C_i, graine d'annuaire), scellé par la session PIN
                            → peut OUVRIR le rapport i et les suivants, écrire dans l'annuaire
✅ Graine de provenance, scellée par la session PIN → sel des horodatages OTS (opt-in)

❌ Clé privée X25519        → ne peut PAS DÉCHIFFRER (jamais persistée)
❌ Clés éphémères passées   → détruites à l'usage (forward security de l'authentification)
❌ Clés des rapports clos   → effacées à la clôture, non redérivables depuis l'état (§8.7)
❌ report_master            → absent de l'appareil après l'inscription ou la migration
❌ Seed / phrase BIP-39     → jamais stockée (papier uniquement)
```

Conséquence opérationnelle : l'attaquant qui obtient *tout* (storage + PIN + RAM) ne lit
pas un seul octet de contenu passé et ne peut plus étendre un rapport clos. Il obtient la
capacité de **se faire passer pour** le militant : s'authentifier, signer le rapport en
cours au moment de l'extraction et tous les rapports ouverts après elle, écrire dans
l'annuaire. Cette capacité n'est bornée ni dans le temps ni en nombre de rapports (le
ratchet tourne avec la graine du batch suivant), aucun canal ne la signale au témoin, et
il n'existe pas de route de révocation d'identité. Le détail et ce qui en limite la portée
sont en §10.1.

### 3.2 L'inspiration Algorand

Le mécanisme vient du consensus Algorand, qui résout un problème structurellement
identique : comment des nœuds peuvent-ils signer au quotidien sans qu'une compromission
future permette de réécrire l'histoire ? La réponse d'Algorand : les **clés de dépense**
restent en cold storage ; les **clés de participation** dérivent des lots de clés
éphémères (*key dilution*) ; chaque clé éphémère est **détruite après son round**.
Personne - pas même le nœud - ne peut signer pour un round passé.

La transposition Frappuccino :

| Algorand | Frappuccino |
|---|---|
| Spending key en cold storage | **Phrase BIP-39 sur papier** (identité + clé de déchiffrement) |
| Participation keys par lots (key dilution √N) | **Batches de 50 clés Ed25519 éphémères** dérivés par chaîne HKDF |
| Une clé par round, détruite après | **Une clé par session/auth, wipée immédiatement** après signature |
| Chaîne d'attestation des lots | **RotationProof** : chaque batch signé par un slot du batch précédent, jusqu'à la signature d'enrôlement par la clé long-terme |
| Impossible de forger le passé | **Forward security de l'authentification, prouvée Tamarin** (§9.2.5) ; pour le contenu, **rapport clos figé** : clé effacée à la clôture et refus du relais (§8.7), couvert par des tests, sans modèle Tamarin |

S'y ajoute une dimension absente d'Algorand parce que propre au témoignage : la
**séparation chiffrement/déchiffrement**. Algorand protège l'intégrité de l'histoire ;
Frappuccino protège aussi sa **confidentialité** - le device chiffre vers une clé
publique X25519 dont la moitié privée n'est dérivable que depuis la phrase. Les deux
lignées (signature forward-secure, chiffrement à capacité asymétrique) sont
indépendantes et se renforcent.

Les autres inspirations revendiquées : **Signal** (discipline de ratchet, effacement),
**MetaMask** (UX seed-une-fois + PIN au quotidien), **Briar** (threat model militant,
panic). La spec d'origine est conservée telle quelle dans
[`STREAM_CRYPTO_V2_ALGORAND.md`](../STREAM_CRYPTO_V2_ALGORAND.md) - elle date d'avril
2026 et décrit une implémentation Kotlin/lazysodium aujourd'hui remplacée par Rust ;
le protocole, lui, est resté celui décrit.

### 3.3 La phrase BIP-39 souveraine

12 mots français (128 bits d'entropie, wordlist BIP-39 FR 2048 mots, normalisation
tolérante aux accents identique côté Rust et côté CLI). La phrase est :

- **générée sur le device, affichée une fois**, confirmée, jamais persistée ;
- le **seul** chemin vers la clé privée X25519 (archives) et la clé privée Ed25519
  long-terme (ré-enrôlement) ;
- saisie exclusivement via un flux dédié en `ByteArray` wipé (jamais de `String` JVM),
  côté Rust en `Zeroizing`.

Un 13ᵉ mot optionnel (passphrase BIP-39 standard) dérive une identité disjointe -
support de déni plausible, à la crédibilité duquel le design ne prétend pas au-delà de
ce que l'utilisateur en fait.

### 3.4 Relais aveugle

Le serveur est conçu pour être **saisissable sans dommage de contenu** : il ne détient
que des blobs chiffrés bout-en-bout, des clés publiques pseudonymes et le registre du
ratchet (batches publics, slots consommés). Son rôle actif se limite à imposer le
protocole : anti-rejeu des nonces, usage unique des slots, monotonie stricte des
rotations. Il est durci en conséquence (§8.4) mais sa compromission est un scénario
*prévu*, pas un échec.

### 3.5 « Soyons overkill » - pourquoi la crypto est 100 % Rust

Décision de mai 2026 (verbatim du carnet de bord : *« soyons overkill, des vies peuvent
se jouer sur le terrain »*), déclenchée par un constat mesuré, pas par dogme : en
Kotlin/JVM, le `fill(0)` ne couvrait qu'environ 5 % de la surface réelle des secrets -
les `String` immutables (PIN, mnemonic, chemins intermédiaires) sont copiées par le
runtime et non-wipeables, le GC déplace les buffers, le JIT peut élider un wipe final.

La réponse : **tout secret matériel vit en Rust**. PIN et mnemonic traversent la
frontière UniFFI en `bytes` et sont consommés côté Rust en `Zeroizing` ; le plaintext
vidéo est lu, chiffré, signé et écrit en enveloppe par Rust (`ReportWriter.seal_chunk_file`)
sans jamais monter sur la heap JVM ; l'effacement est garanti au niveau **IR compilateur** (§9.2.1), pas au niveau
des intentions. Le wipe côté Kotlin subsiste uniquement pour les buffers de saisie UI
(`SecureWipe`), en défense en profondeur.

---

## 4. Architecture cryptographique V2

### 4.1 Hiérarchie de dérivation

```
12 mots BIP-39 FR  [+ 13e mot optionnel → identité disjointe]
        │  PBKDF2-HMAC-SHA512 (salt = "mnemonic"+passphrase, 2048 itér.)
        ▼
   seed 64 octets
        │  HKDF-SHA256, contextes disjoints (séparation cryptographique) :
        ├── "stream.identity.ed25519.v1"   → keypair Ed25519 (identité long-terme)
        │       pk → device (pseudonyme)   sk → signe l'enrôlement, puis WIPÉE
        ├── "stream.encryption.x25519.v1"  → keypair X25519 (chiffrement)
        │       pk → device (sceller K_s)  sk → JAMAIS sur le device (archive only)
        └── "stream.ratchet.chain0.v2"     → chain_0 (amorce du ratchet, wipée après batch_0)
```

À l'issue de l'enrôlement, le device détient : les deux clés publiques, le batch_0
complet (50 keypairs éphémères), la graine `chain_1` - rien d'autre. La `sk` Ed25519
long-terme a servi exactement un usage avant destruction : signer le batch_0
(domaine `0x03`). La récupération d'archive ne passe plus par elle : depuis le modèle de
reports relais-aveugles (§8.7), l'accès aux archives est **sans identité** (connaître le
`report_id` dérivé de la phrase suffit à lire), les écritures sont autorisées par les clés
de capacité dérivées de la phrase (domaines `0x07`/`0x08`/`0x09`), et le domaine
d'authentification d'archive historique `0x04` est **réservé mais retiré**.

**Fingerprint de vérification.** Le device dérive aussi un fingerprint lisible de l'identité -
`SHA-256(ed25519_pk)` tronqué à **12 octets**, formaté en **6 groupes de 4 caractères hex**
séparés par des espaces ([`crypto-rs/core/src/identity.rs`](../crypto-rs/core/src/identity.rs)
`::readable_fingerprint`, parité Kotlin byte-identique) - affiché à l'enrôlement et dans les
réglages pour que le témoin confirme de visu avoir saisi la bonne phrase. C'est le seul
checksum d'identité montré à l'utilisateur ; il n'a aucun rôle cryptographique au-delà de
cette vérification humaine.

### 4.2 Le ratchet éphémère

Chaque batch N est dérivé de `chain_N` par HKDF (contextes
`"frappuccino-v2-ratchet-batch-seeds"` pour les 50 seeds Ed25519,
`"frappuccino-v2-ratchet-next-chain"` pour `chain_{N+1}`), puis `chain_N` est détruite.
HKDF étant unidirectionnel, posséder `chain_{N+1}` ne donne **rien** sur `chain_N` ni
sur aucun batch passé.

Cycle d'une clé éphémère :

```
dérivée (rotation) → au repos dans le blob scellé PIN → chargée en RAM à l'unlock
→ sélectionnée → signe UN message (tag de domaine préfixé) → sk wipée immédiatement
→ slot marqué consommé (bitmap) → blob re-scellé sur disque → irrécupérable
```

Points d'implémentation qui comptent :

- `sign_and_advance()` (Rust, exposé UniFFI) wipe la `sk` **avant** de retourner la
  signature ; la fenêtre d'existence en clair d'une clé est de l'ordre de la
  milliseconde.
- Le blob sérialisé (4 876 octets : 4 844 de payload + 32 de MAC, contexte HKDF
  `"frappuccino-v2-ratchet-blob-mac"`) garde les slots consommés **à zéro** - vérifié à
  la désérialisation, testé par mutation (le bit de consommation d'un slot ≥ 8 a son
  test dédié, §9.3).
- L'auto-rotation se déclenche côté client à ≤ 5 clés restantes.
- **La dernière clé d'un batch est réservée à la rotation, et le refus est dans le
  code Rust, pas dans une convention.** `sign_and_advance` refuse le dernier slot ;
  seul `advance_batch` peut le prendre. La raison est qu'une authentification
  **ratée consomme quand même son slot** (la clé est wipée avant l'envoi), et que la
  rotation automatique ne tourne qu'après un `verify` **réussi** : une série d'échecs
  (horloge fausse au-delà de 30 s, réseau, course sur un slot) pouvait donc vider les
  50 slots sans qu'aucune rotation soit tentée. C'est pourquoi le client tente aussi
  la rotation **avant** de signer quand il ne reste que la réserve, ce que
  `/auth/v2/rotate-batch` autorise puisqu'il n'exige aucun JWT : un appareil qui ne
  peut plus s'authentifier peut encore tourner. Invariant TLA+
  `RotationAlwaysPossible`, avec contrôle négatif (retirer la garde le falsifie).
- **L'épuisement complet serait une impasse, et c'est ce que la réserve empêche.**
  À zéro slot, l'appareil ne peut ni signer ni tourner, et le relais **refuse** une
  identité déjà enrôlée (409, `ratchet_registry.enroll`) : il n'existe aucune route de
  ré-enrôlement ni de révocation. La seule sortie serait une nouvelle phrase, donc une
  nouvelle identité et la perte de l'annuaire de reports. Une version antérieure de
  cette section affirmait l'inverse (« la phrase régénère tout depuis `chain_0`
  ») : c'était faux, le serveur ne reprend pas une identité connue. Corrigé le
  2026-08-28 après la revue d'architecture.
- **Une rotation perdue en route ne coûte plus l'enrôlement.** `advance_batch` fait
  avancer le ratchet **local** et wipe le batch précédent ; si l'appel
  `/auth/v2/rotate-batch` qui suit n'arrive pas, l'appareil est sur `N+1` et le relais
  sur `N`, donc le relais refuse toute auth, définitivement, et la preuve ne peut plus
  être re-signée puisque le batch qui l'a produite n'existe plus. Le client garde donc
  la preuve **avant** l'appel réseau, comme il le fait déjà pour la preuve
  d'enrôlement, et la rejoue au début de chaque authentification.
  C'est une **file** et pas une preuve unique, parce que le relais rend un `401` opaque
  identique pour tout refus de rotation (anti-oracle, R-SRV-1) : « jamais reçue » et
  « déjà appliquée » sont indistinguables depuis l'appareil. Plutôt que de deviner, il
  garde toute la chaîne et la rejoue du plus ancien au plus récent ; chaque preuve
  étant signée par un slot du batch dont elle part, le relais applique celles qui
  partent de là où il est vraiment. Une preuve acceptée, ou une auth acceptée, prouve
  que le relais a rattrapé et purge la file. Tests serveur
  `server/tests/test_rotate_batch_replay.py`, dont le contrôle négatif : rejouée à
  l'envers, la même chaîne ne rattrape qu'un cran.
  Ce qui **n'est pas** couvert : une file pleine (plafond 8, soit environ 400 auths
  refusées d'affilée sans une seule réussie) laisse un appareil déjà perdu ; le
  plafond borne la taille du fichier, il ne sauve rien.

### 4.3 Chaîne de confiance et rotation

```
Ed25519 long-terme ──(0x03 Enrollment)──► batch_0 (concat des 50 pk, 1600 o)
batch_0[49] ──(0x02 BatchRotation)──► batch_1
batch_1[49] ──(0x02)──► batch_2 → …
```

Le serveur vérifie chaque maillon et impose : signataire = slot non consommé du batch
courant, `batch_number` strictement croissant (toute tentative de rollback → 409),
rotation atomique sous lock. Un auditeur muni de la phrase peut rejouer toute la lignée
ex-post et vérifier que chaque blob uploadé est couvert par un slot légitime d'un batch
légitime. La propriété « no-rogue-batch » (tout batch accepté pour une identité honnête
remonte par signatures à son enrôlement) est un **lemme Tamarin vérifié**
(`rotation_lineage` + `root_authentic`).

### 4.4 Séparation de domaine des signatures (R-C-1)

Trouvaille de l'audit adverse + de la modélisation Tamarin (juin 2026) : la séparation
entre les contextes de signature n'était qu'**émergente** - clés vérifiantes
différentes, et écart de longueur entre le challenge d'auth (40 octets `nonce‖ts`) et le
message de rotation (1600 octets `concat(50 pk)`). Pas une vulnérabilité exploitable en
l'état, mais une surface de forge en attente du prochain changement d'endpoint ou de
format. Le fix (commit `da56da4`, modèle Tamarin actualisé) rend la séparation
**explicite et structurelle**. L'espace de tags compte aujourd'hui neuf contextes
(`signature_domain.rs`, enum `SignatureDomain` et son test de gel
`signature_domain_surface_is_frozen` — cité par symbole, les plages de lignes de ce
document ayant déjà pourri une fois), répartis en trois familles :

| Tag | Domaine | Clé signataire | Message | Surface |
|---|---|---|---|---|
| `0x01` | `AuthChallenge` | slot éphémère | `nonce ‖ ts_be_u64` | `/auth/v2/verify` (miroir serveur) |
| `0x02` | `BatchRotation` | slot éphémère | `concat(50 pk)` | `/auth/v2/rotate-batch` (miroir serveur) |
| `0x03` | `Enrollment` | Ed25519 long-terme | `concat(50 pk)` | `/auth/v2/enroll` (miroir serveur) |
| `0x04` | `ArchiveAuth` | (Ed25519 long-terme) | (n/a) | **réservé, retiré** (archives sans identité, §8.7) |
| `0x05` | `ProvenanceManifest` | (clé provenance `P`) | (n/a) | **réservé, retiré** (recul métadonnées 2026-06-25) |
| `0x06` | `ProvenanceKeyAttestation` | (Ed25519 long-terme) | (n/a) | **réservé, retiré** (recul métadonnées 2026-06-25) |
| `0x07` | `ReportCreate` | clé report `R_n` (dérivée seed) | `report_id(16) ‖ report_pk(32)` | `PUT /file/{rid}/{name}` 1er chunk (miroir serveur) |
| `0x08` | `ReportWrite` | clé report `R_n` (dérivée seed) | `report_id(16) ‖ filename ‖ sha256(body)(32)` | `PUT /file/{rid}/{name}` chaque objet (miroir serveur) ; revérifiée au secours |
| `0x09` | `ReportClose` | clé report `R_n` (dérivée seed) | `report_id(16) ‖ u32_be(seq_limit) ‖ sha256(manifest)(32)` | `POST /close/{rid}` (miroir serveur) ; revérifiée au secours |

Source de vérité Rust : [`crypto-rs/core/src/signature_domain.rs`](../crypto-rs/core/src/signature_domain.rs) ;
miroir serveur byte-identique : [`server/app/signature_domain.py`](../server/app/signature_domain.py)
(`0x01`-`0x04` et `0x07`-`0x09` y ont une constante ; le test serveur
`test_signature_domain_mirror.py` vérifie le miroir, et `test_report_close_kat.py` vérifie
en Python des signatures `0x09` figées par Rust, sans jamais re-signer ; `0x05`/`0x06` n'en ont jamais
eu, ayant été hors-ligne quand on les croyait vivants). Attention à ne pas confondre
deux choses : `0x04` garde une constante réservée côté serveur
(`SIG_DOMAIN_ARCHIVE_AUTH`, pour que l'octet n'y soit jamais réutilisé non plus) mais
n'a plus de **vérificateur**. `0x04`, `0x05` et `0x06` sont **conservés dans l'enum pour
la stabilité du contrat wire** et n'ont plus de flux actif : `0x04` depuis que la lecture d'archive est sans identité (§8.7), `0x05`/`0x06`
depuis le recul métadonnées du 2026-06-25 qui a supprimé le manifeste signé au profit du
modèle hash + Bitcoin. Rien ne les émet ni ne les vérifie, ni sur l'appareil, ni en CLI,
ni sur le relais ; les octets restent réservés pour qu'ils ne soient jamais réutilisés. Le
tag est préfixé au message côté signature **et** côté vérification ; il est hardcodé
à l'intérieur de `sign_and_advance`/`advance_batch` (zéro changement pour les appelants
Kotlin), et l'ancien `sign_once` dual-use a été scindé pour rendre la confusion de domaine
**impossible par construction** côté client. Il n'en reste aujourd'hui qu'une méthode,
`sign_enrollment` (0x03) : son pendant `sign_archive_challenge` (0x04) est parti avec le
modèle relais-aveugle, cf. §5.2. Les tests incluent la non-vérifiabilité
cross-domaine in-crate, la parité ratchet, et un contrôle négatif Tamarin (collapse des
tags → le lemme d'authentification se falsifie, comme attendu). Le jeu de tags est en
outre **gelé par un test à `match` exhaustif** (`signature_domain_surface_is_frozen`) :
ajouter ou retirer un domaine ne compile plus tant que le modèle Tamarin, le miroir serveur
et cette section ne sont pas mis à jour en lockstep (gate anti-dérive, §9.3).

### 4.5 Format STRM - le conteneur chiffré

Chaque chunk vidéo (et le manifest de session) devient un blob STRM autonome :

```
"STRM" ‖ version (0x03 V3 courant ; 0x02/0x01 legacy acceptés en lecture seule)
       ‖ sealed_session_key (80 = crypto_box_seal de K_s vers x25519_pk de l'auteur)
       ‖ grant_count (u16 BE, toujours 0 ; un blob qui en déclare est refusé)
       ‖ mode (0x01 SINGLE ≤ 10 MiB | 0x02 CHUNKED, sous-chunks 1 MiB)
       ‖ payload XChaCha20-Poly1305
```

Propriétés :

- **V3 (Phase C / WP-A) : aucune identité au repos.** L'en-tête V3 a **retiré
  l'`author_ed25519_pk`** (présent en V1/V2, octets [5..37]) : une saisie du disque relais
  ne mappe plus `report_id → identité` à partir des seuls octets du blob — c'est le motto
  (« une saisie n'expose rien »). Le champ était *dead* (jamais lu au déchiffrement, qui
  passe par le sealed envelope vers le `x25519_pk` de l'auteur). Un blob V3 est un objet
  wire distinct (jamais de tag AEAD partagé avec un V2). Source de vérité :
  `crypto-rs/stream/src/header.rs`.
- **Le binaire expedié ne décode que V3.** Depuis la décision d'architecture du
  2026-08-28, la lecture des conteneurs hérités V1/V2 vit derrière la feature Cargo
  `legacy-strm`, que seule la CLI active : un témoin relit une archive ancienne sur un
  ordinateur, et l'application n'embarque aucun parseur hérité. C'est la forme déjà
  retenue pour le blob ratchet (`deserialize` refuse V1, `migrate_from_v1` est
  l'échappatoire CLI explicite). **L'isolation ne repose pas sur la commande de
  build** : Cargo unifie les features à l'échelle d'un graphe, donc construire le
  workspace d'un bloc redonnerait le parseur hérité au `.so` sans que rien ne le dise.
  Un marqueur n'existant dans le binaire que sous la feature est donc vérifié par
  `build-android.sh` **et** par la garde Gradle `checkRustSoFresh`, qui refusent tous
  deux un `.so` qui le porte : le binaire dit ce qu'il est, au lieu qu'on fasse
  confiance à la commande qui l'a produit.
- **K_s aléatoire par blob**, jamais réutilisée, wipée après scellement ; chiffrement
  indéterministe de bout en bout (aucun octet constant exploitable).
- **Enveloppe scellée = `crypto_box_seal` anonyme** (reproduction pure-Rust de libsodium,
  [`crypto-rs/core/src/seal.rs`](../crypto-rs/core/src/seal.rs) ; interop Android/CLI/Python
  nacl) : `epk(32) ‖ XSalsa20-Poly1305(tag 16 ‖ ct 32)` = 80 o, avec un **keypair X25519
  éphémère par blob**. L'`x25519_pk` long-terme de l'auteur **n'apparaît jamais** dans
  l'envelope (seul l'`epk` éphémère y figure) : le scellement est **sender-anonyme**, un
  renfort direct du motto V3 « aucune identité au repos ». Le nonce du box interne est
  déterministe — `BLAKE2b(epk ‖ recipient_pk)`, le shape exact de libsodium — mais jamais
  rejoué car l'`epk` est ré-aléatoire à chaque scellement. Le chiffre de l'envelope
  (XSalsa20-Poly1305, NaCl box) est distinct de celui du payload (XChaCha20-Poly1305).
- **AAD = l'en-tête complet** : retirer un grant ou tronquer l'en-tête invalide le MAC
  Poly1305 du payload.
- Mode CHUNKED : nonce = `prefix(20) ‖ index_be_u32` - anti-réordonnancement et
  anti-troncature des sous-chunks, `chunk_count` lié ; bornes anti-DoS
  (`MAX_CHUNK_COUNT`, `MAX_CHUNK_LEN`) testées au mutant près (§9.3).
- **Self-envelope systématique** : l'auteur est toujours destinataire de son propre blob
  - c'est ce qui rend l'archive possible avec la seule phrase.
- **Les grants multi-destinataires n'existent pas, et le décodeur les refuse.** Le
  champ `grant_count` est réservé sur le fil et l'encodeur y écrit toujours 0 ; depuis
  la décision d'architecture du 2026-08-28, un blob qui en déclare **au moins un** est
  rejeté (`HeaderError::GrantsNotSupported`) au lieu d'être parcouru. Le parseur ne
  déroule donc plus `grant_count` entrées de 112 octets d'entrée non fiable pour une
  fonctionnalité qui n'a jamais existé : c'est de la surface de parseur en moins, donc
  de la preuve en moins à porter. Le champ reste à zéro sur le fil, donc aucun blob
  existant ne devient illisible et il n'y a pas de V4. Rouvrir le sujet, c'est
  implémenter le partage multi-destinataires, pas assouplir le contrôle. Prouvé par
  Kani (`check_parse_header_rejects_any_grant`).
- Le parseur d'en-tête est la pièce la plus exposée (il mange des octets non fiables) :
  c'est précisément lui qui est couvert par Kani (no-panic exhaustif borné), le fuzzing,
  la mutation à 98-100 % et les tests de bornes ±1.

Le déchiffrement n'existe que dans deux contextes : mode archive (phrase saisie,
`x25519_sk` re-dérivée en RAM, wipée à la fermeture) et CLI desktop. Sur Android, le
secours télécharge d'abord l'objet **chiffré** sur disque (`archive_fetch_object`, qui
rend aussi son empreinte et la signature d'écriture que le relais a gardée), le vérifie
(§7.4), et ne le déchiffre qu'**ensuite**, fichier à fichier dans Rust
(`strm_decrypt_to_file`), vers le stockage privé de l'application : le clair ne
traverse pas la JVM. Le legacy qui copiait le plaintext vers la JVM avait été scellé
hors FFI (audit 8.1.6 #2) ; l'ancien chemin qui téléchargeait et déchiffrait en un appel,
sans vérifier l'origine, a été retiré.

### 4.6 Stockage local : PIN store double-protégé

Les secrets persistants du device sont le blob ratchet, l'état de rapport
(`report_state.bin`, §8.7) et la graine de provenance. Le blob ratchet est rangé sous
**deux couches indépendantes**, décrites ci-dessous ; l'état de rapport est un fichier
possédé par Rust, scellé par la clé de session PIN (même dérivation Argon2id, AAD
`frappuccino-report-state-v2`), qui ne traverse jamais la JVM. S'y ajoute la **clé de
file**, 32 octets aléatoires qui scellent les en-têtes des enveloppes en attente (§6.3) :
elle est rangée dans un `EncryptedFile` sous la clé maîtresse du Keystore, donc au niveau
de protection de la couche plateforme seule, sans PIN.

1. **Couche crypto (la vraie)** : Argon2id (`m = 256 MiB, t = 4, p = 1`, salt 16 o)
   dérive une clé de 32 o depuis le PIN → XChaCha20-Poly1305 avec AAD versionnée
   (`"frappuccino-v2-pin-store-v1"`). ~1,2 s par dérivation sur le device de référence ;
   un fast-reseal (`pin_store_seal_with_key`) évite de repayer Argon2id à chaque
   consommation de slot, la clé dérivée restant côté Rust.
2. **Couche plateforme (défense en profondeur)** : le blob scellé est rangé dans
   `EncryptedSharedPreferences` (MasterKey du Android Keystore, adossée au TEE quand il
   existe). Cette couche ne porte **aucun** claim de sécurité propre - elle coûte zéro
   et oblige un attaquant à passer par l'extraction du Keystore *en plus* du
   brute-force Argon2id.

Anti-bruteforce actif : deny-list avec backoff sur les tentatives de PIN
(`PinAttemptTracker`). Ordre de grandeur assumé honnêtement : un PIN 6 chiffres face à
un attaquant GPU déterminé tombe en jours/semaines malgré Argon2id - mais ce qu'il
protège (les signatures futures) ne vaut pas ce prix, et c'est le point : **le PIN ne
garde aucun contenu**.

### 4.7 Cycle de vie des secrets en RAM

- Unlock PIN → ratchet désérialisé en RAM. Ses champs `private_keys`/`next_chain_key`
  ([`crypto-rs/core/src/ratchet.rs:162-163`](../crypto-rs/core/src/ratchet.rs)) sont des
  arrays nus zéroïsés via `Zeroize::zeroize()` au `Drop`/`wipe()` (et **non** le wrapper de
  type `Zeroizing`, lui réservé aux copies de pile transitoires `seed`/`signer_seed`), **et
  pas mlock'd** (décision assumée : Android n'a pas de swap disque, seulement de la zram -
  cf. revue de design §2.6) ; `mlock`/`LockedSecret` couvre les secrets dérivés de la phrase
  (identité, provenance, et le `report_master` legacy le temps de la migration, §8.7). Le
  maillon de chaîne, la graine d'annuaire et la clé du rapport en cours sont, comme le
  ratchet, zéroïsés au `Drop` sans être `mlock`'d. JWT d'upload tenu **côté Rust** dans un holder
  `Zeroizing` (`UPLOAD_JWT`, stashé par `verify()`), jamais sur disque ni dans un Intent.
  `UploadAuthHolder` n'en est qu'une façade fine : il n'expose que le bit de présence ou,
  pour une requête, une copie transitoire immédiatement relâchée. Le bearer ne traverse
  donc plus la frontière FFI en `String` Kotlin et ne réside plus dans le heap Dalvik
  (§10.7).
- **Auto-lock du ratchet** : timer d'inactivité dédié (défaut 15 min, configurable),
  **séparé** du clear JWT (dont la temporalité est field-tunée pour ne jamais perdre de
  footage), wipe du ratchet à l'idle, **jamais pendant un enregistrement** (déféré tant
  que le service capture/chiffre), re-PIN exigé au retour.
- `lock()` explicite, `panicWipe()` (§7.3), et destruction du process : dans tous les
  cas le blob au repos reste scellé Argon2id.

### 4.8 Ce que le protocole garantit - et la part de preuve

| Propriété | Mécanisme | Niveau de preuve |
|---|---|---|
| Confidentialité des streams vs device saisi | Pas de `x25519_sk` sur le device ; scellement par blob | Design + revue ; vérité d'implémentation couverte par tests/parité/fuzz |
| Forward security de l'authentification | Wipe immédiat + HKDF one-way + rotation | **Tamarin** `forward_secrecy_auth` (Dolev-Yao) ; wipe prouvé non-élidé en **LLVM IR**. Porte sur l'authentification, pas sur les rapports |
| Rapport clos figé | Clé du rapport effacée à la clôture, état avancé non redérivable (chaîne HKDF) ; le relais refuse tout nom hors de l'ensemble déclaré une fois la clôture `0x09` enregistrée | Tests Rust (chaîne, écrivain, KAT `report_chain_kat.rs`) et pytest (`test_report_close.py`, `test_report_tombstone.py`, KAT croisé `test_report_close_kat.py`). **Pas de modèle Tamarin des rapports.** Ne couvre pas le rapport en cours ni ceux ouverts après une extraction (§10.1) |
| Authenticité des objets au secours | `write_sig` (`0x08`) et clôture (`0x09`) revérifiées sous la `report_pk` **re-dérivée de la phrase**, jamais sous une clé reçue du relais ; ce qui ne vérifie pas est exclu et compté | Tests Rust de `ReportRescue` et du secours FFI ; parité de code Android/CLI (même module Rust) |
| Authentification de l'upload | Challenge-response Ed25519, domaine `0x01` | **Tamarin** `auth_slot_origin` |
| Anti-rejeu | Nonce TTL 60 s à pop atomique + usage unique des slots persisté | **Tamarin** `nonce_use_once` + **TLA+** `AntiReplay` (exhaustif borné) |
| Anti-rollback / monotonie | `batch_number` strictement croissant côté serveur | **TLA+** `NoRollback`/`MonotoneBatch` + tests concurrence serveur |
| Inforgeabilité des rotations | RotationProof signé par slot du batch précédent | **Tamarin** `rotation_authentic`, `rotation_lineage`, `root_authentic` |
| Non-confusion des contextes de signature | Tags de domaine explicites R-C-1 | **Tamarin** (post-R-C-1, 10/10 + contrôles négatifs) + tests cross-domaine |
| Intégrité/anti-troncature des blobs | AAD = header complet, nonce indexé, `chunk_count` lié | Mutation 98-100 % + Kani + fuzz + tests de bornes |

La colonne de droite est le cœur de la crédibilité du projet : chaque ligne pointe vers
un artefact rejouable (§9), pas vers une affirmation.

---

## 5. `crypto-rs/` - le cœur Rust

### 5.1 Topologie

```
crypto-rs/                     # workspace Cargo (toolchain pinnée, deny.toml)
├── core/                      # bip39, hkdf, identity, ratchet, pin_store, seal,
│   │                          # secret (mémoire verrouillée), signature_domain, error
│   ├── audit/                 # assert_zeroize_not_dse.sh (guard IR exécutable)
│   ├── proofs/                # EphemeralRatchet.tla + .cfg, RatchetProtocol.spthy,
│   │                          # run-tlc.sh (JVM Windows), run-tamarin.sh (WSL)
│   └── tests/                 # KATs, proptest FSM, parité, bornes
├── stream/                    # header, encrypt, decrypt, protocol (client serveur V2),
│   │                          # pin (verifier TLS SPKI rustls), secure_delete, kani_proofs
│   └── tests/                 # decrypt_boundaries, header_boundaries, proptest_roundtrip…
├── ffi/                       # frappuccino.udl → bindings Kotlin UniFFI + .so par ABI
├── cli/                       # frappuccino-cli : six sous-commandes, voir --help
│   │                          # parity-test, protocol-probe, migrate-v1-ratchet
│   └── bin/                   # difffuzz_dump (corpus diff-fuzz), generate_fuzz_seeds
├── fuzz/                      # cargo-fuzz : decrypt / header / ratchet / pin_store
├── difffuzz-jvm/              # harnais Gradle/JVM rejouant le corpus via UniFFI→JNA
└── build-android.sh           # .so arm64/armv7/x86_64 + régénération bindings
```

### 5.2 La frontière UniFFI

Toute la surface exposée à Kotlin est déclarée dans `ffi/src/frappuccino.udl` :
génération BIP-39 (`bytes`, jamais `string` pour le matériel sensible), PIN store
(`pin_store_open` seul - survivant pour le seul harness diff-fuzz, **0 appelant
prod** ; `pin_store_seal` a été retiré de la surface le 2026-09-03, la justification
« gardé pour le harnais » étant fausse : le harnais ne traversait la FFI que pour
`open`. Les chemins prod scellent/ouvrent in-crate via le holder PIN-session
`pin_session_*` ;
`open_extended`/`seal_with_key`/`open_with_key` retirés à la migration no-export R-CR-1, §8.8),
l'**état de rapport** (`pin_session_create_report_state` à l'inscription,
`pin_session_migrate_report_state` à la migration, `pin_session_open_report` qui rend un
écrivain, `report_state_wipe`), l'**écrivain de rapport** `ReportWriter`
(`seal_directory_entry`, `seal_metadata`, `seal_chunk_file` : Rust lit le MP4 en
`Zeroizing`, le chiffre, le signe et écrit l'enveloppe - le plaintext ne traverse pas la
JVM -, `close_report`, `abort`, plus `report_writer_abort_live` pour l'effacement
d'urgence), la **file d'enveloppes** (`queue_key_*`, `envelope_inspect`,
`upload_send_envelope` qui construit l'URL depuis l'enveloppe et la vérifie avant tout
envoi), la conversion legacy (`legacy_convert_*`, `legacy_write_closure`), l'horodatage
(`ots_ticket_*`, `pin_session_seal_ots_proof`, `ots_proof_status`), `EphemeralRatchet`
(`sign_and_advance`, `advance_batch`), `EnrollmentKit` (`sign_enrollment` - domaine `0x03`
unique ; le `0x04` ArchiveAuth / `sign_archive_challenge` a été **retiré** avec le modèle
relais-aveugle, cf. §4.4), `ArchiveIdentity`, le **secours** `ReportRescue` /
`RescuePlanner` / `ReportCheck` (énumération, vérification par objet et par clôture,
verdict), `StreamServerClient` (challenge/verify/rotate + `archive_list`, qui rend la liste
et la clôture, et `archive_fetch_object`, qui télécharge le chiffré sur disque),
`strm_decrypt_to_file`, `secure_delete_file`. Les anciens points d'entrée qui chiffraient
sans signer (`strm_encrypt_file`), signaient à l'envoi (`upload_put_report_chunk`,
`upload_put_directory_entry`) ou téléchargeaient sans vérifier (`archive_list_blobs`,
`archive_download_and_decrypt`, `archive_download_raw`) ont été retirés de la surface.

Deux choix structurants :

- **Le client HTTP sensible est en Rust** (`stream/src/protocol.rs`) : c'est lui qui
  parle au relais pour l'auth et l'archive, sous le verifier TLS épinglé. Kotlin
  orchestre, Rust signe et vérifie.
- **Le fuzzing différentiel rejoue les bindings réels** (UniFFI→JNA, même codegen que
  l'APK) : une divergence dans le marshalling serait détectée par l'oracle 759/759,
  pas découverte sur le terrain.

⚠️ Les `.so` et bindings générés ne sont pas trackés en git - régénération par
`build-android.sh` ; un guard Gradle (`checkRustSoFresh`) empêche d'embarquer un `.so`
périmé (symptôme historique : handshake TLS qui échoue silencieusement).

### 5.3 Discipline de code

Règles de codage internes, non publiées, mais dont l'application se vérifie sans elles - dans les `Cargo.toml`, `crypto-rs/deny.toml` et les gates ci-dessous : dépendances épinglées **exactes** ; **zéro
`unsafe`** dans le workspace ; newtypes pour le matériel de clé ; `Zeroizing`/`#[must_use]`
systématiques ; gates `cargo clippy --all-targets -- -D warnings`, `fmt --check`,
`cargo deny`, `cargo audit`. Couverture tarpaulin ~90 % sur le workspace - chiffre cité
pour ce qu'il vaut : la couverture mesure ce qui est *exécuté*, le mutation testing (§9.3)
mesure ce qui est *vérifié*.

### 5.4 TLS épinglé (SPKI) - domaine + jeu de 3 pins break-glass

Verifier rustls 0.23 custom : la confiance est réduite à l'empreinte SPKI du serveur
relais (comparaison constant-time), pas au CA store système - un MITM étatique avec une
CA valide n'obtient rien. Le finding RT-01 (helpers `verify_tls1[23]_signature` qui ne
vérifiaient pas réellement `CertificateVerify`) a été fixé en délégant aux helpers
rustls, avec **test de régression MITM** : un handshake TLS 1.3 in-memory présentant le
certificat épinglé mais signant avec une mauvaise clé est rejeté
(`InvalidCertificate(BadSignature)`).

**Le pin n'est plus single-key ni adossé à une IP** (Lot 3, audit 2026-06-26, D-2).
Deux changements structurels, dans [`crypto-rs/stream/src/pin.rs`](../crypto-rs/stream/src/pin.rs) :

1. **Domaine, plus IP brute.** Le relais est joint par le nom
   `relay.shake-document-protect.org` (enregistrement DNS A vers l'IP de test ;
   `PINNED_HOST` ligne 69). Le certificat reste **auto-signé épinglé par SPKI** (stratégie
   bêta, **pas** Let's Encrypt), le `host-check` SNI est strict, donc l'URL d'upload
   Kotlin (`DEFAULT_SERVER_URL`) doit utiliser ce même nom. Conséquence SNI honnête : voir §10.4.
2. **Jeu de pins, plus pin unique.** `PinnedCertVerifier` porte un `Vec<[u8;32]>` et
   accepte le certificat si son SPKI matche **n'importe lequel** des pins en
   **constant-time** (OR sans early-exit, `spki_matches_any`). Trois pins sont pré-amorcés
   pendant que le parc est sain (`PinnedCertVerifier::new`, pin.rs:110-115) :
   - `PIN_SHA256_B64` (`QnGK0K…`) - **primaire**, la clé courante du relais ;
   - `PIN_NEXT_B64` (`AmIDSg…`) - **break-glass servi** : c'est le certificat dual-SAN que
     le relais sert au moment du basculement de domaine ; sa clé vit sur le relais ;
   - `PIN_NEXT2_B64` (`MUb4HH…`, ligne 62, ajouté 2026-06-28) - **break-glass off-host** :
     sa moitié privée est générée et conservée **hors du relais, jamais déposée dessus**.
     Le certificat est **dormant** (embarqué comme pin + ancre NSC, non servi). C'est le
     chemin de récupération après **saisie du relais** : les deux clés servies tombent
     ensemble dans une saisie ; on monte alors un nouveau relais, on y dépose cette clé,
     on re-pointe le DNS vers le même domaine, et le parc l'épingle/lui fait déjà
     confiance - **le cutover ne demande aucun push d'APK**. Son SAN est le domaine seul.

Aucun de ces pins n'est une « CA de secours » : ce sont trois clés que **nous**
contrôlons, l'union n'affaiblit pas la résistance MITM. Le verifier QUIC du transport
ObfQuic porte le **même jeu de 3 pins** (quic.rs:118-120), et un guard Gradle
(`checkRustSoFresh`) exige les trois dans chaque `.so`. La rotation/le cutover sont
documentés dans le runbook
[`docs/TLS_PINNING_ROTATION_RUNBOOK.md`](TLS_PINNING_ROTATION_RUNBOOK.md) (clé off-host,
`certbot --reuse-key` pour la migration LE future, procédure sans rebuild).

---

## 6. Pipeline de capture et de streaming HEVC

### 6.1 Pourquoi pas CameraX `Recorder`

Deux raisons mesurées sur le terrain, pas théoriques :

1. **Contrôle réel** : `Recorder` traite le bitrate comme un soft-hint (ignoré par
   certains HAL) et n'offre pas de sélection de codec. Pour du streaming adaptatif
   chiffré, il faut piloter MediaCodec directement : HEVC matériel (~35-45 % de gain de
   débit vs H.264 à qualité égale), VBR↔CBR commutable, rotation de chunks sans rebind.
2. **Survie écran éteint** : le pipeline legacy `VideoCapture<Recorder>` gelait sa
   session caméra écran éteint sur batterie (surface de preview on-screen morte →
   reconfiguration HAL qui stalle - observé OnePlus : 6 min de trou silencieux). Pour
   une app dont le cas d'usage est *filmer en poche*, c'est disqualifiant.

### 6.2 Le wedge OpenGL ES

```
CameraX (Preview + Camera2Interop) → SurfaceTexture OES (off-screen)
   → quad GL (EGL14) : correction d'aspect + letterbox
   → double-draw : Surface MediaCodec HEVC  +  preview écran (si visible)
   → MP4 chunk 5 s (RollingChunkRecorder, swap atomique de Surface < 10 ms)
```

Le wedge (`GlVideoPipeline.kt`) découple la caméra de l'écran : la texture OES est
consommée en continu (`updateTexImage`) que l'écran soit allumé ou non - c'est ce qui
rend le recording écran-éteint structurellement immunisé au gel du legacy. Il contourne
aussi le refus de certains HAL (MediaTek) d'une Surface MediaCodec branchée en direct.
Depuis 3.7 (juin 2026), le wedge GL est **l'unique pipeline** : le legacy a été retiré
(−716 lignes) après A/B in-vivo sur les deux SoC de référence.

Briques attenantes : `HevcMediaCodecEncoder` (HEVC matériel + **fallback H.264
runtime** sur `onCodecError`, one-shot, sans rebind caméra) ; `AacEncoderSession` +
`PcmCaptureThread` (audio AAC, PTS `CLOCK_BOOTTIME` absolus, ancrage partagé par chunk) ;
`AdaptiveQualityManager` (montée/descente pilotée par le backlog d'upload, hystérésis,
cooldown anti yo-yo, plafond qualité configurable) ; `ChunkEncoderBundle` (muxing par
chunk + tripwire de synchro `chunkStartSkew` loggé à chaque chunk).

### 6.3 La propriété centrale : chiffré-uploadé pendant la capture

Chaque chunk de 5 s suit, en continu :

```
onChunkReady → exécuteur mono-thread FIFO → ReportWriter.seal_chunk_file(seq) (Rust)
  : lit le MP4 (Zeroizing), le chiffre en STRM, signe 0x08, écrit l'enveloppe
    (.part → sync_all → rename → fsync du répertoire), PUIS l'enregistre au manifeste
  → secure_delete du MP4 clair (seulement après succès)
  → EnvelopeQueue (filesDir/stream_envelopes, persistante)
  → WorkManager ChunkUploadWorker, un job par enveloppe : upload_send_envelope (Rust
    revérifie l'enveloppe, construit l'URL, PUT), bearer tenu côté Rust, backoff
    exponentiel, concurrence adaptative 1-6, circuit-breaker 507
```

**Signature à la production, jamais à l'envoi.** Au début de l'enregistrement, l'appareil
ouvre le rapport suivant (`pin_session_open_report` : l'état avance et est réécrit
durablement **avant** que l'écrivain soit rendu), scelle l'entrée d'annuaire et le JSON de
métadonnées (seq 0) ; un échec à ce stade annule l'écrivain et l'enregistrement ne démarre
pas. Chaque chunk reçoit ensuite son **numéro de capture** (seq ≥ 1) et devient un objet
`NNNNNN.strm`. Un échec de scellement est réessayé un nombre borné de fois ; au-delà, le
MP4 est effacé et compté **perdu**, et le compteur est affiché. À l'arrêt, la clôture est
la **dernière** tâche de l'exécuteur, soumise après le retour réel du `stop()` de
l'enregistreur ; le service reste au premier plan, wake lock tenu, jusqu'à l'écriture de
l'enveloppe de clôture, puis la clé du rapport est effacée. Une borne de sécurité longue
force la clôture si l'enregistreur ne rend pas la main, et tout chunk livré ensuite est
compté perdu et affiché. Une enveloppe de file porte la charge utile exacte à envoyer et
un en-tête chiffré (XChaCha20-Poly1305 sous la clé de file) qui contient l'adresse du
rapport, les signatures et le nom de l'objet ; avant tout envoi, Rust déchiffre cet
en-tête, re-hache la charge utile, vérifie `report_id = H(pk)` et la signature : une
enveloppe qui ne vérifie pas n'est jamais envoyée, ni re-signée (statut
`envelope_corrupt`). Une enveloppe n'est effacée que lorsque le relais la détient (2xx) ;
un refus définitif la range dans `stream_envelopes_failed/`, comptée et affichée jusqu'à
l'effacement d'urgence. Une enveloppe refusée ne peut pas repartir : elle ne peut être
re-signée, et la clé de son rapport n'existe plus (résidu R5, §10.2).

**Garde-fou d'hygiène (F-01, cross-audit 2026-06-30).** Si un MP4 de chunk se trouve
**finalisé mais pas encore chiffré** lors d'une mort anormale du process (panic en plein
scellement, kill OEM), plus rien ne peut le sceller : la clé de l'écrivain est morte
avec le process. **Au démarrage du process** (`MyApplication`, avant tout enregistrement),
le répertoire de scratch est renommé de façon synchrone puis écrasé hors du thread
principal (`CaptureScratchCleaner.detachForStartup`), et une passe interrompue est
reprise au démarrage suivant. `CaptureScratchCleaner.purgeOrphanChunks` secure-delete
aussi **tout** `.mp4` orphelin (quelle que soit sa taille) **avant le bind caméra** au
démarrage du service, et en fin de session **après la clôture du rapport** ; un MP4 non
vide trouvé à ce moment-là est compté perdu. Le contrôle at-rest porteur reste le FBE Android ; cette purge est une
défense en profondeur qui ferme la fenêtre « clair résiduel » entre la finalisation MP4 et
son chiffrement.

Le bearer d'upload est toujours **détenu côté Rust** (`Zeroizing`, jamais en `String`
JVM), et l'upload du chunk est **Rust-only par construction** (design verrouillé) : les
signatures de capacité sont déjà dans l'enveloppe, posées à la production, et Rust en
tire les en-têtes ; il n'existe **aucun chemin OkHttp** de repli côté worker (un PUT
OkHttp serait identity-based, donc rejeté par le relais aveugle). Un binding natif
malsain remonte en `Throwable` → `Result.retry()` (l'enveloppe reste sur disque pour la
tentative suivante), **pas** en bascule de transport ; l'ancien flag `enabled` + « filet
OkHttp » a été retiré à l'audit 2026-06-26 (R-CR-5 : zéro lecteur, le repli décrit
n'existait pas). Le transport Rust route le PUT des objets, le POST de clôture et le
secours entièrement côté Rust, par la même primitive en `DirectTls` et en `ObfQuic` : le
bearer n'entre **jamais** dans la pile HTTP JVM (heap-0 par construction, §10.7).

**Le transport release est désormais `ObfQuic` (Salamander), plus `DirectTls`** (Lot 3
B4, clôture du finding structurel D-1). `RustUploadTransport.mode = TransportMode.OBF_QUIC`
en debug **et** en release (la déclaration du champ `mode` dans
[`RustUploadTransport.kt`](../mobile/src/main/java/rs/readahead/washington/mobile/util/jobs/RustUploadTransport.kt) ;
cité par symbole et non par numéro de ligne, qui pourrit) ;
le binaire release parlait auparavant du TLS épinglé en clair vers l'IP brute du relais,
de sorte qu'un DPI voyait *cela* et *quand* on uploadait. Détail de l'obfuscation,
du repli et de la réalité SNI : §10.4. La matrice réseau dégradé (Gate-0) et l'A/B
cubic-vs-bbr OnePlus (2026-06-16) montrent **0 perte end-to-end de 0 à 20 % de perte de
paquets** : l'intégrité ne dépend pas du transport (elle vient de la file persistante +
zéro abandon de chunk). Field-validé contre la prod sur **deux chipsets** (OnePlus
CPH2653 + MediaTek, 2026-06-27) : `transport=obfquic`, 0 repli, 0 erreur.

Conséquence : à l'instant T d'une saisie, tout ce qui précède T-quelques-secondes est
soit déjà sur le relais, soit en queue **sous forme chiffrée uniquement**. Le coût
crypto par chunk (~30-50 ms tout compris) est négligeable devant l'intervalle de 5 s ;
le goulot est la caméra, jamais le chiffrement.

La résilience de ce chemin a été durcie par itérations de terrain documentées :
queue persistante survivant reboot et mort de process, reprise réseau par
`NetworkCallback` + polling de secours, trio anti perte de données (report idempotent
par session, sweep serveur des reports zombies, HTTP **507** disk-full → circuit ouvert
immédiat côté client, blob préservé on-device - filet validé en condition réelle de
saturation totale du disque serveur : zéro chunk perdu). Depuis la signature à la
production, mettre une enveloppe en file n'exige ni JWT ni déverrouillage ; seul l'objet
qui **crée** un rapport (le premier, ou une entrée d'annuaire) a besoin d'un bearer, et
l'effacement du JWT comme l'auto-lock sont différés tant qu'une telle enveloppe attend.
L'ancien TTL de 48 h sur les chunks en attente (`sweepStaleChunks`) a été retiré : il
visait des fichiers impossibles à envoyer faute de clé, ce que la signature à la
production supprime.

### 6.4 Le squish 1.33 - autopsie d'un bug, méthode du projet

Ce bug mérite sa section parce qu'il illustre la différence entre *faire marcher* et
*comprendre*. Symptôme : étirement vertical ~1,33× du rush **et** de la preview sur
capteur 4:3. Première réponse (mai) : un facteur correctif empirique
`ANAMORPHIC_VSCALE = 0.75` - un fudge mesuré, honnêtement étiqueté comme tel dans le
code et la roadmap. Réponse finale (juin, commit `bb4c80d`) : harness debug 5 modes ×
mesure objective cv2 (`fitEllipse` sur un objet rond filmé, 4 coins) → loi établie
`H/W = (rotatedSrcH/rotatedSrcW) × vscale` → le `0.75` n'était que `1/(4:3)` : le
pipeline étirait le contenu par l'aspect de la source en l'empaquetant dans l'encodeur
9:16. Fix principiel : **vscale dérivé** de `rotatedSrcW/rotatedSrcH`, indépendant du
device et de l'aspect, validé cercle h/w = 1.000 ; preview rendue WYSIWYG (letterbox à
l'aspect encodeur). Les suspects intermédiaires (matrice `SurfaceTexture`,
`setDefaultBufferSize`) ont été **réfutés par mesure**, pas écartés par plausibilité.
Le harness est conservé pour re-valider tout futur device.

### 6.5 Limites connues du pipeline (assumées)

- **Audio au swap de qualité** : gap borné ~300 ms, ~1 fois/30 min (cooldown), **prouvé
  non-cumulatif** par le tripwire `chunkStartSkew` en field (les PTS sont absolus, chaque
  chunk se ré-ancre ; un trou ne décale jamais l'audio suivant). Le vrai fix (ring-buffer
  PCM ou repoint GL) a un rapport risque/valeur défavorable - différé, documenté.
- **Concat archive en un seul MP4** (4.4.7) : non livré ; la règle de re-basage des PTS
  audio/vidéo par chunk est spécifiée dans la roadmap pour éviter une désynchro
  cumulative sur les longues sessions. En attendant : le lecteur interne du mode archive
  enchaîne les chunks dans l'ordre des seq (§7.4), et l'export écrit des fichiers
  numérotés dans cet ordre.
- **Matrice de devices** : validé en profondeur sur deux SoC (MediaTek/Seeker,
  Snapdragon 8 Gen 3/OnePlus 13). Le plan d'élargissement existe
  ([`docs/DEVICE_TEST_MATRIX.md`](DEVICE_TEST_MATRIX.md)) ; l'exécution attend le parc.

---

## 7. Application Android (`mobile/`)

### 7.1 Surfaces V2

| Composant | Rôle |
|---|---|
| `StreamActivity` | Écran REC (style Blackmagic, thème noir/rouge `#CC1A1A`), `FLAG_SECURE`, gate `isLocked → PinUnlockActivity` |
| `PinUnlockActivity` | Unlock Argon2id (Rust), saisie convertie en `ByteArray` (le listener `PinLockView` legacy expose un `String` transitoire, cf R-D-1), deny-list backoff, `excludeFromRecents` |
| `StreamRecordingService` | Foreground service `camera\|microphone`, `PARTIAL_WAKE_LOCK`, recording écran éteint, flags `isRunning`/`isShuttingDown` contre les races de teardown |
| `StreamSettingsActivity` | Fingerprint, qualité max, shake-to-record, auto-lock, lock/panic - gate `isLocked → finish` à l'`onResume` |
| `ArchiveModeActivity` + `ArchiveDownloadService` | Récupération par phrase : FGS `dataSync` + WakeLock + WifiLock HIGH_PERF, énumération et vérification par rapport, statuts affichés, secrets passés en RAM via `ArchiveAuthHolder` (jamais par Intent/Binder) |
| `ArchivePlayerActivity` | Lecteur interne : `VideoView` en `setSecure(true)` + `FLAG_SECURE`, fenêtre glissante de chunks déchiffrés, section « non vérifiable » sous bandeau permanent |
| `V2LockTimeoutController` | Observateur ProcessLifecycle pur-V2 : timer JWT (field-tuné : ne fire jamais pendant un chiffrement in-flight, un recording ou son démontage, ni tant qu'une enveloppe qui peut exiger un JWT attend) + timer séparé d'auto-lock ratchet (15 min défaut) ; purge aussi les copies du lecteur interne : au passage en arrière-plan si aucun écran du secours n'est ouvert et qu'aucun lot ne tourne, puis, après le délai de l'auto-lock, même sous un écran resté ouvert derrière l'accueil, dès qu'aucun lot ne tourne (auto-lock désactivé : seule la première purge reste) |
| Onboarding | Génération + confirmation BIP-39 → PIN V2 → enrôlement serveur (avec worker de retry si offline) - **2 écrans PIN**, l'infra de lock Tella ayant été retirée |

### 7.2 Hygiène des secrets côté UI

Les entrées sensibles (PIN, mnemonic) vivent en `CharArray`/`ByteArray` wipés
(`SecureWipe`, qui évite l'élision JIT du `fill(0)` nu) ; aucun secret dans les Intents,
les logs (`logcat` gardé par règles Semgrep dédiées), ou les `SharedPreferences` non
chiffrées. `FLAG_SECURE` + `excludeFromRecents` + stealth black screen (overlay noir
immédiat, tap-to-exit) sur les surfaces exposées.

### 7.3 Panic wipe

L'effacement d'urgence procède dans cet ordre (`StreamSettingsActivity`, puis
`StreamUploadManager.panicWipe()`, à qui `ArchiveLocalData.detachForPanic()` remet les
répertoires du secours) :

1. **abandon synchrone de l'écrivain vivant** (`report_writer_abort_live`) : la clé du
   rapport en cours disparaît avant tout le reste, sans clôture ;
2. **annulation de tous les jobs WorkManager et de leur historique** (`workdb` prunée -
   fix R-E-2 : cette base était une timeline forensique en clair qui survivait au wipe) ;
3. **arrêt des services** d'enregistrement et de secours, et effacement des clés de la
   session d'archive ;
4. **clés et préférences** : ratchet en RAM et persisté, identité publique locale, JWT,
   graine de provenance, **clé de file** et **état de rapport** ;
5. **répertoires** : la file d'enveloppes, le répertoire d'échecs, les marqueurs, les
   tickets d'horodatage, les restes de l'ancienne file, le scratch de capture, puis les
   copies du lecteur interne (`noBackupFilesDir/archive_view`, `archive_recovery`) sont
   **renommés de façon synchrone** (une écriture tardive échoue alors au lieu de recréer
   un fichier) puis écrasés et supprimés en arrière-plan, en une seule passe : **le clair
   de toutes les parties d'abord** (scratch de capture, miroirs de debug, répertoires
   `plain/` du lecteur, `archive_recovery`), le chiffré ensuite ;
6. **anciennes exportations** : ce que des versions antérieures de cette installation ont
   écrit en clair dans `Download/Frappuccino/` (requête MediaStore à partir d'Android 10,
   qui ne rend que les entrées créées par l'app ; voie fichier avant).

L'app revient à l'état non-enrôlé.

Ce que le panic wipe ne fait **pas**, en toute clarté : il ne supprime pas les blobs déjà
uploadés (c'est le but - ils sont illisibles sans la phrase) ; il **n'efface pas les
exports explicites** faits par le sélecteur de fichiers du système (`ACTION_OPEN_DOCUMENT_TREE`),
qui sont hors de portée de l'app et que l'avertissement d'export annonce comme tels ; il
ne révoque rien côté serveur (il n'existe pas de route de révocation d'identité, et le
wipe n'émet volontairement aucun signal réseau sous contrainte) ; les enregistrements pas
encore envoyés sont perdus avec la file ; il ne garantit rien contre une image forensique
prise **avant** le wipe ; et sur un flash NAND, l'irrécupérabilité physique des secteurs
réécrits n'est pas démontrable depuis l'app (le blob restant étant scellé Argon2id,
l'enjeu réel est faible). Limites détaillées : §10.3.

### 7.4 Archive mode

La phrase saisie re-dérive **en RAM seulement** l'identité d'archive et, pour chaque
index, les `report_id`, clés publiques et noms des deux familles de rapports (legacy et
chaîne, §8.7) ; aucune clé de signature n'est nécessaire au secours. L'accès aux archives
est **sans identité** : aucune signature de challenge long-terme (`0x04`) n'est consommée.
Le secours est le module Rust `ReportRescue` (`crypto-rs/ffi/src/rescue.rs`), le même pour
l'APK et pour `frappuccino-cli fetch-archive`.

**Le secours vérifie avant de ranger.**

1. **Énumération.** Le secours liste l'annuaire, apparie ses noms d'entrée aux index des
   deux familles (*derive-and-match*), puis sonde chaque index jusqu'au plus haut
   apparié plus une marge. Une **clôture de l'annuaire** est affichée comme une anomalie
   (l'appareil ne clôt jamais l'annuaire ; il faut détenir sa clé, donc l'état de
   l'appareil ou la phrase, §10.1) et le sondage continue au-delà. Un 429 fait attendre au moins 60 s puis reprendre ; une énumération
   incomplète est affichée comme telle.
2. **Vérification**, sous la `report_pk` **re-dérivée de la phrase** (le `report_id` est
   recalculé, jamais reçu), objet par objet, avant tout déchiffrement :
   - **rapport chaîne clos** (clôture `0x09` valide, manifeste téléchargé et conforme) :
     chaque objet du manifeste dont l'empreinte est la bonne est `VERIFIED`, même sans
     signature stockée ; empreinte différente → `FOREIGN` ; absent → `MISSING` ; objet
     hors manifeste → `UNEXPECTED`. Le rapport est `COMPLETE`, `INCOMPLETE` (seulement des
     absents) ou `ALTERED` (un objet étranger, ou un objet hors manifeste validement
     signé, donc un second signataire) ;
   - **rapport chaîne sans clôture valide** : un objet est `VERIFIED` si la signature
     d'écriture gardée par le relais (`X-Report-Write-Sig`) vérifie, sinon il est exclu ;
     le rapport est `INTERRUPTED` (objets authentifiés un par un, fin non certifiée) ;
   - **rapport legacy** : signature d'écriture valide → `VERIFIED` ; objet stocké sans
     signature (avant que le relais les garde) → section **« non vérifiable »** ; une
     clôture legacy valide se lit « figé côté relais ».
   Ce qui ne vérifie pas est exclu et compté ; chaque rapport affiche son statut, ses
   compteurs et l'**intervalle de dates** de ses objets (horloge du relais), pour aider le
   témoin à repérer ce qui serait postérieur à une perte ou une saisie.
3. **Horodatage.** La preuve OTS déchiffrée est comparée à l'engagement recalculé depuis
   les objets `VERIFIED` (`OTS_MATCH` / `OTS_MISMATCH` / `OTS_ABSENT`) ; l'ancrage Bitcoin se
   vérifie avec le CLI.

**Lecture interne, export explicite.** Les objets vérifiés sont rangés **chiffrés** dans
`noBackupFilesDir/archive_view/<jeton aléatoire>/` (jamais nommé par le `report_id`,
exclu des sauvegardes). Le lecteur interne (`ArchivePlayerActivity`) ne déchiffre qu'une
**fenêtre glissante** de quelques chunks vers un répertoire privé et efface chaque chunk
dès qu'il en sort ; la capture d'écran est refusée deux fois (`FLAG_SECURE` et
`setSecure(true)` sur la surface). Fermer le secours annule le travail en cours et purge
(renommage synchrone puis effacement en arrière-plan) ; la même purge a lieu au démarrage
de l'app, au minuteur d'arrière-plan quand aucun lot ne tourne (après le délai de
l'auto-lock, même sous un écran du secours resté ouvert derrière l'accueil), et à
l'effacement d'urgence. L'**export** est un bouton par rapport, précédé d'un avertissement (la copie
quitte la protection de l'app et échappe à l'effacement d'urgence), vers un dossier choisi
par `ACTION_OPEN_DOCUMENT_TREE`, sous des noms neutres ; il ne contient que les objets
`VERIFIED`, plus la preuve OTS et son sel quand la preuve correspond. Un objet qui ne se
déchiffre pas est exclu de l'export et compté à l'écran, et le reste du rapport s'exporte ;
si c'est un chunk, la preuve et son sel sont exclus avec lui, puisqu'ils portent sur tous les
chunks vérifiés. Les objets **non
vérifiables** restent à part : listés dans leur propre section, lisibles sous un bandeau
permanent « non vérifié », exportables seulement par leur propre bouton, après un second
avertissement, vers un dossier distinct dont le nom et chaque fichier portent l'étiquette
`not-verified` ; jamais mêlés au témoignage vérifié, à ses compteurs ni à sa vérification
OTS. Aucune version actuelle n'écrit plus dans `Download/Frappuccino/`.

Un secours d'une version antérieure (APK ou CLI) ne connaît pas la famille chaîne : il ne
voit pas les rapports enregistrés après la mise à jour. Le listing d'un rapport n'est pas
paginé et le client le plafonne à 4 Mio (`MAX_LISTING_BYTES`) : un rapport non clos de plus
d'environ 46 000 objets n'est pas énumérable en entier (hors périmètre actuel).

---

## 8. Serveur relais aveugle (`server/`)

FastAPI (Python 3.12, Pydantic v2, uvicorn `--workers 1` imposé - le cache de nonces est
process-local par design documenté) + MinIO pour les blobs. Déployé en Docker Compose
durci sur une instance de test Vultr.

### 8.1 Ce que le serveur voit / ne voit jamais

**Ne voit jamais** : plaintext (vidéo, audio, manifest déchiffré), clés privées,
phrase/seed, PIN, identités réelles, IP dans les logs applicatifs.

**Voit** (et c'est le vrai sujet, §8.5) : pks Ed25519 pseudonymes, batches publics et
slots consommés, report_ids et `report_pk`, noms d'objets (numéros de capture
`NNNNNN.strm`, trous compris), tailles de blobs, timestamps, fréquences d'upload, et pour
un rapport clos sa clôture signée et son manifeste (nombre d'objets, empreintes des
blobs chiffrés). Il garde la signature d'écriture de chaque objet en métadonnée.

### 8.2 Auth V2 (`routes/auth_v2.py`)

- `POST /auth/v2/enroll` - vérifie la signature du batch_0 par l'identité long-terme
  (domaine `0x03`).
- `POST /auth/challenge` → `POST /auth/v2/verify` - nonce 32 o, TTL 60 s, **pop
  atomique** (anti-rejeu) ; le client signe `nonce ‖ ts` au domaine `0x01` avec un slot
  éphémère ; le serveur vérifie identité/batch/index/pk, consomme le slot
  **atomiquement** (anti-double-dépense, persisté), émet un JWT borné.
- `POST /auth/v2/rotate-batch` - vérifie le RotationProof (domaine `0x02`), impose la
  monotonie stricte du `batch_number`, rotation sous lock (course → 409).
- ⚠️ L'ancienne route `GET /auth/v2/status/{pk}` a été **retirée** (audit 2026-06-27,
  H-1 / R-SRV-1 : le bloc de retrait en fin de
  [`server/app/routes/auth_v2.py`](../server/app/routes/auth_v2.py)).
  C'était un **oracle d'activité d'identité** : n'importe qui connaissant un `pk`
  pseudonyme pouvait sonder son batch courant et ses slots restants, donc déduire
  l'activité du témoin. **Correctif d'honnêteté BT-05 (cross-audit, 2026-06-30)** : une
  note antérieure affirmait que « le client ne l'utilisait pas » - **c'était faux**.
  `authenticateV2` (Kotlin) la sondait encore après un échec d'auth (404 → ré-enrôlement
  → un 2ᵉ slot ratchet brûlé par auth ratée). Le débranchement complet du plumbing client
  (`get_status` dans `protocol.rs`/`ffi`/`udl`, `getServerStatus` Kotlin, `protocol_probe`
  CLI) ferme réellement la surface ; la désambiguïsation post-échec passe désormais par un
  état local (`hasPendingServerEnrollment`).
- JWT : durée bornée env-configurable (`JWT_EXPIRE_HOURS` ; il n'y a plus de jeton
  d'archive, les lectures étant sans identité), **révocable** (`/auth/v2/logout` +
  blacklist persistée vérifiée avant decode). C'est le **jeton** qui se révoque, pas
  l'identité.
  Pas de refresh token - décision de design : en V2, re-s'authentifier consomme un slot
  éphémère, c'est-à-dire que le « refresh » est lui-même forward-secure ; un bearer
  long-vécu réintroduirait exactement ce que le ratchet élimine.
- Rate-limit slowapi par endpoint, validation regex stricte des hex (anti
  path-traversal en amont).

### 8.3 Upload et durabilité

`PUT /file/{report_id}/{filename}` - chaque PUT porte `X-Report-PK` + `X-Report-Write-Sig`
(le chunk **créant** ajoute seul `Authorization: Bearer <JWT>` + `X-Report-Create-Sig` ; les
chunks suivants n'ont pas de JWT), whitelist regex sur les noms, streaming
`SpooledTemporaryFile`, PUT idempotent (resume sans double-compte). Filets de
durabilité éprouvés en conditions réelles : HTTP **507** sur disk-full (détection
S3Error MinIO → le client ouvre son circuit et garde le blob), reports idempotents par
`report_id` (= SHA-256 de la `report_pk`) : create-or-verify sous lock, ré-PUT même pk =
no-op, pk différente = 409 (anti-split sur retry) ; reap horaire des reports dont **tous les
blobs ont été purgés** (compte MinIO == 0, conséquence du TTL long de 6 mois - aucun
timestamp par-record ni seuil d'âge stocké), TTL blobs
6 mois (rétention longue **possible parce que** le contenu est E2E-chiffré ; le risque
résiduel est métadonnée/légal, pas contenu), audit horaire reports-vs-blobs en CSV,
backup volumes + restore scriptés (chiffrement age opt-in).

**Signature d'écriture conservée.** La `write_sig` (`0x08`) vérifiée d'un objet est
stockée en métadonnée utilisateur `x-amz-meta-report-write-sig` (hex minuscule) **par le
même `put_object` qui crée l'objet** ; un re-PUT identique d'un objet stocké sans elle la
pose (copie en place, ce qui change son `last_modified`). L'archive la renvoie dans
`X-Report-Write-Sig`. C'est une **donnée d'intégrité** : pour un rapport jamais clos,
elle est la seule chose qui permette au secours de distinguer un objet signé par la clé
du témoin d'un objet qui ne l'est pas. Toute migration de stockage doit donc copier les
métadonnées utilisateur avec les octets ; `deploy/audit-reports-vs-blobs.sh` compte les
objets qui en sont dépourvus (`without_write_sig`), à comparer avant et après.

**Clôture.** `POST /close/{report_id}` (en-têtes `X-Report-PK`, `X-Report-Close-Sig`,
`X-Report-Close-Seq-Limit` ; corps = manifeste `"FQM1" ‖ u32_be(count) ‖ count × (u32_be(seq) ‖
sha256(blob))`, lu en flux, plafond 40 Mo) vérifie `report_id = H(pk)`, l'existence du
rapport (425 sinon), la `report_pk` (409) et la signature `0x09` sur `report_id ‖
u32_be(seq_limit) ‖ sha256(corps)` (403). Sous le verrou du registre, le manifeste est
stocké en objet write-once `manifest` **avant** que la fiche dise « clos », puis la fiche
reçoit `{seq_limit, manifest_sha256, sig}` et est sauvegardée durablement ; une clôture
identique déjà enregistrée rend 204, une différente 409. Ni JWT ni budget. Le relais ne
parse pas le manifeste au-delà de son en-tête et de sa longueur ; c'est le secours qui le
vérifie.

**Règle après clôture.** Une fois la clôture enregistrée, un PUT n'est accepté que si
l'objet existe déjà (write-once : identique 204, différent 409) ou si son nom est
`NNNNNN.strm` avec `NNNNNN < seq_limit` ; tout autre nom reçoit **409 `Report closed`**.
Le contrôle de clôture, le test d'existence et l'écriture forment une section tenue sous
le verrou du registre, sans `await`, si bien qu'aucune clôture ne peut s'intercaler. Le
nom `manifest` est refusé en PUT (400). Une clôture legacy porte un manifeste vide
(`seq_limit = 0`) : elle fige le rapport sans rien lister.

**Pierres tombales.** Le reap horaire supprime la fiche d'un rapport **ouvert** dont tous
les objets ont expiré au TTL. Une fiche **close** n'est jamais supprimée : quand tous ses
objets, `manifest` compris, ont expiré, elle devient une pierre tombale qui refuse toute
écriture, pour que la clôture ne soit jamais oubliée (sinon un PUT de création
recréerait le rapport ouvert). L'archive répond 404 pour une pierre tombale vide, comme
pour un rapport inconnu. Coût : une petite fiche par rapport clos, gardée sans date.

**Registre durable et fail-closed.** `reports.json` est sauvegardé par
écriture-renommage puis **fsync du répertoire** (sinon une coupure pourrait ramener une
version antérieure et oublier une clôture déjà acquittée). Au démarrage, un fichier
illisible ou mal formé **empêche le relais de démarrer**, au lieu de repartir d'un
registre vide qui oublierait toutes les clôtures ; la réparation est la restauration d'une
sauvegarde. Restaurer une sauvegarde **antérieure** perd les clôtures plus récentes : les
rapports concernés se lisent alors « interrompus » au secours (résidu R6, §10.2).

**Ordre de déploiement.** Le relais se déploie **avant** l'APK qui envoie des clôtures, et
se vérifie par une sonde : `POST /close/<rid>` sans en-têtes doit rendre **400**, pas 404.
Côté client, un 404 sur `/close` signifie « route absente » : la clôture est réessayée avec
recul, jamais abandonnée.

### 8.4 Hardening

Conteneurs non-root (uid 1001), FS read-only + tmpfs, `cap_drop ALL`,
`no-new-privileges`, healthcheck Docker + moniteur externe, logs JSON structurés avec
**blocklist d'IP** (toute clé IP-like droppée), `access_log off` nginx, uvicorn sans
access-log, logs Docker bornés. Persistance JSON atomique (write-rename) pour le
registre ratchet et les reports, plus fsync du répertoire pour les reports (§8.3). État
thread-safe sous lock global.

### 8.5 Les métadonnées - le risque résiduel du relais

L'audit dédié ([`docs/METADATA_EXPOSURE_MAP.md`](METADATA_EXPOSURE_MAP.md)) tranche : la
question « le serveur voit-il les IP ? » est **maîtrisée** côté app (rien de loggé) ; la
couche IP reste visible de l'hébergeur et de l'opérateur réseau, hors de portée de
l'application. Depuis le passage au relais-aveugle (§8.7), `reports.json` ne stocke **plus
aucune identité** (`owner`/`author`/`createdAt` retirés) et les clés par-report sont
**indépendantes** : les reports d'un même témoin sont mutuellement **non-liables** au
repos. Le résidu n'est donc plus une corrélation par `owner_pk` (supprimée) mais une
corrélation par **volume, horodatages et cadence** des blobs, plus la **liaison
inter-sessions** que concentre le répertoire de rescue sous un identifiant opaque (résidu
M-1 assumé, §8.7 : noms opaques, mais nombre et cadence restent visibles). La clôture
ajoute peu à cette surface : l'objet `manifest` a un `last_modified` (l'heure de fin de
l'enregistrement, que le dernier chunk donnait déjà à quelques secondes près) et une
taille qui révèle le nombre d'objets, déjà visible au listing ; les numéros de capture
révèlent les trous (chunks perdus à la capture). Les pierres tombales gardent sans limite
de durée, sans date ni identité, une fiche par rapport clos : le registre conserve donc le
compte des rapports clos au-delà du TTL de leurs objets. Côté fil, le
transport **ObfQuic/Salamander** (§6.3/§10.4) rend la connexion inclassifiable tant que
l'UDP passe ; le repli **DirectTls** (UDP bloqué) est classifiable et porte le **SNI en
clair** du domaine. La cible non-fiable (foule/CDN ou rotation d'IP) et un éventuel mode
*fail-closed* sont **hors-scope** du binaire courant (décision 2026-06-28) : Tor a été
**mesuré et écarté** (latence incompatible avec l'upload temps-réel), et le sous-objectif
destination-non-fiable est **reporté au serveur de production**. V2 choisit un relais
simple, auditable et obfusqué plutôt qu'une promesse d'anonymat réseau qu'il ne pourrait
pas tenir. Un utilisateur dont la *métadonnée d'usage* est elle-même compromettante doit
combiner Frappuccino avec une couche réseau adaptée (Tor/VPN au niveau OS).

### 8.6 Hébergement-agnostique : le contenu ne dépend pas de l'hôte

Corollaire direct du relais aveugle : **un rush est un blob opaque** (STRM =
XChaCha20-Poly1305 sous une clé de session scellée à la pubkey X25519 d'archive). Sans la
seed → clé privée X25519, **aucun hébergeur ne peut le lire** : ni Vultr, ni un stockage
S3-compatible (MinIO / Backblaze B2 / Cloudflare R2 / Wasabi), ni un self-host, ni un
réseau décentralisé, ni un acteur **hostile** qui saisirait le serveur. **Le choix de
l'hébergeur du contenu est un choix d'_availability_ et de _métadonnées_, jamais de
confidentialité** - c'est exactement la ligne « saisie du serveur relais » du modèle de
menace (§2.1).

Deux nuances pour rester exact :

1. **Le relais n'est pas du stockage muet.** Il exécute un *control-plane* : auth ratchet
   (challenge/verify Ed25519, anti-rejeu par nonce, monotonie de rotation, lignée de
   batch), séparation de scope (upload vs archive), write-once (refus d'écraser un chunk
   authentique), TTL. Un bucket S3 nu ne fait pas ça. « N'importe quel hôte » vaut donc
   pour les **octets** ; le control-plane, lui, doit faire tourner la logique Frappuccino -
   mais il est **self-hostable, fédérable, multi-homé**. Ce n'est pas « sans serveur »,
   c'est « un serveur que n'importe qui peut tenir, y compris hostile ».
2. **Aveugle au contenu ≠ aveugle aux métadonnées.** Tout hôte voit l'IP (maîtrisée côté
   app, §8.5), les tailles, les horodatages, la cadence (mais **plus d'`owner_pk`** depuis
   le relais-aveugle, §8.7). Un stockage
   *public / décentralisé* peut même **aggraver** la métadonnée (existence et horaires
   publics ; permanence en tension avec le TTL / la suppression forward-secure).
   L'hébergement reste donc une décision de **métadonnées**.

**Directions ouvertes** (non engagées - ROADMAP §10.8) : backend stockage pluggable
(S3-compatible ⇒ quasi-config) ; multi-homing / redondance des blobs (résilience à la
saisie ou au takedown d'un hôte, compatible avec le modèle aveugle) ; couche blob
décentralisée (IPFS / Storj / Arweave) **pour le contenu seul**, à peser contre le
control-plane et la métadonnée / permanence.

### 8.7 Reports relais-aveugles - adressage dérivé de la phrase, noms opaques (M-1)

Un report n'est ni adressé ni autorisé par l'identité du témoin, mais par une clé
**dérivée de la seed BIP-39** ([`crypto-rs/core/src/report.rs`](../crypto-rs/core/src/report.rs)).
Le relais stocke `report_id → report_pk` et **jamais** le lien
`identité → report → quand` : saisir le disque ne révèle aucun rattachement.
`report_id_n = SHA-256("stream.report.id.v1" ‖ report_pk_n)[..16]`. Les écritures sont
signées par capacité, domaine-séparées (R-C-1) : `0x07 ReportCreate` (création paresseuse
au premier PUT), `0x08 ReportWrite` (chaque objet, lié au nom et au `sha256(body)`) et
`0x09 ReportClose` (la clôture), miroir serveur dans `routes/upload.py`. Le témoin
re-dérive n'importe quel `report_id_n` depuis la phrase seule au rescue (device sans état
local).

**Deux schémas de dérivation partagent un seul espace d'index.** Le schéma **legacy**
(index `< k`) dérive `report_master = HKDF(seed, "stream.report.master.v1")` puis
`report_sk_n = HKDF(report_master, "stream.report.key.v1" ‖ u32_be(n))` : n'importe quel
index se redérive du maître, c'est pourquoi l'appareil ne le garde plus. Le schéma
**chaîne** (index `≥ k`, `k = 0` pour une inscription neuve) est à sens unique :

```
C_0     = HKDF(report_master, "stream.report.chain.v2.root")
C_{i+1} = HKDF(C_i, "stream.report.chain.v2.next")
seed_i  = HKDF(C_i, "stream.report.chain.v2.key")      → report_sk_i, report_pk_i, report_id_i
entrée d'annuaire i = hex(HKDF(C_i, "stream.report.chain.v2.directory-entry", 16))
nom de la preuve OTS i = hex(HKDF(C_i, "stream.report.chain.v2.ots-name", 16))
```

L'appareil ne garde que `(i, C_i, graine d'annuaire)` (`report_state.bin`, scellé par la
session PIN, §4.6), et jamais `report_master` après l'inscription ou la migration. Ouvrir
le rapport `i` dérive sa clé de `C_i`, remplace `C_i` par `C_{i+1}`, efface `C_i`, et
n'est rendu à l'appelant qu'une fois l'état avancé écrit durablement. **Conséquence :
l'état ne permet plus de redériver la clé d'un rapport ouvert avant lui.** Il permet en
revanche de dériver celles de **tous les rapports ouverts après lui** : la chaîne est
déterministe, et elle doit l'être pour que la phrase seule retrouve tout au secours. Les
copies antérieures de l'état restées sur la flash échappent à ce que le module peut
effacer ; contre elles, le PIN n'oppose qu'un délai (Argon2id). Ces limites sont les
résidus R1 et R1b (§10.2).

**Cycle de vie d'un rapport chaîne.** L'écrivain (`ReportWriter`, Rust) scelle d'abord
le JSON de métadonnées (seq 0, obligatoire avant tout chunk), puis chaque chunk sous son
numéro de capture (seq ≥ 1, noms `NNNNNN.strm`, trous permis), et tient la table
`seq → empreintes`. `close_report` construit le **manifeste** depuis cette table (seq
strictement croissants, empreinte SHA-256 des octets exacts que stockera le relais),
signe `0x09` sur `report_id ‖ u32_be(seq_limit) ‖ sha256(manifest)` (`seq_limit` = dernier
seq + 1), écrit l'enveloppe de clôture, puis efface la clé ; ensuite tout appel échoue
(`WriterClosed`). L'effacement d'urgence appelle `abort`, qui efface la clé sans clôture.
Un rapport dont la clé disparaît avant l'écriture de sa clôture (mort du processus,
borne de vidange dépassée, échec d'écriture, effacement d'urgence pendant
l'enregistrement) n'est jamais clos : ses objets restent authentifiés un par un, sa fin
n'est pas certifiée (résidu R2).

**L'annuaire.** Un **report-annuaire** singleton (`stream.report.directory.v1`, la même
clé pour les deux schémas) reçoit une entrée par rapport, au moment de son ouverture,
signée par la clé d'annuaire persistante ; le secours y apprend quels index existent.
**M-1 (2026-06-28, commit `075ec6b`, audit 2026-06-26)** a rendu les **noms d'entrée
opaques** : nommer une entrée par l'index décimal en clair (`%010d`) signait l'annuaire
comme un compteur de sessions et laissait un opérateur de relais **lire le nombre de
sessions du témoin et leur cadence** directement sur les noms. Le nom legacy est
`hex(HKDF(report_master, "stream.report.directory.entry.v1" ‖ u32_be(n))[..16])`, le nom
chaîne est dérivé de `C_i` comme ci-dessus : dans les deux cas d'un **secret**, **jamais**
du `directory_pk` public (sinon le relais, qui voit `directory_pk`, ré-énumérerait tous les
noms et reconstruirait chaque index). Le **corps** de l'entrée ne porte pas l'index
(constant, 1 octet). Au rescue, le device re-dérive les noms des deux familles et matche
contre la liste de blobs de l'annuaire (*derive-and-match*) ; les entrées legacy `%010d`
sont **lues en double** (forward-compat). La clé d'annuaire étant persistante, l'annuaire
n'est jamais clos par l'appareil : le secours traite toute clôture d'annuaire comme une
anomalie et sonde au-delà (R1b). Le M-1 legacy a été field-validé sur Seeker (`n_max=6`,
7 reports, 0 erreur) ; le schéma chaîne n'a pas encore de validation terrain.

**Migration des appareils existants.** Au premier déverrouillage après la mise à jour,
hors du thread principal, et sans enregistrement possible tant qu'elle n'a pas fini
(`LegacyReportMigration`) : les anciens travaux d'envoi sont annulés ; chaque session en
attente sans index en reçoit un ; `k` est fixé au-delà de tout index legacy ; l'état chaîne
est écrit à `k` (le maître est descellé dans Rust, il ne traverse pas la FFI) avec la clé de
file ; chaque fichier legacy en attente (blobs `.strm` de la file et du cache, entrées
d'annuaire, preuves OTS déjà reçues) devient une enveloppe **signée à ce moment** avec sa
clé legacy, par ajout d'un en-tête puis renommage, avec contrôle d'espace libre ; une
clôture legacy est écrite pour chaque index `< k` ; **enfin seulement**, le maître et la
comptabilité legacy sont supprimés. Un fichier inconvertible est effacé et compté perdu ;
les horodatages OTS demandés mais pas encore reçus sont annulés (la preuve opt-in est
perdue, la vidéo ne l'est pas). Sur manque d'espace ou erreur, la migration s'arrête sans
rien effacer et reprend au déverrouillage suivant. Les limites propres aux appareils
migrés sont les résidus R3, R3b et R4 (§10.2).

**Résidu honnête** : l'annuaire **relie toujours les sessions d'un témoin au repos** (leur
nombre et leur cadence) sous un même `report_id`. Les noms opaques retirent le
fingerprint trivial et l'index lisible, **pas** la liaison structurelle. La règle stricte
(aucune identité, aucun contenu visible du relais) tient ; la corrélation métadonnée reste
le risque résiduel du relais (§8.5).

### 8.8 Frontière FFI sans export de secret (R-CR-1, Lot 4b)

Corollaire de la discipline « tout secret matériel vit en Rust » (§3.5) durci à l'audit
2026-06-26 : les secrets sensibles - le blob ratchet 50 clés, l'état de rapport (et le
`report_master` legacy, le temps de la migration), les clés de rapport, la graine de
provenance, et la clé de session dérivée Argon2id - **ne traversent plus la frontière
FFI**. La clé de file fait exception, nommée : Kotlin la lit depuis son `EncryptedFile`
en `ByteArray`, l'installe dans Rust (`queue_key_install`) et efface le tableau. Ils restent côté Rust derrière un *handle* ; le sceau/descellement se font
**à l'intérieur de Rust en un seul appel** (`pin_session_*` dans
[`crypto-rs/ffi/src/lib.rs`](../crypto-rs/ffi/src/lib.rs) ; orchestré côté Kotlin par
`StreamUploadManager.kt`). La clé Argon2id de session est mise en cache dans un holder
`Zeroizing` (`PinSessionState`) et seulement **empruntée** par closure (`with_pin_session`,
la référence n'échappe jamais) pour un seal/open in-crate - elle n'est **jamais** un
argument Kotlin ni une valeur de retour. Field-validé sur OnePlus (33 min / 396 chunks,
0 erreur). C'est le même geste que la fermeture heap-0 du bearer d'upload (§10.7),
généralisé à tous les secrets dérivés de la phrase.

### 8.9 Remédiation de l'audit 2026-06-26 intégrée

L'audit adverse du 26 juin 2026 (7 agents en lecture seule) et sa remédiation par lots sont
**intégrés au code décrit ici** : retrait de l'oracle d'identité (§8.2, H-1), logger
`metrics.log` gaté `BuildConfig.DEBUG` (il survivait au panic wipe en release), section
DEBUG de calibration gatée `BuildConfig.DEBUG` (§8.2.8 / R-E-1, commit `2b48610` ; R8
strippe les méthodes qui écrivaient du clair), purge du dict `report_creations` par
identité à la rotation de batch (`server/app/ratchet_registry.py:238`, M-2 : plus de courbe
d'activité datée accumulée), budget serveur atomique anti-TOCTOU
(`reserve_report_creation`/`release_report_creation`, R-SRV-3), MinIO lié à
`127.0.0.1:9000` (loopback seul, R-SRV-2), logs Docker bornés et `access_log` nginx coupé,
et la frontière FFI sans export (§8.8, R-CR-1). Détail complet du protocole d'audit : §9.4.

---

## 9. Assurance - preuves machine-vérifiées et audits adverses

### 9.1 Philosophie : prouver le design, l'implémentation, et le compilateur

La doctrine du projet distingue trois niveaux où un système crypto peut mentir, et
assigne à chacun un outil dont le verdict ne dépend d'aucun LLM ni d'aucune
auto-évaluation (le *model→code gap* : prouver un modèle ne prouve pas le code, et
réciproquement) :

Les chiffres courants sont dans le tableau ci-dessous ; le détail daté de chaque exécution est dans les quatre documents de preuve et dans [`GUIDE_AUDITEUR.md`](GUIDE_AUDITEUR.md). **Provenance du binaire** (le maillon au-delà de l'IR) : le `.so` expédié est lié à son commit et à sa toolchain par `crypto-rs/PROVENANCE.txt` (sha256 par ABI) et par le gate de build `checkSoProvenance` (`mobile/build.gradle`), qui casse le build si un `.so` de `jniLibs` ne correspond pas au manifeste. Les résidus risque-acceptés sont recensés dans [`ACCEPTED_RESIDUALS_2026-06-28.md`](ACCEPTED_RESIDUALS_2026-06-28.md).

| Niveau | Question | Outil | Verdict |
|---|---|---|---|
| **Design / protocole** | Le protocole résiste-t-il à un attaquant réseau actif ? | Tamarin (Dolev-Yao) | 10/10 lemmes |
| **Design / machine à états** | La FSM du ratchet peut-elle rollback/rejouer ? | TLA+/TLC | 2800 états, 0 erreur |
| **Implémentation** | Le code réel panique-t-il sur une entrée adverse ? | Kani (model-checking borné), fuzz, mutation | 8/8 harnais vérifiés au dernier run daté (2026-10-25) ; 0 crash, 98-100 % |
| **Compilateur** | Le wipe des secrets survit-il à l'optimiseur ? | Analyse LLVM IR + guard exécutable | 0 dead-store-elimination |
| **Frontière inter-langages** | Kotlin et Rust voient-ils les mêmes octets ? | Fuzzing différentiel via bindings réels | 759/759 |

Chaque preuve est livrée avec un **runner reproductible** et au moins un **contrôle
négatif** (on casse délibérément la propriété, l'outil doit le voir - une preuve qui ne
peut pas échouer ne prouve rien).

### 9.2 La suite formelle ①→⑤

**① Zeroize-audit (LLVM IR)** - [`docs/ZEROIZE_AUDIT_RATCHET.md`](ZEROIZE_AUDIT_RATCHET.md).
Le wipe du ratchet (`zeroize_secrets` : 50×64 o de clés privées + chain key) est vérifié
**dans l'IR émis par le compilateur** à O0/O1/O2 : zéro élimination de dead-store sur les
6 objets sensibles ; à O2 la chaîne `zeroize` s'inline en boucle `store volatile`
+ fences (les stores volatils *augmentent* avec l'optimisation - l'inverse d'une DSE).
Nuance honnête découverte en route : le profil expédié (`opt-level = "s"` + LTO) garde le
wipe hors-ligne dans des appels `zeroize::Zeroize` - un grep naïf de `store volatile`
y échouerait à tort. Le guard exécutable `core/audit/assert_zeroize_not_dse.sh` asserte
l'invariant robuste sur **les deux** profils, et a été testé négativement (remplacer le
wipe par une affectation simple → le compilateur l'élimine → le guard FAIL).

**② Fuzzing différentiel Kotlin↔Rust** - corpus JSONL déterministe généré par
`frappuccino-difffuzz-dump`, rejoué côté JVM (`crypto-rs/difffuzz-jvm/`) à travers les
**bindings UniFFI→JNA réels** (même codegen que l'APK). **759/759 vecteurs identiques**
sur les 5 surfaces déterministes (bip39, identity, ratchet, pin, archive), 0 crash -
re-confirmé après le changement de protocole R-C-1 (bindings régénérés). C'est l'oracle
qui couvre la surface jugée la plus faible par les audits : la glu inter-langages.

**③ Kani (model-checking borné du Rust réel)** - [`docs/KANI_PROOFS.md`](KANI_PROOFS.md).
Huit harnais, dont **trois sur `parse_header`** : **no-panic prouvé sur l'intégralité de
l'espace d'entrée** borné (≤ 200 octets : un en-tête V3 complet plus une entrée de grant), postconditions garantissant que les slices
dérivées sont sûres, et refus de tout en-tête portant un grant
(`check_parse_header_rejects_any_grant`, qui verrouille en machine la décision de ne pas
exposer les grants). Les deux autres : confirmation machine que l'unique mutant survivant
du parseur (`be_u16 : OR ≡ XOR sur bits disjoints`) est bien équivalent - la mutation
l'avait conjecturé, Kani l'a prouvé - et le no-panic du dé-obfuscateur Salamander
(`check_deobfuscate_in_place_never_panics`), qui lit des paquets UDP non authentifiés.
La refonte des rapports en ajoute trois, sur l'enveloppe de file : le décodeur de
l'en-tête déchiffré, en deux harnais (`check_envelope_trailer_decode_refuses_short_input`
pour toute entrée plus courte que les champs fixes, `check_envelope_trailer_decode_never_panics`
pour chaque longueur au-delà, jusqu'à un nom de 4 octets), et le cadrage de fin de fichier
(`check_envelope_framing_accounts_for_the_whole_file`). Ni l'égalité du nom décodé avec ses
octets ni l'effacement à la libération ne sont prouvés par Kani : le premier point est
couvert par un test unitaire exhaustif sur les 256 valeurs d'octet. Le runner en attend
huit ; le résultat daté est consigné dans `docs/KANI_PROOFS.md`.

**④ TLA+/TLC (FSM du ratchet)** - [`docs/TLA_RATCHET.md`](TLA_RATCHET.md),
`core/proofs/EphemeralRatchet.tla`. Exploration exhaustive de **2800 états** : batch
monotone, anti-rejeu, anti-rollback, bornage des slots, slots consommés wipés. Test
négatif : retirer la garde use-once fait sortir un contre-exemple `AntiReplay` à TLC.
Les invariants modèle sont **pontés au code** par des tests proptest qui rejouent des
schedules aléatoires d'opérations sur le vrai `EphemeralRatchet` Rust.

**⑤ Tamarin (protocole sous Dolev-Yao)** - [`docs/TAMARIN_RATCHET.md`](TAMARIN_RATCHET.md),
`core/proofs/RatchetProtocol.spthy`. Modèle enrollment + rotation + auth face à un
attaquant réseau actif : **10/10 lemmes vérifiés** (secrecy des clés éphémères et
long-terme, `auth_slot_origin`, `nonce_use_once`, `rotation_authentic` -
inforgeabilité du RotationProof -, `rotation_lineage` + `root_authentic` - no-rogue-batch -,
`forward_secrecy_auth`, plus les lemmes d'atteignabilité), **2 contrôles négatifs** qui
falsifient comme attendu. Le flux d'authentification d'archive (et son lemme
`archive_auth_origin` + son contrôle négatif NC3) a été **retiré du modèle** avec le
passage des archives en mode relais-aveugle (§8.7 : la lecture d'archive est désormais
sans identité, plus de domaine `0x04` actif). Le modèle a en outre **produit un finding
réel** : la séparation auth/rotation reposait sur la taille des messages → reco de
domain-separation explicite → implémentée (R-C-1, §4.4) → modèle re-vérifié, finding
fermé. C'est le cycle souhaité : la preuve n'a pas seulement validé le design, elle l'a
amélioré.

### 9.3 Mutation, fuzzing, propriétés, parité

- **Mutation testing (cargo-mutants)** sur les frontières de confiance : parseur
  `decrypt` **100 %** (67/67 mutants viables tués après ajout des tests de bornes ±1),
  parseur `header` **98 %** (48/49, le survivant étant le mutant équivalent prouvé par
  Kani), ratchet (wipe observable, masque de sérialisation, redaction `Debug`
  anti-fuite-par-log - chaque kill spot-checké par injection manuelle du mutant).
- **cargo-fuzz** : 4 cibles (decrypt / header / ratchet / pin_store), ≥ 1 M itérations
  chacune, 0 crash.
- **proptest** (seeds figées, shrinking) : round-trip STRM encrypt/decrypt, round-trip
  sérialisation ratchet, invariants FSM sur schedules aléatoires.
- **Parité cross-implémentation** : vecteurs KAT partagés Rust ⇄ Python (CLI/serveur),
  lockstep test de 16 contextes HKDF (identité, ratchet, rapports legacy et chaîne) et de
  l'AAD de l'état de rapport (`core/tests/hkdf_contexts_lockstep.rs` : tout drift d'une
  constante casse le build) ; KAT figés du schéma chaîne (`core/tests/report_chain_kat.rs`).
- **CI** : fmt + clippy `-D warnings` + tests `--locked` + cargo-deny/audit + Semgrep
  (4 packs + règles maison : tracker de pin TLS, anti-`fill(0)`, anti-secret-dans-les-logs).
- **Anti-dérive modèle/code**, en deux moitiés. Côté **surface** : un test à `match`
  exhaustif (`signature_domain::tests::signature_domain_surface_is_frozen`) **casse le
  build** dès qu'un domaine de signature est ajouté, retiré ou retaggé sans réconcilier le
  modèle Tamarin, le miroir serveur et §4.4. Côté **sémantique** :
  [`.github/workflows/proofs.yml`](../.github/workflows/proofs.yml) **rejoue TLC, Tamarin,
  Kani et le guard zeroize** sur tout changement `crypto-rs/**` - un changement qui casserait
  une preuve casse la CI. Le *model→code gap* résiduel (la sémantique du modèle vs le code)
  reste borné par les ponts : proptest sur le vrai ratchet, parité Rust⇄Python, diff-fuzz.
- **Robustesse crash / mort anormale du process** : la récupération du ratchet à travers une
  interruption est verrouillée en tests Rust déterministes (`core/src/ratchet.rs` :
  consume-non-persisté = no-op au reload · consume-persisté = slot brûlé-mais-sûr · blob
  torn-write rejeté par le MAC · rotation interrompue = même batch déterministe = retry
  idempotent), et la durabilité de la file d'enveloppes est testée **on-device**
  (`EnvelopeQueueDurabilityTest`, instrumenté : survie au redémarrage du processus, `.part`
  interrompu jamais remonté et balayé au démarrage, enveloppe de 0 octet ignorée,
  enveloppe refusée conservée sans être renvoyée, ordre des noms préservé).

### 9.4 Audits adverses - dont l'audit inter-modèle

Le projet a enchaîné les passes adverses : red team / blue team / contre-audit (14
findings triagés, RT-01 MITM et RT-07 rotation morte fixés avec tests de régression),
séance d'audits statiques pré-externes (forensic plan, metadata map, TLS runbook,
device matrix), et en juin 2026 un **audit adverse inter-modèle** : équipes rouge et
bleue sur un modèle distinct de celui du développement quotidien, puis **arbitrage par
un troisième agent re-vérifiant chaque fait porteur directement dans le code** (jamais
sur la foi des rapports). Bilan, donné tel quel parce qu'il est tout sauf cosmétique :

- **2 bloquants réels trouvés et fixés** : R-E-1/R-G-1 - la section DEBUG de calibration
  écrivait en **release** de la vidéo témoin **déchiffrée** dans `filesDir/debug_raw*`
  (le gate documenté était mort, 0 appelant) → section gatée `BuildConfig.DEBUG` + gate
  réveillé + frères purgés ; R-E-2 - la base WorkManager survivait au panic wipe en
  timeline forensique → prunée au wipe.
- **1 finding de design** : la séparation implicite-par-longueur des signatures → R-C-1.
- **0 faux positif retenu** après arbitrage - et l'arbitrage a aussi *invalidé* un doc
  périmé (le panic wipe purgeait bien la queue, contrairement à ce qu'affirmait un
  vieux finding).
- **3 findings device-dépendants classés risque-accepté documenté** (§10.2).

Une seconde vague suivit : l'**audit adverse 2026-06-26** (7 agents Opus en lecture seule)
et sa remédiation par lots (intégrée, §8.9) - retrait de l'oracle d'identité (H-1, §8.2),
calibration DEBUG re-gatée (§8.2.8), purge du dict d'activité par identité à la rotation
(M-2), budget serveur atomique, MinIO loopback, frontière FFI sans export (R-CR-1, §8.8) -
puis le **Lot 3** qui ferme les deux HIGH structurels D-1 (transport ObfQuic release,
§10.4) et D-2 (jeu de 3 pins break-glass, §5.4), et **M-1** (noms d'annuaire opaques,
§8.7). Enfin, une **revue de design-rationale (2026-06-28)** sous
[`docs/design-review-2026-06-28/`](design-review-2026-06-28/) : 8 rapports par domaine
(steelman adverse - pourquoi chaque choix est bon, pourquoi implémenté ainsi, résidus
honnêtes, questions pour un futur audit) + une synthèse cartographiant les paris porteurs,
les tensions internes et une *audit-question map* priorisée. C'est une première couche de
réflexion formalisée pour **amorcer** l'audit externe adverse, pas pour s'y substituer.

La leçon généralisable : les passes IA trouvent des choses réelles **quand** le
protocole les force à l'exploit concret, à la contre-vérification croisée et à
l'arbitrage sur pièces - et c'est l'audit externe humain qui reste juge de paix.

### 9.5 Validation cross-stack live

Le protocole post-R-C-1 a été validé **en vrai**, contre le relais déployé (TLS
épinglé, joint par domaine §5.4) : enrollment (`0x03`), challenge/verify (`0x01`),
rotation (`0x02`) - 3/3 depuis le client Rust. Le chemin de reports relais-aveugles
(capacités `0x07`/`0x08`, noms d'annuaire opaques M-1) et la récupération d'archive sans
identité ont été **field-validés sur device** (Seeker : `n_max=6`, 7 reports, 0 erreur ;
§8.7), via la même primitive Rust que le CLI `fetch-archive`. Le serveur de test héberge
~4000 blobs réels issus des field tests multi-jours sur les deux devices de référence.
Ces validations terrain sont antérieures au schéma chaîne, à la signature à la production,
à la clôture et au secours vérifié (§6.3, §7.4, §8.3, §8.7) : ceux-ci sont couverts par les
tests Rust, Kotlin et pytest, pas encore par une campagne sur appareil.

---

## 10. Limites assumées

Cette section est la contrepartie de tout ce qui précède. Elle est volontairement
inconfortable : la crédibilité d'un outil pour personnes en danger se joue ici.

### 10.1 Compromission device-level *live*, et extraction de l'état

Un attaquant qui obtient **root sur le device pendant que l'app est déverrouillée** (ou
qui dumpe la RAM d'un device saisi allumé et déverrouillé, ou qui extrait le stockage et
casse le PIN) peut lire **l'état courant** de l'appareil à l'instant `t` : les slots
éphémères non consommés et la chain key suivante du ratchet, l'état de rapport `(i, C_i,
graine d'annuaire)`, et, si un enregistrement est en cours et que l'extraction atteint la
mémoire vive, la clé du rapport en cours. Conséquences précises :

- il **ne peut pas déchiffrer un seul stream passé** (pas de `x25519_sk` sur l'appareil) ;
- il **ne peut pas étendre ni réécrire un rapport clos avant `t`** : sa clé a été effacée
  à la clôture et l'état ne la redérive pas (§8.7), et le relais refuse tout nom hors de
  l'ensemble déclaré par la clôture. Une réserve : les versions antérieures de l'état
  scellé restées sur la flash (résidu secdel-flash), contre lesquelles le PIN n'oppose
  qu'un délai (Argon2id) ;
- il **peut** s'authentifier comme l'identité (forward security de l'authentification :
  les slots déjà consommés restent inutilisables, c'est la propriété prouvée par Tamarin et
  le zeroize-audit), signer des objets du **rapport en cours à `t`**, signer **tous les
  rapports ouverts après `t`** (la chaîne est déterministe, elle doit l'être pour que la
  phrase seule les retrouve), et **écrire dans l'annuaire, voire le clore**, sans limite de
  durée (la clé d'annuaire est persistante) ;
- un rapport complet qu'il placerait à un index futur **n'est pas détectable
  cryptographiquement** : il est signé par la bonne clé. Un 409, ou une incohérence de
  manifeste, ne signale qu'une collision avec un usage réel du témoin au même index, et même
  ce 409 n'est pas garanti sous écritures simultanées. Le secours affiche l'intervalle de
  dates de chaque rapport pour aider le témoin à repérer ce qui est postérieur à une perte
  ou une saisie, et traite une clôture d'annuaire comme une anomalie ;
- il n'existe **pas de route de révocation d'identité** ; la parade disponible est une
  ré-inscription avec une phrase neuve, donc une identité neuve.

Ce sont les résidus R1 et R1b (§10.2).

De même, un malware avec accès caméra/écran **avant** le chiffrement voit ce que voit le
capteur : Frappuccino chiffre en aval de la capture, il ne prétend pas protéger contre
un OS compromis au moment des faits.

### 10.2 Risques acceptés documentés (R-D-1/2, R-C-2)

Trois findings de l'audit inter-modèle sont **acceptés et documentés** plutôt que fixés,
parce qu'ils sont device-dépendants, hors de portée raisonnable de l'app, et qu'aucun
n'expose les rushes passés : extraction de l'état ratchet courant par un attaquant root
(cf. 10.1), lecture de secrets via heap-dump privilégié au moment précis où ils
transitent, et scénarios de restauration/backup OS ramenant un blob scellé antérieur
(que la monotonie serveur neutralise au niveau protocole). Les traiter exigerait des
garanties que l'OS ne donne pas ; les documenter vaut mieux que prétendre.

Le finding **§10.6** d'origine (JWT d'upload résiduel dans le heap JVM) relevait **de la
même classe** et du même calibrage (cf. **§2.4**) : in-window, device vivant déverrouillé,
**sans exposition des rushes passés**. Il a depuis été **fermé à 0 par construction**
(§10.7 livré : PUT + report + recovery tous en Rust, le bearer ne touche plus la pile
HTTP JVM ; heap-dump session active = `Bearer eyJ=0`), en plus de la neutralisation
serveur déjà en place (write-once, combo-1 déployé). Il n'est donc **plus** un risque
accepté ; les trois R-D-1/2, R-C-2 ci-dessus, eux, le restent.

**Résidus des rapports figés (R1-R7).** La signature à la production et la clôture
(§6.3, §8.3, §8.7) laissent des limites connues, tenues dans le registre
[`ACCEPTED_RESIDUALS_2026-06-28.md`](ACCEPTED_RESIDUALS_2026-06-28.md) :

- **R1 - capacité après extraction** : une extraction de l'état à l'instant `t` donne la
  signature du rapport en cours à `t` et de tous les rapports ouverts après `t` ; un
  rapport complet placé à un index futur n'est pas détectable cryptographiquement. Les
  rapports clos avant `t` sont hors d'atteinte, sous réserve des versions antérieures de
  l'état restées sur la flash (§10.1).
- **R1b - annuaire** : la clé d'annuaire est persistante ; quiconque a extrait l'état peut
  écrire dans l'annuaire et le clore, sans limite de durée. Le secours traite une clôture
  d'annuaire comme une anomalie et sonde au-delà.
- **R2 - rapport interrompu** : une clé perdue avant l'écriture de la clôture (mort du
  processus, borne de vidange dépassée, échec d'écriture, effacement d'urgence pendant
  l'enregistrement) laisse un rapport jamais clos : objets authentifiés un par un, fin non
  certifiée.
- **R3 - appareils migrés** : une extraction antérieure à la mise à jour a pu emporter
  `report_master`, dont dérivent la chaîne **et** la clé d'annuaire. La migration clôt les
  rapports legacy que le relais connaît et dont la file se vide ; les index legacy jamais
  créés et l'annuaire restent inscriptibles par ce détenteur. La parade est une
  ré-inscription avec une phrase neuve. Les objets legacy en attente à la migration sont
  signés à la migration, pas à la production.
- **R3b - authenticité legacy** : un objet legacy stocké sans signature n'est authentifié
  que par son déchiffrement, or le scellement est anonyme (quiconque connaît la clé
  publique d'archive peut sceller vers elle) ; il va dans la section « non vérifiable »,
  jamais dans le témoignage vérifié. Une clôture legacy, vide, se lit « figé côté relais ».
- **R4** - un rapport legacy dont la file ne se vide jamais reste ouvert.
- **R5** - un objet refusé (409 rapport clos, ou conflit) reste sur le téléphone, dans le
  répertoire d'échecs : il ne peut repartir sans nouvelle signature, et la clé n'existe plus.
- **R6** - restaurer une sauvegarde antérieure du relais perd les clôtures plus récentes ;
  les rapports concernés se lisent « interrompus » au secours.
- **R7 - adresses en attente** : la file d'enveloppes chiffre ses en-têtes sous une clé
  de file protégée par le Keystore (le niveau d'`EncryptedSharedPreferences`) ; une
  extraction capable d'utiliser le Keystore de l'app lit les adresses (`report_id`, noms,
  signatures) des enveloppes encore en attente, pas leur contenu.

### 10.3 Limites du panic wipe

Le panic wipe est un **réducteur de surface**, pas une garantie absolue : il ne protège
pas contre une image prise avant son déclenchement ; l'effacement physique sur NAND
(wear-leveling) n'est pas démontrable depuis l'espace utilisateur ; il n'efface pas les
exports faits par le sélecteur de fichiers du système ; il ne révoque rien côté serveur
(il n'existe pas de route de révocation d'identité, et le wipe n'émet volontairement aucun
signal réseau sous contrainte) ; il abandonne le rapport en cours sans le clore (R2) et
perd ce qui n'était pas encore envoyé ; et il suppose que l'utilisateur a pu le déclencher.
Sa valeur réelle : après wipe, ce qui reste à extraire est un blob Argon2id sans son PIN et
des blobs STRM sans leur phrase.

### 10.4 Métadonnées et couche réseau

Répété depuis §8.5 parce que c'est la limite la plus susceptible de blesser : le contenu
est protégé, **le fait d'émettre ne l'est pas**. Tailles, horaires, fréquences,
pseudonyme stable, IP vue de l'hébergeur/opérateur : un adversaire en position réseau
peut établir *que* quelqu'un streame, et corréler. IMSI-catchers et analyse de trafic
sont hors périmètre app.

**Options de couche réseau (defense-in-depth, hors app aujourd'hui).** Ce non-claim
n'est levable qu'au niveau transport, par une couche que l'utilisateur dont la
métadonnée d'usage est elle-même compromettante doit ajouter. Trois familles, par ordre
de pertinence pour notre menace :

- **Tor + service caché `.onion` (le plus ciblé).** Plutôt qu'obfusquer un tunnel vers
  une IP connue, exposer le relais en `.onion` V3 **supprime la destination
  identifiable** : le client parle au réseau Tor, pas à l'IP fixe du relais, donc le
  signal « cet utilisateur parle au relais » disparaît à la racine. La résistance à la
  censure (pluggable transports obfs4 / Snowflake / meek) est maintenue et auditée par
  la communauté anti-censure. Coût réel : latence et jitter pénibles pour du streaming
  temps réel, Tor sur lien mobile intermittent capricieux. Tracké en ROADMAP 1.5
  (optionnel, post-audit).
- **Obfuscation de tunnel type wg-obfuscator (partiel, de niche).** Un obfuscateur
  WireGuard (XOR par clé + padding, masquage STUN pour ressembler à un appel vidéo) fait
  survivre un tunnel WireGuard au DPI qui bloque les VPN. Utile *si* on adoptait un front
  tunnel WireGuard auto-hébergé (couche absente aujourd'hui) et *si* l'adversaire bloque
  activement WireGuard. Deux réserves dirimantes pour notre cas : il faut contrôler les
  deux bouts et embarquer l'obfuscateur dans l'app (un seul port Android « très simple »,
  pas de lib), et surtout il **n'obfusque pas le timing** : l'enveloppe burst qui trahit
  *quand* on filme passe intacte. Il adresse donc la moitié « IP/destination » du risque,
  pas la moitié « cadence ». L'idée du masquage STUN (avoir l'air d'être en visio) reste
  une piste de camouflage intéressante en soi.
- **ECH (voie domaine).** Le relais est **déjà** joint par un domaine
  (`relay.shake-document-protect.org`, §5.4), donc le `ClientHello` `DirectTls` porte un
  **SNI en clair aujourd'hui** ; sur le chemin ObfQuic, Salamander masque ce SNI tant que
  l'UDP passe. Encrypted Client Hello le supprimerait aussi sur `DirectTls` mais n'est pas
  encore largement déployable. À peser pour le serveur de production final.

Aucune de ces couches ne masque le **timing/volume** sans padding à débit constant ou
cover-traffic (coût batterie/data non trivial sur mobile), et aucune ne remplace le
non-claim : ce sont des renforts pour un profil d'utilisateur précis, pas une promesse
d'anonymat réseau que Frappuccino tiendrait par défaut.

**Couche app-level (livrée, défaut en RELEASE depuis Lot 3 B4) : transport obfusqué.** La
piste retenue (ROADMAP 10.9, Tor recalé pour le streaming continu - latence mesurée puis
écartée) est un transport `ObfQuic` (QUIC/HTTP-3 + BBR userspace, devant un endpoint
obfusqué auto-hébergé) derrière un trait `Transport`, avec fallback automatique vers
`DirectTls`. Elle n'est plus une direction : elle est **implémentée, field-validée et
défaut sur tous les builds** (la clôture du finding structurel D-1), en trois briques.

- **QUIC/BBR (Phase 3a).** Tranché par la mesure on-device (Gate-2, 2026-06-20, harnais
  jeté `quic-spike`) : sur réseau dégradé (netem 1 à 10 % de perte), QUIC+quinn-BBR bat le
  cubic-only kernel d'Android de **×5 à ×15** sur les deux devices, le gain croissant avec
  la perte ; le BBR « Experimental! » de quinn ne plafonne pas (finding bloquant B1 réfuté,
  pas de CC custom à porter), et c'est l'**algorithme BBR** qui gagne (quinn-cubic/newreno
  s'effondrent comme le kernel). Gain d'abord de **fiabilité d'upload** (le footage quitte
  le device plus vite = fenêtre de saisie réduite, surtout sur les devices cubic-only).
  QUIC est le défaut en build **debug ET release** (le toggle Settings debug le rabat sur
  `DirectTls` pour le diagnostic).
- **Fallback QUIC vers DirectTls (brique 3), à l'intérieur de Rust.** Un échec
  d'établissement QUIC (UDP bloqué, endpoint mort) bascule par chunk vers `DirectTls` avec
  le même bearer heap-0 ; un latch fait sauter QUIC pour les chunks suivants, ré-armé à
  chaque enregistrement (clear sur lock / auto-lock / 401 / panic). Field-validé : couper
  l'endpoint en plein enregistrement bascule **sans perte**. C'est le backstop de
  **disponibilité** (l'obfs ne survit pas à un blocage UDP de masse ; le fallback, si). Le
  repli est surfacé, jamais silencieux : `PutOutcome.transportUsed` (`directtls_degraded`)
  remonte dans le champ `StreamMetrics transport=`.
- **Obfuscation Salamander (brique 1).** La transform Salamander (de Hysteria2 :
  sel 8 o par paquet + XOR par keystream `BLAKE2b-256(PSK ‖ sel)`,
  `[sel][payload XOR keystream]`, byte-identique à Hysteria2 pour interop sing-box ;
  [`crypto-rs/stream/src/salamander.rs`](../crypto-rs/stream/src/salamander.rs)) enveloppe
  les datagrammes UDP **sous** QUIC, côté client (`SalamanderSocket`) et serveur (un proxy
  UDP **transparent** devant l'endpoint QUIC : il ne termine pas QUIC, donc ne touche pas
  au pin du relais et n'ajoute pas de 2ᵉ pin). C'est de l'**obfuscation, pas de la
  confidentialité ni de l'authentification** (la sécurité d'upload reste l'auth ratchet +
  le TLS épinglé en dessous) : elle bat le fingerprinting QUIC passif (chaque paquet a
  l'air d'aléa uniforme) et fait du relais un **port mort** pour qui sonde sans le PSK (un
  paquet non-keyé de-obfusque en garbage, ne donne aucun en-tête QUIC valide, est jeté).
  ⚠️ **Le PSK est un secret d'obfs partagé, embarqué dans l'APK** (comme le mot de passe
  obfs d'Hysteria2), donc **extractible du paquet d'installation** - limitation documentée,
  re-provisionné à la publication (étape gatée séparée). Field-validé : un pcap de 36 820
  paquets montre **0 version QUIC en clair**, premier octet étalé sur les 256 valeurs,
  **entropie ≈ 8 bits/octet** (le maximum), inclassifiable comme QUIC pour un dissecteur de
  signature ; surcoût débit négligeable (+8 o/paquet, BBR intact car l'obfs est sous QUIC).

**Même limite que les couches ci-dessus, et un non-claim assumé.** L'obfuscation achète
l'**inclassibilité**, pas l'**invisibilité** : un flux UDP à haute entropie vers une seule
destination reste un signal d'analyse de trafic. Et puisque le relais est désormais joint
par un **domaine** (§5.4), le `DirectTls` porte un **SNI en clair** ; Salamander le masque
sur le chemin ObfQuic tant que l'UDP passe, mais **un État qui bloque UDP/443 force le
downgrade `DirectTls` classifiable, qui ré-expose alors aussi le SNI**. C'est un **résidu
assumé / hors-scope** (décision du mainteneur, 2026-06-28) : pas de mode *fail-closed* offert (la
disponibilité du témoignage prime), Tor mesuré puis recalé (latence), et le sous-objectif
« destination non corrélable » est **reporté au serveur de production final**. Le padding
qui masquerait timing et volume est lui aussi hors scope (le débit prime pour du
témoignage vidéo continu). Cette couche se combine avec une couche réseau ajoutée par
l'utilisateur (Tor/VPN), elle ne la remplace pas.

### 10.5 La phrase papier

Le design concentre **délibérément** la défaillance totale sur un seul artefact : qui
détient la phrase détient tout (archives, identité, forge). C'est un choix - un point de
défaillance physique, hors-ligne, sous contrôle humain, plutôt que dix points logiciels -
mais il doit être dit sans euphémisme : coercition sur la phrase = défaite complète, et
phrase perdue = archives définitivement illisibles. Le 13ᵉ mot offre un déni plausible
dont la solidité dépend entièrement de la préparation de l'utilisateur.

### 10.6 Validation forensique on-device

Le claim « aucun secret ne fuit hors Rust » est validé **statiquement ET on-device** :
la campagne §10.6 est **exécutée** ([`docs/FORENSIC_VALIDATION_REPORT.md`](FORENSIC_VALIDATION_REPORT.md),
compagnon de résultats du [plan](FORENSIC_VALIDATION_PLAN.md)). Les 9 surfaces ont été
vérifiées après les scénarios (recording, stop, lock, panic, reboot, kill) : heap JVM
(Phases A/B/C), logcat/tombstones (**B5** : 3 crashes natifs = 0 plaintext / 0 JWT /
0 mnémo), filesystem post-wipe, frontières UniFFI/JNI, buffers gralloc/MediaCodec
(**B9** : wipe du buffer codec + `glFinish`/clear noir côté app **faits** ; reste un
résidu **firmware** HAL (zéro-isation gralloc/VRAM par le pilote) accepté, FBE =
défense at-rest). Le **finding** trouvé (JWT d'upload résiduel en heap JVM) est
**entièrement fermé** : neutralisé côté serveur (write-once **déployé** = worst-case fermé)
**et** ramené à **heap-0 par construction** (§10.7 livré : PUT + report + recovery tous en
Rust, le bearer ne touche plus la pile HTTP JVM ; heap-dump session active = `Bearer eyJ=0`).
Le calibrage de §2.4 (adversaire RAM-in-window, distinct de la saisie/destruction) reste la
grille de lecture, mais le résidu lui-même est désormais nul. Plusieurs gaps du diagnostic
initial étaient déjà fermés (purge `.strm` au wipe, buffers GL, thumbnails, WorkManager).
Le Niveau 2 (PUT + report + recovery en Rust, heap-0) est **livré, field-validé, et le
SEUL chemin d'upload par construction** : l'ancien flag `enabled` + « filet OkHttp » a été
retiré à l'audit 2026-06-26 (R-CR-5 : zéro lecteur, le repli OkHttp n'existait pas et
serait de toute façon rejeté par le relais aveugle ; §6.3). Un binding natif malsain
remonte en `retry`, le blob reste sur disque. La matrice réseau dégradé + l'A/B OnePlus
(2026-06-16) montrent 0 perte de 0 à 20 % de perte.

### 10.7 Statut honnête

**Field-test ready, candidat à l'audit - pas production-ready.** Validé en usage réel
multi-jours sur deux devices, avec un dossier d'assurance inhabituel pour un projet de
cette taille ; mais pour le threat model visé (saisie, Cellebrite, coercition), le
déploiement à haut risque attend : l'audit crypto externe, la matrice de devices
élargie, et l'infra de production (le DNS est en place avec cert auto-signé épinglé, §5.4 ;
restent la bascule Let's Encrypt à clé persistante et le backup off-host effectif - le
timer de backup n'a jamais tourné sur le serveur de test, gap connu). Quiconque utilise
Frappuccino aujourd'hui doit le faire en connaissance de cet état.

---

## 11. État du projet et trajectoire

Sur les 10 phases de la [`ROADMAP.md`](../ROADMAP.md) (source unique) :

**Livré** - Phases 2 (résilience réseau/background), 3 (qualité adaptative + gapless +
squish root-causé), 4 (remédiation audit + archive retrieval complet), 5 (vault Tella
retiré), 6 (sécurité + CI, crypto 100 % Rust, retrait infra Tella, auto-lock), 7
(UX/polish 18/18 + sweep code mort), §8.4 (l'intégralité de l'infra d'assurance décrite
en §9, close sur décision projet : dossier auditeur jugé suffisant). Le **transport**
(§6.3/§10.4) est lui aussi livré et field-validé : PUT + report + recovery en Rust (heap-0,
Rust-only par construction), et la suite **ObfQuic = défaut release** (QUIC-BBR +
obfuscation Salamander + fallback `DirectTls`, proxy de-obfs déployé sur le relais),
clôturant le finding structurel D-1. Son code est couvert par la **vérification
déterministe** (proptest round-trip + no-panic, Kani no-panic exhaustif sur les parseurs
UDP hostiles, mutation), reflétée dans le `GUIDE_AUDITEUR`. S'ajoutent l'audit adverse
2026-06-26 + sa remédiation (§8.9), le Lot 3 (D-1/D-2, §5.4/§10.4) et M-1 (§8.7), puis la
refonte des rapports : chaîne de clés à sens unique, signature à la production, clôture
`0x09` et règle du relais après clôture, secours qui vérifie avant de ranger, lecture
interne et effacement d'urgence étendu (§6.3, §7.3, §7.4, §8.3, §8.7). Elle est livrée en
code et couverte par les tests ; sa validation sur appareil reste à faire.

**Reste** - Phase 1 résiduelle : le DNS est **en place** (domaine `relay.shake-document-protect.org`,
§5.4) avec cert auto-signé épinglé (stratégie bêta) ; reste la bascule Let's Encrypt à clé
persistante (la clé off-host break-glass est déjà prête via `certbot --reuse-key`) et le
backup off-host réel ; Phase 8 : publication AGPLv3 (8.2.5),
audit externe (budget 30-80 K€, scope `crypto-rs/` + `server/` + protocole + glu),
F-Droid ; Phase 9 : client desktop de rescue (le CLI couvre déjà le cas Linux) ;
Phase 10 : mode photo. Plus les items techniques différés cités en §6.5.

---

## 12. Build, tests, déploiement

```bash
# Crypto Rust - gates obligatoires avant tout commit
cd crypto-rs && cargo test --workspace && cargo clippy --all-targets -- -D warnings
./build-android.sh                  # .so arm64/armv7/x86_64 + bindings Kotlin UniFFI
                                    # (⚠️ rebuild requis après edit pin.rs/ffi -
                                    #  guard Gradle checkRustSoFresh)

# Preuves (runners reproductibles)
crypto-rs/core/proofs/run-tlc.sh              # TLA+/TLC - JVM (Windows OK)
crypto-rs/core/proofs/run-tamarin.sh          # Tamarin - WSL/Linux (+ `negative`)
crypto-rs/run-kani.sh                         # Kani - WSL/Linux
crypto-rs/core/audit/assert_zeroize_not_dse.sh  # guard zeroize (IR aux 2 profils)
cargo mutants                                  # mutation (config .cargo/mutants.toml)

# App Android
./gradlew :mobile:assembleDebug     # puis vérifier `pm path` post-install (le
                                    # gradle install peut mentir sur certains devices)

# Serveur
cd server && python -m pytest tests/
# Déploiement : docker compose build server && up -d server (MinIO reste up)
# Le relais AVANT l'APK : sonde `POST /close/<rid>` sans en-têtes → 400 attendu, pas 404 (§8.3)
```

---

## 13. Références internes

| Document | Contenu |
|---|---|
| `ARCHITECTURE_TECHNIQUE_26-05.md` (retiré du dépôt suivi, conservé localement sous `OLD/`) | Snapshot archi 26 mai (base du présent doc) |
| [`STREAM_CRYPTO_V2_ALGORAND.md`](../STREAM_CRYPTO_V2_ALGORAND.md) | Spec d'origine du ratchet (inspiration Algorand) |
| [`CRYPTOGRAPHIE.md`](../CRYPTOGRAPHIE.md), [`ARCHITECTURE_V2.md`](../ARCHITECTURE_V2.md) | Détail crypto (snapshots avril - wire format et impl. Kotlin périmés, protocole valide) |
| [`ROADMAP.md`](../ROADMAP.md) | Source unique d'état, 10 phases, historique commit-par-commit |
| [`docs/FORK_VS_TELLA.md`](FORK_VS_TELLA.md) | Deltas vs Tella FOSS |
| [`docs/TAMARIN_RATCHET.md`](TAMARIN_RATCHET.md) · [`docs/TLA_RATCHET.md`](TLA_RATCHET.md) · [`docs/KANI_PROOFS.md`](KANI_PROOFS.md) · [`docs/ZEROIZE_AUDIT_RATCHET.md`](ZEROIZE_AUDIT_RATCHET.md) | Les preuves ⑤④③① et leurs runners |
| [`docs/invariants-ratchet-verification.md`](invariants-ratchet-verification.md) · [`docs/methodologie-securite-code.md`](methodologie-securite-code.md) | Invariants → outils ; protocole d'audit anti-dégradation |
| [`docs/FORENSIC_VALIDATION_PLAN.md`](FORENSIC_VALIDATION_PLAN.md) · [`docs/METADATA_EXPOSURE_MAP.md`](METADATA_EXPOSURE_MAP.md) · [`docs/TLS_PINNING_ROTATION_RUNBOOK.md`](TLS_PINNING_ROTATION_RUNBOOK.md) · [`docs/DEVICE_TEST_MATRIX.md`](DEVICE_TEST_MATRIX.md) | Livrables de la séance d'audits pré-externes |
| [`docs/AUDIT_HANDOFF_2026-05-07.md`](AUDIT_HANDOFF_2026-05-07.md) · [`docs/DEADCODE_SWEEP_2026-06-08.md`](DEADCODE_SWEEP_2026-06-08.md) | Handoff auditeur ; rapport du sweep code mort |
| [`docs/design-review-2026-06-28/`](design-review-2026-06-28/) | Revue de design-rationale par domaine (8 rapports + synthèse + audit-question map) - amorce de l'audit externe |
| [`docs/RELAY_BLIND_REPORTS.md`](RELAY_BLIND_REPORTS.md) · [`docs/TRANSPORT_PLAN.md`](TRANSPORT_PLAN.md) | Reports relais-aveugles (§8.7) ; plan transport obfusqué (§10.4) |

---

## Annexe A - Constantes cryptographiques (contrat wire)

Toute divergence casse la compatibilité avec les identités enrôlées et les archives.
**NE PAS CHANGER** sans versionnement explicite et migration.

```
# Identité
BIP-39 : 128 bits / 12 mots FR (wordlist 2048) ; PBKDF2-HMAC-SHA512 × 2048 → seed 64 o
HKDF-SHA256 info :
  "stream.identity.ed25519.v1"            (identité signature)
  "stream.encryption.x25519.v1"           (identité chiffrement)
  "stream.ratchet.chain0.v2"              (amorce ratchet)
  "frappuccino-v2-ratchet-batch-seeds"    (50 seeds par batch)
  "frappuccino-v2-ratchet-next-chain"     (chain suivante)
  "frappuccino-v2-ratchet-blob-mac"       (MAC du blob ratchet)
  "stream.report.master.v1"               (maître des rapports legacy ; absent de l'appareil)
  "stream.report.key.v1" ‖ u32_be(n)      (clé du rapport legacy n)
  "stream.report.directory.v1"            (clé d'annuaire)
  "stream.report.directory.entry.v1"      (noms d'entrée d'annuaire legacy)
  "stream.report.chain.v2.root"           (C_0)
  "stream.report.chain.v2.next"           (C_{i+1})
  "stream.report.chain.v2.key"            (clé du rapport chaîne i)
  "stream.report.chain.v2.directory-entry" (nom d'entrée d'annuaire i, 16 o)
  "stream.report.chain.v2.ots-name"       (nom de la preuve OTS i, 16 o)
report_id = SHA-256("stream.report.id.v1" ‖ report_pk)[..16]
AAD de l'état de rapport = "frappuccino-report-state-v2" ; état = 0x02 ‖ u32_be(i) ‖ C_i(32) ‖ graine d'annuaire(32)

# Ratchet
BATCH_SIZE = 50 ; blob V2 = 4876 o (4844 payload + 32 MAC) ; auto-rotate ≤ 5 clés

# Domaines de signature (R-C-1)
# Miroir serveur byte-identique : 0x01-0x03, 0x07-0x09 (vérificateurs)
# 0x04 : constante réservée côté serveur, sans vérificateur ; 0x05/0x06 : jamais de constante
0x01 AuthChallenge · 0x02 BatchRotation · 0x03 Enrollment
0x04 ArchiveAuth (RÉSERVÉ, retiré - archives sans identité, §8.7)
0x05 ProvenanceManifest · 0x06 ProvenanceKeyAttestation (RÉSERVÉS, retirés - manifeste signé supprimé 2026-06-25)
0x07 ReportCreate · 0x08 ReportWrite · 0x09 ReportClose (capacités report relais-aveugles)

# Rapports
objet chaîne = "NNNNNN.strm" (seq de capture, 0 = métadonnées, ≤ 999 999) ; nom réservé "manifest"
manifeste = "FQM1" ‖ u32_be(count) ‖ count × (u32_be(seq) ‖ sha256(blob)(32)), seq strictement croissants
seq_limit = dernier seq + 1 (0 pour une clôture legacy, manifeste vide)
métadonnée relais = x-amz-meta-report-write-sig (hex minuscule, 128 car.)
enveloppe de file = payload ‖ en-tête XChaCha20-Poly1305 (clé de file, nonce 24 o) ‖ u32_be(len) ‖ "FQE1"

# PIN store
Argon2id m=256 MiB, t=4, p=1, tag=32 ; salt 16 ; XChaCha20-Poly1305 nonce 24 ;
AAD = "frappuccino-v2-pin-store-v1" ‖ version

# STRM
MAGIC "STRM" ; VERSION_CURRENT = 0x03 (V3 ; 0x02/0x01 acceptés en lecture) ; V3 = pas d'`author_ed25519_pk` au repos (sealed envelope à l'offset 5, pas 37) ;
MODE 0x01 SINGLE (≤ 10 MiB) / 0x02 CHUNKED (sous-chunks 1 MiB) ;
sealed envelope 80 o ; grant entry 112 o (réservé, jamais émis, refusé à la lecture) ;
nonce 24 o (prefix 20 + index u32 BE) ;
tag AEAD 16 o ; MAX_CHUNK_COUNT = 1 000 000 ; MAX_CHUNK_LEN = 2 MiB ;
AAD = en-tête complet

# Protocole serveur
nonce TTL 60 s, pop atomique ; slots à usage unique persistés ;
batch_number strictement monotone ; JWT env-configurable, révocable (blacklist)
```

---

*L'historique daté (commit par commit, par phase) vit dans [`../ROADMAP.md`](../ROADMAP.md)
et dans git ; ce document ne porte que l'**état courant** de l'architecture. Successeur
consolidé des snapshots historiques listés en §13. Le code fait foi.*
