# Plan d'implementation : provenance verifiable (integrite, temps, lieu)

> ⚠️ **PÉRIMÉ (recul métadonnées, 2026-06-25).** Ce document décrit le modèle de
> provenance à **manifeste signé et scellé**, avec un mini-cert d'identité
> (tags de signature `0x05`/`0x06`). Ce modèle a été **supprimé** au profit du
> modèle *lean* « hash + Bitcoin » : plus de manifeste, plus de signature, plus
> d'attestation d'identité, parce qu'une non-répudiation stockée est une arme
> contre le témoin. Les tags `0x05`/`0x06` sont aujourd'hui réservés et retirés,
> et la ligne de commande `verify-provenance` citée plus bas n'accepte plus les
> options `--manifest` / `--cert`. L'état courant est
> `docs/ARCHITECTURE_TECHNIQUE_COMPLETE.md` §4.4 et
> `crypto-rs/core/src/provenance.rs`. Conservé comme historique de décision.

> Statut (2026-06-25) : **Phase A + n1 durabilite + (B) verifiabilite tierce
> LIVREES + FIELD-VALIDEES** (Seeker+OnePlus). **n1 durabilite** : `.fpm` durable
> sur le relais (`4b3584e`) + recuperation raw `archive_download_raw` (`193635a`,
> + fix regression rescue) + durcissement au-repos delete-after-upload + purge
> panicWipe (`4882d5c`). **(B) verifiabilite** : mini-cert identite->P (domaine
> **0x06**, mintable qu'a l'enrolement car cle identite wipee apres) + verifier
> **`frappuccino-cli verify-provenance`** + mint cert a l'enrolement + unseal au
> rescue ; `RESULT: PASS - authentic and attributed to identity_pk` bout-en-bout,
> 2 devices (`cc64ca1`/`0b83f4a`/`0ab8ed6`/`5e58ecc`). **Phase B horodatage** :
> mecanisme tranche = **OTS/Bitcoin** (trustless) ; slice 1 verifier `--ots`
> livree host-only (`bcf9b1a`, crate `opentimestamps` desktop-only ; design
> `docs/PHASE_B_TIMESTAMP.md`). **Lieu = OFF total** (GPS auto-declare ET empreinte
> reseau, decision therealshulgin : empreinte = vecteur de-anon). Reste : Phase B
> **slice 2** (soumission relais-assistee, commitment sale, opt-in/enregistrement
> = **GO PROD explicite**) + slice 3 (dernier-km Bitcoin) ; UX export-cert
> standalone (en suspens). Defaut provenance = **ON** (scelle E2E relais-aveugle) ;
> lieu + horodatage OTS = opt-in.
> Signeur = **cle provenance dediee** (decision therealshulgin). Source de
> verite = le code (`crypto-rs/core/src/provenance.rs` + `ProvenanceSigner`,
> `signature_domain.rs` tag 0x05, `crypto-rs/ffi/src/frappuccino.udl` + `lib.rs`).
> Lie a [ROADMAP.md](../ROADMAP.md) section 10.11.
>
> Note d'implementation A-1 : le coeur vit dans `core/` (et non `stream/` comme le
> suggerait la table sec. 7) car il utilise ed25519 + crypto_box_seal +
> signature_domain (tous dans core) et prend les hash de chunks en entree (zero dep
> STRM). La serialisation est un encodage deterministe length-prefixed maison
> (equivalent CBOR canonique, sec. 2.2), choisi pour eviter une dep serde
> feature-gatee et garder un parseur borne prouvable (Kani A-2). Le manifeste signe
> `fields_root` (Merkle des commitments par-champ sales) + l'entete, et non
> `canonical(manifest)` : c'est la reconciliation sec. 2.2 (divulgation selective
> posee des v1) <-> sec. 2.3, sans changement de format pour la Phase D.

## 0. Objectif et non-objectifs

**Objectif.** Rendre **prouvable**, pour un enregistrement choisi par le temoin :

1. **Integrite** : la video presentee est bit-pour-bit celle qui a ete capturee.
2. **Anteriorite (horodatage)** : elle existait avant un instant T verifiable, sans
   se reposer sur l'horloge du telephone.
3. **Lieu revendique** : la position au moment de la capture, **corroboree par
   plusieurs signaux independants** (GPS + cellules + BSSID WiFi + barometre), pour
   qu'un verificateur recoupe de facon autonome.
4. **Attribution a l'identite souveraine** (la seed), pas a un appareil.

But strategique : a l'ere des deepfakes et de la post-verite, **deplacer la charge
de la preuve et augmenter le cout du faux**. Pas prouver la verite absolue.

**Non-objectifs (a publier tels quels, comme le reste du site).**

- **Ne prouve pas la veracite de la scene.** Filmer un ecran qui affiche un deepfake
  produit une preuve « valide » et fausse. Aucun outil (ProofMode, C2PA, eyeWitness)
  ne resout cela : la confiance ne remonte pas plus haut que le capteur.
- **N'elimine pas la liaison forensique au capteur (PRNU).** Le bruit unique du
  capteur est dans les pixels ; un analyste ayant acces au telephone peut, en
  principe, relier la video a *ce* capteur, independamment de toute la crypto.
  Attenuable (debruitage) au prix de la qualite, jamais parfait.
- **Le GPS/RF reste falsifiable a la capture.** Le multi-signal augmente le cout
  d'un faux coherent ; il ne le rend pas impossible.

## 1. Critere dur : zero lien vers un telephone precis

Decision structurante (therealshulgin, 2026-06-23) : **meme une fois dechiffree**, la preuve
ne doit lier la video qu'a un **temps**, un **lieu** et une **identite pseudonyme**,
**jamais a un appareil physique**. Consequences :

- **Signer avec l'identite (seed), pas le materiel.** Le ratchet signe deja avec des
  cles derivees de la seed -> attribution « cette identite », controlee par le temoin.
- **Attestation materielle Android : HORS-JEU.** Elle identifie l'appareil et depend
  de la racine Google. Exclue par ce critere.
- **Bundle de metadonnees curee** : **aucun** IMEI, Android ID, `Build.FINGERPRINT`,
  numero de serie, calibration capteur identifiante. Liste blanche stricte (sec. 3).
- **C2PA sans assertion d'appareil** (sec. 5) : l'assertion « device » est facultative
  dans C2PA ; on l'omet.

## 2. Le manifeste de provenance

Coeur du systeme : un **manifeste signe et scelle**, une structure par enregistrement.

### 2.1 Liaison au media (subtilite plaintext vs ciphertext)

La video est decoupee en chunks chiffres (STRM). Le manifeste doit committer au
**media en clair** que le temoin presentera (sinon l'export C2PA, qui lie le MP4
dechiffre, ne colle pas).

- A la capture, le device a le clair *avant* scellement -> calcule `H_i = SHA-256`
  de chaque chunk **en clair**, et une **racine de Merkle** `root_plain` sur la liste
  ordonnee. Le manifeste committe `root_plain` + la liste ordonnee des `H_i`.
- Le **relais**, lui, ne voit que le chiffre -> son recu (sec. 4) porte sur le hash
  **ciphertext** de ce qu'il recoit. Le lien est fait par le manifeste **scelle** :
  « ce manifeste scelle, qui committe `root_plain`, a ete recu chiffre a T ».

### 2.2 Champs (liste blanche)

Serialisation **deterministe** (CBOR canonique ou equivalent ; pas de JSON a cles
non ordonnees). Chaque champ = une **feuille Merkle salee** (commitment individuel),
pour permettre la divulgation selective future (sec. 6) sans re-architecture.

```
ProvenanceManifest v1 {
  version: u16,
  recording_id: [u8;16],            // = reportId, deja non-identifiant
  media: {
    root_plain: [u8;32],            // racine Merkle des hash de chunks en clair
    chunk_count: u32,
    chunk_hashes: [[u8;32]],        // ordonnes (permet la reconstruction verifiee)
    container: "mp4/hevc",          // type, PAS d'identifiant encodeur device
  },
  time: {
    wall_clock_claim_ms: u64,       // CLAIM device, NON autoritatif
    monotonic_ns: u64,              // coherence interne (duree)
  },
  location: {                       // OPT-IN ; absent si desactive
    gps: { lat: f64, lon: f64, acc_m: f32, ts_ms: u64 } | null,
    cells: [ { mcc, mnc, lac_tac, cid, rsrp_dbm, ts_ms } ],   // tours visibles
    wifi:  [ { bssid: [u8;6], rssi_dbm: i8, ts_ms } ],        // BSSID visibles
    baro_hpa: f32 | null,
  },
  // EXCLUS EXPLICITEMENT : IMEI, Android ID, serie, Build.FINGERPRINT,
  // toute calibration capteur identifiante, toute empreinte d'appareil.
}
```

Note : `cells` et `wifi` sont **eux-memes des donnees de localisation precise** ->
ils sont **dans le scellement E2E** (le relais ne les voit jamais) et ne sont
divulgues qu'au moment de prouver. Ils sont **bruts** (pas hashes) car la
corroboration au verify (sec. 3.2) doit les recouper contre des bases publiques.

### 2.3 Signature et scellement

- **Signature** : `Ed25519(seed_signing_key, domain_0x05 || canonical(manifest))`.
  Nouveau tag de domaine **0x05 = `ProvenanceManifest`** dans
  `crypto-rs/core/src/signature_domain.rs` (0x01-0x04 deja pris ; la separation de
  domaine est deja en place, audit R-C-1). Le manifeste committe `root_plain`, donc
  la signature couvre **video + metadonnees** en un seul objet inviolable : le GPS
  ou l'heure ne peuvent pas etre permutes apres coup.
- **Scellement** : le manifeste signe est chiffre dans l'enveloppe STRM (meme cle
  derivee de la seed que la video). **Le relais ne voit ni le manifeste, ni les
  metadonnees.** (Confirme la propriete posee par therealshulgin : metadonnees jamais en
  clair sur le fil.)

## 3. Corroboration du lieu

### 3.1 Capture (Android, Kotlin)

- **GPS** : `FusedLocationProviderClient`, derniere position + accuracy.
- **Cellules** : `TelephonyManager.getAllCellInfo()` (necessite `ACCESS_FINE_LOCATION`).
- **WiFi** : `WifiManager` scan (BSSID + RSSI ; ⚠️ **throttling de scan** Android 9+,
  prevoir un cache court et le cas « scan refuse »).
- **Barometre** : `SensorManager` `TYPE_PRESSURE` (altitude relative).
- Tous horodates, passes au coeur Rust via UniFFI comme un bundle structure.
- ⚠️ Permissions : la collecte exige `ACCESS_FINE_LOCATION`. **Opt-in par
  enregistrement** : pas de collecte si la provenance est desactivee (defaut OFF).

### 3.2 Verification (cote temoin / verificateur, hors-ligne)

La corroboration n'est **pas** faite a la capture mais au **verify** : le verificateur
recoupe les signaux du manifeste contre des bases publiques :

- BSSID WiFi -> **WiGLE** ; CID cellules -> **OpenCellID** -> position independante.
- Coherence GPS vs triangulation cellulaire/WiFi vs altitude baro.
- L'**ensemble** des reseaux visibles est difficile a falsifier de facon coherente
  pour un lieu arbitraire (cout >> spoof GPS seul). **Coute, ne prouve pas.**

L'implementation cote app se borne donc a **capturer fidelement et lier** ; l'outil de
corroboration (script/CLI de verification) est un livrable separe (Phase D).

## 4. Horodatage (preuve d'anteriorite) : le point fort de Frappuccino

Frappuccino streame en **temps reel** -> le relais est un **temoin d'existence
horodate** que les outils « capture puis upload plus tard » n'ont pas. Deux sources,
combinees, aucune ne reposant sur l'horloge du telephone :

1. **Recu signe du relais** : a la reception, le relais signe `{ ciphertext_root, T_serveur }`
   et le renvoie ; le client l'archive. (Le relais est l'infra du temoin ; un relais
   qui mentirait sur l'heure ne pourrait que **anti-dater**, ce qui n'aide pas un
   accusateur de « faux fabrique apres ».)
2. **OpenTimestamps** (ancrage **Bitcoin**, **zero tiers de confiance**) : la racine de
   l'enregistrement est soumise a une calendar OTS ; la preuve « existait avant le
   bloc N » est recuperable apres confirmation. Gere le cycle **pending -> confirmed**
   (preuve mise a niveau quand le bloc est mine).

**Decision** : le **relais** soumet a OTS a la reception (anteriorite temps-reel) ; la
**CLI desktop** met a niveau et verifie la preuve plus tard. `wall_clock_claim_ms` du
manifeste reste un **claim**, jamais l'autorite.

## 5. Export C2PA (couche d'interoperabilite)

**Quoi** : C2PA / « Content Credentials » = standard de provenance (Adobe, Microsoft,
BBC, Sony, Nikon, Leica, Intel...). Un **manifeste signe** (boite JUMBF dans le MP4)
porte des **assertions** (createur, horodatage, lieu, historique d'editions) + une
signature couvrant assertions + hash du media. Verifiable par `c2patool`,
contentcredentials.org, etc.

**Pourquoi pour nous** : traduire notre preuve interne dans un **conteneur que juges et
journalistes savent verifier**, plutot qu'un format maison. Il existe une lib **Rust
`c2pa-rs`** -> s'integre au coeur Rust existant.

**Comment** : a la **recuperation d'archive** (mode archive / `frappuccino-cli`), generer
un MP4 a Content Credentials embarquees :

- **Liaison** : hard-binding C2PA sur les octets du MP4 reassemble (= `root_plain` du
  manifeste -> coherence verifiable).
- **Assertions** : action `c2pa.created`, horodatage, lieu (assertion standard ou
  custom `org.frappuccino.location`), + assertion custom portant la **preuve OTS** et
  le **recu relais**. C2PA supporte aussi un **timestamp RFC 3161** sur la signature
  du claim -> on l'ajoute en complement.
- **OMIS** : toute assertion d'appareil (`c2pa.device` / capture-device). Respecte le
  critere « pas de lien telephone ».
- **Signataire** : l'**identite pseudonyme** (cle Ed25519 de la seed) dans un cert
  X.509 **auto-signe**. C2PA approuve **Ed25519 (EdDSA)** -> compatible. Resultat :
  integrite + temps + lieu **verifiables** ; identite **auto-declaree** (un pseudonyme
  que le temoin choisit de relier, ou non, a sa personne).

**Limites C2PA (a documenter)** : ne prouve pas la veracite ; un manifeste peut etre
**retire** (mitige par soft-binding/watermark, hors v1) ; identite **non vouchee** par
une autorite (integrite+provenance, pas un label de confiance).

## 6. Modele de divulgation

- **Opt-in par enregistrement** (defaut OFF). Le temoin choisit « celui-ci, je veux
  pouvoir le prouver », en acceptant que la divulgation revele temps + lieu + pseudo.
- **V1 : divulgation complete.** Le temoin dechiffre et presente : MP4 + manifeste
  signe + preuve OTS + recu relais (et/ou l'export C2PA qui emballe le tout).
- **V2 : divulgation selective** (Phase D, futur). La **Merkleisation des champs**
  (sec. 2.2) est posee **des v1** pour la rendre possible sans re-architecture :
  reveler « lieu dans la region R a l'heure T » sans coordonnees exactes (preuve
  d'intervalle ZK), ou prouver l'inclusion d'un champ sans reveler les autres. ZK =
  **amelioration vie privee**, pas brique de base.

## 7. Placement architecture

| Couche | Composant | Role |
|---|---|---|
| Kotlin (`mobile/`) | collecte capteurs (Fused/Telephony/Wifi/Sensor) | bundle de signaux -> UniFFI |
| Rust (`crypto-rs/core`) | `signature_domain` 0x05 | separation de domaine |
| Rust (`crypto-rs/stream`) | construction + signature + scellement du manifeste | coeur |
| Relais (`server/`) | recu signe `{ciphertext_root, T}` + soumission OTS | temoin temps-reel |
| Rust (`frappuccino-cli`) | export C2PA (`c2pa-rs`), upgrade/verif OTS | interop, hors-ligne |

Principe : **toute la crypto sensible reste en Rust** (coherent avec le projet) ;
Kotlin ne fait que collecter et passer des octets ; le relais ne voit que du chiffre.

## 8. Suite de verification (coherent §8.4 / §10.10)

- **Separation de domaine** : tests in-crate « signer en 0x05 ne verifie pas en
  0x01-0x04 et reciproquement » (comme R-C-1).
- **proptest** : round-trip serialisation manifeste ; racine Merkle stable ;
  commitment de champ <-> divulgation (un champ revele verifie contre la racine).
- **Kani** : no-panic sur le parseur de manifeste (entree potentiellement hostile a
  la verification).
- **diff-fuzz** : si une partie de la serialisation/hash a un jumeau Kotlin, le
  differentier ; sinon, Rust-only (parite par construction).
- **Interop C2PA** : l'export passe `c2patool --info` / la validation
  contentcredentials.org (test d'interoperabilite, pas seulement nos propres outils).
- **OTS** : verifier une preuve confirmee de bout en bout.

## 9. Phasage gate (GO/NO-GO par phase)

- **Phase A : manifeste signe scelle** (coeur). Domaine 0x05, hash plaintext + Merkle,
  bundle curee, scellement E2E. **Aucune dependance externe.** Gate : round-trip +
  domain-sep + no-panic verts ; metadonnees jamais en clair (verifie cote relais).
- **Phase B : horodatage robuste**. Recu relais signe + OpenTimestamps (relais soumet,
  CLI upgrade). Gate : preuve OTS confirmee verifiee end-to-end ; recu relais verifie.
- **Phase C : export C2PA**. `c2pa-rs` dans la CLI, assertions sans appareil, signataire
  pseudonyme. Gate : MP4 exporte valide par `c2patool` **et** un verificateur tiers.
- **Phase D (futur) : divulgation selective + outillage corroboration**. ZK/Merkle
  reveal ; script de recoupement WiGLE/OpenCellID. Non bloquant pour une v1 utile.

**Perimetre v1 recommande = Phase A + B** (preuve interne solide : integrite +
anteriorite trustless + lieu lie). **C2PA en Phase C** des que l'interop est voulue.

## 10. Decisions ouvertes (a trancher avec therealshulgin)

1. **Stockage BSSID/cellules** : **brut + chiffre** (requis pour corroborer au verify).
   Alternative hashee = casse la corroboration. **Reco : brut + chiffre.** A confirmer.
2. **OTS** : soumission par le **relais** a la reception (temps-reel) vs par la **CLI**
   post-hoc. **Reco : relais soumet, CLI met a niveau** (meilleure anteriorite).
3. **Identite C2PA** : cert X.509 **auto-signe** pseudonyme (pas de CA). **Reco :
   oui** (le label de confiance n'est pas l'objectif ; integrite+temps+lieu suffisent).
4. **Perimetre v1** : Phase A+B seules, ou inclure C2PA (Phase C) d'emblee ?
5. **Defaut** : provenance **OFF** par defaut (opt-in explicite par enregistrement),
   confirme ?

## 11. Ce qu'on ne promet pas (texte pour le site / le guide)

- Prouve l'**integrite**, l'**anteriorite** et des **metadonnees liees** ; **pas** la
  veracite de la scene (deepfake / ecran filme restent indetectables crypto).
- **PRNU** : la video peut, en analyse forensique, trahir le capteur ; la crypto n'y
  peut rien.
- GPS/RF **falsifiables** ; le multi-signal augmente le cout, ne prouve pas.
- L'identite C2PA est **auto-declaree** (pseudonyme), non vouchee par une autorite.
- Provenance = **opt-in**, metadonnees **chiffrees E2E**, divulgation **choisie**.
