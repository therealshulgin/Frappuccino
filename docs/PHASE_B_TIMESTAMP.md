# Phase B — Horodatage indépendant de la provenance (ROADMAP §10.11)

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

Statut : **Mécanisme TRANCHÉ = (c) OTS/Bitcoin** (décision therealshulgin 2026-06-25).
**Slices 1 + 2 LIVRÉES** (voir §6 staging). **Slice 2 = salté** (décision therealshulgin
2026-06-25 : commitment salé, pas le digest direct). Reste **slice 3** (dernier
kilomètre Bitcoin) + le **déploiement OTS du relais = GO opérateur séparé** (le
code relais est écrit mais **dormant** : `OTS_ENABLED=false` + lib hors
`requirements.txt`).

Bundle de divulgation auto-suffisant (post-rescue) :
`frappuccino-cli verify-provenance --manifest <sid>.manifest --cert cert.json
--chunk … --ots <sid>.ots --ots-salt $(cat <sid>.otssalt)`.

## 1. Le problème exact

Le manifeste de provenance prouve déjà : **intégrité** (Merkle `root_plain`),
**authenticité** (signé par `P`), **attribution** (mini-cert identité→P, 0x06),
**durabilité** (relais). Le seul maillon faible : le **QUAND**. Le manifeste
porte `wall_clock_claim_ms` = **l'heure auto-déclarée de l'horloge du téléphone**.
Un adversaire répond : *« réglable, tu l'as antidaté / fabriqué après coup »*.

Phase B = ajouter une **preuve du QUAND indépendante du témoin**. Sémantique
exacte = **borne supérieure** : « ce manifeste existait *au plus tard* à T » →
tue l'argument *« fabriqué après l'événement »* (le cas adversarial central d'un
témoignage). Ne prouve PAS « filmé pile à T » ni « en direct ».

## 2. Ce qu'on horodate

Le **digest = `SHA-256(manifest.signature)`** (la signature Ed25519 0x05, 64 o).
La signature engage déjà tout le manifeste (entête + `fields_root`), donc
l'horodater = horodater le manifeste entier (donc le média que `root_plain`
engage). Un seul digest par enregistrement. Aucun contenu n'est exposé (un hash).

## 3. Les trois mécanismes possibles (du plus faible au plus fort)

| | Ancre de confiance | Instantané ? | Trustless ? | Complexité | IP témoin exposée à |
|---|---|---|---|---|---|
| **(a) Reçu relais** signé `{digest, T}` | NOTRE relais | oui | ❌ « tu run le relais » | faible | personne de neuf (déjà le relais) |
| **(b) RFC 3161 TSA** (token signé d'une autorité, ex. freeTSA/DigiCert) | un tiers (CA) | oui | ❌ mais tiers indépendant, **reconnu en justice** ; ⚠️ **compellable** (CA régulée, souvent US) | **faible** (1 requête HTTP, token ASN.1) | la TSA |
| **(c) OpenTimestamps → Bitcoin** | **personne** (proof-of-work) | ❌ async (~h) | ✅ **vraiment trustless** | **forte** (calendars + format `.ots` + vérif bloc Bitcoin) | les calendars |

- **(a)** : l'éval neutre l'a jugé sur-vendu, à raison — contre l'adversaire qui
  compte, « antidatage par l'opérateur » est exactement l'attaque. Valeur réelle =
  artefact *portable* (le témoin le garde même relais mort). Pas une ancre.
- **(b)** RFC 3161 : **beaucoup plus simple** que OTS, **instantané**, et c'est le
  standard de l'horodatage de signature de code / documents (donc *reconnu*). Mais
  « fais confiance à la TSA » : une CA US peut être contrainte par un État — exactement
  notre adversaire. Atténuation : multi-TSA (plusieurs juridictions).
- **(c)** OTS/Bitcoin : la seule ancre qu'**aucun État ne peut antidater**.
  **Gratuit** (agrégation : des milliers de hash → 1 transaction Bitcoin payée par
  l'opérateur du calendar). Coût = **latence** (la preuve « mûrit » en ~h) +
  dépendance liveness aux calendars (mais un calendar mort/malveillant ne peut que
  **rater** l'estampille, jamais en **forger** une fausse — il ne falsifie pas la
  proof-of-work) + le **dernier kilomètre** de vérif (confirmer le bloc Bitcoin).

## 4. Architecture de soumission (qui parle aux calendars/TSA)

- **Client-direct** : le device soumet le digest aux calendars/TSA publics. Pas de
  changement relais/PROD. **MAIS expose l'IP du témoin à de nouveaux tiers** (les
  calendars/TSA) → vecteur de-anon pour un activiste.
- **Relais-assisté** : le device envoie le digest au relais (à qui il parle déjà
  pour l'upload) ; **le relais** soumet aux calendars + récupère/stocke le `.ots`.
  Le témoin **ne parle qu'au relais** → aucun tiers nouveau ne voit son IP. ⚠️
  Touche le **relais en PROD = GO explicite therealshulgin**. ⚠️ Le relais apprend « ce
  report a une provenance, estampillée à T » → **fuite de corrélation** (l'éval) →
  atténuer : digest = **commitment salé** (le relais ne peut pas relier au
  `report_id`) + **opt-in par enregistrement** (pas automatique : un `.ots` est une
  miette publique permanente). **✅ FAIT (slice 2)** : `commitment = SHA-256(salt ‖
  SHA-256(signature))`, `salt = HKDF(seed provenance, recording_id)` — calculé en
  Rust au scellement, jamais transmis au relais, re-dérivé depuis la phrase au
  rescue (`<sid>.otssalt` dans le bundle). Défait aussi la **de-anon rétroactive**
  d'un relais loggant face à un manifeste rendu public (sans le salt, pas de lien).
  Opt-in : toggle Settings « HORODATAGE OTS » défaut OFF.

## 5. Vérification (côté verifier CLI, offline)

- (a)/(b) : vérifier la signature du reçu/token contre la pubkey relais / le cert
  de la TSA, et que le digest == `SHA-256(manifest.signature)`.
- (c) OTS : parser le `.ots` (crate `opentimestamps`), **replay** les opérations →
  obtenir l'attestation (calendar *pending*, ou Bitcoin bloc H + racine Merkle) ;
  confirmer que le digest initial == `SHA-256(manifest.signature)`. **Dernier
  kilomètre** = « le bloc H a le timestamp T » : options = (i) interroger un
  explorer Bitcoin (`blockstream.info`) [confiance explorer, PoW dur à forger,
  cross-check multi-explorer], (ii) SPV headers embarqués [lourd], (iii)
  report-only « engage le bloc H, vérifie-le contre Bitcoin ». Cut 1 = (iii)+(i).

## 6. Recommandation

**Cible = (c) OTS/Bitcoin, soumission relais-assistée**, avec commitment salé +
opt-in. C'est la seule ancre trustless, gratuite, alignée sur un adversaire
étatique — exactement notre modèle de menace. Le reçu relais (a) ne vaut pas la
peine ; RFC 3161 (b) est un *interim* simple et instantané si tu veux quelque
chose de tangible vite, mais sa confiance-CA est faible contre notre adversaire.

**Staging** (chaque slice testable, le PROD clairement isolé) :
1. **✅ Verifier `--ots` (HOST, sans PROD)** — crate intégré, `verify-provenance
   --ots <f> [--ots-salt <hex>]` : parse+replay, leaf == SHA-256(sig) ou
   SHA-256(salt‖SHA-256(sig)), report attestation. Tests e2e (salé + non-salé).
2. **✅ Soumission relais-assistée (code écrit, déploiement = GO PROD)** —
   endpoint relais `POST /api/v2/timestamp` (commitment opaque 32 o → calendars →
   `.ots`, **dormant** tant que `OTS_ENABLED=false`) ; device opt-in (worker
   `ProvenanceTimestampWorker` → upload durable chaîné) ; rescue re-dérive +
   exporte le salt. **Reste : déployer l'OTS du relais (GO opérateur) pour activer
   le happy-path** — sans, le worker reçoit 503 et abandonne proprement.
3. **Dernier kilomètre Bitcoin** — explorer-check (i) dans le verifier + `upgrade`
   du `.ots` pending→confirmé.

Option *interim* possible en parallèle : RFC 3161 (b) client-direct ou
relais-assisté = un horodatage **instantané + reconnu** tout de suite, en attendant
que l'ancre OTS mûrisse. À discuter.

## 7. Décisions ouvertes (pour therealshulgin)

1. **Mécanisme** : OTS-Bitcoin seul (trustless, async) / + RFC 3161 en interim
   (instantané, mais CA-trust) / autre ?
2. **Soumission** : relais-assisté (anonymat témoin, GO PROD) confirmé ?
3. **Défaut** : opt-in par enregistrement (recommandé — `.ots` = miette publique
   permanente) ou ON par défaut ?
