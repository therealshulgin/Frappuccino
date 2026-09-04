# Vérification formelle du ratchet & mesure déterministe des passes d'audit

Document de travail pour la V2 crypto de STREAM (ratchet éphémère à lignée Algorand, capacités de device asymétriques).

Deux objectifs distincts :

1. **Partie 1–2** — *Qu'est-ce qui doit être vrai, et avec quel outil le prouver ?* Liste des invariants et mapping vers les outils de preuve.
2. **Partie 3** — *Comment savoir, de façon déterministe, qu'une passe d'audit améliore réellement la sécurité plutôt que de la dégrader ?* (Réponse directe au phénomène de dégradation itérative documenté par IEEE-ISTAS.)

---

## Partie 1 — Invariants crypto à vérifier

### A. Ratchet symétrique (chaînes de clés)

- **One-wayness des chain keys** — la dérivation `CK_{n+1} = KDF_CK(CK_n)` est à sens unique : à partir de `CK_n` on ne peut pas reconstruire `CK_{n-1}` ni aucune `MK` antérieure. C'est le socle de la forward secrecy intra-chaîne.
- **Unicité & usage unique des message keys** — chaque `MK` est dérivée d'un `(CK, compteur)` unique et n'est jamais réutilisée. Invariant critique pour l'AEAD : toute réutilisation de couple (clé, nonce) est catastrophique (perte de confidentialité, forge possible).
- **Séparation de domaine** — root key, chain keys et message keys sont dérivées avec des labels KDF distincts et non ambigus. Aucune clé d'un contexte n'est jamais valide dans un autre contexte.
- **Effacement (zeroization) après usage** — `MK` effacée immédiatement après chiffrement/déchiffrement ; `CK_n` effacée après dérivation de `CK_{n+1}`. L'invariant est *temporel* : à tout instant, le minimum de matériel secret nécessaire existe en mémoire.

### B. Ratchet asymétrique (DH / root key)

- **Forward secrecy (FS)** — la compromission de l'état courant ne révèle aucun message passé. Formellement : tout `MK` consommée est irrécupérable depuis l'état courant.
- **Post-compromise security / healing** — après compromission de l'état, la sécurité est *restaurée* dès qu'un pas de ratchet DH s'exécute avec un aléa non compromis. À prouver : il existe une borne (en nombre de messages/pas) après laquelle un état compromis redevient sûr.
- **Évolution & effacement de la root key** — chaque nouvelle clé publique de ratchet déclenche `RK_{i+1} = KDF_RK(RK_i, DH)` ; `RK_i` est effacée. La root key n'est jamais réutilisée entre époques.
- **Authentification des clés publiques de ratchet** — toute clé publique de ratchet reçue est liée à une identité authentifiée (signée / ancrée dans le handshake initial). Sans cet invariant, FS et PCS sont vides : un MITM actif suffit. **C'est le point où les capacités asymétriques de device entrent en jeu** (voir §E).

### C. Machine à états & ordonnancement

- **Monotonicité des compteurs** — `Ns`, `Nr`, `PN` ne font que croître. Aucun chemin d'exécution ne les décrémente.
- **Absence de rollback** — aucun message ne peut ramener la machine à un état antérieur (pas de réacceptation d'une clé publique de ratchet déjà dépassée).
- **Gestion bornée des skipped keys** — stockage des clés sautées plafonné par `MAX_SKIP` (anti-DoS mémoire) ; les clés sautées sont elles-mêmes effacées après consommation ou expiration.
- **Anti-rejeu** — une `MK` consommée ne peut être acceptée une seconde fois. Découle de l'effacement + des compteurs, mais à vérifier *comme propriété explicite* sur la machine à états.
- **Liaison de l'associated data** — le header (clé publique de ratchet, `PN`, `N`) est lié dans l'AD de l'AEAD : toute altération du header invalide le déchiffrement.

### D. Couche éphémère / forward-secure (lignée Algorand)

- **Monotonicité d'epoch** — le secret de l'epoch `e` est détruit avant le passage à `e+1` ; il ne peut jamais servir à signer/dériver pour `e' < e`. C'est la propriété forward-secure du schéma à clé évolutive.
- **Effacement forward-secure** — l'effacement du secret par epoch *est* la frontière de sécurité ; à prouver que le chemin d'évolution ne conserve aucune information permettant de reconstruire un secret d'epoch passé.
- **VRF — déterminisme** — pour une clé et une entrée données, il existe exactement une sortie valide.
- **VRF — unicité & infalsifiabilité de la preuve** — la preuve VRF n'est vérifiable que pour la sortie correcte ; impossible de produire une preuve valide pour une sortie forgée.
- **VRF — pseudo-aléa** — sans la clé, la sortie est indistinguable d'un aléa uniforme.

### E. Capacités asymétriques de device

- **Non-escalade de capacité** — un device à capacité réduite ne peut dériver aucune clé ni exécuter aucune opération réservée à un device à capacité supérieure. Aucun chemin n'élève les droits.
- **Liaison d'autorité** — chaque opération est liée au token de capacité du device ; le token est infalsifiable et non transférable (lié à l'identité du device).
- **Isolation de compromission** — la compromission d'un device low-cap n'expose pas les secrets high-cap. C'est la PCS au niveau multi-device : le blast radius d'un device compromis est borné à ses propres capacités.

---

## Partie 2 — Mapping invariant → outil de preuve

Trois couches, trois familles d'outils. Aucune ne couvre tout ; la garantie vient de leur recouvrement.

### Couche protocole (modèle symbolique, Dolev-Yao)

- **Tamarin** — le plus adapté aux protocoles à état évolutif (ratchet, multi-device). Exprime FS, PCS/healing, authentification, anti-rejeu comme propriétés de trace, et les compromissions adverses comme règles explicites. Référence : les analyses Signal de Cohn-Gordon et al. sont en Tamarin.
- **ProVerif** — plus rapide sur secret/authentification, modèle applied-pi ; moins confortable sur l'état mutable lourd. Bon complément pour cross-check.

### Couche calculatoire (réductions, bornes concrètes)

- **CryptoVerif** — preuves par jeux dans le modèle calculatoire, plus proche d'une réduction crypto réelle que le symbolique. Pertinent pour justifier les hypothèses sur les KDF/AEAD.
- **EasyCrypt** — preuves game-hopping machine-vérifiées ; plus coûteux, à réserver au cœur (KDF chain, dérivation root).

### Couche machine à états (exploration exhaustive)

- **TLA+ / TLC** — *l'outil que j'ajouterais en priorité* pour la §C. Modélise la FSM du ratchet et vérifie exhaustivement monotonicité des compteurs, absence de rollback, gestion bornée des skipped keys, anti-rejeu, sous toutes les permutations d'ordonnancement et pertes de messages. Déterministe et exhaustif sur états bornés.

### Couche implémentation Rust (du modèle au code)

- **hax** (ex-hacspec, Cryspen) — extrait du Rust vers F\*/Coq/ProVerif. C'est la voie utilisée par les implémentations crypto vérifiées de l'écosystème (libcrux, MLS). Idéal pour relier le code Rust effectif au modèle prouvé.
- **Verus** — vérification SMT consciente de l'ownership Rust ; bon pour les invariants de structure de données et de machine à états directement dans le code.
- **Kani** (CBMC) — bounded model checking : vérifie assertions, débordements, et invariants de la FSM sur des bornes concrètes. Faible coût d'entrée, complète bien Verus.
- **Creusot / Aeneas** — vérification déductive (WhyML) / traduction vers modèles fonctionnels F\*/Coq/Lean pour les portions purement fonctionnelles (KDF).

### Couche side-channel (constant-time)

- **dudect** — test statistique de timing, déterministe sous seed fixe.
- **haybale-pitchfork** — exécution symbolique LLVM pour prouver le constant-time des chemins manipulant des secrets.
- **crate `subtle`** — primitives constant-time côté implémentation (pas un vérificateur, mais l'ancrage pratique des comparaisons de secrets).

> Stratégie de recouvrement recommandée : **Tamarin** (protocole) + **TLA+/TLC** (FSM) + **hax/Verus** (code) + **pitchfork** (constant-time). Chaque invariant de la Partie 1 doit être assigné à au moins une de ces couches.

---

## Partie 3 — Outils déterministes pour mesurer l'effet des passes d'audit

Objectif : détecter empiriquement si une passe Red/Blue **améliore** ou **dégrade**. Le principe directeur : chaque passe doit produire une métrique *déterministe, monotone et lisible par machine*, suivie comme série temporelle, avec un gate de régression. Une passe qui fait remonter une métrique est rejetée — c'est la traduction opérationnelle du critère de terminaison non-LLM.

### Pré-requis : déterminisme reproductible

Fixer tous les aléas (RNG, seeds de fuzzer, seeds de proptest) pour que deux passes soient comparables. Sans seeds figées, les métriques bruitées masquent l'effet réel de la passe.

### Comptage de findings (signal primaire)

- **SARIF diffing** — Semgrep *et* CodeQL émettent du SARIF. Differ les rapports entre passes (`sarif-tools`, code scanning diff) donne un delta déterministe et par-CWE. **Invariant de gate : le compte par classe CWE décroît de façon monotone.** Toute réintroduction = échec de passe.
- **cargo-audit / osv-scanner** — comptage des advisories RustSec/OSV ; doit aller vers zéro et y rester.

### Efficacité réelle des tests (le signal le plus fort)

- **cargo-mutants** (mutation testing Rust) — injecte des fautes et vérifie que la suite les attrape. Le **score de mutation** mesure si les tests *valent quelque chose*, pas seulement s'ils passent. Une bonne passe d'audit *augmente* le score de mutation. Déterministe (opérateurs de mutation + tests déterministes).
- **PIT / Stryker** — équivalent côté base Kotlin Tella, pour auditer l'original indépendamment du port.

### Découverte de défauts par exécution

- **cargo-fuzz / AFL++** — suivre crashes trouvés et croissance de couverture du corpus ; rejeu par seed = déterministe.
- **Differential fuzzing Kotlin↔Rust** — mêmes entrées sur les deux implémentations ; toute divergence non intentionnelle est un bug. Valide la parité *et* trouve des crashes hors suite de tests.
- **KLEE** (exécution symbolique) — couverture de chemins et violations d'assertions, déterministe.

### Couverture & régression

- **cargo-llvm-cov / grcov** — couverture branche + ligne. Nécessaire mais faible seul (à coupler au score de mutation).
- **proptest / quickcheck** à seed figée — property-based testing sur parseurs, désérialiseurs, frontières crypto ; le shrinking donne un contre-exemple minimal reproductible.
- **insta** (snapshot testing) — détection déterministe de régression sur sorties figées.
- **KATs (known-answer tests)** — vecteurs déterministes sur les chaînes KDF et le VRF ; toute dérive = régression immédiate.

### Surface, supply chain & durcissement binaire

- **cargo-geiger** — tendance du nombre de blocs `unsafe` ; doit décroître ou rester stable et justifié.
- **cargo-deny / cargo-vet** — bans, advisories, licences, attestations d'audit de dépendances.
- **cargo-auditable** — embarque la liste des dépendances dans le binaire (traçabilité post-build).
- **checksec** — flags de durcissement du binaire (RELRO, stack canaries, NX, PIE) ; déterministe.

### Vérifiabilité du build

- **diffoscope** — comparaison de binaires pour valider les builds reproductibles ; permet à l'utilisateur de vérifier que le binaire correspond au source (propriété de sécurité de premier ordre pour une app activiste).

### Tableau de bord de passe (synthèse)

Une passe d'audit est **acceptée** si et seulement si, à seeds figées :

| Métrique | Direction attendue | Outil |
|---|---|---|
| Findings SARIF par CWE | ↓ monotone | Semgrep + CodeQL + sarif-tools |
| Advisories dépendances | → 0 | cargo-audit, osv-scanner |
| Score de mutation | ↑ | cargo-mutants |
| Crashes fuzz / divergences diff | ↓ | cargo-fuzz, differential fuzzing |
| Couverture branche | ↑ ou stable | cargo-llvm-cov |
| Blocs `unsafe` | ↓ ou justifié | cargo-geiger |
| Flags de durcissement | tous présents | checksec |
| KATs / snapshots | inchangés | insta, vecteurs figés |

Toute métrique qui régresse déclenche un flag humain et bloque le merge. C'est exactement le mécanisme qui empêche la boucle d'agents de converger vers un faux « clean ».
