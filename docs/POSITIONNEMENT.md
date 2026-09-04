# Frappuccino - Positionnement

> **Objet :** le problème auquel Frappuccino répond, comment, et où il se situe
> face aux outils existants. Matière de référence pour le site de présentation
> et pour cadrer le projet.
>
> **Registre :** le même que tout le reste du dossier - transparence. On dit ce
> que l'outil fait, ce qu'il ne fait pas, et ce que font bien les autres. En cas
> de divergence entre ce document et le code, **le code fait foi**.
>
> **Date :** 2026-06-28. Compagnons : [`ARCHITECTURE_TECHNIQUE_COMPLETE.md`](ARCHITECTURE_TECHNIQUE_COMPLETE.md)
> (architecture détaillée), [`GUIDE_AUDITEUR.md`](GUIDE_AUDITEUR.md) (dossier de
> preuves), [`FORK_VS_TELLA.md`](FORK_VS_TELLA.md) (deltas vs l'upstream).

---

## En une phrase

**Frappuccino transforme un téléphone Android en émetteur de témoignage vidéo
chiffré : la vidéo part pendant qu'elle se filme, vers un relais qui ne peut pas
la lire, et la seule clé de lecture est une phrase de 12 mots écrite sur papier.**

Saisir le téléphone - avant, pendant ou après l'enregistrement - ne donne plus
rien à lire.

---

## 1. Le problème

### 1.1 Le scénario

Un militant filme une exaction. Une journaliste documente un site bouclé. Un
avocat enregistre une interpellation. Trois choses peuvent leur arriver, souvent
dans cet ordre :

1. **Le téléphone est saisi** - au checkpoint, à la frontière, pendant la garde
   à vue, ou arraché des mains en pleine captation.
2. **Le code est exigé** - sous la contrainte, le PIN finit par être donné.
3. **Le matériel part en extraction forensique** - Cellebrite, GrayKey : le
   stockage est imagé, les coffres locaux sont brute-forcés hors ligne.

À l'autre bout de la chaîne, le serveur qui reçoit les images est lui-même une
cible : saisie légale, piratage, opérateur infidèle. Et entre les deux, le
réseau peut être intercepté.

### 1.2 Trois exigences que presque rien ne combine

Pour que le témoignage survive à ce scénario, il faut **simultanément** :

- **(a) Survivre à la saisie et au wipe de l'appareil.** Le contenu doit exister
  ailleurs que sur le téléphone, et rester récupérable par le témoin - y compris
  depuis un appareil neuf, sans compte, sans cloud, sans tiers.
- **(b) Ne pas être lisible par le serveur.** Si le relais est saisi ou hostile,
  il ne doit avoir à livrer que des octets opaques. Un serveur ne peut pas
  trahir ce qu'il ne peut pas lire.
- **(c) Tenir même si le téléphone est arraché en cours d'enregistrement.**
  Un fichier local chiffré « à la fin » ne protège rien si la captation est
  interrompue de force. La vidéo doit quitter l'appareil au fil de la capture,
  déjà chiffrée.

### 1.3 Pourquoi le coffre-fort local ne suffit pas

La réponse classique - chiffrer les fichiers sur l'appareil - répond mal au
scénario : **un coffre, ça s'ouvre**. Par brute-force du code, par coercition
sur son détenteur, par exploitation de l'OS. Tant que la donnée est *sur* le
téléphone et que la clé de lecture y est aussi, le téléphone reste le point de
défaillance unique - et c'est précisément lui que l'adversaire tient dans ses
mains.

Le problème n'est pas de mieux fermer le coffre. C'est de **ne plus être un
coffre**.

---

## 2. Notre réponse

> *« Le téléphone est un émetteur. Pas un coffre. »*

Frappuccino est un fork de Tella FOSS (Horizontal.org) : la base Android de
documentation pour activistes est conservée, le cœur - cryptographie, capture,
transport, modèle de confiance - est remplacé. Cinq choix structurent la
réponse.

### 2.1 La vidéo part pendant qu'elle se filme

L'enregistrement est découpé en **chunks de 5 secondes**, chacun chiffré de
bout en bout **sur l'appareil** puis uploadé immédiatement. Si le téléphone est
arraché à la minute 12, les 12 premières minutes sont déjà hors d'atteinte -
chiffrées sur le relais, illisibles localement.

Le pipeline est conçu pour le terrain, pas pour le studio : encodage **HEVC**
matériel (≈ 35-45 % de débit en moins qu'en H.264, avec repli H.264
automatique), **qualité adaptative** au réseau, file d'upload **persistante**
qui survit aux coupures réseau, au redémarrage et à la mort du process, reprise
et ré-essais automatiques. Enregistrement **écran éteint**, déclenchement par
**secousse du téléphone** (*shake to stream*), écran noir furtif d'un geste.

### 2.2 Un relais qui ne peut pas trahir : le serveur aveugle

Le serveur ne stocke que des **blobs opaques**. Le chiffrement a lieu avant de
quitter l'appareil, vers une clé dont la moitié privée **n'existe sur aucune
machine** - ni sur le téléphone, ni sur le serveur. Le relais vérifie des
signatures, impose l'anti-rejeu, stocke et restitue des octets. Il ne voit
jamais une image. Il ne journalise pas les adresses IP.

Conséquence assumée dans les deux sens : la **saisie du serveur est une donnée
d'entrée du design**, pas un cas d'échec. Et l'opérateur du relais - nous
compris - est traité comme potentiellement hostile : la confidentialité ne
repose sur aucune promesse de bonne conduite.

Honnêteté sur ce qui subsiste au repos : la saisie n'expose **ni identité réelle**
(aucune personne, aucun rattachement civil) **ni contenu**, mais un opérateur voit
des **volumes et des horodatages** de blobs, ainsi qu'un **registre de pseudonymes
d'authentification** (clés Ed25519 auto-générées, non rattachées à une personne,
avec leurs slots consommés) — il ne peut ni en déduire le *qui* réel, ni les relier
à un report précis (le lien report→identité est écarté à l'upload). Les
noms de blobs sont opaques (rien n'y est lisible), y compris ceux du « répertoire »
interne qui permet à un témoin de retrouver tous ses streams sur un appareil neuf :
ses entrées portent désormais un nom **dérivé d'un secret** (et non plus un index
décimal lisible), si bien qu'un opérateur ne peut plus y lire le compteur de
sessions ni la cadence du témoin. Ce qui reste corrélable, c'est le **nombre**
d'objets et leur **cadence** dans le temps, et le fait que les sessions d'un même
témoin restent liées entre elles au repos sous un identifiant opaque - jamais le
**qui** ni le **quoi**. C'est le prix d'un relais qui restitue sans rien connaître,
et c'est borné par le motto : *une saisie n'expose rien* au sens d'aucun témoignage
et d'aucune personne.

### 2.3 La clé n'est pas dans le téléphone : 12 mots sur papier

À l'enrôlement, l'appareil génère une phrase **BIP-39 de 12 mots français**,
affichée une fois, jamais stockée. Cette phrase est la **clé souveraine** : le
seul chemin vers la lecture des streams et la récupération de l'identité.

- Téléphone saisi, détruit, wipé ? Sur un appareil neuf : mode archive, saisie
  des 12 mots, **« RÉCUPÉRER MES STREAMS »** - les témoignages redescendent du
  relais et se déchiffrent localement. Pas de compte, pas d'e-mail, pas de
  cloud, pas de tiers à supplier.
- Aucune autorité - y compris nous - ne peut restituer ou réinitialiser cette
  clé. C'est le sens du mot *souverain* : la capacité de lecture appartient au
  témoin, physiquement, hors ligne.
- Un **13ᵉ mot optionnel** dérive une identité disjointe - un levier de
  cloisonnement pour qui s'y prépare.

La contrepartie est dite sans euphémisme : **qui détient la phrase détient
tout**, et une phrase perdue rend les archives définitivement illisibles. Le
design concentre délibérément la défaillance sur un artefact physique unique,
hors ligne, sous contrôle humain - plutôt que sur dix points logiciels.

### 2.4 Le passé est hors d'atteinte - et c'est prouvé

Après enrôlement, le téléphone peut **chiffrer** et **signer**, mais ne peut
**jamais déchiffrer son propre passé** ni forger des signatures pour des
sessions antérieures :

- La clé privée de lecture (X25519) n'est **jamais persistée** sur l'appareil : elle
  n'est dérivable que depuis la phrase papier, vit en mémoire verrouillée le temps
  d'une session en mode archive, et s'efface à la sortie. Le téléphone qui vient
  d'enregistrer ne l'a jamais eue.
- L'authentification repose sur un **ratchet de clés éphémères** inspiré du
  mécanisme de forward security du consensus **Algorand** : des lots de 50 clés
  de signature à usage unique, chaque clé **détruite immédiatement** après
  usage, chaque lot authentifié par le précédent jusqu'à l'identité d'origine.

Un adversaire qui obtient le téléphone, le PIN, et même un dump mémoire,
obtient au pire la capacité de signer quelques sessions *futures* - bornée,
détectable, révocable - mais **pas un octet de contenu passé**, ni la
possibilité de réécrire l'histoire.

Cette propriété n'est pas une intention : la **forward secrecy du protocole est
prouvée formellement** (modèle Dolev-Yao vérifié par **Tamarin**, 10/10 lemmes,
avec contrôles négatifs qui falsifient quand on retire le mécanisme), sa
machine à états est model-checkée exhaustivement (**TLA+/TLC**), et l'effacement
effectif des clés en mémoire est vérifié **au niveau du code compilé** (audit
d'IR LLVM : le wipe n'est pas éliminé par l'optimiseur).

### 2.5 La confiance ne se déclare pas, elle se vérifie

Toute la cryptographie sensible est écrite en **Rust** (zéro `unsafe` hors un
module mémoire isolé et commenté, dépendances épinglées à la version exacte,
secrets auto-effacés) - aucune primitive maison : nous assemblons des briques
publiques et éprouvées (Ed25519, X25519, XChaCha20-Poly1305, Argon2id, HKDF,
rustls), et ce que nous avons écrit - la logique de protocole - est ce que nous
faisons vérifier.

Le projet maintient une **suite de preuves machine-vérifiées**, chacune
rejouable par commande et munie d'un contrôle négatif :

| Preuve | Ce qu'elle garantit |
|---|---|
| **Tamarin** (protocole, Dolev-Yao) | Secret des clés, authentification, anti-rejeu, inforgeabilité des rotations, forward secrecy |
| **TLA+/TLC** (machine à états, 2 800 états) | Monotonie, anti-rejeu, anti-rollback, usage unique des clés, et **rotation toujours possible** (le dernier slot d'un lot est réservé à la rotation, donc un lot ne peut pas être consommé jusqu'à l'impasse) |
| **Kani** (model-checking borné) | Le parseur d'en-tête ne panique sur **aucune** entrée de 0 à 200 octets, exhaustivement (l'espace borné qui couvre un en-tête complet plus une entrée de grant) |
| **Diff-fuzz Kotlin↔Rust** (759/759 vecteurs) | La migration Rust est byte-identique à la référence |
| **Zeroize-audit** (IR LLVM) | L'effacement des secrets survit à l'optimiseur, au profil de compilation expédié |
| **Provenance binaire** (manifest sha256 + gate de build) | Le `.so` crypto expédié vient bien de **ce commit + cette toolchain** (pas un binaire substitué) - le maillon au-delà de l'IR |

S'y ajoutent mutation testing (jusqu'à 100 % de mutants tués sur le chemin de
déchiffrement), fuzzing, property testing, et des **audits adverses internes
croisés entre modèles d'IA distincts, arbitrés par re-vérification sur le code**
- jamais sur la parole des agents. Le tout est documenté pour être rejoué par
un auditeur externe ([`GUIDE_AUDITEUR.md`](GUIDE_AUDITEUR.md)).

Ce niveau d'assurance - des preuves formelles du protocole jusqu'à l'IR du
compilateur - est rare dans cette catégorie d'outils. Il ne remplace pas
l'audit humain externe (prévu, pas encore réalisé - voir §5) ; il le prépare.

### 2.6 Et le quotidien du terrain

PIN protégé par **Argon2id** (256 MiB de mémoire par tentative : le brute-force
hors ligne devient un projet industriel), liste de refus anti-essais, **TLS
épinglé** au certificat du relais (un MITM avec une autorité de certification
valide est rejeté - testé), écrans sensibles protégés contre la capture,
verrouillage automatique du ratchet à l'inactivité, **bouton d'effacement
d'urgence** (panic wipe) qui détruit l'état local - les streams, eux, sont déjà
ailleurs, récupérables par les 12 mots.

---

## 3. Face aux autres outils

Aucun des outils ci-dessous n'est un adversaire : plusieurs sont
**complémentaires**, et chacun fait mieux que Frappuccino sur son propre
terrain. Le tableau situe la combinaison ; le détail nuance.

| Capacité | Frappuccino | Tella | Signal | ProofMode | eyeWitness |
|---|---|---|---|---|---|
| Pensé pour le témoignage vidéo de terrain | **Oui** | Oui | Non (messagerie) | Oui (photo/vidéo) | Oui |
| Le contenu quitte l'appareil **pendant** la capture, chiffré | **Oui** | Non (envoi a posteriori) | Non | Non | Non (envoi après capture) |
| Serveur structurellement incapable de lire (relais aveugle) | **Oui** | Non¹ | Hors objet² | Hors objet | Non (l'institution lit - c'est sa fonction) |
| Saisie de l'appareil : rien de lisible localement | **Oui** | Partiel (coffre local = cible) | Partiel | Non | Partiel (après envoi) |
| Compromission de l'appareil : le passé reste illisible (forward secrecy) | **Oui, prouvée formellement** | Non | Oui (messages) | Hors objet | Non documenté³ |
| Récupération souveraine sans tiers (phrase 12 mots) | **Oui** | Non | Non | Non | Non (via l'institution) |
| Authenticité / chaîne de custody pour un tribunal | **Non (pas l'objet)** | Partiel (métadonnées) | Non | **Oui** | **Oui** |
| Maturité, communauté, audits externes | **Pas encore** | Oui | Oui | Oui | Oui |

¹ Le serveur de destination (Tella Web, Uwazi) reçoit et lit les rapports :
c'est voulu - c'est l'organisation du militant qui l'opère.
² Signal ne stocke pas les contenus côté serveur ; il n'offre simplement pas de
fonction d'archivage.
³ À notre connaissance ; modèle de confiance institutionnel, code non public.

### 3.1 Tella - l'upstream, et ce qu'on lui doit

**Ce que Tella fait bien** - et la raison pour laquelle nous sommes partis
d'elle : une app de documentation éprouvée sur le terrain, portée par
Horizontal, traduite en 17 langues, disponible sur Android, iOS et F-Droid ;
un coffre chiffré local, le camouflage de l'app (nom, icône, calculatrice
fonctionnelle), la collecte structurée (formulaires ODK) vers les serveurs
d'une organisation (Tella Web, Uwazi), la suppression rapide. Pour une ONG qui
coordonne une collecte d'observations avec son propre serveur, **Tella reste le
bon outil** - et son périmètre (iOS, formulaires, multilingue) dépasse le nôtre.

**Ce que Frappuccino remplace.** Le modèle de Tella est le **coffre au repos** :
les fichiers sont chiffrés *sur* l'appareil, l'envoi vient ensuite. Face à une
saisie en cours de captation ou à une extraction forensique, le coffre est la
cible. Frappuccino inverse le modèle : streaming chiffré temps réel vers relais
aveugle, plus rien de lisible sur l'appareil, récupération par les 12 mots. La
cryptographie a été **entièrement réécrite** (protocole V2 forward-secure,
100 % Rust, prouvée formellement) ; le pipeline vidéo aussi (HEVC temps réel).

**Ce qu'on a retiré, et pourquoi c'est un choix.** Le camouflage calculatrice
et les formulaires ODK ne sont plus dans Frappuccino. Notre pari est différent :
plutôt que *cacher* l'app, faire qu'une app **trouvée, ouverte et déverrouillée
n'ait rien à montrer**. Les deux postures se défendent ; elles ne protègent pas
contre la même fouille.

### 3.2 Signal - la coordination, pas l'archivage

Signal est une messagerie chiffrée remarquable, et rien ici ne suggère le
contraire : pour **communiquer**, c'est l'outil. Mais ce n'est pas un outil de
témoignage : la vidéo n'y part pas chiffrée *pendant* la captation ;
l'historique vit sur l'appareil, lisible si l'appareil est saisi déverrouillé ;
et si le téléphone est détruit ou confisqué, récupérer ses contenus n'est pas
son objet. Signal protège la conversation ; Frappuccino protège la **captation
et l'archive**. Sur le terrain, on a typiquement besoin des deux.

### 3.3 ProofMode - l'authenticité, notre complément naturel

ProofMode (Guardian Project / WITNESS) répond à la question symétrique de la
nôtre : non pas « comment mettre le témoignage à l'abri », mais « comment
prouver qu'il est authentique » - signatures cryptographiques, métadonnées de
capture, vérifiabilité. C'est précisément ce que Frappuccino **ne fait pas
aujourd'hui** : nos blobs prouvent leur intégrité et leur origine
cryptographique, pas leur valeur probatoire devant un tribunal. ProofMode, en
retour, ne fournit ni exfiltration temps réel, ni stockage E2E sur relais
aveugle, ni récupération souveraine. Les deux approches sont complémentaires -
une intégration de la provenance est un horizon envisageable, pas une promesse.

### 3.4 eyeWitness to Atrocities - la voie institutionnelle

eyeWitness (International Bar Association) capture avec métadonnées vérifiées
et transmet à une institution qui **conserve, certifie et peut témoigner** de
l'intégrité des éléments devant la justice. Pour construire un dossier
judiciaire avec un tiers de confiance, ce modèle est fort - plus fort que le
nôtre. Son revers est structurel : le serveur n'est pas aveugle (il *doit*
lire pour certifier), et la confiance comme la garde reposent sur
l'institution. Frappuccino fait le choix inverse : personne d'autre que le
témoin ne peut lire, personne n'a à être cru. Souveraineté contre force
probatoire institutionnelle : deux réponses à deux questions différentes.

### 3.5 Ce que Frappuccino ne prétend pas

La crédibilité d'un outil pour personnes en danger se joue dans cette liste
(détail : [`ARCHITECTURE_TECHNIQUE_COMPLETE.md` §10](ARCHITECTURE_TECHNIQUE_COMPLETE.md)) :

- **Le contenu est protégé ; le fait d'émettre ne l'est pas.** Volume, cadence
  et destination restent visibles : un adversaire en position réseau peut
  établir *que* quelqu'un streame. Frappuccino n'est ni un anonymiseur réseau ni
  une défense contre l'analyse de trafic. Le transport par défaut **obfusque le
  fil** (voir §5 : il rend le trafic inclassifiable comme protocole et le relais
  silencieux pour un sondeur), mais l'obfuscation n'est pas l'invisibilité. Le
  relais est joint par un **nom de domaine** ; sur le chemin de repli TLS direct
  (si l'UDP est bloqué), le *ClientHello* porte ce nom **en clair** (SNI), tandis
  que sur le chemin obfusqué il est masqué tant que l'UDP passe. Un adversaire
  qui bloque l'UDP/443 peut donc forcer le repli TLS direct, classifiable et
  porteur du SNI : c'est un **résidu assumé**, hors périmètre actuel (pas de mode
  *fail-closed*, Tor mesuré puis écarté pour la latence, la destination
  non-corrélable repoussée au serveur de production final). Nous le disons comme
  une **non-promesse**, pas comme un correctif à venir.
- **Un OS compromis au moment des faits voit ce que voit le capteur.** Le
  chiffrement commence en aval de la caméra ; aucune app ne peut rien contre un
  malware qui lit l'écran.
- **Pas de valeur probatoire judiciaire** au sens chaîne de custody (voir
  ProofMode / eyeWitness ci-dessus).
- **La phrase papier est un point de défaillance total assumé** : coercition
  sur la phrase = défaite complète ; phrase perdue = archives illisibles.
- **Android uniquement**, français/anglais, un seul relais de test à ce jour.
- **Pas encore audité par un tiers humain** - voir §5.

---

## 4. La méthode : la transparence comme antidote

Frappuccino est développé par un développeur solo avec une **IA (Claude) comme
pair de programmation principal** - y compris pour le code cryptographique et
les audits internes. C'est dit frontalement, parce que c'est la condition de la
confiance dans tout le reste.

Le risque est réel et nommé : une IA peut produire du code plausible et faux,
et sur-noter son propre travail. La parade structure tout le projet : **aucune
affirmation de sécurité ne repose sur le jugement d'une IA** - chaque propriété
importante est adossée à un oracle *non-IA*, déterministe et rejouable
(model-checkers, analyse du code compilé, mutation testing, fuzzing
différentiel), et les audits internes opposent des modèles distincts dont les
conclusions ne comptent que re-prouvées contre le code. Le threat model est
écrit noir sur blanc, les limites sont publiées avec le même soin que les
forces, et le code sera publié sous **AGPLv3** pour être attaqué.

Les outils de surveillance s'écrivent déjà avec des IA. *Ils s'en servent pour
surveiller. Nous nous en servons pour outiller la résistance* - et nous
publions de quoi vérifier que l'outillage tient.

---

## 5. Statut et trajectoire

**Field-test ready, candidat à l'audit - pas production-ready.** L'application
est validée en usage réel multi-jours sur plusieurs appareils, le relais de
test est opérationnel, et le dossier d'assurance (preuves formelles, runners
reproductibles, guide d'audit) est d'un niveau inhabituel pour un projet de
cette taille. Mais pour le threat model visé - saisie, Cellebrite, coercition -
le déploiement à haut risque attend encore : l'audit cryptographique externe
(Cure53 / Trail of Bits envisagés), la validation forensique on-device
systématique, une matrice d'appareils élargie et l'infrastructure de
production. Quiconque utilise Frappuccino aujourd'hui doit le faire en
connaissance de cet état.

Côté trajectoire récente : les secrets sensibles (le lot de clés du ratchet, la
clé maîtresse des rapports, la graine de provenance, la clé de session Argon2) ne
**traversent plus jamais** la frontière FFI - ils restent côté Rust derrière un
handle, scellés et descellés en un seul appel à l'intérieur du Rust ; et le jeton
d'accès à l'upload ne quitte plus le coffre natif, désormais actif **par défaut**,
avec un filet qui garantit qu'aucun chunk n'est perdu en cas de pépin du binding.
La robustesse réseau a une suite **validée par la mesure** : sur mauvais réseau
(forte perte de paquets, le quotidien du terrain), un transport QUIC à contrôle de
congestion BBR fait sortir le footage **×5 à ×15 plus vite** que la pile réseau par
défaut d'Android, confirmé on-device sur deux appareils. Cette même couche porte
désormais une **obfuscation du fil** (transform Salamander, proxy de-obfs déployé
sur le relais), **active par défaut en release** : elle rend le trafic
**inclassifiable comme protocole** (0 marqueur en clair, entropie maximale) et fait
du relais un port mort pour un sondeur sans la clé d'obfuscation, avec un repli
automatique vers le TLS direct si l'UDP est bloqué. Le relais est désormais joint
par un **nom de domaine** (certificat auto-signé épinglé par sa clé publique, avec
des pins de secours pré-chargés pour une rotation sans nouvelle livraison d'APK).
Honnêteté : cela achète l'inclassibilité, pas l'invisibilité - la destination est
une cible connue, le padding qui masquerait timing et volume est hors scope, et un
adversaire qui bloque l'UDP force le repli TLS direct (classifiable, SNI en clair) ;
un renfort réel, pas une promesse d'anonymat réseau (voir §3.5).

Le positionnement, lui, tient en trois lignes :

> **Pas « mieux que tout ». Une combinaison que rien d'autre n'offre, à notre
> connaissance : le témoignage vidéo qui quitte l'appareil pendant la capture,
> chiffré vers un relais incapable de le lire, dont le passé est hors d'atteinte
> de l'appareil lui-même - preuve formelle à l'appui - et dont la seule clé
> tient en 12 mots sur un papier, dans la poche du témoin.**
