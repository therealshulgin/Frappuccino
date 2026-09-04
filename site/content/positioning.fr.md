+++
title = "Positionnement"
description = "Le problème auquel répond Frappuccino, comment il y répond, et où il se situe parmi les outils existants : Tella, Signal, ProofMode, eyeWitness."
+++

> **De quoi il s'agit :** le problème auquel répond Frappuccino, la manière dont il y répond, et sa place parmi les outils existants. Le registre est celui de tout le projet : la transparence sur ce que l'outil fait, ce qu'il ne fait pas, et ce que les autres réussissent mieux. Là où cette page et le code divergent, **le code fait foi.**

## En une phrase

**Frappuccino transforme un téléphone Android en émetteur de témoignages vidéo chiffrés : la vidéo part pendant le tournage, vers un relais qui ne peut pas la lire, et la seule clé tient en douze mots écrits sur papier.** Saisir le téléphone, avant, pendant ou après l'enregistrement, ne donne plus rien à lire.

## 1. Le problème

Un militant filme une violence. Une journaliste documente un site bouclé. Un avocat enregistre une arrestation. Trois choses peuvent leur arriver, souvent dans cet ordre : le **téléphone est saisi** (point de contrôle, frontière, garde à vue, ou arraché en pleine capture) ; le **code PIN est extorqué** ; puis le matériel part en **extraction forensique** (Cellebrite, GrayKey : stockage cloné, coffres locaux cassés hors ligne par force brute). À l'autre bout de la chaîne, le serveur qui reçoit les images est lui-même une cible : saisie légale, intrusion, opérateur déloyal. Et entre les deux, le réseau peut être intercepté.

Pour qu'un témoignage survive à ce scénario, trois exigences doivent tenir **en même temps** :

- **(a) Survivre à la saisie et à l'effacement de l'appareil.** Le contenu doit exister ailleurs que sur le téléphone et rester récupérable par le témoin, y compris depuis un appareil neuf, sans compte, sans cloud, sans tiers.
- **(b) Être illisible pour le serveur.** Si le relais est saisi ou hostile, il ne doit avoir que des octets opaques à livrer. Un serveur ne peut pas trahir ce qu'il ne peut pas lire.
- **(c) Tenir même si le téléphone est arraché en plein enregistrement.** Un fichier local chiffré « à la fin » ne protège rien si la capture est interrompue par la force. La vidéo doit quitter l'appareil au fil de la capture, déjà chiffrée.

La réponse habituelle, chiffrer les fichiers sur l'appareil, convient mal : **un coffre, cela s'ouvre.** En cassant le code par force brute, en contraignant son détenteur, en exploitant le système. Tant que les données et la clé de lecture résident sur le téléphone, celui-ci reste le point unique de défaillance, et c'est précisément ce que l'adversaire tient. Il ne s'agit pas de mieux verrouiller le coffre. Il s'agit de **cesser d'être un coffre.**

## 2. Notre réponse

> *« Le téléphone est un émetteur. Pas un coffre-fort. »*

Frappuccino est un fork de Tella FOSS (Horizontal.org) : la base de documentation Android pour militants est conservée ; le cœur (cryptographie, capture, transport, modèle de confiance) est remplacé. Cinq choix structurent la réponse.

- **La vidéo part pendant le tournage.** L'enregistrement est découpé en fragments de 5 secondes, chacun chiffré de bout en bout **sur l'appareil**, puis envoyé aussitôt. Un téléphone arraché à la douzième minute laisse déjà les douze premières minutes hors d'atteinte. La chaîne de capture est pensée pour le terrain : **HEVC** matériel (environ 35 à 45 % de débit en moins que H.264, repli H.264 automatique), qualité adaptée au réseau, une file d'envoi **persistante** qui survit à la perte de réseau, au redémarrage et à l'arrêt du processus, l'enregistrement écran éteint, le déclenchement par secousse, un écran noir furtif accessible d'un geste. Les envois passent en QUIC (HTTP/3) enveloppé dans une couche d'obfuscation Salamander, avec un repli transparent vers le TLS épinglé : le flux résiste au profilage et continue d'avancer sur un réseau dégradé ou hostile.
- **Un relais incapable de trahir : le serveur aveugle.** Il ne conserve que des **blobs opaques**, chiffrés avant de quitter l'appareil vers une clé dont la moitié privée n'existe sur **aucune machine**. Il vérifie des signatures, applique l'anti-rejeu, stocke et renvoie des octets ; il ne voit jamais une image et ne journalise aucune IP. La saisie du serveur est un **postulat de conception, pas un mode de défaillance**, et l'opérateur, nous y compris, est traité comme potentiellement hostile.
- **La clé n'est pas dans le téléphone : douze mots sur papier.** À l'enrôlement, l'appareil génère une phrase BIP-39 de 12 mots, affichée une seule fois, jamais conservée : la **clé souveraine**. Téléphone saisi, détruit, effacé ? Sur un appareil neuf : mode archive, saisie des douze mots, « récupérer mes flux ». Aucune autorité, nous y compris, ne peut la restaurer ni la réinitialiser. Un treizième mot facultatif dérive une identité distincte. Le revers, sans détour : **qui détient la phrase détient tout**, et une phrase perdue rend les archives définitivement illisibles.
- **Le passé est hors d'atteinte, et c'est prouvé.** Après l'enrôlement, le téléphone peut chiffrer et signer, mais ne peut **jamais déchiffrer son propre passé**. La clé de lecture X25519 n'est jamais sur l'appareil ; l'authentification utilise un **ratchet de clés éphémères** inspiré de la sécurité prospective d'Algorand : des lots de 50 clés de signature à usage unique, chacune détruite juste après usage, chaque lot authentifié par le précédent jusqu'à l'identité d'origine. Un adversaire muni du téléphone, du PIN et d'une copie de la mémoire obtient au pire quelques signatures **futures** et bornées, jamais un octet du contenu passé. Cette sécurité prospective est prouvée en **Tamarin** (Dolev-Yao), la machine à états est vérifiée par exploration exhaustive en **TLA+/TLC**, et l'effacement des clés est contrôlé au niveau du **code compilé (IR LLVM)**.
- **La confiance se vérifie, elle ne se déclare pas.** Toute la cryptographie sensible est en **Rust** (zéro `unsafe` hors d'un seul module mémoire isolé et commenté, dépendances figées à la version exacte, secrets qui s'effacent d'eux-mêmes) : pas de primitive maison, seulement des briques publiques éprouvées, assemblées par une logique de protocole, et c'est cette logique que nous faisons vérifier, avec un lanceur reproductible et un contrôle négatif pour chaque preuve.

## 3. À côté des autres outils

Aucun des outils ci-dessous n'est un adversaire : plusieurs sont **complémentaires**, et chacun fait mieux que Frappuccino sur son propre terrain. Le tableau situe la combinaison ; les notes apportent la nuance.

| Capacité | Frappuccino | Tella | Signal | ProofMode | eyeWitness |
|---|---|---|---|---|---|
| Conçu pour le témoignage vidéo de terrain | **Oui** | Oui | Non (messagerie) | Oui (photo/vidéo) | Oui |
| Le contenu quitte l'appareil **pendant** la capture, chiffré | **Oui** | Non (envoyé après) | Non | Non | Non (envoyé après capture) |
| Serveur structurellement incapable de lire (relais aveugle) | **Oui** | Non¹ | S.O.² | S.O. | Non (l'institution lit, c'est sa fonction) |
| Appareil saisi : rien de lisible localement | **Oui** | Partiel (coffre local = cible) | Partiel | Non | Partiel (après envoi) |
| Appareil compromis : le passé reste illisible (sécurité prospective) | **Oui, prouvé formellement** | Non | Oui (messages) | S.O. | Non documenté³ |
| Récupération souveraine sans tiers (phrase de 12 mots) | **Oui** | Non | Non | Non | Non (via l'institution) |
| Authenticité et chaîne de possession pour un tribunal | **Non (hors objectif)** | Partiel (métadonnées) | Non | **Oui** | **Oui** |
| Maturité, communauté, audits externes | **Pas encore** | Oui | Oui | Oui | Oui |

¹ Le serveur de destination (Tella Web, Uwazi) reçoit et lit les rapports, par conception ; il est opéré par l'organisation du militant.
² Signal ne stocke pas le contenu côté serveur ; il n'offre tout simplement pas de fonction d'archivage.
³ À notre connaissance ; modèle de confiance institutionnel, code non public.

**Tella : l'amont, et ce que nous lui devons.** Une application de documentation éprouvée sur le terrain, signée Horizontal, traduite en 17 langues, sur Android, iOS et F-Droid : coffre chiffré local, camouflage de l'application, collecte structurée (formulaires ODK) vers les serveurs d'une organisation. Pour une ONG qui coordonne une collecte avec son propre serveur, **Tella reste le bon outil**, et son périmètre (iOS, formulaires, multilingue) dépasse le nôtre. Frappuccino inverse le modèle : diffusion chiffrée en temps réel vers un relais aveugle, rien de lisible laissé sur l'appareil, récupération par les douze mots. Le camouflage en calculatrice et les formulaires ODK ont d'ailleurs été **retirés** à dessein : le pari est différent. Plutôt que de *cacher* l'application, en proposer une qui, trouvée, ouverte et déverrouillée, **n'a rien à montrer.**

**Signal : la coordination, pas l'archivage.** Une messagerie chiffrée remarquable : pour **communiquer**, c'est l'outil. Mais la vidéo n'en sort pas chiffrée *pendant* la capture, l'historique vit sur l'appareil, et récupérer le contenu d'un téléphone détruit ou confisqué n'est pas son objet. Signal protège la conversation ; Frappuccino protège la **capture et l'archive.** Sur le terrain, les deux sont généralement nécessaires.

**ProofMode : l'authenticité, notre complément naturel.** ProofMode (Guardian Project / WITNESS) répond à la question symétrique : non pas « comment mettre un témoignage hors d'atteinte », mais « comment prouver qu'il est authentique » : signatures cryptographiques, métadonnées de capture, vérifiabilité. C'est précisément ce que Frappuccino **ne fait pas** aujourd'hui. Les deux approches sont complémentaires ; une intégration de provenance est un horizon envisageable, pas une promesse.

**eyeWitness to Atrocities : la voie institutionnelle.** eyeWitness (International Bar Association) capture avec des métadonnées vérifiées et transmet à une institution qui **conserve, certifie et peut attester** de l'intégrité devant un tribunal. Pour bâtir un dossier judiciaire avec un tiers de confiance, ce modèle est solide, plus solide que le nôtre. Son revers est structurel : le serveur n'est pas aveugle (il *doit* lire pour certifier), et la confiance repose sur l'institution. Frappuccino fait le choix inverse : personne d'autre que le témoin ne peut lire, et il n'y a personne à qui faire confiance.

## 4. Ce que Frappuccino ne prétend pas

La crédibilité d'un outil destiné à des personnes exposées se joue dans cette liste (détail dans le document d'architecture, sections 2 et 10) :

- **Le contenu est protégé ; le fait d'émettre ne l'est pas.** Les tailles, la cadence et la destination visibles par l'opérateur permettent à un adversaire placé sur le réseau d'établir *qu'*une transmission a lieu. L'application embarque bien un transport obfusqué (QUIC enveloppé en Salamander, validé sur le terrain) qui rend l'envoi inclassable comme QUIC face à une inspection par signatures, mais cela le rend inclassable sans le rendre invisible : le profil de tailles et de cadence ne change pas. Quand l'UDP est bloqué, le client bascule vers le TLS épinglé, dont la poignée de main porte désormais le **nom de domaine du relais en clair (SNI)** : sur cette voie, *qu'*une transmission a lieu et *vers où* deviennent visibles. Frappuccino cache **qui** et **quoi**, pas nécessairement **que** ni **quand** ; ce n'est pas un outil d'anonymisation réseau, et un adversaire capable de bloquer l'UDP/443 peut forcer le repli TLS classable (et son SNI) : un résidu assumé, pas un correctif à venir. Lorsque la métadonnée elle-même fait courir un risque, il se combine à une couche réseau adaptée (Tor, VPN).
- **Un système d'exploitation compromis au moment de la capture voit ce que voit le capteur.** Le chiffrement commence en aval de la caméra ; aucune application ne peut vaincre un logiciel malveillant qui lit l'écran.
- **Aucune chaîne de possession recevable en justice** (voir ProofMode et eyeWitness ci-dessus).
- **La phrase sur papier est un point unique de défaillance totale, assumé comme tel :** la contrainte exercée sur la phrase est une défaite complète ; une phrase perdue rend les archives illisibles.
- **Android uniquement**, français et anglais, un seul relais de test à ce jour (joint par un domaine, épinglé à un petit ensemble de clés que nous contrôlons).
- **Pas encore audité par un tiers humain externe.**

## 5. Statut et trajectoire

**Prêt pour le test de terrain, prêt pour l'audit, pas prêt pour la production.** Validé en conditions réelles sur plusieurs jours, sur plusieurs appareils, avec un relais de test opérationnel et un dossier d'assurance (preuves formelles, lanceurs reproductibles, guide pour auditeur) inhabituel pour un projet de cette taille. Mais pour le modèle de menace visé (saisie, Cellebrite, contrainte), un déploiement à haut risque attend encore l'audit cryptographique externe, l'élargissement du parc d'appareils testés et une infrastructure de production.

Le positionnement lui-même tient en trois lignes :

> **Non pas « mieux que tout », mais une combinaison que rien d'autre n'offre, à notre connaissance : un témoignage vidéo qui quitte l'appareil pendant la capture, chiffré vers un relais incapable de le lire, dont le passé est hors d'atteinte de l'appareil lui-même, preuve formelle à l'appui, et dont la seule clé tient en douze mots sur un bout de papier, dans la poche du témoin.**

## Note personnelle

*Au-delà de Frappuccino, la question du futur des I.A. et l'asymétrie des forces et des pouvoirs, des exploités et des trillionnaires. Les I.A. sont des outils aux atours culturels particuliers et aux conséquences humaines et environnementales certaines. Elles rendent leur adoption plus naturelle au sein des milieux tech et des obédiences libérales. Pourtant, les I.A. sont aussi des outils et plus encore, ce sont des armes. Avec ces outils, j'ai décidé de voir jusqu'où je pouvais aller et si, avec un peu de chance et beaucoup de patience, je pouvais rendre un code disponible, libre, gratuit, prêt à être audité et suffisamment solide pour que d'autres puissent le rendre meilleur et utile à tous.*
