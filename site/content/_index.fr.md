+++
title = "Frappuccino"
+++

**Shake. Document. Protect.** Frappuccino transforme un téléphone Android en émetteur de témoignages vidéo chiffrés de bout en bout : les images quittent l'appareil **pendant le tournage**, vers un relais qui **ne peut pas les lire**, et la seule clé capable de les déchiffrer un jour tient en **douze mots, sur papier**, dans la poche du témoin.

Saisir le téléphone, avant, pendant ou après l'enregistrement, ne donne plus rien à lire.

## En trente secondes

- **À quoi ça sert :** filmer une situation à risque quand le téléphone peut être saisi, fouillé ou détruit.
- **Comment :** la vidéo est découpée en fragments, chiffrée et envoyée *pendant* l'enregistrement, jamais laissée en clair sur l'appareil.
- **Le relais ne peut pas la lire** et ne journalise aucune adresse IP.
- **Le téléphone ne peut pas rouvrir le passé :** un fragment parti est hors de sa portée.
- **Une seule clé : douze mots sur papier,** détenus par le seul témoin. Personne, nous compris, ne peut la restaurer.
- **Où en est le projet :** prêt pour le test de terrain et l'audit, pas encore pour un usage où des vies en dépendent.

## Le problème

Un militant filme une violence. Une journaliste documente un site bouclé. Un avocat enregistre une arrestation. Trois choses surviennent souvent, dans cet ordre : le téléphone est **saisi**, le code PIN est **extorqué**, puis le matériel part en **extraction forensique** (Cellebrite, GrayKey). Pour qu'un témoignage survive à cela, trois propriétés doivent tenir en même temps :

1. **Survivre à la saisie et à l'effacement.** Le contenu doit exister ailleurs, récupérable par le seul témoin, même depuis un téléphone neuf : sans compte, sans cloud, sans tiers.
2. **Rester illisible pour le serveur.** Un relais saisi ou hostile ne doit avoir que des octets opaques à livrer.
3. **Tenir même si le téléphone est arraché en plein enregistrement.** Des images chiffrées « à la fin » ne protègent rien si la capture est interrompue par la force.

La réponse habituelle, chiffrer les fichiers sur l'appareil, convient mal : **un coffre, cela s'ouvre.** Par force brute, par contrainte, par une faille du système. Tant que les données et leur clé résident sur le téléphone, celui-ci reste le point unique de défaillance, et c'est précisément ce que l'adversaire tient. L'objectif n'est pas un meilleur coffre. C'est de **cesser d'être un coffre.**

## Pourquoi c'est différent

- **Les images quittent l'appareil pendant la capture.** L'enregistrement est découpé en fragments de 5 secondes, chacun chiffré de bout en bout sur l'appareil, puis envoyé aussitôt. Un téléphone arraché à la douzième minute laisse déjà les douze premières minutes hors d'atteinte.
- **Un relais aveugle, incapable de trahir.** Le serveur ne conserve que des blobs opaques, chiffrés vers une clé dont la moitié privée n'existe sur **aucune machine**. Il ne voit jamais une image et ne journalise aucune adresse IP.
- **Une clé souveraine : douze mots sur papier.** À l'enrôlement, l'appareil génère une phrase BIP-39, affichée une seule fois et jamais conservée. Aucun compte, aucune autorité (nous y compris) ne peut la réinitialiser.
- **Le passé est hors d'atteinte, et c'est démontré.** L'authentification repose sur un ratchet de clés à usage unique inspiré d'Algorand, chacune détruite juste après signature. Le mécanisme est prouvé en **Tamarin**, sa machine à états explorée exhaustivement en **TLA+**, et l'effacement des clés est contrôlé jusque dans le code compilé.
- **Cœur cryptographique 100 % Rust.** Des primitives publiques et éprouvées (Ed25519, X25519, XChaCha20-Poly1305, Argon2id, HKDF, rustls). La vidéo en clair ne transite jamais par la mémoire de la JVM.
- **TLS épinglé.** Un vérificateur réduit la confiance à l'empreinte de la clé du relais (un petit ensemble de clés, à temps constant, que nous contrôlons, pour qu'une rotation de certificat ou la reprise d'un relais saisi ne réclame pas de nouvelle application). Une interception, même munie d'un certificat valide signé par une autorité reconnue, est rejetée.
- **Un trafic d'envoi résistant au profilage.** Les fragments sont transmis en QUIC (HTTP/3), enveloppés dans une couche d'obfuscation Salamander qui masque chaque datagramme à l'aide d'une clé pré-partagée : pour une inspection approfondie des paquets, le flux n'expose aucun marqueur QUIC ou TLS exploitable. Si cette voie est ralentie ou bloquée, le client bascule de façon transparente vers le TLS épinglé, et les images continuent de partir. Validé sur le terrain, avec sa limite assumée : le trafic devient inclassable, non invisible (voir plus bas).

## Modèle de menace

| Si l'adversaire… | Alors… |
|---|---|
| Saisit le téléphone après l'enregistrement | Rien de lisible sur l'appareil ; les images sont sur le relais, chiffrées |
| Arrache le téléphone en plein enregistrement | Tout, jusqu'à quelques secondes avant l'arrachage, est déjà chiffré et hors de l'appareil |
| Extorque le code PIN | Au pire une capacité de signature **future** et bornée : pas un octet du contenu passé |
| Exécute Cellebrite ou GrayKey | Aucune clé de déchiffrement sur l'appareil ; l'état du ratchet est scellé sous Argon2id |
| Intercepte le réseau, même avec une autorité illégitime | Chiffrement XChaCha20-Poly1305 par blob, à l'intérieur d'un TLS épinglé sur la clé |
| Saisit le relais ou le détourne | Uniquement des blobs opaques et des clés pseudonymes : rien à lire, rien à divulguer |

Ce que Frappuccino **ne** protège **pas**, énoncé sans détour : le **fait d'émettre** reste visible. Sur le transport obfusqué, l'envoi est inclassable comme QUIC pour une inspection par signatures, mais il n'est pas invisible : le profil de tailles et de cadence ne change pas, et la destination est un relais connu. Quand cette voie est bloquée (UDP coupé), le client bascule vers le TLS épinglé, dont la poignée de main porte le **nom de domaine du relais en clair (SNI)** : un adversaire placé sur le réseau peut alors voir *qu'*une transmission a lieu et *vers où*. Frappuccino cache **qui** vous êtes et **ce que** vous filmez ; il ne promet pas de cacher **que** vous envoyez, ni **quand**, et ce **n'est pas un outil d'anonymisation réseau** (combinez-le à Tor ou un VPN si la métadonnée elle-même fait courir un risque). Un **système d'exploitation compromis au moment de la capture** voit ce que voit le capteur ; le projet n'offre **aucune chaîne de possession recevable en justice** (c'est le domaine de ProofMode et d'eyeWitness) ; et la **phrase sur papier est un point unique de défaillance totale, assumé comme tel**.

## Assurance

La confiance se vérifie, elle ne se déclare pas. Un système cryptographique peut échouer à trois niveaux : la conception, l'implémentation, le compilateur. Chacun est contrôlé par un outil dont le verdict ne dépend du jugement de personne, et chaque preuve s'accompagne d'un lanceur reproductible et d'un contrôle négatif.

| Couche | Outil | Résultat |
|---|---|---|
| Protocole face à un attaquant réseau actif | Tamarin (Dolev-Yao) | 10/10 lemmes + 2 contrôles négatifs |
| Machine à états du ratchet | TLA+/TLC | 2800 états explorés, 0 erreur |
| Analyse des entrées non fiables (le vrai code Rust) | Kani | parseurs prouvés sans panique |
| Frontière Kotlin/Rust | Fuzzing différentiel | 759/759 vecteurs identiques à l'octet près |
| Sortie du compilateur | Audit de l'IR LLVM | l'effacement du secret n'est jamais supprimé par le compilateur |
| Binaire expédié | manifest sha256 + garde de build | le `.so` crypto est lié à son commit et sa toolchain - pas de binaire substitué |

S'y ajoutent le test par mutation, le fuzzing (cargo-fuzz), le test fondé sur les propriétés, et des audits croisés entre IA distinctes, arbitrés par une re-vérification indépendante face au code. Cet ensemble prépare un audit humain externe ; il ne le remplace pas.

## Statut

**Prêt pour le test de terrain. Prêt pour l'audit. Pas prêt pour la production.**

- Validé en conditions réelles sur plusieurs jours, sur deux appareils de référence (l'un sur plateforme MediaTek, l'autre sur Snapdragon 8 Gen 3) ; le relais de test est opérationnel.
- **Aucun audit de sécurité externe à ce jour.** La suite de preuves et le dossier d'audit rendent le projet auditable ; un audit humain indépendant, de la classe de Cure53 ou Trail of Bits, est prévu mais pas encore réalisé.
- Une **campagne de validation forensique sur appareil a été menée** (mémoire, fichiers de plantage natif, système de fichiers après chaque scénario).
- Un seul relais de test, joint par un nom de domaine et épinglé à un petit ensemble de clés TLS que nous contrôlons (une rotation de clé ou la reprise d'un relais saisi ne réclame alors aucune mise à jour de l'application) ; **Android uniquement**, interface en français et en anglais.

> Si des vies dépendent de ces images aujourd'hui, Frappuccino ne doit pas en être l'unique ligne de défense. Les limites connues sont documentées avec le même soin que les fonctionnalités.

## Construit pour être vérifié

Le projet est développé par une seule personne, avec une IA pour binôme de programmation principal, y compris sur le code cryptographique et les audits internes. C'est annoncé d'emblée, car c'est la condition de la confiance accordée à tout le reste : **aucune affirmation de sécurité ne repose sur le jugement d'une IA.** Chaque propriété importante est ancrée à un oracle déterministe, rejouable et indépendant de l'IA, et le code est publié pour être attaqué.

Pour une analyse plus approfondie du problème, des choix de conception et de la place de Frappuccino parmi les outils existants (Tella, Signal, ProofMode, eyeWitness), voir la [page positionnement](@/positioning.fr.md).
