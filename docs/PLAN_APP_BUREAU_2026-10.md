# Plan : application de bureau de récupération (Windows et Ubuntu)

Octobre 2026. Remplace la conception de la Phase 9 de `ROADMAP.md` (Tauri, lecteur de l'OS,
clair en fichiers temporaires), écrite avant les rapports figés et le secours vérifié.

Méthode : deux relevés de faits sur le code (format réel des morceaux, surface Rust
réutilisable), trois architectures conçues indépendamment (Rust natif + egui + libmpv ; Tauri ;
Rust natif + iced + GStreamer), jugées par trois juges sur trois angles (sécurité, robustesse
produit, effort et maintenance). Les trois juges ont retenu la même architecture ; les
meilleures idées des deux autres y sont greffées, et leurs points bloquants deviennent le lot
préalable et les décisions de la section 8.

## 1. Ce que l'app doit faire

On entre la phrase de 12 mots, l'app retrouve les prises de vue, les vérifie, les montre et
les exporte. Exigences :

1. **Robuste et sûre, crypto en Rust** : elle réutilise `crypto-rs` (énumération, vérification
   des signatures 0x08 et de la clôture 0x09, déchiffrement STRM V3), pas une réimplémentation.
2. **Aucune trace de la phrase ni des clés à la fermeture** : ni sur disque, ni dans le swap, ni
   dans un vidage, ni dans le presse-papiers, ni dans un historique.
3. **Aperçu des vidéos** dans l'app.
4. **Une prise de vue = une vidéo** : les morceaux de 5 s sont regroupés par prise de vue,
   assemblés et présentés comme un tout.

Hors périmètre : enrôlement, envoi, enregistrement, macOS.

## 2. Faits qui contraignent la conception

Relevés dans le code ; « [à mesurer] » signale ce qui reste à confirmer sur de vrais morceaux.

- **Une prise de vue = un rapport** (un enregistreur par rapport). Objets `%06d.strm`, le seq 0
  est un JSON (`version`, `sessionId`, `startedAt`, `triggerMethod`, `chunkIntervalMs`). Le
  manifeste de clôture liste les seq dans l'ordre ; les trous sont possibles. Legacy :
  `<sid>_<seq>.strm`, regroupés par `sid` dans le rapport.
- **Chaque morceau est un MP4 autonome** (MediaMuxer, non fragmenté), encodeurs recréés à chaque
  morceau, donc une image clé au début de chaque morceau. Les horodatages repartent de 0.
- **Codecs** : HEVC si l'appareil a un encodeur matériel, sinon H.264 ; AAC-LC 48 kHz mono.
  Portrait natif (1080×1920, 720×1280, 480×854), sans métadonnée de rotation. Fréquence
  d'images variable (24-30).
- **Les paramètres changent au sein d'une prise** : un changement de qualité modifie résolution
  et débit, et un repli HEVC → H.264 puis un retour sont possibles. La durée d'un morceau n'est
  pas constante (changement de qualité, rotation ratée, dernier morceau).
- **L'audio est continu d'un morceau à l'autre** (aucun échantillon perdu à la rotation), mais
  réparti sur des encodeurs AAC distincts, chacun avec son amorçage [à mesurer].
- **`startedAt` est l'heure locale du téléphone suivie d'un `Z` littéral** : le fuseau réel est
  inconnu. Aucune heure de fin.
- **Le secours Rust existe** (`crypto-rs/ffi/src/rescue.rs`, partagé avec la CLI) mais vit dans
  le crate FFI et écrit sur disque ; il n'y a pas de récupération en mémoire ni de saisie de
  phrase sans chaîne de caractères.

### 2.1 Mesures du lot 0 (2026-10-25, une prise de test d'environ une minute, Seeker)

Faites avec ffprobe et ffmpeg sur les morceaux exportés (métadonnées et recollage d'essai
seulement, rien de copié ni de publié).

- **13 morceaux, et un changement de qualité dans la prise, pas un repli de codec.** Sur le
  relais, les morceaux 1 à 9 pèsent environ 1,5 Mo (720p HEVC), le morceau 10 s'arrête à 1,45 s
  et les morceaux 11 à 13 pèsent environ 3 Mo, la taille d'un morceau 1080p HEVC à 4 Mbit/s. Le
  morceau 10 a été coupé par le passage adaptatif de 720p à 1080p : une prise du 2026-10-26,
  journalisée de bout en bout sur le même téléphone, montre la même coupure et aucune erreur
  d'encodeur. Les fichiers exportés étudiés ici donnent pourtant les morceaux 11 à 13 en H.264
  720×1280 de 1,7 Mo : ils ont été convertis après l'export, hors de l'app, qui ne contient aucun
  encodeur en dehors de la capture. Ce qui suit sur ces trois morceaux décrit la conversion, pas
  l'app.
- **Paramètres d'encodage identiques à l'octet** d'un morceau à l'autre au sein d'une même
  configuration (`hvcC` des morceaux 1 à 10) ; configuration audio identique partout. Un seul
  descripteur d'échantillons par segment suffit.
- **Image clé au début de chaque morceau, aucune image B.**
- **Audio** : AAC-LC 48 kHz mono, amorçage non signalé (`initial_padding` 0), une liste
  d'édition par morceau. Chaque morceau a 70 à 130 ms d'audio de plus que de vidéo ; dans le
  premier, la vidéo ne démarre qu'à 0,92 s.
- **Métadonnées** : pas de `creation_time` ; une étiquette `com.android.version` (version
  d'Android du téléphone) dans chaque morceau, à retirer à l'export.
- **Recollage d'essai sans réencodage** (ffmpeg, démultiplexeur concat, copie) : le segment
  H.264 (converti) sort propre ; le segment HEVC garde ses 1 140 images, placées sur l'horloge de l'audio
  (aucune dérive : dernière image à 47,57 s pour 47,61 s d'audio), mais ffmpeg écrit un
  en-tête de piste faux (40,0 s annoncées pour 47,6 s d'échantillons). Conséquences : **le placement ancré sur l'audio est le bon** ; l'outil d'assemblage
  doit écrire ses propres en-têtes au lieu de s'en remettre à ffmpeg ; entre deux morceaux, la
  dernière image reste affichée 80 à 150 ms (l'audio est plus long), ce qui est sans perte.
- **Pas encore mesuré** : les morceaux bruts d'un changement de qualité (résolution), donc le
  cas à plusieurs descripteurs, pourtant le cas courant : les deux prises connues passent de
  720p à 1080p en cours de route ; la frontière audio à l'oreille (amorçage de chaque encodeur).

## 3. Architecture retenue

**Rust natif : iced 0.14 pour l'interface, GStreamer (gstreamer-rs 0.24) pour l'aperçu et
l'assemblage**, dans un workspace Cargo séparé `desktop/` (Cargo unifie les features par
graphe : un membre de `crypto-rs` qui activerait d'autres features changerait le `.so` Android).
Versions épinglées exactes ; toolchain 1.88 comme `crypto-rs`.

Pourquoi pas les deux autres :
- **Tauri** : la phrase passerait par des chaînes JavaScript et la mémoire d'une WebView, ni
  effaçables ni maîtrisables ; dernier des trois juges.
- **egui + libmpv** : solide (deuxième), mais le passage de libmpv à une source en mémoire
  demande de lever des protections de mpv, et l'assemblage reste à écrire à part. Plusieurs de
  ses idées sont reprises ci-dessous.

### 3.1 Deux processus

- **Le coffre** (sans interface) : reçoit les 12 indices de mots par un tube, dérive les clés,
  énumère, vérifie, déchiffre, re-scelle le clair sous une clé de session aléatoire, puis
  **se termine**. Les clés dérivées meurent avec le processus. Ni fenêtre, ni pilote GPU, ni
  clavier, ni presse-papiers ne partagent son espace d'adressage.
- **L'interface** : ne voit jamais la phrase en clair (seulement des indices, effacés après
  envoi), ni la graine, ni les clés. Elle reçoit la clé de session et le cache re-scellé, et
  fait tourner l'aperçu et l'export.
- Le protocole entre les deux est minimal et fuzzé. Sur la fin du tube, le coffre efface et
  sort ; sous Linux il meurt avec son parent (`PDEATHSIG`).

### 3.2 Flux

1. Saisie → 12 indices → coffre.
2. Coffre : phrase canonique transitoire → graine (PBKDF2) → clés de rapport et clé
   d'archive, dans une mémoire verrouillée ; la phrase et la graine sont effacées aussitôt.
3. Énumération (annuaire puis sondes), un 429 donne une attente d'au moins 60 s affichée.
4. Par rapport : clôture vérifiée, objets récupérés **en mémoire**, signature vérifiée **avant**
   déchiffrement, déchiffrement, re-scellement sous la clé de session dans un cache anonyme.
5. Fin de l'import : le coffre se termine. Badge « Phrase et clés effacées ».
6. Aperçu et export : uniquement depuis le cache re-scellé, jamais avec les clés dérivées
   vivantes.

## 4. Aucune trace de la phrase

| Canal | Mesure |
|---|---|
| Saisie | Grille de 12 cases maison, pas de champ texte : chaque frappe devient une lettre dans un tampon fixe, puis un index dès que le préfixe est unique (au plus 4 lettres pour les 2048 mots). Aucune `String`, aucune liste de suggestions, collage désactivé, l'app n'écrit jamais dans le presse-papiers, IME désactivé, affichage masqué par défaut. |
| Erreurs | « Mot 7 inconnu », « Un mot est faux ou mal placé » : jamais d'écho du mot. |
| Mémoire | Les secrets du coffre vivent dans des pages dédiées, alignées et verrouillées, exclues des vidages (`MADV_DONTDUMP`, exclusion WER) ; zéroïsation au drop ; allocateur global effaçant dans le coffre seulement. |
| Plantages | Linux : `PR_SET_DUMPABLE=0` et `RLIMIT_CORE=0`. Windows : rapports d'erreur sans tas, pas de boîte de plantage, mémoire secrète exclue. |
| Veille | Pendant l'import, mise en veille empêchée ; une veille ou une fin de session interrompt l'import et efface. |
| Disque | Le chiffré d'origine n'est jamais écrit. Le seul fichier temporaire est un cache anonyme re-scellé sous une clé qui ne vit qu'en RAM (effacement cryptographique, supprimé par le système à la fermeture, balayé au lancement suivant s'il reste après une coupure). Aucun fichier de réglages, aucun journal, aucune boîte de dialogue native (donc pas de listes « récents » de Windows ni de GTK), aucun nom de fichier tiré du relais. |
| Capture d'écran | Windows : fenêtre exclue des captures. Linux : impossible sous X11, un bandeau le dit. |
| Fermeture | « Effacer et quitter » toujours visible ; la croix, la fin de session et SIGTERM suivent la même séquence. |

**Vérifié par des tests, pas seulement affirmé** (en CI quand c'est possible, sinon au test
terrain, avec des contrôles négatifs) : aucune écriture hors du cache et de l'export (Process
Monitor, `strace -f`) ; aucune valeur de registre ; un vidage des deux processus après « clés
effacées » ne contient ni les mots d'une phrase de test, ni la graine, ni la clé d'archive.

**Ce qui reste hors de portée, et sera dit à l'utilisateur** : hibernation (copie toute la
RAM) ; clavier espion, logiciel malveillant administrateur ; X11 ; le **clair vidéo** (pas la
clé) qui passe par les tampons des décodeurs et peut aller dans le swap (recommander BitLocker,
LUKS ou Tails) ; traces d'usage du système (Prefetch, cache DNS). L'export est en clair, par
nature.

## 5. Une prise de vue, une vidéo

- **Regroupement** : un rapport chaîné = une prise de vue, dans l'ordre des seq vérifiés ; le
  seq 0 donne la date de début. Legacy : par `sid` à l'intérieur du rapport (le `sid` n'est
  jamais affiché).
- **Statut affiché en mots** : « Complète et certifiée », « Incomplète, n morceaux manquants »,
  « Interrompue, fin non certifiée », « Altérée, éléments étrangers exclus ».
- **Date** : « 14:03, heure du téléphone (fuseau inconnu) » ; période de réception par le relais
  dans Détails.
- **Assemblage (`ShotTimeline`, Rust pur, testé par propriétés)** : partagé par l'aperçu et
  l'export, pour que ce qui est exporté soit exactement ce qui a été vu.
  - Placement ancré sur l'audio (continu par construction) : pas de dérive cumulée, au pire
    quelques dizaines de ms de silence par frontière, supprimées si la mesure P0 confirme
    l'amorçage AAC.
  - Segments homogènes : un changement de qualité garde un seul fichier (plusieurs
    descriptions d'échantillons dans la même piste) si la matrice de compatibilité le permet,
    sinon un fichier par partie ; un changement de codec ouvre toujours une nouvelle partie.
  - **Trous** : aucune durée inventée ; repère rouge « n morceaux manquants, durée inconnue »
    sur la timeline et dans un `.srt` à côté de l'export.

## 6. Aperçu

- GStreamer alimenté **depuis la RAM** (`appsrc`) : jamais de clair sur disque pour l'aperçu.
- Une seule timeline par prise de vue (« 03:12 / 12:31 »), bandes de couleur par qualité,
  repères aux changements et aux trous, vignette au survol, recherche précise.
- Rendu dans iced par un widget vidéo (NV12 via wgpu), repli RGBA sans GPU.
- **Décodage logiciel par défaut** (moins exposé aux défauts des pilotes HEVC), matériel en
  option, repli automatique en cas d'erreur ; liste blanche de plugins vérifiée au démarrage,
  aucun plugin de l'utilisateur chargé.
- Les objets **non vérifiés ne sont jamais donnés aux décodeurs** : ils ne sortent qu'en export
  brut, à part, avec un avertissement.
- Les vignettes et l'aperçu ne démarrent qu'après la fin du coffre.

## 7. Export

- Feuille d'export avec un sélecteur de destination intégré (lecteurs amovibles d'abord), et
  un avertissement : les vidéos exportées sont en clair, choisir un support chiffré.
- **« Original » (par défaut)** : sans réencodage, un fichier par prise de vue
  (`prise-01.mp4`, ou `prise-01-partie-N.mp4` si le codec change). Métadonnées nettoyées :
  dates à zéro, pas de `udta`, ni de champ fabricant, ni de SEI propre au fabricant si P0 en
  trouve. Le fichier écrit est relu et comparé au modèle avant d'être annoncé prêt.
- **« Preuve » (cochée par défaut)** : les morceaux déchiffrés exacts, numérotés par seq avec
  les trous visibles, `SHA256SUMS`, `verification.json` (statut, clôture, seq vérifiés et
  manquants, empreintes) et un `LISEZMOI`. Jamais d'identifiant de rapport.
- « Compatible » (réencodage H.264 lisible partout) : reporté en v1.1.
- Écriture atomique (`.part`, synchronisation, renommage). L'app n'ouvre jamais l'explorateur
  (vignettes).

## 8. Décisions à prendre avant de coder

| # | Question | Recommandation |
|---|---|---|
| D1 | Un processus avec typestate, ou un coffre séparé qui se termine après l'import ? | Coffre séparé (3.1) : la disparition des clés devient une garantie du système, pas seulement du code. |
| D2 | Windows : embarquer les décodeurs logiciels FFmpeg (LGPL, via gst-libav), ou matériel seul ? | Embarquer : lecture garantie sur toute machine et décodage logiciel par défaut ; licence LGPL respectée (liaison dynamique, sources exactes) ; l'exposition aux brevets HEVC/H.264/AAC est à assumer et documenter, comme le font les lecteurs libres. |
| D3 | Mode Tor (SOCKS5 avec DNS distant) dès la v1 ? | Oui, en option par session : sans lui, le relais voit l'IP du poste lire tous les rapports du témoin. |
| D4 | Accessibilité : iced n'a pas de lecteur d'écran. | L'accepter en v1 (l'absence d'arbre d'accessibilité ferme aussi un canal de fuite) ; option « lire les lettres » plus tard. Sinon egui avec AccessKit, au prix d'un toolchain plus récent. |
| D5 | Signature Windows : Smart App Control peut bloquer une app non signée. | Demander SignPath Foundation (certificat au nom de la fondation, pas d'identité civile) ; en attendant, v1 non signée avec minisign et attestations GitHub. |
| D6 | Archives V1/V2 (avant STRM V3) | Hors de l'app, renvoi vers la CLI ; le TTL de 6 mois les fait disparaître. |

**Décidé le 2026-10-25 par le mainteneur** : D1 coffre séparé ; D2 décodeurs logiciels
embarqués ; D3 Tor en option, à activer par session ; D4 iced sans lecteur d'écran en v1
(l'app sert à récupérer des vidéos que la personne a elle-même filmées). D5 et D6 : les
recommandations s'appliquent sauf avis contraire.

## 9. Travaux et lots

| Lot | Contenu | Effort |
|---|---|---|
| **0. Mesures et prototypes** | Sur de vrais morceaux déchiffrés du Seeker et du OnePlus (ffprobe, gst-discoverer) : profil, `hvc1`/`hev1`, B-frames, `hvcC` identiques ou non, amorçage AAC, bandes noires, `udta`, `creation_time`. Prototypes : GStreamer depuis la RAM sous Windows et Ubuntu, matrice de compatibilité multi-descriptions (VLC, Films et TV, navigateurs, Android), décodage HEVC sans l'extension du Store, repli logiciel sur erreur injectée, IME réellement désactivé, `PR_SET_DUMPABLE` face à apport, exclusion WER. **Bloque les lots 4 et 5.** | 3-4 j |
| **1. Préalables dans `crypto-rs`** | Crate `frappuccino-rescue` extrait du FFI (sans `unsafe`, sans UniFFI, UDL inchangé) avec récupération et vérification de clôture **en mémoire** ; BIP-39 par indices (phrase canonique NFKD jusqu'à 155 octets, KAT d'équivalence et propriétés) ; erreurs bip39 sans écho et `decrypt_chunked` en place ; mémoire secrète à pages dédiées corrigée ; profil de relais au moment du build (le déménagement UE impose des versions bureau et Android synchronisées). Touche le chemin Android : `.so` 3 ABI, manifeste de provenance, parité, test terrain. Ratchet non touché. | 5-7 j |
| **2. Squelette** | Workspace `desktop/`, module plateforme (seul `unsafe`, justifié appel par appel), coffre et protocole, CI Windows + Ubuntu, `cargo deny`/`audit`, scan de fuites étendu aux **binaires** (chemins de build, PDB). | 3 j |
| **3. Saisie et import** | Grille de phrase, empreinte de l'archive affichée après ouverture (même format que le téléphone, pour vérifier la phrase), énumération, vérification, cache re-scellé, compte à rebours 429, option Tor. | 6 j |
| **4. Timeline et aperçu** | Lecteur de tables MP4 fuzzé, `ShotTimeline`, pipelines GStreamer, widget vidéo, timeline unique avec trous et changements. | 8 j |
| **5. Export** | Original, Preuve, nettoyage des métadonnées, relecture de contrôle, sélecteur intégré. | 5 j |
| **6. Durcissement et invariants** | Tests « aucune trace » (écritures, registre, vidages) avec contrôles négatifs ; veille, fin de session, plantage. | 3 j |
| **7. Paquets** | Windows : ZIP portable avec runtime GStreamer officiel vérifié (signature, SHA-256 épinglé) réduit à une liste blanche. Ubuntu : `.deb` (24.04 et 26.04) qui s'appuie sur le GStreamer de la distribution. Builds reproductibles, notice LGPL, signatures. | 4 j |
| **8. Docs et test réel** | Guide utilisateur (précautions, Tails, support chiffré), notes pour l'auditeur, remplacement de la Phase 9 de la ROADMAP, résidus ; test avec une personne non technicienne sur Windows et Ubuntu. | 3 j |
| **9. Revue adverse** | Revue multi-agents du lot complet, puis cadrage d'une ré-audit externe (iced, wgpu, GStreamer élargissent la surface). | 2 j |

**Total : environ 42 à 45 jours** pour un développeur seul, dont 8 à 11 de préalables
(lots 0 et 1) qui servent aussi l'app Android.

## 10. Risques principaux

- Les mesures P0 peuvent changer le format d'export (paramètres qui diffèrent à l'octet, amorçage
  AAC non signalé) : d'où le lot 0 avant toute timeline.
- Lisibilité de l'export HEVC : le lecteur intégré de Windows exige une extension payante ;
  VLC recommandé, export « Compatible » en v1.1.
- Brevets et signature Windows (D2, D5) : sujets juridiques et de distribution, pas techniques.
- Surface d'audit élargie (iced, wgpu, GStreamer, FFmpeg) : les décodeurs ne reçoivent que du
  clair authentifié (signature vérifiée avant déchiffrement), ce qui borne l'exposition sans
  l'annuler.
- Volume : une session réelle peut faire plusieurs Go ; le cache est sur disque et chiffré,
  l'espace est vérifié avant l'import, et le relais limite le débit (import long, affiché).
