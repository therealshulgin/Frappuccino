# Étude : hébergement du stockage hors de nos serveurs (split S3, coûts, juridiction)

> **Statut** : étude de travail, pas un canon. Question posée par therealshulgin (2026-07-09) :
> comment réduire le coût serveur sans casser le motto ? Cloud perso de l'utilisateur ?
> **Méthode** : recherche multi-agents avec prix fetchés LIVE le 2026-07-09 quand
> possible ; chaque chiffre porte son statut (**LIVE** = page officielle fetchée,
> **search** = recoupé par plusieurs sources de recherche, **NV** = non vérifié).
> Faits code re-vérifiés contre le repo (le code fait foi). 3 fiches manquantes
> pour cause de limite de session (Exoscale/Infomaniak, iDrive, Contabo) : voir §10.
> Devise : telle que publiée ($ ou € HT), pas de conversion inventée.
>
> **DÉCISION DU MAINTENEUR (2026-07-09, le jour même) : actée.** « Vultr est vraiment
> temporaire » : l'option 2 (déménagement cohérent relais + stockage EU)
> **s'exécute au moment du test fermé**. Le choix du fournisseur précis reste
> ouvert (candidat n°1 Hetzner) ; prérequis avant bascule = §2 + relire les ToS
> + re-confirmer les prix. Le block storage Vultr est rétrogradé en filet de
> secours si le disque sature avant.

## 0. TL;DR

Le cloud perso de l'utilisateur (Drive/Dropbox) est **exclu** : trois ruptures du
motto (§1). En revanche l'intuition « E2E ⇒ stockage untrusted » est exacte et le
code est déjà prêt : **pointer le relais vers un S3 externe = pure config** (§2).
Trois faits changent la donne :

1. **MinIO est mort comme logiciel libre** (repo archivé, dernier binaire oct. 2025
   = correctif CVE critique, plus aucun patch à venir). Pas d'urgence (loopback-only,
   image épinglée, blobs E2E), mais on ne bâtit rien de neuf dessus. §3.
2. **La juridiction du stockage compte peu** (blobs E2E sans identité : aucun régime
   ne peut contraindre à déchiffrer). Elle compte pour la **disponibilité** (ToS,
   saisie de compte) et surtout pour **le relais lui-même**, qui est aujourd'hui
   chez un hébergeur US (Vultr, CLOUD Act) : c'est là que vit le vrai risque
   juridique (précédent Proton 2021 : ordre de logging prospectif). §7.
3. Le stockage objet EU sans parent US coûte **€5-8/To/mois** (Hetzner ~€5,
   OVH ~€7,3, Scaleway ~€8) contre $25/To pour le block storage Vultr prévu. §5-6.

**Recommandation** (§9) : au moment du test fermé / 8.2.5, déménager le relais vers
un hébergeur EU sans parent US (Hetzner/Scaleway/OVH ; le runbook de migration
existe déjà) et brancher le stockage sur un S3 externe EU, ce qui retire MinIO du
chemin d'écriture. Donations en complément à 8.2.5. Fédération (les orgs hébergent
leur relais) = la vraie réponse à l'échelle, post-audit. En attendant, le block
storage Vultr déjà planifié reste le geste minimal si le disque presse avant.

## 1. Pourquoi pas le cloud personnel de l'utilisateur

Écarté pour trois ruptures d'architecture, pas pour l'image :

1. **« Ni identité »** : un compte cloud EST une identité (email, paiement, IPs).
   Une réquisition chez le fournisseur donne qui/quand/combien.
2. **« La saisie n'expose rien »** : le token OAuth vit sur le téléphone ; PIN
   extorqué = l'adversaire peut **supprimer les preuves**. Notre write-once sans
   route DELETE (`server/app/storage.py:22`) ne peut pas exister contre les
   credentials du propriétaire.
3. **Le relais n'est pas un seau** : enrollment, vérification des slots ratchet à
   chaque upload, anti-rejeu, 401 byte-identique. Drive ne vérifie rien.

La seule variante défendable est le cloud de l'**organisation réceptrice** : c'est
la fédération (§9, option 3).

## 2. Faits code : le split est déjà presque pluggable (vérifié dans le repo)

- **Client S3 générique** : `Minio(config.MINIO_ENDPOINT, access_key, secret_key,
  secure)` (`storage.py:73-78`), 4 variables d'env (`config.py:7-11`). **7 verbes
  S3 seulement** dans tout le serveur : `put_object`, `stat_object`, `get_object`,
  `list_objects`, `remove_object`, `bucket_exists`, `make_bucket`. Aucune API
  admin MinIO, aucun header SSE, pas de multipart (PUT à longueur exacte, choix
  documenté pour l'idempotence), pas de presigned URL, pas de requête
  conditionnelle.
- **Write-once portable** : HEAD + SHA-256 des octets relus (`storage.py:163-194`),
  volontairement indépendant des ETags. Coût : 1 HEAD par PUT chez le fournisseur.
- **TTL 6 mois côté app** : sweep horaire LIST + `remove_object`
  (`blob_cleanup.py`), portable partout ; le lifecycle provider peut s'y ajouter
  mais rien ne l'exige.
- **SSE-KMS n'est PAS dans le repo** : aucun `MINIO_KMS_*` dans le compose (l'audit
  du 2026-06-26 le notait déjà). Si le relais live en a, c'est dans le `.env`
  serveur hors repo. Conséquence : un fournisseur externe s'appuie sur son propre
  chiffrement at-rest, et nos blobs sont E2E de toute façon.
- **ROADMAP §10.8 charte déjà ce split** (« B2/R2/Wasabi/self-MinIO = changement
  d'endpoint/config », effort « Faible »).

**Adaptations nécessaires avant bascule** (petites, pas des rustines) :

| # | Adaptation | Pourquoi |
|---|---|---|
| 1 | Étendre `_DISK_FULL_CODES` (`storage.py:41-47`) aux codes quota du fournisseur choisi | Sinon un quota plein part en 500 générique au lieu du 507 qui ouvre le circuit-breaker client |
| 2 | Pré-créer le bucket + clé scoped bucket-only | `make_bucket` au démarrage crash si la clé n'a pas CreateBucket ; et on ne donne pas une clé root à un tiers |
| 3 | `MINIO_ENDPOINT` externe + `MINIO_SECURE=true` | Format host:port sans schéma (convention minio-py) |
| 4 | Test d'intégration minio-py contre l'endpoint réel (HEAD/PUT/GET/LIST/DELETE, write-once, latence) | Obligatoire avant toute bascule ; les quirks S3 se voient à l'usage |
| 5 | Vérifier la maintenance du client `minio-py` (7.2.12 épinglé) | MinIO Inc a abandonné le serveur ; le client Python peut suivre. Fallback : boto3 |

Latence hot path : chaque chunk = 1 HEAD + 1 PUT sur WAN (~10-30 ms intra-EU),
négligeable devant la cadence de rotation 5 s.

## 3. Découverte structurante : MinIO est EOL (vérifié live sur GitHub)

- Repo `minio/minio` **archivé** (`archived:true` via l'API GitHub), README « THIS
  REPOSITORY IS NO LONGER MAINTAINED ». Console communautaire vidée (fév-juin 2025),
  mode maintenance (déc. 2025), distribution binaire stoppée.
- Dernière release : `RELEASE.2025-10-15`, elle-même un correctif de **CVE critique**
  (élévation de privilèges STS/service accounts). Toute CVE postérieure ne sera
  jamais corrigée.
- Notre exposition est amortie : MinIO loopback-only derrière le relais, image
  digest-pinnée (B4), blobs E2E. **Pas d'urgence, mais interdiction de bâtir du
  neuf dessus** (le tiering ILM vers un S3 distant existe encore dans la dernière
  release communautaire, mais s'en servir = approfondir la dépendance à du code mort).
- **Remplaçant crédible : Garage** (asso française Deuxfleurs, AGPL, financé
  NLnet/NGI, **Rust**) : couvre exactement nos 5 opérations + lifecycle Expiration
  (notre TTL), v2.3.0 (avr. 2026) a un mode single-node auto-configuré. Perd
  SSE-KMS (acceptable : E2E) ; provisioning à réécrire (clés par bucket). Fallback
  si on dépasse le single-node : SeaweedFS (Apache 2.0, très actif, plus lourd).
- Alignement narratif non négligeable : Garage est financé par NLnet, à qui on
  demande un grant.

Note : **le split S3 externe retire aussi MinIO** (le relais parle directement au
fournisseur ; plus de serveur objet chez nous du tout). Deux sorties possibles du
même problème.

## 4. Modèle de volume (constantes lues dans le code, terrain à l'appui)

- FHD 1080p : 4 Mbps vidéo + 96 kbps audio (`StreamQuality.kt:40-47`), ~1,84 Go/h
  nominal, **~2,0 Go/h observé terrain** (2,8 Mo/chunk moyen sur 2284 blobs,
  ROADMAP:130).
- HD 720p (défaut) : 2 Mbps, **~0,94-1,2 Go/h**. SD : ~0,5 Go/h.
- Chunks de 5 s (~1,7-2,8 Mo), soit 720 PUT+HEAD par heure d'enregistrement.
  Surcoût chiffrement STRM : <0,01 %.
- Stock permanent = ingest mensuel × 6 (TTL 6 mois).

| Scénario | Hypothèse | Ingest/mois | Stock permanent (TTL 6 mois) |
|---|---|---|---|
| S1 : test fermé 15 volontaires | 2 h/mois/pers., HD-FHD | 36-60 Go | **~0,2-0,4 To** |
| S2 : 100 utilisateurs | 2 h/mois/pers. | 240-400 Go | **~1,4-2,4 To** |
| S3 : 1000 utilisateurs | 2 h/mois/pers. | 2,4-4 To | **~14-24 To** |

Un mois d'événement (usage intensif) peut doubler ponctuellement l'ingest ; le
stock suit avec 6 mois d'inertie.

## 5. Fiches fournisseurs (prix au 2026-07-09, devise telle que publiée)

| Fournisseur | Stockage /To/mois | Egress | Minimums | Lifecycle TTL | Juridiction | Statut prix |
|---|---|---|---|---|---|---|
| **Hetzner Object Storage** | base **€4,99/mois (1 To + 1 To egress inclus)**, puis ~€5/To (€0,0067/To-h) | €1/To au-delà de 1 To | objet min facturable 64 Ko | Oui (expiry) | **DE, pas de parent US** | **search** (pages en JS ; multi-sources concordantes, à re-confirmer à l'inscription) |
| **OVH Object Storage 1-AZ** | **~€7,27/Tio** (€0,00000972/Gio/h × 730 h) | **Gratuit** (politique déc. 2025, jeune donc révisable) | aucun trouvé | Oui (endpoint `.io` seulement, lag possible >24 h) | **FR (OVH Groupe SA), entité US séparée** | LIVE (via proxy JS + docs officielles) |
| **Scaleway One Zone** | **€8,03/To** (Multi-AZ : €16,06) | 75 Go/mois gratuits puis €0,01/Go | aucun trouvé | Oui (+ **conditional writes If-Match/If-None-Match documentés**, seul du panel) | **FR (Iliad), pas de parent US** | LIVE |
| **Backblaze B2** | **$6,95/To** (a augmenté : plus $6) | gratuit jusqu'à 3× le stock moyen, puis $0,01/Go | **aucun** (ni durée ni plancher) | Oui (Days) | US (CLOUD Act), DC EU = Amsterdam, **compte verrouillé région à la création** | LIVE |
| **Wasabi** | $7,99/To | « gratuit » (fair-use : egress ≤ stock) | **90 j de durée min + plancher 1 To** ($7,99/mois) | Oui (nouveaux buckets seulement) | US (CLOUD Act), 6 régions EU | LIVE |
| **Cloudflare R2** | $15/To (Standard) | **$0** (vérifié) | classe IA : 30 j min | Oui | US (CLOUD Act) ; « jurisdiction EU » = résidence des données, pas bouclier légal | LIVE |
| **Storj** | $7/To | $7/To | **$50/mois minimum depuis le 2026-07-01** (sauf paiement en token STORJ) | Non (TTL par objet via header seulement) | US Inc. (le « décentralisé » ne décentralise pas le droit : satellite = chokepoint ; warrant canary retiré 2022) | LIVE |
| **Vultr Object Storage** | $18/mois (1 To inclus) puis $18/To ; classe Archival $6/To (accès <1×/mois) | 1 To inclus puis $0,01/Go | plancher = base tier | Oui | US (Vultr) | LIVE |
| **Vultr Block Storage** (option déjà planifiée) | **$25/To HDD** / $100/To NVMe, **provisionné** (payé même vide) | via quota VPS | min $1/mois | n/a (MinIO au-dessus) | US (Vultr) | LIVE |

Baseline VPS : Vultr actuel = disque ~23-25 Go (plan exact non documenté au repo),
80 Go sur le plan $20/4 Go, quota trafic 3 To puis $10,24/To (LIVE). Candidat
déménagement : **Hetzner Cloud ~€4-5/mois (2 vCPU/4 Go), 20 To de trafic inclus
en EU, overage €1/To** (search ; hausses de prix Hetzner 2026 signalées, à
confirmer). Écarté d'office : auto-hébergement d'un 2e serveur de stockage
(Storage Box + couche S3) = charge d'ops d'un projet solo pour économiser des
clopinettes à notre échelle.

## 6. Coût mensuel modélisé (stockage seul, stock milieu de fourchette)

| Option | S1 (~0,3 To) | S2 (~2 To) | S3 (~20 To) | Note |
|---|---|---|---|---|
| **Hetzner OS** | **€4,99** | **~€10** | **~€100** | le moins cher partout, egress quasi inclus |
| OVH 1-AZ | ~€2,2 | ~€14,5 | ~€145 | pas de plancher ; egress gratuit |
| B2 | ~$2 | ~$14 | ~$139 | zéro minimum = idéal aussi en 2e copie/backup |
| Scaleway One Zone | ~€2,4 | ~€16 | ~€161 | conditional writes documentés |
| Wasabi | $8 (plancher) | ~$16 | ~$160 | 90 j min hostile aux purges précoces |
| R2 | ~$4,5 | ~$30 | ~$300 | cher mais egress $0 |
| Storj | $50 (min) | $50 (min) | ~$140 | absurde sous ~7 To |
| Vultr Object | $18 | ~$36 | ~$360 | |
| **Vultr Block HDD (statu quo+)** | $25 (1 To prov.) | $50-75 | $500+ | zéro changement app, garde MinIO mort, capacité à provisionner d'avance |

**Piège egress VPS du split** : l'ingest transite par le relais, donc chaque chunk
ressort du VPS vers le stockage externe. Sur Vultr : quota 3 To/mois, S3 (~4 To
sortants/mois) ≈ +$10/mois d'overage. Sur Hetzner Cloud : 20 To inclus, zéro.
La récupération d'archive compte double (egress stockage + egress VPS), rare chez
nous. Stockage local (block storage) = zéro egress d'ingest, par construction.

**Comparaison « tout compris » aux trois échelles** (VPS + stockage) :

| Architecture | S1 | S2 | S3 |
|---|---|---|---|
| Vultr VPS + Block HDD (minimal) | ~$35-45 | ~$70-95 | ~$520+ |
| Vultr VPS + Hetzner OS (split) | ~$20 + €5 | ~$20 + €10 | ~$20 + €100 + ~$10 egress |
| **Hetzner VPS + Hetzner OS (déménagement)** | **~€9-10** | **~€15** | **~€105** | 

## 7. Juridique (synthèse de la fiche dédiée, sources live)

- **La confidentialité est protégée par la crypto, pas par le drapeau.** Aucun
  régime étudié (CLOUD Act US, e-Evidence EU, BÜPF suisse, satellite Storj) ne
  crée d'autorité pour contraindre au déchiffrement de données chiffrées côté
  client. Une réquisition contre le stockage donne : ciphertext, tailles,
  timestamps, IP du relais, et **l'identité du compte** (le vrai butin).
- **Le risque réel du stockage = disponibilité** : pas de suppression ordonnée
  silencieuse dans aucun régime, mais résiliation ToS/abuse ou saisie de compte
  = témoignages détruits. **La mitigation est technique, pas juridique : une 2e
  copie chez un 2e fournisseur dans une 2e juridiction** (= le point 1.8 off-host
  backup de la roadmap, à traiter comme mitigation légale).
- **US strictement dominé** : même ciphertext livré, mais long-arm le plus fort,
  gag orders industrialisés (2705(b), NSL), culture OFAC, abuse teams nerveuses.
  EU sans parent US = meilleur équilibre (e-Evidence, applicable **18 août 2026**,
  donne aux 27 États un pouvoir d'ordre direct, mais ne rapporte que
  ciphertext+métadonnées). Suisse : mur MLAT précieux contre les requêtes
  étrangères, mais la révision VÜPF (par ordonnance, pause parlementaire fév.
  2026) érode la prime ; OK en 2e copie.
- **⚠️ Le vrai sujet juridique est LE RELAIS, pas le stockage** : il termine TLS
  et voit les IPs des témoins. Le schéma d'attaque documenté est l'ordre de
  **logging prospectif** contre le fournisseur (précédent Proton 2021, activiste
  français). Notre relais est aujourd'hui chez **Vultr = société US, CLOUD Act,
  gaggable**, hyperviseur compris. À la bascule test fermé/8.2.5, la juridiction
  du relais mérite la même exigence que cette étude : EU sans parent US
  (la ROADMAP visait déjà Greenhost NL / 1984 IS).
- Divers vérifiés : chat-control EU expiré (avr. 2026), CSAR en trilogue sans
  scanning obligatoire côté Conseil, rien n'atteint un stockage aveugle ;
  sanctions = le client du stockage est le relais, jamais le témoin (Iran couvert
  par 31 CFR 560.540) ; arrêt CJUE EDPS v SRB (sept. 2025) : nos blobs sans
  identité ne sont plausiblement même pas des données personnelles dans les mains
  du fournisseur. **Avant 8.2.5 : une heure de revue par un juriste droits
  numériques (réseau EFF/EDRi) sur la juridiction du relais et la structure du
  compte de stockage.**

## 8. Ce que le fournisseur de stockage apprend (rappel motto)

Blobs STRM V3 sans identité au repos, scellés vers une clé dont la moitié privée
n'existe que sur papier. Le fournisseur voit : tailles, cadence, IP du relais
(jamais celle d'un témoin), et compte facturier. C'est exactement le modèle de
menace déjà assumé pour MinIO ; le split ne crée **aucune** nouvelle classe
d'exposition, il déplace un stockage untrusted d'une boîte US (Vultr) vers un
fournisseur choisi.

## 9. Options et recommandation

| Option | Coût S1→S3 | Effort | Verdict |
|---|---|---|---|
| **0. Statu quo + block storage Vultr** (déjà planifié) | $45→$520+ | quasi nul (geste therealshulgin : attacher /dev/vdb) | OK si le disque presse avant la bascule ; garde MinIO mort + relais US |
| **1. Split S3 externe** (relais inchangé) | ~$25→~$130 | config + 5 adaptations §2 | Retire MinIO du chemin d'écriture ; paie l'egress VPS Vultr à l'échelle |
| **2. Déménagement cohérent : relais EU + S3 externe EU** | **~€10→~€105** | migration runbook existant (backup/restore one-command, déjà écrit) + adaptations §2 | **Recommandé au moment test fermé/8.2.5** : coût minimal, MinIO retiré, juridiction relais réglée en même temps |
| 2bis. Souveraineté max : Garage self-host + block storage | ~$45→$520+ | spike Garage | Si on refuse tout tiers ; plus cher, garde la charge d'ops stockage |
| **3. Fédération** (les orgs hébergent leur relais) | →0 pour nous | docs de déploiement + durcissement | La vraie réponse à l'échelle, **post-audit** |

**Séquence recommandée** :

1. **Maintenant** : rien d'urgent (S1 = ~0,3 To ; même le disque actuel + purge
   tient le test fermé de justesse, le block storage Vultr est le filet). Décision
   à prendre : quel fournisseur pour l'option 2.
2. **Au test fermé / 8.2.5** : option 2. Candidat n°1 : **Hetzner** (VPS + Object
   Storage, ~€10/mois tout compris à notre échelle, 20 To de trafic, DE/GDPR sans
   parent US, même datacenter pour relais et stockage). Alternative FR : Scaleway
   (conditional writes documentés) ou OVH (egress gratuit). Choisir aussi la **2e
   copie** (1.8) dans une juridiction différente : B2 EU (zéro minimum, $6,95/To)
   ou Scaleway si primaire Hetzner.
3. **8.2.5** : donations (GitHub Sponsors/OpenCollective) : couvre ~€10-15/mois
   dès quelques donateurs ; NLnet finance du dev/audit, pas de l'ops récurrent.
4. **Post-audit** : fédération (option 3) + retrait définitif de Garage/MinIO de
   notre périmètre si le split a déjà retiré le serveur objet.

## 10. Limites de cette étude (honnêteté d'inventaire)

- **Fiches manquantes** (limite de session ×2) : Exoscale/Infomaniak (Suisse),
  iDrive e2, Contabo. Impact faible : la Suisse n'était candidate qu'en 2e copie
  (VÜPF en érosion), iDrive/Contabo étaient des outsiders (prix promo/réputation).
- **Prix Hetzner = search multi-sources, pas page-live** (prix injectés en JS) ;
  à re-confirmer à l'inscription. Hausses Hetzner 2026 signalées sur les VPS.
- **ToS/abuse non lus** pour Scaleway/OVH/Hetzner (lu pour R2/Storj). À faire
  avant de signer : le contenu est du ciphertext, mais la résiliation de compte
  est LE risque de disponibilité.
- **Aucun test d'intégration minio-py réel** contre un endpoint externe : le §2.4
  est un prérequis absolu, pas une formalité.
- Maintenance du client `minio-py` non vérifiée (le serveur MinIO est EOL, pas
  forcément le client).
- Prix relevés le 2026-07-09 ; Storj vient de changer les siens 8 jours avant
  (×10 sur le minimum) : les prix bougent, re-vérifier avant signature.
- Vérification adverse multi-agents non passée sur ce doc (limite de session) ;
  les chiffres sont recopiés des fiches sources conservées dans le scratchpad de
  session. À re-passer si on en fait un canon.

## Annexe : sources principales (échantillon)

- Faits code : `server/app/storage.py`, `server/app/blob_cleanup.py`,
  `server/app/config.py`, `server/docker-compose.yml`, `StreamQuality.kt`,
  `StreamRecordingService.kt`, ROADMAP §10.8 et :104-143.
- MinIO EOL : api.github.com/repos/minio/minio (`archived:true`), release
  2025-10-15 ; Garage : git.deuxfleurs.fr releases, matrice S3 officielle.
- Prix : backblaze.com/cloud-storage/pricing, wasabi.com/pricing(/faq),
  developers.cloudflare.com/r2/pricing, storj.dev/dcs/pricing/simplified,
  scaleway.com/en/pricing/storage, ovhcloud.com/fr|en/public-cloud/prices (via
  proxy JS) + ovh/docs GitHub, api.vultr.com/v2/plans, vultr.com/products/*,
  hetzner.com/storage/object-storage (structure) + recoupements search.
- Juridique : eur-lex 2023/1543 (e-Evidence), Cornell 18 USC 2258A, Federal
  Register GL D-2, CJUE C-413/23 P, jurist.org/techcrunch (Proton 2021),
  isoc.ch (VÜPF), storj.io/blog + storj.dev (satellite/legal).
