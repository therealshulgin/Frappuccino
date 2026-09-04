# Plan d'annonce & de recherche d'audit externe — 2026-07

> **Statut** : plan de travail, pas un canon. Recherche multi-agents du 2026-07-03 :
> 43 venues recensées en 6 catégories, règles de soumission **fetchées en live**
> (juillet 2026) sauf mention contraire. Objectif : susciter l'intérêt technique
> et un **audit externe** — pas une promo grand public (l'app vise des populations
> à risque ; toute annonce porte « not yet externally audited »).
>
> Déjà contacté : Tella FOSS (Horizontal).

## 0. Constats transverses (vérifiés)

- **2026 = règles anti-contenu-IA partout** : r/netsec « No AI-generated posts »,
  r/cryptography « No AI-slop — AI-assisted content must be thoroughly reviewed »,
  Show HN « genuine effort rather than quick generation », r/programming « No
  LLM-Written Content », This Week in Rust exige la **divulgation**. Conséquence :
  les posts s'écrivent **à la main** ; le vibecoding assumé se dit en réponse aux
  questions (ou en 2e phrase), **jamais en titre** — sauf r/ClaudeAI où c'est
  l'accroche. La ligne éditoriale « transparence » du site est compatible partout.
- **Presque tout est gaté par la publication 8.2.5** + un **writeup technique en
  anglais sur le site** (r/netsec interdit les liens repo/README, Show HN veut du
  testable, r/cryptography interdit les liens vers une home). Le writeup est LE
  prérequis n°1.
- **Croyances périmées corrigées par le fetch** : la voie « NLnet/NGI Zero →
  audit gratuit Radically Open Security » est **morte** (dernier call NGI0 clos
  01/06/2026, service ROS « capacity reached ») ; « OTF Red Team Lab » n'existe
  plus sous ce nom (fusionné dans **Security Lab**) ; Mozilla MOSS/SOS **mort** ;
  moderncrypto **mort** (dernier fil 2018) ; **tous les CFP conférences Rust 2026
  fermés** ; Global Gathering 2026 : deadline dépassée (30/06) → 2027.
- **Tension à anticiper** : « don't roll your own crypto » = première objection
  partout. Parade validée : primitives standard (libsodium-class), seule la
  composition est nouvelle, et elle est **prouvée** (Tamarin 10+2, Kani 4/4, TLC,
  zeroize-LLVM) + « pas encore audité en externe, c'est exactement ce qu'on
  cherche » — l'objection devient le call-to-action.

## 1. Tier 1 — la voie directe vers un audit

| Venue | Quoi | Quand | Verdict |
|---|---|---|---|
| **OTF Security Lab** (ex-Red Team Lab) | Audits **gratuits** (Cure53/ToB-class, 170+ audits) pour outils internet-freedom, y compris non-grantees ; « cryptographic design reviews » explicites. Formulaire `apply.opentech.fund/security-lab/` ou `security_lab@opentech.fund`. Le dossier attendu = exactement GUIDE_AUDITEUR + AUDIT_SCOPE_RUST + résidus. | Dès 8.2.5 | **LE canal n°1.** Caveat : financement gouv. US (turbulences 2025, budget FY2026 signé) → délais possibles + facteur d'image à assumer en doc. |
| **Least Authority** — pro bono PETs | Programme pro bono annoncé pour PETs à budget contraint servant des populations à risque = définition exacte du projet. `consulting@leastauthority.com`. | Dès 8.2.5, en parallèle d'OTF | Coût = 1 email. Capacité 2026 non confirmée ; réponse possible = devis commercial. |
| **Voie académique — premier contact : Jannik Dreier (LORIA/PESTO, Nancy)** | **Co-développeur de Tamarin, francophone, en France** (Maître de Conférences Univ. Lorraine, enseigne à TELECOM Nancy ; page perso : « I am co-developing the Tamarin prover », Levchin Prize). `jannik.dreier@loria.fr`. Un simple email peut donner un retour sur nos modèles `.spthy` avant tout audit financé. Vérifié par fetch 2026-07-03 (via doc contacts therealshulgin). | Email possible dès maintenant (les modèles Tamarin sont montrables) ; plus fort après 8.2.5 | **Le contact académique le plus direct** vu le contexte (langue, pays, Tamarin core). |
| Voie académique (suite) : **CISPA (Cas Cremers — co-créateur Tamarin, preuves Signal)** et ETH Zurich (groupe Paterson, « Breaking Cryptography in the Wild » : Threema, Matrix, MEGA…) | Pitcher le protocole comme sujet de thèse/papier : un système réel déployé **avec modèles Tamarin existants** est un sujet idéal (« vos preuves tiennent-elles ? »). Cremers : `people.cispa.io/cas.cremers/`. | Après 8.2.5 + docs protocole publiques ; horizon 6-12 mois | Gratuit, crédibilité maximale si un papier sort — même « on a cassé X » est assumable vu la ligne honnêteté. |
| **NLnet — open call** (réouverture « after the summer » 2026) | Grant 5-50 k€ avec ligne budget « audit externe » ; formulaire léger ; le profil (Rust, crypto vérifiée, privacy, dev EU solo) coche tout. **Contact coordinateur : Michiel Leenaars, `ngizero-coordinator@nlnet.nl`** — un email avant la réouverture peut clarifier les règles de la nouvelle call. ⚠️ Ne PAS candidater via `nlnet.nl/commonsfund` : la 13e et dernière call NGI0 Commons est **close depuis le 01/06/2026** (vérifié). | Email coordinateur possible maintenant ; dossier prêt pour l'automne | La voie audit-ROS-gratuit est morte, mais un grant **finance** un audit commercial + financement **européen** (indépendant du risque politique US d'OTF). |
| **OSTIF** | En direct : faible (ils ciblent les briques critiques répandues). En **courtier** : fort — scoping + appel d'offres auditeurs si on apporte le financement (ex. grant NLnet). | Après une piste de financement | Email direct à l'Executive Director (site en 403 anti-bot, vérifier les coordonnées à la main). |

Écartés à ce stade : **Sovereign Tech Fund** (critère « prevalence » disqualifiant
pour une app neuve ; à revoir si la crate crypto acquiert des dépendants),
**GitHub Secure Open Source Fund** (pas un audit : 10 k$ + formation ; exige
traction), **Cure53/Trail of Bits en direct** (= devis 30-80 k$ ; la route
réaliste vers eux passe par OTF/OSTIF). Contacts gardés **en réserve devis**
si OTF/NLnet n'aboutissent pas : Cure53 `hello@cure53.de` (+49 1520 8675 782 —
palmarès très pertinent : rustls, ed25519, crypto_box/secretbox, Threema,
Mullvad, IVPN) ; Trail of Bits `info@trailofbits.com` / trailofbits.com/contact
(revue design Ockam, partenaire historique OTF Security Lab). Contact général
OTF en plus du lab : `hello@opentech.fund`.

## 2. Tier 2 — communautés à densité d'auditeurs

Ordre de tir conseillé (après 8.2.5 + writeup) :

1. **Rust Secure Code WG — Zulip `#wg-secure-code`** : la plus haute densité
   d'yeux sécu-Rust par lecteur. Format = demande de revue, pas annonce.
   **Soft-launch acceptable AVANT la publication** — leurs retours ajustent
   l'annonce publique.
2. **users.rust-lang.org #announcements** : zéro règle anti-self-promo (vérifié),
   audience experte. Répétition générale 2-3 jours avant r/rust.
3. **r/rust** : plus gros bassin, auditeurs pros en lecture passive. Post texte
   technique, titre factuel avec « seeking external audit ». Règles à relire
   dans la sidebar (non fetchables). Risque : le thread dérive sur l'IA —
   transparence en une ligne, preuves en avant, ne pas débattre.
4. **Show HN** : une seule cartouche. Il faut du **testable** (repo + APK).
   Titre sobre, angle IA dans le premier commentaire de l'auteur, dispo 24-48 h.
   Mardi-jeudi, matin US.
5. **Lobsters** : tags show+cryptography+security+rust, très formal-methods-friendly.
   ⚠️ **Inscription sur invitation + comptes neufs bridés ~70 jours → demander
   l'invitation MAINTENANT.**
6. **r/crypto** : ⚠️ sub **Restricted** — il faut l'approbation des mods
   (u/Natanael_L) avant de poster → **modmail dès maintenant**. Post centré
   PROTOCOLE (wire V3, ratchet, preuves), pas « voici mon app ».
7. **r/cryptography** : framing « design review request / proofreading »
   (explicitement listé comme bon post). « Extraordinary claims require
   extraordinary proofs » = notre règle préférée.
8. **r/netsec** : le repo va dans le **monthly tool thread** (les posts outils
   sont interdits) ; le writeup (threat model, forensics on-device) en post
   normal, flair Cryptography/Research.
9. **This Week in Rust** : PR sur `draft/` avec le billet technique (pas un lien
   repo nu) ; divulgation IA requise = alignée avec notre ligne. + entrée « Call
   for Participation : external security review wanted ».
10. **IACR ePrint** : tech report « STREAM V3 + ratchet + threat model + formal
    analysis ». Transforme la perception (« paper » vs « README »), prérequis de
    facto pour RWC, appât n°1 pour les groupes académiques. ⚠️ **non-anonyme**
    (nom réel + contact en première page) — à trancher explicitement. Effort
    2-4 semaines.
11. **Real World Crypto 2027** (Seattle, 5-7 avril) : **deadline soumission
    15 octobre 2026**. Audience = littéralement « les cryptographes qui auditent
    des systèmes réels ». Angle taillé : deployment + « making cryptography work
    for users » + social/political. Présence physique obligatoire (~2-3 k€).

## 3. Tier 3 — écosystème, crédibilité, distribution

- **Guardian Project** (vérifié GO, contacts confirmés : support@guardianproject.info,
  Matrix `#guardianproject:matrix.org`, Nathan Freitas) : outreach pair-à-pair —
  les pionniers du créneau (ProofMode/ObscuraCam), historiquement financés OTF,
  réseau dense vers les auditeurs. Avant ou juste après publication.
- **WITNESS** (video-as-evidence) : formulaire générique → légitimité domaine,
  pas d'audit. Anticiper la question « anonymat de la source vs valeur probante »
  (ils poussent la provenance C2PA, nous l'anonymat).
- **Privacy Guides Forum — Project Showcase** : seule section self-promo autorisée,
  **UN seul thread, pas de 2e chance** ; vérification dev par mail au domaine du
  site. Communauté qui démolit les surventes = review gratuite. Après F-Droid
  idéalement (question posée systématiquement).
- **F-Droid** : canal de crédibilité majeur, mais gros chantier — recette de
  build 3-ABI Rust/UniFFI reproductible sur leur CI (doc repro : « anything
  built using the NDK will be much more sensitive », pin NDK exact, chemins
  identiques). Voie rapide intermédiaire : **IzzyOnDroid** (APK signé dev,
  scans publics = mini-vetting gratuit). **F-Droid Forum** (catégorie Apps) =
  OK avant audit, bon vivier de reviewers build-chain, et le bon endroit pour
  demander de l'aide sur la repro NDK/Rust. ⚠️ Toute distribution = installable
  par des utilisateurs à risque avant audit → description « beta, non auditée,
  relais de test » obligatoire.
- **cryptography.rs (RCIG)** : issue de soumission du cœur crypto (pas l'app)
  avec le dossier de preuves — il existe un badge **« formal verification »**
  taillé pour nous ; le badge « security audits » vide = levier de motivation à
  citer. + `rust-cc/awesome-cryptography-rust` (PR immédiate possible) ;
  `awesome-rust` attend ~50 étoiles.
- **r/androiddev** : writeup « Rust crypto via UniFFI + build reproductible »
  (pas une annonce d'app). Règles non vérifiées → relire la sidebar.
- **exodus-privacy** : après F-Droid, demander l'analyse → un rapport
  « 0 trackers » public = badge opposable pour le motto. Pré-vérifier en local
  avec exodus-standalone.

### Angle IA (à doser)

- **r/ClaudeAI — flair « Built with Claude »** : seule venue où le vibecoding est
  l'accroche. Récit du workflow (audits multi-agents adverses, cross-audit GPT-5,
  « le code fait foi », preuves formelles comme oracle non-IA). ⚠️ karma OP > 50
  requis → préparer le compte. Faible valeur audit, mais visibilité Anthropic
  (Discord officiel, hackathons « Built with Claude »).
- **Latent Space** (guest posts via formulaire, ~1 mois de lead, pas de cold
  email) : essai process « Shipping security-critical software with AI agents:
  formal methods as the compensating control ». **Pitchable AVANT la publication.**
- **The Pragmatic Engineer** (guest deepdive **rémunéré**, pitch via Google Form,
  « security engineering » cité comme sujet type) : « Solo-building a
  life-critical app with AI agents: what formal verification can and can't
  compensate ». Très sélectif, la meilleure pièce de légitimité possible.
- **dev.to** : pas de découvrabilité propre, mais bon miroir canonical_url du
  writeup du site.
- **X/Bluesky** : amplificateur + DM d'auditeurs individuels ; compte neuf =
  portée nulle → commencer à exister maintenant (threads formal-methods/Rust).

## 4. À ÉVITER (vérifié)

- **r/programming** : règles écrites contre exactement ce post (« No LLM-Written
  Content » + « No Product Promotion/'I Made This' »). Suppression + risque ban.
- **r/ExperiencedDevs** : No Advertisements, posts IA cantonnés mercredi/samedi
  sous peine de ban, karma in-sub requis, tonalité très AI-sceptique. Au mieux
  une question de discussion process, après HN, sans lien.
- **r/privacy** : historiquement hostile à la self-promo (règles 2026 non
  vérifiables) ; le Project Showcase de Privacy Guides est le substitut explicite.
- **GIJN / RSF / CPJ : APRÈS audit externe UNIQUEMENT.** Ces canaux prescrivent
  des outils à des populations à risque — y pousser une app non auditée serait
  contraire au motto et grillerait la crédibilité. Post-audit, GIJN est le
  meilleur cheval média (pitch `editorial@gijn.org`, série « My Tools » ; le
  pipeline Tella : couverture GIJN → financement OTF). Le RSF Digital Security
  Lab fait de la forensique d'attaques, pas de l'audit de code.
- Morts/fermés : moderncrypto, Mozilla MOSS/SOS, CFP Rust 2026 (RustConf clos
  16/02, EuroRust clos 04/05, Oxidize/RustLab clos), CFP Crypto & Privacy
  Village 2026, Global Gathering 2026 (clos 30/06 → réseau Team CommUNITY en
  continu + candidature 2027 au printemps).

## 5. Ordre d'opérations (~3 mois)

> **Logique d'échiquier (décision therealshulgin 2026-07-03)** : sans backup
> institutionnel ni premier audit, les communautés dev seront agressives sur la
> question IA. Donc : **(1) l'ouverture = coups privés à exposition nulle**
> (emails Dreier/NLnet, pitchs newsletters, préparation de comptes) qui
> fabriquent des « jetons de bouclier » — une réponse d'un core-dev Tamarin, un
> guest post accepté, un « audit application filed with OTF Security Lab » ;
> **(2) le premier coup PUBLIC = r/ClaudeAI au jour J de la publi** (seule venue
> où l'angle IA est l'atout ; mais sa règle « free to try » exige le repo public
> — pas de post avant 8.2.5) ; **(3) les communautés sécu/dev ensuite seulement**,
> en tenant déjà un ou plusieurs jetons. Chaque post public est permanent et
> googlable : le récit « formal methods as the compensating control » doit être
> le cadrage dès le premier post, car les auditeurs le liront plus tard.
> Brouillons des coups d'ouverture : `docs/OUTREACH_DRAFTS_2026-07.md`.

**Maintenant (avant 8.2.5)** — tout est gratuit et sans exposition :
1. Demander une **invitation Lobsters** (compte à faire mûrir ~70 j).
2. **Modmail r/crypto** (sub Restricted, approbation à obtenir).
3. Comptes : karma Reddit (r/ClaudeAI >50), compte HN pas tout neuf, présence
   X/Bluesky embryonnaire.
4. Écrire le **writeup technique EN** du site (pierre angulaire de tout le reste)
   — candidats : « A relay, not a vault » (threat model) + « Proving a ratchet
   protocol with Tamarin/Kani/TLA+ on Android ».
5. Préparer le **dossier NLnet** (réouverture automne) et le squelette **eprint**.
6. Optionnel : pitch **Latent Space / Pragmatic Engineer** (lead long).
7. Soft-launch **Zulip #wg-secure-code** possible avant publication.

**Semaine de la publication 8.2.5** :
1. Repo public + writeup en ligne le même jour.
2. **OTF Security Lab** (candidature) + **Least Authority** (email) +
   **Guardian Project** (email pair-à-pair) — les trois partent en parallèle.
3. URLO #announcements → 2-3 jours plus tard **r/rust** → puis la même semaine
   **Show HN + Lobsters + r/cryptography** + repo dans le monthly thread r/netsec
   + PR **This Week in Rust** ; **r/crypto** dès approbation ; r/ClaudeAI en fin
   de semaine.
4. Issue **cryptography.rs** + PR awesome-cryptography-rust ; suggestion
   **IzzyOnDroid** ; post **F-Droid Forum** + début de la recette fdroiddata.

**Été → automne** :
1. Finir l'**eprint** → soumission **RWC 2027 avant le 15 octobre**.
2. Emails **ETH Zurich / CISPA (Cremers)** avec l'eprint en pièce maîtresse.
3. **NLnet** à la réouverture ; si accordé → **OSTIF en courtier**.
4. F-Droid MR quand la recette repro tient.

**Post-audit externe** (quel qu'il soit) :
GIJN, Privacy Guides (recommandation officielle), r/privacy éventuel, CFP 2027
(RustConf ~déc., EuroRust ~fév., Crypto & Privacy Village ~mars, Global
Gathering ~printemps), badge « security audit » cryptography.rs.

## 6. Pièges récurrents

1. **Une seule cartouche par venue à fort enjeu** (Show HN, thread unique Privacy
   Guides, r/rust) → tout repose sur le writeup et la disponibilité de réponse.
2. **Le texte des posts s'écrit à la main** — partout. Un post « qui sent l'IA »
   est supprimé (r/netsec, r/cryptography) ou démoli (HN 2026).
3. **Ne jamais sur-vendre avant audit** : « not yet externally audited » dans
   chaque post — c'est aussi ce qui rend la démarche crédible et transforme
   chaque trou trouvé en confirmation d'honnêteté plutôt qu'en démolition.
4. **eprint = non-anonyme** (nom réel en première page) : décision explicite à
   prendre avant d'emprunter la voie académique.
5. **Vote manipulation = ban partout** (HN explicite) : zéro coordination d'amis.
6. Reddit infetchable par outillage : **relire les sidebars dans l'app le jour
   du post** (r/rust, r/androiddev en particulier — non vérifiées ici).
