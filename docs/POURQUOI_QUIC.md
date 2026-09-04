# Pourquoi QUIC

**En une phrase** : notre upload de témoignages s'effondre sous la perte réseau parce
qu'Android envoie en TCP `cubic`. QUIC embarque son propre contrôle de congestion en
**userspace, indépendant du `cubic` du kernel Android**. Bonus : il obfusque le trafic et
sort le JWT du heap JVM.

## Le problème

Frappuccino streame des chunks vidéo chiffrés vers un relais aveugle, souvent depuis des
réseaux instables (cellulaire faible, wifi saturé, zones tendues). Quand le lien perd des
paquets, l'upload ralentit **bien plus** que le réseau ne le justifie : à 10 % de perte,
on n'utilise plus que ~6 % du débit disponible. Des chunks finissent par expirer avant
d'être montés.

## La cause racine (mesurée)

Pour un **upload**, c'est le contrôle de congestion de l'**émetteur** (le téléphone) qui
gouverne, pas celui du serveur. Or nos deux devices de référence (Seeker, OnePlus 13)
envoient en **TCP `cubic` par défaut**, et `cubic` s'effondre sous la perte. Le BBR du
serveur ne sert qu'au download.

Débit d'upload mesuré (Mbit/s, réseau simulé, plafond du lien en jeu) :

| Réseau | TCP `cubic` (nous) | CC userspace (QUIC) |
|---|---|---|
| 1 % perte | 3.13 | 19.6 |
| 5 % perte | 0.62 | 7.87 |
| 10 % perte | 0.21 | 3.89 |

Notre baseline réelle, c'est la colonne `cubic`. Elle décroche d'un facteur **6 à 15**.

## Pourquoi pas juste basculer TCP en BBR

Parce que ce n'est **pas portable**. BBR existe sur le OnePlus mais **pas sur le Seeker**
(kernel `reno`/`cubic` only). Un correctif au niveau du socket TCP marcherait sur certains
devices et échouerait sur d'autres. (On garde quand même cette bascule comme quick-win là
où elle est disponible, mais ce n'est pas le fix de fond.)

## Ce que QUIC résout

- **Fiabilité d'upload sous perte.** QUIC porte son contrôle de congestion en
  **userspace**, donc il échappe au `cubic`-only du kernel Android. Fix **uniforme sur
  tous les devices**, indépendant du kernel. Moins de chunks perdus sur réseau dégradé.
- **Obfuscation (bonus).** Le trafic ressemble à du QUIC/HTTP-3 générique, plus difficile
  à identifier comme « Frappuccino » par une inspection profonde (DPI).
- **Heap-0 du JWT (bonus).** Faire le PUT dans le Rust signifie que le bearer ne traverse
  plus la pile HTTP de la JVM : le token reste côté Rust, effaçable. (Converge avec la
  cible §10.7.)

Une seule implémentation Rust livre les trois.

## Ce que QUIC ne résout PAS

La **destination reste visible**. On cache *quoi* (le contenu est déjà chiffré de bout en
bout) et bientôt *que c'est nous* (obfuscation), mais pas *à qui on parle*. Masquer la
destination relève d'un autre chantier (front CDN partagé, VPN, rotation d'IP).

## Statut

L'effondrement de `cubic` est **mesuré et réel**. Le **gain exact** de notre transport
QUIC reste **en validation** (le chiffre QUIC ci-dessus est un meilleur cas, débit
informé) : un PoC client le tranchera sur device, avec pour gate un débit au moins égal au
direct sur mauvais réseau, un trafic inclassifiable, le heap-0, et **zéro régression** sur
les protections anti-perte de données.

Détail technique et plan : `docs/TRANSPORT_QUIC_POC_SPEC.md`. Contexte métadonnées :
`docs/METADATA_EXPOSURE_MAP.md` §8. Décision et résultats : `ROADMAP.md` §10.9.
