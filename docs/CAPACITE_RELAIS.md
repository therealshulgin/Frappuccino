# Capacité du relais : ce que le disque supporte, et pourquoi le test fermé ne tient pas dessus

> Écrit le 2026-08-28 avant le test fermé à 15 volontaires, sur décision du mainteneur
> (revue d'architecture, décision 6). Le relais reste **ouvert à l'enrôlement** : ce
> document mesure la capacité, il n'ajoute aucun contrôle d'admission.
>
> Les chiffres viennent du relais de test réel, pas d'une estimation. La méthode de
> mesure est donnée pour chacun, parce qu'un modèle de capacité dont on ne peut pas
> refaire l'arithmétique ne vaut rien.

## 1. Le résultat, d'abord

**Le test fermé à 15 volontaires ne tient pas sur le relais actuel.** Il reste 7,6 Go
libres, un appareil qui filme en consomme environ 1 Go par heure, et le TTL de six mois
ne rend rien pendant la durée du test. Selon l'intensité d'usage, le disque se remplit
en **une demi-heure** (15 appareils filmant en même temps) ou en **un jour et demi**
(15 volontaires filmant 20 minutes par jour chacun).

Ce n'est pas une perte de témoignage : à disque plein le relais répond 507, le client
ouvre son disjoncteur et **garde le blob chiffré sur l'appareil** jusqu'à ce que la place
revienne. C'est un mur de disponibilité, pas de données. Mais pour un test dont l'objet
est justement de voir si la chaîne tient en usage réel, un mur atteint le deuxième jour
invalide le test.

## 2. Ce qui a été mesuré, et comment

| Grandeur | Valeur | Méthode |
|---|---|---|
| Disque total | 23 Go, dont **7,6 Go libres** (66 % utilisés) | `df -h /` sur le relais |
| Aucun volume de bloc attaché | confirmé | `df -h` ne montre que `/dev/vda1` et `/dev/vda2` |
| Blobs stockés | 2 225 | comptage des objets `.strm` sous le volume MinIO |
| Volume occupé par les blobs | 3,3 Go | `du -sh` du volume `frappuccino_minio_data` |
| **Taille moyenne d'un blob** | **1,52 Mo** | 3,3 Gio / 2 225. MinIO range chaque objet dans un **répertoire** (`xl.meta` plus les parts), donc un `stat` par fichier rend 4096 octets et induit en erreur : il faut diviser le volume par le nombre d'objets |
| Cadence de chunk | un chunk toutes les **5 s** | `RollingChunkRecorder.kt:61`, `chunkIntervalMs = 5_000L` |

Deux réserves honnêtes sur la moyenne. Ces 2 225 blobs viennent de tests terrain à des
qualités variables, avec l'adaptation automatique de qualité active ; un usage en bonne
lumière et bon réseau produira des chunks plus gros. Et le corpus mélange des chunks
vidéo avec quelques petits objets (entrées d'annuaire, preuves). La moyenne est donc un
ordre de grandeur utile, pas une constante.

## 3. Le débit, par appareil qui filme

Un chunk toutes les 5 s, soit 12 chunks par minute :

```
12 chunks/min  ×  1,52 Mo  =  18,2 Mo/min  =  1,07 Go/heure  et par appareil
```

Rien ne se libère en face pendant le test : le TTL des blobs est de **six mois**
(`config.py:71`), et le reap des reports ne s'occupe que de ceux dont tous les blobs ont
déjà été purgés. Sur la durée d'un test fermé, la consommation est donc **cumulative**.

## 4. Combien de temps tiennent 7,6 Go

| Scénario | Débit | Le disque se remplit en |
|---|---|---|
| 1 appareil qui filme en continu | 1,07 Go/h | ~7 h |
| 15 appareils qui filment en même temps | 16,1 Go/h | **~28 min** |
| 15 volontaires, 20 min de film par jour chacun | 5,3 Go/jour | **~34 h**, soit un jour et demi |
| 15 volontaires, 5 min de film par jour chacun | 1,3 Go/jour | ~5 jours et demi |

La ligne du milieu est le pire cas plausible d'une démonstration collective ; la
troisième est l'usage attendu d'un test de terrain. Aucune ne dépasse la semaine.

## 5. Ce qui se passe exactement à disque plein

La chaîne est déjà correcte, et c'est ce qui rend le mur supportable :

1. MinIO refuse l'écriture, `storage.upload_blob_stream_write_once` lève `StorageFullError`.
2. La route rend **507** et non 500 (`upload.py`), ce qui dit au client que la condition
   est persistante et non transitoire.
3. Le client ouvre son disjoncteur et **conserve le blob chiffré sur l'appareil**. Rien
   n'est effacé côté device tant que l'upload n'a pas réussi.
4. Les uploads reprennent quand de la place revient, sans intervention.

Le blob attend donc sur le téléphone. C'est exactement ce que le motto ne veut pas comme
état durable (le téléphone est un relais, pas un coffre) : plus le mur dure, plus le
témoignage reste là où une saisie l'atteint. **La disponibilité du relais est une
propriété du motto, pas seulement du confort.**

## 6. Les autres bornes, et pourquoi elles ne sont pas le sujet

Elles tiennent toutes ; le disque est ce qui casse en premier.

| Borne | Valeur | Marge face au test |
|---|---|---|
| PUT par IP | 600/min (`upload.py:89`) | un appareil émet ~12 PUT/min en régime, ~360/min en vidange de retard (6 uploads concurrents). Large |
| Enrôlement par IP | 5/min (`auth_v2.py:95`) | 15 volontaires s'enrôlent une fois. Sans objet |
| Auth par IP | 30/min (`auth_v2.py:167`) | une auth par session. Large |
| Taille d'un PUT | 500 Mo (`upload.py:11`) | un chunk fait 1,5 Mo. Sans objet |
| Reports par lot et par identité | 256 (`config.py:54`) | une session = un report ; 256 sessions par lot de ratchet. Large |
| Rotation par IP | 5/min (`auth_v2.py:289`) | une rotation toutes les ~45 sessions. Sans objet |

À noter pour un usage collectif : les compteurs sont **par IP**. Quinze volontaires
derrière une même sortie NAT ou un même VPN partagent le seau. Un 429 n'est jamais
destructif (le client réessaie, le blob reste sur l'appareil), mais il ralentit
exactement la vidange de retard que le motto veut rapide.

## 7. Ce qu'il faut faire avant le test

Le relais actuel est un **relais de test jetable** sur un hébergeur américain, et le
déménagement vers l'Europe est déjà décidé pour le moment du test fermé
(`docs/ETUDE_STOCKAGE_SPLIT_2026-07.md`). Ce document ne rouvre pas cette décision, il
lui donne son chiffre : **il faut du disque avant les volontaires, pas après.**

Dimensionnement à retenir, pour 15 volontaires sur un test d'un mois à 20 min de film
par jour :

```
15 × 20 min/jour × 30 jours  =  150 heures de film
150 h × 1,07 Go/h            ≈  160 Go
```

Avec une marge pour la qualité maximale et les reprises, **200 Go** est le bon ordre de
grandeur, contre 7,6 Go disponibles aujourd'hui. Trois voies, non exclusives :

1. **Déménager** vers l'hébergeur européen prévu, dimensionné dès le départ (c'est la
   décision déjà prise, et la seule qui règle aussi la question juridique).
2. **Raccourcir le TTL pendant le test.** Six mois protègent le contenu sans risque
   (les blobs sont chiffrés), mais pendant un test d'un mois ils n'apportent rien et
   coûtent tout le disque. Un TTL de test plus court est un réglage d'environnement
   (`ARCHIVE_BLOB_TTL_SECONDS`), pas un changement de code. À arbitrer contre le fait
   qu'un volontaire doit pouvoir récupérer ses rushes après le test.
3. **Surveiller et alerter**, dans tous les cas.

## 8. Seuils de surveillance

À poser avant le premier volontaire, quelle que soit la voie choisie :

| Seuil | Signification | Action |
|---|---|---|
| 70 % du disque | régime normal, on observe | rien |
| 85 % | il reste moins de deux jours au débit attendu | prévenir, préparer l'extension |
| 92 % | moins d'une journée | étendre le disque ou raccourcir le TTL, maintenant |
| 507 servi une seule fois | le mur est atteint, des blobs attendent sur des téléphones | intervention immédiate ; le compteur de 507 est l'alerte, pas le disque |

Le dernier seuil est le vrai : un 507 signifie qu'un témoignage est resté sur un
appareil. C'est l'événement à surveiller, et il doit être bruyant.

---

*Le relais de production n'existe pas encore. Ce document décrit la capacité du relais de
test au 2026-08-28 et ce qu'il faudrait pour le test fermé ; il sera périmé le jour du
déménagement, et c'est le but.*
