# Frappuccino : guide de test

*English version below.*

Frappuccino filme et envoie la vidéo **pendant** qu'elle est filmée : chaque morceau de
5 secondes est chiffré sur le téléphone, puis part vers un relais qui ne peut pas le lire. Si
le téléphone est saisi ou perdu, ce qui a été filmé est déjà parti, et seule votre phrase de
12 mots permet de le récupérer.

## Avant de commencer : c'est une version de test

- **N'y mettez pas de vraies images sensibles.** Le relais utilisé est un serveur de test,
  hébergé aux États-Unis, qui pourra être effacé ou remplacé sans préavis. Une version
  destinée à un usage réel passera par un relais hébergé en Europe.
- Les vidéos stockées sur le relais sont effacées automatiquement au bout de 6 mois.
- Cette version n'est pas passée par le Play Store : Android vous demandera d'autoriser
  son installation.

## 1. Installer

**Recommandé : avec Obtainium**, qui installe l'app et la met à jour automatiquement.
1. Installez [Obtainium](https://github.com/ImranR98/Obtainium/releases) (son fichier `.apk`).
2. Dans Obtainium : « Ajouter une application », collez
   `https://github.com/therealshulgin/Frappuccino`, cochez « Inclure les pré-versions »,
   puis installez.

**Sans Obtainium** : téléchargez le fichier `.apk` depuis la page de la version sur GitHub,
ouvrez-le et autorisez l'installation quand Android le demande.

**Vérifier le fichier (conseillé)** : la page de la version donne l'empreinte SHA-256 de
l'APK. Elle doit être identique à celle du fichier que vous avez téléchargé.

## 2. Premier lancement

1. Choisissez un **code PIN**. Il protège l'app sur ce téléphone.
2. L'app affiche votre **phrase de 12 mots**. **Écrivez-la sur papier** et gardez-la loin du
   téléphone : c'est la seule façon de récupérer vos vidéos. Personne ne peut la retrouver à
   votre place, ni nous, ni le relais.
3. L'app vous redemande quelques mots pour vérifier que vous les avez bien notés.

## 3. Filmer

- Appuyez sur le bouton d'enregistrement. Les morceaux partent au fil de l'eau ; sans réseau,
  ils attendent sur le téléphone et partent dès que le réseau revient.
- À l'arrêt, l'app « clôt » l'enregistrement : à partir de là, personne ne peut plus y
  ajouter quoi que ce soit, pas même avec votre téléphone.
- **Effacement d'urgence** (dans les réglages) : efface d'un coup tout ce que l'app garde sur
  le téléphone. Les vidéos déjà envoyées restent récupérables avec la phrase.

## 4. Récupérer vos vidéos

1. Dans les réglages, ouvrez le **mode archive** et saisissez votre phrase.
2. **Récupérer** télécharge vos enregistrements depuis le relais et contrôle qu'ils sont bien
   les vôtres et intacts. Le statut s'affiche : complet, incomplet, interrompu, altéré.
3. **Regarder** : les vidéos se lisent dans l'app. Rien n'est écrit dans la galerie, et tout
   est effacé à la fermeture du mode archive.
4. **Exporter** (geste volontaire) : chaque enregistrement devient une vidéo, recollée sans
   perte de qualité. Il peut y en avoir plusieurs pour un même enregistrement : l'app adapte la
   qualité de l'image au réseau pendant qu'elle filme, et chaque changement de qualité commence
   une nouvelle vidéo ; de même s'il manque un morceau, car une vidéo exportée ne cache jamais
   un trou. Option : les morceaux d'origine, pour servir de preuve. Les
   fichiers exportés sortent de la protection de l'app : rangez-les sur un support chiffré.

## 5. Nous faire un retour

Notez ce que vous avez fait, ce que vous attendiez et ce qui s'est passé, avec le modèle du
téléphone et la version d'Android. Utilisez le canal convenu avec votre structure ; n'y mettez
jamais votre phrase de 12 mots.

---

# Frappuccino: testing guide

Frappuccino films and uploads video **while** it is being filmed: each 5-second piece is
encrypted on the phone, then sent to a relay that cannot read it. If the phone is seized or
lost, what was filmed has already left, and only your 12-word phrase can recover it.

## Before you start: this is a test version

- **Do not record real sensitive footage.** The relay is a test server hosted in the United
  States; it may be wiped or replaced without notice. A version meant for real use will go
  through a relay hosted in Europe.
- Videos stored on the relay are deleted automatically after 6 months.
- This version does not come from the Play Store: Android will ask you to allow installing it.

## 1. Install

**Recommended: with Obtainium**, which installs the app and keeps it up to date.
1. Install [Obtainium](https://github.com/ImranR98/Obtainium/releases) (its `.apk` file).
2. In Obtainium: "Add app", paste `https://github.com/therealshulgin/Frappuccino`, tick
   "Include prereleases", then install.

**Without Obtainium**: download the `.apk` file from the release page on GitHub, open it and
allow the installation when Android asks.

**Check the file (recommended)**: the release page gives the SHA-256 fingerprint of the APK. It
must match the file you downloaded.

## 2. First launch

1. Choose a **PIN**. It protects the app on this phone.
2. The app shows your **12-word phrase**. **Write it on paper** and keep it away from the
   phone: it is the only way to recover your videos. Nobody can recover it for you: not us,
   not the relay.
3. The app asks for a few of the words to check that you wrote them down.

## 3. Film

- Press the record button. Pieces leave as they are filmed; with no network, they wait on the
  phone and leave as soon as the network is back.
- When you stop, the app "closes" the recording: from then on, nobody can add anything to it,
  not even with your phone.
- **Emergency wipe** (in the settings): erases at once everything the app keeps on the phone.
  Videos already sent stay recoverable with the phrase.

## 4. Recover your videos

1. In the settings, open **archive mode** and enter your phrase.
2. **Retrieve** downloads your recordings from the relay and checks that they are yours and
   intact. The status shows: complete, incomplete, interrupted, altered.
3. **Watch**: videos play inside the app. Nothing is written to the gallery, and everything is
   erased when archive mode closes.
4. **Export** (a deliberate step): each recording becomes one video, joined without any loss
   of quality. A recording can give several videos: the app adapts the image quality to the
   network while it films, and each change of quality starts a new video; the same happens if
   a piece is missing, because an exported video never hides a gap. Option: the original pieces,
   as evidence. Exported files leave the app's protection: keep them on encrypted storage.

## 5. Give us feedback

Write down what you did, what you expected and what happened, with the phone model and the
Android version. Use the channel agreed with your organisation; never include your 12-word
phrase.
