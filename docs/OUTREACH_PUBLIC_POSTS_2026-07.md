# Coups d'ouverture PUBLICS - communautés AI engineer (2026-07)

> **Statut : BROUILLONS, à poster par therealshulgin (sa décision, son compte).**
> Ce sont les premiers coups **publics** (distincts des coups privés à exposition
> nulle de `OUTREACH_DRAFTS_2026-07.md`). Cadrage imposé : **post de MÉTHODE, pas
> de produit** (surtout pas « venez utiliser mon app » : ça, c'est le jour J de la
> 8.2.5, ça attirerait des utilisateurs à risque avant l'audit). **Pseudonyme**,
> jamais le vrai nom (public permanent et googlable). **Zéro tiret cadratin**
> (`U+2014`) et zéro tic IA (un post qui « sent l'IA » se fait démolir dans ces
> salles en 2026). Tout fait cité est vrai au 2026-07-06 et vérifiable dans le repo.
>
> **Revue adverse passée (4 agents, workflow `wxv780241`) :** fact-check = 0 écart
> (tous les chiffres tenus contre le code) ; em-dash = 0 (byte-sweep) ; corrigé
> ensuite : le titre + les antithèses « X, not Y » répétées (tell IA de r/ClaudeAI),
> le glissement méthode→promo (recruiting/roadmap retiré du corps), la dépendance
> à un seul lien (artefact concret ajouté dans le corps), et 3 sur-portées
> substantielles attrapées par le sceptique (wipe LLVM = 1 fonction pas « tous les
> wipes » ; « 100% Rust » nickable par `ring` en transport → frontière nommée ;
> rotation « custom » assumée pour inoculer le « rolled your own crypto »).

## Pré-requis compte (à régler AVANT de poster)

- **r/ClaudeAI** : karma OP > 50 requis (règle du sub). Utiliser un compte déjà
  mûr, pas un compte neuf, sinon retrait automatique.
- **Compte pseudonyme** aligné `0xmah` (ou autre), **jamais** lié au vrai nom.
- Les deux posts pointent le writeup #1 déjà en ligne :
  https://shake-document-protect.org/writeups/proving-ai-assisted-crypto/

---

## 1. r/ClaudeAI (self-post, flair « Built with Claude »)

**Titre :**
> I let Claude write the crypto for a security-critical app, then built a proof
> stack so I wouldn't have to trust it

**Corps :**

I'm a solo dev. For months my main pair programmer has been Claude Code, on an
end-to-end encrypted video-testimony app for people whose phone can get seized
(activists, journalists). The application crypto, the ratchet, the message and
chunk encryption, the enrollment signatures, is pure Rust (RustCrypto/dalek). A
bug there is a safety problem for a real person, not a bad day.

So yes, I let an AI write security code, including a custom key-rotation scheme.
And I don't trust it, or myself, to have gotten it right just by reading it. The
way I made that OK: nothing load-bearing is allowed to rest on the model's
judgment, or mine. It has to be checkable by something that isn't an LLM. So the
load-bearing pieces are pinned to deterministic, replayable oracles:

- the rotation scheme is a custom construction, which is exactly why it's modeled
  in Tamarin instead of trusted: 10 lemmas proven, plus 2 negative controls where
  I mutate the model to break the mechanism on purpose and require the prover to
  catch it (drop the signature check and it falsifies authentication; collapse two
  message tags and it falsifies rotation integrity). A proof that can't fail proves
  nothing.
- the ratchet state machine is modeled in TLA+ and the model is checked
  exhaustively by TLC (bounded).
- parsing of untrusted input is verified with Kani on the real Rust.
- the ratchet's secret-key wipe is checked at the LLVM IR level, because a naive
  wipe gets dead-store-eliminated by the optimizer and you'd never catch it from
  the source. (It's one function, the one holding the long-lived secrets; other
  buffers lean on tests and fuzzing.)

Claude wrote a lot of that. It also reviewed it adversarially, in multi-agent runs
where one group of agents tries to break what another group built, and I ran a
cross-model pass with a different vendor's model as the red team. Every finding,
from either side, gets re-verified against the actual code before a line changes.
Both models produce confident nonsense sometimes. When they disagree, or when I'm
not sure, the oracle is the tiebreaker.

The code isn't public yet, so this is about the approach, not something to go
install. It's also not externally audited, and I say that everywhere it appears.
Full writeup with the real numbers and the failures left in, if you want the rest:
https://shake-document-protect.org/writeups/proving-ai-assisted-crypto/

The obvious hole: the review harness is itself partly AI-written. I'm curious how
other people here handle load-bearing AI code. What's your oracle, or do you just
review harder and hope? And tell me where mine is fooling me.

---

## 2. Latent Space (message communauté / Discord, registre pair-à-pair)

Been building a security-critical thing mostly with Claude Code (an E2E encrypted
witness-video app for activists, application crypto in pure Rust) and wrote up the
part I think this crowd will actually find interesting: how do you ship code when
you can't fully trust the author, and the author is an LLM (and honestly, when it's
you too).

The approach that held: nothing load-bearing rests on the model's judgment.
Everything important is pinned to a non-AI oracle. The key-rotation scheme is
custom, so it's modeled in Tamarin (10 lemmas + 2 negative controls that
deliberately break it so the prover has to catch them) rather than trusted; the
ratchet state machine is modeled in TLA+ and checked exhaustively by TLC (bounded);
Kani runs on the real Rust parser for untrusted input; and an LLVM-IR check makes
sure the ratchet's secret-key wipe actually survives the optimizer (a naive wipe
gets dead-store-eliminated, and you'd never see it in the source). Claude did a lot
of the writing and a lot of the adversarial reviewing (multi-agent harnesses, plus
a cross-model pass with another vendor as the red team), but every finding gets
re-verified against the code before anything changes.

Writeup, numbers and failures included:
https://shake-document-protect.org/writeups/proving-ai-assisted-crypto/

Code isn't public yet and it's not externally audited, so it's the method I'm
putting out, not the app. Would love this crowd to poke holes in the approach. The
one I already know about: the harness that reviews the AI is itself partly AI.

---

## Suivi

| Coup | Posté le | Réponse | Note |
|---|---|---|---|
| r/ClaudeAI | - | - | - |
| Latent Space (Discord) | - | - | - |
