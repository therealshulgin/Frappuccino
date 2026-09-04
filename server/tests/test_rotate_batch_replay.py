#!/usr/bin/env python3
"""
test_rotate_batch_replay.py — les faits serveur dont dépend la réparation de
désynchro côté appareil.

`advanceBatch()` fait avancer le ratchet LOCAL et wipe le batch précédent, puis
l'appareil appelle `/auth/v2/rotate-batch`. Si cet appel n'arrive pas, l'appareil
est sur N+1 et le relais sur N : le relais compare `batch_number` à chaque auth,
donc il refuse tout, définitivement (ni ré-enrôlement, ni révocation côté client).
La seule sortie est de renvoyer la preuve, qui ne peut plus être re-signée
puisque le batch qui l'a produite n'existe plus.

Le client garde donc une FILE de preuves non confirmées et la rejoue à chaque
auth. Ce dispositif repose sur trois faits, qui vivent ici et pas dans le client :

  1. une preuve rejouée est ACCEPTÉE tant que le relais n'a pas avancé ;
  2. la même preuve est REFUSÉE une fois appliquée, avec le 401 opaque commun à
     tous les rejets — donc l'appareil ne peut PAS distinguer « jamais reçue » de
     « déjà appliquée », et c'est précisément pour ça qu'il garde la chaîne
     entière plutôt qu'une seule preuve ;
  3. une chaîne rejouée du plus ancien au plus récent rattrape le relais en une
     passe.

Le contrôle négatif du 3 est le test 4 : rejouée à l'envers, la même chaîne ne
rattrape qu'un seul cran. C'est ce qui rend l'ordre de `retryPendingRotations`
(StreamUploadManager) porteur, et pas décoratif.
"""

import os
import sys
import tempfile
from pathlib import Path

import nacl.bindings
import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

os.environ["JWT_SECRET"] = "test-secret-do-not-use"
_tmp = tempfile.mkdtemp()
os.environ.setdefault("RATCHET_REGISTRY_FILE", os.path.join(_tmp, "registry.json"))
os.environ.setdefault("REPORTS_DB_PATH", os.path.join(_tmp, "reports.json"))

from fastapi.testclient import TestClient  # noqa: E402
from app.main import app  # noqa: E402
from app import ratchet_registry  # noqa: E402
from app.signature_domain import (  # noqa: E402
    SIG_DOMAIN_BATCH_ROTATION,
    SIG_DOMAIN_ENROLLMENT,
)


# --- helpers (miroir du client Kotlin / Rust) -------------------------------

def _keypair():
    pk, sk = nacl.bindings.crypto_sign_seed_keypair(os.urandom(32))
    return pk, sk


def _sign(sk, msg):
    return nacl.bindings.crypto_sign(msg, sk)[:64]


def _batch(n=ratchet_registry.BATCH_SIZE):
    return [_keypair() for _ in range(n)]


def _concat(pairs):
    return b"".join(p[0] for p in pairs)


@pytest.fixture()
def client():
    ratchet_registry._clear_for_tests()
    return TestClient(app)


def _enroll(client):
    id_pk, id_sk = _keypair()
    id_hex = id_pk.hex()
    batch0 = _batch()
    sig = _sign(id_sk, SIG_DOMAIN_ENROLLMENT + _concat(batch0)).hex()
    r = client.post("/auth/v2/enroll", json={
        "ed25519_pk": id_hex,
        "batch_0_public_keys": [p[0].hex() for p in batch0],
        "batch_0_signature": sig,
    })
    assert r.status_code == 200, r.text
    return id_hex, batch0


def _proof(id_hex, signer_batch, from_batch, to_batch, signer_idx=49):
    """La preuve que l'appareil produit en passant de `from_batch` à `to_batch`.

    Signée par un slot de `from_batch`, comme le fait `advance_batch()` côté
    Rust. Elle est construite ici SANS rien envoyer : c'est tout l'intérêt, un
    appareil peut avoir avancé plusieurs fois pendant que le relais n'en a vu
    aucune.
    """
    signer_pk, signer_sk = from_batch[signer_idx]
    sig = _sign(signer_sk, SIG_DOMAIN_BATCH_ROTATION + _concat(to_batch)).hex()
    return {
        "ed25519_pk": id_hex,
        "signer_batch_number": signer_batch,
        "signer_key_index": signer_idx,
        "signer_public_key": signer_pk.hex(),
        "new_batch_public_keys": [p[0].hex() for p in to_batch],
        "new_batch_signature": sig,
    }


def _server_batch(id_hex):
    return ratchet_registry.get(id_hex)["batch_number"]


GENERIC_REJECT = {"detail": "Rotation rejected"}


# --- 1. renvoyer une preuve perdue répare -----------------------------------

def test_replaying_a_lost_proof_is_accepted(client):
    """L'appel a échoué au réseau : le relais est resté sur 0, l'appareil est
    sur 1. Le renvoi de la MÊME preuve remet les deux d'accord."""
    id_hex, batch0 = _enroll(client)
    b1 = _batch()
    proof = _proof(id_hex, 0, batch0, b1)

    # (le premier envoi est supposé perdu en route : on ne l'émet pas)
    assert _server_batch(id_hex) == 0

    r = client.post("/auth/v2/rotate-batch", json=proof)
    assert r.status_code == 200, r.text
    assert r.json()["new_batch_number"] == 1
    assert _server_batch(id_hex) == 1


# --- 2. un refus ne dit pas POURQUOI, et c'est ce qui impose la file --------

def test_replay_after_apply_is_refused_indistinguishably(client):
    """Une fois la rotation appliquée, le rejeu est refusé — avec le même corps
    qu'une preuve franchement invalide.

    L'appareil voit donc la même chose dans les deux situations opposées :
    « le relais ne l'a jamais reçue » (renvoyer répare) et « il l'a déjà
    appliquée » (renvoyer ne sert à rien). Il ne peut pas trancher, donc il ne
    tranche pas : il garde toutes les preuves et les rejoue.
    """
    id_hex, batch0 = _enroll(client)
    b1 = _batch()
    proof = _proof(id_hex, 0, batch0, b1)

    assert client.post("/auth/v2/rotate-batch", json=proof).status_code == 200
    assert _server_batch(id_hex) == 1

    rejeu = client.post("/auth/v2/rotate-batch", json=proof)
    assert rejeu.status_code == 401, rejeu.text
    assert rejeu.json() == GENERIC_REJECT

    # Repère : une preuve dont la signature est bidon, donc invalide pour une
    # raison entièrement différente.
    bidon = _proof(id_hex, 1, b1, _batch())
    bidon["new_batch_signature"] = "ab" * 64
    autre = client.post("/auth/v2/rotate-batch", json=bidon)
    assert autre.status_code == 401, autre.text

    # Indistinguables : c'est l'ambiguïté que le client ne peut pas lever.
    assert rejeu.status_code == autre.status_code
    assert rejeu.text == autre.text
    # Et le compteur serveur ne fuit pas au passage.
    assert "batch" not in rejeu.text.lower()


# --- 3. une chaîne rejouée dans l'ordre rattrape en une passe ---------------

def test_replaying_a_chain_in_order_catches_the_relay_up(client):
    """L'appareil a avancé trois fois sans qu'aucune rotation n'arrive. Rejouer
    la file du plus ancien au plus récent remet le relais à niveau d'un coup."""
    id_hex, batch0 = _enroll(client)
    b1, b2, b3 = _batch(), _batch(), _batch()
    file_attente = [
        _proof(id_hex, 0, batch0, b1),
        _proof(id_hex, 1, b1, b2),
        _proof(id_hex, 2, b2, b3),
    ]
    assert _server_batch(id_hex) == 0

    for i, p in enumerate(file_attente):
        r = client.post("/auth/v2/rotate-batch", json=p)
        assert r.status_code == 200, "preuve %d refusée : %s" % (i, r.text)
        assert r.json()["new_batch_number"] == i + 1

    assert _server_batch(id_hex) == 3


# --- 4. contrôle négatif : à l'envers, la même chaîne ne rattrape pas -------

def test_replaying_the_same_chain_newest_first_does_not_catch_up(client):
    """Mêmes preuves, ordre inverse : une seule passe.

    Chaque preuve n'est valable que depuis le batch dont elle part, donc les
    deux plus récentes arrivent trop tôt et sont refusées. Le relais finit sur 1
    au lieu de 3, et les preuves 1->2 et 2->3 restent à renvoyer. C'est ce qui
    rend l'ordre de `retryPendingRotations` porteur : sans lui la file finit par
    passer, mais il faut une auth par cran, et chacune brûle un slot.
    """
    id_hex, batch0 = _enroll(client)
    b1, b2, b3 = _batch(), _batch(), _batch()
    a_lenvers = [
        _proof(id_hex, 2, b2, b3),
        _proof(id_hex, 1, b1, b2),
        _proof(id_hex, 0, batch0, b1),
    ]
    codes = [client.post("/auth/v2/rotate-batch", json=p).status_code
             for p in a_lenvers]

    assert codes == [401, 401, 200], codes
    assert _server_batch(id_hex) == 1
