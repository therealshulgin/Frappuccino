#!/usr/bin/env python3
"""
test_rotate_batch_oracle.py — `POST /auth/v2/rotate-batch` ne doit pas être un
oracle d'existence, de révocation ni d'activité par identité.

Vérifier la signature d'abord, puis fusionner tous les échecs — état comme
signature — en un unique `401 "Rotation rejected"`, en miroir de
`/auth/v2/verify`. L'ordre fait tout le travail : la signature ne dépend que de
l'input de l'appelant, l'état dépend de l'identité visée, donc brancher sur
l'état avant la vérif fait parler la route. C'est ce qu'elle faisait, avec
quatre réponses distinctes :
  - 404 "Identity not enrolled"           → révèle l'enrôlement
  - 403 "Identity revoked"                → révèle la révocation
  - 409 "Batch number mismatch: server=N" → fuite le compteur de batch serveur
  - 400 "Signer public key mismatch"      → confirme l'appartenance d'une pk

soit exactement l'oracle identité→activité que le retrait de `get_status`
(R-SRV-1 / BT-05) visait à supprimer.

Rendre ces erreurs « plus utiles » le rouvrirait, et c'est le réflexe naturel.
D'où des tests qui exigent des rejets byte-identiques — même status, même corps,
donc indistinguables — et un corps qui ne laisse jamais filtrer le batch_number
du serveur ; le chemin légitime, lui, doit continuer à répondre 200.
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
    """Enrôle une identité fraîche, retourne (id_hex, batch0 pairs)."""
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


def _rotate_body(id_hex, signer_batch, signer_idx, signer_pk_hex, new_batch, sk_for_sig):
    """Construit un corps de rotation ; `sk_for_sig` signe concat(new pks)."""
    sig = _sign(sk_for_sig, SIG_DOMAIN_BATCH_ROTATION + _concat(new_batch)).hex()
    return {
        "ed25519_pk": id_hex,
        "signer_batch_number": signer_batch,
        "signer_key_index": signer_idx,
        "signer_public_key": signer_pk_hex,
        "new_batch_public_keys": [p[0].hex() for p in new_batch],
        "new_batch_signature": sig,
    }


GENERIC_REJECT = {"detail": "Rotation rejected"}


# --- 1. le chemin légitime marche toujours ----------------------------------

def test_rotate_happy_path_still_returns_200(client):
    id_hex, batch0 = _enroll(client)
    new_batch = _batch()
    body = _rotate_body(id_hex, 0, 49, batch0[49][0].hex(), new_batch, batch0[49][1])
    r = client.post("/auth/v2/rotate-batch", json=body)
    assert r.status_code == 200, r.text
    assert r.json()["new_batch_number"] == 1


# --- 2. le batch_number serveur ne fuit JAMAIS dans un rejet ----------------

def test_stale_batch_does_not_leak_server_batch_number(client):
    id_hex, batch0 = _enroll(client)
    # Rotation légitime 0 -> 1 pour que le serveur soit au batch 1.
    b1 = _batch()
    ok = client.post("/auth/v2/rotate-batch",
                     json=_rotate_body(id_hex, 0, 49, batch0[49][0].hex(), b1, batch0[49][1]))
    assert ok.status_code == 200 and ok.json()["new_batch_number"] == 1

    # Un prober rejoue une rotation avec le batch PÉRIMÉ 0 (slot déjà consommé).
    b2 = _batch()
    r = client.post("/auth/v2/rotate-batch",
                    json=_rotate_body(id_hex, 0, 48, batch0[48][0].hex(), b2, batch0[48][1]))
    assert r.status_code == 401, r.text
    assert r.json() == GENERIC_REJECT
    # Le corps ne doit RIEN révéler du compteur serveur courant (1).
    assert "server=" not in r.text
    assert "batch" not in r.text.lower()
    assert "1" not in r.json()["detail"]


# --- 3. tous les rejets état/signature sont byte-identiques -----------------

def test_all_state_and_signature_rejections_are_indistinguishable(client):
    """Le cœur de la fermeture d'oracle : unenrolled / revoked / wrong-batch /
    bad-signature / wrong-signer-pk doivent produire une réponse IDENTIQUE
    (status + corps). 5 appels rotate = pile la limite 5/min."""
    id_hex, batch0 = _enroll(client)

    responses = []

    # (a) identité jamais enrôlée — signée par sa propre paire (self-sig valide)
    other_pk, other_sk = _keypair()
    nb = _batch()
    responses.append(client.post(
        "/auth/v2/rotate-batch",
        json=_rotate_body(other_pk.hex(), 0, 0, nb[0][0].hex(), nb, nb[0][1])))

    # (b) mauvais signer pk (ne matche pas batch_keys[idx]) — self-sig valide
    stray_pk, stray_sk = _keypair()
    nb = _batch()
    responses.append(client.post(
        "/auth/v2/rotate-batch",
        json=_rotate_body(id_hex, 0, 0, stray_pk.hex(), nb, stray_sk)))

    # (c) signature invalide (bon signer pk, sig bidon)
    nb = _batch()
    body = _rotate_body(id_hex, 0, 1, batch0[1][0].hex(), nb, batch0[1][1])
    body["new_batch_signature"] = "ab" * 64
    responses.append(client.post("/auth/v2/rotate-batch", json=body))

    # (d) mauvais batch_number (le vrai est 0)
    nb = _batch()
    responses.append(client.post(
        "/auth/v2/rotate-batch",
        json=_rotate_body(id_hex, 7, 2, batch0[2][0].hex(), nb, batch0[2][1])))

    # (e) identité révoquée
    ratchet_registry.revoke(id_hex)
    nb = _batch()
    responses.append(client.post(
        "/auth/v2/rotate-batch",
        json=_rotate_body(id_hex, 0, 3, batch0[3][0].hex(), nb, batch0[3][1])))

    for r in responses:
        assert r.status_code == 401, r.text
        assert r.json() == GENERIC_REJECT, r.text

    # Indistinguables : un seul status + un seul corps sur les 5 chemins.
    assert len({r.status_code for r in responses}) == 1
    assert len({r.text for r in responses}) == 1


# --- 4. les erreurs de FORMAT restent distinctes (input appelant, pas état) --

def test_format_errors_stay_400_they_do_not_leak_identity_state(client):
    """Un mauvais nombre de clés ne dépend que de l'input de l'appelant : il
    peut rester un 400 explicite sans divulguer l'état d'une identité cible."""
    id_hex, batch0 = _enroll(client)
    short = _batch(10)  # != BATCH_SIZE
    body = _rotate_body(id_hex, 0, 0, batch0[0][0].hex(), short, batch0[0][1])
    r = client.post("/auth/v2/rotate-batch", json=body)
    assert r.status_code == 400, r.text
