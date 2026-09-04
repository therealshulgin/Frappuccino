#!/usr/bin/env python3
"""
Surface hardening of the relay-blind auth routes: what must stay gone, and what
must stay.

``POST /auth/verify`` minted a scopeless JWT with no ratchet involved (audit
A-2), and the V1 invite registration ``POST /auth/invite/verify`` went with it.
Reintroducing either reopens an authentication path that bypasses the ratchet
entirely, which is why the tests demand a 404/405 and not "the route moved".

``POST /auth/challenge``, on the other hand, must SURVIVE the V1 removal: it is
shared with the V2 ratchet flow.

A 422 must never echo the submitted value back (E-1). A malformed pk repeated
in the response body is a pk that also lands in the relay's logs, so the
handler scrubs each error down to loc + type.
"""

import os
import sys
import tempfile
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

os.environ["JWT_SECRET"] = "test-secret-do-not-use"
_tmp = tempfile.mkdtemp()
os.environ.setdefault("RATCHET_REGISTRY_FILE", os.path.join(_tmp, "registry.json"))
os.environ.setdefault("REPORTS_DB_PATH", os.path.join(_tmp, "reports.json"))

from fastapi.testclient import TestClient  # noqa: E402
from app import main  # noqa: E402


@pytest.fixture()
def client():
    return TestClient(main.app)


def test_v1_verify_endpoint_removed(client):
    # The non-ratchet scopeless-JWT creation path (audit A-2) is gone.
    r = client.post(
        "/auth/verify",
        json={"ed25519_pk": "a" * 64, "nonce": "b" * 64, "timestamp": 1, "signature": "c" * 128},
    )
    assert r.status_code in (404, 405)


def test_v1_invite_endpoint_removed(client):
    r = client.post("/auth/invite/verify", json={"code": "x", "ed25519_pk": "a" * 64})
    assert r.status_code in (404, 405)


def test_challenge_still_available(client):
    # /auth/challenge is shared with the V2 flow and must survive V1 removal.
    r = client.post("/auth/challenge")
    assert r.status_code == 200
    body = r.json()
    assert "nonce" in body and "timestamp" in body


def test_422_does_not_echo_malformed_input(client):
    # E-1 — a malformed pk must NOT be echoed back in the 422 body.
    bad_pk = "z" * 64  # 64 chars but not hex -> fails the Hex64 pattern
    r = client.post(
        "/auth/v2/enroll",
        json={
            "ed25519_pk": bad_pk,
            "batch_0_public_keys": ["a" * 64] * 50,
            "batch_0_signature": "c" * 128,
        },
    )
    assert r.status_code == 422
    assert bad_pk not in r.text
    # Scrubbed shape: loc + type only, never input / msg / url.
    detail = r.json()["detail"]
    assert all(set(e.keys()) <= {"loc", "type"} for e in detail)
