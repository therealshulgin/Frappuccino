#!/usr/bin/env python3
"""
test_upload_write_once_route.py — §10.6 write-once, as the upload route maps it
to HTTP, end to end through TestClient on the relay-blind capability path (a
creating chunk carries X-Report-PK, create and write signatures, and a stream
JWT).

A capability that leaked must not be able to overwrite a stored chunk with
different bytes: that is what the 409 is for, not a stylistic pick of status
code. Its counterpart, the identical re-PUT that still answers 204, is
load-bearing for a reason of its own, given at test_put_identical_returns_204
and in test_storage_write_once.py. A full disk keeps its 507.

The report key is a random Ed25519 pair on purpose: the relay verifies the
report_id <-> report_pk binding and the signatures, never the seed derivation,
so a test needs no BIP-39 to hold a valid capability — which does not mean the
relay has a say in how a report key was derived. The anti-abuse budget is
monkeypatched to allow (covered separately) and storage is stubbed, so no MinIO
is needed.
"""

import hashlib
import os
import sys
import tempfile
from pathlib import Path

import nacl.signing
import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

os.environ["JWT_SECRET"] = "test-secret-do-not-use"
_tmp = tempfile.mkdtemp()
os.environ.setdefault("RATCHET_REGISTRY_FILE", os.path.join(_tmp, "registry.json"))
os.environ.setdefault("REPORTS_DB_PATH", os.path.join(_tmp, "reports.json"))

from fastapi.testclient import TestClient  # noqa: E402
from app import auth, main, ratchet_registry, storage  # noqa: E402
from app.routes import reports as reports_mod  # noqa: E402

DOM_CREATE = b"\x07"
DOM_WRITE = b"\x08"


def _new_key():
    sk = nacl.signing.SigningKey.generate()
    pk = bytes(sk.verify_key)
    rid = hashlib.sha256(b"stream.report.id.v1" + pk).digest()[:16].hex()
    return sk, pk, rid


def _creating_headers(sk, pk, rid, filename, body):
    create_sig = sk.sign(DOM_CREATE + bytes.fromhex(rid) + pk).signature
    write_sig = sk.sign(
        DOM_WRITE + bytes.fromhex(rid) + filename.encode() + hashlib.sha256(body).digest()
    ).signature
    return {
        "X-Report-PK": pk.hex(),
        "X-Report-Create-Sig": create_sig.hex(),
        "X-Report-Write-Sig": write_sig.hex(),
        "Authorization": f"Bearer {auth.create_jwt('aa' * 32)}",
    }


@pytest.fixture()
def client(monkeypatch):
    reports_mod._reset_for_test()
    # The creation gate now RESERVES atomically (reserve_report_creation) and
    # rolls back on failure (release_report_creation); patch both to no-ops here.
    monkeypatch.setattr(ratchet_registry, "reserve_report_creation", lambda sub, mx: True)
    monkeypatch.setattr(ratchet_registry, "release_report_creation", lambda sub: None)
    try:
        yield TestClient(main.app)
    finally:
        reports_mod._reset_for_test()


def _put(client, monkeypatch, store_result_or_exc, body=b"sealed-bytes"):
    sk, pk, rid = _new_key()

    def _store(*a, **k):
        if isinstance(store_result_or_exc, Exception):
            raise store_result_or_exc
        return store_result_or_exc

    monkeypatch.setattr(storage, "upload_blob_stream_write_once", _store)
    return client.put(
        f"/file/{rid}/chunk_1.strm",
        content=body,
        headers=_creating_headers(sk, pk, rid, "chunk_1.strm", body),
    )


def test_put_created_returns_204(client, monkeypatch):
    assert _put(client, monkeypatch, "created").status_code == 204


def test_put_identical_returns_204(client, monkeypatch):
    # The load-bearing case: a legit retry / race re-PUTs identical bytes and
    # MUST still succeed, never a 409.
    assert _put(client, monkeypatch, "identical").status_code == 204


def test_put_conflict_returns_409(client, monkeypatch):
    assert _put(client, monkeypatch, storage.WriteOnceConflictError("differs")).status_code == 409


def test_put_disk_full_returns_507(client, monkeypatch):
    assert _put(client, monkeypatch, storage.StorageFullError("full")).status_code == 507


def test_put_empty_body_rejected_400(client, monkeypatch):
    # Phase C — an empty body cannot anchor a report (no durable blob), so it is
    # rejected before storage is ever called (the blob-first invariant).
    called = {"n": 0}

    def _spy(*a, **k):
        called["n"] += 1
        return "created"

    monkeypatch.setattr(storage, "upload_blob_stream_write_once", _spy)
    sk, pk, rid = _new_key()
    r = client.put(
        f"/file/{rid}/chunk_1.strm",
        content=b"",
        headers=_creating_headers(sk, pk, rid, "chunk_1.strm", b""),
    )
    assert r.status_code == 400
    assert called["n"] == 0
