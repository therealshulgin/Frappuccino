#!/usr/bin/env python3
"""
Archive reads carry no token, and that is deliberate: knowing the 128-bit
report_id IS the read capability. There is no archive-scope JWT and no
`/api/v2/archive/auth` challenge any more, precisely so that the relay holds no
at-rest `identity -> reports` join (the reasoning is in the module docstring of
app/routes/archive.py). "Repairing" these routes by putting a token back on them
rebuilds that join. A record is otherwise gated by its existence alone (404 on
unknown), and report_id is strictly validated as 32 lowercase hex.

This file locks the archive-route specifics — storage payload passthrough (the
closure in the listing, the stored write signature as a header),
strict validation, the 404 cases — with storage mocked (no MinIO). The full
capability flow is covered in test_relay_blind_reports.py.
"""

import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

os.environ["JWT_SECRET"] = "test-secret-do-not-use"
_tmp = tempfile.mkdtemp()
os.environ.setdefault("REPORTS_DB_PATH", os.path.join(_tmp, "reports.json"))

from fastapi.testclient import TestClient  # noqa: E402
from app import main, storage  # noqa: E402
from app.routes import reports as reports_mod  # noqa: E402

VALID_RID = "a" * 32  # 32 lowercase hex chars


def _seed(rid: str, pk_hex: str = "bb" * 32):
    with reports_mod._reports_lock:
        reports_mod._reports[rid] = {"report_id": rid, "report_pk": pk_hex}
        reports_mod._save_reports_locked()


@pytest.fixture()
def client():
    reports_mod._reset_for_test()
    try:
        yield TestClient(main.app)
    finally:
        reports_mod._reset_for_test()


def test_list_blobs_identity_free_passthrough(client):
    _seed(VALID_RID)
    fake = [{"filename": "chunk_1.strm", "size": 2048, "last_modified": "2026-05-10T10:00:00"}]
    with patch("app.routes.archive.storage.list_blobs", return_value=fake):
        resp = client.get(f"/api/v2/archive/reports/{VALID_RID}/blobs")  # no token
    assert resp.status_code == 200
    # An open report lists its closure as null; the key is always present.
    assert resp.json() == {"blobs": fake, "closure": None}


def test_list_blobs_serves_the_recorded_closure(client):
    _seed(VALID_RID)
    closure = {"seq_limit": 3, "manifest_sha256": "cd" * 32, "sig": "ef" * 64}
    with reports_mod._reports_lock:
        reports_mod._reports[VALID_RID]["closure"] = dict(closure)
    with patch("app.routes.archive.storage.list_blobs", return_value=[]):
        resp = client.get(f"/api/v2/archive/reports/{VALID_RID}/blobs")
    assert resp.status_code == 200
    assert resp.json() == {"blobs": [], "closure": closure}


def test_list_blobs_404_for_unknown_report(client):
    resp = client.get(f"/api/v2/archive/reports/{'0' * 32}/blobs")
    assert resp.status_code == 404


def test_invalid_report_id_returns_400(client):
    # Non-hex / wrong length is rejected by the strict ^[a-f0-9]{32}$ guard.
    resp = client.get("/api/v2/archive/reports/NOTHEXNOTHEXNOTHEXNOTHEXNOTHEX99/blobs")
    assert resp.status_code == 400


def test_download_blob_streams_content(client):
    _seed(VALID_RID)
    with patch("app.routes.archive.storage.stat_blob",
               return_value=storage.BlobInfo(size=128, write_sig_hex=None)), \
         patch("app.routes.archive.storage.iter_blob",
               return_value=iter([b"X" * 64, b"Y" * 64])):
        resp = client.get(f"/api/v2/archive/reports/{VALID_RID}/chunk_1.strm")
    assert resp.status_code == 200
    assert resp.headers["Content-Length"] == "128"
    assert resp.content == b"X" * 64 + b"Y" * 64
    # No stored signature, no header: never an empty or placeholder value.
    assert "X-Report-Write-Sig" not in resp.headers


def test_download_blob_carries_the_stored_write_sig(client):
    _seed(VALID_RID)
    sig = "ab" * 64
    with patch("app.routes.archive.storage.stat_blob",
               return_value=storage.BlobInfo(size=4, write_sig_hex=sig)), \
         patch("app.routes.archive.storage.iter_blob", return_value=iter([b"DATA"])):
        resp = client.get(f"/api/v2/archive/reports/{VALID_RID}/000001.strm")
    assert resp.status_code == 200
    assert resp.headers["X-Report-Write-Sig"] == sig


def test_download_blob_404_when_blob_missing(client):
    _seed(VALID_RID)
    with patch("app.routes.archive.storage.stat_blob", return_value=None):
        resp = client.get(f"/api/v2/archive/reports/{VALID_RID}/missing.strm")
    assert resp.status_code == 404


def test_download_blob_404_when_report_unknown(client):
    # Even with a blob present in storage, an unknown record 404s at the gate.
    with patch("app.routes.archive.storage.stat_blob",
               return_value=storage.BlobInfo(size=4, write_sig_hex=None)):
        resp = client.get(f"/api/v2/archive/reports/{'0' * 32}/x.strm")
    assert resp.status_code == 404
