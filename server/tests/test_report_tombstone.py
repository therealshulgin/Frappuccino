#!/usr/bin/env python3
"""
A closed report outlives its objects: the reaper keeps its record as a
tombstone instead of deleting it.

The reaper deletes the record of a report whose objects have all been purged at
the blob TTL. For an open report that is the whole point. For a closed one it
would forget the closure, and a creating PUT would then rebuild the record
open: names the signed closure refused would be accepted again. So a closed
record with nothing left becomes a tombstone, which refuses every write, and the
archive answers 404 for it, as for a report the relay never knew.

The reaper also lists blobs without the registry lock. A closure recorded
between its count and its decision stores a `manifest`, so the report is no
longer empty; the record must come out of that pass untouched, closure
included, instead of being deleted after the client already got 204.

Storage is the real `app.storage` over the in-memory MinIO of conftest.py; an
object purged at the TTL is simply removed from it.
"""

import hashlib
import json
import os
import struct
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
from app import auth, config, main, ratchet_registry, storage  # noqa: E402
from app.routes import reports as reports_mod  # noqa: E402

CTX_ID = b"stream.report.id.v1"
CLOSED = {"detail": "Report closed"}


def _key():
    sk = nacl.signing.SigningKey.generate()
    pk = bytes(sk.verify_key)
    return sk, pk, hashlib.sha256(CTX_ID + pk).digest()[:16].hex()


def _sha(body: bytes) -> bytes:
    return hashlib.sha256(body).digest()


def _put(client, sk, pk, rid, name, body, creating=False):
    headers = {
        "X-Report-PK": pk.hex(),
        "X-Report-Write-Sig": sk.sign(
            b"\x08" + bytes.fromhex(rid) + name.encode() + _sha(body)
        ).signature.hex(),
    }
    if creating:
        headers["X-Report-Create-Sig"] = sk.sign(
            b"\x07" + bytes.fromhex(rid) + pk
        ).signature.hex()
        headers["Authorization"] = f"Bearer {auth.create_jwt('aa' * 32)}"
    return client.put(f"/file/{rid}/{name}", content=body, headers=headers)


def _manifest(blobs: dict[int, bytes]) -> bytes:
    """`FQM1 || u32 count || count x (u32 seq || sha256(blob))`."""
    out = b"FQM1" + struct.pack(">I", len(blobs))
    for seq in sorted(blobs):
        out += struct.pack(">I", seq) + _sha(blobs[seq])
    return out


def _close(client, sk, pk, rid, manifest: bytes, seq_limit: int):
    sig = sk.sign(
        b"\x09" + bytes.fromhex(rid) + struct.pack(">I", seq_limit) + _sha(manifest)
    ).signature
    return client.post(
        f"/close/{rid}",
        content=manifest,
        headers={
            "X-Report-PK": pk.hex(),
            "X-Report-Close-Sig": sig.hex(),
            "X-Report-Close-Seq-Limit": str(seq_limit),
        },
    )


def _purge(minio, rid: str):
    """What the blob TTL does: every object of the report is gone."""
    for path in [p for p in minio.objects if p.startswith(rid + "/")]:
        del minio.objects[path]


@pytest.fixture()
def relay(fake_minio, monkeypatch):
    reports_mod._reset_for_test()
    monkeypatch.setattr(ratchet_registry, "reserve_report_creation", lambda s, m: True)
    monkeypatch.setattr(ratchet_registry, "release_report_creation", lambda s: None)
    yield TestClient(main.app), fake_minio
    reports_mod._reset_for_test()


def _closed_report(client):
    """A chained report with objects 0 and 1, closed with seq_limit 3 (seq 2 is
    covered by the closure but never arrived)."""
    sk, pk, rid = _key()
    blobs = {0: b"metadata", 1: b"chunk one"}
    assert _put(client, sk, pk, rid, "000000.strm", blobs[0], creating=True).status_code == 204
    assert _put(client, sk, pk, rid, "000001.strm", blobs[1]).status_code == 204
    assert _close(client, sk, pk, rid, _manifest(blobs), 3).status_code == 204
    return sk, pk, rid


def test_an_emptied_closed_report_becomes_a_tombstone(relay):
    client, minio = relay
    sk, pk, rid = _closed_report(client)
    closure = reports_mod.get_report(rid)["closure"]
    _purge(minio, rid)

    deleted, remaining = reports_mod.reap_blobless_reports()

    assert (deleted, remaining) == (0, 1)
    record = reports_mod.get_report(rid)
    assert record["closure"] == closure, "the closure is kept as it was signed"
    assert reports_mod.is_tombstone(record)
    on_disk = json.loads(Path(config.REPORTS_DB_PATH).read_text(encoding="utf-8"))
    assert on_disk[rid]["tombstone"] is True
    # A later pass leaves it as it is.
    assert reports_mod.reap_blobless_reports() == (0, 1)
    assert reports_mod.get_report(rid) == record


def test_a_tombstone_refuses_every_write_and_cannot_be_reopened(relay):
    client, minio = relay
    sk, pk, rid = _closed_report(client)
    _purge(minio, rid)
    reports_mod.reap_blobless_reports()

    # seq 2 was covered by the closure; seq 0 existed; neither comes back.
    for name in ["000002.strm", "000000.strm", "000009.strm"]:
        r = _put(client, sk, pk, rid, name, b"late")
        assert (r.status_code, r.json()) == (409, CLOSED), name
        r = _put(client, sk, pk, rid, name, b"late", creating=True)
        assert (r.status_code, r.json()) == (409, CLOSED), name
    assert not [p for p in minio.objects if p.startswith(rid + "/")]
    assert reports_mod.get_report(rid).get("closure") is not None
    # Nothing to rescue: the same answer as for an unknown report.
    assert client.get(f"/api/v2/archive/reports/{rid}/blobs").status_code == 404


def test_a_closed_report_with_objects_left_is_not_a_tombstone(relay):
    client, minio = relay
    sk, pk, rid = _closed_report(client)
    # The chunks expired, the manifest (written last) is still there.
    for name in ["000000.strm", "000001.strm"]:
        del minio.objects[f"{rid}/{name}"]
    assert reports_mod.reap_blobless_reports() == (0, 1)
    assert not reports_mod.is_tombstone(reports_mod.get_report(rid))
    # Its closure still admits the covered name that never arrived.
    assert _put(client, sk, pk, rid, "000002.strm", b"late").status_code == 204


def test_a_closure_recorded_during_the_reap_survives_it(relay, monkeypatch):
    """The reaper counts an open report at zero objects; a closure lands before
    its decision. The client got 204: the closure must not be forgotten."""
    client, minio = relay
    sk, pk, rid = _key()
    name = "2115607e_000000.strm"
    assert _put(client, sk, pk, rid, name, b"old", creating=True).status_code == 204
    _purge(minio, rid)
    legacy_closure = b"FQM1\x00\x00\x00\x00"
    real_list = storage.list_blobs
    codes = []

    def list_then_close(report_id):
        listed = real_list(report_id)
        if report_id == rid and not codes:
            codes.append(_close(client, sk, pk, rid, legacy_closure, 0).status_code)
        return listed

    monkeypatch.setattr(storage, "list_blobs", list_then_close)
    deleted, remaining = reports_mod.reap_blobless_reports()

    assert codes == [204]
    assert (deleted, remaining) == (0, 1)
    record = reports_mod.get_report(rid)
    assert record["closure"]["seq_limit"] == 0
    assert not reports_mod.is_tombstone(record)
    r = _put(client, sk, pk, rid, "2115607e_000001.strm", b"new", creating=True)
    assert (r.status_code, r.json()) == (409, CLOSED)
