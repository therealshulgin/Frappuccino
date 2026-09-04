#!/usr/bin/env python3
"""
End-to-end proof of the relay-blind authz for capability-addressed upload and
archive reads (TestClient, storage mocked, no MinIO).

Everything here turns on lazy blob-first creation, and on its order: the record
is written only AFTER its first chunk is durably stored, and it holds nothing
but report_id -> report_pk, no identity. That order is what makes the 425 on a
"subsequent" chunk for an absent record a correct answer rather than a retry
bug — and nothing is stored on the way, so a writer holding neither a create-sig
nor a bearer cannot park bytes under a record that does not exist. That same
order is what the archive's 404-on-unknown and the timestamp-free reaper of
test_report_cleanup.py stand on.

A report key is just a random Ed25519 keypair here. The relay verifies the
report_id <-> report_pk binding — report_id == SHA-256("stream.report.id.v1" ||
report_pk)[..16], a self-authenticating address — plus the create (0x07) and
write (0x08) signatures under report_pk. It never verifies the seed derivation,
so the test needs no BIP-39 chain; wiring one in would not make it more
faithful, only suggest the relay controls a derivation it never sees.

Also locked below: the anti-abuse budget's 429, and archive reads that carry no
token and 404 on an unknown record.
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

CTX_ID = b"stream.report.id.v1"
DOM_CREATE = b"\x07"
DOM_WRITE = b"\x08"


# --- report capability key helpers (mirror crypto-rs/core/src/report.rs) ----

def new_report_key():
    sk = nacl.signing.SigningKey.generate()
    pk = bytes(sk.verify_key)
    rid = hashlib.sha256(CTX_ID + pk).digest()[:16]
    return sk, pk, rid.hex()


def sig_create(sk, rid_hex, pk):
    return sk.sign(DOM_CREATE + bytes.fromhex(rid_hex) + pk).signature


def sig_write(sk, rid_hex, filename, body):
    msg = DOM_WRITE + bytes.fromhex(rid_hex) + filename.encode() + hashlib.sha256(body).digest()
    return sk.sign(msg).signature


def creating_headers(sk, pk, rid_hex, filename, body, jwt_sub="aa" * 32):
    return {
        "X-Report-PK": pk.hex(),
        "X-Report-Write-Sig": sig_write(sk, rid_hex, filename, body).hex(),
        "X-Report-Create-Sig": sig_create(sk, rid_hex, pk).hex(),
        "Authorization": f"Bearer {auth.create_jwt(jwt_sub)}",
    }


def writing_headers(sk, pk, rid_hex, filename, body):
    return {
        "X-Report-PK": pk.hex(),
        "X-Report-Write-Sig": sig_write(sk, rid_hex, filename, body).hex(),
    }


# --- in-memory storage fake (backs every storage.* the routes call) ---------

class FakeStore:
    def __init__(self):
        self.blobs: dict[tuple[str, str], bytes] = {}

    def put(self, report_id, filename, fp, total, digest):
        data = fp.read()
        key = (report_id, filename)
        if key in self.blobs and self.blobs[key] != data:
            raise storage.WriteOnceConflictError("differs")
        self.blobs[key] = data
        return "created"

    def list_blobs(self, rid):
        return [
            {"filename": f, "size": len(b), "last_modified": None}
            for (r, f), b in self.blobs.items()
            if r == rid
        ]

    def blob_exists(self, rid, fn):
        return (rid, fn) in self.blobs

    def get_blob_size(self, rid, fn):
        return len(self.blobs.get((rid, fn), b""))

    def iter_blob(self, rid, fn):
        yield self.blobs[(rid, fn)]


@pytest.fixture()
def env(monkeypatch):
    reports_mod._reset_for_test()
    store = FakeStore()
    monkeypatch.setattr(storage, "upload_blob_stream_write_once", store.put)
    monkeypatch.setattr(storage, "list_blobs", store.list_blobs)
    monkeypatch.setattr(storage, "blob_exists", store.blob_exists)
    monkeypatch.setattr(storage, "get_blob_size", store.get_blob_size)
    monkeypatch.setattr(storage, "iter_blob", store.iter_blob)
    # Budget allowed by default (the budget itself is covered separately). The
    # gate now RESERVES atomically via reserve_report_creation (rolled back via
    # release_report_creation on failure) — patch both to no-ops so the route
    # never touches the real registry here.
    monkeypatch.setattr(ratchet_registry, "reserve_report_creation", lambda sub, mx: True)
    monkeypatch.setattr(ratchet_registry, "release_report_creation", lambda sub: None)
    client = TestClient(main.app)
    try:
        yield client, store
    finally:
        reports_mod._reset_for_test()


# ---------------------------------------------------------------------------
# Creation (blob-first, lazy)
# ---------------------------------------------------------------------------

def test_creating_chunk_stores_blob_then_record(env):
    client, store = env
    sk, pk, rid = new_report_key()
    body = b"sealed-strm-bytes"
    r = client.put(
        f"/file/{rid}/chunk_0.strm",
        content=body,
        headers=creating_headers(sk, pk, rid, "chunk_0.strm", body),
    )
    assert r.status_code == 204
    # Record written, identity-free: only report_id -> report_pk.
    rec = reports_mod.get_report(rid)
    assert rec == {"report_id": rid, "report_pk": pk.hex()}
    assert "owner" not in rec and "author" not in rec and "createdAt" not in rec
    # Blob is durable.
    assert store.blobs[(rid, "chunk_0.strm")] == body


def test_report_id_must_match_report_pk(env):
    client, _ = env
    sk, pk, rid = new_report_key()
    other_rid = "f" * 32  # not H(report_pk)
    body = b"x"
    r = client.put(
        f"/file/{other_rid}/chunk_0.strm",
        content=body,
        headers=creating_headers(sk, pk, other_rid, "chunk_0.strm", body),
    )
    assert r.status_code == 400


def test_bad_create_sig_rejected_403(env):
    client, _ = env
    sk, pk, rid = new_report_key()
    other_sk, _, _ = new_report_key()
    body = b"x"
    headers = creating_headers(sk, pk, rid, "chunk_0.strm", body)
    headers["X-Report-Create-Sig"] = sig_create(other_sk, rid, pk).hex()  # wrong signer
    r = client.put(f"/file/{rid}/chunk_0.strm", content=body, headers=headers)
    assert r.status_code == 403


def test_bad_write_sig_rejected_403(env):
    client, _ = env
    sk, pk, rid = new_report_key()
    body = b"x"
    headers = creating_headers(sk, pk, rid, "chunk_0.strm", body)
    headers["X-Report-Write-Sig"] = sig_write(sk, rid, "chunk_0.strm", b"different").hex()
    r = client.put(f"/file/{rid}/chunk_0.strm", content=body, headers=headers)
    assert r.status_code == 403


def test_empty_body_rejected_400(env):
    client, store = env
    sk, pk, rid = new_report_key()
    r = client.put(
        f"/file/{rid}/chunk_0.strm",
        content=b"",
        headers=creating_headers(sk, pk, rid, "chunk_0.strm", b""),
    )
    assert r.status_code == 400
    assert store.blobs == {}


def test_budget_exhausted_rejected_429(env, monkeypatch):
    client, _ = env
    # The gate reserves via reserve_report_creation; over-budget => False => 429.
    monkeypatch.setattr(ratchet_registry, "reserve_report_creation", lambda sub, mx: False)
    sk, pk, rid = new_report_key()
    body = b"x"
    r = client.put(
        f"/file/{rid}/chunk_0.strm",
        content=body,
        headers=creating_headers(sk, pk, rid, "chunk_0.strm", body),
    )
    assert r.status_code == 429


# ---------------------------------------------------------------------------
# Subsequent chunks
# ---------------------------------------------------------------------------

def test_subsequent_chunk_after_creation_204(env):
    client, _ = env
    sk, pk, rid = new_report_key()
    b0, b1 = b"chunk-zero", b"chunk-one"
    client.put(f"/file/{rid}/c0.strm", content=b0, headers=creating_headers(sk, pk, rid, "c0.strm", b0))
    r = client.put(f"/file/{rid}/c1.strm", content=b1, headers=writing_headers(sk, pk, rid, "c1.strm", b1))
    assert r.status_code == 204


def test_subsequent_chunk_before_creation_returns_425(env):
    client, store = env
    sk, pk, rid = new_report_key()
    body = b"orphan-first"
    # No create-sig + no Authorization → record absent → 425, nothing stored.
    r = client.put(f"/file/{rid}/c1.strm", content=body, headers=writing_headers(sk, pk, rid, "c1.strm", body))
    assert r.status_code == 425
    assert store.blobs == {}
    assert reports_mod.get_report(rid) is None


# ---------------------------------------------------------------------------
# Archive reads — identity-free, 404 on unknown record
# ---------------------------------------------------------------------------

def test_archive_list_blobs_identity_free(env):
    client, _ = env
    sk, pk, rid = new_report_key()
    body = b"sealed"
    client.put(f"/file/{rid}/c0.strm", content=body, headers=creating_headers(sk, pk, rid, "c0.strm", body))
    # No token at all.
    r = client.get(f"/api/v2/archive/reports/{rid}/blobs")
    assert r.status_code == 200
    names = [b["filename"] for b in r.json()["blobs"]]
    assert names == ["c0.strm"]


def test_archive_unknown_report_404(env):
    client, _ = env
    rid = "0" * 32  # valid shape, never created
    r = client.get(f"/api/v2/archive/reports/{rid}/blobs")
    assert r.status_code == 404


def test_archive_download_blob_identity_free(env):
    client, _ = env
    sk, pk, rid = new_report_key()
    body = b"sealed-download"
    client.put(f"/file/{rid}/c0.strm", content=body, headers=creating_headers(sk, pk, rid, "c0.strm", body))
    r = client.get(f"/api/v2/archive/reports/{rid}/c0.strm")
    assert r.status_code == 200
    assert r.content == body


def test_archive_auth_endpoint_is_gone(env):
    client, _ = env
    # The POST /api/v2/archive/auth endpoint no longer exists.
    r = client.post("/api/v2/archive/auth", json={})
    assert r.status_code in (404, 405)


# ---------------------------------------------------------------------------
# Anti-abuse budget — the real registry counter
# ---------------------------------------------------------------------------

def test_reserve_report_creation_budget(monkeypatch):
    # Exercise the real per-(identity, batch) atomic reservation (not the route
    # monkeypatch). reserve increments; over budget returns False.
    pk_hex = "bb" * 32
    ratchet_registry._clear_for_tests()
    ratchet_registry.enroll(pk_hex, [f"{i:064x}" for i in range(50)], "00" * 64)
    assert ratchet_registry.reserve_report_creation(pk_hex, 2) is True
    assert ratchet_registry.reserve_report_creation(pk_hex, 2) is True
    assert ratchet_registry.reserve_report_creation(pk_hex, 2) is False  # budget hit
    # An unknown identity is never allowed.
    assert ratchet_registry.reserve_report_creation("cc" * 32, 2) is False
    ratchet_registry._clear_for_tests()


def test_can_create_report_peeks_and_reserve_release_roundtrip():
    # Audit R-SRV-3: can_create_report PEEKS (no consume); reserve_report_creation
    # consumes atomically; release_report_creation rolls back. Peek and reserve
    # agree on the boundary.
    pk_hex = "dd" * 32
    ratchet_registry._clear_for_tests()
    ratchet_registry.enroll(pk_hex, [f"{i:064x}" for i in range(50)], "00" * 64)
    # Peeking any number of times never consumes the budget.
    for _ in range(10):
        assert ratchet_registry.can_create_report(pk_hex, 2) is True
    # Reserve consumes; peek tracks it.
    assert ratchet_registry.reserve_report_creation(pk_hex, 2) is True
    assert ratchet_registry.can_create_report(pk_hex, 2) is True
    assert ratchet_registry.reserve_report_creation(pk_hex, 2) is True
    assert ratchet_registry.can_create_report(pk_hex, 2) is False  # exhausted
    assert ratchet_registry.reserve_report_creation(pk_hex, 2) is False
    # Release gives one slot back → a reservation fits again.
    ratchet_registry.release_report_creation(pk_hex)
    assert ratchet_registry.can_create_report(pk_hex, 2) is True
    assert ratchet_registry.reserve_report_creation(pk_hex, 2) is True
    # Release is clamped at 0 and a no-op for an unknown identity.
    ratchet_registry.release_report_creation("ee" * 32)
    # Unknown / unenrolled identity never peek-passes or reserves.
    assert ratchet_registry.can_create_report("ee" * 32, 2) is False
    assert ratchet_registry.reserve_report_creation("ee" * 32, 2) is False
    ratchet_registry._clear_for_tests()


def test_failed_creating_upload_does_not_burn_budget(monkeypatch):
    # Audit ②: a creating PUT that fails AFTER the budget check but BEFORE the
    # record is durable (here: an invalid write-sig => 403) must NOT consume the
    # per-batch budget. Previously the count was bumped at the gate, so a failed
    # or retried creating chunk wasted budget and could spuriously 429 the report
    # that finally lands.
    from app import config
    sub = "aa" * 32  # the default jwt_sub baked into creating_headers
    ratchet_registry._clear_for_tests()
    ratchet_registry.enroll(sub, [f"{i:064x}" for i in range(50)], "00" * 64)
    monkeypatch.setattr(config, "MAX_REPORTS_PER_BATCH", 1)  # room for exactly ONE report
    reports_mod._reset_for_test()
    store = FakeStore()
    monkeypatch.setattr(storage, "upload_blob_stream_write_once", store.put)
    client = TestClient(main.app)
    try:
        # (1) A creating PUT with a BAD write-sig: 403, nothing stored, budget intact.
        sk, pk, rid = new_report_key()
        body = b"sealed"
        headers = creating_headers(sk, pk, rid, "c0.strm", body)
        headers["X-Report-Write-Sig"] = sig_write(sk, rid, "c0.strm", b"different").hex()
        r = client.put(f"/file/{rid}/c0.strm", content=body, headers=headers)
        assert r.status_code == 403
        assert store.blobs == {}
        assert ratchet_registry.can_create_report(sub, 1) is True  # not consumed
        # (2) A VALID creating PUT for a DIFFERENT report now succeeds — the one
        # unit of budget was never spent by the failed attempt. Under the old
        # bump-at-gate behaviour this would 429.
        sk2, pk2, rid2 = new_report_key()
        body2 = b"sealed-2"
        r2 = client.put(
            f"/file/{rid2}/c0.strm",
            content=body2,
            headers=creating_headers(sk2, pk2, rid2, "c0.strm", body2),
        )
        assert r2.status_code == 204
        assert ratchet_registry.can_create_report(sub, 1) is False  # the success consumed it
    finally:
        reports_mod._reset_for_test()
        ratchet_registry._clear_for_tests()


def test_validate_path_rejects_dot_dotdot_and_overlong():
    # Audit LOW #22/#23: `.`, `..` ANYWHERE, and >128-char names must be rejected
    # at the source so the stored key stays byte-identical to the write-signed
    # name (no silent `.replace("..","")` rewrite / collision) and no `..` reaches
    # a rescue consumer's sink. upload + archive share app.paths (symmetric now —
    # archive previously had NO `.`/`..` guard).
    from fastapi import HTTPException
    from app.routes import archive, upload

    def _archive(r, f):
        archive._validate_path(r, f)

    bad_names = (".", "..", "..foo", "a..b", "foo..bar", "x" * 129)
    for validate in (upload._validate_path, _archive):
        for bad in bad_names:
            with pytest.raises(HTTPException) as exc:
                validate("a" * 32, bad)
            assert exc.value.status_code == 400, f"{validate} accepted {bad!r}"
    # Real chunk / directory-index names still pass (no regression), both routes.
    for good in ("2115607e_000001.strm", "0000000000", "x" * 128):
        upload._validate_path("a" * 32, good)
        archive._validate_path("a" * 32, good)
    # archive filename is optional (report-level ops pass None).
    archive._validate_path("a" * 32, None)


def test_create_or_verify_rolls_back_on_save_failure(monkeypatch):
    # Audit LOW: if the disk save raises, the in-memory insert is rolled back so
    # RAM never claims a record the disk doesn't hold (the rescue's
    # 404-on-unknown + the blob-first contract rely on record<->disk agreement).
    reports_mod._reset_for_test()
    rid, pk_hex = "ab" * 16, "cd" * 32  # 32-hex id, 64-hex pk (binding not checked here)

    def boom():
        raise OSError("disk full")

    monkeypatch.setattr(reports_mod, "_save_reports_locked", boom)
    with pytest.raises(OSError):
        reports_mod.create_or_verify_report(rid, pk_hex)
    # Rolled back: the failed creation left no in-memory record.
    assert reports_mod.get_report(rid) is None
    reports_mod._reset_for_test()
