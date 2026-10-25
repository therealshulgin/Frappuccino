#!/usr/bin/env python3
"""
Closed reports: `POST /close/{report_id}`, the rule a PUT obeys once a closure is
recorded, and the write signature kept with each object.

A closure is the report key's signature (domain 0x09) over
`report_id || u32_be(seq_limit) || sha256(manifest)`. Once the relay has recorded
one, a PUT that would create a new object is accepted only for a name
`NNNNNN.strm` with `NNNNNN < seq_limit`; everything else is 409
`{"detail": "Report closed"}`. That exact body is part of the contract: the
client tells this 409 apart from the write-once one by it. An object that
already exists keeps write-once semantics (identical 204, different 409),
closure or not.

The race the closure rule is built around has its own test: a closure recorded
while a PUT's body is still streaming. The PUT read the record before the body,
so only the re-read after the signature check can see the closure, and the
store happens under the same registry lock the closure is recorded under.

Storage here is the real `app.storage` code over an in-memory MinIO
(`fake_minio` in conftest.py), so the closure rule and the metadata are those of
the module that runs in production, not of a stub. Report keys are random
Ed25519 pairs: the relay checks report_id == H(report_pk) and the signatures,
never how the key was derived.
"""

import hashlib
import io
import json
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

from fastapi import HTTPException  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from app import auth, config, main, paths, ratchet_registry  # noqa: E402
from app.routes import reports as reports_mod  # noqa: E402
from app.routes import upload  # noqa: E402

CTX_ID = b"stream.report.id.v1"
DOM_CREATE = b"\x07"
DOM_WRITE = b"\x08"
DOM_CLOSE = b"\x09"
META = "X-Amz-Meta-Report-Write-Sig"  # as MinIO hands it back


# --- helpers ----------------------------------------------------------------

def new_report_key():
    sk = nacl.signing.SigningKey.generate()
    pk = bytes(sk.verify_key)
    return sk, pk, hashlib.sha256(CTX_ID + pk).digest()[:16].hex()


def sha(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def write_sig(sk, rid, name, body) -> bytes:
    return sk.sign(DOM_WRITE + bytes.fromhex(rid) + name.encode() + sha(body)).signature


def close_sig(sk, rid, seq_limit, manifest) -> bytes:
    msg = DOM_CLOSE + bytes.fromhex(rid) + seq_limit.to_bytes(4, "big") + sha(manifest)
    return sk.sign(msg).signature


def manifest_for(bodies: dict[int, bytes]) -> tuple[bytes, int]:
    """"FQM1" || u32_be(count) || count x (u32_be(seq) || sha256(blob)), and the
    seq_limit (last seq + 1, 0 when empty)."""
    seqs = sorted(bodies)
    out = b"FQM1" + len(seqs).to_bytes(4, "big")
    out += b"".join(s.to_bytes(4, "big") + sha(bodies[s]) for s in seqs)
    return out, (seqs[-1] + 1 if seqs else 0)


def put(client, sk, pk, rid, name, body, creating=False):
    headers = {"X-Report-PK": pk.hex(), "X-Report-Write-Sig": write_sig(sk, rid, name, body).hex()}
    if creating:
        headers["X-Report-Create-Sig"] = sk.sign(DOM_CREATE + bytes.fromhex(rid) + pk).signature.hex()
        headers["Authorization"] = f"Bearer {auth.create_jwt('aa' * 32)}"
    return client.put(f"/file/{rid}/{name}", content=body, headers=headers)


def close_headers(sk, pk, rid, manifest, seq_limit):
    return {
        "X-Report-PK": pk.hex(),
        "X-Report-Close-Sig": close_sig(sk, rid, seq_limit, manifest).hex(),
        "X-Report-Close-Seq-Limit": str(seq_limit),
    }


def close(client, sk, pk, rid, manifest, seq_limit):
    return client.post(
        f"/close/{rid}", content=manifest, headers=close_headers(sk, pk, rid, manifest, seq_limit)
    )


def open_report(client, uploaded=(0, 1, 2), names=None):
    """Create a report and upload the given chunks. Returns (sk, pk, rid, bodies)
    with a body for every uploaded seq."""
    sk, pk, rid = new_report_key()
    bodies = {seq: f"sealed-chunk-{seq}".encode() for seq in uploaded}
    for i, seq in enumerate(uploaded):
        name = names[seq] if names else f"{seq:06d}.strm"
        assert put(client, sk, pk, rid, name, bodies[seq], creating=(i == 0)).status_code == 204
    return sk, pk, rid, bodies


@pytest.fixture()
def relay(fake_minio, monkeypatch):
    reports_mod._reset_for_test()
    # The creation budget is covered elsewhere; allow it here.
    monkeypatch.setattr(ratchet_registry, "reserve_report_creation", lambda sub, mx: True)
    monkeypatch.setattr(ratchet_registry, "release_report_creation", lambda sub: None)
    try:
        yield TestClient(main.app), fake_minio
    finally:
        reports_mod._reset_for_test()


# ---------------------------------------------------------------------------
# POST /close — success, idempotence, durability
# ---------------------------------------------------------------------------

def test_close_records_the_closure_and_stores_the_manifest(relay):
    client, minio = relay
    sk, pk, rid, bodies = open_report(client)
    manifest, seq_limit = manifest_for(bodies)
    # No Authorization header: a closure needs no JWT and no budget.
    r = close(client, sk, pk, rid, manifest, seq_limit)
    assert r.status_code == 204
    expected = {
        "seq_limit": 3,
        "manifest_sha256": sha(manifest).hex(),
        "sig": close_sig(sk, rid, seq_limit, manifest).hex(),
    }
    assert reports_mod.get_report(rid)["closure"] == expected
    # Durable: the registry file on disk holds it too.
    on_disk = json.loads(Path(config.REPORTS_DB_PATH).read_text(encoding="utf-8"))
    assert on_disk[rid]["closure"] == expected
    # The manifest is the write-once object `manifest`, byte for byte.
    assert minio.objects[f"{rid}/{paths.MANIFEST_NAME}"][0] == manifest


def test_close_retry_with_the_same_closure_is_204(relay):
    client, _ = relay
    sk, pk, rid, bodies = open_report(client)
    manifest, seq_limit = manifest_for(bodies)
    assert close(client, sk, pk, rid, manifest, seq_limit).status_code == 204
    before = dict(reports_mod.get_report(rid)["closure"])
    assert close(client, sk, pk, rid, manifest, seq_limit).status_code == 204
    assert reports_mod.get_report(rid)["closure"] == before


def test_a_different_closure_is_409_and_the_first_one_stays(relay):
    client, _ = relay
    sk, pk, rid, bodies = open_report(client)
    manifest, seq_limit = manifest_for(bodies)
    assert close(client, sk, pk, rid, manifest, seq_limit).status_code == 204
    before = dict(reports_mod.get_report(rid)["closure"])
    shorter, shorter_limit = manifest_for({0: bodies[0], 1: bodies[1]})
    for m, n in ((shorter, shorter_limit), (manifest, seq_limit + 1)):
        r = close(client, sk, pk, rid, m, n)
        assert r.status_code == 409
        assert r.json() == {"detail": "A different closure is already recorded"}
    assert reports_mod.get_report(rid)["closure"] == before


def test_legacy_closure_with_an_empty_manifest(relay):
    client, minio = relay
    names = {0: "2115607e_000000.strm", 1: "2115607e_000001.strm"}
    sk, pk, rid, _ = open_report(client, uploaded=(0, 1), names=names)
    manifest, seq_limit = manifest_for({})
    assert (manifest, seq_limit) == (b"FQM1\x00\x00\x00\x00", 0)
    assert close(client, sk, pk, rid, manifest, seq_limit).status_code == 204
    assert reports_mod.get_report(rid)["closure"]["seq_limit"] == 0
    assert minio.objects[f"{rid}/manifest"][0] == manifest


def test_seq_limit_upper_bound_is_accepted(relay):
    client, _ = relay
    sk, pk, rid, _ = open_report(client, uploaded=(0,))
    # The relay does not check entries against seq_limit; any well-framed
    # manifest with the right count of entries will do for the bound itself.
    manifest = b"FQM1" + (1).to_bytes(4, "big") + (999_999).to_bytes(4, "big") + bytes(32)
    assert close(client, sk, pk, rid, manifest, paths.MAX_SEQ_LIMIT).status_code == 204


# ---------------------------------------------------------------------------
# POST /close — refusals
# ---------------------------------------------------------------------------

def test_close_without_headers_is_400_not_404(relay):
    # The deployment probe: a relay that serves the route answers 400 to a bare
    # POST; a relay without it answers 404, which the client reads as "route
    # absent, retry later".
    client, _ = relay
    r = client.post(f"/close/{'a' * 32}")
    assert r.status_code == 400


@pytest.mark.parametrize("bad_rid", ["A" * 32, "a" * 31, "a" * 33, "g" * 32, "a" * 32 + "%0A"])
def test_close_invalid_report_id_is_400(relay, bad_rid):
    client, _ = relay
    sk, pk, _ = new_report_key()
    manifest, n = manifest_for({})
    r = client.post(f"/close/{bad_rid}", content=manifest, headers=close_headers(sk, pk, "a" * 32, manifest, n))
    assert r.status_code == 400


@pytest.mark.parametrize("missing", ["X-Report-PK", "X-Report-Close-Sig", "X-Report-Close-Seq-Limit"])
def test_close_missing_header_is_400(relay, missing):
    client, minio = relay
    sk, pk, rid, bodies = open_report(client)
    manifest, n = manifest_for(bodies)
    headers = close_headers(sk, pk, rid, manifest, n)
    del headers[missing]
    r = client.post(f"/close/{rid}", content=manifest, headers=headers)
    assert r.status_code == 400
    assert "closure" not in reports_mod.get_report(rid)
    assert f"{rid}/manifest" not in minio.objects


@pytest.mark.parametrize("value", ["01", "00", "-1", "+1", "1.0", "1e3", "0x10", "", "a",
                                   "10000000", "1000001", "99999999999999999999"])
def test_close_seq_limit_not_canonical_or_out_of_range_is_400(relay, value):
    client, _ = relay
    sk, pk, rid, bodies = open_report(client)
    manifest, n = manifest_for(bodies)
    headers = close_headers(sk, pk, rid, manifest, n)
    headers["X-Report-Close-Seq-Limit"] = value
    assert client.post(f"/close/{rid}", content=manifest, headers=headers).status_code == 400


@pytest.mark.parametrize("value", [" 1", "1 ", "1\t", "١", "１", "1\n"])
def test_seq_limit_parser_refuses_whitespace_and_non_ascii_digits(value):
    # Checked on the parser directly: an HTTP stack may trim or refuse such a
    # header before it reaches the route, so the route test cannot cover them.
    with pytest.raises(HTTPException) as exc:
        upload._parse_seq_limit(value)
    assert exc.value.status_code == 400


def test_seq_limit_parser_accepts_canonical_values():
    for value, expected in (("0", 0), ("1", 1), ("999999", 999_999), ("1000000", 1_000_000)):
        assert upload._parse_seq_limit(value) == expected


def test_close_report_id_not_hash_of_pk_is_400(relay):
    client, _ = relay
    sk, pk, rid, bodies = open_report(client)
    _, other_pk, other_rid = new_report_key()
    manifest, n = manifest_for(bodies)
    headers = close_headers(sk, pk, rid, manifest, n)
    headers["X-Report-PK"] = other_pk.hex()  # rid != H(other_pk)
    assert client.post(f"/close/{rid}", content=manifest, headers=headers).status_code == 400


def test_close_unknown_report_is_425_and_stores_nothing(relay):
    client, minio = relay
    sk, pk, rid = new_report_key()  # valid binding, never created
    manifest, n = manifest_for({0: b"x"})
    r = close(client, sk, pk, rid, manifest, n)
    assert r.status_code == 425
    assert reports_mod.get_report(rid) is None
    assert minio.objects == {}


def test_close_pk_differing_from_the_record_is_409(relay):
    client, minio = relay
    sk, pk, rid = new_report_key()
    with reports_mod._reports_lock:
        reports_mod._reports[rid] = {"report_id": rid, "report_pk": "cc" * 32}
    manifest, n = manifest_for({0: b"x"})
    r = close(client, sk, pk, rid, manifest, n)
    assert r.status_code == 409
    assert "closure" not in reports_mod.get_report(rid)
    assert minio.objects == {}


def test_close_bad_signature_is_403_and_records_nothing(relay):
    client, minio = relay
    sk, pk, rid, bodies = open_report(client)
    manifest, n = manifest_for(bodies)
    other_sk, _, _ = new_report_key()
    wrong = [
        close_sig(other_sk, rid, n, manifest),        # wrong key
        close_sig(sk, rid, n + 1, manifest),          # covers another seq_limit
        close_sig(sk, rid, n, manifest + b"\x00"),    # covers another manifest
        write_sig(sk, rid, "manifest", manifest),     # another domain (0x08)
    ]
    for sig in wrong:
        headers = close_headers(sk, pk, rid, manifest, n)
        headers["X-Report-Close-Sig"] = sig.hex()
        assert client.post(f"/close/{rid}", content=manifest, headers=headers).status_code == 403
    assert "closure" not in reports_mod.get_report(rid)
    assert f"{rid}/manifest" not in minio.objects


@pytest.mark.parametrize("body", [
    b"",
    b"FQM",
    b"FQM2\x00\x00\x00\x00",
    b"FQM1\x00\x00\x00\x01",                       # announces 1 entry, carries none
    b"FQM1\x00\x00\x00\x00" + bytes(36),           # announces 0 entries, carries 1
    b"FQM1\x00\x00\x00\x01" + bytes(35),           # one byte short
])
def test_close_body_not_a_manifest_frame_is_400(relay, body):
    client, minio = relay
    sk, pk, rid, _ = open_report(client)
    # Correctly signed over the malformed body: the frame check is what refuses.
    r = client.post(f"/close/{rid}", content=body, headers=close_headers(sk, pk, rid, body, 3))
    assert r.status_code == 400
    assert r.json() == {"detail": "Malformed manifest"}
    assert f"{rid}/manifest" not in minio.objects


def test_close_body_above_the_cap_is_413(relay, monkeypatch):
    client, minio = relay
    sk, pk, rid, bodies = open_report(client)
    manifest, n = manifest_for(bodies)
    monkeypatch.setattr(upload, "MAX_MANIFEST_SIZE", len(manifest) - 1)
    assert close(client, sk, pk, rid, manifest, n).status_code == 413
    assert "closure" not in reports_mod.get_report(rid)
    assert f"{rid}/manifest" not in minio.objects


def test_close_when_a_different_manifest_object_exists_is_409(relay):
    client, minio = relay
    sk, pk, rid, bodies = open_report(client)
    manifest, n = manifest_for(bodies)
    minio.objects[f"{rid}/manifest"] = (b"FQM1\x00\x00\x00\x00", {})
    r = close(client, sk, pk, rid, manifest, n)
    assert r.status_code == 409
    assert r.json() == {"detail": "Manifest already stored with different content"}
    assert "closure" not in reports_mod.get_report(rid)


def test_close_storage_full_is_507(relay):
    client, minio = relay
    sk, pk, rid, bodies = open_report(client)
    manifest, n = manifest_for(bodies)
    minio.disk_full = True
    assert close(client, sk, pk, rid, manifest, n).status_code == 507
    assert "closure" not in reports_mod.get_report(rid)


def test_close_registry_save_failure_is_503_then_the_retry_records(relay, monkeypatch):
    client, minio = relay
    sk, pk, rid, bodies = open_report(client)
    manifest, n = manifest_for(bodies)
    real_save = reports_mod._save_reports_locked

    def boom():
        raise OSError("disk full")

    monkeypatch.setattr(reports_mod, "_save_reports_locked", boom)
    assert close(client, sk, pk, rid, manifest, n).status_code == 503
    # Rolled back in memory; the manifest stays, identical for the retry.
    assert "closure" not in reports_mod.get_report(rid)
    assert minio.objects[f"{rid}/manifest"][0] == manifest
    monkeypatch.setattr(reports_mod, "_save_reports_locked", real_save)
    assert close(client, sk, pk, rid, manifest, n).status_code == 204
    assert reports_mod.closed_seq_limit(reports_mod.get_report(rid)) == n


def test_close_is_rate_limited():
    # Same shared limiter as every route (test_rate_limit.py): bare POSTs fail
    # header validation (400) until the per-IP cap answers 429.
    client = TestClient(main.app)
    codes = set()
    for _ in range(600 * 2 + 20):
        code = client.post(f"/close/{'a' * 32}").status_code
        codes.add(code)
        if code == 429:
            break
    assert codes == {400, 429}


# ---------------------------------------------------------------------------
# PUT after a closure
# ---------------------------------------------------------------------------

def test_new_name_after_close_is_409_report_closed(relay):
    client, minio = relay
    sk, pk, rid, bodies = open_report(client)
    manifest, n = manifest_for(bodies)
    assert close(client, sk, pk, rid, manifest, n).status_code == 204
    r = put(client, sk, pk, rid, f"{n:06d}.strm", b"after-the-end")
    assert r.status_code == 409
    assert r.json() == {"detail": "Report closed"}
    assert f"{rid}/{n:06d}.strm" not in minio.objects


def test_late_chunk_below_seq_limit_is_accepted_after_close(relay):
    # The closure envelope can reach the relay before a chunk it lists.
    client, minio = relay
    sk, pk, rid, bodies = open_report(client, uploaded=(0, 1))
    bodies[2] = b"sealed-chunk-2"
    manifest, n = manifest_for(bodies)
    assert close(client, sk, pk, rid, manifest, n).status_code == 204
    r = put(client, sk, pk, rid, "000002.strm", bodies[2])
    assert r.status_code == 204
    data, meta = minio.objects[f"{rid}/000002.strm"]
    assert data == bodies[2]
    assert meta[META] == write_sig(sk, rid, "000002.strm", bodies[2]).hex()


def test_existing_objects_keep_write_once_after_close(relay):
    client, _ = relay
    sk, pk, rid, bodies = open_report(client)
    manifest, n = manifest_for(bodies)
    assert close(client, sk, pk, rid, manifest, n).status_code == 204
    assert put(client, sk, pk, rid, "000001.strm", bodies[1]).status_code == 204
    r = put(client, sk, pk, rid, "000001.strm", b"replacement")
    assert r.status_code == 409
    assert r.json() == {"detail": "Chunk already stored with different content"}


def test_legacy_name_is_refused_after_a_legacy_closure(relay):
    client, minio = relay
    names = {0: "2115607e_000000.strm", 1: "2115607e_000001.strm"}
    sk, pk, rid, bodies = open_report(client, uploaded=(0, 1), names=names)
    manifest, n = manifest_for({})
    assert close(client, sk, pk, rid, manifest, n).status_code == 204
    for name in ("2115607e_000002.strm", "000000.strm"):
        r = put(client, sk, pk, rid, name, b"late")
        assert r.status_code == 409
        assert r.json() == {"detail": "Report closed"}
        assert f"{rid}/{name}" not in minio.objects
    # The legacy objects already stored are still re-PUTable identically.
    assert put(client, sk, pk, rid, names[1], bodies[1]).status_code == 204


@pytest.mark.parametrize("name", ["0000001.strm", "00001.strm", "00000a.strm", "000001.STRM",
                                  "000001.strm.x", "x000001.strm", "1.strm", "f" * 32])
def test_only_six_digit_strm_names_survive_a_closure(relay, name):
    # Even at the largest seq_limit, a name that is not exactly NNNNNN.strm is
    # never a new object in a closed report.
    client, _ = relay
    sk, pk, rid, _ = open_report(client, uploaded=(0,))
    manifest = b"FQM1" + (1).to_bytes(4, "big") + (999_999).to_bytes(4, "big") + bytes(32)
    assert close(client, sk, pk, rid, manifest, paths.MAX_SEQ_LIMIT).status_code == 204
    r = put(client, sk, pk, rid, name, b"late")
    assert r.status_code == 409
    assert r.json() == {"detail": "Report closed"}


@pytest.mark.parametrize("closed", [False, True])
def test_put_to_the_reserved_manifest_name_is_400(relay, closed):
    client, minio = relay
    sk, pk, rid, bodies = open_report(client)
    manifest, n = manifest_for(bodies)
    if closed:
        assert close(client, sk, pk, rid, manifest, n).status_code == 204
    r = put(client, sk, pk, rid, "manifest", manifest)
    assert r.status_code == 400
    if not closed:
        assert f"{rid}/manifest" not in minio.objects


def test_put_to_manifest_cannot_create_a_report(relay):
    client, minio = relay
    sk, pk, rid = new_report_key()
    assert put(client, sk, pk, rid, "manifest", b"FQM1\x00\x00\x00\x00", creating=True).status_code == 400
    assert reports_mod.get_report(rid) is None
    assert minio.objects == {}


# ---------------------------------------------------------------------------
# The race: a closure recorded while a PUT's body is still streaming
# ---------------------------------------------------------------------------

def _streaming_put(client, monkeypatch, sk, pk, rid, name, body, during_stream):
    """PUT `body`, running `during_stream()` after the route has read the record
    and while the body is still arriving."""
    reads = []
    real_get_report = reports_mod.get_report

    def spying_get_report(report_id):
        reads.append(report_id)
        return real_get_report(report_id)

    monkeypatch.setattr(reports_mod, "get_report", spying_get_report)

    def chunks():
        yield body[:4]
        assert reads == [rid], "the route must have read the record before the body"
        during_stream()
        yield body[4:]

    headers = {"X-Report-PK": pk.hex(), "X-Report-Write-Sig": write_sig(sk, rid, name, body).hex()}
    r = client.put(f"/file/{rid}/{name}", content=chunks(), headers=headers)
    # Read once before the body, once again in the locked section after it.
    assert reads == [rid, rid]
    return r


def _record_closure(sk, pk, rid, manifest, n):
    outcome = reports_mod.close_report(
        rid, pk.hex(), n, sha(manifest).hex(), close_sig(sk, rid, n, manifest).hex(),
        io.BytesIO(manifest), len(manifest),
    )
    assert outcome == "recorded"


def test_closure_recorded_during_the_body_stream_refuses_a_new_name(relay, monkeypatch):
    client, minio = relay
    sk, pk, rid, bodies = open_report(client)
    manifest, n = manifest_for(bodies)  # covers 0..2, seq_limit 3
    name = f"{n:06d}.strm"
    r = _streaming_put(
        client, monkeypatch, sk, pk, rid, name, b"written-at-the-wrong-moment",
        lambda: _record_closure(sk, pk, rid, manifest, n),
    )
    assert r.status_code == 409
    assert r.json() == {"detail": "Report closed"}
    assert f"{rid}/{name}" not in minio.objects


def test_put_and_close_store_under_the_registry_lock(relay, monkeypatch):
    # The re-read alone is not enough: POST /close records from a worker thread,
    # so the PUT's store must hold the same lock or a closure could land between
    # its check and its write. Both writers are observed holding it.
    from app import storage

    client, _ = relay
    held = []
    real_store = storage.upload_blob_stream_write_once

    def spy(*args, **kwargs):
        held.append((args[1], reports_mod._reports_lock.locked()))
        return real_store(*args, **kwargs)

    monkeypatch.setattr(storage, "upload_blob_stream_write_once", spy)
    sk, pk, rid, bodies = open_report(client, uploaded=(0, 1))
    manifest, n = manifest_for(bodies)
    assert close(client, sk, pk, rid, manifest, n).status_code == 204
    assert held == [("000000.strm", True), ("000001.strm", True), ("manifest", True)]


def test_closure_recorded_during_the_body_stream_still_admits_a_listed_chunk(relay, monkeypatch):
    client, minio = relay
    sk, pk, rid, bodies = open_report(client, uploaded=(0, 1))
    bodies[2] = b"sealed-chunk-2-arriving-late"
    manifest, n = manifest_for(bodies)
    r = _streaming_put(
        client, monkeypatch, sk, pk, rid, "000002.strm", bodies[2],
        lambda: _record_closure(sk, pk, rid, manifest, n),
    )
    assert r.status_code == 204
    assert minio.objects[f"{rid}/000002.strm"][0] == bodies[2]


# ---------------------------------------------------------------------------
# Write signature: stored, served, attached on re-PUT
# ---------------------------------------------------------------------------

def test_write_sig_is_stored_by_the_creating_put(relay):
    client, minio = relay
    sk, pk, rid, bodies = open_report(client, uploaded=(0, 1))
    for seq in (0, 1):
        key = f"{rid}/{seq:06d}.strm"
        assert minio.objects[key][1][META] == write_sig(sk, rid, f"{seq:06d}.strm", bodies[seq]).hex()
        # One put per object, no metadata copy afterwards.
        assert minio.calls.count(("put", key)) == 1
        assert ("copy", key) not in minio.calls


def test_get_serves_the_stored_write_sig(relay):
    client, _ = relay
    sk, pk, rid, bodies = open_report(client, uploaded=(0, 1))
    r = client.get(f"/api/v2/archive/reports/{rid}/000001.strm")
    assert r.status_code == 200
    assert r.content == bodies[1]
    assert r.headers["X-Report-Write-Sig"] == write_sig(sk, rid, "000001.strm", bodies[1]).hex()


def test_get_object_without_metadata_has_no_write_sig_header(relay):
    client, minio = relay
    sk, pk, rid, _ = open_report(client, uploaded=(0,))
    minio.objects[f"{rid}/legacy_000001.strm"] = (b"stored-before", {})
    r = client.get(f"/api/v2/archive/reports/{rid}/legacy_000001.strm")
    assert r.status_code == 200
    assert "X-Report-Write-Sig" not in r.headers


def test_identical_reput_attaches_a_missing_write_sig_once(relay):
    client, minio = relay
    sk, pk, rid, _ = open_report(client, uploaded=(0,))
    name, body = "legacy_000001.strm", b"stored-before-the-relay-kept-signatures"
    key = f"{rid}/{name}"
    minio.objects[key] = (body, {})
    assert put(client, sk, pk, rid, name, body).status_code == 204
    assert minio.objects[key] == (body, {META: write_sig(sk, rid, name, body).hex()})
    assert minio.calls.count(("copy", key)) == 1
    assert put(client, sk, pk, rid, name, body).status_code == 204
    assert minio.calls.count(("copy", key)) == 1  # already there: left alone
    assert ("put", key) not in minio.calls


def test_manifest_is_downloadable_by_the_archive_route(relay):
    client, _ = relay
    sk, pk, rid, bodies = open_report(client)
    manifest, n = manifest_for(bodies)
    assert close(client, sk, pk, rid, manifest, n).status_code == 204
    r = client.get(f"/api/v2/archive/reports/{rid}/manifest")
    assert r.status_code == 200
    assert r.content == manifest
    assert "X-Report-Write-Sig" not in r.headers


def test_listing_carries_the_closure(relay):
    client, _ = relay
    sk, pk, rid, bodies = open_report(client)
    listing = client.get(f"/api/v2/archive/reports/{rid}/blobs").json()
    assert listing["closure"] is None
    manifest, n = manifest_for(bodies)
    assert close(client, sk, pk, rid, manifest, n).status_code == 204
    listing = client.get(f"/api/v2/archive/reports/{rid}/blobs").json()
    assert listing["closure"] == {
        "seq_limit": n,
        "manifest_sha256": sha(manifest).hex(),
        "sig": close_sig(sk, rid, n, manifest).hex(),
    }
    names = sorted(b["filename"] for b in listing["blobs"])
    assert names == ["000000.strm", "000001.strm", "000002.strm", "manifest"]


# ---------------------------------------------------------------------------
# Path validators: whole-string match
# ---------------------------------------------------------------------------

def test_validators_refuse_a_trailing_newline():
    for bad in ("a" * 32 + "\n", "a" * 32 + "\r\n"):
        with pytest.raises(HTTPException):
            paths.validate_report_id(bad)
    for bad in ("000001.strm\n", "x\n"):
        with pytest.raises(HTTPException):
            paths.validate_filename(bad)
    paths.validate_report_id("a" * 32)
    paths.validate_filename("000001.strm")


def test_newline_in_the_url_path_is_400(relay):
    client, minio = relay
    sk, pk, rid = new_report_key()
    body = b"x"
    r = client.put(f"/file/{rid}%0A/000000.strm", content=body, headers={
        "X-Report-PK": pk.hex(), "X-Report-Write-Sig": write_sig(sk, rid, "000000.strm", body).hex(),
    })
    assert r.status_code == 400
    assert client.get(f"/api/v2/archive/reports/{rid}%0A/blobs").status_code == 400
    assert client.get(f"/api/v2/archive/reports/{rid}/x.strm%0A").status_code == 400
    assert minio.objects == {}


def test_name_allowed_after_close():
    assert paths.name_allowed_after_close("000000.strm", 1)
    assert paths.name_allowed_after_close("999999.strm", 1_000_000)
    assert not paths.name_allowed_after_close("000001.strm", 1)
    assert not paths.name_allowed_after_close("000000.strm", 0)
    assert not paths.name_allowed_after_close("000000.strm\n", 1)
    assert not paths.name_allowed_after_close("sid_000000.strm", 1_000_000)
