#!/usr/bin/env python3
"""
test_report_close_kat.py — cross-language Known-Answer Test for the chained
report scheme on the relay side: the closure signature (domain 0x09, for a
chained report and for a legacy one) and the create / write signatures (0x07 /
0x08) of a chained report.

Same discipline as test_report_sig_kat.py, for the same reason: never re-sign
these vectors from Python. They are produced by the Rust source of truth,
``crypto-rs/core/tests/report_chain_kat.rs`` (fixed mnemonic ``MN_FIXED``,
chain index 0, plus the closure of legacy report 0), which pins them as
``EXP_*`` on its own side. This file only checks that the relay verifies those
exact bytes against the messages it rebuilds itself:

  0x07 || report_id(16) || report_pk(32)
  0x08 || report_id(16) || filename || sha256(body)(32)
  0x09 || report_id(16) || u32_be(seq_limit) || sha256(manifest)(32)

and that the manifest has the layout the relay frames
(``"FQM1" || u32_be(count) || count x (u32_be(seq) || sha256(blob))``). The
route tests in test_report_close.py sign in Python with the relay's own
constants, so a drift on one side only would leave them green; this file is the
check that goes red.

On a deliberate change to the report crypto, rerun
``cargo test -p frappuccino-crypto-core --test report_chain_kat -- --nocapture``
and copy the printed values into both files. Re-signing in Python to turn a red
test green makes the KAT tautological.
"""

import hashlib
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
from app import auth, main, paths, ratchet_registry, signature_domain  # noqa: E402
from app.routes import reports as reports_mod  # noqa: E402
from app.routes import upload  # noqa: E402

# --- Vectors produced by crypto-rs/core/tests/report_chain_kat.rs -------------
# MUST stay byte-identical to the EXP_* constants of that Rust KAT. The name in
# the `KAT <name> = ...` line it prints is given for each.

# Chained report, index 0.
# chain_pk_0
CHAIN_REPORT_PK = "74650ad013cd6ebdacfd09b27877f468f11974fc0d0c6f6065b673f57655cca4"
# chain_id_0 = SHA-256("stream.report.id.v1" || chain_pk_0)[..16]
CHAIN_REPORT_ID = "a918268f24dd26e637aad05e9fd53da3"
# create_sig_0 (0x07)
CHAIN_CREATE_SIG = (
    "ed3895f37bfb4d87148c265ce6fb54c7d1f3b129cfcefe853ef73c2f8288d10c"
    "becb70ff47e1f8b8e7ee51c33d1bf24f275e7a8f4a719f69168e9e1d8b465a02"
)
# The object seq 0: its name, its stored bytes (blob_seq0, i.e. bytes(range(32))),
# their SHA-256 (blob_sha256_seq0) and its write signature (write_sig_0, 0x08).
SEQ0_NAME = "000000.strm"
SEQ0_BLOB = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
SEQ0_BLOB_SHA256 = "630dcd2966c4336691125448bbb25b4ff412a49c732db2c8abc1b8581bd710dd"
SEQ0_WRITE_SIG = (
    "78cf356eb3d846a2dd2ca9d562ab6098e9ea84c9a6018b14c551a150f9d3274a"
    "e7c36c6f345b803a9ab54b54ea29f9811b6e1bea261a8cc09575fd65c2377c0a"
)
# manifest: seq 0 -> SEQ0_BLOB_SHA256, seq 1 -> 0x11 x 32, seq 3 -> 0x33 x 32
# (seq 2 is a gap, as when a chunk is lost at capture).
MANIFEST = (
    "46514d3100000003"
    "00000000630dcd2966c4336691125448bbb25b4ff412a49c732db2c8abc1b8581bd710dd"
    "000000011111111111111111111111111111111111111111111111111111111111111111"
    "000000033333333333333333333333333333333333333333333333333333333333333333"
)
# manifest_sha256
MANIFEST_SHA256 = "646333e15d611c60daf7c15cc2b08ea236ec78b53488b217609113efe698676a"
# seq_limit (last seq + 1)
SEQ_LIMIT = 4
# close_sig (0x09) under chain_pk_0
CLOSE_SIG = (
    "e023ed75070c336d0c8bc09a42d948b2b21492315bbcc56314dc7f6a2f09311d"
    "9df54f2f49d02b89e2222da8944928b565e0303aa6278fab38113d0a408a700a"
)

# Legacy report 0, closed the way a migration closes it: empty manifest,
# seq_limit 0, signed by the legacy key.
# legacy_pk_0 (the same key test_report_sig_kat.py pins as REPORT_PK)
LEGACY_REPORT_PK = "5339770a3e754ca07f33f7f1d183f2a2f162795a575b885dd6b8d0fa416ebc47"
# Its report_id, pinned by crypto-rs/core/src/report.rs as EXP_REPORT_ID.
LEGACY_REPORT_ID = "21e4f004dfb2b5da3e14537505f19f92"
# legacy_close_sig_0 (0x09)
LEGACY_CLOSE_SIG = (
    "c9c7c76ea639150ec8c300b10af15edce3b03c861979ae1f69fb6864d8c02e51"
    "7d5008fef4ad7b4afd58cfa35b445c6acdd21d840bab86614f678a944512990e"
)
# The empty manifest, "FQM1" || u32_be(0): the format, not a Rust output.
EMPTY_MANIFEST = "46514d3100000000"


def _close_message(domain: bytes, report_id_hex: str, seq_limit: int, manifest: bytes) -> bytes:
    return (
        domain
        + bytes.fromhex(report_id_hex)
        + seq_limit.to_bytes(4, "big")
        + hashlib.sha256(manifest).digest()
    )


def _write_message(domain: bytes, name: str, body: bytes) -> bytes:
    return (
        domain
        + bytes.fromhex(CHAIN_REPORT_ID)
        + name.encode("utf-8")
        + hashlib.sha256(body).digest()
    )


@pytest.fixture()
def relay(fake_minio, monkeypatch):
    reports_mod._reset_for_test()
    # The creation budget is the ratchet registry's business, covered by its own
    # tests; here it must not stand between the Rust vectors and the routes.
    monkeypatch.setattr(ratchet_registry, "reserve_report_creation", lambda sub, mx: True)
    monkeypatch.setattr(ratchet_registry, "release_report_creation", lambda sub: None)
    try:
        yield TestClient(main.app), fake_minio
    finally:
        reports_mod._reset_for_test()


# ---------------------------------------------------------------------------
# The vectors themselves
# ---------------------------------------------------------------------------

def test_domain_tag_is_0x09():
    # Not a vector: the relay's constant itself, which the KAT below relies on.
    assert signature_domain.SIG_DOMAIN_REPORT_CLOSE == b"\x09"


def test_seq0_blob_vector_is_self_consistent():
    # Documents what SEQ0_BLOB is, so the vector can be regenerated, and that
    # the relay's hash of those bytes is the one Rust signed and listed.
    assert SEQ0_BLOB == bytes(range(32)).hex()
    assert hashlib.sha256(bytes.fromhex(SEQ0_BLOB)).hexdigest() == SEQ0_BLOB_SHA256


def test_manifest_vector_has_the_specified_layout():
    manifest = bytes.fromhex(MANIFEST)
    assert manifest[:4] == b"FQM1"
    count = int.from_bytes(manifest[4:8], "big")
    assert count == 3
    assert len(manifest) == 8 + 36 * count
    entries = [
        (
            int.from_bytes(manifest[8 + 36 * i: 12 + 36 * i], "big"),
            manifest[12 + 36 * i: 44 + 36 * i].hex(),
        )
        for i in range(count)
    ]
    assert entries == [
        (0, SEQ0_BLOB_SHA256),
        (1, "11" * 32),
        (3, "33" * 32),
    ]
    assert SEQ_LIMIT == entries[-1][0] + 1
    assert SEQ_LIMIT <= paths.MAX_SEQ_LIMIT
    assert hashlib.sha256(manifest).hexdigest() == MANIFEST_SHA256


def test_relay_frames_both_manifest_vectors():
    # The only parsing the relay does on a closure body: magic and length.
    for hex_body in (MANIFEST, EMPTY_MANIFEST):
        body = bytes.fromhex(hex_body)
        upload._check_manifest_frame(body[:8], len(body))


def test_report_ids_derivation_matches_rust():
    assert upload._report_id_from_pk(bytes.fromhex(CHAIN_REPORT_PK)).hex() == CHAIN_REPORT_ID
    assert upload._report_id_from_pk(bytes.fromhex(LEGACY_REPORT_PK)).hex() == LEGACY_REPORT_ID


# ---------------------------------------------------------------------------
# The relay's verifier on the Rust signatures
# ---------------------------------------------------------------------------

def test_chain_create_sig_verifies_on_relay():
    pk = bytes.fromhex(CHAIN_REPORT_PK)
    sig = bytes.fromhex(CHAIN_CREATE_SIG)
    rid = bytes.fromhex(CHAIN_REPORT_ID)
    create = signature_domain.SIG_DOMAIN_REPORT_CREATE
    assert auth.verify_detached_ed25519(pk, sig, create + rid + pk)
    for other in (signature_domain.SIG_DOMAIN_REPORT_WRITE, signature_domain.SIG_DOMAIN_REPORT_CLOSE):
        assert not auth.verify_detached_ed25519(pk, sig, other + rid + pk)


def test_chain_write_sig_verifies_on_relay():
    pk = bytes.fromhex(CHAIN_REPORT_PK)
    sig = bytes.fromhex(SEQ0_WRITE_SIG)
    body = bytes.fromhex(SEQ0_BLOB)
    write = signature_domain.SIG_DOMAIN_REPORT_WRITE
    assert auth.verify_detached_ed25519(pk, sig, _write_message(write, SEQ0_NAME, body))
    # The signature binds the name, the body and the domain.
    assert not auth.verify_detached_ed25519(pk, sig, _write_message(write, "000001.strm", body))
    assert not auth.verify_detached_ed25519(pk, sig, _write_message(write, SEQ0_NAME, body + b"\x00"))
    create = signature_domain.SIG_DOMAIN_REPORT_CREATE
    assert not auth.verify_detached_ed25519(pk, sig, _write_message(create, SEQ0_NAME, body))


def test_close_sig_verifies_on_relay():
    pk = bytes.fromhex(CHAIN_REPORT_PK)
    sig = bytes.fromhex(CLOSE_SIG)
    manifest = bytes.fromhex(MANIFEST)
    close = signature_domain.SIG_DOMAIN_REPORT_CLOSE
    assert auth.verify_detached_ed25519(
        pk, sig, _close_message(close, CHAIN_REPORT_ID, SEQ_LIMIT, manifest)
    )
    # The signature binds the seq_limit, the manifest, the report and the domain.
    assert not auth.verify_detached_ed25519(
        pk, sig, _close_message(close, CHAIN_REPORT_ID, SEQ_LIMIT + 1, manifest)
    )
    assert not auth.verify_detached_ed25519(
        pk, sig, _close_message(close, CHAIN_REPORT_ID, SEQ_LIMIT, manifest + b"\x00")
    )
    assert not auth.verify_detached_ed25519(
        pk, sig, _close_message(close, LEGACY_REPORT_ID, SEQ_LIMIT, manifest)
    )
    write = signature_domain.SIG_DOMAIN_REPORT_WRITE
    assert not auth.verify_detached_ed25519(
        pk, sig, _close_message(write, CHAIN_REPORT_ID, SEQ_LIMIT, manifest)
    )


def test_legacy_close_sig_verifies_on_relay():
    pk = bytes.fromhex(LEGACY_REPORT_PK)
    sig = bytes.fromhex(LEGACY_CLOSE_SIG)
    empty = bytes.fromhex(EMPTY_MANIFEST)
    close = signature_domain.SIG_DOMAIN_REPORT_CLOSE
    assert auth.verify_detached_ed25519(pk, sig, _close_message(close, LEGACY_REPORT_ID, 0, empty))
    assert not auth.verify_detached_ed25519(
        pk, sig, _close_message(close, LEGACY_REPORT_ID, 1, empty)
    )
    # Not valid under the chained report's key either: a closure is per report.
    assert not auth.verify_detached_ed25519(
        bytes.fromhex(CHAIN_REPORT_PK), sig, _close_message(close, LEGACY_REPORT_ID, 0, empty)
    )


# ---------------------------------------------------------------------------
# End to end through the routes, with the Rust bytes only
# ---------------------------------------------------------------------------

def test_routes_accept_the_rust_chain_report_and_its_closure(relay):
    # The creating PUT of seq 0, then the closure, each verified against the
    # message the relay rebuilds from the URL, the headers and the body; then
    # the rescue's view of both, with the Rust signatures handed back intact.
    client, minio = relay
    body = bytes.fromhex(SEQ0_BLOB)
    r = client.put(
        f"/file/{CHAIN_REPORT_ID}/{SEQ0_NAME}",
        content=body,
        headers={
            "X-Report-PK": CHAIN_REPORT_PK,
            "X-Report-Write-Sig": SEQ0_WRITE_SIG,
            "X-Report-Create-Sig": CHAIN_CREATE_SIG,
            "Authorization": f"Bearer {auth.create_jwt('aa' * 32)}",
        },
    )
    assert r.status_code == 204, r.text
    assert reports_mod.get_report(CHAIN_REPORT_ID)["report_pk"] == CHAIN_REPORT_PK

    manifest = bytes.fromhex(MANIFEST)
    close_headers = {
        "X-Report-PK": CHAIN_REPORT_PK,
        "X-Report-Close-Sig": CLOSE_SIG,
        "X-Report-Close-Seq-Limit": str(SEQ_LIMIT),
    }
    r = client.post(f"/close/{CHAIN_REPORT_ID}", content=manifest, headers=close_headers)
    assert r.status_code == 204, r.text
    # A retry whose answer was lost is the same closure: 204 again.
    r = client.post(f"/close/{CHAIN_REPORT_ID}", content=manifest, headers=close_headers)
    assert r.status_code == 204, r.text
    assert minio.objects[f"{CHAIN_REPORT_ID}/{paths.MANIFEST_NAME}"][0] == manifest

    listing = client.get(f"/api/v2/archive/reports/{CHAIN_REPORT_ID}/blobs")
    assert listing.status_code == 200
    assert listing.json()["closure"] == {
        "seq_limit": SEQ_LIMIT,
        "manifest_sha256": MANIFEST_SHA256,
        "sig": CLOSE_SIG,
    }
    names = sorted(blob["filename"] for blob in listing.json()["blobs"])
    assert names == sorted([SEQ0_NAME, paths.MANIFEST_NAME])

    seq0 = client.get(f"/api/v2/archive/reports/{CHAIN_REPORT_ID}/{SEQ0_NAME}")
    assert seq0.status_code == 200
    assert seq0.content == body
    assert seq0.headers["X-Report-Write-Sig"] == SEQ0_WRITE_SIG
    stored = client.get(f"/api/v2/archive/reports/{CHAIN_REPORT_ID}/{paths.MANIFEST_NAME}")
    assert stored.status_code == 200
    assert stored.content == manifest
    assert "X-Report-Write-Sig" not in stored.headers


def test_close_route_refuses_the_rust_vector_with_another_seq_limit(relay):
    # Same Rust signature, seq_limit header off by one: the relay's rebuilt
    # message differs, so 403 and nothing recorded.
    client, minio = relay
    with reports_mod._reports_lock:
        reports_mod._reports[CHAIN_REPORT_ID] = {
            "report_id": CHAIN_REPORT_ID,
            "report_pk": CHAIN_REPORT_PK,
        }
    r = client.post(
        f"/close/{CHAIN_REPORT_ID}",
        content=bytes.fromhex(MANIFEST),
        headers={
            "X-Report-PK": CHAIN_REPORT_PK,
            "X-Report-Close-Sig": CLOSE_SIG,
            "X-Report-Close-Seq-Limit": str(SEQ_LIMIT + 1),
        },
    )
    assert r.status_code == 403
    assert "closure" not in reports_mod.get_report(CHAIN_REPORT_ID)
    assert f"{CHAIN_REPORT_ID}/{paths.MANIFEST_NAME}" not in minio.objects


def test_close_route_accepts_the_rust_legacy_closure(relay):
    # A migrated device closes each legacy report with an empty manifest and
    # seq_limit 0. The legacy record already exists on the relay.
    client, minio = relay
    with reports_mod._reports_lock:
        reports_mod._reports[LEGACY_REPORT_ID] = {
            "report_id": LEGACY_REPORT_ID,
            "report_pk": LEGACY_REPORT_PK,
        }
    r = client.post(
        f"/close/{LEGACY_REPORT_ID}",
        content=bytes.fromhex(EMPTY_MANIFEST),
        headers={
            "X-Report-PK": LEGACY_REPORT_PK,
            "X-Report-Close-Sig": LEGACY_CLOSE_SIG,
            "X-Report-Close-Seq-Limit": "0",
        },
    )
    assert r.status_code == 204, r.text
    closure = reports_mod.get_report(LEGACY_REPORT_ID)["closure"]
    assert closure == {
        "seq_limit": 0,
        "manifest_sha256": hashlib.sha256(bytes.fromhex(EMPTY_MANIFEST)).hexdigest(),
        "sig": LEGACY_CLOSE_SIG,
    }
    assert minio.objects[f"{LEGACY_REPORT_ID}/{paths.MANIFEST_NAME}"][0] == bytes.fromhex(
        EMPTY_MANIFEST
    )
