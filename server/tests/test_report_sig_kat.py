#!/usr/bin/env python3
"""
test_report_sig_kat.py — cross-language Known-Answer Test for the relay-blind
report capability signatures, 0x07 (create) and 0x08 (write) (audit ③).

Never re-sign these vectors from Python. They are produced by the Rust source of
truth — the KAT in ``crypto-rs/core/src/report.rs::report_sig_cross_language_kat``
(fixed mnemonic ``MN_FIXED``, report index 0), which pins them as ``EXP_*`` on
its own side — and this test only checks that the relay verifies those exact
bytes against the messages it rebuilds itself. So if either side's report crypto
drifts, one of the two tests goes red; on a deliberate change, rerun the Rust
test with ``--nocapture`` and copy the printed values into both files. Re-signing
in Python to get a red test back to green makes the KAT tautological and quietly
removes the only cross-language check this protocol has.

It really is the only one: both neighbouring suites are blind to a drift on a
single side. The diff-fuzz corpus is a Kotlin<->Rust boundary differential that
never leaves the FFI, and the route tests (test_relay_blind_reports.py) sign in
Python using the server's own signature_domain constants. Change the report-id
context, a domain tag or the signed-message byte layout on the Rust client or on
the Python relay but not both, and both suites round-trip green while every real
upload gets a 403 Invalid signature.
"""

import os
import sys
import tempfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

os.environ["JWT_SECRET"] = "test-secret-do-not-use"
_tmp = tempfile.mkdtemp()
os.environ.setdefault("RATCHET_REGISTRY_FILE", os.path.join(_tmp, "registry.json"))
os.environ.setdefault("REPORTS_DB_PATH", os.path.join(_tmp, "reports.json"))

from app import auth, signature_domain  # noqa: E402
from app.routes import upload  # noqa: E402

# --- Vectors produced by crypto-rs/core/src/report.rs (MN_FIXED, index 0) ----
# MUST stay byte-identical to the EXP_* constants in that Rust KAT.
REPORT_PK = "5339770a3e754ca07f33f7f1d183f2a2f162795a575b885dd6b8d0fa416ebc47"
REPORT_ID = "21e4f004dfb2b5da3e14537505f19f92"
FILENAME = "kat_000000.strm"
BODY_SHA256 = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
CREATE_SIG = (
    "3ef66c784192466fb5eda1e2191247024f014fbd34e9f94c6a110c3ab68d7677"
    "0a685e5c982cf90dc251049706bd9323c685911704371bc994c20ffe48cb1b07"
)
WRITE_SIG = (
    "76a6fae277d4ac08831c36823a810cbd35e049763e734f4b6f5c6e9e6c6765fb"
    "779297c175165648e9dc6d12c8c22fcde7d9b7a0eb58a6736ff9593f4b559603"
)


def test_body_sha256_vector_is_self_consistent():
    # Documents what BODY_SHA256 is (bytes 00..1f) so the vector is regenerable.
    assert BODY_SHA256 == bytes(range(32)).hex()


def test_report_id_derivation_matches_rust():
    # The relay's identity-free address ctx (_report_id_from_pk) must equal
    # Rust's CTX_REPORT_ID = "stream.report.id.v1".
    pk = bytes.fromhex(REPORT_PK)
    assert upload._report_id_from_pk(pk).hex() == REPORT_ID


def test_create_sig_verifies_on_relay():
    # 0x07 || report_id(16) || report_pk(32) — the exact message the relay
    # rebuilds in upload.py for a creating chunk.
    pk = bytes.fromhex(REPORT_PK)
    msg = (
        signature_domain.SIG_DOMAIN_REPORT_CREATE
        + bytes.fromhex(REPORT_ID)
        + pk
    )
    assert auth.verify_detached_ed25519(pk, bytes.fromhex(CREATE_SIG), msg)
    # Wrong domain (the write tag) must NOT verify — pins the 0x07/0x08 split.
    wrong = signature_domain.SIG_DOMAIN_REPORT_WRITE + bytes.fromhex(REPORT_ID) + pk
    assert not auth.verify_detached_ed25519(pk, bytes.fromhex(CREATE_SIG), wrong)


def test_write_sig_verifies_on_relay():
    # 0x08 || report_id(16) || filename || sha256(body)(32).
    pk = bytes.fromhex(REPORT_PK)
    msg = (
        signature_domain.SIG_DOMAIN_REPORT_WRITE
        + bytes.fromhex(REPORT_ID)
        + FILENAME.encode("utf-8")
        + bytes.fromhex(BODY_SHA256)
    )
    assert auth.verify_detached_ed25519(pk, bytes.fromhex(WRITE_SIG), msg)
    # Tamper the filename -> must fail (the write-sig binds the chunk name).
    bad_name = (
        signature_domain.SIG_DOMAIN_REPORT_WRITE
        + bytes.fromhex(REPORT_ID)
        + b"other.strm"
        + bytes.fromhex(BODY_SHA256)
    )
    assert not auth.verify_detached_ed25519(pk, bytes.fromhex(WRITE_SIG), bad_name)
    # Wrong domain (the create tag) must NOT verify.
    wrong_dom = (
        signature_domain.SIG_DOMAIN_REPORT_CREATE
        + bytes.fromhex(REPORT_ID)
        + FILENAME.encode("utf-8")
        + bytes.fromhex(BODY_SHA256)
    )
    assert not auth.verify_detached_ed25519(pk, bytes.fromhex(WRITE_SIG), wrong_dom)
