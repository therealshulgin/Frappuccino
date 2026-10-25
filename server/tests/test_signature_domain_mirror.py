#!/usr/bin/env python3
"""
test_signature_domain_mirror.py — the relay's signature domain tags are a
mirror of ``crypto-rs/core/src/signature_domain.rs``, checked against that file.

The KATs (test_auth_sig_kat.py, test_report_sig_kat.py, test_report_close_kat.py)
catch a drift in the bytes a signature covers, but only for the contexts they
have vectors for. This file checks the table itself: the exact set of tags the
relay knows, that each one has the value of its Rust enum variant, and that the
Rust enum holds no tag this mirror has not accounted for. A new signing context
added on one side only makes it red; the fix is to decide, here, whether the
relay verifies it.

0x05 and 0x06 are Rust-only on purpose: retired provenance tags, reserved there
and never mirrored here (see app/signature_domain.py).
"""

import os
import re
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
REPO_ROOT = PROJECT_ROOT.parent
sys.path.insert(0, str(PROJECT_ROOT))

os.environ.setdefault("JWT_SECRET", "test-secret-do-not-use")

from app import signature_domain  # noqa: E402

RUST_SOURCE = REPO_ROOT / "crypto-rs" / "core" / "src" / "signature_domain.rs"

# Python constant -> (tag, Rust variant).
MIRRORED = {
    "SIG_DOMAIN_AUTH_CHALLENGE": (b"\x01", "AuthChallenge"),
    "SIG_DOMAIN_BATCH_ROTATION": (b"\x02", "BatchRotation"),
    "SIG_DOMAIN_ENROLLMENT": (b"\x03", "Enrollment"),
    "SIG_DOMAIN_ARCHIVE_AUTH": (b"\x04", "ArchiveAuth"),
    "SIG_DOMAIN_REPORT_CREATE": (b"\x07", "ReportCreate"),
    "SIG_DOMAIN_REPORT_WRITE": (b"\x08", "ReportWrite"),
    "SIG_DOMAIN_REPORT_CLOSE": (b"\x09", "ReportClose"),
}
RUST_ONLY = {"ProvenanceManifest": 0x05, "ProvenanceKeyAttestation": 0x06}


def _rust_tags() -> dict[str, int]:
    source = RUST_SOURCE.read_text(encoding="utf-8")
    body = re.search(r"pub enum SignatureDomain \{(.*?)\n\}", source, re.S)
    assert body is not None, f"SignatureDomain enum not found in {RUST_SOURCE}"
    found = re.findall(r"^\s*([A-Z]\w*)\s*=\s*0x([0-9A-Fa-f]{2})\s*,", body.group(1), re.M)
    return {name: int(value, 16) for name, value in found}


def test_python_mirror_is_exactly_the_expected_set():
    actual = {n: getattr(signature_domain, n) for n in dir(signature_domain)
              if n.startswith("SIG_DOMAIN_")}
    assert actual == {n: tag for n, (tag, _) in MIRRORED.items()}
    tags = list(actual.values())
    assert all(len(t) == 1 for t in tags)
    assert len(set(tags)) == len(tags), "two contexts share a tag"
    assert not {b"\x05", b"\x06"} & set(tags), "a retired tag was reused"


def test_rust_enum_holds_no_tag_this_mirror_has_not_accounted_for():
    known = {rust for _, rust in MIRRORED.values()} | set(RUST_ONLY)
    unknown = sorted(set(_rust_tags()) - known)
    assert not unknown, (
        f"crypto-rs SignatureDomain has {unknown}, unknown to the relay mirror. "
        "If the relay verifies it, mirror it in app/signature_domain.py; either "
        "way, account for it here."
    )


def test_rust_only_tags_keep_their_reserved_values():
    rust = _rust_tags()
    for name, tag in RUST_ONLY.items():
        assert rust.get(name) == tag


def test_mirrored_tags_equal_their_rust_variants():
    rust = _rust_tags()
    for py_name, (tag, rust_name) in MIRRORED.items():
        if rust_name == "ReportClose":
            continue  # its own test below
        assert rust_name in rust, f"{rust_name} missing from {RUST_SOURCE.name}"
        assert rust[rust_name] == tag[0], py_name


def test_report_close_equals_its_rust_variant():
    rust = _rust_tags()
    if "ReportClose" not in rust:
        pytest.skip("crypto-rs has no SignatureDomain::ReportClose yet")
    assert rust["ReportClose"] == signature_domain.SIG_DOMAIN_REPORT_CLOSE[0] == 0x09
