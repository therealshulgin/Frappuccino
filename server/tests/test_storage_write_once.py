#!/usr/bin/env python3
"""
test_storage_write_once.py — §10.6 write-once overwrite gate.

A byte-identical re-PUT of storage.upload_blob_stream_write_once must stay a
silent no-op and never become a 409. Legitimate retries (1.12 and 3.41 both rely
on an idempotent re-PUT) and client/server races are the normal regime, and a
false 409 makes the client drop the chunk — the very data loss write-once is
layered on top of, back through the front door. The obvious hardening, "key
occupied, so 409", is the bug.

A PUT of DIFFERENT bytes onto an occupied key does conflict, and that one is
anti-tampering: an upload JWT that leaked cannot corrupt a witness chunk already
stored on the relay.

The rest is the mapping the tests below walk through — a free key is written, an
empty body stays a no-op, and a full disk still surfaces as StorageFullError
(→ 507) on the create path. The MinIO client is mocked, so the test never
touches a real backend.

Run via:
    JWT_SECRET=dummy uv run --with pytest --with-requirements \
        server/requirements.txt python -m pytest \
        server/tests/test_storage_write_once.py -v
"""

import hashlib
import io
import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from minio.error import S3Error

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# config.py exits if JWT_SECRET is missing — set before importing app.*
os.environ["JWT_SECRET"] = "test-secret-do-not-use"
_tmp = tempfile.mkdtemp()
os.environ.setdefault("RATCHET_REGISTRY_FILE", os.path.join(_tmp, "registry.json"))

from app import storage  # noqa: E402


def _s3err(code: str) -> S3Error:
    """Build an S3Error robustly across minio-py signature variants."""
    try:
        return S3Error(code, "boom", "/x", "req-id", "host-id", MagicMock())
    except TypeError:
        return S3Error(
            code=code, message="boom", resource="/x",
            request_id="req-id", host_id="host-id", response=MagicMock(),
        )


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class _FakeGetObject:
    """Mimics the minio get_object response: chunked .read(n) + close/release."""

    def __init__(self, data: bytes):
        self._buf = io.BytesIO(data)

    def read(self, n: int = -1) -> bytes:
        return self._buf.read(n)

    def close(self):
        pass

    def release_conn(self):
        pass


def _client_absent() -> MagicMock:
    """A MinIO client where the target key does NOT exist."""
    client = MagicMock()
    client.stat_object.side_effect = _s3err("NoSuchKey")
    return client


def _client_holding(data: bytes) -> MagicMock:
    """A MinIO client where the target key already holds `data`."""
    client = MagicMock()
    client.stat_object.return_value = MagicMock(size=len(data))
    client.get_object.return_value = _FakeGetObject(data)
    return client


def test_new_object_is_written(monkeypatch):
    data = b"x" * 1234
    client = _client_absent()
    monkeypatch.setattr(storage, "_client", client)
    result = storage.upload_blob_stream_write_once(
        "rid", "chunk_1.strm", io.BytesIO(data), len(data), _sha(data)
    )
    assert result == "created"
    client.put_object.assert_called_once()


def test_identical_reput_is_noop(monkeypatch):
    data = b"sealed-strm-bytes" * 64
    client = _client_holding(data)
    monkeypatch.setattr(storage, "_client", client)
    result = storage.upload_blob_stream_write_once(
        "rid", "chunk_1.strm", io.BytesIO(data), len(data), _sha(data)
    )
    assert result == "identical"
    # The stored bytes are left exactly as they are — no rewrite.
    client.put_object.assert_not_called()


def test_different_content_conflicts(monkeypatch):
    stored = b"authentic-witness-chunk" * 64
    attacker = b"garbage-overwrite-attempt" * 64
    client = _client_holding(stored)
    monkeypatch.setattr(storage, "_client", client)
    with pytest.raises(storage.WriteOnceConflictError):
        storage.upload_blob_stream_write_once(
            "rid", "chunk_1.strm", io.BytesIO(attacker), len(attacker), _sha(attacker)
        )
    # The authentic stored object is never overwritten.
    client.put_object.assert_not_called()


def test_empty_body_is_noop(monkeypatch):
    client = MagicMock()
    monkeypatch.setattr(storage, "_client", client)
    result = storage.upload_blob_stream_write_once(
        "rid", "f", io.BytesIO(b""), 0, _sha(b"")
    )
    assert result == "empty"
    client.stat_object.assert_not_called()
    client.put_object.assert_not_called()


def test_disk_full_on_create_still_507(monkeypatch):
    data = b"x" * 10
    client = _client_absent()
    client.put_object.side_effect = _s3err("XMinioStorageFull")
    monkeypatch.setattr(storage, "_client", client)
    with pytest.raises(storage.StorageFullError):
        storage.upload_blob_stream_write_once(
            "rid", "chunk_1.strm", io.BytesIO(data), len(data), _sha(data)
        )


def test_other_s3error_on_stat_propagates(monkeypatch):
    client = MagicMock()
    client.stat_object.side_effect = _s3err("AccessDenied")
    monkeypatch.setattr(storage, "_client", client)
    with pytest.raises(S3Error):
        storage.upload_blob_stream_write_once(
            "rid", "chunk_1.strm", io.BytesIO(b"x" * 10), 10, _sha(b"x" * 10)
        )
    client.put_object.assert_not_called()
