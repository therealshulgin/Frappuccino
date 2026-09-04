#!/usr/bin/env python3
"""
test_storage_disk_full.py — only a full MinIO disk becomes StorageFullError.

Every other S3Error has to keep propagating untranslated (→ HTTP 500):
translating more widely would report an AccessDenied or a misconfiguration as a
full disk. Why a full disk deserves an exception of its own is in
storage.StorageFullError. The MinIO client is mocked, so the test never touches
a real backend.

Run via:
    JWT_SECRET=dummy uv run --with pytest --with-requirements \
        server/requirements.txt python -m pytest \
        server/tests/test_storage_disk_full.py -v
"""

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
    """Build an S3Error robustly across minio-py signature variants. The
    response arg is a MagicMock so any attribute access stays inert."""
    try:
        return S3Error(code, "boom", "/x", "req-id", "host-id", MagicMock())
    except TypeError:
        return S3Error(
            code=code, message="boom", resource="/x",
            request_id="req-id", host_id="host-id", response=MagicMock(),
        )


@pytest.mark.parametrize(
    "code",
    ["XMinioStorageFull", "StorageFull", "InsufficientStorage", "xminiostoragefull"],
)
def test_is_disk_full_true(code):
    assert storage._is_disk_full(_s3err(code)) is True


@pytest.mark.parametrize("code", ["AccessDenied", "NoSuchKey", "InternalError", ""])
def test_is_disk_full_false(code):
    assert storage._is_disk_full(_s3err(code)) is False


def test_upload_blob_stream_raises_storage_full(monkeypatch):
    client = MagicMock()
    client.put_object.side_effect = _s3err("XMinioStorageFull")
    monkeypatch.setattr(storage, "_client", client)
    with pytest.raises(storage.StorageFullError):
        storage.upload_blob_stream("rid", "chunk_1.strm", io.BytesIO(b"x" * 10), 10)


def test_upload_blob_raises_storage_full(monkeypatch):
    client = MagicMock()
    client.put_object.side_effect = _s3err("InsufficientStorage")
    monkeypatch.setattr(storage, "_client", client)
    with pytest.raises(storage.StorageFullError):
        storage.upload_blob("rid", "chunk_1.strm", b"x" * 10)


def test_other_s3error_propagates_untranslated(monkeypatch):
    client = MagicMock()
    client.put_object.side_effect = _s3err("AccessDenied")
    monkeypatch.setattr(storage, "_client", client)
    with pytest.raises(S3Error):
        storage.upload_blob_stream("rid", "chunk_1.strm", io.BytesIO(b"x" * 10), 10)


def test_empty_upload_is_noop(monkeypatch):
    client = MagicMock()
    monkeypatch.setattr(storage, "_client", client)
    storage.upload_blob_stream("rid", "f", io.BytesIO(b""), 0)
    storage.upload_blob("rid", "f", b"")
    client.put_object.assert_not_called()
