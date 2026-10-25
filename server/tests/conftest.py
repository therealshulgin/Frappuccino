"""Pytest collection config.

``test_server.py``, ``test_e2e_v2.py`` and ``test_auth_v2.py`` must stay out of
collection. Each is a standalone script that defines a top-level
``def test(name, ...)`` helper and drives its own assertions from a ``__main__``
block; pytest reads that helper as a test function and errors on a missing
``name`` fixture. Putting them back to "recover some coverage" turns the whole
suite red on a fixture error that has nothing to do with the code. They stay
runnable on their own (``python tests/test_X.py``) for live-relay smoke testing.

The flows themselves are covered as first-class pytest, all through the FastAPI
``TestClient``: relay-blind report / upload / archive in
``test_relay_blind_reports.py``, V2 enrollment and batch rotation in
``test_rotate_batch_oracle.py`` and ``test_relay_blind_hardening.py``. The one
gap the exclusion leaves is ``POST /auth/v2/verify``, exercised only by the
ignored ``test_e2e_v2.py``.

``fake_minio`` swaps the storage module's MinIO client for an in-memory one, so
a route test runs the real ``app.storage`` logic rather than a stub of it.
"""

import os
import sys
import tempfile
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# Non-destructive env defaults so any pytest module (or the limiter import in the
# fixture below) has a config even if its own module-level setup is skipped.
# Tests that hard-set these still win (they run after conftest import).
os.environ.setdefault("JWT_SECRET", "test-secret-do-not-use")
os.environ.setdefault("MINIO_ACCESS_KEY", "dummy")
os.environ.setdefault("MINIO_SECRET_KEY", "dummy")
_tmp = tempfile.mkdtemp()
os.environ.setdefault("RATCHET_REGISTRY_FILE", os.path.join(_tmp, "registry.json"))
os.environ.setdefault("REPORTS_DB_PATH", os.path.join(_tmp, "reports.json"))
os.environ.setdefault("NONCE_CACHE_FILE", os.path.join(_tmp, "nonce.json"))

collect_ignore = ["test_server.py", "test_e2e_v2.py", "test_auth_v2.py"]


def s3_error(code: str):
    """Build an S3Error robustly across minio-py signature variants."""
    from unittest.mock import MagicMock

    from minio.error import S3Error

    try:
        return S3Error(code, "boom", "/x", "req-id", "host-id", MagicMock())
    except TypeError:
        return S3Error(
            code=code, message="boom", resource="/x",
            request_id="req-id", host_id="host-id", response=MagicMock(),
        )


def _as_stored_metadata(metadata):
    # MinIO hands user metadata back as canonicalised headers
    # ("X-Amz-Meta-Report-Write-Sig"), not in the case it was sent in. The fake
    # does the same, so a lookup that only works in one case goes red here.
    out = {}
    for key, value in (metadata or {}).items():
        if key.lower().startswith("x-amz-meta-"):
            out["-".join(part.capitalize() for part in key.split("-"))] = value
    return out


class _Reader:
    def __init__(self, data: bytes):
        import io

        self._buf = io.BytesIO(data)

    def read(self, n: int = -1) -> bytes:
        return self._buf.read(n)

    def close(self):
        pass

    def release_conn(self):
        pass


class FakeMinio:
    """In-memory stand-in for the few minio client calls app.storage makes, so
    route tests run the real storage code (write-once, closure rule, metadata)
    instead of a re-implementation of it. `calls` records (operation, key)."""

    def __init__(self):
        self.objects: dict[str, tuple[bytes, dict]] = {}
        self.calls: list[tuple[str, str]] = []
        self.disk_full = False

    def stat_object(self, bucket, path):
        from types import SimpleNamespace

        self.calls.append(("stat", path))
        if path not in self.objects:
            raise s3_error("NoSuchKey")
        data, meta = self.objects[path]
        return SimpleNamespace(size=len(data), metadata=dict(meta))

    def get_object(self, bucket, path):
        self.calls.append(("get", path))
        return _Reader(self.objects[path][0])

    def put_object(self, bucket, path, data, length,
                   content_type="application/octet-stream", metadata=None):
        self.calls.append(("put", path))
        if self.disk_full:
            raise s3_error("XMinioStorageFull")
        raw = data.read(length)
        assert len(raw) == length
        self.objects[path] = (raw, _as_stored_metadata(metadata))

    def copy_object(self, bucket, path, source, metadata=None, metadata_directive=None):
        self.calls.append(("copy", path))
        assert (source.bucket_name, source.object_name) == (bucket, path)
        assert metadata_directive == "REPLACE"
        if self.disk_full:
            raise s3_error("XMinioStorageFull")
        data, _ = self.objects[path]
        self.objects[path] = (data, _as_stored_metadata(metadata))

    def list_objects(self, bucket, prefix="", recursive=False):
        from types import SimpleNamespace

        for path in sorted(self.objects):
            if path.startswith(prefix):
                yield SimpleNamespace(
                    object_name=path, size=len(self.objects[path][0]), last_modified=None
                )


@pytest.fixture()
def fake_minio(monkeypatch):
    from app import storage

    fake = FakeMinio()
    monkeypatch.setattr(storage, "_client", fake)
    return fake


@pytest.fixture(autouse=True)
def _reset_rate_limiter():
    # WP-B2 — the app-wide limiter (app/ratelimit.py) now enforces real
    # per-(client IP, endpoint) limits. Under pytest every TestClient request
    # comes from the same `testclient` host, so without a reset the counters
    # accumulate ACROSS tests within one wall-clock minute and a late test can
    # spuriously hit a 429. Reset around each test so buckets start empty.
    from app.ratelimit import limiter

    limiter.reset()
    yield
    limiter.reset()
