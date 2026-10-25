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
(→ 507) on the create path. Then the two additions: the write signature rides
the creating put_object as user metadata (and an identical re-PUT attaches it to
an object that lacks it), and a closed report refuses a new name on the same
single stat that tests existence. The MinIO client is mocked, so the test never
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


def _client_holding(data: bytes, metadata: dict | None = None) -> MagicMock:
    """A MinIO client where the target key already holds `data`. `metadata` is
    explicit: a bare MagicMock attribute would answer every lookup with another
    MagicMock instead of saying "absent"."""
    client = MagicMock()
    client.stat_object.return_value = MagicMock(size=len(data), metadata=dict(metadata or {}))
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


# ---------------------------------------------------------------------------
# Write signature kept as user metadata
# ---------------------------------------------------------------------------

SIG = "ab" * 64
OTHER_SIG = "cd" * 64


def test_creating_put_carries_the_write_sig_metadata(monkeypatch):
    # The signature rides the SAME put_object that creates the object: there is
    # no instant at which the object exists without it.
    data = b"x" * 64
    client = _client_absent()
    monkeypatch.setattr(storage, "_client", client)
    result = storage.upload_blob_stream_write_once(
        "rid", "000001.strm", io.BytesIO(data), len(data), _sha(data), write_sig_hex=SIG
    )
    assert result == "created"
    client.put_object.assert_called_once()
    assert client.put_object.call_args.kwargs["metadata"] == {storage.WRITE_SIG_METADATA_KEY: SIG}
    client.copy_object.assert_not_called()


def test_identical_reput_attaches_a_missing_write_sig(monkeypatch):
    data = b"legacy-object" * 8
    client = _client_holding(data, metadata={})
    monkeypatch.setattr(storage, "_client", client)
    result = storage.upload_blob_stream_write_once(
        "rid", "000001.strm", io.BytesIO(data), len(data), _sha(data), write_sig_hex=SIG
    )
    assert result == "identical"
    client.put_object.assert_not_called()
    client.copy_object.assert_called_once()
    args, kwargs = client.copy_object.call_args
    # A copy of the object onto its own key, replacing the metadata.
    assert args[1] == "rid/000001.strm"
    assert (args[2].bucket_name, args[2].object_name) == (args[0], "rid/000001.strm")
    assert kwargs["metadata_directive"] == "REPLACE"
    assert kwargs["metadata"][storage.WRITE_SIG_METADATA_KEY] == SIG


def test_identical_reput_leaves_a_present_write_sig_alone(monkeypatch):
    # Present in MinIO's canonical case: the lookup must not miss it and copy.
    data = b"stored" * 8
    client = _client_holding(data, metadata={"X-Amz-Meta-Report-Write-Sig": OTHER_SIG})
    monkeypatch.setattr(storage, "_client", client)
    result = storage.upload_blob_stream_write_once(
        "rid", "000001.strm", io.BytesIO(data), len(data), _sha(data), write_sig_hex=SIG
    )
    assert result == "identical"
    client.copy_object.assert_not_called()


def test_identical_reput_without_a_sig_never_copies(monkeypatch):
    data = b"stored" * 8
    client = _client_holding(data, metadata={})
    monkeypatch.setattr(storage, "_client", client)
    storage.upload_blob_stream_write_once(
        "rid", "000001.strm", io.BytesIO(data), len(data), _sha(data)
    )
    client.copy_object.assert_not_called()


def test_malformed_write_sig_is_refused_before_any_io(monkeypatch):
    client = MagicMock()
    monkeypatch.setattr(storage, "_client", client)
    for bad in ("AB" * 64, "ab" * 63, "zz" * 64, ""):
        with pytest.raises(ValueError):
            storage.upload_blob_stream_write_once(
                "rid", "000001.strm", io.BytesIO(b"x"), 1, _sha(b"x"), write_sig_hex=bad
            )
    client.stat_object.assert_not_called()
    client.put_object.assert_not_called()


def test_disk_full_on_the_metadata_copy_is_storage_full(monkeypatch):
    data = b"legacy" * 8
    client = _client_holding(data, metadata={})
    client.copy_object.side_effect = _s3err("XMinioStorageFull")
    monkeypatch.setattr(storage, "_client", client)
    with pytest.raises(storage.StorageFullError):
        storage.upload_blob_stream_write_once(
            "rid", "000001.strm", io.BytesIO(data), len(data), _sha(data), write_sig_hex=SIG
        )


def test_stat_blob_reports_size_and_write_sig(monkeypatch):
    client = MagicMock()
    client.stat_object.return_value = MagicMock(
        size=12, metadata={"X-Amz-Meta-Report-Write-Sig": SIG, "Content-Type": "x"}
    )
    monkeypatch.setattr(storage, "_client", client)
    assert storage.stat_blob("rid", "000001.strm") == storage.BlobInfo(size=12, write_sig_hex=SIG)


@pytest.mark.parametrize("metadata", [{}, {"X-Amz-Meta-Report-Write-Sig": "not-hex"},
                                      {"X-Amz-Meta-Report-Write-Sig": "AB" * 64}])
def test_stat_blob_without_a_valid_write_sig(monkeypatch, metadata):
    client = MagicMock()
    client.stat_object.return_value = MagicMock(size=12, metadata=metadata)
    monkeypatch.setattr(storage, "_client", client)
    assert storage.stat_blob("rid", "000001.strm") == storage.BlobInfo(size=12, write_sig_hex=None)


def test_stat_blob_absent_is_none(monkeypatch):
    monkeypatch.setattr(storage, "_client", _client_absent())
    assert storage.stat_blob("rid", "000001.strm") is None


# ---------------------------------------------------------------------------
# Closure rule: decided on the single stat that tests existence
# ---------------------------------------------------------------------------

def test_closed_report_refuses_a_new_name_on_one_stat(monkeypatch):
    client = _client_absent()
    monkeypatch.setattr(storage, "_client", client)
    with pytest.raises(storage.ReportClosedError):
        storage.upload_blob_stream_write_once(
            "rid", "000005.strm", io.BytesIO(b"x"), 1, _sha(b"x"),
            write_sig_hex=SIG, closed_seq_limit=5,
        )
    assert client.stat_object.call_count == 1
    client.get_object.assert_not_called()
    client.put_object.assert_not_called()


def test_closed_report_admits_a_late_chunk_below_seq_limit(monkeypatch):
    client = _client_absent()
    monkeypatch.setattr(storage, "_client", client)
    result = storage.upload_blob_stream_write_once(
        "rid", "000004.strm", io.BytesIO(b"x"), 1, _sha(b"x"),
        write_sig_hex=SIG, closed_seq_limit=5,
    )
    assert result == "created"
    assert client.stat_object.call_count == 1
    client.put_object.assert_called_once()


def test_closed_report_keeps_write_once_for_existing_objects(monkeypatch):
    # Even a legacy closure (seq_limit 0), which admits no new name at all,
    # answers an existing object with write-once semantics, not "closed".
    data = b"stored-before-the-close" * 4
    client = _client_holding(data, metadata={"X-Amz-Meta-Report-Write-Sig": SIG})
    monkeypatch.setattr(storage, "_client", client)
    assert storage.upload_blob_stream_write_once(
        "rid", "sid_000001.strm", io.BytesIO(data), len(data), _sha(data),
        write_sig_hex=SIG, closed_seq_limit=0,
    ) == "identical"
    with pytest.raises(storage.WriteOnceConflictError):
        storage.upload_blob_stream_write_once(
            "rid", "sid_000001.strm", io.BytesIO(b"other"), 5, _sha(b"other"),
            write_sig_hex=SIG, closed_seq_limit=0,
        )
    client.put_object.assert_not_called()
