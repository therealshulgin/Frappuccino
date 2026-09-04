#!/usr/bin/env python3
"""
test_report_cleanup.py — the reaper for report records left with no blobs.

Never add a createdAt to a record in order to decide what to reap.
reap_blobless_reports needs no per-record timestamp, and that is deliberate:
with the lazy blob-first invariant (a record is written only after at least one
durable blob exists), a record down to zero blobs means blob_cleanup already
purged them all at the long retention TTL, so "no blob left" already means "old
enough". A date would put back on the relay the per-report timeline the registry
refuses to hold.

And never reap on a count we could not verify: if list_blobs raises, the record
is kept, or one MinIO outage wipes the whole registry. That is what
test_list_blobs_failure_keeps_report pins; its name alone does not say why.
storage.list_blobs is monkeypatched here, so no real MinIO is involved.
"""

import json
import sys
import tempfile
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


@pytest.fixture()
def reports_mod(monkeypatch):
    """Fresh reports module pointed at a temp DB, with storage.list_blobs mocked
    from a per-test {report_id: blob_count} table."""
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "reports.json"
        monkeypatch.setenv("REPORTS_DB_PATH", str(path))
        monkeypatch.setenv("JWT_SECRET", "test-secret-do-not-use")
        for mod in ["app.config", "app.routes.reports", "app.routes", "app"]:
            sys.modules.pop(mod, None)
        from app.routes import reports

        blob_counts: dict[str, int] = {}

        def fake_list_blobs(rid: str):
            n = blob_counts.get(rid, 0)
            return [{"filename": f"chunk_{i}", "size": 1} for i in range(n)]

        monkeypatch.setattr(reports.storage, "list_blobs", fake_list_blobs)
        yield reports, path, blob_counts


def _put(reports, rid: str, blobs: int, blob_counts: dict):
    with reports._reports_lock:
        reports._reports[rid] = {"report_id": rid, "report_pk": "bb" * 32}
    blob_counts[rid] = blobs


def test_blobless_report_is_reaped(reports_mod):
    reports, _path, blob_counts = reports_mod
    _put(reports, "a" * 32, 0, blob_counts)
    deleted, remaining = reports.reap_blobless_reports()
    assert deleted == 1
    assert remaining == 0
    assert "a" * 32 not in reports._reports


def test_report_with_blobs_is_kept(reports_mod):
    reports, _path, blob_counts = reports_mod
    _put(reports, "b" * 32, 85, blob_counts)
    deleted, _remaining = reports.reap_blobless_reports()
    assert deleted == 0
    assert "b" * 32 in reports._reports


def test_single_blob_report_is_kept(reports_mod):
    reports, _path, blob_counts = reports_mod
    _put(reports, "c" * 32, 1, blob_counts)
    deleted, _remaining = reports.reap_blobless_reports()
    assert deleted == 0
    assert "c" * 32 in reports._reports


def test_mix_only_blobless_reaped_and_persisted(reports_mod):
    reports, path, blob_counts = reports_mod
    _put(reports, "d" * 32, 0, blob_counts)   # reap
    _put(reports, "e" * 32, 10, blob_counts)  # keep
    _put(reports, "f" * 32, 0, blob_counts)   # reap

    deleted, remaining = reports.reap_blobless_reports()
    assert deleted == 2
    assert remaining == 1
    assert set(reports._reports.keys()) == {"e" * 32}
    # The deletion must be persisted atomically to disk.
    on_disk = json.loads(path.read_text())
    assert set(on_disk.keys()) == {"e" * 32}


def test_list_blobs_failure_keeps_report(reports_mod, monkeypatch):
    # If list_blobs() throws for a report, KEEP it (never delete on an
    # unverified blob count) while still processing the others.
    reports, _path, blob_counts = reports_mod
    _put(reports, "b" * 32, 0, blob_counts)        # will raise (boom)
    _put(reports, "0" * 32, 0, blob_counts)        # verified empty -> reaped

    def flaky_list_blobs(rid: str):
        if rid == "b" * 32:
            raise RuntimeError("MinIO down")
        return []

    monkeypatch.setattr(reports.storage, "list_blobs", flaky_list_blobs)
    deleted, _remaining = reports.reap_blobless_reports()
    assert deleted == 1
    assert "b" * 32 in reports._reports   # kept (unverified)
    assert "0" * 32 not in reports._reports  # reaped (verified empty)


def test_no_reports_is_noop(reports_mod):
    reports, _path, _blob_counts = reports_mod
    deleted, remaining = reports.reap_blobless_reports()
    assert deleted == 0
    assert remaining == 0
