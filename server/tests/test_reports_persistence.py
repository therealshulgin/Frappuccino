#!/usr/bin/env python3
"""
test_reports_persistence.py — persistence of the report registry.

A record is `report_id -> report_pk` and nothing else: no owner, no author, no
createdAt. The three negative assertions in test_save_and_reload_roundtrip are
there for that reason, not out of tidiness — a seizure of reports.json must
reveal no identity and no timeline. Add a field "just to debug" and it is the
seizure that gains, not the debugging.

The registry is also where a report's closure lives, and that is why loading
is fail-closed: a relay that started on an empty registry after a corrupt file
would forget every closure in silence, and frozen reports would accept new names
again. The tests that once pinned "corrupt file -> empty registry" now pin the
refusal, down to a real process that will not start.

The rest — a durable save on every mutation (directory fsync included), a reload
at import time, the create_or_verify_report binding — is what the test names
say.
"""

import hashlib
import io
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

os.environ.setdefault("JWT_SECRET", "test-secret-do-not-use")

RID = "a" * 32
PK = "bb" * 32


@pytest.fixture()
def tmp_reports_db(monkeypatch):
    """Point REPORTS_DB_PATH at a per-test temp file and reload the modules."""
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "reports.json"
        monkeypatch.setenv("REPORTS_DB_PATH", str(path))
        for mod in ["app.config", "app.routes.reports", "app.routes", "app"]:
            sys.modules.pop(mod, None)
        yield path


def test_load_returns_empty_when_no_db_file(tmp_reports_db):
    from app.routes import reports
    assert reports._load_reports() == {}


def test_save_and_reload_roundtrip(tmp_reports_db):
    from app.routes import reports

    with reports._reports_lock:
        reports._reports[RID] = {"report_id": RID, "report_pk": PK}
        reports._save_reports_locked()

    on_disk = json.loads(tmp_reports_db.read_text())
    assert on_disk[RID] == {"report_id": RID, "report_pk": PK}
    # No identity-linking fields are ever persisted.
    assert "owner" not in on_disk[RID]
    assert "author" not in on_disk[RID]
    assert "createdAt" not in on_disk[RID]


def test_create_or_verify_report_binding(tmp_reports_db):
    from app.routes import reports

    # Absent -> created.
    assert reports.create_or_verify_report(RID, PK) is True
    assert reports.get_report(RID) == {"report_id": RID, "report_pk": PK}
    # Present, same pk -> idempotent verify.
    assert reports.create_or_verify_report(RID, PK) is True
    # Present, different pk -> rejected (binding pinned).
    assert reports.create_or_verify_report(RID, "cc" * 32) is False
    # Persisted to disk.
    on_disk = json.loads(tmp_reports_db.read_text())
    assert on_disk[RID]["report_pk"] == PK


def test_atomic_write_does_not_leave_temp_file(tmp_reports_db):
    from app.routes import reports

    reports.create_or_verify_report(RID, PK)
    parent = tmp_reports_db.parent
    leftover = [p for p in parent.iterdir() if p.name != tmp_reports_db.name]
    assert leftover == [], f"temp files left behind: {leftover}"


def test_load_corrupt_db_refuses(tmp_reports_db):
    from app.routes import reports

    tmp_reports_db.write_text("{not valid json", encoding="utf-8")
    with pytest.raises(reports.ReportsRegistryUnreadable):
        reports._load_reports()


def test_load_non_dict_db_refuses(tmp_reports_db):
    from app.routes import reports

    tmp_reports_db.write_text("[1, 2, 3]", encoding="utf-8")
    with pytest.raises(reports.ReportsRegistryUnreadable):
        reports._load_reports()


def test_load_non_dict_record_refuses(tmp_reports_db):
    from app.routes import reports

    tmp_reports_db.write_text(json.dumps({RID: "not-a-record"}), encoding="utf-8")
    with pytest.raises(reports.ReportsRegistryUnreadable):
        reports._load_reports()


def test_load_unreadable_db_refuses(tmp_reports_db):
    # A directory where the file should be: opening it raises an OSError other
    # than FileNotFoundError, which must not read as "no reports yet".
    from app.routes import reports

    tmp_reports_db.mkdir()
    with pytest.raises(reports.ReportsRegistryUnreadable):
        reports._load_reports()


def _start_relay(reports_path: Path, tmp: Path) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env.update({
        "REPORTS_DB_PATH": str(reports_path),
        "JWT_SECRET": "test-secret-do-not-use",
        "RATCHET_REGISTRY_FILE": str(tmp / "registry.json"),
        "NONCE_CACHE_FILE": str(tmp / "nonce.json"),
    })
    return subprocess.run(
        [sys.executable, "-c", "import app.main; print('relay-imported')"],
        cwd=PROJECT_ROOT, env=env, capture_output=True, text=True, timeout=120,
    )


def test_relay_process_refuses_to_start_on_corrupt_registry():
    # The real startup path, in a separate process: importing app.main loads
    # the registry. A corrupt file must stop it there.
    with tempfile.TemporaryDirectory() as tmp:
        reports_path = Path(tmp) / "reports.json"
        reports_path.write_text("{truncated", encoding="utf-8")
        done = _start_relay(reports_path, Path(tmp))
    assert done.returncode != 0
    assert "ReportsRegistryUnreadable" in done.stderr
    assert "relay-imported" not in done.stdout


def test_relay_process_starts_on_valid_registry():
    # Control for the test above: the same harness with a valid file starts,
    # so the refusal is the registry's doing, not the harness's.
    with tempfile.TemporaryDirectory() as tmp:
        reports_path = Path(tmp) / "reports.json"
        reports_path.write_text(
            json.dumps({RID: {"report_id": RID, "report_pk": PK}}), encoding="utf-8"
        )
        done = _start_relay(reports_path, Path(tmp))
    assert done.returncode == 0, done.stderr
    assert "relay-imported" in done.stdout


def test_save_fsyncs_the_directory_after_the_atomic_write(tmp_reports_db, monkeypatch):
    from app.routes import reports

    order = []
    real_save = reports.atomic_json_save

    def save(path, data, indent=None):
        order.append(("save", Path(path)))
        real_save(path, data, indent=indent)

    monkeypatch.setattr(reports, "atomic_json_save", save)
    monkeypatch.setattr(reports, "_fsync_directory", lambda d: order.append(("fsync_dir", Path(d))))
    reports.create_or_verify_report(RID, PK)
    assert order == [("save", tmp_reports_db), ("fsync_dir", tmp_reports_db.parent)]


@pytest.mark.skipif(os.name != "posix", reason="directory fsync exists on POSIX only")
def test_fsync_directory_really_fsyncs_on_posix(monkeypatch):
    from app.routes import reports

    calls = []
    real_fsync = os.fsync

    def spy(fd):
        calls.append(fd)
        real_fsync(fd)

    monkeypatch.setattr(reports.os, "fsync", spy)
    with tempfile.TemporaryDirectory() as tmp:
        reports._fsync_directory(Path(tmp))
    assert len(calls) == 1


def test_directory_fsync_failure_rolls_the_creation_back(tmp_reports_db, monkeypatch):
    from app.routes import reports

    def boom(_directory):
        raise OSError("fsync failed")

    monkeypatch.setattr(reports, "_fsync_directory", boom)
    with pytest.raises(OSError):
        reports.create_or_verify_report(RID, PK)
    assert reports.get_report(RID) is None


def _closure_args(manifest: bytes, seq_limit: int):
    sha = hashlib.sha256(manifest).hexdigest()
    return seq_limit, sha, "ab" * 64, io.BytesIO(manifest), len(manifest)


MANIFEST = b"FQM1" + (1).to_bytes(4, "big") + (0).to_bytes(4, "big") + bytes(32)


def test_create_or_verify_report_preserves_the_closure(tmp_reports_db, fake_minio):
    from app.routes import reports

    reports.create_or_verify_report(RID, PK)
    assert reports.close_report(RID, PK, *_closure_args(MANIFEST, 1)) == "recorded"
    before = json.loads(tmp_reports_db.read_text())[RID]["closure"]
    # A later creating PUT for the same report (a retry) verifies the binding and
    # leaves the record alone, closure included, in memory and on disk.
    assert reports.create_or_verify_report(RID, PK) is True
    assert reports.get_report(RID)["closure"] == before
    assert json.loads(tmp_reports_db.read_text())[RID]["closure"] == before


def test_closure_is_durable_and_survives_a_reload(tmp_reports_db, fake_minio):
    from app.routes import reports

    reports.create_or_verify_report(RID, PK)
    seq_limit, sha, sig, stream, length = _closure_args(MANIFEST, 1)
    reports.close_report(RID, PK, seq_limit, sha, sig, stream, length)
    expected = {"seq_limit": 1, "manifest_sha256": sha, "sig": sig}
    assert json.loads(tmp_reports_db.read_text())[RID]["closure"] == expected
    assert fake_minio.objects[f"{RID}/manifest"][0] == MANIFEST
    for mod in ["app.routes.reports", "app.routes"]:
        sys.modules.pop(mod, None)
    from app.routes import reports as reloaded

    assert reloaded.get_report(RID)["closure"] == expected
    assert reloaded.closed_seq_limit(reloaded.get_report(RID)) == 1


def test_close_report_save_failure_rolls_back_memory(tmp_reports_db, fake_minio, monkeypatch):
    from app.routes import reports

    reports.create_or_verify_report(RID, PK)
    real_save = reports._save_reports_locked

    def boom():
        raise OSError("disk full")

    monkeypatch.setattr(reports, "_save_reports_locked", boom)
    with pytest.raises(OSError):
        reports.close_report(RID, PK, *_closure_args(MANIFEST, 1))
    # Memory never claims a closure the disk does not hold...
    assert "closure" not in reports.get_report(RID)
    assert reports.closed_seq_limit(reports.get_report(RID)) is None
    # ...while the manifest stays stored, so the retry finds it identical.
    assert fake_minio.objects[f"{RID}/manifest"][0] == MANIFEST
    monkeypatch.setattr(reports, "_save_reports_locked", real_save)
    assert reports.close_report(RID, PK, *_closure_args(MANIFEST, 1)) == "recorded"


def test_close_report_outcomes(tmp_reports_db, fake_minio):
    from app.routes import reports

    with pytest.raises(reports.ReportUnknownError):
        reports.close_report(RID, PK, *_closure_args(MANIFEST, 1))
    reports.create_or_verify_report(RID, PK)
    with pytest.raises(reports.ReportKeyMismatchError):
        reports.close_report(RID, "cc" * 32, *_closure_args(MANIFEST, 1))
    assert reports.close_report(RID, PK, *_closure_args(MANIFEST, 1)) == "recorded"
    assert reports.close_report(RID, PK, *_closure_args(MANIFEST, 1)) == "identical"
    with pytest.raises(reports.ClosureConflictError):
        reports.close_report(RID, PK, *_closure_args(MANIFEST, 2))
    other = MANIFEST[:-1] + b"\x01"
    with pytest.raises(reports.ClosureConflictError):
        reports.close_report(RID, PK, *_closure_args(other, 1))


def test_reset_for_test_clears_disk(tmp_reports_db):
    from app.routes import reports

    reports.create_or_verify_report(RID, PK)
    assert tmp_reports_db.exists()

    reports._reset_for_test()
    assert not tmp_reports_db.exists()
    assert reports._reports == {}
