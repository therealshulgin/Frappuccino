#!/usr/bin/env python3
"""
test_reports_persistence.py — persistence of the report registry.

A record is `report_id -> report_pk` and nothing else: no owner, no author, no
createdAt. The three negative assertions in test_save_and_reload_roundtrip are
there for that reason, not out of tidiness — a seizure of reports.json must
reveal no identity and no timeline. Add a field "just to debug" and it is the
seizure that gains, not the debugging.

The rest — a save on every mutation, a reload at import time, the
create_or_verify_report binding — is what the test names say.
"""

import json
import os
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


def test_load_corrupt_db_resets_to_empty(tmp_reports_db):
    tmp_reports_db.write_text("{not valid json", encoding="utf-8")
    from app.routes import reports
    assert reports._load_reports() == {}


def test_load_non_dict_db_resets_to_empty(tmp_reports_db):
    tmp_reports_db.write_text("[1, 2, 3]", encoding="utf-8")
    from app.routes import reports
    assert reports._load_reports() == {}


def test_reset_for_test_clears_disk(tmp_reports_db):
    from app.routes import reports

    reports.create_or_verify_report(RID, PK)
    assert tmp_reports_db.exists()

    reports._reset_for_test()
    assert not tmp_reports_db.exists()
    assert reports._reports == {}
