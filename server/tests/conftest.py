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
