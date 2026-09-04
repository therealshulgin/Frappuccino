#!/usr/bin/env python3
"""Regression guard for the rate-limit wiring (WP-B2).

Two slowapi semantics, each of which fails SILENTLY when violated:

  1. A ``@limiter.limit`` is enforced only if the instance that decorates the
     route is the one registered as ``app.state.limiter``. A route module that
     builds its own ``Limiter()`` — the natural gesture — turns every one of its
     limits into a no-op. Hence the single shared instance in
     ``app/ratelimit.py``, imported everywhere.
  2. ``key_style="url"``, slowapi's default, keys each limit by the *filled*
     request path. ``PUT /file/{report_id}/{filename}`` carries a chunk name
     that is unique per upload, so every request landed in a fresh bucket and
     the counter never accumulated. Hence ``key_style="endpoint"``, which keys
     by the view function.

Both were live at once, and every limit on the relay except /health was a no-op
in production: no brute-force and no flood protection, and not one red test.
These go red if either regresses. The autouse fixture in conftest.py resets the
limiter around each test, so the bursts below stay isolated from the others.
"""

import os
import sys
import tempfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

os.environ.setdefault("JWT_SECRET", "test-secret-do-not-use")
os.environ.setdefault("MINIO_ACCESS_KEY", "dummy")
os.environ.setdefault("MINIO_SECRET_KEY", "dummy")
_tmp = tempfile.mkdtemp()
os.environ.setdefault("RATCHET_REGISTRY_FILE", os.path.join(_tmp, "registry.json"))
os.environ.setdefault("REPORTS_DB_PATH", os.path.join(_tmp, "reports.json"))
os.environ.setdefault("NONCE_CACHE_FILE", os.path.join(_tmp, "nonce.json"))

from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402

client = TestClient(app)

# The PUT limit (app/routes/upload.py). Kept in sync deliberately: if the limit
# is retuned, update this too.
PUT_LIMIT_PER_MIN = 600


def test_put_limit_enforces_across_unique_filenames():
    # Guards BOTH fixes at once. Every request uses a UNIQUE filename — the exact
    # shape that key_style="url" silently exempted. Bare PUTs fail header
    # validation (400) UNTIL the per-IP cap trips and slowapi returns 429.
    rid = "a" * 32
    saw_429 = False
    saw_400 = False
    # Fire up to 2x the limit so a rare wall-clock-minute boundary split still
    # leaves one bucket above the cap. Stop early once the limit fires.
    for i in range(PUT_LIMIT_PER_MIN * 2 + 20):
        code = client.put(f"/file/{rid}/chunk_{i}.strm").status_code
        if code == 400:
            saw_400 = True
        if code == 429:
            saw_429 = True
            break
    assert saw_400, "under-limit PUTs should reach the handler (400 missing header)"
    assert saw_429, (
        "PUT rate limit never fired across unique filenames — slowapi wiring "
        "regressed (shared instance and/or key_style='endpoint')"
    )


def test_health_limit_enforces():
    # The no-path-param control: /health is limited at 30/min on the app-level
    # limiter. Proves the shared limiter is registered and enforcing.
    codes = [client.get("/health").status_code for _ in range(33)]
    assert codes.count(200) == 30
    assert codes.count(429) == 3


def test_shared_limiter_is_app_state_limiter():
    # The structural invariant behind fix #1: every router's limiter must BE the
    # one registered on the app, or its @limiter.limit decorators are no-ops.
    from app.ratelimit import limiter as shared
    from app.routes.upload import limiter as upload_lim
    from app.routes.auth_v2 import limiter as auth_lim
    from app.routes.archive import limiter as archive_lim

    assert shared is app.state.limiter
    assert upload_lim is app.state.limiter
    assert auth_lim is app.state.limiter
    assert archive_lim is app.state.limiter
    # And the key style must stay "endpoint" (fix #2).
    assert app.state.limiter._key_style == "endpoint"
