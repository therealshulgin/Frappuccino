#!/usr/bin/env python3
"""
test_timestamp_routes.py — §10.11 the relay-assisted OpenTimestamps endpoint.

app.timestamp_ots.stamp_digest stays mocked in every test here. Nothing in this
suite may reach a real calendar: doing it "for realism" would publish a
commitment to third parties straight from CI, and it would tie the suite to the
optional `opentimestamps` library, which is not installed by default.

The route loads even when the feature is off: with OTS_ENABLED unset it answers
503, which is what test_dormant_by_default_returns_503 pins. The other tests
walk the status mapping: a stamp takes a stream-scope JWT and nothing else —
any other scope is refused with 403 (R-H2) — then malformed commitment,
success, calendars unreachable, library absent.

Run via:
    JWT_SECRET=dummy uv run --with-requirements server/requirements.txt \
        --with pytest python -m pytest server/tests/test_timestamp_routes.py -v
"""

import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

GOOD_COMMITMENT = "11" * 32  # 32 bytes, 64 hex chars


@pytest.fixture()
def client(monkeypatch):
    with tempfile.TemporaryDirectory() as tmp:
        monkeypatch.setenv("REPORTS_DB_PATH", str(Path(tmp) / "reports.json"))
        # Force module reload so a clean app (and config) is built per test.
        for mod in list(sys.modules):
            if mod.startswith("app"):
                sys.modules.pop(mod, None)
        from fastapi.testclient import TestClient
        from app import main

        yield TestClient(main.app)


def _stream_token(subject: str = "u" * 64) -> str:
    from app import auth as auth_mod

    # create_jwt mints a no-scope token, which require_stream_auth accepts.
    return auth_mod.create_jwt(subject)


def test_requires_auth(client):
    resp = client.post("/api/v2/timestamp", json={"commitment": GOOD_COMMITMENT})
    # Missing Authorization header: 422 (Header(...) missing) or 401/403.
    assert resp.status_code in (401, 403, 422)


def test_dormant_by_default_returns_503(client):
    # Default config: OTS_ENABLED is false → 503 even with valid auth + body.
    resp = client.post(
        "/api/v2/timestamp",
        json={"commitment": GOOD_COMMITMENT},
        headers={"Authorization": f"Bearer {_stream_token()}"},
    )
    assert resp.status_code == 503


def test_bad_commitment_returns_400(client, monkeypatch):
    from app import config

    monkeypatch.setattr(config, "OTS_ENABLED", True)
    headers = {"Authorization": f"Bearer {_stream_token()}"}

    # Wrong length (Pydantic min/max_length 64) → 422 from validation.
    resp = client.post(
        "/api/v2/timestamp", json={"commitment": "ab"}, headers=headers
    )
    assert resp.status_code == 422

    # Right length but non-hex → 400 from bytes.fromhex.
    resp = client.post(
        "/api/v2/timestamp", json={"commitment": "zz" * 32}, headers=headers
    )
    assert resp.status_code == 400


def test_success_returns_raw_ots(client, monkeypatch):
    from app import config

    monkeypatch.setattr(config, "OTS_ENABLED", True)
    fake_ots = b"\x00OpenTimestamps\x00fake-proof-bytes"
    with patch(
        "app.routes.timestamp.timestamp_ots.stamp_digest", return_value=fake_ots
    ) as m:
        resp = client.post(
            "/api/v2/timestamp",
            json={"commitment": GOOD_COMMITMENT},
            headers={"Authorization": f"Bearer {_stream_token()}"},
        )
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/octet-stream"
    assert resp.content == fake_ots
    # The opaque 32-byte commitment was handed through verbatim as the digest.
    (digest_arg, _urls, _timeout) = m.call_args.args
    assert digest_arg == bytes.fromhex(GOOD_COMMITMENT)


def test_calendars_unreachable_returns_502(client, monkeypatch):
    from app import config, timestamp_ots

    monkeypatch.setattr(config, "OTS_ENABLED", True)
    with patch(
        "app.routes.timestamp.timestamp_ots.stamp_digest",
        side_effect=timestamp_ots.OtsSubmitError("all calendars down"),
    ):
        resp = client.post(
            "/api/v2/timestamp",
            json={"commitment": GOOD_COMMITMENT},
            headers={"Authorization": f"Bearer {_stream_token()}"},
        )
    assert resp.status_code == 502


def test_library_absent_returns_503(client, monkeypatch):
    from app import config, timestamp_ots

    monkeypatch.setattr(config, "OTS_ENABLED", True)
    with patch(
        "app.routes.timestamp.timestamp_ots.stamp_digest",
        side_effect=timestamp_ots.OtsUnavailable("lib not installed"),
    ):
        resp = client.post(
            "/api/v2/timestamp",
            json={"commitment": GOOD_COMMITMENT},
            headers={"Authorization": f"Bearer {_stream_token()}"},
        )
    assert resp.status_code == 503


def test_non_stream_scope_token_rejected(client, monkeypatch):
    """A token carrying a non-stream scope must NOT be able to request a stamp —
    require_stream_auth rejects any scope != 'stream' with 403 (R-H2
    segregation). Phase C removed the archive-scope JWT entirely, so we forge a
    scope='archive' token by hand to prove the scope gate still holds for any
    future scoped token."""
    import time
    import jwt
    from app import config

    monkeypatch.setattr(config, "OTS_ENABLED", True)
    now = int(time.time())
    scoped = jwt.encode(
        {"sub": "u" * 64, "scope": "archive", "iat": now, "exp": now + 300},
        config.JWT_SECRET,
        algorithm=config.JWT_ALGORITHM,
    )
    resp = client.post(
        "/api/v2/timestamp",
        json={"commitment": GOOD_COMMITMENT},
        headers={"Authorization": f"Bearer {scoped}"},
    )
    assert resp.status_code == 403
