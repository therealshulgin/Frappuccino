#!/usr/bin/env python3
"""
test_diag.py — the diagnostic-logs route of test builds (app/routes/diag.py).

The route is an exception to what the relay keeps, so most of what is tested
here is the edge of that exception: absent unless the operator turns it on,
headers that cannot become a path, a body cap, a gzip bomb cap, two storage
ceilings, a retention, and no client IP anywhere in what it writes or logs.

Each test builds a fresh app (the `app.*` modules are re-imported with the
DIAG_LOGS_DIR under test, as test_timestamp_routes does) and puts the original
modules back afterwards, so the test files that run later keep the app they
imported at collection time.

Run via:
    uv run --with-requirements server/requirements.txt --with pytest \
        --with httpx python -m pytest server/tests/test_diag.py -v
"""

import asyncio
import gzip
import logging
import os
import re
import sys
import tempfile
import time
import zlib
from pathlib import Path
from types import SimpleNamespace

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
os.environ.setdefault("JWT_SECRET", "test-secret-do-not-use")

ROUTE = "/diag/v1/logs"
INSTALL = "0123456789abcdef" * 2
APP_VERSION = "2.12.0-test2"
TEXT = b"device: test\n" + b"I/StreamMetrics: camera state OPEN\n" * 200
# The client address every request below comes from, and a second one carried
# in X-Forwarded-For. Neither may show up in a stored file or a log line.
CLIENT_IP = "203.0.113.77"
FORWARDED_IP = "198.51.100.23"
_FILE_NAME = re.compile(r"\d{8}T\d{6}Z-[0-9a-f]{8}-(?P<app>[A-Za-z0-9._-]{1,40})\.log\.gz")


def _is_app_module(name: str) -> bool:
    return name == "app" or name.startswith("app.")


@pytest.fixture()
def fresh_modules():
    saved = {k: v for k, v in sys.modules.items() if _is_app_module(k)}
    yield
    for name in [k for k in sys.modules if _is_app_module(k)]:
        del sys.modules[name]
    sys.modules.update(saved)


def _import_app(monkeypatch, diag_dir):
    """Re-import the app with DIAG_LOGS_DIR set to `diag_dir` (None = unset)."""
    if diag_dir is None:
        monkeypatch.delenv("DIAG_LOGS_DIR", raising=False)
    else:
        monkeypatch.setenv("DIAG_LOGS_DIR", str(diag_dir))
    for name in [k for k in sys.modules if _is_app_module(k)]:
        del sys.modules[name]
    from app import config, main
    from app.routes import diag

    return SimpleNamespace(main=main, config=config, diag=diag)


def _from_ip(asgi_app, ip):
    """What uvicorn's proxy-headers handling does behind nginx: the request's
    client becomes the real address."""

    async def wrapped(scope, receive, send):
        if scope["type"] == "http":
            scope = dict(scope, client=(ip, 41234))
        await asgi_app(scope, receive, send)

    return wrapped


def _client(asgi_app):
    from fastapi.testclient import TestClient

    return TestClient(_from_ip(asgi_app, CLIENT_IP))


@pytest.fixture()
def workdir():
    # tempfile, like the rest of this suite, rather than pytest's own temporary
    # directory fixture.
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        yield Path(tmp)


@pytest.fixture()
def relay(monkeypatch, workdir, fresh_modules):
    root = workdir / "diag"
    mods = _import_app(monkeypatch, root)
    return SimpleNamespace(
        client=_client(mods.main.app),
        root=root,
        config=mods.config,
        diag=mods.diag,
        main=mods.main,
    )


def _headers(install=INSTALL, app=APP_VERSION, **extra):
    headers = {"Content-Type": "application/gzip"}
    if install is not None:
        headers["X-Diag-Install"] = install
    if app is not None:
        headers["X-Diag-App"] = app
    headers.update(extra)
    return headers


def _post(client, body, **kwargs):
    return client.post(ROUTE, content=body, headers=_headers(**kwargs))


def _gz(data: bytes) -> bytes:
    return gzip.compress(data, mtime=0)


def _stored(root: Path) -> list[Path]:
    if not root.exists():
        return []
    return sorted(p for p in root.rglob("*") if p.is_file())


def _surface(asgi_app):
    return {
        (method, route.path)
        for route in asgi_app.routes
        for method in (getattr(route, "methods", None) or [])
        if method != "HEAD"
    }


# --- off unless the operator turns it on ---------------------------------------


def test_off_by_default_the_route_does_not_exist(monkeypatch, fresh_modules):
    mods = _import_app(monkeypatch, None)
    assert ("POST", ROUTE) not in _surface(mods.main.app)
    resp = _post(_client(mods.main.app), _gz(TEXT))
    assert resp.status_code == 404


@pytest.mark.parametrize("value", ["", "   "])
def test_an_empty_setting_is_off(monkeypatch, fresh_modules, value):
    mods = _import_app(monkeypatch, value)
    assert ("POST", ROUTE) not in _surface(mods.main.app)
    assert _post(_client(mods.main.app), _gz(TEXT)).status_code == 404


def test_turning_it_on_adds_exactly_this_route(monkeypatch, workdir, fresh_modules):
    off = _surface(_import_app(monkeypatch, None).main.app)
    on = _surface(_import_app(monkeypatch, workdir / "diag").main.app)
    assert on - off == {("POST", ROUTE)}
    assert off - on == set()


def test_a_router_mounted_with_the_setting_empty_writes_nothing(relay, monkeypatch):
    monkeypatch.setattr(relay.config, "DIAG_LOGS_DIR", "")
    assert _post(relay.client, _gz(TEXT)).status_code == 404
    assert _stored(relay.root) == []


# --- the happy path -------------------------------------------------------------


def test_stores_the_body_exactly_as_received(relay):
    body = _gz(TEXT)
    resp = _post(relay.client, body)
    assert resp.status_code == 204
    assert resp.content == b""
    files = _stored(relay.root)
    assert len(files) == 1
    stored = files[0]
    assert stored.parent == relay.root / INSTALL
    match = _FILE_NAME.fullmatch(stored.name)
    assert match is not None, stored.name
    assert match.group("app") == APP_VERSION
    assert stored.read_bytes() == body
    assert gzip.decompress(stored.read_bytes()) == TEXT


def test_two_uploads_in_the_same_second_make_two_files(relay):
    for _ in range(2):
        assert _post(relay.client, _gz(TEXT)).status_code == 204
    assert len(_stored(relay.root)) == 2


def test_several_gzip_members_are_one_valid_body(relay):
    body = _gz(b"profile\n") + _gz(TEXT)
    assert _post(relay.client, body).status_code == 204
    assert _stored(relay.root)[0].read_bytes() == body


@pytest.mark.skipif(os.name != "posix", reason="file modes are POSIX only")
def test_directories_are_0700_and_files_0600(relay):
    assert _post(relay.client, _gz(TEXT)).status_code == 204
    (stored,) = _stored(relay.root)
    assert stored.stat().st_mode & 0o777 == 0o600
    assert (relay.root / INSTALL).stat().st_mode & 0o777 == 0o700
    assert relay.root.stat().st_mode & 0o777 == 0o700


@pytest.mark.skipif(os.name != "posix", reason="file modes are POSIX only")
def test_an_existing_directory_is_made_0700(relay):
    # The volume root exists before the first upload; mkdir's mode does not
    # apply to it.
    relay.root.mkdir()
    # Too open on purpose: the test checks that the relay narrows it.
    os.chmod(relay.root, 0o755)  # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions
    assert _post(relay.client, _gz(TEXT)).status_code == 204
    assert relay.root.stat().st_mode & 0o777 == 0o700


# --- headers --------------------------------------------------------------------


@pytest.mark.parametrize(
    "install",
    [
        None,
        "",
        INSTALL.upper(),
        INSTALL[:-1],
        INSTALL + "0",
        "../" + INSTALL[3:],
        "g" * 32,
        INSTALL[:31] + "/",
        INSTALL[:31] + ".",
    ],
)
def test_a_malformed_install_id_is_400(relay, install):
    assert _post(relay.client, _gz(TEXT), install=install).status_code == 400
    assert _stored(relay.root) == []


@pytest.mark.parametrize(
    "app", [None, "", "a" * 41, "2.12/x", "2.12 x", "2.12\\x", "2.12:x", "2.12+x"]
)
def test_a_malformed_app_version_is_400(relay, app):
    assert _post(relay.client, _gz(TEXT), app=app).status_code == 400
    assert _stored(relay.root) == []


def test_an_app_version_of_40_characters_is_accepted(relay):
    app = "a" * 40
    assert _post(relay.client, _gz(TEXT), app=app).status_code == 204
    (stored,) = _stored(relay.root)
    assert _FILE_NAME.fullmatch(stored.name).group("app") == app


# --- body cap -------------------------------------------------------------------


def test_a_body_at_the_cap_passes_it(relay):
    # Not gzip: the 400 comes from the gzip check, so the body got past the cap.
    body = b"x" * relay.diag.MAX_BODY_BYTES
    assert _post(relay.client, body).status_code == 400


def test_a_body_over_the_cap_is_413(relay):
    body = b"x" * (relay.diag.MAX_BODY_BYTES + 1)
    assert _post(relay.client, body).status_code == 413
    assert _stored(relay.root) == []


def test_a_chunked_body_over_the_cap_is_413(relay):
    # No Content-Length: only the running count can refuse it.
    piece = b"x" * 65536
    count = relay.diag.MAX_BODY_BYTES // len(piece) + 1

    def chunks():
        for _ in range(count):
            yield piece

    resp = relay.client.post(ROUTE, content=chunks(), headers=_headers())
    assert resp.status_code == 413
    assert _stored(relay.root) == []


def test_a_declared_length_over_the_cap_is_413_on_the_header_alone(relay):
    headers = _headers()
    headers["Content-Length"] = str(relay.diag.MAX_BODY_BYTES + 1)
    resp = relay.client.post(ROUTE, content=b"x" * 16, headers=headers)
    assert resp.status_code == 413


# --- gzip -----------------------------------------------------------------------


def _corrupt_crc(data: bytes) -> bytes:
    # The trailer is CRC32 then ISIZE; flip one CRC byte.
    return data[:-8] + bytes([data[-8] ^ 0xFF]) + data[-7:]


@pytest.mark.parametrize(
    "body",
    [
        pytest.param(b"", id="empty"),
        pytest.param(TEXT, id="plain-text"),
        pytest.param(b"\x1f\x8b", id="magic-only"),
        pytest.param(_gz(TEXT)[:-4], id="truncated"),
        pytest.param(_gz(TEXT)[:20], id="cut-short"),
        pytest.param(_corrupt_crc(_gz(TEXT)), id="bad-crc"),
        pytest.param(_gz(TEXT) + b"trailing", id="trailing-bytes"),
        pytest.param(_gz(TEXT) + b"\x1f\x8b", id="trailing-magic"),
        pytest.param(b"\x1f\x8b" + b"\x00" * 64, id="garbage-after-magic"),
        pytest.param(zlib.compress(TEXT), id="zlib-stream"),
        pytest.param(zlib.compress(TEXT)[2:-4], id="raw-deflate"),
        pytest.param(_gz(TEXT) + zlib.compress(TEXT), id="zlib-after-gzip"),
    ],
)
def test_a_body_that_is_not_complete_gzip_is_400(relay, body):
    assert _post(relay.client, body).status_code == 400
    assert _stored(relay.root) == []


def test_a_gzip_bomb_is_413(relay):
    bomb = _gz(b"\x00" * (relay.diag.MAX_INFLATED_BYTES + 1))
    assert len(bomb) < 64 * 1024
    assert _post(relay.client, bomb).status_code == 413
    assert _stored(relay.root) == []


def test_a_body_inflating_to_exactly_the_ceiling_is_accepted(relay):
    body = _gz(b"\x00" * relay.diag.MAX_INFLATED_BYTES)
    assert _post(relay.client, body).status_code == 204


def test_the_inflate_ceiling_counts_across_members(relay):
    half = relay.diag.MAX_INFLATED_BYTES // 2 + 1
    body = _gz(b"\x00" * half) + _gz(b"\x00" * half)
    assert _post(relay.client, body).status_code == 413
    assert _stored(relay.root) == []


def test_more_gzip_members_than_the_cap_is_400(relay):
    cap = relay.diag.MAX_GZIP_MEMBERS
    assert _post(relay.client, _gz(TEXT) * cap).status_code == 204
    assert _post(relay.client, _gz(TEXT) * (cap + 1)).status_code == 400
    assert len(_stored(relay.root)) == 1


def test_a_megabyte_of_empty_members_is_refused_after_the_cap(relay, monkeypatch):
    # Each member end copies the rest of the body, so checking every one of
    # these 50,000-odd members would cost seconds of CPU. The check must stop
    # at the cap: counted here by the decompressors it creates.
    empty = _gz(b"")
    body = empty * (relay.diag.MAX_BODY_BYTES // len(empty))
    created = []
    real = zlib.decompressobj

    def counting(*args, **kwargs):
        created.append(1)
        return real(*args, **kwargs)

    monkeypatch.setattr(relay.diag.zlib, "decompressobj", counting)
    assert _post(relay.client, body).status_code == 400
    assert len(created) <= relay.diag.MAX_GZIP_MEMBERS
    assert _stored(relay.root) == []


# --- ceilings -------------------------------------------------------------------


def test_the_total_ceiling_is_507(relay, monkeypatch):
    body = _gz(TEXT)
    monkeypatch.setattr(
        relay.config, "DIAG_MAX_TOTAL_BYTES", 2 * relay.diag.charge(len(body))
    )
    assert _post(relay.client, body, install="a" * 32).status_code == 204
    # Exactly at the ceiling is still accepted.
    assert _post(relay.client, body, install="b" * 32).status_code == 204
    assert _post(relay.client, body, install="c" * 32).status_code == 507
    assert not (relay.root / ("c" * 32)).exists()
    assert len(_stored(relay.root)) == 2


def test_the_per_install_ceiling_is_507(relay, monkeypatch):
    body = _gz(TEXT)
    monkeypatch.setattr(relay.config, "DIAG_MAX_INSTALL_BYTES", relay.diag.charge(len(body)))
    assert _post(relay.client, body, install="a" * 32).status_code == 204
    assert _post(relay.client, body, install="a" * 32).status_code == 507
    # Another install is not affected.
    assert _post(relay.client, body, install="b" * 32).status_code == 204
    assert len(_stored(relay.root / ("a" * 32))) == 1


def test_a_small_file_counts_for_a_whole_disk_block(relay, monkeypatch):
    # 20 bytes on the wire, one block and one inode on the disk.
    tiny = _gz(b"")
    assert len(tiny) < 64
    block = relay.diag.DISK_BLOCK
    assert relay.diag.charge(len(tiny)) == block
    assert relay.diag.charge(block + 1) == 2 * block
    monkeypatch.setattr(relay.config, "DIAG_MAX_INSTALL_BYTES", 2 * block)
    assert _post(relay.client, tiny).status_code == 204
    assert _post(relay.client, tiny).status_code == 204
    assert _post(relay.client, tiny).status_code == 507


def test_files_already_on_disk_count_from_the_first_upload(relay, monkeypatch):
    # No purge before this upload: the ceilings read the disk themselves.
    monkeypatch.setattr(relay.diag, "_last_purge", time.monotonic())
    _log(relay.root / INSTALL, 0)
    monkeypatch.setattr(relay.config, "DIAG_MAX_INSTALL_BYTES", relay.diag.DISK_BLOCK)
    assert _post(relay.client, _gz(TEXT)).status_code == 507


def test_an_upload_does_not_list_the_stored_files(relay, monkeypatch):
    assert _post(relay.client, _gz(TEXT)).status_code == 204
    listed = []
    real = os.scandir

    def counting(*args, **kwargs):
        listed.append(args)
        return real(*args, **kwargs)

    monkeypatch.setattr(relay.diag.os, "scandir", counting)
    assert _post(relay.client, _gz(TEXT)).status_code == 204
    assert listed == []


def test_files_removed_by_hand_are_forgotten_at_the_next_purge(relay, monkeypatch):
    body = _gz(TEXT)
    monkeypatch.setattr(relay.config, "DIAG_MAX_TOTAL_BYTES", relay.diag.charge(len(body)))
    assert _post(relay.client, body).status_code == 204
    assert _post(relay.client, body).status_code == 507
    for path in _stored(relay.root):
        path.unlink()
    relay.diag.purge_expired(relay.root)
    assert _post(relay.client, body).status_code == 204


# --- retention ------------------------------------------------------------------

_counter = iter(range(1, 1_000_000))


def _log(install_dir: Path, age_days: float, name: str | None = None) -> Path:
    """A file as `_store` names it (unless `name` is given), aged `age_days`."""
    if name is None:
        name = f"20260101T000000Z-{next(_counter):08x}-{APP_VERSION}.log.gz"
    path = install_dir / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(_gz(b"old"))
    when = time.time() - age_days * 86400
    os.utime(path, (when, when))
    return path


def test_stored_names_are_the_names_the_purge_deletes(relay):
    assert _post(relay.client, _gz(TEXT)).status_code == 204
    (stored,) = _stored(relay.root)
    assert relay.diag._FILE_RE.fullmatch(stored.name)
    assert relay.diag._FILE_RE.fullmatch(stored.name + ".k3j_9xq2.tmp")


def test_the_purge_deletes_expired_files_and_emptied_install_dirs(relay):
    gone_dir = relay.root / ("a" * 32)
    _log(gone_dir, 31)
    kept_dir = relay.root / ("b" * 32)
    old = _log(kept_dir, 31)
    leftover = _log(kept_dir, 31, name=old.name + ".k3j_9xq2.tmp")
    recent = _log(kept_dir, 29)

    assert relay.diag.purge_expired(relay.root) == 3
    assert not gone_dir.exists()
    assert not old.exists()
    assert not leftover.exists()
    assert recent.exists()


def test_the_purge_deletes_nothing_it_did_not_write(relay):
    # What DIAG_LOGS_DIR set to the wrong directory would hold, long unmodified:
    # a directory not named like an install (each filter is tested on its own,
    # so the file in it has a log file's name), and a file not named like one.
    in_other_dir = _log(relay.root / "state", 400)
    other_name = _log(relay.root / ("c" * 32), 400, name="reports.json")
    assert relay.diag.purge_expired(relay.root) == 0
    assert in_other_dir.exists()
    assert other_name.exists()


def test_the_purge_follows_the_retention_setting(relay, monkeypatch):
    monkeypatch.setattr(relay.config, "DIAG_RETENTION_DAYS", 1)
    old = _log(relay.root / ("a" * 32), 2)
    assert relay.diag.purge_expired(relay.root) == 1
    assert not old.exists()


def test_the_purge_tolerates_a_missing_directory(relay):
    assert relay.diag.purge_expired(relay.root / "absent") == 0


def test_an_upload_purges_once_the_hour_has_passed(relay, monkeypatch):
    old = _log(relay.root / ("b" * 32), 31)
    monkeypatch.setattr(
        relay.diag, "_last_purge", time.monotonic() - relay.diag.PURGE_INTERVAL_SECONDS - 1
    )
    assert _post(relay.client, _gz(TEXT)).status_code == 204
    assert not old.exists()


def test_the_first_upload_purges_when_nothing_has_yet(relay):
    assert relay.diag._last_purge is None
    old = _log(relay.root / ("b" * 32), 31)
    assert _post(relay.client, _gz(TEXT)).status_code == 204
    assert not old.exists()


def test_an_upload_within_the_hour_does_not_purge(relay, monkeypatch):
    old = _log(relay.root / ("b" * 32), 31)
    monkeypatch.setattr(relay.diag, "_last_purge", time.monotonic())
    assert _post(relay.client, _gz(TEXT)).status_code == 204
    assert old.exists()


def test_the_relay_purges_at_startup(relay, monkeypatch):
    from fastapi.testclient import TestClient

    async def idle():
        await asyncio.Event().wait()

    main = relay.main
    monkeypatch.setattr(main.storage, "ensure_bucket", lambda: None)
    monkeypatch.setattr(main.blob_cleanup, "cleanup_loop", idle)
    monkeypatch.setattr(main.report_cleanup, "cleanup_loop", idle)
    monkeypatch.setattr(main.auth, "nonce_cleanup_loop", idle)
    old = _log(relay.root / ("a" * 32), 31)
    with TestClient(main.app):
        assert not old.exists()


def test_the_relay_purges_every_interval_without_uploads(relay, monkeypatch):
    # The purge on upload needs uploads; a relay the testers have stopped
    # sending to must still delete the expired files.
    from fastapi.testclient import TestClient

    async def idle():
        await asyncio.Event().wait()

    main = relay.main
    monkeypatch.setattr(main.storage, "ensure_bucket", lambda: None)
    monkeypatch.setattr(main.blob_cleanup, "cleanup_loop", idle)
    monkeypatch.setattr(main.report_cleanup, "cleanup_loop", idle)
    monkeypatch.setattr(main.auth, "nonce_cleanup_loop", idle)
    monkeypatch.setattr(relay.diag, "PURGE_INTERVAL_SECONDS", 0.05)
    with TestClient(main.app):
        # Written after the startup purge: only a later one can delete it.
        old = _log(relay.root / ("a" * 32), 31)
        deadline = time.monotonic() + 5
        while old.exists() and time.monotonic() < deadline:
            time.sleep(0.02)
        assert not old.exists()


# --- no client address, no other header -----------------------------------------


def test_no_client_ip_or_other_header_is_logged_or_stored(relay, monkeypatch, caplog, capsys):
    caplog.set_level(logging.DEBUG)
    from app.logging_setup import JsonFormatter

    probes = [CLIENT_IP, FORWARDED_IP, "probe-agent/7.1", "probe-token-9f3c"]
    extra = {
        "X-Forwarded-For": FORWARDED_IP,
        "X-Real-IP": FORWARDED_IP,
        "User-Agent": "probe-agent/7.1",
        "Authorization": "Bearer probe-token-9f3c",
    }
    body = _gz(TEXT)
    # Stored, refused on a header, refused on a ceiling, and refused on a write
    # failure: each path that logs, or writes, once.
    assert _post(relay.client, body, **extra).status_code == 204
    assert _post(relay.client, body, install="bad", **extra).status_code == 400
    monkeypatch.setattr(relay.config, "DIAG_MAX_INSTALL_BYTES", len(body))
    assert _post(relay.client, body, **extra).status_code == 507
    monkeypatch.setattr(relay.config, "DIAG_MAX_INSTALL_BYTES", 64 * 1024 * 1024)

    def failing_save(path, data):
        raise OSError("disk")

    monkeypatch.setattr(relay.diag.atomic_io, "atomic_bytes_save", failing_save)
    assert _post(relay.client, body, **extra).status_code == 503

    # And refused on the rate limit, whose library logs the key of its counter:
    # the client IP (app/logging_setup.py silences it).
    codes = [_post(relay.client, body, install="bad", **extra).status_code for _ in range(9)]
    assert codes[-1] == 429, codes

    formatter = JsonFormatter()
    logged = "\n".join(formatter.format(r) for r in caplog.records)
    # A logger cut off from every handler still writes to stderr, through
    # Python's last-resort handler, unless it is also disabled: read stderr too.
    logged += "\n" + capsys.readouterr().err
    assert any(r.name == "stream.diag" for r in caplog.records)
    written = [str(p.relative_to(relay.root)) for p in relay.root.rglob("*")]
    contents = [p.read_bytes() for p in _stored(relay.root)]
    contents += [gzip.decompress(c) for c in contents]
    for probe in probes:
        assert probe not in logged
        assert all(probe not in name for name in written)
        assert all(probe.encode() not in c for c in contents)


# --- rate limit -----------------------------------------------------------------


def test_the_route_is_rate_limited_at_12_per_minute(relay):
    codes = [_post(relay.client, b"", install=None).status_code for _ in range(13)]
    assert codes[:12] == [400] * 12
    assert codes[12] == 429


# --- deployment: its own volume, out of the backups -----------------------------

SERVER = PROJECT_ROOT


def test_compose_keeps_the_logs_in_their_own_volume_and_off_by_default():
    compose = (SERVER / "docker-compose.yml").read_text(encoding="utf-8")
    assert re.search(r"^\s+DIAG_LOGS_DIR: \$\{DIAG_LOGS_DIR:-\}\s*$", compose, re.M)
    assert re.search(r"^\s+- diag_logs:/diag\s*$", compose, re.M)
    assert re.search(r"^  diag_logs:", compose, re.M)
    # Nothing else is mounted at /diag, and the logs volume nowhere else.
    assert re.findall(r"^\s+- (\S+):/diag\S*\s*$", compose, re.M) == ["diag_logs"]
    assert re.findall(r"^\s+- diag_logs:(\S+)\s*$", compose, re.M) == ["/diag"]


def test_the_backup_copies_the_state_and_the_blobs_only():
    script = (SERVER / "deploy" / "backup-state.sh").read_text(encoding="utf-8")
    assert re.findall(r"resolve_volume (\w+)\)", script) == ["server_state", "minio_data"]
    mounts = re.findall(r'-v "\$\{(\w+)\}":', script)
    assert mounts == ["VOL_STATE", "VOL_MINIO"]


def test_the_image_creates_the_mount_point_private_to_the_relay_user():
    dockerfile = (SERVER / "Dockerfile").read_text(encoding="utf-8")
    assert re.search(r"install -d -m 0700 -o stream -g stream /diag\b", dockerfile)
