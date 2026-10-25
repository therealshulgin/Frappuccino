#!/usr/bin/env python3
"""
The nginx front must not refuse a body the relay route accepts.

A closure's body is its manifest, `8 + 36 x count` bytes, so up to about 36 MB
for the largest report the sequence space allows. The `/close` route caps it at
MAX_MANIFEST_SIZE; the DirectTls front (deploy/nginx/relay.conf.template) caps
every body at its `client_max_body_size`. If the front's cap for `/close/` were
lower, the closure of a long report would be refused there with a 413 and never
reach the route. This reads the template and checks the cap that applies to
`/close/<report_id>` against the route's.
"""

import os
import re
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
os.environ.setdefault("JWT_SECRET", "test-secret-do-not-use")

from app import paths  # noqa: E402
from app.routes import upload  # noqa: E402

TEMPLATE = PROJECT_ROOT / "deploy" / "nginx" / "relay.conf.template"
_UNITS = {"": 1, "k": 1024, "m": 1024 ** 2, "g": 1024 ** 3}
_SIZE = re.compile(r"^\s*client_max_body_size\s+(\d+)([kmg]?)\s*;", re.IGNORECASE | re.MULTILINE)


def _bytes(match: re.Match) -> int:
    return int(match.group(1)) * _UNITS[match.group(2).lower()]


def _relay_server_block(text: str) -> str:
    """The TLS server block (the one that proxies to the relay)."""
    start = text.index("server {")
    end = text.index("\nserver {", start + 1)
    return text[start:end]


def _close_cap(text: str) -> int:
    """The body cap nginx applies to `POST /close/<rid>`: the one set in a
    location matching `/close/`, else the server-level one."""
    server = _relay_server_block(text)
    location = re.search(r"location\s+\^~\s+/close/\s*\{(.*?)\n    \}", server, re.DOTALL)
    if location is not None:
        inner = _SIZE.search(location.group(1))
        if inner is not None:
            return _bytes(inner)
    # Server level: the first directive outside any location block.
    outside = server.split("location", 1)[0]
    return _bytes(_SIZE.search(outside))


def test_the_largest_manifest_fits_the_route():
    largest = 8 + 36 * paths.MAX_SEQ_LIMIT
    assert largest <= upload.MAX_MANIFEST_SIZE


def test_nginx_lets_any_closure_the_route_accepts_through():
    cap = _close_cap(TEMPLATE.read_text(encoding="utf-8"))
    assert cap >= upload.MAX_MANIFEST_SIZE, (
        f"nginx caps /close/ at {cap} bytes, the route at {upload.MAX_MANIFEST_SIZE}"
    )
