"""The app's single slowapi ``Limiter``.

Two things here are easy to undo by accident, and both fail the same way: the
limits keep decorating the routes while enforcing nothing, with no error and no
log line.

First, there must be one instance. Every module imports THIS ``limiter`` and
``main.py`` registers it as ``app.state.limiter``, which is where slowapi looks
the route's limits up at call time. A route module that builds its own
``Limiter(key_func=...)``, the natural thing to write, gets limits that never
run. That was WP-B2 (audit 2026-06-28), and it left ``/auth/challenge``,
``/auth/v2/enroll|verify|rotate-batch|logout``, ``PUT /file/...`` and the archive
routes documenting brute-force protections that had never once fired.

Second, ``key_style="endpoint"`` is not cosmetic. slowapi otherwise keys each
bucket by the filled request path, so a route whose path varies per call, like
``PUT /file/{report_id}/{filename}`` where the chunk name is different every
time, would get a fresh bucket per request and never accumulate. Keying by the
view function keeps one bucket per client IP and route.

The key func resolves the real client IP: nginx sets
``X-Forwarded-For: $remote_addr`` and uvicorn runs with
``--forwarded-allow-ips 127.0.0.1``, so buckets are per-device instead of one
shared bucket for the nginx loopback.
"""

from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address, key_style="endpoint")
