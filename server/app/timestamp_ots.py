"""
Relay-side OpenTimestamps submission (§10.11).

Isolated wrapper around the `opentimestamps` library, so nothing else in the
relay imports it directly. The library is optional and lazily imported: a relay
that hasn't enabled timestamping (the default) boots and runs exactly as before,
and the import only happens the first time a stamp is actually requested.

The relay stays blind to what the digest commits to: the device sends an opaque
commitment (the salt policy lives entirely on the device and its verifier), so
the relay cannot correlate a stamp to a stored report.

The contract with the other end, and the only thing the route and the device
verifier agree on: the 32-byte `digest` handed in here is stamped verbatim as
the OTS leaf, and the returned bytes are a standard detached `.ots` proof whose
`start_digest` equals that `digest`. The Rust verifier (`frappuccino-cli
verify-provenance --ots`) parses exactly this format; both sides use the same
OTS wire format, so they interoperate by construction and any variation here
breaks device-side verification silently.

⚠️ Nothing in this module has ever run on the current relay: it stays inert
while OTS_ENABLED is false and the library is absent. The `opentimestamps` API
calls below are written against python-opentimestamps 0.4.5 (the reference
library) and must be validated against the installed version at deploy time.
Deploying it touches the relay in PROD = separate operator GO.
"""
import logging

logger = logging.getLogger("stream.timestamp")

DIGEST_LEN = 32


class OtsUnavailable(Exception):
    """Timestamping is disabled or the `opentimestamps` library is not
    installed. The route maps this to HTTP 503 (dormant / not configured)."""


class OtsSubmitError(Exception):
    """Every configured calendar failed (network / calendar down). The route
    maps this to HTTP 502 so the device retries later — a transient condition,
    never a loss: the commitment is re-derivable on the device from the
    manifest, so a failed stamp just means "try again", not "evidence gone"."""


def stamp_digest(digest: bytes, calendar_urls: list[str], timeout: float) -> bytes:
    """Submit `digest` (32 raw bytes) to the OTS calendars and return a
    serialized detached `.ots` proof.

    The proof is *pending* on return, and a caller that assumes otherwise gets
    it wrong: the calendars only commit to fold the digest into the next Bitcoin
    block aggregation (~hours), and the Bitcoin attestation is fetched later via
    the `upgrade` path of slice 3 (§10.11 phase B in ROADMAP.md), which is not
    written yet. Pending is already useful — it binds the digest to a calendar
    that will anchor it — and the device uploads it durably immediately.

    Every calendar is tried, in turn and with no short-circuit on the first
    success, and every answer that comes back is merged into the same proof. One
    acceptance is enough, so a dead calendar slows the stamp down — it costs its
    whole timeout before the loop moves on — instead of sinking it.

    Raises:
        ValueError      — `digest` is not exactly 32 bytes (caller bug).
        OtsUnavailable  — the `opentimestamps` library is not installed.
        OtsSubmitError  — every calendar failed.
    """
    if len(digest) != DIGEST_LEN:
        raise ValueError(f"digest must be {DIGEST_LEN} bytes, got {len(digest)}")

    try:
        from opentimestamps.calendar import RemoteCalendar
        from opentimestamps.core.op import OpSHA256
        from opentimestamps.core.serialize import BytesSerializationContext
        from opentimestamps.core.timestamp import DetachedTimestampFile, Timestamp
    except ImportError as e:
        raise OtsUnavailable(f"opentimestamps library not installed: {e}") from e

    timestamp = Timestamp(digest)
    merged = 0
    last_err: Exception | None = None
    for url in calendar_urls:
        try:
            calendar = RemoteCalendar(url)
            calendar_ts = calendar.submit(digest, timeout=timeout)
            timestamp.merge(calendar_ts)
            merged += 1
        except Exception as e:  # noqa: BLE001 — a single calendar failing is non-fatal
            last_err = e
            logger.warning("OTS calendar %s submission failed: %s", url, e)
            continue

    if merged == 0:
        raise OtsSubmitError(
            f"all {len(calendar_urls)} OTS calendars failed; last error: {last_err}"
        )

    detached = DetachedTimestampFile(OpSHA256(), timestamp)
    ctx = BytesSerializationContext()
    detached.serialize(ctx)
    logger.info("OTS stamp built (%d/%d calendars merged)", merged, len(calendar_urls))
    return ctx.getbytes()
