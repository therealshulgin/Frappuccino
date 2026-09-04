"""
Relay-assisted OpenTimestamps (§10.11).

The witness only ever talks to the relay it already trusts, never to the public
OTS calendars: the relay submits on their behalf, so the calendars — third
parties the witness never chose — never see the witness's IP. Letting the client
submit directly would be one hop shorter and would reopen exactly that de-anon
vector.

The commitment is opaque to the relay. The device decides whether and how to
salt it, so the relay cannot link a stamp back to a stored report by content;
passing a report_id, or any digest the server can recompute, breaks that.

    POST /api/v2/timestamp
        Body  : {"commitment": "<64 hex>"}   — a 32-byte opaque commitment.
        Auth  : stream-scope JWT (the witness is recording; same bearer it uses
                to PUT chunks — held in RAM for the session).
        Reply : application/octet-stream — the detached `.ots` proof bytes
                (pending calendar attestation; the Bitcoin confirmation matures
                asynchronously and is fetched later via the slice-3 upgrade).

The route is dormant by default: 503 until OTS_ENABLED=true and the
`opentimestamps` library is installed (requirements-ots.txt). The base relay is
untouched — the route loads, the OTS lib being imported lazily only when a stamp
is requested, but refuses to act until explicitly enabled. Enabling it touches
the relay in PROD, so it is a separate operator go-ahead.

What is built here is slice 2 of phase B (§10.11 in ROADMAP.md, where the
endpoint contract, the salted-commitment model and the dormancy rule come from).
Slice 3 — the `upgrade` path named above, which turns a pending proof into a
Bitcoin-confirmed one — is not written yet.
"""
import asyncio
import logging

from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel, Field

from app import config, timestamp_ots
from app.routes._deps import require_stream_auth

logger = logging.getLogger("stream.timestamp")

router = APIRouter(prefix="/api/v2")


class TimestampRequest(BaseModel):
    # 32-byte commitment, hex-encoded → exactly 64 hex chars.
    commitment: str = Field(..., min_length=64, max_length=64)


@router.post("/timestamp")
async def create_timestamp(
    body: TimestampRequest,
    _user: str = Depends(require_stream_auth),
):
    """Stamp an opaque 32-byte commitment via the OTS calendars.

    Errors:
      * 503 — timestamping disabled (default) or the OTS library is absent.
      * 400 — commitment is not 32 hex-encoded bytes.
      * 502 — every calendar was unreachable (transient; device retries).
    """
    if not config.OTS_ENABLED:
        # Dormant: the operator has not turned timestamping on for this relay.
        raise HTTPException(503, "Timestamping not enabled on this relay")

    try:
        digest = bytes.fromhex(body.commitment)
    except ValueError:
        raise HTTPException(400, "commitment must be hex")
    if len(digest) != timestamp_ots.DIGEST_LEN:
        raise HTTPException(
            400, f"commitment must be {timestamp_ots.DIGEST_LEN} bytes ({timestamp_ots.DIGEST_LEN * 2} hex chars)"
        )

    try:
        # The calendar round-trips are blocking urllib calls: run them off the
        # event loop, or the single uvicorn worker (workers=1, because the nonce
        # cache is process-local) stops serving everyone else while they run.
        # Same off-loop pattern as the ratchet-registry / nonce fsync offload.
        ots_bytes = await asyncio.to_thread(
            timestamp_ots.stamp_digest,
            digest,
            config.OTS_CALENDAR_URLS,
            config.OTS_SUBMIT_TIMEOUT_S,
        )
    except timestamp_ots.OtsUnavailable as e:
        logger.warning("timestamp requested but OTS unavailable: %s", e)
        raise HTTPException(503, "Timestamping not available")
    except timestamp_ots.OtsSubmitError as e:
        logger.warning("timestamp calendars unreachable: %s", e)
        raise HTTPException(502, "Timestamp calendars unreachable — retry later")

    return Response(
        content=ots_bytes,
        media_type="application/octet-stream",
        headers={"Content-Length": str(len(ots_bytes))},
    )
