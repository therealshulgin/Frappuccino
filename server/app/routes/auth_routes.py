import asyncio
import logging
from fastapi import APIRouter, HTTPException, Request
from app import auth
from app.models import ChallengeResponse
from app.ratelimit import limiter  # shared app-wide Limiter (see app/ratelimit.py)

logger = logging.getLogger("stream.auth_routes")
router = APIRouter()


# The V1 auth paths are gone from this module and must not come back.
# POST /auth/verify minted a scopeless upload JWT from a long-term Ed25519
# signature alone: a creation path that skipped the ratchet entirely and
# contradicted the decision that creation is ratchet-gated (audit A-2). Upload
# authorization now flows only through /auth/v2/verify, which burns an ephemeral
# ratchet slot. POST /auth/invite/verify was the V1 invite-code registration,
# redundant since /auth/v2/enroll registers its own key; the invite module and
# auth.is_key_registered went with it, so there is no live invite path left to
# go looking for.
#
# /auth/challenge stays here on purpose: a nonce is a nonce, and the V2 flow
# shares this one. It is not a V1 leftover to move into auth_v2.py.


@router.post("/auth/challenge", response_model=ChallengeResponse)
@limiter.limit("10/minute")
async def challenge(request: Request):
    # The sync challenge generation does disk I/O (fsync +
    # rename of _nonce_cache.json); run it off-thread so it doesn't block the
    # event loop. OSError surfaces as 503 so the client retries.
    try:
        nonce, ts = await asyncio.to_thread(auth.generate_challenge)
    except OSError as e:
        logger.error("generate_challenge persistence failed: %s", e)
        raise HTTPException(
            status_code=503,
            detail="Server state I/O error — retry shortly",
        )
    return ChallengeResponse(nonce=nonce, timestamp=ts)
