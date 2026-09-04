import asyncio
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from app import auth, blob_cleanup, report_cleanup, storage
from app.ratelimit import limiter
from app.logging_setup import setup_logging
from app.routes import archive, auth_routes, auth_v2, timestamp, upload

# Phase 6.1.6 — JSON structured logging sans IP. Voir logging_setup.py
# pour le rationale (audit SIEM-compatible + threat model "no IP leak").
# Doit être appelé AVANT toute instanciation de logger pour que tous les
# loggers du process héritent du JsonFormatter.
setup_logging(level="INFO")
logger = logging.getLogger("stream.server")

# H-10: Rate limiting — the single app-wide Limiter lives in app.ratelimit
# (imported above) and is registered as app.state.limiter below, so EVERY
# router's @limiter.limit enforces (see app/ratelimit.py for why one instance).


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: ensure MinIO bucket exists
    logger.info("Initializing MinIO storage...")
    storage.ensure_bucket()

    # Phase 6.1.15 — background blob cleanup task. Wakes up every hour,
    # supprime les blobs > 24h. Démarre APRÈS bucket init pour ne pas
    # taper un bucket inexistant. Cancellée au shutdown.
    cleanup_task = asyncio.create_task(blob_cleanup.cleanup_loop())

    # Phase C (relay-blind reports) — background blobless-report reaper.
    # Separate task from blob_cleanup: that purges MinIO blobs at the long
    # retention TTL (6 months) ; this deletes the report records in
    # reports.json whose blobs are all gone (so the registry doesn't
    # accumulate orphan records after a purge). No createdAt / TTL needed.
    report_cleanup_task = asyncio.create_task(report_cleanup.cleanup_loop())

    # Phase 6.1.22 (2026-05-18) — Red Team R-MED-3 fix. Background
    # nonce cache purge every 60 s. Without this, expired nonces are
    # only cleaned up at challenge-time (O(N) per insertion). Under
    # sustained flood at the rate-limit ceiling the cache can reach
    # 14k entries/hour with rising per-request cost. This task keeps
    # it bounded.
    nonce_cleanup_task = asyncio.create_task(auth.nonce_cleanup_loop())

    logger.info("STREAM blind relay server ready")
    yield

    # Shutdown
    logger.info("Shutting down — cancelling background tasks")
    cleanup_task.cancel()
    report_cleanup_task.cancel()
    nonce_cleanup_task.cancel()
    for task in (cleanup_task, report_cleanup_task, nonce_cleanup_task):
        try:
            await task
        except asyncio.CancelledError:
            pass
    logger.info("Shutdown complete")


app = FastAPI(
    title="STREAM Blind Relay",
    description="Zero-knowledge relay server for STREAM encrypted blobs",
    version="0.1.0",
    lifespan=lifespan,
)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


# Phase C (A-1) — seal the exception channel. Without an explicit handler,
# Starlette logs unhandled exceptions via uvicorn.error with a full traceback
# (frame locals rendered via repr can carry a pk / IP / nonce). The formatter
# already scrubs exc_info to the type only (logging_setup.py); here we also
# guarantee a generic response and a request-detail-free log line.
@app.exception_handler(Exception)
async def _unhandled_exception_handler(request: Request, exc: Exception):
    logger.error("Unhandled exception: %s", type(exc).__name__)
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})


# Phase C (E-1) — FastAPI's default 422 echoes the offending `input` (which can
# be a malformed pk / nonce) back in the response body and into logs. Report
# only the field location + error type, never the input value.
@app.exception_handler(RequestValidationError)
async def _validation_exception_handler(request: Request, exc: RequestValidationError):
    safe = [{"loc": e.get("loc"), "type": e.get("type")} for e in exc.errors()]
    return JSONResponse(status_code=422, content={"detail": safe})

# M-07: Security headers middleware
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "no-referrer"
    # Phase 6.1.2 — HSTS. 1 an + sous-domaines + preload-eligible. Le
    # client Android a un SPKI pin sur le cert nginx, donc HSTS ne change
    # rien pour lui ; en revanche un browser qui hit le serveur au pif
    # (debug, healthcheck externe) s'engage à retry HTTPS. Pas de
    # `includeSubDomains` retiré : on n'a pas de sous-domaine HTTP-only.
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


@app.get("/health")
@limiter.limit("30/minute")
async def health(request: Request):
    # IMP-R1-5 — slowapi rate-limit. Without one, /health
    # is the cheapest amplification vector on the relay : a flood of
    # unauthenticated GETs ties up the single uvicorn worker (Phase
    # 6.1.3 — workers=1 is intentional because the nonce cache is
    # process-local). 30/min per source IP is generous for the legit
    # client (StreamRecordingService.isRelayReachable probes at most
    # once per 30 s cooldown = ~2/min) while bounding an abusive
    # source.
    return {"status": "ok"}


# Include routes. Mount order is indifferent here, and that is worth one line
# because three comments used to claim the opposite: that reports.router's
# `GET /{slug}` Tella catch-all would otherwise shadow /api/v2/archive/* and
# /api/v2/timestamp. It never could. A Starlette path parameter compiles to an
# anchored `[^/]+`, so a one-segment route cannot match a six-segment path; the
# ordering those comments protected was doing nothing, while reading like a
# security invariant. The catch-all itself is gone (2026-09-03, no caller).
#
# What IS load-bearing, and is NOT about mount order: inside `archive.py`,
# `/reports/{report_id}/blobs` must stay declared before
# `/reports/{report_id}/{filename}`, or the literal `blobs` gets swallowed by the
# parameter and listing a report silently becomes a download. Pinned by
# `tests/test_route_surface.py`.
#
# Also load-bearing here: the only single-segment GET routes are /health, /docs,
# /redoc and /openapi.json, all registered above before any router. Adding a
# single-segment route inside a router would make mount order matter again.
app.include_router(upload.router)
app.include_router(auth_routes.router)
app.include_router(auth_v2.router)
app.include_router(archive.router)
# §10.11 Phase B slice 2 — relay-assisted OpenTimestamps, prefix /api/v2.
# Dormant unless OTS_ENABLED (config).
app.include_router(timestamp.router)
