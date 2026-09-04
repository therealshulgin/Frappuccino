"""
Periodic reaper for report records left with zero blobs.

Two collectors, easy to confuse at a glance. `blob_cleanup` purges the MinIO
**blobs** past the long retention TTL (BLOB_TTL_SECONDS, 6 months); this one
removes the report **records** whose blobs are all gone, so `reports.json` does
not accumulate orphans after a purge. Same cadence, one hour.

What makes that safe with no per-record timestamp — the relay deliberately
stores no createdAt — is the lazy blob-first invariant: a record is written
only AFTER at least one durable blob (see app/routes/upload.py), so a record
at zero blobs is a fully purged report and never a half-finished upload. The
rest of the reasoning, including the honesty note about the upload time that
still leaks through the MinIO object's `last_modified` (R-SRV-7), lives with
the logic in `reports.reap_blobless_reports`.
"""
from __future__ import annotations

import asyncio
import logging

from app.routes import reports

logger = logging.getLogger("stream.report_cleanup")

CLEANUP_INTERVAL_SECONDS = 3600                       # 1h entre 2 ticks


async def cleanup_loop() -> None:
    """
    Boucle périodique. Appelée comme background task depuis main.py
    `lifespan`. Termine proprement quand la task est cancelled (shutdown
    serveur). Calquée sur `blob_cleanup.cleanup_loop`.
    """
    logger.info(
        "Blobless-report reaper starting (interval=%ds)", CLEANUP_INTERVAL_SECONDS
    )
    while True:
        try:
            # reap_blobless_reports est synchrone (client MinIO sync + dict
            # ops) → off-thread pour ne pas bloquer l'event loop.
            await asyncio.to_thread(reports.reap_blobless_reports)
        except asyncio.CancelledError:
            logger.info("Blobless-report reaper cancelled, exiting")
            raise
        except Exception:
            # On log mais on ne raise pas — une erreur transient MinIO ne
            # doit pas tuer la task pour de bon.
            logger.exception("Report reaper tick failed, will retry next interval")
        try:
            await asyncio.sleep(CLEANUP_INTERVAL_SECONDS)
        except asyncio.CancelledError:
            logger.info("Blobless-report reaper cancelled during sleep, exiting")
            raise
