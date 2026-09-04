"""
Archive retrieval, identity-free.

What is deliberately ABSENT here is the point. There is no
`POST /api/v2/archive/auth`, no long-term Ed25519 archive challenge (signature
domain 0x04), no archive-scope JWT, and no `GET .../reports` listing: the at-rest
`identity -> reports` join does not exist. Each of those four is an addition
someone will propose in good faith to answer "how does a witness find their
reports again?", and each one rebuilds the join.

The answer to that question is derivation, not a listing. After a device loss the
witness types the BIP-39 phrase, the client re-derives the per-report capability
keys `R_n` (crypto-rs/core/src/report.rs) and enumerates `report_id_0, 1, 2, ...`
on its own. Knowing a 128-bit report_id IS the read capability, which is why the
two GET routes below take no token: one returns the blob list
`[{filename, size, last_modified}]` (404 if the report is unknown), the other
streams the raw STRM bytes. Those bytes are encrypted and decrypted client-side,
so the relay never learns which identity reads what.
"""

import logging
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import StreamingResponse

from app import paths, storage
from app.ratelimit import limiter  # shared app-wide Limiter (see app/ratelimit.py)
from app.routes.reports import get_report

logger = logging.getLogger("stream.archive")

router = APIRouter(prefix="/api/v2/archive")


def _validate_path(report_id: str, filename: str | None = None):
    # Phase C — same strict validation as the upload route (app.paths, single
    # source of truth): 32-hex report_id + bounded filename with no `/`, `\`, a
    # lone `.`, or `..` anywhere. Previously the archive validator had NO `.`/`..`
    # guard at all (asymmetry with upload) — now symmetric.
    paths.validate_report_id(report_id)
    if filename is not None:
        paths.validate_filename(filename)


def _require_known_report(report_id: str):
    """404 on an unknown record. The blob-first invariant guarantees a known
    record has >=1 blob, so the rescue can distinguish "no such report" (404)
    from "report exists" reliably — `list_blobs` on an empty MinIO prefix would
    otherwise return 200 + []."""
    if get_report(report_id) is None:
        raise HTTPException(404, "Report not found")


@router.get("/reports/{report_id}/blobs")
@limiter.limit("60/minute")
async def list_report_blobs(request: Request, report_id: str):
    """List every STRM blob in a report (filename + size + last_modified)."""
    _validate_path(report_id)
    _require_known_report(report_id)
    return {"blobs": storage.list_blobs(report_id)}


@router.get("/reports/{report_id}/{filename}")
@limiter.limit("600/minute")
async def download_blob(request: Request, report_id: str, filename: str):
    """Stream a single STRM blob.

    The body is the on-disk MinIO object verbatim (the V2 STRM container). The
    client decrypts with the BIP-39-derived keys.
    """
    _validate_path(report_id, filename)
    _require_known_report(report_id)
    if not storage.blob_exists(report_id, filename):
        raise HTTPException(404, "Blob not found")
    size = storage.get_blob_size(report_id, filename)
    return StreamingResponse(
        storage.iter_blob(report_id, filename),
        media_type="application/octet-stream",
        headers={
            "Content-Length": str(size),
            "Content-Disposition": f'attachment; filename="{filename}"',
        },
    )
