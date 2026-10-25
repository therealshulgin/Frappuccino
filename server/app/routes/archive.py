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
keys (crypto-rs/core/src/report.rs) and enumerates the report_ids on its own.
Knowing a 128-bit report_id IS the read capability, which is why the two GET
routes below take no token: one returns the blob list
`[{filename, size, last_modified}]` plus the report's recorded closure (404 if
the report is unknown), the other streams the raw stored bytes, with the
object's stored write signature in `X-Report-Write-Sig` when it has one. Those
bytes are encrypted and decrypted client-side, so the relay never learns which
identity reads what.

The signatures and closures served here are input to the rescue's own check,
never a verdict: the rescue verifies them (domains 0x08 and 0x09) under the
report key it re-derives from the phrase, not under anything the relay sends.
"""

import logging
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import StreamingResponse

from app import paths, storage
from app.ratelimit import limiter  # shared app-wide Limiter (see app/ratelimit.py)
from app.routes.reports import closure_view, get_report, is_tombstone

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


def _require_known_report(report_id: str) -> dict:
    """404 on an unknown record, else the record. The blob-first invariant
    guarantees a known record has >=1 blob until the blob TTL purges them, so
    the rescue can distinguish "no such report" (404) from "report exists"
    reliably — `list_blobs` on an empty MinIO prefix would otherwise return
    200 + []. A closed record outlives its blobs as a tombstone; the listing
    answers 404 for one with nothing left."""
    record = get_report(report_id)
    if record is None:
        raise HTTPException(404, "Report not found")
    return record


@router.get("/reports/{report_id}/blobs")
@limiter.limit("60/minute")
async def list_report_blobs(request: Request, report_id: str):
    """List every stored object in a report (filename + size + last_modified),
    `manifest` included once the report is closed, and the closure:
    `{"seq_limit", "manifest_sha256", "sig"}`, or null while the report is
    open."""
    _validate_path(report_id)
    record = _require_known_report(report_id)
    blobs = storage.list_blobs(report_id)
    if not blobs and is_tombstone(record):
        # A closed report whose objects have all expired: nothing to rescue,
        # the same answer as for a report the relay never knew.
        raise HTTPException(404, "Report not found")
    return {"blobs": blobs, "closure": closure_view(record)}


@router.get("/reports/{report_id}/{filename}")
@limiter.limit("600/minute")
async def download_blob(request: Request, report_id: str, filename: str):
    """Stream a single stored object, `manifest` included.

    The body is the on-disk MinIO object verbatim (the V2 STRM container, or
    the closure manifest). The client decrypts with the BIP-39-derived keys.
    `X-Report-Write-Sig` carries the object's stored write signature (0x08,
    hex) when it has one; objects stored before the relay kept signatures, and
    the manifest, have none.
    """
    _validate_path(report_id, filename)
    _require_known_report(report_id)
    info = storage.stat_blob(report_id, filename)
    if info is None or info.size <= 0:
        raise HTTPException(404, "Blob not found")
    headers = {
        "Content-Length": str(info.size),
        "Content-Disposition": f'attachment; filename="{filename}"',
    }
    if info.write_sig_hex is not None:
        headers["X-Report-Write-Sig"] = info.write_sig_hex
    return StreamingResponse(
        storage.iter_blob(report_id, filename),
        media_type="application/octet-stream",
        headers=headers,
    )
