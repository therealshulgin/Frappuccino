import asyncio
import hashlib
import logging
import re
import tempfile
from fastapi import APIRouter, Header, Request, Response, HTTPException
from app import auth, config, paths, ratchet_registry, signature_domain, storage
from app.ratelimit import limiter  # shared app-wide Limiter (see app/ratelimit.py)
from app.routes import reports

logger = logging.getLogger("stream.upload")

router = APIRouter()

MAX_UPLOAD_SIZE = 500 * 1024 * 1024  # 500 MB per PUT request

# Closure manifest: "FQM1" || u32_be(count) || count x (u32_be(seq) || sha256(32)).
# seq < 1_000_000, so a manifest is at most 8 + 36 x 1_000_000 bytes (~36 MB);
# the cap leaves headroom and refuses anything larger before it is spooled.
MAX_MANIFEST_SIZE = 40 * 1024 * 1024
_MANIFEST_MAGIC = b"FQM1"
_MANIFEST_HEADER_LEN = 8
_MANIFEST_ENTRY_LEN = 36

# X-Report-Close-Seq-Limit: canonical decimal, no sign, no leading zero, no
# whitespace, at most seven digits (the range check comes after).
_SEQ_LIMIT_RE = re.compile(r"(?:0|[1-9][0-9]{0,6})")

# Mirror of crypto-rs/core/src/report.rs::report_id_from_pk — the report's
# identity-free address is SHA-256("stream.report.id.v1" || report_pk)[..16].
# MUST stay byte-identical to the Rust derivation (a change orphans every
# report); see app/signature_domain.py for the matching signature tags.
_REPORT_ID_CTX = b"stream.report.id.v1"


def _report_id_from_pk(report_pk: bytes) -> bytes:
    return hashlib.sha256(_REPORT_ID_CTX + report_pk).digest()[:16]


def _validate_path(report_id: str, filename: str):
    # Strict validation from the single source of truth (app.paths):
    # 32-hex report_id (hex-decodable to the 16 bytes the signatures cover) and a
    # bounded-length filename with no `/`, `\`, a lone `.`, or `..` anywhere. The
    # stored MinIO key is thus byte-identical to the write-signed name — never
    # rewritten (an old `.replace("..","")` silently desynced key vs signed name
    # and could collide two names). Real names are chunk ids (`<sid>_NNNNNN.strm`,
    # `NNNNNN.strm`) or an opaque 32-hex directory entry (M-1), never `.`/`..`.
    paths.validate_report_id(report_id)
    paths.validate_filename(filename)
    # `manifest` is written only by POST /close, from the body whose hash the
    # closure signature covers. A PUT to it is refused whatever the report's
    # state: write-once would otherwise let the first writer choose the bytes a
    # later closure has to match.
    if filename == paths.MANIFEST_NAME:
        raise HTTPException(400, "Reserved object name")


def _parse_hex(value: str | None, nbytes: int, name: str) -> bytes:
    if value is None:
        raise HTTPException(400, f"Missing {name} header")
    try:
        raw = bytes.fromhex(value)
    except ValueError:
        raise HTTPException(400, f"Invalid {name} header")
    if len(raw) != nbytes:
        raise HTTPException(400, f"{name} must be {nbytes} bytes")
    return raw


# WP-G residual (2026-06-29) — the HEAD `/file/{report_id}/{filename}` route
# (a blob existence/size oracle) was REMOVED. It was dead code: the client only
# ever PUTs chunks + archive-GETs them back, never HEAD (verified by grep across
# mobile/ + crypto-rs/). Deleting it eliminates the existence/size oracle outright
# (the HEAD-oracle residual in docs/ACCEPTED_RESIDUALS_2026-06-28.md) instead of
# merely bounding it with a rate-limit. Re-introduce behind a capability check +
# rate-limit only if a real "is this chunk already stored?" client need appears.
@router.put("/file/{report_id}/{filename}")
# Per-IP rate limit on the chunk-upload hot path (WP-B2, audit 2026-06-28).
#
# The bucket is per-device only because nginx sets `X-Forwarded-For:
# $remote_addr` and uvicorn runs with `--forwarded-allow-ips 127.0.0.1`
# (Dockerfile), so get_remote_address sees the client rather than the nginx
# loopback. Break either half and every client collapses into one shared bucket
# where a single uploader can eat the whole 600/min: a conf change that looks
# cosmetic becomes a denial of service against every witness. And it is not just
# this route — every limiter on the relay is keyed the same way and collapses
# with it.
#
# 600/min is not a round number. This is the witness recording path and the
# motto wants chunks off the device as fast as possible, so the cap has to clear
# a legitimate backlog flush, not just steady state. One device emits ~12
# PUT/min steady (5 s chunks, RollingChunkRecorder) but bursts hard when a
# queued backlog drains after a reconnect: the client caps itself at MAX_CAP=6
# concurrent uploads (UploadConcurrencyLimiter), so on a fast link (~0.5-1
# s/PUT) the ceiling is ~360 PUT/min. 600 clears that with headroom while still
# bounding a single IP to 10 req/s. Lowering it throttles exactly the backlog
# recovery the motto is about.
#
# A 429 here never loses testimony: ChunkUploadWorker maps it to Result.retry()
# (WorkManager backoff) and the blob stays on-device, so even an extreme
# very-fast-link flush that briefly exceeds the cap only slows the upload down.
# That is also what makes the NAT tradeoff acceptable: clients behind one
# CGNAT/VPN exit share a bucket (same accepted tradeoff as the enroll and verify
# limits), and a 429 stays non-destructive for them.
#
# All of this is defense in depth, not the primary control. Every PUT already
# needs a valid per-report write-sig (else 403 before anything is stored), and
# storage abuse is bounded by MAX_UPLOAD_SIZE (500 MB), write-once, the
# per-identity creation budget, and 507-on-full. The limiter only caps
# request-flood churn — connections and signature-verification CPU — on top.
@limiter.limit("600/minute")
async def upload_file(
    report_id: str,
    filename: str,
    request: Request,
    x_report_pk: str | None = Header(default=None),
    x_report_write_sig: str | None = Header(default=None),
    x_report_create_sig: str | None = Header(default=None),
    authorization: str | None = Header(default=None),
):
    """Relay-blind upload: capability-addressed, lazy, blob-first.

    Two things here are load-bearing and neither is enforced by the code below.

    The identity carried by the JWT is used once, for the soft anti-abuse
    counter, then discarded. It is never written alongside the report: storing
    `sub` in the record to know "who uploaded this" would be exactly the
    identity -> report join at rest that the whole design refuses.

    And the order of the steps matters, in particular that the blob is durable
    BEFORE any record is written. That is what makes "a record implies >=1
    durable blob" true, which in turn makes the rescue's 404-on-unknown-record
    reliable and lets us do without a per-record createdAt and without an
    empty-report sweep. Swapping steps 5 and 6 to simplify the flow would break
    archive reads after a device loss without turning a single upload test red.

      1. report_id == H(report_pk)            (self-authenticating address)
      2. record exists?  -> presented pk must match the stored binding (409)
         record absent?   -> require creation headers + valid JWT + create-sig +
                             creation budget, else 425 ("retry, not yet created")
      3. stream body -> SHA-256 (one pass)
      4. verify write-sig over (0x08 || report_id || filename || sha256(body))
      5. re-read the record and store the blob (write-once, with its write-sig
         as metadata) under the closure rule — durable before any record is
         written
      6. if creating: create-or-verify the record (now that >=1 blob is durable)

    Every PUT carries `X-Report-PK` + `X-Report-Write-Sig` (the per-report key
    `R_n` authorizes this chunk). Only the creating chunk also carries
    `Authorization: Bearer <stream JWT>` (proof of enrollment, anti-sybil) and
    `X-Report-Create-Sig`, which binds report_id to report_pk.
    """
    _validate_path(report_id, filename)

    # ---- (1) Always-present capability headers (cheap, pre-stream) ----------
    report_pk = _parse_hex(x_report_pk, 32, "X-Report-PK")
    write_sig = _parse_hex(x_report_write_sig, 64, "X-Report-Write-Sig")
    report_id_bytes = bytes.fromhex(report_id)  # 16 bytes (validated above)
    report_pk_hex = report_pk.hex()             # canonical lowercase for storage

    # The report_id must be the hash of the presented report_pk. This binds the
    # URL to the key up front and makes substituting a different report_pk a
    # second-preimage problem on SHA-256.
    if _report_id_from_pk(report_pk) != report_id_bytes:
        raise HTTPException(400, "report_id does not match X-Report-PK")

    # ---- (2) Create vs subsequent, on record existence (cheap) --------------
    record = reports.get_report(report_id)
    is_creation = record is None
    # Carries the creating identity from the budget CHECK (below) to the budget
    # COMMIT (step 6); set only on the creation path. Declared here so step 6
    # never references an unbound name.
    creation_identity: str | None = None
    if record is not None:
        if record.get("report_pk") != report_pk_hex:
            raise HTTPException(409, "report_pk does not match the stored report")
    else:
        if x_report_create_sig is None or authorization is None:
            # A "subsequent" chunk arrived before its creating chunk (the
            # client's WorkManager enqueue does not order PUTs). Tell the client
            # to retry — store nothing, create nothing.
            raise HTTPException(425, "Report not yet created — retry")
        create_sig = _parse_hex(x_report_create_sig, 64, "X-Report-Create-Sig")
        # The JWT proves enrollment; its subject (the identity) is used once for
        # the anti-abuse counter, then discarded.
        payload = auth.verify_jwt(authorization)
        if payload is None:
            raise HTTPException(401, "Invalid or expired token")
        scope = payload.get("scope")
        if scope is not None and scope != "stream":
            raise HTTPException(403, f"Token scope '{scope}' not allowed")
        create_msg = (
            signature_domain.SIG_DOMAIN_REPORT_CREATE + report_id_bytes + report_pk
        )
        if not auth.verify_detached_ed25519(report_pk, create_sig, create_msg):
            raise HTTPException(403, "Invalid create signature")
        sub = payload.get("sub")
        del payload
        # Soft per-(identity, batch) creation budget: a count, not a map.
        # RESERVE one slot here, check and increment under a single lock. Do not
        # go back to peeking here and committing at step 6: that split left a
        # check-vs-commit TOCTOU across the body stream and the to_thread store,
        # so concurrent creating PUTs for the same (identity, batch) all passed
        # on a stale read and the cap was bypassable by plain concurrency (audit
        # 2026-06-27, R-SRV-3). If anything below fails before the record is
        # durable, the `finally` releases the slot, so a failed or aborted
        # creation never burns budget and the cap stays a hard wall. Only `sub`
        # (the identity string) is held, in RAM, for the duration of the
        # request; it is never written to disk, so relay-blind-at-rest is
        # unchanged. Run under to_thread because the reserve fsyncs and the
        # single async worker must not block on disk I/O.
        if not isinstance(sub, str):
            raise HTTPException(429, "Report creation not allowed (budget)")
        if not await asyncio.to_thread(
            ratchet_registry.reserve_report_creation,
            sub,
            config.MAX_REPORTS_PER_BATCH,
        ):
            raise HTTPException(429, "Report creation not allowed (budget)")
        creation_identity = sub

    # ---- (3..6) A creation slot may be reserved (step 2). From here, RELEASE it
    # on ANY failure so a creation that never lands a durable record does not
    # burn budget; keep it only once the record is durable (audit R-SRV-3). -----
    creation_committed = False
    try:
        # ---- (3) Stream the body to a spool + SHA-256 (one pass) ------------
        total = 0
        hasher = hashlib.sha256()
        with tempfile.SpooledTemporaryFile(max_size=8 * 1024 * 1024) as tmp:
            async for chunk in request.stream():
                total += len(chunk)
                if total > MAX_UPLOAD_SIZE:
                    raise HTTPException(status_code=413, detail="Upload too large")
                hasher.update(chunk)
                tmp.write(chunk)

            # An empty body cannot anchor a report (no durable blob), which would
            # break the record => >=1 blob invariant. Reject before any record.
            if total == 0:
                raise HTTPException(400, "Empty upload not allowed")

            # ---- (4) Verify the write signature ----------------------------
            # body hash MUST be byte-identical to what storage persists below.
            write_msg = (
                signature_domain.SIG_DOMAIN_REPORT_WRITE
                + report_id_bytes
                + filename.encode("utf-8")
                + hasher.digest()
            )
            if not auth.verify_detached_ed25519(report_pk, write_sig, write_msg):
                raise HTTPException(403, "Invalid write signature")

            # ---- (5) Store the blob (write-once), durable BEFORE the record -
            # The record read at step (2) predates the body stream, and a
            # closure can be recorded while the body is still arriving, so the
            # record is read again here, after the signature check. From that
            # read to the end of the store this section holds the registry lock
            # and never awaits: POST /close records closures under the same
            # lock (from a worker thread), so "closure recorded" and "new
            # object stored" cannot interleave. The store is synchronous on the
            # event loop, as it always was; the lock can add a wait of one
            # closure write (manifest store + registry save) to it.
            tmp.seek(0)
            try:
                with reports.registry_lock():
                    current = reports.get_report(report_id)
                    if current is not None and current.get("report_pk") != report_pk_hex:
                        raise HTTPException(409, "report_pk does not match the stored report")
                    storage.upload_blob_stream_write_once(
                        report_id,
                        filename,
                        tmp,
                        total,
                        hasher.hexdigest(),
                        write_sig_hex=write_sig.hex(),
                        closed_seq_limit=reports.closed_seq_limit(current),
                    )
            except storage.ReportClosedError:
                # The report's signed closure does not cover this new name.
                # Keep the body exact: the client tells this 409 apart from
                # the write-once 409 below by it (crypto-rs reads the body of a
                # 409 and reports `report_closed` only for exactly
                # `{"detail":"Report closed"}`).
                raise HTTPException(status_code=409, detail="Report closed")
            except storage.StorageFullError:
                # MinIO disk-full. 507 rather than 500 tells the client this is
                # a persistent capacity condition, so it opens its circuit
                # breaker and keeps the blob on-device until space frees.
                raise HTTPException(
                    status_code=507,
                    detail="Server storage full — contact the administrator",
                )
            except storage.WriteOnceConflictError:
                # §10.6 write-once — the key already holds different bytes. Refuse
                # the overwrite (a leaked capability trying to corrupt a stored
                # chunk) with 409. A byte-identical re-PUT (legit retry / race)
                # is a no-op and does not reach here.
                raise HTTPException(
                    status_code=409,
                    detail="Chunk already stored with different content",
                )

        # ---- (6) Creation: blob is durable, now write the record -----------
        # to_thread: the save fsyncs, and the single worker's event loop must
        # not wait on the disk.
        if is_creation:
            if not await asyncio.to_thread(
                reports.create_or_verify_report, report_id, report_pk_hex
            ):
                # A concurrent worker created the same id with a different pk.
                raise HTTPException(409, "report_pk does not match the stored report")

        # Past this point the report (if any) is durable — keep the reserved
        # slot (exactly one per report actually created; a retry of this creating
        # PUT finds the record present above, so it is not a creation and never
        # re-charges).
        creation_committed = True
        return Response(status_code=204)
    finally:
        # Roll back the reserved creation slot unless the report became durable.
        # No-op on the subsequent-chunk path (creation_identity is None) and on
        # the happy path (creation_committed True). to_thread: release fsyncs.
        if creation_identity is not None and not creation_committed:
            await asyncio.to_thread(
                ratchet_registry.release_report_creation, creation_identity
            )


def _parse_seq_limit(value: str | None) -> int:
    if value is None:
        raise HTTPException(400, "Missing X-Report-Close-Seq-Limit header")
    if _SEQ_LIMIT_RE.fullmatch(value) is None:
        raise HTTPException(400, "Invalid X-Report-Close-Seq-Limit header")
    seq_limit = int(value)
    if seq_limit > paths.MAX_SEQ_LIMIT:
        raise HTTPException(400, "Invalid X-Report-Close-Seq-Limit header")
    return seq_limit


def _check_manifest_frame(head: bytes, total: int) -> None:
    """400 unless the body has the manifest's magic and the exact length its
    count announces. Deliberately the only parsing the relay does: the entries
    (seq order, hashes) are checked by the rescue against the stored objects,
    and the relay never needs them."""
    if total < _MANIFEST_HEADER_LEN or head[:4] != _MANIFEST_MAGIC:
        raise HTTPException(400, "Malformed manifest")
    count = int.from_bytes(head[4:_MANIFEST_HEADER_LEN], "big")
    if total != _MANIFEST_HEADER_LEN + count * _MANIFEST_ENTRY_LEN:
        raise HTTPException(400, "Malformed manifest")


@router.post("/close/{report_id}")
# Same bucket shape and ceiling as the PUT above, for the same reason: a backlog
# drain after a reconnect sends closures along with chunks, and a 429 only
# delays them (the client retries, the envelope stays on the device).
@limiter.limit("600/minute")
async def close_report_route(
    report_id: str,
    request: Request,
    x_report_pk: str | None = Header(default=None),
    x_report_close_sig: str | None = Header(default=None),
    x_report_close_seq_limit: str | None = Header(default=None),
):
    """Freeze a report: after this, the relay accepts no new object name in it
    outside what the signed closure covers.

    The body is the closure manifest; the 0x09 signature under the record's
    report_pk covers `report_id || u32_be(seq_limit) || sha256(body)`. Once
    recorded, a PUT that would create a new object is accepted only for a name
    `NNNNNN.strm` with `NNNNNN < seq_limit` (a chunk the manifest can list,
    arriving late); existing objects keep their write-once semantics. A legacy
    closure (empty manifest, seq_limit 0) therefore admits no new object.

    No JWT and no creation budget, on purpose. A closure creates nothing: it
    needs an existing record, and the signature under that record's key is the
    only authorization that means anything here. A bearer token would hand the
    relay an identity at the moment a report ends, exactly the join it must not
    hold.

    Codes, in the order they are checked:
      400  bad report_id, missing/malformed header, seq_limit not canonical or
           above 1_000_000, report_id != H(report_pk)
      425  no record yet: the closure overtook the report's creating chunk
           (the client's queue does not order uploads), retry later
      409  report_pk differs from the record's
      413  body above MAX_MANIFEST_SIZE (checked while it streams)
      400  body is not a manifest frame (magic, length)
      403  invalid 0x09 signature
      then, under the registry lock: the 425/409 record checks again; 409 if a
      different closure is already recorded or a different `manifest` object
      is already stored; 507 storage full; 503 the registry save failed
      (nothing recorded); 204 closure recorded, or the same closure was already
      recorded.
    """
    paths.validate_report_id(report_id)
    report_pk = _parse_hex(x_report_pk, 32, "X-Report-PK")
    close_sig = _parse_hex(x_report_close_sig, 64, "X-Report-Close-Sig")
    seq_limit = _parse_seq_limit(x_report_close_seq_limit)
    report_id_bytes = bytes.fromhex(report_id)
    report_pk_hex = report_pk.hex()
    if _report_id_from_pk(report_pk) != report_id_bytes:
        raise HTTPException(400, "report_id does not match X-Report-PK")

    # Cheap record checks before reading up to 40 MB of body. They are repeated
    # under the lock in reports.close_report, which is the one that counts.
    record = reports.get_report(report_id)
    if record is None:
        raise HTTPException(425, "Report not yet created — retry")
    if record.get("report_pk") != report_pk_hex:
        raise HTTPException(409, "report_pk does not match the stored report")

    total = 0
    hasher = hashlib.sha256()
    head = bytearray()
    with tempfile.SpooledTemporaryFile(max_size=8 * 1024 * 1024) as tmp:
        async for chunk in request.stream():
            total += len(chunk)
            if total > MAX_MANIFEST_SIZE:
                raise HTTPException(status_code=413, detail="Manifest too large")
            if len(head) < _MANIFEST_HEADER_LEN:
                head.extend(chunk[: _MANIFEST_HEADER_LEN - len(head)])
            hasher.update(chunk)
            tmp.write(chunk)
        _check_manifest_frame(bytes(head), total)

        manifest_sha256 = hasher.digest()
        close_msg = (
            signature_domain.SIG_DOMAIN_REPORT_CLOSE
            + report_id_bytes
            + seq_limit.to_bytes(4, "big")
            + manifest_sha256
        )
        if not auth.verify_detached_ed25519(report_pk, close_sig, close_msg):
            raise HTTPException(403, "Invalid close signature")

        tmp.seek(0)
        try:
            # One worker thread for the whole lookup + manifest store + save,
            # under the registry lock (reports.close_report).
            await asyncio.to_thread(
                reports.close_report,
                report_id,
                report_pk_hex,
                seq_limit,
                manifest_sha256.hex(),
                close_sig.hex(),
                tmp,
                total,
            )
        except reports.ReportUnknownError:
            raise HTTPException(425, "Report not yet created — retry")
        except reports.ReportKeyMismatchError:
            raise HTTPException(409, "report_pk does not match the stored report")
        except reports.ClosureConflictError:
            raise HTTPException(409, "A different closure is already recorded")
        except storage.WriteOnceConflictError:
            raise HTTPException(409, "Manifest already stored with different content")
        except storage.StorageFullError:
            raise HTTPException(
                status_code=507,
                detail="Server storage full — contact the administrator",
            )
        except OSError as e:
            # An I/O error, most likely the registry save. close_report rolls
            # its in-memory change back, so nothing is recorded and the client
            # retries; a manifest already stored is found identical then.
            logger.error("Closure not recorded, I/O error: %s", type(e).__name__)
            raise HTTPException(503, "Report registry unavailable — retry")
    return Response(status_code=204)
