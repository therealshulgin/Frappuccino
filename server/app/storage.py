import hashlib
import io
import logging
import re
from collections.abc import Mapping
from typing import NamedTuple

from minio import Minio
from minio.commonconfig import REPLACE, CopySource
from minio.error import S3Error
from app import config, paths

logger = logging.getLogger("stream.storage")

_client: Minio | None = None


class StorageFullError(Exception):
    """Phase 1.12 — raised when MinIO rejects a PUT because the backing
    disk is full. The upload route maps this to HTTP 507 so the client
    opens its circuit breaker immediately and STOPS retrying (a disk-full
    won't fix itself on the next backoff bucket) while keeping the blob
    on-device until space frees. Any OTHER S3Error keeps propagating
    untranslated (→ 500, transient-server semantics)."""


class WriteOnceConflictError(Exception):
    """§10.6 write-once — raised when a PUT would overwrite an EXISTING
    object with DIFFERENT content. The upload route maps this to HTTP 409.

    The threat is the §10.6 JWT-in-heap finding: the 24 h upload JWT can
    survive device seizure in the JVM heap. Scope segregation (R-H2) means a
    leaked upload token cannot read, list or decrypt the archive, and there is
    no DELETE route — but back when the PUT was a plain idempotent overwrite
    (Phase 3.12), that token could still replace already-stored witness chunks
    with garbage, corrupting the recent rushes remotely. Write-once closes it:
    an existing object is immutable.

    A byte-identical re-PUT is still allowed through as a no-op — a legit
    retry (1.12 / 3.41) or a client/server race — so the idempotent-retry
    guarantee those paths rely on is preserved."""


class ReportClosedError(Exception):
    """Raised when a PUT would create a NEW object in a report whose closure
    the relay has recorded, under a name that closure does not cover
    (`paths.name_allowed_after_close`). The upload route maps it to 409
    `{"detail": "Report closed"}`.

    The decision is taken here, on the same `stat_object` that tells whether
    the key is free, so "is this a new object?" and "may a new object be
    written?" are one answer, not two probes. An object that already exists is
    not a creation: it keeps the write-once semantics (identical re-PUT is a
    no-op, different bytes raise WriteOnceConflictError) whatever the closure
    says."""


class BlobInfo(NamedTuple):
    """What one `stat_object` says about a stored object."""

    size: int
    # The object's write signature (domain 0x08) as 128 lowercase hex chars, or
    # None for an object stored before the relay kept it.
    write_sig_hex: str | None


# User metadata under which the relay keeps each object's write signature
# (domain 0x08), as lowercase hex, written by the same `put_object` that
# creates the object.
#
# It is integrity data, not a convenience. A report that was never closed has
# no manifest, so the signature stored here is the only thing that lets the
# rescue tell a chunk the witness's key signed from one it did not. A storage
# migration that copies object bytes without their user metadata turns every
# such chunk into an unverifiable one; `deploy/audit-reports-vs-blobs.sh`
# counts the objects that lack it.
WRITE_SIG_METADATA_KEY = "x-amz-meta-report-write-sig"
_WRITE_SIG_RE = re.compile(r"[a-f0-9]{128}")


# MinIO/S3 error codes meaning "out of storage". Matched leniently (exact
# set + case-insensitive substring) because the exact code has varied
# across MinIO releases — XMinioStorageFull historically, the generic S3
# InsufficientStorage in others.
_DISK_FULL_CODES = frozenset({"XMinioStorageFull", "StorageFull", "InsufficientStorage"})


def _is_disk_full(e: S3Error) -> bool:
    code = getattr(e, "code", "") or ""
    lc = code.lower()
    return code in _DISK_FULL_CODES or "storagefull" in lc or "insufficientstorage" in lc


def _raise_if_disk_full(e: S3Error, op: str, path: str) -> None:
    """Re-raise a disk-full S3Error as [StorageFullError]; return otherwise,
    so the caller re-raises every other S3Error unchanged."""
    if _is_disk_full(e):
        logger.error(
            "MinIO disk-full on %s %s (code=%s) → StorageFullError",
            op, path, getattr(e, "code", "?"),
        )
        raise StorageFullError(str(e)) from e


def _put_object_guarded(path: str, data, length: int, metadata: dict | None = None):
    """Wraps client.put_object, translating a disk-full S3Error into
    [StorageFullError]. All other S3Errors propagate unchanged so they
    keep their existing (→ HTTP 500) transient-server semantics."""
    client = get_client()
    try:
        client.put_object(
            config.MINIO_BUCKET, path, data, length,
            content_type="application/octet-stream",
            metadata=metadata,
        )
    except S3Error as e:
        _raise_if_disk_full(e, "PUT", path)
        raise


def get_client() -> Minio:
    global _client
    if _client is None:
        _client = Minio(
            config.MINIO_ENDPOINT,
            access_key=config.MINIO_ACCESS_KEY,
            secret_key=config.MINIO_SECRET_KEY,
            secure=config.MINIO_SECURE,
        )
    return _client


def ensure_bucket():
    client = get_client()
    if not client.bucket_exists(config.MINIO_BUCKET):
        client.make_bucket(config.MINIO_BUCKET)
        logger.info("Created bucket: %s", config.MINIO_BUCKET)


def _object_path(report_id: str, filename: str) -> str:
    # report_id + filename are validated strict upstream (app.paths): the object
    # key is byte-identical to the write-signed name, never silently rewritten.
    # Fail CLOSED if an unvalidated caller ever reaches here (mangled/colliding
    # key) instead of the old silent `.replace("..","")` that mutated the key.
    if ".." in report_id or "/" in report_id or "\\" in report_id:
        raise ValueError("unvalidated report_id reached storage layer")
    if ".." in filename or "/" in filename or "\\" in filename:
        raise ValueError("unvalidated filename reached storage layer")
    return f"{report_id}/{filename}"


def _stat_or_none(path: str):
    """`stat_object`, or None when the key is free. Any other S3Error
    propagates."""
    try:
        return get_client().stat_object(config.MINIO_BUCKET, path)
    except S3Error as e:
        if e.code == "NoSuchKey":
            return None
        raise


def _write_sig_from_metadata(metadata) -> str | None:
    """The write signature kept in an object's user metadata, or None.

    The lookup ignores case: header names are case-insensitive, the store may
    hand them back canonicalised (`X-Amz-Meta-Report-Write-Sig`), and while
    the stat result's headers compare case-insensitively, a plain dict does
    not. A value that is not 128 lowercase hex chars is treated as absent
    rather than served: this relay only ever writes that form there.
    """
    if not isinstance(metadata, Mapping):
        return None
    for key, value in metadata.items():
        if str(key).lower() != WRITE_SIG_METADATA_KEY:
            continue
        if isinstance(value, str) and _WRITE_SIG_RE.fullmatch(value) is not None:
            return value
        logger.warning("Ignoring malformed write-sig metadata")
        return None
    return None


def stat_blob(report_id: str, filename: str) -> BlobInfo | None:
    """Size and stored write signature of one object, or None if absent. One
    `stat_object`, which the archive download reads for Content-Length and for
    the `X-Report-Write-Sig` header."""
    stat = _stat_or_none(_object_path(report_id, filename))
    if stat is None:
        return None
    return BlobInfo(size=stat.size, write_sig_hex=_write_sig_from_metadata(stat.metadata))


def upload_blob(report_id: str, filename: str, data: bytes):
    """Plain overwrite PUT, off the production path: only the disk-full tests
    call it. Live uploads go through `upload_blob_stream_write_once`, which
    refuses to clobber an occupied key (409) — that, not this, is the PUT
    semantics of the relay.

    Never rebuild a relay-side "resume" on top of it. Earlier versions
    downloaded the existing object, concatenated the new bytes and re-uploaded,
    and one race window was enough to break that: a reconnect flush cancels a
    worker mid-PUT, the server-side PUT completes anyway, the client retries
    the same filename, and the old code then **appended the same bytes to
    themselves**, leaving a 2× blob on disk that fails to decode at play time,
    long after the upload reported success. The resume path was never needed
    in the first place — a STRM chunk is sealed end-to-end on the device and
    either arrives whole or not at all.

    Overwriting outright is also what RFC 9110 §9.3.4 asks of a PUT, and it
    makes the race benign: a duplicate PUT just rewrites the same bytes.
    """
    if len(data) == 0:
        return
    path = _object_path(report_id, filename)
    # Phase 1.12 — disk-full → StorageFullError (route maps to 507).
    _put_object_guarded(path, io.BytesIO(data), len(data))


def upload_blob_stream(report_id: str, filename: str, stream, length: int):
    """Length-known streaming upload: same overwrite-only semantics as
    `upload_blob`, but it takes an IO-like object (a rewound
    `SpooledTemporaryFile`, say) instead of buffering the whole payload as
    `bytes`. That saves one in-process copy of the body, ~1.7 MB per chunk on
    the current quality profile, and a measurable slice of response time on
    the FastAPI worker (SPEED-R1-1).

    `length` must be the exact byte count the stream will yield: MinIO's
    `put_object` uses it to pre-allocate and to validate the boundary. Passing
    `-1` when the size is unknown is tempting and the API accepts it, but it
    forces a multipart upload, which is NOT idempotent — a disconnect leaves
    orphan parts behind — and breaks the PUT-overwrite guarantee the rest of
    this module is built on.
    """
    if length <= 0:
        return
    path = _object_path(report_id, filename)
    # Phase 1.12 — disk-full → StorageFullError (route maps to 507).
    _put_object_guarded(path, stream, length)


def _stored_sha256(path: str) -> str:
    """§10.6 write-once — SHA-256 (hex) of the object already stored at `path`.

    The hash is recomputed from the bytes on disk rather than read off an ETag
    or stored metadata, and that is not wasted work: MinIO ETags are irregular
    under multipart and under SSE, and the legacy blobs that predate write-once
    carry no hash metadata at all. Comparing ETags instead — free, and the
    first thing anyone reaches for — would either 409 a legitimate re-PUT of a
    legacy blob or call two different objects identical and let an overwrite
    through.

    It stays cheap in practice: a brand-new chunk costs one `stat_object` that
    raises NoSuchKey, no GET. The read-back only happens on a *re-PUT* to an
    occupied key: a retry whose first response was lost, or a race."""
    client = get_client()
    obj = client.get_object(config.MINIO_BUCKET, path)
    h = hashlib.sha256()
    try:
        while True:
            data = obj.read(64 * 1024)
            if not data:
                break
            h.update(data)
    finally:
        obj.close()
        obj.release_conn()
    return h.hexdigest()


def _attach_write_sig(path: str, write_sig_hex: str) -> None:
    """Add the write-signature metadata to an object stored without it.

    S3 has no in-place metadata edit: a copy of the object onto its own key
    with the REPLACE directive is the operation for it. The bytes do not change,
    but the object's `last_modified` becomes the time of the copy, and both the
    retention TTL (blob_cleanup) and the rescue's per-report date range read
    that field. It happens at most once per object: the first identical re-PUT
    of an object stored before the relay kept signatures.
    """
    client = get_client()
    try:
        client.copy_object(
            config.MINIO_BUCKET,
            path,
            CopySource(config.MINIO_BUCKET, path),
            metadata={
                "Content-Type": "application/octet-stream",
                WRITE_SIG_METADATA_KEY: write_sig_hex,
            },
            metadata_directive=REPLACE,
        )
    except S3Error as e:
        _raise_if_disk_full(e, "COPY", path)
        raise


def upload_blob_stream_write_once(
    report_id: str,
    filename: str,
    stream,
    length: int,
    sha256_hex: str,
    write_sig_hex: str | None = None,
    closed_seq_limit: int | None = None,
) -> str:
    """§10.6 write-once PUT — an existing object is immutable. A free key takes
    the bytes and returns "created", a byte-identical re-PUT is a no-op that
    returns "identical" (the idempotent-retry guarantee the client's retries
    lean on), and a PUT that would replace stored bytes with different ones
    raises WriteOnceConflictError, which the route maps to 409.

    `write_sig_hex`, when given, is the verified write signature of these
    bytes. It is stored as user metadata by the `put_object` that creates the
    object, never by a second request, so no object created through here with a
    signature is ever visible without it. An identical re-PUT of an object that
    lacks it (stored before the relay kept signatures) attaches it; one that
    already has it leaves it alone, like the bytes.

    `closed_seq_limit` is the seq_limit of the report's recorded closure, or
    None while the report is open. When it is set, a free key is written only
    if `paths.name_allowed_after_close` admits the name; otherwise
    ReportClosedError. The upload route reads the closure under the registry
    lock and holds that lock across this call, so a closure cannot be recorded
    between that read and the write.

    Two things to keep if this is ever rewritten. The write itself must stay
    the length-known, non-multipart streaming PUT of `upload_blob_stream`, so
    a full disk keeps surfacing as StorageFullError and the route keeps
    answering 507. And refusing to clobber an occupied key is, with the closure
    rule, the only behaviour added on top of it — that refusal is what stops a
    leaked upload JWT from corrupting already-stored witness chunks (threat
    model spelled out on WriteOnceConflictError)."""
    if length <= 0:
        return "empty"
    if write_sig_hex is not None and _WRITE_SIG_RE.fullmatch(write_sig_hex) is None:
        raise ValueError("write signature must be 128 lowercase hex chars")
    path = _object_path(report_id, filename)
    incoming = (sha256_hex or "").strip().lower()
    stat = _stat_or_none(path)
    if stat is not None:
        if _stored_sha256(path) != incoming:
            raise WriteOnceConflictError(
                f"{path}: stored object differs from incoming bytes (write-once)"
            )
        # Idempotent retry / race — leave the stored bytes.
        if write_sig_hex is not None and _write_sig_from_metadata(stat.metadata) is None:
            _attach_write_sig(path, write_sig_hex)
        return "identical"
    if closed_seq_limit is not None and not paths.name_allowed_after_close(
        filename, closed_seq_limit
    ):
        raise ReportClosedError(f"{path}: report closed")
    metadata = None if write_sig_hex is None else {WRITE_SIG_METADATA_KEY: write_sig_hex}
    # Disk-full → StorageFullError (route maps to 507).
    _put_object_guarded(path, stream, length, metadata)
    return "created"


def list_blobs(report_id: str) -> list[dict]:
    """Phase 4.4 — list every blob under a report's MinIO prefix.

    Returns a list of {filename, size, last_modified} dicts. The report_id
    sanitization is the same path-traversal guard used everywhere else in
    this module. Blob filenames are returned without the report prefix
    (so the client can pair them straight with GET endpoints).
    """
    # report_id validated strict upstream (32-hex); no rewrite, fail closed.
    if ".." in report_id or "/" in report_id or "\\" in report_id:
        raise ValueError("unvalidated report_id reached storage layer")
    prefix = f"{report_id}/"
    client = get_client()
    out: list[dict] = []
    try:
        for obj in client.list_objects(config.MINIO_BUCKET, prefix=prefix, recursive=True):
            name = obj.object_name
            if name and name.startswith(prefix):
                bare = name[len(prefix):]
            else:
                bare = name or ""
            out.append({
                "filename": bare,
                "size": obj.size,
                "last_modified": (
                    obj.last_modified.isoformat() if obj.last_modified else None
                ),
            })
    except S3Error as e:
        if e.code == "NoSuchBucket":
            return []
        logger.error("S3 error listing blobs for %s: %s", report_id, e)
        raise
    return out


def iter_blob(report_id: str, filename: str, chunk_size: int = 64 * 1024):
    """Phase 4.4 — streaming GET for archive download.

    Yields fixed-size byte chunks straight from MinIO. The caller (FastAPI
    StreamingResponse) is responsible for closing the underlying urllib3
    connection by exhausting or breaking out of the generator — the
    `try/finally` here covers both paths.
    """
    client = get_client()
    path = _object_path(report_id, filename)
    obj = client.get_object(config.MINIO_BUCKET, path)
    try:
        while True:
            data = obj.read(chunk_size)
            if not data:
                break
            yield data
    finally:
        obj.close()
        obj.release_conn()
