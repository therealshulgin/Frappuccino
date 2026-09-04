import hashlib
import io
import logging
from minio import Minio
from minio.error import S3Error
from app import config

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


# MinIO/S3 error codes meaning "out of storage". Matched leniently (exact
# set + case-insensitive substring) because the exact code has varied
# across MinIO releases — XMinioStorageFull historically, the generic S3
# InsufficientStorage in others.
_DISK_FULL_CODES = frozenset({"XMinioStorageFull", "StorageFull", "InsufficientStorage"})


def _is_disk_full(e: S3Error) -> bool:
    code = getattr(e, "code", "") or ""
    lc = code.lower()
    return code in _DISK_FULL_CODES or "storagefull" in lc or "insufficientstorage" in lc


def _put_object_guarded(path: str, data, length: int):
    """Wraps client.put_object, translating a disk-full S3Error into
    [StorageFullError]. All other S3Errors propagate unchanged so they
    keep their existing (→ HTTP 500) transient-server semantics."""
    client = get_client()
    try:
        client.put_object(
            config.MINIO_BUCKET, path, data, length,
            content_type="application/octet-stream",
        )
    except S3Error as e:
        if _is_disk_full(e):
            logger.error(
                "MinIO disk-full on PUT %s (code=%s) → StorageFullError",
                path, getattr(e, "code", "?"),
            )
            raise StorageFullError(str(e)) from e
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


def get_blob_size(report_id: str, filename: str) -> int:
    client = get_client()
    try:
        stat = client.stat_object(config.MINIO_BUCKET, _object_path(report_id, filename))
        return stat.size
    except S3Error as e:
        if e.code == "NoSuchKey":
            return 0
        logger.error("S3 error checking blob size: %s", e)
        raise


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

    `existing_size` is not consulted here. `get_blob_size` itself is live in
    production — the archive download reads it for Content-Length, and
    `blob_exists` is built on it.
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


def _existing_object_sha256(path: str) -> str | None:
    """§10.6 write-once — SHA-256 (hex) of the object already stored at
    `path`, or None if the key is free.

    The hash is recomputed from the bytes on disk rather than read off an ETag
    or stored metadata, and that is not wasted work: MinIO ETags are irregular
    under multipart and under SSE, and the legacy blobs that predate write-once
    carry no hash metadata at all. Comparing ETags instead — free, and the
    first thing anyone reaches for — would either 409 a legitimate re-PUT of a
    legacy blob or call two different objects identical and let an overwrite
    through.

    It stays cheap in practice: a brand-new chunk costs one `stat_object` that
    raises NoSuchKey, no GET. The read-back only happens on a *re-PUT* to an
    occupied key, which the client avoids by HEADing first and skipping chunks
    already stored."""
    client = get_client()
    try:
        client.stat_object(config.MINIO_BUCKET, path)
    except S3Error as e:
        if e.code == "NoSuchKey":
            return None
        raise
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


def upload_blob_stream_write_once(
    report_id: str, filename: str, stream, length: int, sha256_hex: str
) -> str:
    """§10.6 write-once PUT — an existing object is immutable. A free key takes
    the bytes and returns "created", a byte-identical re-PUT is a no-op that
    returns "identical" (the idempotent-retry guarantee the client's retries
    lean on), and a PUT that would replace stored bytes with different ones
    raises WriteOnceConflictError, which the route maps to 409.

    Two things to keep if this is ever rewritten. The write itself must stay
    the length-known, non-multipart streaming PUT of `upload_blob_stream`, so
    a full disk keeps surfacing as StorageFullError and the route keeps
    answering 507. And refusing to clobber an occupied key is the only
    behaviour added on top of it — that refusal is what stops a leaked upload
    JWT from corrupting already-stored witness chunks (threat model spelled
    out on WriteOnceConflictError)."""
    if length <= 0:
        return "empty"
    path = _object_path(report_id, filename)
    incoming = (sha256_hex or "").strip().lower()
    existing = _existing_object_sha256(path)
    if existing is not None:
        if existing == incoming:
            return "identical"  # idempotent retry / race — leave the stored bytes
        raise WriteOnceConflictError(
            f"{path}: stored object differs from incoming bytes (write-once)"
        )
    # Phase 1.12 — disk-full → StorageFullError (route maps to 507).
    _put_object_guarded(path, stream, length)
    return "created"


def blob_exists(report_id: str, filename: str) -> bool:
    return get_blob_size(report_id, filename) > 0


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
