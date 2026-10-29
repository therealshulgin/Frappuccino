"""
Diagnostic logs from pre-release test builds.

A test build of the app (version name ending in `-testN`) sends its own log
lines and a description of the phone here, so that a problem seen on only some
phones can be diagnosed from what the phone recorded rather than guessed at.
Production builds do not contain the uploader, and a relay mounts this route
only when its operator sets DIAG_LOGS_DIR, which only the test relay does.
Anywhere else the path answers 404 like any unknown path (main.py).

This is a deliberate exception to what the relay otherwise keeps, and the limits
below are what keep it an exception:

- No identity. The request carries no JWT and no report capability, only an
  install id the app draws at random and forgets on an emergency wipe. The app
  passes every line through a redactor before storing or sending it, meant to
  strip report and session ids, keys and addresses; that is a filter, not a
  proof. The relay does not read the text either: the inflate pass below counts
  bytes and throws them away.
- No address. The only use of the client IP on this path is the rate limiter's
  key, held in memory. It is never logged and never written
  (app/logging_setup.py), and of the request headers only the two validated
  below reach the disk, as path components.
- Bounded. A body is at most MAX_BODY_BYTES of gzip, in at most MAX_GZIP_MEMBERS
  members, that must inflate to at most MAX_INFLATED_BYTES; the directory and
  each install have a ceiling (507 beyond), counted in disk blocks so that
  small files cannot hold more of the disk than the ceiling says; files older
  than DIAG_RETENTION_DAYS are deleted at startup and then every hour.
  The total ceiling is shared: anyone who finds the route can fill it, and
  every upload then gets 507 until the files expire or the operator purges
  them (deploy/README.md). On a test relay that is an outage of the
  diagnostics, not of the relay.
- Out of the backups. In the compose deployment the files live in their own
  volume, `diag_logs`, mounted at /diag. backup-state.sh copies `server_state`
  and `minio_data` only, so the relay's backups do not carry the logs (a
  snapshot of the whole disk taken by the host would), and purging them at the
  end of a test is one command (deploy/README.md).

Layout: DIAG_LOGS_DIR/<install>/<UTC YYYYmmddTHHMMSSZ>-<8 hex>-<app>.log.gz,
directories 0700, files 0600, each file holding the request body exactly as
received (read them with zcat).
"""

import asyncio
import logging
import os
import re
import secrets
import stat
import threading
import time
import zlib
from pathlib import Path

from fastapi import APIRouter, Header, HTTPException, Request, Response

from app import atomic_io, config
from app.ratelimit import limiter  # shared app-wide Limiter (see app/ratelimit.py)

logger = logging.getLogger("stream.diag")

router = APIRouter()

# One request body: gzip, at most 1 MiB. The app splits a larger upload into
# several requests, and treats a 413 like a 400: it drops what it sent, so a
# payload refused here does not come back in a loop.
MAX_BODY_BYTES = 1024 * 1024

# The gzip bomb ceiling: what the members of one body may inflate to, in all. A
# few KiB of gzip can inflate to gigabytes, and the operator reads these files
# with zcat. The app keeps at most 2 MiB of log files on the phone and captures
# at most 1 MiB of logcat per upload, so a legitimate body inflates to a few MiB.
MAX_INFLATED_BYTES = 8 * 1024 * 1024

# The app sends one gzip member per body. A few are accepted, as `cat a.gz b.gz`
# makes, but not many: at the end of each member zlib copies all the input left
# into `unused_data`, so checking N members costs N times the body, and 1 MiB of
# empty 20-byte members takes seconds of CPU on a thread the chunk uploads need.
MAX_GZIP_MEMBERS = 8

# What a stored file counts for against the ceilings: its size rounded up to
# whole blocks of this size, the allocation unit of an ext4 file system, and one
# block at least. Counting bytes alone would let 20-byte uploads take 200 times
# the disk, and as many inodes as files, that the ceiling says. It also bounds
# the number of files: DIAG_MAX_TOTAL_BYTES / DISK_BLOCK at most.
DISK_BLOCK = 4096
# The install id becomes a directory name: exactly 32 lowercase hex, nothing a
# path could be built from. The app version goes into the file name. Both are
# matched with `fullmatch`, never `match`: `$` also matches before a trailing
# newline (see app/paths.py).
_INSTALL_RE = re.compile(r"[a-f0-9]{32}")
_APP_RE = re.compile(r"[A-Za-z0-9._-]{1,40}")
# The names `_store` gives its files, plus the temporary name atomic_io writes
# first (`<name>.<random>.tmp`), which a crash can leave behind.
_FILE_RE = re.compile(
    r"[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}-[A-Za-z0-9._-]{1,40}\.log\.gz(?:\.[a-z0-9_]+\.tmp)?"
)

# Inflated bytes produced per step, so a bomb is refused one step past the
# ceiling instead of being inflated in full first.
_INFLATE_STEP = 64 * 1024

PURGE_INTERVAL_SECONDS = 3600

# Serialises the quota check with the write, and both with the purge: two
# concurrent uploads could otherwise each pass the check on the same total, and
# the purge could remove an install directory between its creation and the write.
_store_lock = threading.Lock()
# time.monotonic() of the last purge; None until the first one.
_last_purge: float | None = None
# What the directory holds, in blocks charged (DISK_BLOCK): in all, and per
# entry of the directory. Read from disk by the first upload and by every purge
# (at startup, then hourly), kept up to date by each upload in between, so that
# an upload does not list every stored file while it holds _store_lock. Files
# removed by hand are forgotten at the next purge. Guarded by _store_lock.
_usage_total: int | None = None
_usage_by_entry: dict[str, int] = {}


class _QuotaExceeded(Exception):
    def __init__(self, which: str):
        super().__init__(which)
        self.which = which


@router.post("/diag/v1/logs")
# The app uploads at start, after each recording and hourly, one request per MiB
# of compressed logs, so 12/min per IP leaves room for a multi-part upload while
# capping a flood. A 429 only delays an upload: the app retries later. Testers
# behind one NAT share a bucket, and for them too it is only a delay.
@limiter.limit("12/minute")
async def upload_diag_logs(
    request: Request,
    x_diag_install: str | None = Header(default=None),
    x_diag_app: str | None = Header(default=None),
):
    """Store one gzip body of diagnostic logs.

    Codes, in the order they are checked:
      429  over the rate limit
      404  diagnostics are off on this relay (DIAG_LOGS_DIR empty)
      400  X-Diag-Install or X-Diag-App missing or malformed
      413  body above MAX_BODY_BYTES (checked before the body is read in full)
      400  body is not gzip, is corrupt, truncated, has trailing bytes, or
           holds more than MAX_GZIP_MEMBERS members
      413  body inflates above MAX_INFLATED_BYTES
      507  the directory or this install is at its ceiling
      503  the file could not be written
      204  stored
    """
    if not config.DIAG_LOGS_DIR:
        # main.py does not mount this router when the setting is empty. This
        # second check keeps a router mounted by mistake from writing under the
        # working directory.
        raise HTTPException(404, "Not Found")
    install, app_version = _check_headers(x_diag_install, x_diag_app)
    body = await _read_capped(request)
    await asyncio.to_thread(_check_gzip, body)

    root = Path(config.DIAG_LOGS_DIR)
    await _purge_if_due(root)
    try:
        await asyncio.to_thread(_store, root, install, app_version, body)
    except _QuotaExceeded as e:
        logger.warning("Diagnostics upload refused: %s ceiling reached", e.which)
        raise HTTPException(507, "Diagnostics storage full")
    except OSError as e:
        logger.error("Diagnostics upload not stored: %s", type(e).__name__)
        raise HTTPException(503, "Diagnostics storage unavailable")
    return Response(status_code=204)


async def startup_purge() -> None:
    """Delete the files past their retention once, when the relay starts
    (main.py's lifespan), before it serves anything. `purge_loop` does it
    hourly afterwards."""
    global _last_purge
    _last_purge = time.monotonic()
    await _purge(Path(config.DIAG_LOGS_DIR))


async def purge_loop() -> None:
    """Delete the files past their retention every PURGE_INTERVAL_SECONDS, as a
    background task of main.py's lifespan, cancelled at shutdown. Without it a
    relay that keeps running after the testers stop sending would keep their
    files past the retention: the purge on upload needs uploads to run."""
    global _last_purge
    while True:
        await asyncio.sleep(PURGE_INTERVAL_SECONDS)
        _last_purge = time.monotonic()
        try:
            await _purge(Path(config.DIAG_LOGS_DIR))
        except Exception as e:
            # _purge handles OSError; anything else is logged by type, and the
            # loop goes on to the next interval.
            logger.error("Diagnostics purge failed: %s", type(e).__name__)


async def _purge_if_due(root: Path) -> None:
    # A second line behind purge_loop: an upload purges too when no purge has
    # run for an interval.
    global _last_purge
    now = time.monotonic()
    if _last_purge is not None and now - _last_purge < PURGE_INTERVAL_SECONDS:
        return
    _last_purge = now
    await _purge(root)


async def _purge(root: Path) -> None:
    # A failed purge must not refuse the upload or stop the relay from starting:
    # it is logged and tried again at the next interval.
    try:
        removed = await asyncio.to_thread(purge_expired, root)
    except OSError as e:
        logger.error("Diagnostics purge failed: %s", type(e).__name__)
        return
    if removed:
        logger.info("Diagnostics purge removed %d expired file(s)", removed)


def purge_expired(root: Path, now: float | None = None) -> int:
    """Delete the files older than DIAG_RETENTION_DAYS (by modification time) in
    every install directory, then the install directories left empty, and read
    again what the directory holds for the ceilings. Returns the number of files
    deleted.

    Only what `_store` writes is ever deleted: directories named like an install
    id, holding files named like its files. Without that filter, a DIAG_LOGS_DIR
    set by mistake to `/` or to a parent of /state would have the purge delete
    every file of a subdirectory left unmodified for the retention period, the
    relay's own state included."""
    global _usage_total
    cutoff = (time.time() if now is None else now) - config.DIAG_RETENTION_DAYS * 86400
    removed = 0
    with _store_lock:
        # Forgotten first: if the purge fails half way, the next upload reads
        # the disk again instead of trusting totals the purge has made stale.
        _usage_total = None
        try:
            with os.scandir(root) as it:
                installs = [
                    e
                    for e in it
                    if e.is_dir(follow_symlinks=False) and _INSTALL_RE.fullmatch(e.name)
                ]
        except FileNotFoundError:
            _read_usage(root)
            return 0
        for install in installs:
            with os.scandir(install.path) as files:
                expired = [
                    f.path
                    for f in files
                    if f.is_file(follow_symlinks=False)
                    and _FILE_RE.fullmatch(f.name)
                    and f.stat(follow_symlinks=False).st_mtime < cutoff
                ]
            for path in expired:
                os.unlink(path)
                removed += 1
            with os.scandir(install.path) as left:
                empty = next(left, None) is None
            if empty:
                os.rmdir(install.path)
        _read_usage(root)
    return removed


def _check_headers(install: str | None, app_version: str | None) -> tuple[str, str]:
    if install is None or _INSTALL_RE.fullmatch(install) is None:
        raise HTTPException(400, "Invalid X-Diag-Install header")
    if app_version is None or _APP_RE.fullmatch(app_version) is None:
        raise HTTPException(400, "Invalid X-Diag-App header")
    return install, app_version


async def _read_capped(request: Request) -> bytes:
    # A declared length above the cap is refused before anything is read. The
    # running count below is what holds when there is no Content-Length
    # (chunked) or when it understates the body.
    try:
        declared = int(request.headers.get("content-length", "0"))
    except ValueError:
        declared = 0
    if declared > MAX_BODY_BYTES:
        raise HTTPException(413, "Diagnostics upload too large")
    body = bytearray()
    async for chunk in request.stream():
        if len(body) + len(chunk) > MAX_BODY_BYTES:
            raise HTTPException(413, "Diagnostics upload too large")
        body.extend(chunk)
    return bytes(body)


def _check_gzip(body: bytes) -> None:
    """400 unless `body` is one to MAX_GZIP_MEMBERS complete gzip members and
    nothing else; 413 once the members inflate past MAX_INFLATED_BYTES, counted
    across all of them. Inflated bytes are counted and dropped, never kept."""
    inflated = 0
    rest = body
    for _ in range(MAX_GZIP_MEMBERS):
        # 16 + MAX_WBITS is gzip framing only: zlib refuses data that does not
        # start with the gzip magic (1f 8b), a zlib or raw deflate stream
        # included, and checks each member's CRC and length. Automatic
        # detection (32 + MAX_WBITS) would also take a zlib stream.
        member = zlib.decompressobj(16 + zlib.MAX_WBITS)
        pending = rest
        try:
            while not member.eof:
                out = member.decompress(pending, _INFLATE_STEP)
                inflated += len(out)
                if inflated > MAX_INFLATED_BYTES:
                    raise HTTPException(413, "Diagnostics upload inflates too large")
                if not out and len(member.unconsumed_tail) == len(pending):
                    break  # no output and no input taken: the data has run out
                pending = member.unconsumed_tail
        except zlib.error:
            raise HTTPException(400, "Body is not valid gzip")
        if not member.eof:
            raise HTTPException(400, "Truncated gzip")
        # What follows the end of a member can only be another member.
        rest = member.unused_data
        if not rest:
            return
    raise HTTPException(400, "Too many gzip members")


def _store(root: Path, install: str, app_version: str, body: bytes) -> None:
    global _usage_total
    with _store_lock:
        _private_dir(root)
        if _usage_total is None:
            _read_usage(root)
        cost = charge(len(body))
        mine = _usage_by_entry.get(install, 0)
        if _usage_total + cost > config.DIAG_MAX_TOTAL_BYTES:
            raise _QuotaExceeded("total")
        if mine + cost > config.DIAG_MAX_INSTALL_BYTES:
            raise _QuotaExceeded("per-install")
        install_dir = root / install
        _private_dir(install_dir)
        stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        name = f"{stamp}-{secrets.token_hex(4)}-{app_version}.log.gz"
        atomic_io.atomic_bytes_save(install_dir / name, body)
        _usage_by_entry[install] = mine + cost
        _usage_total += cost


def charge(size: int) -> int:
    """What a file of `size` bytes counts for against the ceilings: whole
    DISK_BLOCKs, one at least (an empty file still takes an inode)."""
    return max(1, -(-size // DISK_BLOCK)) * DISK_BLOCK


def _private_dir(path: Path) -> None:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    # mkdir's mode goes through the umask and does nothing to a directory that
    # already exists, so the mode is checked and set explicitly. If the relay
    # cannot set it (a directory it does not own), the upload fails with 503
    # rather than land in a directory others may read.
    if stat.S_IMODE(os.stat(path).st_mode) != 0o700:
        # The rule flags every chmod; this one narrows the mode to the owner.
        os.chmod(path, 0o700)  # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions


def _read_usage(root: Path) -> None:
    """Set _usage_total and _usage_by_entry from the disk. Caller holds
    _store_lock. Every regular file counts, in the directory and one level
    below it, leftover temporary files included: they take the same disk."""
    global _usage_total, _usage_by_entry
    by_entry: dict[str, int] = {}
    try:
        with os.scandir(root) as it:
            for entry in it:
                if entry.is_dir(follow_symlinks=False):
                    by_entry[entry.name] = _dir_charge(entry.path)
                elif entry.is_file(follow_symlinks=False):
                    by_entry[entry.name] = charge(entry.stat(follow_symlinks=False).st_size)
    except FileNotFoundError:
        pass
    _usage_by_entry = by_entry
    _usage_total = sum(by_entry.values())


def _dir_charge(path: str) -> int:
    with os.scandir(path) as it:
        return sum(
            charge(f.stat(follow_symlinks=False).st_size)
            for f in it
            if f.is_file(follow_symlinks=False)
        )
