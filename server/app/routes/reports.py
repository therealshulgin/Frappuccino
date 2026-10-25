import json
import logging
import os
import threading
from pathlib import Path
from app import config, paths, storage
from app.atomic_io import atomic_json_save

logger = logging.getLogger("stream.reports")

# No router here any more. This module used to carry two Tella compat routes
# (`GET /p/{slug}` and `GET /{slug}`, both answering a constant project record
# behind a JWT); they had no caller anywhere in the tree and were removed
# 2026-09-03. What is left is the report registry itself, called in-process by
# upload authorization, the closure route, the archive 404 gate, and
# report_cleanup.
# Report registry: a JSON file on disk, reloaded at import, saved on every
# mutation. A record is the minimal, identity-free binding the relay needs to
# authorize and serve a report:
#
#     report_id (32 hex, = SHA-256("stream.report.id.v1"||report_pk)[..16])
#       -> { "report_id": <hex>, "report_pk": <64 hex>,
#            "closure": { "seq_limit": <int>, "manifest_sha256": <64 hex>,
#                         "sig": <128 hex> },       # only once closed
#            "tombstone": true }                    # only once closed AND emptied
#
# There is deliberately NO owner, NO author, NO createdAt, NO title, and adding
# one is how the motto breaks: "let users list their reports" wants an owner,
# "purge the old ones" wants a createdAt, and either one puts back at rest
# exactly what a seizure of the relay must not yield, which identity created what
# and when. report_pk is a per-report, seed-derived public key, unlinkable to the
# identity or to the other reports without the witness's secret master. The
# closure adds no date either (the `manifest` object it points to has a
# `last_modified`, like every object, see `reap_blobless_reports`). It is the
# report key's signed end of the report: the manifest lists the chunks the
# report is made of (an empty manifest for a legacy report, whose closure only
# freezes it). Written once by `POST /close/{report_id}`, never changed after.
#
# A closed record is never deleted. Once every object of the report, `manifest`
# included, has been purged at the blob TTL, the reaper marks it a tombstone
# instead (`reap_blobless_reports`): a tombstone accepts no write at all (every
# PUT is refused with the closure's 409) and, since a record is never rewritten,
# a creating PUT cannot bring the report back open. The archive answers 404 for
# a tombstone with nothing left, as it would for an unknown report. The cost is
# one small record per closed report, kept for good; it holds the same identity-
# free, date-free fields as before, plus the flag.
#
# The lock guards _reports plus the file write. The server runs --workers 1; the
# lock stays anyway, and it is not only about workers: the creation and closure
# writes run in `asyncio.to_thread` workers, and the upload route holds the lock
# across its closure check and its store (see `registry_lock`).
_reports: dict[str, dict] = {}
_reports_lock = threading.Lock()


class ReportsRegistryUnreadable(RuntimeError):
    """`reports.json` exists but cannot be used. Raised at import, so the relay
    refuses to start instead of serving from an empty registry."""


class ReportUnknownError(Exception):
    """No record for this report_id (closure route → 425)."""


class ReportKeyMismatchError(Exception):
    """The presented report_pk is not the one bound to the record (→ 409)."""


class ClosureConflictError(Exception):
    """A different closure is already recorded for this report (→ 409)."""


def _load_reports() -> dict[str, dict]:
    """Load the registry, fail-closed.

    Only a missing file means "no reports yet". A file that cannot be read,
    does not parse, or is not a mapping of records makes the relay refuse to
    start. Starting empty instead looks like the resilient choice and is the
    worst one: every record would be forgotten, so the archive answers 404 for
    reports whose blobs are all still stored, and every closure would be
    forgotten too, so frozen reports accept new names again with nothing to
    show it. An operator restoring `reports.json` from a backup is the repair.
    """
    path = Path(config.REPORTS_DB_PATH)
    try:
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        return {}
    except (OSError, ValueError) as e:
        # ValueError covers json.JSONDecodeError and UnicodeDecodeError.
        raise ReportsRegistryUnreadable(
            f"reports DB at {path} is unreadable ({type(e).__name__}); "
            "refusing to start on an empty registry"
        ) from e
    if not isinstance(data, dict) or not all(isinstance(v, dict) for v in data.values()):
        raise ReportsRegistryUnreadable(
            f"reports DB at {path} is not a mapping of records; "
            "refusing to start on an empty registry"
        )
    return data


def _fsync_directory(directory: Path) -> None:
    """fsync a directory, so a rename inside it survives a power loss.

    `atomic_json_save` makes the new file's bytes durable, then renames it over
    the old one. The rename itself is a change to the directory, and until the
    directory is synced a crash can bring back the previous `reports.json`: the
    relay answered 204 to a closure (or a creation) that the disk no longer
    holds, and a report the witness believes frozen accepts new names again.

    This lives here rather than in `atomic_io`, which the nonce cache, the JWT
    blacklist and the ratchet registry share: a directory fsync there changes
    their write cost too, a separate decision. Windows has no directory handle
    that `os.fsync` accepts; the relay runs on Linux, and the step is skipped
    where the test suite runs on Windows.
    """
    if os.name != "posix":
        return
    fd = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _save_reports_locked():
    """Durable save of the whole registry: tmp file, fsync, rename
    (`atomic_json_save`), then fsync of the directory. Caller holds
    `_reports_lock`. Raises on any I/O error; the caller rolls its in-memory
    change back."""
    path = Path(config.REPORTS_DB_PATH)
    atomic_json_save(path, _reports, indent=2)
    _fsync_directory(path.parent)


_reports.update(_load_reports())

def get_report(report_id: str) -> dict | None:
    """Accessor for other modules (upload authorization, archive 404 gate)."""
    return _reports.get(report_id)


def registry_lock() -> threading.Lock:
    """The registry lock, for a caller that must keep the registry still across
    work of its own.

    The upload route holds it from its re-read of the record to the end of the
    object store, so a closure cannot be recorded in between. Nothing may hold
    it across an `await`, and nothing that holds it may wait on the event loop:
    the closure and creation writes take it from `asyncio.to_thread` workers,
    and the upload route takes it on the event loop itself.
    """
    return _reports_lock


def closed_seq_limit(record: dict | None) -> int | None:
    """The seq_limit of a record's closure, or None if the report is open.

    0 for a tombstone: a closed report whose objects have all expired accepts
    no new name at all, whatever its closure covered."""
    if record is None:
        return None
    closure = record.get("closure")
    if closure is None:
        return None
    if is_tombstone(record):
        return 0
    return int(closure["seq_limit"])


def is_tombstone(record: dict | None) -> bool:
    """Whether the record is a closed report whose objects have all been
    purged (see `reap_blobless_reports`)."""
    return record is not None and record.get("tombstone") is True


def closure_view(record: dict) -> dict | None:
    """The closure as the archive listing serves it: exactly
    `{seq_limit, manifest_sha256, sig}`, or None while the report is open."""
    closure = record.get("closure")
    if closure is None:
        return None
    return {
        "seq_limit": closure["seq_limit"],
        "manifest_sha256": closure["manifest_sha256"],
        "sig": closure["sig"],
    }


def create_or_verify_report(report_id: str, report_pk_hex: str) -> bool:
    """Record the `report_id -> report_pk` binding, lazily.

    Call this only for a creating chunk, and only once that chunk's blob is
    durably stored. Nothing here can check it, and inverting the order raises no
    error, but that ordering is what makes a record always imply at least one
    durable blob. The rescue's 404 on an unknown record and the absence of any
    createdAt both rely on it.

    Creation is idempotent and race-safe under the single lock. A record already
    present with a different pk is rejected and the caller answers 409, so the
    binding stays pinned even if a mismatched report_id slipped past the check
    upstream. A record already present is never rewritten, so a closure it
    carries survives every later creating PUT.

    Blocking (fsync): async callers go through `asyncio.to_thread`.
    """
    with _reports_lock:
        existing = _reports.get(report_id)
        if existing is not None:
            return existing.get("report_pk") == report_pk_hex
        _reports[report_id] = {"report_id": report_id, "report_pk": report_pk_hex}
        try:
            _save_reports_locked()
        except Exception:
            # Roll back the insert: memory must never claim a record the disk
            # doesn't hold. The ratchet registry deliberately does the opposite,
            # tolerating a brief divergence and rewriting itself on the next
            # mutation, so harmonising the two is a tempting refactor that would
            # quietly break this one. Here the rescue's 404 on an unknown record
            # assumes record and disk agree. The blob is already durable, so
            # dropping the record only costs the client a retry.
            del _reports[report_id]
            raise
    return True


def close_report(
    report_id: str,
    report_pk_hex: str,
    seq_limit: int,
    manifest_sha256_hex: str,
    close_sig_hex: str,
    manifest_stream,
    manifest_length: int,
) -> str:
    """Record a verified closure: store its manifest, then mark the record.

    The caller has already checked the 0x09 signature over
    `report_id || u32_be(seq_limit) || manifest_sha256`. Everything here runs
    under the registry lock, from the closure lookup to the durable save, and
    the upload route reads closures under the same lock, so no new object can
    land between "closure recorded" and the next PUT's check.

    Returns "recorded", or "identical" when the same `(seq_limit,
    manifest_sha256)` is already recorded (a retry whose response was lost).
    Raises ReportUnknownError, ReportKeyMismatchError, ClosureConflictError
    (another closure is recorded: a closure is never replaced), and whatever
    the store raises (WriteOnceConflictError if a different `manifest` object
    is already stored, StorageFullError) or the save raises (OSError).

    The manifest goes to the write-once object `manifest` BEFORE the record
    says "closed", the same blob-first order as report creation: a closure the
    registry shows always has its manifest stored. If the save then fails, the
    in-memory record is put back as it was and the manifest stays; the
    client's retry finds it identical and records the closure again.

    Blocking (MinIO + fsync): async callers go through `asyncio.to_thread`.
    """
    closure = {
        "seq_limit": seq_limit,
        "manifest_sha256": manifest_sha256_hex,
        "sig": close_sig_hex,
    }
    with _reports_lock:
        record = _reports.get(report_id)
        if record is None:
            raise ReportUnknownError(report_id)
        if record.get("report_pk") != report_pk_hex:
            raise ReportKeyMismatchError(report_id)
        existing = record.get("closure")
        if existing is not None:
            if (
                existing.get("seq_limit") == seq_limit
                and existing.get("manifest_sha256") == manifest_sha256_hex
            ):
                return "identical"
            raise ClosureConflictError(report_id)
        storage.upload_blob_stream_write_once(
            report_id,
            paths.MANIFEST_NAME,
            manifest_stream,
            manifest_length,
            manifest_sha256_hex,
        )
        _reports[report_id] = {**record, "closure": closure}
        try:
            _save_reports_locked()
        except Exception:
            # Same rule as creation: memory never claims a closure the disk
            # does not hold. Concurrent lock-free readers (`get_report`) see
            # either the old record or the new one, never a half-built one.
            _reports[report_id] = record
            raise
    return "recorded"


def _reset_for_test():
    """Test-only: wipe the in-memory + on-disk state."""
    with _reports_lock:
        _reports.clear()
        path = Path(config.REPORTS_DB_PATH)
        try:
            path.unlink()
        except FileNotFoundError:
            pass


def reap_blobless_reports() -> tuple[int, int]:
    """Reap report records left with zero blobs. Returns (deleted, remaining).

    The point of this collector is that it needs no per-record timestamp. A
    record only reaches zero blobs once blob_cleanup has purged them all at the
    long retention TTL (BLOB_TTL_SECONDS, 6 months), so "no blobs left" already
    means "fully purged, safe to reap". Any other design asks for a createdAt to
    delete records older than X, which is the per-identity date at rest this
    module refuses to keep.

    Only open records are deleted. A closed one with zero blobs (its `manifest`
    purged too) becomes a tombstone and stays: deleting it would forget the
    closure, and a creating PUT would then rebuild the report open, accepting
    the names the closure refused. A tombstone counts in `remaining`.

    To be exact about what that buys (audit 2026-06-27, R-SRV-7): dropping
    createdAt removes a redundant copy of the "when", not the "when" itself,
    which still shows in the MinIO object's `last_modified` as it would in any
    object store.

    list_blobs() is a MinIO round-trip and runs outside the lock, which only
    guards the in-memory dict. A record is acted on only if its closure is
    unchanged between the snapshot (1) and the decision (3): a closure recorded
    in between (`close_report` stores its manifest, so the report is no longer
    empty) leaves the record alone until the next pass, and so does a concurrent
    delete.
    """
    # (1) Snapshot candidate ids and their closure under the lock — no I/O here.
    with _reports_lock:
        snapshot = {
            rid: record.get("closure") for rid, record in _reports.items()
            if not is_tombstone(record)
        }
        remaining = len(_reports)
    candidate_ids = list(snapshot)
    if not candidate_ids:
        return (0, remaining)

    # (2) Check blob counts WITHOUT the lock — list_blobs() hits MinIO and must
    #     not block upload auth on the single worker.
    empty: list[str] = []
    for rid in candidate_ids:
        try:
            if len(storage.list_blobs(rid)) == 0:
                empty.append(rid)
        except Exception:
            logger.exception("reap: list_blobs failed for %s, keeping it", rid)
    if not empty:
        return (0, remaining)

    # (3) Under the lock, persist once: delete the confirmed-empty open records,
    #     mark the confirmed-empty closed ones as tombstones.
    deleted = 0
    tombstoned = 0
    with _reports_lock:
        before = {rid: _reports[rid] for rid in empty if rid in _reports}
        for rid, record in before.items():
            if record.get("closure") != snapshot[rid]:
                continue  # closed since the snapshot: no longer empty
            if record.get("closure") is None:
                del _reports[rid]
                deleted += 1
            else:
                _reports[rid] = {**record, "tombstone": True}
                tombstoned += 1
        if deleted or tombstoned:
            try:
                _save_reports_locked()
            except Exception:
                # Memory never claims a state the disk does not hold.
                _reports.update(before)
                raise
        remaining = len(_reports)
    if deleted or tombstoned:
        logger.info(
            "Blobless-report reap: deleted=%d, tombstoned=%d, remaining=%d",
            deleted, tombstoned, remaining,
        )
    return (deleted, remaining)
