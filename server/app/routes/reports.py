import json
import logging
import os
import tempfile
import threading
from pathlib import Path
from app import config, storage

logger = logging.getLogger("stream.reports")

# No router here any more. This module used to carry two Tella compat routes
# (`GET /p/{slug}` and `GET /{slug}`, both answering a constant project record
# behind a JWT); they had no caller anywhere in the tree and were removed
# 2026-09-03. What is left is the report registry itself, called in-process by
# upload authorization, the archive 404 gate, and report_cleanup.
# Report registry: a JSON file on disk, reloaded at import, saved on every
# mutation. A record is the minimal, identity-free binding the relay needs to
# authorize and serve a report:
#
#     report_id (32 hex, = SHA-256("stream.report.id.v1"||report_pk)[..16])
#       -> { "report_id": <hex>, "report_pk": <64 hex> }
#
# There is deliberately NO owner, NO author, NO createdAt, NO title, and adding
# one is how the motto breaks: "let users list their reports" wants an owner,
# "purge the old ones" wants a createdAt, and either one puts back at rest
# exactly what a seizure of the relay must not yield, which identity created what
# and when. report_pk is a per-report, seed-derived public key, unlinkable to the
# identity or to the other reports without the witness's secret master.
#
# The lock guards _reports plus the file write. The server runs --workers 1; the
# lock stays anyway.
_reports: dict[str, dict] = {}
_reports_lock = threading.Lock()


def _load_reports() -> dict[str, dict]:
    path = Path(config.REPORTS_DB_PATH)
    if not path.exists():
        return {}
    try:
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            logger.warning("reports DB at %s is not a dict, resetting", path)
            return {}
        return data
    except (json.JSONDecodeError, OSError) as e:
        logger.warning("Failed to load reports DB at %s: %s", path, e)
        return {}


def _save_reports_locked():
    """Atomic save: write to a temp file then rename onto the target. Records
    are plain dicts (no pydantic models to dump), so this is a straight
    json.dump."""
    path = Path(config.REPORTS_DB_PATH)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(
        dir=path.parent, prefix=path.name + ".", suffix=".tmp"
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(_reports, f, indent=2)
        os.replace(tmp_path, path)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


_reports.update(_load_reports())

def get_report(report_id: str) -> dict | None:
    """Accessor for other modules (upload authorization, archive 404 gate)."""
    return _reports.get(report_id)


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
    upstream.
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

    To be exact about what that buys (audit 2026-06-27, R-SRV-7): dropping
    createdAt removes a redundant copy of the "when", not the "when" itself,
    which still shows in the MinIO object's `last_modified` as it would in any
    object store.

    list_blobs() is a MinIO round-trip and runs outside the lock, which only
    guards the in-memory dict. The gap between listing and deleting is harmless,
    since a report purged six months ago won't start receiving chunks again, and
    the `rid in _reports` re-check covers a concurrent delete.
    """
    # (1) Snapshot candidate ids under the lock — no I/O here.
    with _reports_lock:
        candidate_ids = list(_reports.keys())
        remaining = len(_reports)
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

    # (3) Delete the confirmed-empty records under the lock + persist once.
    deleted = 0
    with _reports_lock:
        for rid in empty:
            if rid in _reports:
                del _reports[rid]
                deleted += 1
        if deleted:
            _save_reports_locked()
        remaining = len(_reports)
    if deleted:
        logger.info(
            "Blobless-report reap: deleted=%d, remaining=%d", deleted, remaining
        )
    return (deleted, remaining)
