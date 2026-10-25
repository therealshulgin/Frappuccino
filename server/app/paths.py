"""Shared path / object-name validators for the relay's blob storage.

The stored MinIO object key MUST be byte-identical to the filename covered by the
client's write signature (domain 0x08) — the relay never rewrites it. So a
filename is validated STRICT at every entry point (upload, archive) from this
single source of truth, rather than "sanitized": a silent rewrite (the old
``filename.replace("..", "")``) would desync the stored key from the signed name
and could collide two distinct names onto one key (unexpected write-once 409, or
a blob the archive can't find under its signed name).

Real names are chunk ids: ``<sid>_NNNNNN.strm`` (~44 chars) for legacy reports,
``NNNNNN.strm`` for chain reports; or an opaque 32-hex directory-index (M-1) or
OpenTimestamps entry (the relay stores and signs over the bytes, never parses
them); plus the reserved ``manifest`` that ``POST /close`` writes. Never ``.`` /
``..``. The ``{1,128}`` bound is ~3x the longest legitimate name and refuses a
kilo/mega-byte name before it becomes a MinIO key or is hashed into a signed
message.

Every pattern here is applied with ``re.fullmatch``, never ``re.match`` with a
``^...$`` pattern: ``$`` also matches just before a trailing newline, so
``match`` accepted ``<32 hex>\\n`` as a report_id and ``<name>\\n`` as a
filename. A path parameter can carry that newline (``%0A`` in the URL), and
``bytes.fromhex`` skips it, so the signatures still covered the canonical 16-byte
id while the object key and the registry entry were built from the string with
the newline.

The two former copies of the filename regex (``upload.py`` + ``archive.py``) are
consolidated here so they cannot drift ("editing one entry != auditing the list").
"""

import re

from fastapi import HTTPException

# report_id = 128-bit capability rendered as exactly 32 lowercase hex chars
# (hex-decodable to the 16 bytes the create/write signatures cover).
REPORT_ID_RE = re.compile(r"[a-f0-9]{32}")

# Blob filename: strict charset + bounded length. `..` (anywhere) and a lone `.`
# are rejected separately below — the charset alone admits both, and they resolve
# to parent / this-dir when a rescue consumer joins them onto an output sink.
FILENAME_RE = re.compile(r"[a-zA-Z0-9._-]{1,128}")

# Object name under which `POST /close/{report_id}` stores the closure manifest.
# Reserved: a PUT to this name is refused, so the only `manifest` a report can
# hold is the one whose hash its signed closure covers.
MANIFEST_NAME = "manifest"

# Names a report may still receive as NEW objects once its closure is recorded:
# chain-report chunks `NNNNNN.strm` whose sequence number is below the closure's
# seq_limit. Legacy names never match, so a legacy closure (seq_limit 0) admits
# no new object at all.
CLOSED_REPORT_NAME_RE = re.compile(r"[0-9]{6}\.strm")

# seq is at most 999_999 (six digits), so a closure's seq_limit is at most
# 1_000_000.
MAX_SEQ_LIMIT = 1_000_000


def validate_report_id(report_id: str) -> None:
    """Raise 400 unless ``report_id`` is exactly 32 lowercase hex chars."""
    if REPORT_ID_RE.fullmatch(report_id) is None:
        raise HTTPException(400, "Invalid report_id")


def validate_filename(filename: str) -> None:
    """Raise 400 unless ``filename`` is a safe, bounded object name.

    Rejects: wrong charset, length outside 1..128, a lone ``.``, or ``..``
    anywhere (traversal / silent-rewrite guard).
    """
    if FILENAME_RE.fullmatch(filename) is None or filename == "." or ".." in filename:
        raise HTTPException(400, "Invalid filename")


def name_allowed_after_close(filename: str, seq_limit: int) -> bool:
    """Whether a closed report may still receive a NEW object named ``filename``.

    True only for ``NNNNNN.strm`` with ``NNNNNN < seq_limit``: a chunk the
    closure's manifest can cover, whose upload simply reached the relay after
    the closure did (the client's queue does not order uploads). This says
    nothing about objects that already exist; those keep write-once semantics
    whatever the closure says.
    """
    if CLOSED_REPORT_NAME_RE.fullmatch(filename) is None:
        return False
    return int(filename[:6]) < seq_limit
