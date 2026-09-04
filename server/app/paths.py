"""Shared path / object-name validators for the relay's blob storage.

The stored MinIO object key MUST be byte-identical to the filename covered by the
client's write signature (domain 0x08) — the relay never rewrites it. So a
filename is validated STRICT at every entry point (upload, archive) from this
single source of truth, rather than "sanitized": a silent rewrite (the old
``filename.replace("..", "")``) would desync the stored key from the signed name
and could collide two distinct names onto one key (unexpected write-once 409, or
a blob the archive can't find under its signed name).

Real names are chunk ids ``<sid>_NNNNNN.strm`` (~44 chars) or an opaque 32-hex
directory-index entry (M-1, the relay stores + signs over the bytes, never parses
them) — never ``.`` / ``..``. The ``{1,128}`` bound is ~3x the longest legitimate
name and refuses a kilo/mega-byte name before it becomes a MinIO key or is hashed
into a signed message.

The two former copies of the filename regex (``upload.py`` + ``archive.py``) are
consolidated here so they cannot drift ("editing one entry != auditing the list").
"""

import re

from fastapi import HTTPException

# report_id = 128-bit capability rendered as exactly 32 lowercase hex chars
# (hex-decodable to the 16 bytes the create/write signatures cover).
REPORT_ID_RE = re.compile(r"^[a-f0-9]{32}$")

# Blob filename: strict charset + bounded length. `..` (anywhere) and a lone `.`
# are rejected separately below — the charset alone admits both, and they resolve
# to parent / this-dir when a rescue consumer joins them onto an output sink.
FILENAME_RE = re.compile(r"^[a-zA-Z0-9._-]{1,128}$")


def validate_report_id(report_id: str) -> None:
    """Raise 400 unless ``report_id`` is exactly 32 lowercase hex chars."""
    if not REPORT_ID_RE.match(report_id):
        raise HTTPException(400, "Invalid report_id")


def validate_filename(filename: str) -> None:
    """Raise 400 unless ``filename`` is a safe, bounded object name.

    Rejects: wrong charset, length outside 1..128, a lone ``.``, or ``..``
    anywhere (traversal / silent-rewrite guard).
    """
    if not FILENAME_RE.match(filename) or filename == "." or ".." in filename:
        raise HTTPException(400, "Invalid filename")
