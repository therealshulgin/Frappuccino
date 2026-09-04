#!/usr/bin/env bash
# Server-side reports vs blobs audit.
# Phase C relay-blind (2026-06-26) — re-framed: reports.json no longer
# carries owner / createdAt / title, only `report_id -> report_pk`. The
# audit now checks the relay-blind INVARIANT instead of age-based health.
#
# Cross-references `/state/reports.json` (the report_id -> report_pk index)
# with the actual `/data/stream-blobs/<report_id>/` directories that MinIO
# holds. Produces a health snapshot of the pipeline :
#
#   - has_content        : report_id in reports.json AND >= 1 blob in MinIO
#                          — a normal, populated report.
#   - blobless_records   : report_id in reports.json but 0 blobs in MinIO.
#                          VIOLATES the Phase C blob-first invariant (a
#                          record is written ONLY after >= 1 durable blob,
#                          reports.py create_or_verify_report), so this
#                          MUST be ~0. A non-zero count is a real bug
#                          (a record written without a durable blob) — not
#                          a benign "user tapped REC + close" any more.
#   - orphan_minio       : blobs in MinIO with NO matching report_id record
#                          — the EXPECTED residual (a crash between
#                          store-blob and write-record leaves a blob with
#                          no record, §6; reaped by blob_cleanup on
#                          last_modified TTL). Informational, not alarming.
#
# Integrity ratio = has_content / total_records, target ~100 % (blob-first
# makes "record without blobs" an invariant violation, not a normal state).
#
# No createdAt / title / age is read any more — those fields were removed
# so a seizure of reports.json reveals no `identity -> report -> when` map.
# The audit only cross-references opaque report_ids, so its output is
# itself relay-blind-safe.
#
# Run via cron or systemd timer, or on-demand: `bash audit-reports-vs-blobs.sh`.
#
# Usage :
#   ./audit-reports-vs-blobs.sh                 # human-readable summary
#   ./audit-reports-vs-blobs.sh --json          # machine-readable JSON
#   ./audit-reports-vs-blobs.sh --csv >> audit.csv  # append to historical
#
# Implementation note : we extract data from the containers via
# `docker exec ... > file`, then analyse in Python on the host. The
# previous "heredoc into docker exec python3 -" approach hung when run
# over an SSH-piped session (stdin handling quirks) — host-side
# analysis sidesteps that entirely and keeps the script debuggable
# (the intermediate files survive in /tmp for inspection on failure).
#
# Exit codes :
#   0 — audit ran OK (regardless of zombie count)
#   1 — couldn't reach docker / containers not running
#   2 — bad CLI args

set -euo pipefail

MODE="human"
while [[ $# -gt 0 ]]; do
    case "$1" in
        --json) MODE="json"; shift ;;
        --csv) MODE="csv"; shift ;;
        -h|--help) sed -n '1,40p' "$0" | sed 's/^# \?//' ; exit 0 ;;
        *) echo "Unknown arg: $1" >&2; exit 2 ;;
    esac
done

SERVER_CTR="${FRAPPUCCINO_SERVER_CTR:-frappuccino-server-1}"
MINIO_CTR="${FRAPPUCCINO_MINIO_CTR:-frappuccino-minio-1}"

if ! docker ps --format '{{.Names}}' | grep -q "^${SERVER_CTR}$"; then
    echo "ERROR: container ${SERVER_CTR} not running" >&2
    exit 1
fi
if ! docker ps --format '{{.Names}}' | grep -q "^${MINIO_CTR}$"; then
    echo "ERROR: container ${MINIO_CTR} not running" >&2
    exit 1
fi

# Extract data into host /tmp files. The /tmp on a Vultr-class VM is
# host tmpfs (not the container's) so this writes to RAM and is gone
# at reboot. The files are tiny (KB scale) regardless of report count.
TMP=$(mktemp -d /tmp/frappuccino-audit.XXXXXX)
trap 'rm -rf "$TMP"' EXIT

docker exec "${MINIO_CTR}" sh -c '
    for d in /data/stream-blobs/*/ ; do
        [ -d "$d" ] || continue
        rid=$(basename "$d")
        # Skip MinIO internal markers (.minio.sys, .bloomcycle, etc.)
        case "$rid" in .*) continue ;; esac
        n=$(ls "$d" 2>/dev/null | wc -l)
        bytes=$(du -sb "$d" 2>/dev/null | cut -f1)
        echo "$rid|$n|$bytes"
    done
' > "$TMP/minio.txt"

docker exec "${SERVER_CTR}" cat /state/reports.json > "$TMP/reports.json"

# Host-side Python does the analysis. Tries `python3` first, falls
# back to `python` if a minimal Ubuntu image is missing the `python3`
# alias (Ubuntu 24.04 ships it by default but some custom images skip).
PYTHON_BIN=""
for cand in python3 python; do
    if command -v "$cand" >/dev/null 2>&1; then
        PYTHON_BIN="$cand"
        break
    fi
done
if [[ -z "$PYTHON_BIN" ]]; then
    echo "ERROR: python3 not in PATH on host" >&2
    exit 1
fi

MODE="$MODE" MINIO_FILE="$TMP/minio.txt" REPORTS_FILE="$TMP/reports.json" \
    "$PYTHON_BIN" <<'PYEOF'
import json
import os
from datetime import datetime, timezone

mode = os.environ.get("MODE", "human")
minio_file = os.environ["MINIO_FILE"]
reports_file = os.environ["REPORTS_FILE"]

# Parse MinIO listing ("rid|n|bytes").
minio = {}
with open(minio_file) as f:
    for line in f:
        line = line.strip()
        if not line or "|" not in line:
            continue
        parts = line.split("|")
        if len(parts) >= 3:
            rid = parts[0]
            try:
                n = int(parts[1])
                b = int(parts[2])
            except ValueError:
                continue
            minio[rid] = (n, b)

# Load reports.json. Phase C relay-blind schema:
#   { report_id : { "report_id": <hex>, "report_pk": <64 hex> } }
# No owner, no createdAt, no title -- a seizure reveals no identity->report
# ->when map, only opaque report_id->report_pk bindings.
try:
    with open(reports_file) as f:
        reports = json.load(f)
except (FileNotFoundError, json.JSONDecodeError):
    reports = {}

# Run timestamp (the audit's own clock, NOT report metadata -- non-sensitive).
now = datetime.now(timezone.utc)

has_content = []        # record + >=1 blob (normal)
blobless_records = []   # record + 0 blobs -- VIOLATES the blob-first invariant
for rid in reports:
    blob_count, _ = minio.get(rid, (0, 0))
    if blob_count > 0:
        has_content.append((rid, *minio[rid]))
    else:
        blobless_records.append(rid)

orphan_minio = []       # blobs without a record -- expected residual (a crash
                        # between store-blob and write-record; blob_cleanup TTL).
for rid, (n, b) in minio.items():
    if rid not in reports:
        orphan_minio.append((rid, n, b))

total_blobs = sum(n for n, _ in minio.values())
total_bytes = sum(b for _, b in minio.values())
integrity = 100.0 * len(has_content) / max(len(reports), 1)

if mode == "json":
    out = {
        "timestamp": now.isoformat(),
        "reports_total": len(reports),
        "minio_dirs_total": len(minio),
        "categories": {
            "has_content": len(has_content),
            "blobless_records": len(blobless_records),
            "orphan_minio": len(orphan_minio),
        },
        "blobs_total": total_blobs,
        "bytes_total": total_bytes,
        "integrity_pct": round(integrity, 1),
    }
    print(json.dumps(out, indent=2))
elif mode == "csv":
    # Columns (Phase C): ts, records, minio_dirs, has_content,
    # blobless_records, orphan_minio, blobs, bytes.
    print(",".join([
        now.isoformat(),
        str(len(reports)),
        str(len(minio)),
        str(len(has_content)),
        str(len(blobless_records)),
        str(len(orphan_minio)),
        str(total_blobs),
        str(total_bytes),
    ]))
else:
    print(f"=== Frappuccino reports/blobs audit (relay-blind) @ {now.isoformat()} ===")
    print()
    print(f"  reports.json records  : {len(reports)}")
    print(f"  MinIO report dirs     : {len(minio)}")
    print(f"  Total blobs in MinIO  : {total_blobs}")
    print(f"  Total bytes in MinIO  : {total_bytes:,} ({total_bytes / 1024 / 1024:.1f} MB)")
    print()
    print(f"  Categories :")
    print(f"    has_content       : {len(has_content)}")
    print(f"    blobless_records  : {len(blobless_records)}  (invariant: MUST be 0)")
    print(f"    orphan_minio      : {len(orphan_minio)}  (expected residual)")
    print(f"  Integrity ratio     : {integrity:.1f} % (target ~100 %, blob-first)")
    print()
    if has_content:
        print(f"  Top reports by blob count :")
        for rid, n, b in sorted(has_content, key=lambda x: -x[1])[:10]:
            print(f"    {rid[:8]}  {n:>5} blobs  {b // 1024 // 1024:>5} MB")
        print()
    if blobless_records:
        print(f"  !! BLOBLESS RECORDS (blob-first invariant violation, top 10) :")
        for rid in blobless_records[:10]:
            print(f"    {rid[:8]}  0 blobs")
        print()
    if orphan_minio:
        print(f"  Orphan MinIO dirs (blob without record, expected residual, top 10) :")
        for rid, n, b in orphan_minio[:10]:
            print(f"    {rid[:8]}  {n} blobs  {b // 1024} KB")
        print()
PYEOF
