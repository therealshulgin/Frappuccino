#!/usr/bin/env bash
# Phase 1.x-prep (2026-05-19) — full server-state backup for migration
# and disaster recovery.
#
# Backs up the TWO named Docker volumes the relay relies on :
#
#   1. `server_state`  — auth metadata (ratchet_registry.json,
#                        nonce_cache.json, reports.json). Without this, every
#                        previously enrolled Android client becomes un-authable
#                        and silently retries forever.
#
#   2. `minio_data`    — the actual encrypted STRM blobs. Without this,
#                        the archive retrieval flow (Phase 4.4) returns
#                        empty for every report.
#
# Both volumes live at `/var/lib/docker/volumes/<name>/_data/` on the
# host. We don't tar them directly from the host because dockerd may
# hold open file handles ; instead we spin up a transient alpine
# container that mounts the volumes read-only and streams the tarball
# to stdout (or a target path).
#
# Why this script exists : the previous README migration runbook said
# `tar /opt/frappuccino/state` which is a path the bootstrap *creates*
# but docker-compose *never uses* (we use named volumes, not bind
# mounts) — and it didn't mention minio_data at all. A migration
# following that runbook would silently lose every uploaded stream.
#
# Usage :
#   ./backup-state.sh                                # → /opt/frappuccino/backups/frappuccino-state-<ts>.tar.gz
#   ./backup-state.sh /path/to/output.tar.gz         # explicit output
#   ./backup-state.sh -                              # streams to stdout (for `ssh A | ssh B`)
#   FRAPPUCCINO_BACKUP_DIR=/elsewhere ./backup-state.sh  # override default dir
#
# Exit codes :
#   0 — backup OK, tarball written, sha256 logged to stderr
#   1 — generic failure (docker not running, volume missing, disk full)
#   2 — bad CLI args
#
# Determinism : the tarball is NOT reproducible byte-exact (alpine
# tar uses ctime + variable Docker UID mapping). Don't rely on the
# sha256 across two runs of the same state — it's a content
# integrity check for THIS dump only, useful to verify the
# rsync/scp leg of a migration didn't corrupt bits in flight.
#
# Disk footprint : `minio_data` grows with usage. On a relay with
# a long-running journalist (1 GB / hour of HD video chunks), a
# 30-day archive can hit 700 GB. Keep the backup target on a
# different physical disk or off-host (rsync.net / Backblaze B2 /
# Greenhost storage).

set -euo pipefail

DEPLOY_DIR="${FRAPPUCCINO_DEPLOY_DIR:-/opt/frappuccino}"
BACKUP_DIR="${FRAPPUCCINO_BACKUP_DIR:-${DEPLOY_DIR}/backups}"
TIMESTAMP=$(date -u +"%Y%m%dT%H%M%SZ")

log() { echo "[backup-state] $*" >&2; }
die() { log "FATAL: $*"; exit 1; }

# Sanity : docker must be runnable.
command -v docker >/dev/null 2>&1 || die "docker not in PATH"
docker info >/dev/null 2>&1 || die "docker daemon not reachable (try: sudo systemctl start docker)"

# Resolve volume names. Docker Compose prefixes named volumes with
# the project name (= the directory `docker compose` runs from, by
# default). The Vultr deploy at /opt/frappuccino/ → project name
# `frappuccino` → actual volumes are `frappuccino_server_state` +
# `frappuccino_minio_data`. Detection strategy :
#   1. Use explicit FRAPPUCCINO_VOLUME_PREFIX if set (e.g. when the
#      project name differs from the default).
#   2. Else COMPOSE_PROJECT_NAME env var (Docker's own convention).
#   3. Else auto-detect : find a unique volume matching `*_server_state`.
#      If multiple match (e.g. multiple compose projects on the same
#      host) we bail rather than guess.
#   4. Fallback : raw `server_state` / `minio_data` (in case someone
#      configured `name:` explicitly in docker-compose.yml).
resolve_volume() {
    local suffix="$1"
    if [[ -n "${FRAPPUCCINO_VOLUME_PREFIX:-}" ]]; then
        echo "${FRAPPUCCINO_VOLUME_PREFIX}_${suffix}"
        return
    fi
    if [[ -n "${COMPOSE_PROJECT_NAME:-}" ]]; then
        echo "${COMPOSE_PROJECT_NAME}_${suffix}"
        return
    fi
    # Auto-detect.
    local matches
    matches=$(docker volume ls --format '{{.Name}}' | grep -E "_${suffix}$" || true)
    local count
    count=$(echo "$matches" | grep -c . || true)
    if [[ "$count" == "1" ]]; then
        echo "$matches"
    elif [[ "$count" -gt "1" ]]; then
        log "Multiple volumes match *_${suffix} on this host :"
        echo "$matches" | while read -r v; do log "  - $v"; done
        die "Set FRAPPUCCINO_VOLUME_PREFIX=<project> to disambiguate."
    elif docker volume inspect "$suffix" >/dev/null 2>&1; then
        # No-prefix variant (rare — only if docker-compose.yml uses
        # `name: $suffix` explicitly).
        echo "$suffix"
    else
        die "No volume matching *_${suffix} found. Has 'docker compose up -d' ever run?"
    fi
}

VOL_STATE=$(resolve_volume server_state)
VOL_MINIO=$(resolve_volume minio_data)
log "Resolved volumes: state=${VOL_STATE} minio=${VOL_MINIO}"

# WP-A3 (audit 2026-06-28) — at-rest encryption
# is MANDATORY.
#
# The tarball contains the relay's state dossier: reports.json (Phase C
# relay-blind: `report_id -> report_pk` only — no owner / createdAt / title),
# ratchet_registry.json, nonce_cache.json + all blobs.
# The blobs are STRM-E2E-encrypted and reports.json no longer maps an identity
# to its reports, but ratchet_registry.json still holds the SET of enrolled
# identity pks (the assumed residual, §6) — a plaintext tar
# on disk (or pushed off-host, 1.8) would be one `cp` from the enrollment
# registry on seizure. So we NEVER write the dossier in clear.
#
# FRAPPUCCINO_BACKUP_AGE_RECIPIENT (an age recipient `age1…`, whose IDENTITY /
# private key is kept OFF the relay) is REQUIRED. If it is unset, or `age` is
# not installed, we fail loud rather than emit a plaintext dossier. There is
# deliberately NO plaintext escape hatch (motto: a seizure of the relay disk
# must expose nothing actionable, enrolled identities included). The off-host
# push (1.8) inherits this guarantee for free.
AGE_RECIPIENT="${FRAPPUCCINO_BACKUP_AGE_RECIPIENT:-}"
[[ -n "$AGE_RECIPIENT" ]] \
    || die "FRAPPUCCINO_BACKUP_AGE_RECIPIENT is required (age recipient, e.g. age1…). Refusing to write a plaintext state dossier (WP-A3)."
command -v age >/dev/null 2>&1 \
    || die "FRAPPUCCINO_BACKUP_AGE_RECIPIENT set but 'age' not in PATH (apt install age)"
log "At-rest encryption: ON (mandatory; age recipient ${AGE_RECIPIENT:0:16}…)"

# Emit the tar.gz of both volumes to stdout (canonical Docker pattern).
stream_backup() {
    docker run --rm \
        --log-driver=none \
        -v "${VOL_STATE}":/src/state:ro \
        -v "${VOL_MINIO}":/src/minio:ro \
        alpine:3 \
        tar -czf - -C /src state minio
}

# Always age-encrypt the stream (recipient validated above).
encrypt_stream() {
    age -r "$AGE_RECIPIENT"
}

# Resolve output target.
case "${1:-}" in
    "")
        mkdir -p "$BACKUP_DIR"
        OUT="$BACKUP_DIR/frappuccino-state-${TIMESTAMP}.tar.gz.age"
        ;;
    -)
        OUT=-
        ;;
    -h|--help)
        sed -n '1,40p' "$0" | sed 's/^# \?//'
        exit 0
        ;;
    *)
        OUT="$1"
        mkdir -p "$(dirname "$OUT")"
        ;;
esac

log "Backup target: ${OUT}"
log "Volumes: server_state + minio_data"

# Why alpine + tar in a transient container :
#   - The tar binary on the host doesn't know about Docker's overlay
#     storage layout. Running tar inside a container that mounts the
#     volumes is the canonical (Docker-documented) way.
#   - --read-only on the bind mount ensures we never accidentally
#     mutate the volume during backup.
#   - We pipe through gzip on the host side to avoid bloating the
#     alpine image with gzip choice (it has it, but staying explicit).
#   - The internal layout `state/` + `minio/` becomes the restore
#     contract. restore-state.sh expects exactly these two directories
#     at the tarball root.
#
# Exit-code chaining : `set -o pipefail` propagates failure from
# any pipeline member. If alpine's tar fails (e.g. permission), gzip
# still runs but produces a truncated file ; the trailing
# `gzip -t` check below catches that.

TMP_TARBALL=""
cleanup() {
    if [[ -n "${TMP_TARBALL:-}" && -e "${TMP_TARBALL}" ]]; then
        rm -f "${TMP_TARBALL}"
    fi
}
trap cleanup EXIT

if [[ "$OUT" == "-" ]]; then
    # Streaming mode — no integrity check possible at end (caller's
    # job). Most useful for `ssh A backup-state.sh - | ssh B restore-state.sh -`.
    log "Streaming to stdout (no post-write integrity check)"
    stream_backup | encrypt_stream
else
    # Write to a tmp file in the same dir first, then atomic rename
    # to OUT. This way a Ctrl-C mid-backup doesn't leave a corrupted
    # half-tarball at the canonical name (which a restore script
    # might later pick up and silently corrupt the destination).
    TMP_TARBALL="${OUT}.tmp.$$"
    log "Streaming volumes through alpine tar + age..."
    stream_backup | encrypt_stream > "$TMP_TARBALL"

    # Can't gzip -t an age file (and we don't hold the identity to
    # decrypt-test). Verify the age header is present + file non-empty.
    log "Verifying age header..."
    head -c 22 "$TMP_TARBALL" | grep -q "age-encryption.org" \
        || die "age header missing — encryption failed on $TMP_TARBALL"

    # Atomic rename — POSIX guarantee on same filesystem.
    mv "$TMP_TARBALL" "$OUT"
    TMP_TARBALL=""  # clear so cleanup trap doesn't re-delete

    SIZE=$(du -h "$OUT" | awk '{print $1}')
    SHA=$(sha256sum "$OUT" | awk '{print $1}')
    log "OK: ${OUT} (${SIZE}, sha256=${SHA})"

    # Append to a simple manifest so the operator can scan
    # "what backups do I have, when, how big" without ls-ing.
    MANIFEST="${BACKUP_DIR}/manifest.txt"
    {
        printf "%s  %s  %s  %s\n" \
            "$TIMESTAMP" "$(basename "$OUT")" "$SIZE" "$SHA"
    } >> "$MANIFEST"
    log "Manifest updated: ${MANIFEST}"
fi
