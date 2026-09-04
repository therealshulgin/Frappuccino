#!/usr/bin/env bash
# Phase 1.x-prep (2026-05-19) — companion to backup-state.sh.
#
# Restores a tarball produced by backup-state.sh into the two named
# Docker volumes (server_state + minio_data) on a target host. Designed
# for the migration use-case : new VPS, fresh bootstrap.sh, no live
# data yet, restore from the old VPS's last backup.
#
# Usage :
#   ./restore-state.sh /path/to/frappuccino-state-<ts>.tar.gz
#   ./restore-state.sh -                                          # read from stdin
#   ./restore-state.sh --force /path/to/backup.tar.gz             # skip empty-check
#
# Safety rails :
#   1. By default, refuses to run if either volume already contains
#      data — protection against overwriting a live deploy by accident.
#      Use --force to bypass (e.g. you've manually wiped first).
#   2. Stops the docker-compose stack before restore (so the FastAPI
#      server doesn't observe a half-restored state) and restarts it
#      after. Will skip the stop/start if docker-compose.yml isn't in
#      the expected location (operator should stop manually then).
#   3. The tarball is extracted via the same alpine + tar pattern as
#      the backup (consistent layout, no host-tar gotchas).
#
# Exit codes :
#   0 — restore OK
#   1 — generic failure
#   2 — bad CLI args
#   3 — destination volume not empty (use --force or wipe manually)

set -euo pipefail

DEPLOY_DIR="${FRAPPUCCINO_DEPLOY_DIR:-/opt/frappuccino}"
FORCE=0
SOURCE=""

log() { echo "[restore-state] $*" >&2; }
die() { log "FATAL: $*"; exit 1; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --force) FORCE=1; shift ;;
        -h|--help) sed -n '1,30p' "$0" | sed 's/^# \?//' ; exit 0 ;;
        -*) log "Unknown flag: $1" ; exit 2 ;;
        *) SOURCE="$1"; shift ;;
    esac
done

[[ -n "$SOURCE" ]] || { log "Usage: $0 [--force] <tarball|->" ; exit 2 ; }

command -v docker >/dev/null 2>&1 || die "docker not in PATH"
docker info >/dev/null 2>&1 || die "docker daemon not reachable"

# Optional at-rest decryption, symmetric to
# backup-state.sh's age encryption. Set FRAPPUCCINO_BACKUP_AGE_IDENTITY to
# the age identity (private key) file — kept OFF the relay, brought in only
# for a restore. Input is treated as encrypted if the identity is set OR the
# source filename ends in `.age` (so a `.age` file without an identity fails
# loud rather than feeding tar an age blob).
AGE_IDENTITY="${FRAPPUCCINO_BACKUP_AGE_IDENTITY:-}"
DECRYPT=0
maybe_decrypt() { cat; }  # default: pass-through (plaintext)

# Resolve volume names. Same auto-detection logic as backup-state.sh
# (see that file for full rationale). The Vultr deploy at
# /opt/frappuccino/ uses project name `frappuccino` so volumes
# become `frappuccino_server_state` + `frappuccino_minio_data`.
# Set FRAPPUCCINO_VOLUME_PREFIX or COMPOSE_PROJECT_NAME to override.
#
# On restore the volumes may not exist yet (fresh host before
# docker-compose up). In that case we'll create them with the
# detected prefix — if prefix is unknown (no compose project name
# anywhere) we default to `frappuccino` which matches the standard
# bootstrap.
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
        echo "$suffix"
    else
        # Default for the fresh-host restore case.
        echo "frappuccino_${suffix}"
    fi
}

VOL_STATE=$(resolve_volume server_state)
VOL_MINIO=$(resolve_volume minio_data)
log "Resolved volumes: state=${VOL_STATE} minio=${VOL_MINIO}"

# Pre-flight : ensure volumes exist (created lazily by `docker volume
# create` if they don't — bootstrap.sh + docker-compose up handle this
# normally but we cover the "restore on a brand-new host before
# compose up" path).
for vol in "$VOL_STATE" "$VOL_MINIO"; do
    if ! docker volume inspect "$vol" >/dev/null 2>&1; then
        log "Creating Docker volume '$vol'"
        docker volume create "$vol" >/dev/null
    fi
done

# Pre-flight : refuse to overwrite a non-empty volume unless --force.
# We check via the same alpine pattern as the backup. `find ... -type
# f | head -1` short-circuits as soon as it finds anything, so the
# probe is fast even on huge minio_data.
if [[ $FORCE -ne 1 ]]; then
    log "Checking destination volumes are empty..."
    EXISTING=$(docker run --rm \
        --log-driver=none \
        -v "${VOL_STATE}":/check/state:ro \
        -v "${VOL_MINIO}":/check/minio:ro \
        alpine:3 \
        sh -c 'find /check/state /check/minio -type f 2>/dev/null | head -1' \
        || true)
    if [[ -n "$EXISTING" ]]; then
        log "ERROR: at least one destination volume is non-empty :"
        log "       $EXISTING"
        log "       Run with --force to overwrite, or wipe manually with :"
        log "         docker compose down && docker volume rm ${VOL_STATE} ${VOL_MINIO}"
        exit 3
    fi
fi

# Stop the stack if compose is here. We bring it back up after. If
# the operator is restoring on a fresh host where compose hasn't been
# brought up yet, this is a graceful no-op.
COMPOSE_UP=0
if [[ -f "${DEPLOY_DIR}/docker-compose.yml" ]]; then
    if (cd "$DEPLOY_DIR" && docker compose ps -q 2>/dev/null | grep -q .); then
        log "Stopping docker-compose stack..."
        (cd "$DEPLOY_DIR" && docker compose stop) >/dev/null 2>&1 || true
        COMPOSE_UP=1
    fi
fi

# Restore. Same alpine + tar pattern as the backup. We mount the
# volumes RW (vs :ro in backup) and extract the tarball's `state/`
# + `minio/` directories into their corresponding mount points.
# Decide whether the source is age-encrypted, now that
# SOURCE is known.
if [[ -n "$AGE_IDENTITY" || "$SOURCE" == *.age ]]; then
    [[ -n "$AGE_IDENTITY" ]] \
        || die "Source looks encrypted (.age) but FRAPPUCCINO_BACKUP_AGE_IDENTITY is not set"
    command -v age >/dev/null 2>&1 || die "age not in PATH (apt install age)"
    [[ -f "$AGE_IDENTITY" ]] || die "age identity file not found: $AGE_IDENTITY"
    DECRYPT=1
    maybe_decrypt() { age -d -i "$AGE_IDENTITY"; }
    log "At-rest decryption: ON (identity ${AGE_IDENTITY})"
fi

log "Restoring from ${SOURCE}${DECRYPT:+ (age-decrypt)}..."
unpack() {
    docker run --rm -i \
        --log-driver=none \
        -v "${VOL_STATE}":/dst/state \
        -v "${VOL_MINIO}":/dst/minio \
        alpine:3 \
        tar -xzf - -C /dst
}
if [[ "$SOURCE" == "-" ]]; then
    # Stdin mode — pipe straight through (decrypt if configured).
    maybe_decrypt | unpack
else
    [[ -f "$SOURCE" ]] || die "Source file not found: $SOURCE"
    if [[ "$DECRYPT" -eq 0 ]]; then
        # Plaintext: keep the gzip integrity pre-check. (Can't gzip -t an
        # age blob without the identity, so we skip it when encrypted.)
        log "Verifying gzip integrity on source tarball..."
        gzip -t "$SOURCE" || die "Source tarball is corrupted (gzip -t failed)"
    fi
    maybe_decrypt < "$SOURCE" | unpack
fi

log "Restore extraction OK"

# Bring the stack back up if we stopped it.
if [[ $COMPOSE_UP -eq 1 ]]; then
    log "Restarting docker-compose stack..."
    (cd "$DEPLOY_DIR" && docker compose up -d) >/dev/null 2>&1 || true
fi

log "DONE — verify with: docker compose ps && curl -ksf https://127.0.0.1:8443/health"
