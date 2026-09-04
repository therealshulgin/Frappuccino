#!/usr/bin/env bash
# External health probe for the Frappuccino relay (Blue Team LOW-2).
#
# The Docker healthcheck in docker-compose.yml restarts the `server` container
# when uvicorn's asyncio loop wedges, but nothing inside the box notices when
# the box itself goes away: network outage, kernel panic, BGP hijack, OOM
# killer firing on dockerd. Without a witness outside, the relay stays down
# until someone finds out the hard way at the next field test ("uploads aren't
# going through"). So this one runs from ANOTHER machine — a laptop, a spare
# monitoring VPS, a CI runner — and pages on extended unreachability.
#
#   ./monitor-health.sh                       # one-shot probe
#   ./monitor-health.sh --alert-email you@x   # one-shot, mail on fail
#   crontab -e :  */5 * * * * /path/monitor-health.sh --alert-email ...
#
# Exit 0 only on 200 + `{"status":"ok"}`, 1 otherwise; every verdict is logged
# to stderr with a timestamp. A 200 carrying some other body counts as a
# failure too: it means something else is answering on that URL (wrong cert,
# route shadowed by another service). A 5xx — relay up, FastAPI dead — should
# already have been caught by the Docker healthcheck; we probe for it anyway,
# as a second line of defence.
#
# The tunables below are all overridable through their FRAPPUCCINO_* env var.
# FAIL_THRESHOLD is the one to weigh before touching: 3 consecutive fails on the
# 5-minute cron above means ≈ 15 min before anyone is paged. The counter that
# carries across runs is persisted in STATE_DIR, /tmp/frappuccino-monitor by
# default.
#
# curl runs with -k on purpose. The relay cert is self-signed and in no system
# CA store, and the real authentication is the SPKI pin enforced by the client
# app, not by this probe — drop the -k and the probe just goes permanently red.
#
# The probed URL defaults to the current Vultr deploy. If you migrate to
# Greenhost NL / 1984hosting, override it via env var.

set -euo pipefail

RELAY_URL="${FRAPPUCCINO_RELAY_URL:-https://136.244.101.236:8443/health}"
TIMEOUT="${FRAPPUCCINO_TIMEOUT_S:-10}"
STATE_DIR="${FRAPPUCCINO_STATE_DIR:-/tmp/frappuccino-monitor}"
FAIL_THRESHOLD="${FRAPPUCCINO_FAIL_THRESHOLD:-3}"

ALERT_EMAIL=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --alert-email) ALERT_EMAIL="$2"; shift 2 ;;
        *) echo "Unknown arg: $1" >&2; exit 2 ;;
    esac
done

mkdir -p "$STATE_DIR"
COUNTER_FILE="$STATE_DIR/consecutive_fails"
[ -f "$COUNTER_FILE" ] || echo 0 > "$COUNTER_FILE"

timestamp() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }
log() { echo "[$(timestamp)] $*" >&2; }

# One-shot probe : curl returns the body on stdout (we eat it), HTTP
# code on -w. -k tolerates self-signed cert. --connect-timeout caps the
# TLS handshake too. -s suppresses progress noise.
HTTP_CODE=""
BODY=""
if BODY=$(curl -k -s -m "$TIMEOUT" \
             --connect-timeout "$TIMEOUT" \
             -w "\n%{http_code}" \
             "$RELAY_URL" 2>/dev/null); then
    HTTP_CODE=$(echo "$BODY" | tail -n1)
    BODY=$(echo "$BODY" | sed '$d')
else
    HTTP_CODE="000"  # curl-level error (timeout, refused, DNS)
    BODY=""
fi

if [[ "$HTTP_CODE" == "200" && "$BODY" == *'"status":"ok"'* ]]; then
    # Reset counter on success.
    PREV=$(cat "$COUNTER_FILE")
    echo 0 > "$COUNTER_FILE"
    if [[ "$PREV" != "0" ]]; then
        log "OK : relay recovered after $PREV consecutive fail(s)"
        if [[ -n "$ALERT_EMAIL" ]]; then
            echo "Frappuccino relay $RELAY_URL recovered after $PREV fail(s) at $(timestamp)." | \
                mail -s "Frappuccino relay RECOVERED" "$ALERT_EMAIL" 2>/dev/null || true
        fi
    else
        log "OK : 200 + valid body"
    fi
    exit 0
fi

# Failure path : increment counter.
PREV=$(cat "$COUNTER_FILE")
COUNT=$((PREV + 1))
echo "$COUNT" > "$COUNTER_FILE"

log "FAIL : http_code=$HTTP_CODE consecutive=$COUNT/$FAIL_THRESHOLD"
log "Body : $(echo "$BODY" | head -c 200)"

# Alert on threshold cross, then every Nth iteration after (avoid spam).
if [[ "$COUNT" -ge "$FAIL_THRESHOLD" ]]; then
    if [[ -n "$ALERT_EMAIL" ]] && \
       { [[ "$COUNT" == "$FAIL_THRESHOLD" ]] || \
         [[ $((COUNT % (FAIL_THRESHOLD * 4))) == 0 ]]; }; then
        SUBJECT="Frappuccino relay DOWN (consecutive=$COUNT)"
        BODY_TEXT="Frappuccino relay $RELAY_URL is failing health checks.

Consecutive fails : $COUNT (threshold $FAIL_THRESHOLD)
Last HTTP code   : $HTTP_CODE
Last body        : $(echo "$BODY" | head -c 500)
Last probe       : $(timestamp)

Run \`docker compose ps\` and \`docker compose logs server\` on the
VPS. Restart with \`docker compose up -d\` if containers are down."
        echo "$BODY_TEXT" | mail -s "$SUBJECT" "$ALERT_EMAIL" 2>/dev/null || \
            log "Mail send failed (mail command not configured?)"
    fi
fi

exit 1
