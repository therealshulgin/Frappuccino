#!/usr/bin/env bash
#
# (Re)create the relay's QUIC front container from the versioned Caddyfile.
#
# Run on the relay host as root, from /opt/frappuccino, after copying
# deploy/caddy/Caddyfile to /opt/frappuccino/caddy/Caddyfile.
#
# Removing the old container also removes its Docker log, which is the only
# place an earlier Caddyfile wrote its access log. That removal is final.
#
# What the container gets:
#   - the image pinned by digest, so a recreation never pulls a different Caddy;
#   - host networking (the obfuscation proxy forwards to 127.0.0.1:8444, and
#     Caddy proxies to the relay on 127.0.0.1:8000);
#   - the TLS material and the Caddyfile, both read-only;
#   - a capped Docker log: with no access log, Caddy only writes startup and
#     error lines there, and the cap keeps even those from growing without end.
set -euo pipefail

NAME=frappuccino-quic-front
IMAGE='caddy@sha256:cfeb0b281bc44a5a51fecde39e9e577c60d863c0b6196e6bbdf58fd00960887f'
BASE=/opt/frappuccino

[ -f "$BASE/caddy/Caddyfile" ] || { echo "missing $BASE/caddy/Caddyfile" >&2; exit 1; }
[ -f "$BASE/tls/frappuccino_ca.crt" ] || { echo "missing $BASE/tls/frappuccino_ca.crt" >&2; exit 1; }

# Refuse to start a front that would log requests again.
if grep -vE '^\s*#' "$BASE/caddy/Caddyfile" | grep -qE '^\s*log(\s|\{|$)'; then
    echo "the Caddyfile holds a log directive: refusing to start a front that logs requests" >&2
    exit 1
fi

docker rm -f "$NAME" >/dev/null 2>&1 || true
docker run -d \
    --name "$NAME" \
    --restart unless-stopped \
    --network host \
    --log-driver json-file \
    --log-opt max-size=1m \
    --log-opt max-file=2 \
    -v "$BASE/tls:/certs:ro" \
    -v "$BASE/caddy/Caddyfile:/etc/caddy/Caddyfile:ro" \
    "$IMAGE" \
    caddy run --config /etc/caddy/Caddyfile --adapter caddyfile
docker ps --filter "name=$NAME" --format '{{.Names}} {{.Status}}'
