#!/usr/bin/env bash
#
# Render the relay nginx config from relay.conf.template. A SINGLE flag decides
# the whole posture: DOMAIN.
#
#   DOMAIN empty  → solo / IP / self-signed mode (current "I'm the only tester"
#                   setup): HOST = $RELAY_HOST (the bare IP), self-signed cert,
#                   NO HSTS. Pair with MINIO_SECURE=false (MinIO stays plaintext
#                   on the internal docker bridge).
#   DOMAIN set    → domain mode (going multi-user): HOST = $DOMAIN, Let's
#                   Encrypt cert, HSTS on. Pair with MINIO_SECURE=true once
#                   MinIO has TLS certs, and switch the SPKI pin / port plan
#                   per deploy/README.md.
#
# Inputs come from the environment, or from a .env sourced next to this repo's
# deploy dir; the names and their defaults are read right below. Output: the
# rendered config on stdout, or to $1 if given.
#
# Usage:
#   # solo IP mode (current):
#   RELAY_HOST=136.244.101.236 ./render-relay-conf.sh > frappuccino-relay.conf
#   # domain mode (the flip):
#   DOMAIN=relay.shake-document-protect.org ./render-relay-conf.sh > frappuccino-relay.conf
#   nginx -t -c ... ; ln -s ... /etc/nginx/sites-enabled/ ; systemctl reload nginx
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEMPLATE="$SCRIPT_DIR/relay.conf.template"

# Optionally source a .env sitting in server/deploy/ so the same flag file that
# drives docker-compose also drives nginx.
ENV_FILE="${ENV_FILE:-$SCRIPT_DIR/../.env}"
if [ -f "$ENV_FILE" ]; then
  # shellcheck disable=SC1090
  set -a; . "$ENV_FILE"; set +a
fi

DOMAIN="${DOMAIN:-}"
RELAY_PORT="${RELAY_PORT:-8443}"

if [ -n "$DOMAIN" ]; then
  HOST="$DOMAIN"
  TLS_CERT="${TLS_CERT:-/etc/letsencrypt/live/$DOMAIN/fullchain.pem}"
  TLS_KEY="${TLS_KEY:-/etc/letsencrypt/live/$DOMAIN/privkey.pem}"
  # max-age 1 year + includeSubDomains. (No `preload` — opting into the preload
  # list is a one-way commitment; add it deliberately once the domain is stable.)
  HSTS_HEADER='add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;'
  echo "[render] DOMAIN mode: host=$HOST port=$RELAY_PORT HSTS=on" >&2
else
  HOST="${RELAY_HOST:-}"
  if [ -z "$HOST" ]; then
    echo "[render] ERROR: IP mode needs RELAY_HOST (the server IP). Set RELAY_HOST or DOMAIN." >&2
    exit 2
  fi
  TLS_CERT="${TLS_CERT:-/etc/nginx/ssl/frappuccino-relay.crt}"
  TLS_KEY="${TLS_KEY:-/etc/nginx/ssl/frappuccino-relay.key}"
  HSTS_HEADER=''
  echo "[render] IP mode: host=$HOST port=$RELAY_PORT HSTS=off (self-signed)" >&2
fi

# Refuse to render a config that would brick TLS. Three ways a rendered
# relay.conf bricks the fleet (WP-F5, audit 2026-06-28 / L-10):
#   1. cert and key don't match  -> nginx serves a cert whose key it lacks; the
#      TLS handshake then fails for every client.
#   2. the cert's SPKI != the pin the Android clients hard-code -> every pinned
#      client rejects the connection (a SILENT fleet brick) even though the
#      handshake itself "works" — the clients enforce SPKI pinning, not CA trust.
#   3. the cert is EXPIRED (pin-expiry residual, audit 2026-06-29) -> the TLS
#      handshake fails for every client. Near-expiry (<30 d) = a WARN renewal
#      reminder; pinning is on SPKI not validity, so `certbot --reuse-key` renews
#      without changing the pin.
# We catch all three BEFORE writing the config. The cert/key may legitimately not be
# provisioned yet at render time (paths are baked into the config, the files
# arrive later); in that case we WARN and skip (never silent) instead of failing.
#
# Expected SPKI pins (base64 SHA-256), in priority order:
#   - $EXPECTED_SPKI_PINS (space/comma-separated) if set, else
#   - auto-extracted from crypto-rs/stream/src/pin.rs (the PIN_*_B64 constants)
#     when that source is reachable from here, else
#   - the pin-match check is skipped with a loud warning (cert<->key match is
#     still enforced — it needs no external input).
tls_brick_guard() {
  local cert_pub key_pub spki expected normalized matched p pin_rs
  if ! command -v openssl >/dev/null 2>&1; then
    echo "[render] WARN: openssl not found — TLS brick guard skipped (apt install openssl to enable)" >&2
    return 0
  fi
  if [ ! -f "$TLS_CERT" ] || [ ! -f "$TLS_KEY" ]; then
    echo "[render] WARN: cert/key not provisioned yet (cert=$TLS_CERT key=$TLS_KEY) — TLS brick guard skipped; re-run after provisioning to validate." >&2
    return 0
  fi

  # 1. cert <-> key match. Compare the public key extracted from each; this is
  #    identical iff they pair, for both RSA and EC keys.
  cert_pub="$(openssl x509 -in "$TLS_CERT" -noout -pubkey 2>/dev/null)" \
    || { echo "[render] ERROR: cannot read public key from cert $TLS_CERT" >&2; exit 1; }
  key_pub="$(openssl pkey -in "$TLS_KEY" -pubout 2>/dev/null)" \
    || { echo "[render] ERROR: cannot derive public key from key $TLS_KEY" >&2; exit 1; }
  if [ "$cert_pub" != "$key_pub" ]; then
    echo "[render] ERROR: cert and key DO NOT MATCH (cert=$TLS_CERT key=$TLS_KEY)." >&2
    echo "[render]   Refusing to render a config that would break every TLS handshake." >&2
    exit 1
  fi
  echo "[render] TLS guard: cert<->key match OK" >&2

  # 1b. cert expiry (pin-expiry residual). An expired cert bricks the handshake
  #     for everyone; a near-expiry one is a renewal reminder. SPKI pinning is on
  #     the key, not the validity dates, so `certbot --reuse-key` (or re-signing
  #     the self-signed cert with the same key) renews WITHOUT changing the pin.
  if ! openssl x509 -checkend 0 -noout -in "$TLS_CERT" >/dev/null 2>&1; then
    echo "[render] ERROR: cert $TLS_CERT is ALREADY EXPIRED ($(openssl x509 -enddate -noout -in "$TLS_CERT" 2>/dev/null))." >&2
    echo "[render]   Rendering with an expired cert bricks the TLS handshake. Renew (certbot --reuse-key keeps the SPKI pin) before deploying." >&2
    exit 1
  elif ! openssl x509 -checkend 2592000 -noout -in "$TLS_CERT" >/dev/null 2>&1; then
    echo "[render] WARN: cert $TLS_CERT expires within 30 days ($(openssl x509 -enddate -noout -in "$TLS_CERT" 2>/dev/null)) — renew soon (certbot --reuse-key preserves the SPKI pin)." >&2
  else
    echo "[render] TLS guard: cert not near expiry OK" >&2
  fi

  # 2. SPKI pin. The served cert's SPKI SHA-256 (base64) must be one the clients
  #    pin, or every pinned client silently rejects the relay.
  spki="$(openssl x509 -in "$TLS_CERT" -pubkey -noout 2>/dev/null \
    | openssl pkey -pubin -outform DER 2>/dev/null \
    | openssl dgst -sha256 -binary 2>/dev/null \
    | openssl base64 2>/dev/null)" \
    || { echo "[render] ERROR: cannot compute SPKI pin from cert $TLS_CERT" >&2; exit 1; }
  echo "[render] TLS guard: served cert SPKI sha256/base64 = $spki" >&2

  expected="${EXPECTED_SPKI_PINS:-}"
  if [ -z "$expected" ]; then
    pin_rs="$SCRIPT_DIR/../../../crypto-rs/stream/src/pin.rs"
    if [ -f "$pin_rs" ]; then
      # Each SHA-256 SPKI pin is 44 base64 chars (43 + '='); match exactly that
      # shape so PSKs / other literals can't be picked up by mistake.
      expected="$(grep -oE '"[A-Za-z0-9+/]{43}="' "$pin_rs" 2>/dev/null | tr -d '"' | tr '\n' ' ' || true)"
      [ -n "$expected" ] && echo "[render] TLS guard: expected pins auto-loaded from pin.rs" >&2
    fi
  fi
  if [ -z "$expected" ]; then
    echo "[render] WARN: no EXPECTED_SPKI_PINS set and pin.rs not reachable — SPKI pin-match check skipped. Set EXPECTED_SPKI_PINS to the client pins to enable it." >&2
    return 0
  fi

  normalized="$(printf '%s' "$expected" | tr ',' ' ')"
  matched=0
  for p in $normalized; do
    if [ "$p" = "$spki" ]; then matched=1; break; fi
  done
  if [ "$matched" != "1" ]; then
    echo "[render] ERROR: served cert SPKI ($spki) is NOT in the client pin set:" >&2
    for p in $normalized; do echo "[render]          pinned: $p" >&2; done
    echo "[render]   Every pinned Android client would reject this relay (silent fleet brick)." >&2
    echo "[render]   Refusing to render. If this is an intentional, pre-seeded rotation, set" >&2
    echo "[render]   EXPECTED_SPKI_PINS to the new pin to override deliberately." >&2
    exit 1
  fi
  echo "[render] TLS guard: SPKI pin matches the client pin set OK" >&2
}

tls_brick_guard

[ -f "$TEMPLATE" ] || { echo "[render] ERROR: template not found: $TEMPLATE" >&2; exit 1; }

# Substitute with '|' as the sed delimiter so cert paths (full of '/') are safe.
rendered="$(sed \
  -e "s|{{HOST}}|$HOST|g" \
  -e "s|{{RELAY_PORT}}|$RELAY_PORT|g" \
  -e "s|{{TLS_CERT}}|$TLS_CERT|g" \
  -e "s|{{TLS_KEY}}|$TLS_KEY|g" \
  -e "s|{{HSTS_HEADER}}|$HSTS_HEADER|g" \
  "$TEMPLATE")"

if printf '%s' "$rendered" | grep -q '{{'; then
  echo "[render] ERROR: unsubstituted placeholder(s) remain:" >&2
  printf '%s\n' "$rendered" | grep -n '{{' >&2
  exit 1
fi

if [ "${1:-}" != "" ]; then
  printf '%s\n' "$rendered" > "$1"
  echo "[render] wrote $1" >&2
else
  printf '%s\n' "$rendered"
fi
