#!/usr/bin/env bash
# update-spki-pin.sh — Affiche le SPKI pin du cert actuel et la commande sed
# à lancer côté repo pour mettre à jour pin.rs.
#
# Usage:
#   bash update-spki-pin.sh [path/to/frappuccino_ca.crt]
#   bash update-spki-pin.sh [hostname:port]    # connecte en TLS pour récupérer

set -euo pipefail

INPUT="${1:-./tls/frappuccino_ca.crt}"

if [[ -f "${INPUT}" ]]; then
  # Mode 1 : fichier cert local
  SPKI_B64=$(openssl x509 -in "${INPUT}" -pubkey -noout \
    | openssl pkey -pubin -outform DER \
    | openssl dgst -sha256 -binary \
    | openssl base64)
elif [[ "${INPUT}" =~ ^[^/]+:[0-9]+$ ]]; then
  # Mode 2 : hostname:port
  SPKI_B64=$(openssl s_client -connect "${INPUT}" -servername "${INPUT%:*}" </dev/null 2>/dev/null \
    | openssl x509 -pubkey -noout \
    | openssl pkey -pubin -outform DER \
    | openssl dgst -sha256 -binary \
    | openssl base64)
else
  echo "ERROR: ${INPUT} not found, and not in hostname:port format" >&2
  exit 1
fi

echo "Current SPKI SHA-256 (base64): ${SPKI_B64}"
echo
echo "Pour mettre à jour le client Rust :"
echo "  sed -i \"s|pub const PIN_SHA256_B64: &str = \\\".*\\\";|pub const PIN_SHA256_B64: \\&str = \\\"${SPKI_B64}\\\";|\" \\"
echo "    crypto-rs/stream/src/pin.rs"
echo
echo "Puis re-builder :"
echo "  cd crypto-rs && cargo test --workspace --release"
echo "  TARGETS=arm64-v8a ./build-android.sh"
echo "  ./gradlew :mobile:assembleDebug"
