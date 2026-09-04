#!/usr/bin/env bash
# gen-self-signed.sh — Génère un cert auto-signé EC P-256 pour le relais, puis
# imprime le pin SPKI à reporter dans pin.rs.
#
# Exemple:
#   bash gen-self-signed.sh 136.244.101.236 /opt/frappuccino/tls

set -euo pipefail

HOST="${1:?Usage: $0 <IP_OR_HOSTNAME> [output_dir]}"
OUT="${2:-./tls}"
DAYS=3650  # 10 ans — pas de mécanisme de renouvellement, on regénère manuellement

mkdir -p "${OUT}"
cd "${OUT}"

# 1. Détecte si HOST est une IP ou un nom de domaine
if [[ "${HOST}" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then
  SAN="IP:${HOST}"
else
  SAN="DNS:${HOST}"
fi

# 2. Génère clé EC P-256 + cert auto-signé
openssl ecparam -name prime256v1 -genkey -noout -out frappuccino_ca.key
chmod 600 frappuccino_ca.key

openssl req -x509 -new -key frappuccino_ca.key -days "${DAYS}" \
  -subj "/CN=Frappuccino Relay/O=Frappuccino/C=FR" \
  -addext "subjectAltName=${SAN}" \
  -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
  -addext "extendedKeyUsage=serverAuth" \
  -out frappuccino_ca.crt

# 3. Extrait le SPKI SHA-256 (= ce qu'on pin côté client)
SPKI_B64=$(openssl x509 -in frappuccino_ca.crt -pubkey -noout \
  | openssl pkey -pubin -outform DER \
  | openssl dgst -sha256 -binary \
  | openssl base64)
echo "${SPKI_B64}" > spki_sha256.txt

# 4. Affiche le résumé
echo
echo "=== Cert généré ==="
openssl x509 -in frappuccino_ca.crt -noout -subject -issuer -dates -ext subjectAltName
echo
echo "=== SPKI SHA-256 (pin client) ==="
echo "${SPKI_B64}"
echo
echo "À reporter dans crypto-rs/stream/src/pin.rs :"
echo "  pub const PIN_SHA256_B64: &str = \"${SPKI_B64}\";"
echo "  pub const PINNED_HOST: &str = \"${HOST}\";"
echo
echo "Et copier le cert public vers le client comme fixture :"
echo "  cp ${OUT}/frappuccino_ca.crt <repo>/crypto-rs/stream/assets/frappuccino_ca.crt"
