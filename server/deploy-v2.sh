#!/bin/bash
# deploy-v2.sh — Rebuild et redémarre la pile relais sur le serveur.
#
# Tourne SUR le serveur, dans /opt/frappuccino. Depuis le poste local :
#   scp -r server/app server/docker-compose.yml server/Dockerfile server/requirements.txt \
#       root@136.244.101.236:/opt/frappuccino/
#   ssh root@136.244.101.236 'bash /opt/frappuccino/deploy-v2.sh'
#
# Prends un backup en dehors de ce script avant de le lancer : le `cp -r` du
# step 1 ne copie que /opt/frappuccino, pas les volumes docker minio_data (les
# blobs) ni server_state (registre ratchet + cache de nonces), et la ligne de
# rollback affichée à la fin ne les ramène donc pas non plus. /opt/frappuccino/.env
# doit exister avec JWT_SECRET et MINIO_ROOT_USER / MINIO_ROOT_PASSWORD, sinon
# docker compose refuse de démarrer.

set -e

SERVER_DIR="/opt/frappuccino"
BACKUP_DIR="/opt/frappuccino-backup-$(date +%Y%m%d-%H%M%S)"

cd "$SERVER_DIR" || { echo "ERR: $SERVER_DIR introuvable"; exit 1; }

echo "== Frappuccino V2 deploy =="
echo "Timestamp : $(date)"
echo

# 1. Backup du répertoire courant (au cas où)
echo "[1/5] Backup du répertoire courant → $BACKUP_DIR"
cp -r "$SERVER_DIR" "$BACKUP_DIR"

# 2. Stop du container existant
echo "[2/5] Arrêt du container V1"
docker-compose down 2>/dev/null || docker compose down

# 3. Build du nouveau container avec code V2
echo "[3/5] Build du container V2"
docker-compose build --no-cache server 2>&1 | tail -20 || docker compose build --no-cache server

# 4. Démarrage
echo "[4/5] Démarrage des containers"
docker-compose up -d 2>/dev/null || docker compose up -d

# 5. Vérifications
echo "[5/5] Vérifications"
sleep 5
echo "-- docker ps --"
docker ps | grep -E "frappuccino|minio" || true
echo
echo "-- /health --"
curl -sf http://localhost:8000/health || echo "WARN: /health ne répond pas"
echo
echo "-- OpenAPI : endpoints V2 enregistrés --"
curl -sf http://localhost:8000/openapi.json 2>/dev/null | grep -oE '"/auth/v2/[a-z-]+"' | sort -u || echo "WARN: OpenAPI pas accessible"
echo
echo "-- Logs (20 dernières lignes) --"
docker-compose logs --tail=20 server 2>/dev/null || docker compose logs --tail=20 server
echo
echo "Deploy terminé. Test manuel :"
echo "  curl -X POST http://136.244.101.236:8000/auth/challenge"
echo "Rollback si besoin : mv $BACKUP_DIR $SERVER_DIR && docker-compose up -d"
