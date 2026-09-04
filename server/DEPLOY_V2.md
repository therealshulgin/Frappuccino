# Déploiement V2 sur Vultr — Instructions

## État actuel
- Serveur Vultr (136.244.101.236:8000) tourne la V1 (healthy)
- Backup V1 fait (confirmé par l'user)
- Code V2 local dans `server/`, 57 tests verts

## Option A — Déploiement rapide (recommandé)

Depuis ta machine locale (là où tu as ton mot de passe SSH root) :

```bash
cd <repo>

# 1. Upload du nouveau code sans écraser .env, logs, state
scp -r server/app \
       server/docker-compose.yml \
       server/Dockerfile \
       server/requirements.txt \
       server/deploy-v2.sh \
       root@136.244.101.236:/opt/frappuccino/

# 2. Connexion + déploiement
ssh root@136.244.101.236
cd /opt/frappuccino
bash deploy-v2.sh
```

Le script `deploy-v2.sh` fait :
1. Backup `/opt/frappuccino/` → `/opt/frappuccino-backup-YYYYMMDD-HHMMSS/`
2. `docker-compose down` (stop V1)
3. `docker-compose build --no-cache server` (build V2)
4. `docker-compose up -d` (start V2)
5. Check `/health` + liste des endpoints V2 enregistrés
6. Affiche les logs

## Option B — Manuel (si tu veux contrôler chaque étape)

```bash
# Sur ton laptop
scp server/app/ratchet_registry.py    root@136.244.101.236:/opt/frappuccino/app/
scp server/app/routes/auth_v2.py       root@136.244.101.236:/opt/frappuccino/app/routes/
scp server/app/models.py               root@136.244.101.236:/opt/frappuccino/app/
scp server/app/main.py                 root@136.244.101.236:/opt/frappuccino/app/
scp server/docker-compose.yml          root@136.244.101.236:/opt/frappuccino/

# Sur le serveur
ssh root@136.244.101.236
cd /opt/frappuccino
docker-compose down
docker-compose build --no-cache server
docker-compose up -d

# Vérifications
curl http://localhost:8000/health
curl http://localhost:8000/openapi.json | jq '.paths | keys' | grep v2
docker-compose logs --tail=50 server
```

## Smoke test depuis ton laptop (après deploy)

```bash
# Liste des endpoints V2 — doit inclure 4 entrées
curl -s http://136.244.101.236:8000/openapi.json | \
    python -c "import sys,json; d=json.load(sys.stdin); print('\n'.join(p for p in d['paths'] if '/v2/' in p))"

# Attendu :
# /auth/v2/enroll
# /auth/v2/verify
# /auth/v2/rotate-batch
# /auth/v2/logout
# (GET /auth/v2/status/{ed25519_pk} RETIRE — audit 2026-06-27 R-SRV-1 :
#  c'etait un oracle d'existence+activite par identite, joignable sans auth)
```

Tu peux aussi lancer un test E2E complet :

```bash
cd <repo>/server
# Modifier tests/test_e2e_v2.py pour pointer sur http://136.244.101.236:8000
# (ou écrire un petit client Python de 30 lignes)
```

## Rollback

Si quelque chose casse :

```bash
ssh root@136.244.101.236
cd /opt
docker-compose -f frappuccino/docker-compose.yml down
mv frappuccino frappuccino-v2-failed
mv frappuccino-backup-YYYYMMDD-HHMMSS frappuccino
cd frappuccino
docker-compose up -d
```

Ou plus simple : le backup global que tu as pris avant cette session.

## Ce qui change côté serveur

### Nouveaux fichiers
- `app/ratchet_registry.py` — singleton thread-safe + persistance JSON
- `app/routes/auth_v2.py` — 4 endpoints V2

### Fichiers modifiés
- `app/models.py` — +7 modèles pydantic (V2EnrollRequest, etc.)
- `app/main.py` — include du router V2
- `docker-compose.yml` — volume `server_state` pour persister
  `ratchet_registry.json` (+ reports / nonce-cache / jwt-blacklist)

### Nouveau volume Docker
Le container passe en lecture-seule MAIS écrit dans `/state` via un volume nommé
`server_state`. Pour inspecter :
```bash
docker volume inspect frappuccino_server_state
# Puis :
ls /var/lib/docker/volumes/frappuccino_server_state/_data/
```

### Compatibilité V1
- `/auth/challenge` : inchangé, partagé V1/V2
- `/auth/verify` (V1) : inchangé, accepte toujours signatures long-terme Ed25519
- `/auth/v2/*` : nouveaux, utilisent ratchet éphémère

Les identités V1 enrôlées dans `.authorized_keys.json` restent valides pour
l'endpoint `/auth/verify` V1. Un device peut utiliser les deux (si enrôlé V2,
il aura aussi un batch dans `.ratchet_registry.json`).

## Notes de sécurité

- Le volume `server_state` contient des **clés publiques uniquement** (rien de secret
  côté serveur, pas de clés privées, pas de mnemonics). La saisie du disque Vultr ne
  permet pas de déchiffrer les streams.
- Le JWT secret est dans `.env` (hors volume, dans le filesystem du host). Protège-le.
- Le container a `read_only: true` + `cap_drop: ALL` + `no-new-privileges:true`.
  Seul `/tmp` (tmpfs) et `/state` (volume) sont writable.

## Tests pré-déploiement déjà verts localement

```
tests/test_auth_v2.py : 36/36  (registry + crypto helpers)
tests/test_e2e_v2.py  : 21/21  (FastAPI TestClient)
```

Total Phase 4 : **57/57 tests V2 verts**.
