# server/deploy/ — Bootstrap portable du relais Frappuccino

Procédure pour déployer le relais (FastAPI + MinIO + nginx TLS) sur une VM
neuve Ubuntu 24.04 LTS. Conçu pour être réutilisable sur n'importe quel
fournisseur — Vultr, Greenhost, 1984, OVH, bare-metal — sans changement.

## Pré-requis VM

- Ubuntu 24.04 LTS fresh
- Au moins 1 GB RAM (2 GB recommandé pour MinIO + Argon2id confort)
- Accès SSH user non-root avec `sudo` (`relay` par convention, configurable via RELAY_USER)
- IP publique stable (ou hostname pointant dessus si tu veux Let's Encrypt)

## Étape 1 — Setup système (one-shot, ~5 min)

```bash
# Depuis le repo local :
scp -r server/ relay@<IP>:/tmp/

# Sur la VM (avec NOPASSWD sudo temporaire posé) :
ssh relay@<IP> 'sudo bash /tmp/server/deploy/bootstrap.sh'
```

Le script `bootstrap.sh` est **idempotent** — relance-le sans risque pour
re-vérifier l'état. Il installe :
- apt full-upgrade + autoremove
- sshd hardening (PermitRootLogin no, PasswordAuthentication no)
- UFW (22, 80, 443, 8443) — ⚠️ les ports app (8000/9000) NE sont PAS protégés
  par UFW (Docker DNAT le contourne) : ils sont bindés `127.0.0.1` au niveau
  compose (WP-B1 / R-SRV-2). Cf. la vérif (e) post-déploiement.
- swap 2 GB + swappiness=10
- Docker + Compose (depot officiel, pas le snap)
- nginx + certbot + fail2ban + unattended-upgrades
- répertoire `/opt/frappuccino/` + `.env` depuis `.env.example`

**À la fin du bootstrap :** retire le NOPASSWD :
```bash
ssh relay@<IP> 'sudo rm /etc/sudoers.d/90-relay-bootstrap'
```

## Étape 2 — TLS

> ### ⭐ Option 0 — RESTAURER la clé existante (réinstall sans rebuild APK)
>
> **À privilégier sur tout réinstall / migration sur la MÊME IP.** Le client
> Android épingle **trois** SPKI acceptés en union. Le certificat que le relais
> sert aujourd'hui est celui du pin `AmIDSg…`, seul des trois à porter un SAN
> domaine, donc seul à pouvoir passer la vérification de nom depuis la bascule au
> domaine du 2026-06-27 ; `QnGK0K…`, que cette ligne désignait, a un SAN IP seul.
> Compare donc au bon. Tant que
> le serveur ressert la **même clé**, les téls se reconnectent sans rien
> remarquer — **aucun rebuild `.so`, aucun nouvel APK, aucune réinstall**.
> Régénérer un cert (Option A) produit une **nouvelle** clé → nouveau SPKI →
> tous les téls terrain bricked jusqu'au rebuild+réinstall. Donc, si tu as un
> backup off-host de `frappuccino_ca.{key,crt}` (cf. plus bas), restaure-le au
> lieu de régénérer :
>
> ```bash
> # depuis la machine qui détient le backup off-host :
> pscp frappuccino_ca.key root@<IP>:/opt/frappuccino/tls/frappuccino_ca.key
> pscp frappuccino_ca.crt root@<IP>:/opt/frappuccino/tls/frappuccino_ca.crt
> ssh root@<IP> 'chmod 600 /opt/frappuccino/tls/frappuccino_ca.key &&
>                nginx -t && systemctl reload nginx &&
>                curl -ksf https://localhost:8443/health'   # → {"status":"ok"}
> ```
>
> Vérifier que le SPKI restauré == le pin client (falsifiable) :
> ```bash
> openssl x509 -in frappuccino_ca.crt -pubkey -noout \
>   | openssl pkey -pubin -outform DER | openssl dgst -sha256 -binary | openssl base64
> # doit afficher exactement la valeur de PIN_SHA256_B64 (crypto-rs/stream/src/pin.rs)
> ```
>
> **Backup off-host de la clé** (à faire UNE fois, garder hors du repo git) :
> ```bash
> pscp root@<IP>:/opt/frappuccino/tls/frappuccino_ca.key  <dossier-hors-repo>/
> pscp root@<IP>:/opt/frappuccino/tls/frappuccino_ca.crt  <dossier-hors-repo>/
> ```
> ⚠️ La clé privée n'est **jamais** commitée. Sans ce backup, une perte de VM
> force la rotation (Option A) + rebuild+réinstall client. (Chiffrer le backup
> = amélioration future, hors phase test.)

### Option A — cert auto-signé (rapide, dev/test ; ROTATION = brick les clients pinnés)

```bash
ssh relay@<IP> 'cd /opt/frappuccino && bash /tmp/server/deploy/tls/gen-self-signed.sh <IP> ./tls'
```

Récupère le SPKI SHA-256 affiché et mets-le à jour dans le client Rust :

```bash
# Sur ta machine :
bash server/deploy/tls/update-spki-pin.sh <IP>:8443
# → affiche la ligne sed à passer sur crypto-rs/stream/src/pin.rs

# Puis copier le cert comme fixture pour les tests Rust :
scp relay@<IP>:/opt/frappuccino/tls/frappuccino_ca.crt \
  crypto-rs/stream/assets/frappuccino_ca.crt
```

### Option B — Let's Encrypt (prod, requiert un domaine pointant sur la VM)

```bash
ssh relay@<IP> 'sudo certbot certonly --nginx -d relay.frappuccino.app -m you@example.com --agree-tos -n'
```

Met à jour `.env` avec `DOMAIN=relay.frappuccino.app` et utilise les paths
`/etc/letsencrypt/live/relay.frappuccino.app/fullchain.pem` + `privkey.pem`
dans la config nginx (étape 3).

## Étape 3 — nginx reverse proxy

La conf nginx est rendue par `render-relay-conf.sh` à partir du template, piloté
par **un seul flag : `DOMAIN`** (Phase 6.1.2). Vide = mode solo IP (cert
auto-signé, **pas de HSTS**) ; rempli = mode domaine (Let's Encrypt + HSTS). Le
script refuse de rendre s'il reste un placeholder non substitué et log le mode
choisi.

```bash
ssh relay@<IP> '
  cd /tmp/server/deploy/nginx
  # Mode SOLO (tu testes seul — IP + self-signed) :
  RELAY_HOST=<IP> RELAY_PORT=8443 \
    TLS_CERT=/opt/frappuccino/tls/frappuccino_ca.crt \
    TLS_KEY=/opt/frappuccino/tls/frappuccino_ca.key \
    bash render-relay-conf.sh \
    | sudo tee /etc/nginx/sites-available/frappuccino-relay > /dev/null
  sudo ln -sf /etc/nginx/sites-available/frappuccino-relay /etc/nginx/sites-enabled/
  sudo nginx -t && sudo systemctl reload nginx
'
```

> En mode domaine, omets `RELAY_HOST` et passe `DOMAIN=relay.frappuccino.app`
> (cert Let's Encrypt par défaut + HSTS activé). Détail : section
> **Passer en mode domaine** plus bas.

> **Phase 8.1.6-D (audit 8.1.3) — disable the GLOBAL access log too.**
> The relay vhost (`relay.conf.template`) already sets `access_log off`, so
> real client traffic (`PUT /file`, `/auth`) is never logged. But the distro
> default `/etc/nginx/nginx.conf` ships `access_log /var/log/nginx/access.log;`
> in the `http {}` block, which logs the default `:80` server — scanner noise
> today, but real client IPs if anything ever hits `:80` — with 14-day
> logrotate retention. A blind relay has no use for access logs, so turn it
> off globally:
> ```bash
> ssh relay@<IP> '
>   sudo sed -i "s|^\(\s*\)access_log /var/log/nginx/access.log;|\1access_log off;|" /etc/nginx/nginx.conf
>   sudo nginx -t && sudo systemctl reload nginx
>   # optional: purge existing scanner-noise logs
>   sudo sh -c ": > /var/log/nginx/access.log; rm -f /var/log/nginx/access.log.*"
> '
> ```
> `error_log` stays active, so failures are still captured.

## Étape 4 — déploiement code applicatif

```bash
# Copier le code serveur applicatif (FastAPI app + Dockerfile + compose) :
ssh relay@<IP> 'sudo install -d -o relay -g relay /opt/frappuccino'
scp -r server/app server/Dockerfile server/docker-compose.yml server/requirements.txt \
  relay@<IP>:/opt/frappuccino/

# Éditer .env si pas déjà fait :
ssh relay@<IP> 'nano /opt/frappuccino/.env'

# Démarrer :
ssh relay@<IP> 'cd /opt/frappuccino && docker compose up -d'

# Vérifier :
ssh relay@<IP> 'docker compose ps && docker compose logs --tail=20 server'
```

## Étape 5 — systemd unit (auto-start au boot)

```bash
ssh relay@<IP> 'sudo cp /tmp/server/deploy/systemd/frappuccino-relay.service /etc/systemd/system/ && sudo systemctl daemon-reload && sudo systemctl enable frappuccino-relay'
```

## Étape 6 — vérification end-to-end

```bash
# Depuis ta machine :
curl -ksf https://<IP>:8443/health   # -k pour ignorer cert auto-signé
# → {"status":"ok"} attendu

# Si OK, test E2E avec le client Rust :
cd crypto-rs
cargo test --release -p frappuccino-crypto-stream --test e2e_protocol -- --ignored --test-threads=1
```

## Passer en mode domaine (flip Phase 6.1.2 — quand tu n'es plus seul à tester)

Le mode solo (IP + cert auto-signé) suffit tant que tu testes seul. Pour ouvrir
à d'autres, bascule en mode domaine — **un seul flag, `DOMAIN`**, qui pilote
nginx (`render-relay-conf.sh`) et l'app (`MINIO_SECURE` via docker-compose) :

1. **DNS** (Phase 1.3) : A record `relay.frappuccino.app` → IP de la VM.
2. **Cert Let's Encrypt** (Phase 1.2) — `--reuse-key` garde le SPKI stable
   d'un renew à l'autre (pas de re-pin / rebuild APK) :
   ```bash
   ssh relay@<IP> 'sudo certbot certonly --nginx -d relay.frappuccino.app \
     -m you@example.com --agree-tos -n --reuse-key'
   ```
3. **`.env`** : `DOMAIN=relay.frappuccino.app`, `TLS_EMAIL=…`, et
   `MINIO_SECURE=true` (seulement après avoir déposé des certs TLS côté MinIO).
4. **nginx** — re-render en mode domaine (HSTS s'active tout seul) :
   ```bash
   ssh relay@<IP> 'cd /tmp/server/deploy/nginx && DOMAIN=relay.frappuccino.app \
     bash render-relay-conf.sh | sudo tee /etc/nginx/sites-available/frappuccino-relay >/dev/null
     sudo nginx -t && sudo systemctl reload nginx'
   ```
5. **App** : `docker compose up -d` relit `MINIO_SECURE` depuis `.env`.
6. **Client** : tant que tu restes sur `:8443` avec la même clé (`--reuse-key`),
   le pin SPKI tient → aucun rebuild APK. Un passage `:8443`→`:443` ou un
   changement de clé = bump SPKI + rebuild + grace period 7-14 j.

Ce que le flag bascule, d'un coup d'œil :

| | `DOMAIN` vide (solo) | `DOMAIN` rempli (domaine) |
|---|---|---|
| HOST nginx | `RELAY_HOST` (IP) | le domaine |
| Cert TLS | auto-signé | Let's Encrypt |
| HSTS | off (no-op sur IP) | **on** (1 an + includeSubDomains) |
| `MINIO_SECURE` | `false` (HTTP interne) | `true` (après certs MinIO) |

## Backup automatique (Phase 1.x-prep, 2026-05-19)

Deux scripts + un timer systemd pour gérer les sauvegardes et les
migrations sans risque de perte de données :

| Fichier | Rôle |
|---|---|
| `backup-state.sh` | Dump des deux volumes Docker (`server_state` + `minio_data`) en un tarball horodaté + sha256 + manifest |
| `restore-state.sh` | Restauration symétrique sur une VM neuve (refuse d'écraser un volume non-vide sans `--force`) |
| `systemd/frappuccino-backup.{service,timer}` | Backup automatique quotidien 03:30 UTC + rétention 30 jours |

**Installation des scripts + timer sur le relais :**
```bash
ssh relay@<IP> '
  sudo install -d -o relay -g relay /opt/frappuccino/deploy
  sudo cp /tmp/server/deploy/backup-state.sh /opt/frappuccino/deploy/
  sudo cp /tmp/server/deploy/restore-state.sh /opt/frappuccino/deploy/
  sudo chmod +x /opt/frappuccino/deploy/*.sh

  sudo cp /tmp/server/deploy/systemd/frappuccino-backup.service /etc/systemd/system/
  sudo cp /tmp/server/deploy/systemd/frappuccino-backup.timer /etc/systemd/system/
  sudo systemctl daemon-reload
  sudo systemctl enable --now frappuccino-backup.timer

  # Smoke-test : fire un backup manuel + check le résultat
  sudo systemctl start frappuccino-backup.service
  ls -lh /opt/frappuccino/backups/
'
```

**Vérifier la planification :**
```bash
ssh relay@<IP> 'sudo systemctl list-timers frappuccino-backup.timer'
```

**Pousser les backups off-host (recommandé pour DR réelle) :**
les backups locaux dans `/opt/frappuccino/backups/` ne protègent que
contre une perte de la stack Docker (volume corrompu, mauvais
`docker compose down -v`). Pour la perte de la VM elle-même
(terminate Vultr, défaillance disque), il faut envoyer les
tarballs ailleurs. Exemple cron rsync vers rsync.net / Backblaze /
Greenhost :
```bash
# /etc/cron.daily/frappuccino-offsite-backup
#!/bin/bash
# Les backups sont age-chiffres au repos (WP-A3) -> l'envoi off-host (1.8)
# herite du chiffrement gratuitement ; le host distant ne voit jamais l'etat
# en clair.
LATEST=$(ls -t /opt/frappuccino/backups/frappuccino-state-*.tar.gz.age | head -1)
[ -n "$LATEST" ] && rsync -az "$LATEST" \
  backup@offsite.example.com:/backups/frappuccino/
```

## Migration vers un nouveau fournisseur

Quand tu quittes Vultr pour Greenhost / 1984 / autre :

1. **Provisionne la nouvelle VM** Ubuntu 24.04, installe ta clé SSH publique.
2. **Suit les étapes 1-5 ci-dessus** comme s'il s'agissait d'une première install
   (bootstrap, TLS, nginx, code, systemd).
   - À ce stade le nouveau relais tourne à vide (volumes Docker `server_state` et
     `minio_data` créés mais vides).
3. **Dump l'état de l'ancienne VM** vers la nouvelle, en un seul pipe SSH :
   ```bash
   # Option A — pipe direct (rapide, pas de fichier intermédiaire)
   ssh relay@<OLD_IP> 'sudo /opt/frappuccino/deploy/backup-state.sh -' \
     | ssh relay@<NEW_IP> 'sudo /opt/frappuccino/deploy/restore-state.sh -'

   # Option B — via un tarball intermédiaire (utile si la liaison
   # SSH est instable et que tu veux pouvoir reprendre)
   ssh relay@<OLD_IP> 'sudo /opt/frappuccino/deploy/backup-state.sh'
   scp relay@<OLD_IP>:/opt/frappuccino/backups/frappuccino-state-<latest>.tar.gz.age ./
   scp frappuccino-state-<latest>.tar.gz.age relay@<NEW_IP>:/tmp/
   ssh relay@<NEW_IP> 'sudo /opt/frappuccino/deploy/restore-state.sh /tmp/frappuccino-state-<latest>.tar.gz.age'
   ```
   - ⚠️ **Chiffrement au repos OBLIGATOIRE (WP-A3).** `backup-state.sh` refuse
     d'écrire un dossier en clair : exporte `FRAPPUCCINO_BACKUP_AGE_RECIPIENT`
     (clé publique `age1…`) côté backup, et `FRAPPUCCINO_BACKUP_AGE_IDENTITY`
     (fichier clé privée, gardé **hors relais**) côté restore. Les tarballs
     sont `*.tar.gz.age`. Le pipe direct (Option A) doit donc passer ces env
     dans les shells SSH distants.
   - Le script `backup-state.sh` capture les **deux volumes** (auth state +
     blobs MinIO). Avant cette infra, la migration ratait silencieusement les
     blobs MinIO — toutes les vidéos uploadées étaient perdues.
   - Le script `restore-state.sh` refuse d'écraser un volume non-vide sans
     `--force`, donc tu ne peux pas accidentellement écraser une prod live.
4. **Update DNS** (si domaine) ou le `PINNED_HOST` du client Rust pointant sur
   le nouveau IP.
5. **Régénère le cert TLS** sur la nouvelle VM (Étape 2 Option A), update le
   SPKI pin client (`update-spki-pin.sh`), rebuild APK.
   - Note : si tu as un domaine et Let's Encrypt (Option B), le cert se
     régénère tout seul et le SPKI peut rester identique tant que le couple
     domaine/clé privée reste le même. Tu peux migrer côté VM sans toucher
     l'APK — c'est la grosse valeur d'avoir un domaine.
6. **Smoke test** post-migration depuis ta machine :
   ```bash
   curl -ksf https://<NEW_IP>:8443/health     # → {"status":"ok"}
   # Et test E2E archive sur ton client Android :
   #   Mode Archive → phrase BIP-39 → RÉCUPÉRER MES STREAMS
   # Doit lister les reports de l'ancienne VM.
   ```
7. **Coupe l'ancienne VM** une fois le test E2E vert.

**Temps total** : ~30-45 min la première fois (la majorité = upload du tarball
MinIO si tu as beaucoup de blobs), ~15 min ensuite. Si tu as un domaine + Let's
Encrypt, ajoute 0 min APK rebuild — sinon ajoute ~7-14 j de grace period pour
que les users updatent l'APK avec le nouveau SPKI pin.

## Cutover relais-aveugle (Phase C — clean break, DESTRUCTIF, GO requis)

> ⚠️ **Opération destructive sur le relais PROD (`136.244.101.236`, PAS
> l'hote du site, qui est une autre machine).** Elle **efface tout l'état de test** (reports +
> blobs MinIO + registre d'enrôlement + logs) et exige un **re-enroll** des
> devices. À exécuter **uniquement sous GO explicite, étape par étape**.
> Acceptable car **pré-publication, zéro vrai utilisateur** (spec §10.4).
>
> **Ne touche PAS au TLS** (`/opt/frappuccino/tls/frappuccino_ca.{key,crt}` =
> host path, pas un volume Docker) ⇒ le **SPKI pinné reste stable** ⇒ **aucun
> rebuild `.so`/APK**. Les devices se reconnectent au même `:8443`.

**Pourquoi.** Le serveur relais-aveugle (Phase C, `server/app` réécrit) stocke
`report_id → report_pk` (jamais l'identité), n'a plus d'`owner`/`createdAt`, et
les lectures sont id-free. L'ancien état (owner-based) est **incompatible** —
d'où le clean break plutôt qu'une migration de schéma.

### Pré-flight (sous GO)

```bash
# 0. CONFIRME l'IP — c'est bien le relais, pas l'hote du site.
ssh root@136.244.101.236 -i ~/.ssh/id_ed25519 'hostname && curl -ksf https://localhost:8443/health'

# 1. Backup de SÛRETÉ (rollback) AVANT de toucher quoi que ce soit. Même si on
#    wipe tout, un backup horodaté permet de revenir en arrière si besoin.
#    WP-A3 : le backup est age-chiffré OBLIGATOIRE — exporte le recipient
#    (clé publique age1…, clé privée gardée HORS relais) sinon le script
#    refuse d'écrire en clair.
ssh root@136.244.101.236 -i ~/.ssh/id_ed25519 \
  'sudo FRAPPUCCINO_BACKUP_AGE_RECIPIENT=age1REMPLACER /opt/frappuccino/deploy/backup-state.sh'
#    → note le chemin/sha256 du tarball .tar.gz.age affiché (pour le rollback).
```

### Étape 1 — déployer le code relais-aveugle (SANS encore wiper)

```bash
# Depuis le repo local (worktree à jour) — recopie l'app Phase C + rebuild.
scp -r server/app server/Dockerfile server/docker-compose.yml server/requirements.txt \
  root@136.244.101.236:/opt/frappuccino/
ssh root@136.244.101.236 -i ~/.ssh/id_ed25519 \
  'cd /opt/frappuccino && docker compose up -d --build && docker compose logs --tail=20 server'
```

### Étape 2 — clean-break wipe (état + blobs + logs)

```bash
ssh root@136.244.101.236 -i ~/.ssh/id_ed25519 '
  cd /opt/frappuccino
  # down -v retire conteneurs + réseaux + les volumes nommés (server_state +
  # minio_data) en un coup ⇒ wipe reports.json + .ratchet_registry.json +
  # .nonce_cache.json + .jwt_blacklist.json +
  # TOUS les blobs MinIO. Les logs conteneur partent avec
  # les conteneurs supprimés. Le TLS (host path) NEST PAS touché.
  docker compose down -v
  # Recrée des volumes VIDES + repart sur le code Phase C.
  docker compose up -d --build
  docker compose ps
'
```

### Étape 3 — vérifier l'état vierge + le code relais-aveugle

```bash
ssh root@136.244.101.236 -i ~/.ssh/id_ed25519 '
  curl -ksf https://localhost:8443/health                       # → {"status":"ok"}
  # reports.json vide (ou absent jusquau 1er upload) :
  docker exec frappuccino-server-1 sh -c "cat /state/reports.json 2>/dev/null || echo VIDE"
  # marqueur relais-aveugle dans le code déployé (domaines 0x07/0x08, archive id-free) :
  docker exec frappuccino-server-1 grep -c SIG_DOMAIN_REPORT_WRITE /app/app/signature_domain.py
'
```

### Étape 4 — re-enroll des devices (gestes therealshulgin)

Sur **Seeker** puis **OnePlus** : ouvrir l'app, déverrouiller (PIN) — l'app
ré-enregistre l'identité (dérivée de la phrase, donc identique) + un batch frais
contre le relais vierge. Vérifier dans logcat : `V2 server enrollment OK` puis
`V2 auth OK batch=0 remaining=…`.

### Étape 5 — vérification post-cutover (le test du motto)

```bash
ssh root@136.244.101.236 -i ~/.ssh/id_ed25519 '
  # (a) reports.json = report_id -> report_pk SEUL (0 owner/createdAt/author/title) :
  docker exec frappuccino-server-1 sh -c "cat /state/reports.json" \
    | grep -iE "owner|createdAt|author|title" && echo "!! FUITE IDENTITE" || echo "OK 0 identite"
  # (b) logs serveur = 0 clé publique (le scrub T2b) — cherche un hex 64 :
  docker compose -f /opt/frappuccino/docker-compose.yml logs server \
    | grep -ioE "[0-9a-f]{64}" | head && echo "!! PK DANS LOGS" || echo "OK 0 pk logs"
  # (c) santé pipeline (invariant blob-first) :
  /opt/frappuccino/deploy/audit-reports-vs-blobs.sh        # integrity ~100 %, blobless_records=0
'
```

> **(d) test du motto BINAIRE (F-C1).** Le grep ASCII (a) sur `reports.json` ne
> voit PAS les 32 octets binaires de l'identité à l'intérieur d'un blob — c'est
> exactement ce qui a laissé passer F-C1 (l'en-tête STRM stockait
> `author_ed25519_pk` en clair). Depuis la V3, l'identité n'est plus écrite au
> repos. Vérif : après cutover (les blobs legacy V1/V2 partent avec
> `docker compose down -v`), AUCUN octet d'objet MinIO ne doit contenir
> l'identité long-terme d'un témoin. `PK_HEX` = clé ed25519 hex du témoin
> (`stream_decrypt.py --show-identity`, ou `frappuccino-cli` côté device). La
> garde permanente vit dans `crypto-rs/stream/tests/motto_no_identity_at_rest.rs`
> (au build) ; ceci en est le pendant terrain au repos.

```bash
ssh root@136.244.101.236 -i ~/.ssh/id_ed25519 '
  PK_HEX="REMPLACER_par_la_cle_ed25519_hex_du_temoin"
  # MinIO stocke les objets sous /data (volume minio_data) dans le conteneur minio.
  docker exec -i frappuccino-minio-1 python3 - "$PK_HEX" <<"PY"
import os, sys, glob
pk = bytes.fromhex(sys.argv[1])
hits = [f for f in glob.glob("/data/**/*", recursive=True)
        if os.path.isfile(f) and pk in open(f, "rb").read()]
print("!! FUITE IDENTITE AU REPOS:", hits) if hits else print("OK 0 identite dans les blobs")
PY
'
```

> **(e) surface réseau (WP-B1 / H-3).** Les ports applicatifs (`8000` FastAPI,
> `9000` MinIO) sont **loopback-only** au niveau compose. Docker publie les ports
> via des règles iptables DNAT qui **contournent UFW** (`ufw default deny` n'est
> pas consulté), donc le binding `127.0.0.1:…` est la vraie frontière — pas le
> pare-feu. Seuls 22/80/443/8443 sont exposés. Vérif après `docker compose up -d` :

```bash
# (e1) sur le relais : les ports app n'ecoutent QUE sur loopback.
ssh root@136.244.101.236 -i ~/.ssh/id_ed25519 \
  "ss -ltn | grep -E ':(8000|9000)\b' || echo 'aucun listener 8000/9000'"
#   -> attendu : 127.0.0.1:8000 et 127.0.0.1:9000 (JAMAIS 0.0.0.0:…)
# (e2) depuis l'EXTERIEUR (ton poste) : le port app doit etre injoignable.
nc -z -w3 136.244.101.236 8000 && echo '!! 8000 EXPOSE' || echo 'OK 8000 ferme'
nc -z -w3 136.244.101.236 8443 && echo 'OK 8443 ouvert (nginx TLS)' || echo '!! 8443 injoignable'
```

Puis **T5 field-test** : sur un device, enregistrer (dont **background +
écran-éteint**) → Mode Archive → phrase → RÉCUPÉRER → vérifier que les chunks
reviennent (énumération id-free). C'est la validation terrain finale de Phase C.

### Rollback (si l'étape 3/5 échoue)

```bash
ssh root@136.244.101.236 -i ~/.ssh/id_ed25519 '
  cd /opt/frappuccino && docker compose down -v
  # Re-déployer l ANCIEN code (git checkout de la révision pré-Phase-C côté repo,
  # re-scp server/app) PUIS restaurer l état sauvegardé en pré-flight :
  # WP-A3 : le backup est age-chiffré (*.tar.gz.age) -> apporte la clé PRIVÉE age
  # (gardée hors relais) pour le restore, sinon restore-state.sh échoue loud.
  sudo FRAPPUCCINO_BACKUP_AGE_IDENTITY=/chemin/vers/age-identity.txt \
    /opt/frappuccino/deploy/restore-state.sh --force \
    /opt/frappuccino/backups/frappuccino-state-<TS-du-preflight>.tar.gz.age
  docker compose up -d --build && curl -ksf https://localhost:8443/health
'
```

> ⚠️ **Le rollback restaure l'ANCIEN schéma** (owner-based) ⇒ ne marche qu'avec
> l'ANCIEN code serveur. Ne pas mélanger code Phase C + état owner-based.

### Référence — fichiers d'état du relais (sous le volume `server_state`)

| Fichier | Module | Contenu post-cutover |
|---|---|---|
| `data/reports.json` (`REPORTS_DB_PATH`) | `routes/reports.py` | `report_id → report_pk` (0 identité) |
| `/state/ratchet_registry.json` (`RATCHET_REGISTRY_FILE` ; le nom à point est le défaut du code, que le compose surcharge) | `ratchet_registry.py` | pks enrôlés + compteurs batch/création (résidu §6 ; **seul** index d'identité au repos depuis le retrait de `.authorized_keys.json`, 2026-06-29) |
| `/state/nonce_cache.json` (`NONCE_CACHE_FILE` ; idem) | `auth.py` | nonces one-shot (transitoire) |
| `.jwt_blacklist.json` (`JWT_BLACKLIST_FILE` ; celui-ci n'est **pas** surchargé par le compose, il garde le défaut à point) | `jwt_blacklist.py` | hashes de tokens révoqués |

## Hygiène

- **Pas de secret dans Git** — `.env` doit être dans `.gitignore` (déjà le cas
  via `**/.env` à la racine repo).
- **Pas de `--workers >1`** sur uvicorn tant que le nonce cache vit en mémoire
  (RT-12). Voir `app/auth.py` pour la doc.
- **Backups quotidiens** automatisés via le timer ci-dessus
  (`frappuccino-backup.timer`). Garde l'œil sur la taille `minio_data`
  (`docker system df -v`) — sur un relais saturé de captures longues il peut
  grossir vite, et tes backups itou.
