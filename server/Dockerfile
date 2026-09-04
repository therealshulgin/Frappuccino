FROM python:3.12-slim

# Phase 6.1.7 — non-root user. Even if a remote exec gains code execution
# inside the container, the relay process never holds CAP_DAC_OVERRIDE or
# any capability beyond what `stream` UID has on the (read-only) app dir.
# The MinIO/Postgres data lives in volumes, owned by their respective
# containers — no breakout via shared FS.
RUN groupadd --system --gid 1001 stream \
 && useradd  --system --uid 1001 --gid stream --no-create-home stream

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ app/

# Lock app dir to read-only for the runtime user.
RUN chown -R stream:stream /app && chmod -R u=rX,g=,o= /app

# Phase 3.X-devops (2026-05-15) — pre-create /state owned by the
# runtime user so the Docker named volume inherits this ownership the
# first time it's initialized. Without this, a fresh deploy on a fresh
# host creates the volume root:root → uvicorn's unprivileged `stream`
# user (UID 1001) cannot write to /state → `ratchet_registry._save`
# fails with "[Errno 13] Permission denied" and the enrollment data
# stays RAM-only. Observed 2026-05-15 in-vivo after the Vultr OS
# reinstall : therealshulgin had to enroll 3× before a manual `chown
# 1001:1001 /var/lib/docker/volumes/frappuccino_server_state/_data`
# on the host fixed the persistence path. The fix below makes the
# correct ownership the install-time default.
#
# Note: Docker initializes a named volume mounted to a non-empty
# directory by copying the image's content (and ownership) into the
# volume the first time it's bound. If the volume already exists with
# content, Docker preserves it — so this change is harmless on hosts
# where the volume is already chown'd correctly.
RUN install -d -m 0750 -o stream -g stream /state

USER stream

# Phase 6.1.3 — `--workers 1` EXPLICITE.
# Le nonce cache (auth challenge replay protection) est process-local
# (cf. server/app/auth.py). Plusieurs workers = chacun son cache → un
# nonce mis par worker A inconnu de worker B → bypass possible via
# load-balancing. Tant que la migration Redis n'est pas faite, ne JAMAIS
# augmenter ce nombre. uvicorn default est 1 mais on le rend explicite
# pour bloquer toute future tentative de bump.
#
# Phase 6.1.6 — `--no-access-log` : on a un JsonFormatter custom dans
# app/logging_setup.py qui silence `uvicorn.access` pour éviter le leak
# d'IP du client. `--no-access-log` est l'équivalent CLI.
#
# Phase 3.38-C (NEW-2) — `--loop uvloop --http httptools` explicites.
# `uvicorn[standard]` (requirements.txt) installe déjà uvloop et
# httptools en deps, mais sans les flags explicites uvicorn tente d'auto-
# détecter et peut tomber en fallback asyncio + h11 si l'auto-détection
# échoue silencieusement (déjà vu sur certains containers Alpine). Les
# rendre explicites : (a) garantit la perf attendue (uvloop ≈ 2-4× plus
# rapide que asyncio sur du I/O event-loop, httptools un parser C plus
# rapide que h11) ; (b) bloque toute régression silencieuse si une
# future build ne pull plus l'extra `[standard]`. Gain mesuré côté
# upstream FastAPI sur PUT 1.7 MB : +15-30 % throughput vs default.
#
# Phase 6.1.22 (2026-05-18) — `--forwarded-allow-ips="127.0.0.1"`.
# Red Team R-MED-1 fix : nginx reverse proxy 8443 → 127.0.0.1:8000
# terminates TLS. Without this flag, every incoming request looks to
# uvicorn (and to slowapi's `get_remote_address`) like it came from
# 127.0.0.1 — so the rate-limit `30/minute` was SHARED between all
# clients globally. An attacker flooding `/health` or `/auth/challenge`
# could exhaust the legitimate users' quota in seconds. With this flag,
# uvicorn trusts the `X-Forwarded-For` header from 127.0.0.1 (= nginx
# only, never from external clients) and sets `request.client.host` to
# the real client IP that nginx wrote. slowapi then keys per-client.
# nginx already sets `proxy_set_header X-Forwarded-For $remote_addr;`
# (cf. server/deploy/nginx/relay.conf.template:88) so the header is
# always present and authentic.
# `--host 0.0.0.0` binds the CONTAINER's interface — required so Docker can
# forward the published port to the app. The internet exposure is bounded at the
# compose layer, which publishes this port on 127.0.0.1 ONLY (WP-B1 / H-3, see
# docker-compose.yml). Do NOT "harden" this to 127.0.0.1 here: Docker forwards to
# the container IP, not its loopback, so that would make the app unreachable
# through the published port (nginx -> 127.0.0.1:8000 would break).
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", \
     "--workers", "1", "--no-access-log", \
     "--loop", "uvloop", "--http", "httptools", \
     "--forwarded-allow-ips", "127.0.0.1"]
