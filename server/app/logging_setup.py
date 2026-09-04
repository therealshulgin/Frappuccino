"""
Logs JSON structurés, sans jamais une IP client.

Ne jamais logger l'IP d'un client (finding M-09, RT-cloud) : sur un serveur
public elle relie un militant à son activité, et une saisie du serveur suffit
alors à recoller users ↔ logs. Le piège, c'est que s'abstenir ne suffit pas —
FastAPI/uvicorn logge cette IP par défaut dans son access log (`%(h)s`), il faut
donc désarmer la configuration livrée. C'est le travail de `setup_logging` :
`uvicorn` et `uvicorn.error` sont re-routés vers notre formatter, et
`uvicorn.access` est intégralement désactivé (handlers vidés, propagate=False,
disabled=True). Il n'y a plus d'access log applicatif du tout, scrubé ou non.

Le format structuré, lui, est là pour rester lisible par un outil SIEM
(filebeat, vector, logstash) : du texte humain va très bien en debug local, plus
du tout au-delà d'une instance. Un objet JSON par ligne, les extras d'un
`logger.info(..., extra={...})` étant fusionnés au top-level.

Trois absences sont volontaires : pas de python-json-logger (une dépendance
externe de plus à auditer pour ~50 lignes de code, surface trop large avant un
audit externe type Cure53 / Trail of Bits), pas de rotation (Docker et systemd
s'en chargent, la sortie partant sur la sortie d'erreur standard du conteneur),
pas de batch ni d'async (perdre un log au crash coûte plus cher que le gain de
perf).
"""
from __future__ import annotations

import json
import logging
import sys
import time
from typing import Any


# Champs LogRecord standard exclus du dump JSON (déjà mappés en top-level
# ou inutiles pour l'audit). Toute clé non listée est considérée extra et
# fusionnée dans la sortie JSON.
_LOG_RECORD_BUILTINS = frozenset({
    "name", "msg", "args", "levelname", "levelno", "pathname",
    "filename", "module", "exc_info", "exc_text", "stack_info",
    "lineno", "funcName", "created", "msecs", "relativeCreated",
    "thread", "threadName", "processName", "process",
    # Python 3.12+ : LogRecord pose `taskName` automatiquement pour les
    # logs depuis des coroutines asyncio. Souvent None pour du code
    # synchrone, on le drop pour ne pas polluer l'output JSON.
    "taskName",
    # Phase 6.1.6 : champs blocklist explicite — `client_ip`,
    # `remote_addr`, `forwarded_for` sont des aliases courants pour
    # l'IP du client. Si du code les pose dans extra, on les drop.
    "client_ip", "remote_addr", "forwarded_for", "x_forwarded_for",
    "ip", "host",
})


# Champs de top-level posés par le formatter. Si du code dans extra ré-utilise
# ces noms, on log un warning silencieux et on conserve la valeur du formatter
# (pas de prefix-dance qui rendrait le log ininterprétable).
_TOP_LEVEL_KEYS = frozenset({"ts", "level", "logger", "msg", "module", "fn", "line"})


class JsonFormatter(logging.Formatter):
    """
    1 line = 1 JSON object. ASCII-only output (`ensure_ascii=True`) pour
    éviter les surprises sur des terminaux / pipelines mal configurés.
    """

    def format(self, record: logging.LogRecord) -> str:
        # Construit la base avec timestamp ISO 8601 UTC + millisecondes.
        gm = time.gmtime(record.created)
        ts = time.strftime("%Y-%m-%dT%H:%M:%S", gm) + f".{int(record.msecs):03d}Z"

        out: dict[str, Any] = {
            "ts": ts,
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
            "module": record.module,
            "fn": record.funcName,
            "line": record.lineno,
        }

        # Merge des extras user — exclus les champs builtins de LogRecord
        # ET les noms blocklist (client_ip, etc.) pour respecter "no IP".
        for key, value in record.__dict__.items():
            if key in _LOG_RECORD_BUILTINS or key in _TOP_LEVEL_KEYS:
                continue
            if key.startswith("_"):
                continue
            try:
                # Sérialisable JSON ? Si non, on stringify pour ne pas
                # casser le log.
                json.dumps(value)
                out[key] = value
            except (TypeError, ValueError):
                out[key] = repr(value)

        # Phase C (A-1) — NEVER dump a full traceback or stack to the container
        # logs. A formatted traceback renders frame locals via repr(), which can
        # carry a pk, a client IP, a nonce, or request bytes — exactly the
        # identity↔activity link a seizure of the json-file logs must not yield.
        # uvicorn.error logs unhandled request exceptions with exc_info=True and
        # propagates to this root formatter, so scrubbing here covers that
        # channel too. We keep only the exception CLASS NAME as an ops signal.
        if record.exc_info and record.exc_info[0] is not None:
            out["exc_type"] = record.exc_info[0].__name__
        if record.stack_info:
            out["stack_info"] = "<omitted>"

        return json.dumps(out, ensure_ascii=True, default=str)


def setup_logging(level: str = "INFO") -> None:
    """
    Configure le root logger avec le JsonFormatter sur stderr. Doit être
    appelé une seule fois au démarrage (cf. main.py lifespan). Idempotent
    par effet de bord — si appelé plusieurs fois, le handler est remplacé.
    """
    root = logging.getLogger()
    # Nettoie les handlers pré-existants (basicConfig laisse souvent un
    # StreamHandler avec format texte — on ne veut PAS de doublons).
    for h in list(root.handlers):
        root.removeHandler(h)

    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(JsonFormatter())
    root.addHandler(handler)
    root.setLevel(level)

    # uvicorn et FastAPI utilisent leurs propres loggers — propagation
    # vers root est OK par défaut, mais uvicorn.access logge l'IP du
    # client. On le SILENCE complètement (le proxy nginx en amont a déjà
    # ses propres access logs si on les veut, sans corrélation user).
    logging.getLogger("uvicorn.access").handlers = []
    logging.getLogger("uvicorn.access").propagate = False
    logging.getLogger("uvicorn.access").disabled = True

    # These four lines look redundant with the global exception handler in
    # main.py. They are not: that handler only covers its own line, never
    # uvicorn's re-raise path. Left alone, uvicorn keeps a plain-text
    # StreamHandler on the parent `uvicorn` logger (propagate=False) and logs
    # unhandled-exception tracebacks on `uvicorn.error` (httptools_impl,
    # "Exception in ASGI application", exc_info=exc). Those never reach the root
    # formatter and land raw, multi-line, in the container json-file logs, frame
    # locals rendered by repr() — a pk, a client IP, a nonce, request bytes.
    # That is the A-1 channel §9 claims sealed.
    #
    # Clearing the parent handlers and forcing propagation routes every uvicorn
    # record (uvicorn.error tracebacks included) through the root JsonFormatter,
    # whose exc_info scrub keeps only the exception class name: no traceback, no
    # frame locals. (uvicorn.access stays fully disabled above.)
    for _name in ("uvicorn", "uvicorn.error"):
        _lg = logging.getLogger(_name)
        _lg.handlers = []
        _lg.propagate = True
