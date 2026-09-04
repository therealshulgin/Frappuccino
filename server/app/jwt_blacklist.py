"""
Révocation de JWT. Sans elle, un token volé reste valide jusqu'à son `exp`
(24 h), donc un device perdu ne peut pas être coupé depuis un autre device.

La blacklist vit dans le processus, et elle n'est correcte que parce que le
serveur tourne en `--workers 1` (Dockerfile, unit systemd). Passer à plusieurs
workers pour gagner du débit rendrait la révocation partielle sans le moindre
signal : le token révoqué resterait accepté par les autres workers. Un store
partagé est donc un préalable à ce changement, pas une optimisation d'après.

Une entrée associe le SHA-256 hex du JWT à son `exp` ; le hash suffit puisqu'on
ne teste que l'égalité. Les entrées périmées sont retirées au passage, le JWT
étant de toute façon déjà invalide.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
import time
from pathlib import Path

from app.atomic_io import atomic_json_save

logger = logging.getLogger("stream.jwt_blacklist")

_BLACKLIST_FILE = Path(os.getenv("JWT_BLACKLIST_FILE", ".jwt_blacklist.json"))
_blacklist: dict[str, float] = {}
_lock = threading.Lock()


def _hash_token(token: str) -> str:
    """SHA-256 hex digest of the JWT string (Bearer prefix stripped)."""
    if token.startswith("Bearer "):
        token = token[7:]
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def _load() -> None:
    """
    Load persisted blacklist at boot. Drop expired entries.
    Called once at module import time.
    """
    global _blacklist
    if not _BLACKLIST_FILE.exists():
        return
    try:
        raw = json.loads(_BLACKLIST_FILE.read_text())
        now = time.time()
        loaded: dict[str, float] = {}
        for k, v in raw.items():
            try:
                expiry = float(v)
            except (TypeError, ValueError):
                continue
            if expiry > now:
                loaded[k] = expiry
        with _lock:
            _blacklist = loaded
        logger.info(
            "Loaded %d unexpired blacklisted JWTs (dropped %d expired)",
            len(loaded), len(raw) - len(loaded),
        )
    except Exception as e:
        logger.warning("Failed to load JWT blacklist: %s", e)


def _save_unlocked() -> None:
    """Atomic durable write (fsync + rename). Caller must hold _lock.

    Raises OSError on failure (audit 2026-06-27, R-SRV-5), like the rest of the
    `atomic_io` callers. It used to swallow the error, and that meant a
    revocation the client believed had worked could be undone by a container
    restart, quietly making a stolen token valid again.

    Only one caller may swallow it: the expiry cleanup in `is_revoked`, which
    drops entries that are already invalid anyway. `revoke()` lets it through so
    `/logout` answers 503 and the client retries.
    """
    atomic_json_save(_BLACKLIST_FILE, _blacklist)


def _cleanup_unlocked() -> None:
    """Drop entries whose exp has passed. Caller must hold _lock."""
    now = time.time()
    expired = [k for k, v in _blacklist.items() if v <= now]
    for k in expired:
        del _blacklist[k]


def revoke(token: str, expiry: float) -> None:
    """
    Add a JWT to the blacklist with its `exp` claim.

    Caller is expected to have already verified the JWT signature + exp
    before calling this (typically in the /logout handler). We don't
    re-verify here — this module is a pure storage layer.
    """
    if expiry <= time.time():
        # Already expired naturally, no need to blacklist.
        return
    h = _hash_token(token)
    with _lock:
        _blacklist[h] = float(expiry)
        _cleanup_unlocked()
        _save_unlocked()
    logger.info("JWT revoked (hash=%s..., expires in %ds)", h[:8],
                int(expiry - time.time()))


def is_revoked(token: str) -> bool:
    """
    True iff `token` was previously revoked AND its exp hasn't passed.
    Cleans up stale entries opportunistically.
    """
    h = _hash_token(token)
    with _lock:
        expiry = _blacklist.get(h)
        if expiry is None:
            return False
        if expiry <= time.time():
            # Token would be naturally invalid anyway, drop from blacklist.
            del _blacklist[h]
            # Best-effort persist: this drops an ALREADY-EXPIRED entry (the token
            # is invalid by `exp` regardless), so a save failure here must not
            # 500 a legitimate auth check (audit 2026-06-27, R-SRV-5). The
            # critical durability is in `revoke()`, which propagates.
            try:
                _save_unlocked()
            except OSError as e:
                logger.warning("jwt_blacklist cleanup save failed (non-fatal): %s", e)
            return False
        return True


def _reset_for_test() -> None:
    """Reset state for unit tests. NOT for production use."""
    global _blacklist
    with _lock:
        _blacklist = {}
        if _BLACKLIST_FILE.exists():
            try:
                _BLACKLIST_FILE.unlink()
            except OSError:
                pass


_load()
