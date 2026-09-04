import asyncio
import json
import logging
import os
import threading
import time
from pathlib import Path
import jwt
import nacl.bindings
import nacl.exceptions
from app import config, jwt_blacklist
from app.atomic_io import atomic_json_save

logger = logging.getLogger("stream.auth")

# Le cache de nonces est persisté sur disque, écriture atomique (BT-HIGH-13,
# audit Red/Blue Team V2 2026-04-17). Avant, il ne vivait qu'en RAM : un
# redémarrage rejetait tous les challenges en vol — coupure gênante, mais
# fail-closed, un nonce absent du cache est refusé et non rejoué. Le vrai
# risque de rejeu, borné par NONCE_TTL, est ailleurs : une sauvegarde ratée
# en silence suivie d'un crash rechargerait un snapshot où un nonce déjà
# consommé est encore présent, d'où le contrat de `_save_nonces_unlocked`.
#
# Chaque entrée vaut {"ts": secondes Unix frappées par le serveur, "expiry":
# quand le nonce est lâché}. On stocke le `ts` parce que le client le resigne
# et nous le renvoie : c'est le nôtre qui fait autorité, pas le sien.
_NONCE_FILE = Path(os.getenv("NONCE_CACHE_FILE", ".nonce_cache.json"))
_nonce_cache: dict[str, dict] = {}
_nonce_lock = threading.Lock()

# Audit 2026-06-29 — l'index V1 des clés autorisées (_authorized_keys /
# .authorized_keys.json) est retiré. Depuis le drop de is_key_registered
# (5004847, son seul lecteur), il était write-only : une copie redondante du
# set de pk déjà porté par le ratchet registry (.ratchet_registry.json, lui lu
# par la vérif). Le motto ne gagne pas (l'identité reste au repos dans le
# registry, résidu §6 inhérent) mais on supprime un store mort. L'enroll/revoke
# n'écrivent plus ce fichier.


def _load_nonces():
    """BT-HIGH-13 — load persisted nonces at boot, drop expired ones.

    S9-pre-audit pt2 : le format change — les anciennes entrées (float
    expiry) sont normalisées en {"ts": int(expiry - NONCE_TTL), "expiry":
    float}. Ça permet une transition sans perdre les nonces non expirés du
    cache d'avant le pt2.
    """
    global _nonce_cache
    if not _NONCE_FILE.exists():
        return
    try:
        raw = json.loads(_NONCE_FILE.read_text())
        now = time.time()
        loaded: dict[str, dict] = {}
        for k, v in raw.items():
            if isinstance(v, dict):
                expiry = float(v.get("expiry", 0))
                if expiry > now:
                    loaded[k] = {"ts": int(v["ts"]), "expiry": expiry}
            else:
                # Legacy entry: just a float expiry. Synthesize a ts that
                # sits NONCE_TTL back from the expiry — it may drift a few
                # seconds but the client hasn't seen this nonce yet anyway.
                expiry = float(v)
                if expiry > now:
                    loaded[k] = {"ts": int(expiry - NONCE_TTL), "expiry": expiry}
        with _nonce_lock:
            _nonce_cache = loaded
        logger.info(
            "Loaded %d unexpired nonces (dropped %d expired)",
            len(loaded), len(raw) - len(loaded)
        )
    except Exception as e:
        logger.warning("Failed to load nonce cache: %s", e)


def _save_nonces_unlocked():
    """
    Persist the current nonce cache. Caller must hold [_nonce_lock].

    This raises OSError instead of swallowing it, and that is the point of the
    function (audit R-M2 / Blue HIGH-7). Swallowing a failed write — the
    natural reflex when the disk fills up during a burst — leaves the
    in-memory mutation with no counterpart on disk: a consumed nonce stays
    present in the snapshot, reloads as fresh after a crash, and a captured
    signature replays for the remaining 60 s of its TTL.

    So every caller must either roll its in-memory mutation back
    (`generate_challenge`, `verify_challenge`) or let the error become a 503 so
    the client retries (`routes/auth_v2.py::verify`). The write itself goes
    through a rename, which keeps the previous snapshot intact if the process
    dies mid-write.
    """
    atomic_json_save(_NONCE_FILE, _nonce_cache)


NONCE_TTL = 60  # seconds
# S9-pre-audit pt2 : tolérance de skew horloge client/serveur sur le timestamp
# embarqué dans le challenge. ±30 s couvre NTP drift + sleep Android + latence
# réseau sans ouvrir une fenêtre de replay supérieure au TTL du nonce.
CHALLENGE_CLOCK_SKEW_TOLERANCE_SECONDS = 30

_load_nonces()


def generate_challenge() -> tuple[str, int]:
    """Return `(nonce_hex, unix_timestamp)`. The client must sign
    `nonce_bytes || timestamp.to_bytes(8, 'big')` via the ratchet.

    Phase 6.1.20 — rolls back the in-memory insertion if persistence
    fails, so we never return a nonce that isn't on disk. The OSError
    propagates to the async route which returns 503.
    """
    nonce = os.urandom(32).hex()
    ts = int(time.time())
    with _nonce_lock:
        _nonce_cache[nonce] = {"ts": ts, "expiry": float(ts) + NONCE_TTL}
        _cleanup_expired_nonces_unlocked()
        try:
            _save_nonces_unlocked()
        except OSError:
            # Rollback : the nonce isn't persisted, so it doesn't
            # exist as far as the verify path is concerned. Pop to keep
            # in-memory and on-disk consistent.
            _nonce_cache.pop(nonce, None)
            raise
    return nonce, ts


def verify_challenge(
    ed25519_pk_hex: str,
    nonce_hex: str,
    signature_hex: str,
    timestamp: int,
    domain: bytes = b"",
) -> bool:
    """Pop the nonce (atomic) and verify the Ed25519 signature covers
    `domain || nonce_bytes || timestamp_BE_u64`.

    `domain` is the R-C-1 one-byte signature-domain tag the caller prepends
    before signing. Its empty default is a leftover from the V1 flow that has
    since been removed (see routes/auth_routes.py) and must not be relied on: a
    new caller that keeps it signs with no domain separation, and that
    signature stays valid in any other context that also omits the tag. The
    archive-auth caller that passed `SIG_DOMAIN_ARCHIVE_AUTH` (0x04) went away
    with the id-free archive, and the live `/auth/v2/verify` builds the 0x01
    AuthChallenge message and calls `_verify_ed25519_sig` directly, so the only
    caller left here is the standalone auth smoke test.

    Returns False on any validation or cryptographic failure: unknown or
    expired nonce, client timestamp diverging from the stored one, skew beyond
    tolerance, malformed inputs, bad signature. A persistence OSError does
    propagate, though — the caller maps it to a 503.
    """
    with _nonce_lock:
        entry = _nonce_cache.pop(nonce_hex, None)
        if entry is not None:
            try:
                _save_nonces_unlocked()
            except OSError:
                # Rollback the pop so the nonce isn't silently lost
                # before the client gets a chance to retry. Propagate
                # to the async handler → 503.
                _nonce_cache[nonce_hex] = entry
                raise
    now = time.time()
    if entry is None or now > entry["expiry"]:
        return False
    stored_ts = int(entry["ts"])
    # The client must not tamper with the timestamp it echoes back; match it
    # against the one we stored when minting the nonce.
    if stored_ts != timestamp:
        return False
    if abs(int(now) - stored_ts) > CHALLENGE_CLOCK_SKEW_TOLERANCE_SECONDS:
        return False

    try:
        pk = bytes.fromhex(ed25519_pk_hex)
        nonce = bytes.fromhex(nonce_hex)
        signature = bytes.fromhex(signature_hex)
        if len(nonce) != 32 or len(pk) != 32 or len(signature) != 64:
            return False
        ts_bytes = int(stored_ts).to_bytes(8, "big", signed=False)
        # R-C-1: prepend the one-byte signature domain tag (mirrors the Rust
        # client in crypto-rs/core/src/signature_domain.rs).
        message = domain + nonce + ts_bytes

        # Ed25519 verify: will raise if invalid
        nacl.bindings.crypto_sign_open(signature + message, pk)
        return True
    except (nacl.exceptions.BadSignatureError, ValueError, KeyError, OverflowError):
        return False


def create_jwt(subject: str) -> str:
    payload = {
        "sub": subject,
        "iat": int(time.time()),
        "exp": int(time.time()) + config.JWT_EXPIRE_HOURS * 3600,
    }
    return jwt.encode(payload, config.JWT_SECRET, algorithm=config.JWT_ALGORITHM)


# Phase C (relay-blind reports) — archive-scope JWT REMOVED.
#
# Archive reads are now capability-addressed and identity-free: a rescue
# device enumerates `report_id_n` by derivation (crypto-rs/core/src/report.rs)
# and downloads ciphertext without any token (app/routes/archive.py). The
# POST /api/v2/archive/auth endpoint, its long-term Ed25519 challenge (domain
# 0x04), `create_archive_jwt`, and `require_archive_auth` are all gone — the
# relay no longer learns *which identity* reads *which reports*.


def verify_detached_ed25519(public_key: bytes, signature: bytes, message: bytes) -> bool:
    """Verify a detached Ed25519 signature over `message` under `public_key`
    (libsodium `crypto_sign_open`, strict). Never raises.

    This is the verifier for the per-report capability signatures, 0x07
    ReportCreate and 0x08 ReportWrite, both checked in app/routes/upload.py.

    It does NOT prepend the signature-domain tag; the caller does, and nothing
    in the signature here hints at it. A caller that hands over a bare message
    signs with no domain separation, and that signature stays valid in any
    other context that also omits the tag. The tags live in
    app/signature_domain.py and mirror the Rust client's
    `SignatureDomain::prefixed` (crypto-rs/core/src/report.rs).

    The signer is the per-report key R_n derived from the seed, never the
    identity, so this path neither learns nor stores who is writing.
    """
    if len(public_key) != 32 or len(signature) != 64:
        return False
    try:
        nacl.bindings.crypto_sign_open(signature + message, public_key)
        return True
    except (nacl.exceptions.BadSignatureError, ValueError, KeyError, OverflowError):
        return False


def verify_jwt(token: str) -> dict | None:
    try:
        # Strip "Bearer " prefix if present
        if token.startswith("Bearer "):
            token = token[7:]
        # Phase 6.1.1 — check blacklist BEFORE decoding. Évite le coût
        # cryptographique de la signature verification sur un token déjà
        # connu comme révoqué (defense en profondeur + perf).
        if jwt_blacklist.is_revoked(token):
            return None
        return jwt.decode(token, config.JWT_SECRET, algorithms=[config.JWT_ALGORITHM])
    except jwt.InvalidTokenError:
        return None


# V2 : verify_legacy_login supprimé. register_key / unregister_key (l'index V1
# _authorized_keys) retirés en même temps — voir la note en tête de module : la
# révocation vit désormais entièrement dans le ratchet registry (revoked=True,
# lu par la vérif), sans copie redondante du set de pk.


def _cleanup_expired_nonces_unlocked():
    """Caller must hold [_nonce_lock]."""
    now = time.time()
    expired = [k for k, v in _nonce_cache.items() if now > float(v["expiry"])]
    for k in expired:
        del _nonce_cache[k]


# This periodic purge is not a duplicate of the
# `_cleanup_expired_nonces_unlocked()` call already made by
# `generate_challenge` (audit R-MED-3), and dropping it as one costs both
# memory and CPU. That inline cleanup only runs when a challenge is minted, so
# what the cache holds is the mint rate over NONCE_TTL: bounded per client by
# the 10/min rate-limit ceiling (per client since R-MED-1), but growing with the
# number of distinct clients — around 14k entries an hour under a sustained
# flood — while the inline pass itself becomes O(N) on every insertion. This one
# purges every NONCE_CLEANUP_INTERVAL_S whatever the request load.
#
# It only does anything if `main.lifespan` spawns it at startup and cancels it
# at shutdown; nothing in this file wires that up.
NONCE_CLEANUP_INTERVAL_S = 60.0


async def nonce_cleanup_loop():
    """Background task : purge expired nonces from _nonce_cache every
    [NONCE_CLEANUP_INTERVAL_S]. Persists ONLY if something was actually
    expired (avoid unnecessary fsync calls under no-load).

    The lock acquisition + save runs via `asyncio.to_thread` so the
    event loop stays free for incoming requests during the (rare)
    fsync.
    """
    logger.info(
        "Nonce cleanup loop started, interval=%.0fs", NONCE_CLEANUP_INTERVAL_S
    )
    try:
        while True:
            await asyncio.sleep(NONCE_CLEANUP_INTERVAL_S)
            try:
                expired_count = await asyncio.to_thread(_cleanup_nonces_locked)
                if expired_count > 0:
                    logger.debug(
                        "Nonce cleanup : purged %d expired entries", expired_count
                    )
            except OSError as e:
                logger.warning(
                    "Nonce cleanup : save failed (will retry next tick): %s", e
                )
            except Exception as e:
                logger.exception("Nonce cleanup iteration failed: %s", e)
    except asyncio.CancelledError:
        logger.info("Nonce cleanup loop cancelled")
        raise


def _cleanup_nonces_locked() -> int:
    """Sync helper used by [nonce_cleanup_loop] via asyncio.to_thread.
    Returns the number of expired entries removed. Saves to disk if
    anything changed (raises OSError on save failure).
    """
    with _nonce_lock:
        before = len(_nonce_cache)
        _cleanup_expired_nonces_unlocked()
        expired = before - len(_nonce_cache)
        if expired > 0:
            _save_nonces_unlocked()
        return expired
