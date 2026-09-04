"""
Endpoints V2 : enrôlement, signature éphémère, rotation de batch.

`/auth/v2/verify` (signature par une clé éphémère du batch courant) est le seul
chemin d'authentification qui reste : les routes V1 ont été supprimées, cf. le
commentaire de tête de `auth_routes.py`.

Aucune route de challenge ici. Le nonce vient de `/auth/challenge`
(`auth_routes.py`) et sert aux deux flux — un nonce est un nonce, il n'y a pas
de doublon à ajouter sous `/auth/v2/`.
"""

import asyncio
import logging
import time
from fastapi import APIRouter, Header, HTTPException, Request, Response
import jwt as pyjwt
import nacl.bindings
import nacl.exceptions

from app import auth, config, jwt_blacklist, ratchet_registry, signature_domain
from app.models import (
    V2EnrollRequest, V2EnrollResponse,
    V2VerifyRequest, LoginResponse,
    V2RotateBatchRequest, V2RotateBatchResponse,
)
from app.ratelimit import limiter  # shared app-wide Limiter (see app/ratelimit.py)

logger = logging.getLogger("stream.auth_v2")
router = APIRouter(prefix="/auth/v2")


# -----------------------------------------------------------------------------
# Helpers : vérification de signature détachée Ed25519
# -----------------------------------------------------------------------------

def _verify_ed25519_sig(pk_hex: str, message: bytes, signature_hex: str) -> bool:
    """Vérifie une signature détachée Ed25519. Retourne True si valide."""
    try:
        pk = bytes.fromhex(pk_hex)
        sig = bytes.fromhex(signature_hex)
        if len(pk) != 32 or len(sig) != 64:
            return False
        # pynacl's low-level binding : crypto_sign_open prend signature||message
        # et retourne le message si OK, sinon raise.
        nacl.bindings.crypto_sign_open(sig + message, pk)
        return True
    except (nacl.exceptions.BadSignatureError, ValueError):
        return False


def _pop_nonce_locked(nonce_hex: str) -> dict | None:
    """Sync helper for the V2 verify path: pops the nonce from the cache and
    persists; on OSError, rolls back the pop and re-raises.

    Call it through `asyncio.to_thread` from the async handler, otherwise the
    fsync + rename block the event loop.

    Returns the popped entry (`ts` + `expiry` fields), or None if the nonce was
    unknown.
    """
    with auth._nonce_lock:
        entry = auth._nonce_cache.pop(nonce_hex, None)
        if entry is None:
            return None
        try:
            auth._save_nonces_unlocked()
        except OSError:
            # Rollback : restore the nonce so the next retry can pop it.
            auth._nonce_cache[nonce_hex] = entry
            raise
        return entry


def _concat_public_keys(hex_keys: list[str]) -> bytes:
    """Concat 50 × 32 bytes = 1600 bytes (même sérialisation que le client Kotlin)."""
    if len(hex_keys) != ratchet_registry.BATCH_SIZE:
        raise ValueError(
            f"Expected {ratchet_registry.BATCH_SIZE} keys, got {len(hex_keys)}"
        )
    result = bytearray()
    for h in hex_keys:
        b = bytes.fromhex(h)
        if len(b) != 32:
            raise ValueError(f"Invalid pk length: {len(b)}")
        result.extend(b)
    return bytes(result)


# -----------------------------------------------------------------------------
# POST /auth/v2/enroll
# -----------------------------------------------------------------------------

@router.post("/enroll", response_model=V2EnrollResponse)
@limiter.limit("5/minute")
async def enroll(request: Request, body: V2EnrollRequest):
    """Enrôle une identité V2 avec son batch_0.

    Une identité déjà enrôlée est refusée en 409 : le renouvellement passe par
    `/auth/v2/rotate-batch`.
    """
    # 1. Validation de format
    if len(body.batch_0_public_keys) != ratchet_registry.BATCH_SIZE:
        raise HTTPException(
            status_code=400,
            detail=f"Expected {ratchet_registry.BATCH_SIZE} public keys in batch_0"
        )
    try:
        concat = _concat_public_keys(body.batch_0_public_keys)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid batch keys: {e}")

    # 2. Vérification de la signature Ed25519 par la clé long-terme
    # R-C-1: enrollment signs concat(batch_0_pks) in the Enrollment domain.
    if not _verify_ed25519_sig(
        body.ed25519_pk,
        signature_domain.SIG_DOMAIN_ENROLLMENT + concat,
        body.batch_0_signature,
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid enrollment signature — batch_0 not signed by ed25519_pk"
        )

    # 3. Enrollment (atomique), en to_thread : le fsync de
    #    _ratchet_registry.json ne doit pas bloquer l'event loop.
    try:
        ok = await asyncio.to_thread(
            ratchet_registry.enroll,
            body.ed25519_pk,
            body.batch_0_public_keys,
            body.batch_0_signature,
        )
    except OSError as e:
        logger.error("ratchet_registry.enroll persistence failed: %s", e)
        raise HTTPException(
            status_code=503,
            detail="Server state I/O error — retry shortly",
        )
    if not ok:
        raise HTTPException(
            status_code=409,
            detail="Identity already enrolled — use /auth/v2/rotate-batch to refresh"
        )

    # L'enregistrement dans l'index V1 _authorized_keys (auth.register_key) est
    # retiré : cet index était write-only et redondant, le ratchet registry
    # écrit juste au-dessus porte déjà l'identité enrôlée et c'est lui que la
    # vérif lit. Enroll n'écrit donc plus qu'un seul état au repos
    # (audit 2026-06-29).

    # Ne jamais logger la pk d'identité : une saisie des logs du conteneur ne
    # doit pas rendre identité↔activité. On journalise l'événement, pas qui.
    logger.info("V2 enrollment OK")
    return V2EnrollResponse(
        enrolled=True,
        ed25519_pk=body.ed25519_pk,
        batch_number=0,
    )


# -----------------------------------------------------------------------------
# POST /auth/v2/verify
# -----------------------------------------------------------------------------

@router.post("/verify", response_model=LoginResponse)
@limiter.limit("30/minute")
async def verify(request: Request, body: V2VerifyRequest):
    """
    Vérifie une signature éphémère, consomme la clé éphémère, retourne un JWT.

    Le message signé est `0x01 (domaine AuthChallenge) || nonce (32 octets) ||
    timestamp big-endian u64 non signé`. Le préfixe de domaine fait partie du
    message, il vient de `app/signature_domain.py` (R-C-1) et c'est lui qui
    empêche une signature de rotation ou d'enrôlement de passer ici. C'est un
    contrat de fil : le client doit le reproduire à l'octet près, préfixe
    compris, sinon toute l'auth V2 échoue sans le moindre diagnostic. Et le
    `timestamp` renvoyé doit être exactement celui émis par `/auth/challenge`,
    pas l'horloge locale du device : le serveur compare à ce qu'il a stocké,
    puis re-sérialise sa propre valeur pour reconstruire le message.

    Quatre des refus viennent d'un autre module et sont donc invisibles à la
    lecture de ce fichier : `ratchet_registry.is_ephemeral_key_valid` rejette
    une identité inconnue ou révoquée, un `batch_number` qui n'est plus le
    courant, un `key_index` déjà consommé, et un `ephemeral_pk` qui ne
    correspond pas à `batch_keys[key_index]`. Ces quatre-là, et eux seuls, sont
    réellement indiscernables : la fonction ne rend qu'un booléen. Les autres
    refus sortent aussi en 401, mais avec un `detail` qui les distingue encore
    — nonce, timestamp, dérive d'horloge, signature.

    La dérive d'horloge tolérée est de 30 s
    (`auth.CHALLENGE_CLOCK_SKEW_TOLERANCE_SECONDS`) : un appareil dont l'heure
    est fausse au-delà ne s'authentifie plus du tout. C'est la première chose à
    regarder quand un témoin reste bloqué sur le terrain.
    """
    # 1. Atomic pop du nonce + lecture du timestamp signé par le serveur.
    #    Rollback in-memory si le save raise : le nonce n'est pas perdu et le
    #    client peut retenter sur le 503.
    try:
        entry = await asyncio.to_thread(_pop_nonce_locked, body.nonce)
    except OSError as e:
        logger.error("nonce save failed during V2 verify: %s", e)
        raise HTTPException(
            status_code=503,
            detail="Server state I/O error — retry shortly",
        )
    if entry is None or time.time() > float(entry["expiry"]):
        raise HTTPException(status_code=401, detail="Invalid or expired nonce")
    stored_ts = int(entry["ts"])
    if body.timestamp != stored_ts:
        # Le client a modifié le timestamp : on refuse sans rien fuiter.
        raise HTTPException(status_code=401, detail="Timestamp mismatch")
    now = int(time.time())
    if abs(now - stored_ts) > auth.CHALLENGE_CLOCK_SKEW_TOLERANCE_SECONDS:
        raise HTTPException(status_code=401, detail="Clock skew beyond tolerance")

    # 2. Vérifie que la clé éphémère est utilisable (sans la consommer)
    if not ratchet_registry.is_ephemeral_key_valid(
        body.ed25519_pk, body.batch_number, body.key_index, body.ephemeral_pk
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid ephemeral key — mismatched batch, consumed index, or wrong pk"
        )

    # 3. Vérifie la signature Ed25519 de la clé éphémère sur le domaine 0x01
    #    préfixé à nonce||ts_be_u64 (voir l'appel plus bas, et la docstring).
    try:
        nonce_bytes = bytes.fromhex(body.nonce)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid nonce hex")
    if len(nonce_bytes) != 32:
        raise HTTPException(status_code=400, detail="Nonce length != 32")
    try:
        ts_bytes = int(stored_ts).to_bytes(8, "big", signed=False)
    except OverflowError:
        raise HTTPException(status_code=400, detail="Timestamp out of range")
    message = nonce_bytes + ts_bytes
    # R-C-1: the ephemeral slot signs nonce||ts in the AuthChallenge domain.
    if not _verify_ed25519_sig(
        body.ephemeral_pk,
        signature_domain.SIG_DOMAIN_AUTH_CHALLENGE + message,
        body.signature,
    ):
        raise HTTPException(status_code=401, detail="Invalid ephemeral signature")

    # 4. Consomme la clé (atomic), en to_thread : le fsync du registry ne doit
    #    pas bloquer l'event loop.
    try:
        consumed = await asyncio.to_thread(
            ratchet_registry.consume_ephemeral_key,
            body.ed25519_pk, body.batch_number, body.key_index,
        )
    except OSError as e:
        logger.error("consume_ephemeral_key persistence failed: %s", e)
        raise HTTPException(
            status_code=503,
            detail="Server state I/O error — retry shortly",
        )
    if not consumed:
        # Race perdue (quelqu'un d'autre a consommé entre-temps)
        raise HTTPException(status_code=409, detail="Ephemeral key race — retry with next index")

    # 5. Issue JWT (même format que V1, avec flag v2=True)
    token = auth.create_jwt(subject=body.ed25519_pk)  # V1-compat JWT
    # Jamais la pk, même en DEBUG ; batch et index, eux, n'identifient personne.
    logger.debug("V2 auth OK batch=%d idx=%d", body.batch_number, body.key_index)
    return LoginResponse(
        access_token=token,
        user={
            # 128 bits de la pk ([:32]), élargi depuis 64 bits ([:16]) : ne pas
            # re-rétrécir. Même troncature qu'auth_routes.py et reports.py, les
            # trois doivent rester d'accord.
            "id": body.ed25519_pk[:32],
            "username": body.ed25519_pk[:32],
            "role": "user",
            "auth_version": 2,
            "batch_number": body.batch_number,
            "key_index": body.key_index,
        },
    )


# -----------------------------------------------------------------------------
# POST /auth/v2/rotate-batch
# -----------------------------------------------------------------------------

@router.post("/rotate-batch", response_model=V2RotateBatchResponse)
@limiter.limit("5/minute")
async def rotate_batch(request: Request, body: V2RotateBatchRequest):
    """
    Avance vers batch_{N+1}.

    Cette route modifie l'état sans exiger le moindre JWT, et c'est délibéré :
    la signature est elle-même l'authentification (batch_{N}[i] signe la concat
    des 50 nouvelles pk), donc appartenir au batch courant suffit à prouver
    qu'on est l'appelant légitime. Ne pas ajouter de `require_stream_auth` ici :
    obtenir ce token demanderait de brûler d'abord un cran du ratchet via
    `/auth/v2/verify`, et rattacherait chaque rotation à une session d'identité.

    L'advance incrémente `batch_number`, installe `new_batch_public_keys` et
    repart avec `consumed_indices` vide. L'index du signataire, consommé dans
    l'ancien batch, devient donc inaccessible plutôt que rejouable.
    """
    # 1. Validation de FORMAT. Ces refus ne dépendent QUE de l'input de
    #    l'appelant (nombre/longueur de ses propres clés), jamais de l'état du
    #    registry pour l'identité cible → ils ne divulguent rien sur elle.
    if len(body.new_batch_public_keys) != ratchet_registry.BATCH_SIZE:
        raise HTTPException(
            status_code=400,
            detail=f"Expected {ratchet_registry.BATCH_SIZE} new batch keys"
        )
    try:
        concat = _concat_public_keys(body.new_batch_public_keys)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid new batch keys: {e}")

    # 2. Vérifie la signature D'ABORD (R-SRV-1) : elle ne couvre que des données
    #    fournies par l'appelant (signer_public_key + concat des nouvelles pk),
    #    donc la vérifier avant tout accès au registry ne divulgue rien sur
    #    l'existence ni sur l'état de l'identité cible.
    # R-C-1: the rotation signs concat(new pks) in the BatchRotation domain.
    sig_ok = _verify_ed25519_sig(
        body.signer_public_key,
        signature_domain.SIG_DOMAIN_BATCH_ROTATION + concat,
        body.new_batch_signature,
    )

    # 3. Confirme l'appartenance du signataire au batch COURANT, puis FUSIONNE
    #    tout échec (état ET signature) en une UNIQUE réponse générique. Aucun
    #    code distinct (plus de 404/403/409/400-pk), jamais le batch_number
    #    serveur dans le corps : `rotate-batch` ne doit pas être un oracle
    #    identité→activité, en miroir exact de `/auth/v2/verify` qui replie déjà
    #    tous ses états en un seul 401. Les deux prédicats sont évalués
    #    inconditionnellement (réponse constante).
    signer_ok = ratchet_registry.is_rotation_signer_valid(
        body.ed25519_pk,
        body.signer_batch_number,
        body.signer_key_index,
        body.signer_public_key,
    )
    if not (sig_ok and signer_ok):
        raise HTTPException(status_code=401, detail="Rotation rejected")

    # 4. Applique la rotation (atomique), en to_thread : le registry fsync.
    try:
        new_batch_number = await asyncio.to_thread(
            ratchet_registry.rotate_batch,
            body.ed25519_pk,
            body.signer_batch_number,
            body.signer_key_index,
            body.new_batch_public_keys,
            body.new_batch_signature,
        )
    except OSError as e:
        logger.error("rotate_batch persistence failed: %s", e)
        raise HTTPException(
            status_code=503,
            detail="Server state I/O error — retry shortly",
        )
    if new_batch_number is None:
        # Course perdue (rotation concurrente entre le check et l'apply).
        # Réponse générique identique — ne pas rouvrir d'oracle d'état.
        raise HTTPException(status_code=401, detail="Rotation rejected")

    # Jamais la pk ; les numéros de batch, eux, n'identifient personne.
    logger.info("V2 batch rotated: %d -> %d",
                body.signer_batch_number, new_batch_number)
    return V2RotateBatchResponse(
        new_batch_number=new_batch_number,
        batch_size=ratchet_registry.BATCH_SIZE,
    )


# -----------------------------------------------------------------------------
# GET /auth/v2/status/{ed25519_pk} — REMOVED (audit 2026-06-27, R-SRV-1 / H-1)
# -----------------------------------------------------------------------------
# Do not add a status endpoint back, however handy one looks for debugging. This
# one took a long-term identity pk in the path (unauthenticated, only rate-
# limited) and returned enrolled_at / updated_at / consumed_count /
# batch_number / revoked: a network-reachable existence and activity oracle
# keyed by identity, which is exactly "prove a person used the app, and roughly
# when" — the thing the blind relay exists to deny. The app itself lost no
# feature when it went away.
#
# It was not free either, and that part is worth remembering. An earlier note
# here claimed get_status had no app caller in production; that was wrong
# (BT-05 cross-audit, 2026-06-30). `authenticateV2` probed it on every verify
# failure, to tell "the server forgot me" from "bad signature", so once the
# route was gone that probe 404'd and burned a second ratchet slot per failed
# auth until the client caught up. The Kotlin app no longer calls get_status —
# the verify-failure disambiguation now uses local pending-enrollment state —
# and the client plumbing (protocol.rs / ffi / udl get_status, getServerStatus,
# CLI `protocol_probe --pk`) was removed in the same sweep.


# -----------------------------------------------------------------------------
# POST /auth/v2/logout — révocation de JWT
# -----------------------------------------------------------------------------

@router.post("/logout")
@limiter.limit("10/minute")
async def logout_v2(request: Request, authorization: str = Header(...)):
    """
    Révoque le JWT passé en `Authorization: Bearer <token>`.

    Sert au device perdu ou volé : depuis un autre appareil (ou via curl), avec
    le token capturé, on le révoque tout de suite au lieu d'attendre les 24 h de
    l'`exp`.

    Le token entre dans la blacklist (cf. app/jwt_blacklist.py) avec son `exp`
    natif comme TTL, donc l'entrée disparaît d'elle-même une fois le JWT
    naturellement invalide : la liste ne grossit pas indéfiniment.

    204 No Content sur succès, et 204 aussi au second appel sur le même token —
    la route est idempotente, un client peut re-tenter sans se poser de
    question. 401 si le token est manquant, malformé, déjà expiré, ou de
    signature invalide.
    """
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing Bearer token")
    token = authorization[7:]

    # Vérifier la signature + exp avant d'accepter le revoke. On ne veut
    # pas qu'un attaquant puisse spammer la blacklist avec des tokens
    # arbitraires (ce serait un DoS sur la mémoire serveur).
    try:
        payload = pyjwt.decode(
            token, config.JWT_SECRET, algorithms=[config.JWT_ALGORITHM]
        )
    except pyjwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    exp = payload.get("exp")
    if not isinstance(exp, (int, float)) or exp <= time.time():
        # pyjwt a déjà rejeté un `exp` passé (401 ci-dessus) : il ne reste ici
        # qu'un token signé dont l'`exp` est absent ou non numérique. Rien à
        # blacklister, et 204 pour rester idempotent côté client.
        return Response(status_code=204)

    try:
        await asyncio.to_thread(jwt_blacklist.revoke, token, float(exp))
    except OSError:
        # The revocation must be durable: if the blacklist save fails, tell the
        # client to retry rather than return a false 204 that a container
        # restart would silently un-revoke (audit 2026-06-27, R-SRV-5).
        raise HTTPException(status_code=503, detail="Revocation not persisted, retry")
    # Jamais le `sub` (la pk d'identité) ; le ttl, lui, n'identifie personne.
    logger.info("Token revoked, remaining_ttl=%ds", int(exp - time.time()))
    return Response(status_code=204)
