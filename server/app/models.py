from pydantic import BaseModel, Field
from typing import Optional, Annotated


# Alias hexadécimaux typés des clés publiques et signatures du protocole V2.
#
# Le `[a-f0-9]` est strictement lowercase, et ce n'est pas cosmétique : le
# registre ratchet indexe les identités par la chaîne hex brute
# (`_registry[ed25519_pk_hex]`), sans normalisation nulle part. Élargir la regex
# en `[a-fA-F0-9]`, réflexe naturel de tolérance sur l'entrée, ferait exister la
# même clé publique sous deux entrées de registre distinctes, donc deux batchs de
# slots éphémères pour une seule identité. La casse est fixée côté Rust
# (crypto-rs/core/src/identity.rs).
#
# Valider au schema plutôt qu'endpoint par endpoint évite de dupliquer la regex
# et rend le 422 automatique.

Hex64 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$", min_length=64, max_length=64)]
Hex128 = Annotated[str, Field(pattern=r"^[a-f0-9]{128}$", min_length=128, max_length=128)]


# --- Auth models ---

# V2 : LoginRequest (username/password) supprimé.


class ChallengeResponse(BaseModel):
    nonce: Hex64
    # S9-pre-audit pt2 : Unix seconds stamped by the server at nonce creation.
    # The client MUST sign `nonce_bytes || timestamp_BE_u64` rather than the
    # raw nonce — the server verifies the binding + enforces a ±30 s tolerance
    # window on /auth/v2/verify.
    timestamp: int


class AuthVerifyRequest(BaseModel):
    ed25519_pk: Hex64
    nonce: Hex64
    # S9-pre-audit pt2 : legacy V1 path aussi exige le timestamp. Aucun
    # client V1 n'est en service, mais on garde le point d'entrée cohérent
    # avec /auth/v2/verify — pas de chemin silencieusement plus permissif.
    timestamp: int
    signature: Hex128


# Phase C (relay-blind reports) — ArchiveAuthRequest/Response REMOVED with the
# POST /api/v2/archive/auth endpoint. Archive reads are identity-free (no token,
# no long-term Ed25519 challenge); see app/routes/archive.py.


class LoginResponse(BaseModel):
    access_token: str
    user: Optional[dict] = None


# --- V2 ephemeral ratchet auth models ---

class V2EnrollRequest(BaseModel):
    """Payload d'enrôlement V2 depuis le device."""
    ed25519_pk: Hex64                       # 64 hex chars — identité long-terme publique
    batch_0_public_keys: list[Hex64]        # 50 × 64 hex chars — clés éphémères publiques batch_0
    batch_0_signature: Hex128               # 128 hex chars — Ed25519(ed25519_sk, concat(batch_0_pks))


class V2EnrollResponse(BaseModel):
    enrolled: bool
    ed25519_pk: Hex64
    batch_number: int


class V2VerifyRequest(BaseModel):
    """Challenge-response V2 avec clé éphémère."""
    ed25519_pk: Hex64                       # identité long-terme
    ephemeral_pk: Hex64                     # 64 hex chars — clé du slot consommé
    batch_number: int
    key_index: int                          # 0..49
    nonce: Hex64                            # 64 hex chars — reçu via /auth/challenge
    # S9-pre-audit pt2 : le serveur impose |now - timestamp| ≤ 30 s et la
    # signature couvre `nonce_bytes || timestamp_BE_u64`.
    timestamp: int
    signature: Hex128                       # 128 hex chars — Ed25519(ephemeral_sk, nonce||timestamp_be)


class V2RotateBatchRequest(BaseModel):
    """Rotation de batch : batch_{N+1} signé par une clé du batch_N."""
    ed25519_pk: Hex64
    signer_batch_number: int                # batch_N actuel
    signer_key_index: int                   # slot consommé par la rotation
    signer_public_key: Hex64                # 64 hex chars — sanity check (doit matcher batch_keys[signer_key_index])
    new_batch_public_keys: list[Hex64]      # 50 × 64 hex chars
    new_batch_signature: Hex128             # 128 hex chars


class V2RotateBatchResponse(BaseModel):
    new_batch_number: int
    batch_size: int


# V2IdentityStatusResponse REMOVED (audit 2026-06-27, R-SRV-1): it backed the
# GET /auth/v2/status/{pk} identity-activity oracle, now removed from auth_v2.py.

# --- Report models ---
#
# Phase C (relay-blind reports) — ReportBody / Author / ReportResponse REMOVED
# with the create_report endpoint. Reports are created lazily at the first chunk
# PUT (app/routes/upload.py); the relay stores only `report_id -> report_pk`,
# never a title, author, or createdAt.

# ProjectResponse REMOVED (2026-09-03): it was the response model of the two
# Tella compat routes `GET /p/{slug}` and `GET /{slug}`, which had no caller and
# were removed with it (app/routes/reports.py).
