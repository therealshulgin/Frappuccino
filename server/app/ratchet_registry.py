"""
ratchet_registry.py — Registre V2 des identités et de leur batch éphémère.

Rien ici ne doit dater l'activité d'une identité. C'est pour ça que
`enrolled_at` / `updated_at` ont été retirés (F-C4 / WP-A4) : aucun chemin ne
les lisait — l'oracle de status qui les exposait est parti avec R-SRV-1 — et
sur un relais saisi, deux horodatages par identité suffisent à dresser une
courbe de présence par témoin. C'est typiquement le champ qu'on rajoute pour
l'ops ou pour trier ; les entrées étant persistées, la régression serait
invisible et définitive. Même raison pour l'historique des compteurs de
création (M-2).

Ce qu'on garde par identité, et rien de plus :
  - Numéro de batch courant (incrementé à chaque rotation)
  - 50 clés publiques du batch courant
  - Indices consommés (set, strictement croissant au fil des signatures)
  - Signature du batch (par ed25519_sk au setup, ou par batch_{N-1}[i] à la rotation)
  - Compteur de créations de rapports du batch courant
    ({batch_number → compteur}, remis à zéro à la rotation)
  - Métadonnées : revoked

Verrou global et persistance JSON atomique, avec réécriture du fichier entier à
chaque mutation : c'est dimensionné pour le volume d'une démo, pas au-delà.
Passer à l'échelle voudrait dire une base avec un verrou par ligne, une ligne
par identité.
"""

import json
import logging
import os
from pathlib import Path
from threading import Lock
from typing import Optional

from app.atomic_io import atomic_json_save

logger = logging.getLogger("stream.ratchet_registry")

BATCH_SIZE = 50

_REGISTRY_FILE = Path(os.getenv("RATCHET_REGISTRY_FILE", ".ratchet_registry.json"))
_lock = Lock()
_registry: dict[str, dict] = {}


class RatchetError(Exception):
    """Erreur de logique du ratchet registry (identité inconnue, index consommé, etc.)."""


def _load():
    global _registry
    if not _REGISTRY_FILE.exists():
        _registry = {}
        return
    try:
        _registry = json.loads(_REGISTRY_FILE.read_text())
        # Convert consumed_indices from list to set for fast membership checks
        for k, v in _registry.items():
            v["consumed_indices"] = set(v.get("consumed_indices", []))
        logger.info("Loaded ratchet registry: %d identities", len(_registry))
    except Exception as e:
        logger.warning("Failed to load ratchet registry, starting empty: %s", e)
        _registry = {}


def _save():
    """Persiste le registre (set → list pour JSON).

    Call this from `asyncio.to_thread`, never straight from a coroutine: the
    fsync + rename blocks for the whole disk write and the relay runs a single
    worker (see main.py), so a direct call freezes it.

    On OSError it raises instead of swallowing, and callers must turn that into
    a 503 so the client retries (Blue Team HIGH-8). Swallowing would let the
    in-memory registry diverge from disk, which means a consumed ephemeral index
    or a `revoked=True` can fail to survive a restart — a ratchet notch
    replayed, an identity back from revocation. What divergence remains is
    bounded and needs no reconciliation machinery: the next successful mutation
    rewrites the whole file.
    """
    serializable = {}
    for k, v in _registry.items():
        entry = dict(v)
        entry["consumed_indices"] = sorted(list(entry["consumed_indices"]))
        serializable[k] = entry
    atomic_json_save(_REGISTRY_FILE, serializable, indent=2)


_load()


def exists(ed25519_pk_hex: str) -> bool:
    """True si l'identité est enrôlée."""
    with _lock:
        return ed25519_pk_hex in _registry


def get(ed25519_pk_hex: str) -> Optional[dict]:
    """Retourne une COPIE de l'état de l'identité, ou None."""
    with _lock:
        entry = _registry.get(ed25519_pk_hex)
        if not entry:
            return None
        copy = dict(entry)
        copy["consumed_indices"] = set(copy["consumed_indices"])
        return copy


def enroll(
    ed25519_pk_hex: str,
    batch_0_keys: list[str],
    batch_0_signature_hex: str,
) -> bool:
    """
    Enrôle une nouvelle identité avec son batch_0.

    Retourne False si l'identité existe déjà. True sur succès.
    Ne vérifie PAS la signature — l'appelant doit le faire avant d'invoquer enroll().
    """
    assert len(batch_0_keys) == BATCH_SIZE, f"Expected {BATCH_SIZE} batch keys"
    with _lock:
        if ed25519_pk_hex in _registry:
            return False
        _registry[ed25519_pk_hex] = {
            "ed25519_pk": ed25519_pk_hex,
            "batch_number": 0,
            "batch_keys": list(batch_0_keys),
            "consumed_indices": set(),
            "batch_signature": batch_0_signature_hex,
            "revoked": False,
        }
        _save()
    # Phase C log scrub — no pk in the container logs.
    logger.info("Enrolled new V2 identity")
    return True


def is_ephemeral_key_valid(
    ed25519_pk_hex: str,
    batch_number: int,
    key_index: int,
    ephemeral_pk_hex: str,
) -> bool:
    """
    Vérifie que la clé éphémère est utilisable, sans la consommer.

    La consommation vient après, une fois la signature vérifiée, dans
    `consume_ephemeral_key`. Fondre les deux en un seul check-and-burn
    permettrait de brûler des slots sur des signatures bidon, à qui connaît déjà
    la pk d'identité de la cible et les pk de son batch courant : la
    consommation ne doit jamais précéder la vérification de signature.

    Toutes les conditions d'appartenance sont fusionnées en un seul booléen,
    pour que `/auth/v2/verify` réponde un 401 unique quelle qu'ait été la cause.
    """
    with _lock:
        entry = _registry.get(ed25519_pk_hex)
        if not entry:
            return False
        if entry.get("revoked"):
            return False
        if entry["batch_number"] != batch_number:
            return False
        if not (0 <= key_index < BATCH_SIZE):
            return False
        if key_index in entry["consumed_indices"]:
            return False
        if entry["batch_keys"][key_index] != ephemeral_pk_hex:
            return False
        return True


def is_rotation_signer_valid(
    ed25519_pk_hex: str,
    signer_batch_number: int,
    signer_key_index: int,
    signer_public_key_hex: str,
) -> bool:
    """
    Vérifie que le signataire de rotation est un slot valide du batch COURANT,
    sans rien consommer ni muter. Miroir de :func:`is_ephemeral_key_valid` pour
    le chemin de rotation.

    Le booléen opaque est délibéré : ne jamais renvoyer d'ici la cause de
    l'échec, pour que `/auth/v2/rotate-batch` réponde un 401 unique et constant
    quel que soit l'état (inconnu, révoqué, mauvais batch, index déjà consommé,
    pk de slot qui ne correspond pas). Brancher sur l'état faisait de la route
    un oracle d'existence et d'activité par identité — le corps du 409 rendait
    même le `batch_number` serveur —, exactement ce que le retrait de
    `get_status` (R-SRV-1 / BT-05) visait à supprimer. Des « messages d'erreur
    utiles » (404 identité inconnue, 403 révoquée, 409 mauvais batch)
    rouvriraient cet oracle en croyant améliorer l'ergonomie.
    """
    with _lock:
        entry = _registry.get(ed25519_pk_hex)
        if not entry:
            return False
        if entry.get("revoked"):
            return False
        if entry["batch_number"] != signer_batch_number:
            return False
        if not (0 <= signer_key_index < BATCH_SIZE):
            return False
        if signer_key_index in entry["consumed_indices"]:
            return False
        if entry["batch_keys"][signer_key_index] != signer_public_key_hex:
            return False
        return True


def consume_ephemeral_key(
    ed25519_pk_hex: str,
    batch_number: int,
    key_index: int,
) -> bool:
    """
    Marque une clé éphémère comme consommée.
    Appelé APRÈS que la signature soit vérifiée.

    Retourne True si la consommation a réussi (l'identité existe et le batch matche),
    False sinon (ex : identité non trouvée, mauvais batch, déjà consommé).
    """
    with _lock:
        entry = _registry.get(ed25519_pk_hex)
        if not entry:
            return False
        if entry.get("revoked"):
            return False
        if entry["batch_number"] != batch_number:
            return False
        if key_index in entry["consumed_indices"]:
            return False
        entry["consumed_indices"].add(key_index)
        _save()
        return True


def rotate_batch(
    ed25519_pk_hex: str,
    signer_batch_number: int,
    signer_key_index: int,
    new_batch_keys: list[str],
    new_batch_signature_hex: str,
) -> Optional[int]:
    """
    Avance vers batch_{N+1}.

    Cette fonction ne vérifie AUCUNE signature : c'est à l'appelant de le faire
    avant, avec `batch_keys[signer_key_index]` comme clé publique. Les contrôles
    d'état qu'elle enchaîne ensuite donnent l'illusion d'une validation
    complète ; s'y fier laisserait n'importe qui faire tourner le batch d'une
    identité tierce, donc prendre la main sur son ratchet.

    Retourne le nouveau batch_number sur succès, None sinon.
    """
    assert len(new_batch_keys) == BATCH_SIZE
    with _lock:
        entry = _registry.get(ed25519_pk_hex)
        if not entry:
            return None
        if entry.get("revoked"):
            return None
        if entry["batch_number"] != signer_batch_number:
            return None
        if signer_key_index in entry["consumed_indices"]:
            return None
        # Consomme implicitement la clé signataire du batch précédent
        entry["consumed_indices"].add(signer_key_index)
        # Avance vers nouveau batch
        new_batch_number = signer_batch_number + 1
        entry["batch_number"] = new_batch_number
        entry["batch_keys"] = list(new_batch_keys)
        entry["consumed_indices"] = set()  # fresh
        # Audit 2026-06-27 (M-2) — drop the previous batch's report-creation
        # counter(s). Only the CURRENT batch's count is ever read (the budget
        # gate), and a fresh batch starts at 0; keeping the historical
        # {batch -> count} dict would accumulate a dated per-identity activity
        # curve at rest for zero anti-abuse benefit, so clear it like
        # consumed_indices.
        entry["report_creations"] = {}
        entry["batch_signature"] = new_batch_signature_hex
        _save()
        # Phase C log scrub — no pk; batch numbers are non-identifying.
        logger.info("Rotated batch: %d -> %d", signer_batch_number, new_batch_number)
        return new_batch_number


def reserve_report_creation(ed25519_pk_hex: str, max_per_batch: int) -> bool:
    """Reserve one creation slot on the identity's current batch, atomically
    (anti-abuse D1).

    The check and the increment must stay inside the SAME lock acquisition. The
    former split — peek through `can_create_report`, commit later through
    `note_report_creation` — had a check-vs-commit TOCTOU (R-SRV-3): under the
    single async worker, the body stream and the `to_thread` store sat between
    the two halves, so concurrent creating PUTs for the same (identity, batch)
    all read `count < max` before any of them had committed and the cap was
    soft. Under one lock, reservations serialize and the cap is a hard wall.

    What we keep is a count per `batch_number` (gross activity), never a
    report↔identity map: the creating PUT carries a valid stream JWT (proof of
    enrollment) whose subject is passed here once, then discarded by the caller.
    Logging which identity created which report is the natural shape of this
    feature, and it is exactly what we refuse — same residual class as
    `consumed_indices`.

    Pairs with :func:`release_report_creation`: the upload path reserves here
    before the stream/store and releases (decrements) if the upload then fails
    to produce a durable record (stream error, 507, 409, invalid write-sig,
    exception), so the count still equals the number of reports actually created
    and a failed upload does not burn budget.

    Returns True (and reserves) if within budget; False if the current batch's
    budget is exhausted, the identity is unknown (not enrolled), or revoked.
    Never raises beyond a persistence OSError.
    """
    with _lock:
        entry = _registry.get(ed25519_pk_hex)
        if not entry or entry.get("revoked"):
            return False
        batch_key = str(entry["batch_number"])  # JSON object keys are strings
        counts = entry.setdefault("report_creations", {})
        current = int(counts.get(batch_key, 0))
        if current >= max_per_batch:
            return False
        counts[batch_key] = current + 1
        _save()
        return True


def release_report_creation(ed25519_pk_hex: str) -> None:
    """Roll back one reserved creation slot on the identity's current batch.

    Called when an upload that reserved a slot through
    :func:`reserve_report_creation` fails before its record is durable
    (R-SRV-3), so a failed creation does not burn budget.

    The no-op when the batch has moved on is deliberate, not an oversight: a
    concurrent `rotate_batch` clears the per-batch counters, so an in-flight
    reservation on a batch we have left is moot. "Fixing" it by decrementing
    some other batch would falsify the current batch's count. Raises only a
    persistence OSError.
    """
    with _lock:
        entry = _registry.get(ed25519_pk_hex)
        if not entry:
            return
        batch_key = str(entry["batch_number"])
        counts = entry.get("report_creations")
        if not counts:
            return
        current = int(counts.get(batch_key, 0))
        if current <= 0:
            return
        counts[batch_key] = current - 1
        _save()


def can_create_report(ed25519_pk_hex: str, max_per_batch: int) -> bool:
    """Read-only peek at the per-(identity, batch) creation budget: no
    increment, no ``_save`` (anti-abuse D1).

    Do NOT use this as the gate before a creation, however inviting the name is.
    Being side-effect-free, it reopens the check-vs-commit TOCTOU that R-SRV-3
    closed, and the per-batch cap goes soft again under concurrent requests. The
    real gate is :func:`reserve_report_creation`, rolled back by
    :func:`release_report_creation`. What is left here is introspection: tests,
    read-only status.

    True iff a creation is currently within budget; False if the current batch's
    budget is exhausted, the identity is unknown, or revoked.
    """
    with _lock:
        entry = _registry.get(ed25519_pk_hex)
        if not entry or entry.get("revoked"):
            return False
        batch_key = str(entry["batch_number"])
        counts = entry.get("report_creations", {})
        return int(counts.get(batch_key, 0)) < max_per_batch


def revoke(ed25519_pk_hex: str) -> bool:
    """Marque une identité comme révoquée dans le ratchet registry.

    Marquer l'entrée ici suffit : tous les chemins qui accordent quelque chose
    refusent une identité `revoked=True` — `is_ephemeral_key_valid`,
    `is_rotation_signer_valid`, `consume_ephemeral_key`, `rotate_batch`,
    `reserve_report_creation` et `can_create_report`. Pas besoin d'ajouter un
    second état « par sécurité » — il n'y en a justement plus : la fonction
    retirait aussi la pk de l'index V1 `_authorized_keys` (Red Team R-H3),
    index supprimé depuis parce que write-only et redondant avec ce registre,
    donc plus rien à désynchroniser.

    Retourne True si l'identité existait et a été marquée, False sinon.
    """
    with _lock:
        entry = _registry.get(ed25519_pk_hex)
        if not entry:
            return False
        entry["revoked"] = True
        _save()
    # Phase C log scrub — no pk; the revocation event is enough.
    logger.warning("Revoked identity (ratchet=revoked)")
    return True


def stats() -> dict:
    """Stats publics (pour /health ou /admin)."""
    with _lock:
        total = len(_registry)
        revoked = sum(1 for e in _registry.values() if e.get("revoked"))
        return {
            "total_identities": total,
            "revoked": revoked,
            "active": total - revoked,
        }


# Test helpers — NON destinés à la production
def _clear_for_tests():
    """À utiliser uniquement dans les tests."""
    with _lock:
        _registry.clear()
