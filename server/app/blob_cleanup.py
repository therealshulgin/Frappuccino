"""
Purge périodique des blobs MinIO. Un blob y reste le temps que le témoin le
rapatrie en mode archive, puis disparaît au-delà du TTL de rétention
(`config.BLOB_TTL_SECONDS`, réglable via `ARCHIVE_BLOB_TTL_SECONDS`).

Le TTL par défaut est de 6 mois, et ce n'est pas un durcissement oublié : il
est passé de 24 h à 6 mois délibérément. Les blobs STRM sont chiffrés E2E et
restent inexploitables sans les clés dérivées de la phrase BIP-39, qui ne
quittent jamais le client — un serveur saisi ne rend que du ciphertext, quelle
que soit l'ancienneté des sessions, donc une rétention longue n'augmente pas le
risque réel. Un TTL court, lui, casse le terrain : sur réseau intermittent en
déplacement, le rapatriement peut largement dépasser 24 h, et le 2026-05-21 une
session sous mauvaise couverture train a perdu 39 % de ses chunks faute d'avoir
pu drainer sa queue d'upload. Resserrer cette valeur en croyant durcir se paie
en témoignages perdus.

Pas de flag « in_use », parce qu'il n'y a rien à protéger :
- `put_object` MinIO est atomique. Un blob en cours d'upload n'apparaît pas
  dans `list_objects` tant que le put n'est pas committé, donc le cleanup ne
  peut ni voir un blob à moitié uploadé, ni supprimer sous un PUT en cours.
- Si le cleanup supprime une clé, elle redevient simplement libre et un PUT
  ultérieur sur ce nom repart en « created »
  (`storage.upload_blob_stream_write_once`).
- Le relais tourne en `workers=1` : pas de concurrence inter-process. La passe
  tourne en revanche bel et bien en parallèle des uploads, `_cleanup_once`
  étant exécuté via `asyncio.to_thread`.

La purge effective tombe dans une fenêtre de ± CLEANUP_INTERVAL_SECONDS autour
du TTL, ce qui est indolore à 6 mois. Resserrer l'intervalle ne gagne que cette
précision, et fait relister le bucket entier d'autant plus souvent.
"""
from __future__ import annotations

import asyncio
import logging
import time
from app import config, storage

logger = logging.getLogger("stream.blob_cleanup")

CLEANUP_INTERVAL_SECONDS = 3600          # 1h entre 2 ticks
BLOB_TTL_SECONDS = config.BLOB_TTL_SECONDS  # défaut 6 mois, cf. config.py


async def cleanup_loop() -> None:
    """
    Boucle périodique. Appelée comme background task depuis main.py
    `lifespan`. Termine proprement quand la task est cancelled (shutdown
    serveur).
    """
    logger.info(
        "Blob cleanup loop starting (interval=%ds, ttl=%ds)",
        CLEANUP_INTERVAL_SECONDS, BLOB_TTL_SECONDS,
    )
    while True:
        try:
            await asyncio.to_thread(_cleanup_once)
        except asyncio.CancelledError:
            logger.info("Blob cleanup loop cancelled, exiting")
            raise
        except Exception:
            # On log mais on ne raise pas — pour qu'une erreur transient
            # MinIO (network blip, etc.) ne tue pas la task pour de bon.
            logger.exception("Cleanup tick failed, will retry next interval")
        try:
            await asyncio.sleep(CLEANUP_INTERVAL_SECONDS)
        except asyncio.CancelledError:
            logger.info("Blob cleanup loop cancelled during sleep, exiting")
            raise


def _cleanup_once() -> tuple[int, int]:
    """
    Une passe de cleanup. Retourne `(deleted, kept)`.

    Synchrone (utilise le client MinIO sync). Appelé depuis cleanup_loop
    via `asyncio.to_thread` pour ne pas bloquer l'event loop.
    """
    client = storage.get_client()
    cutoff = time.time() - BLOB_TTL_SECONDS
    deleted = 0
    kept = 0
    failed = 0

    try:
        objects = list(client.list_objects(config.MINIO_BUCKET, recursive=True))
    except Exception:
        logger.exception("Failed to list bucket %s", config.MINIO_BUCKET)
        return (0, 0)

    for obj in objects:
        # `obj.last_modified` est un datetime UTC (avec tz). On convertit en
        # epoch pour comparer avec cutoff.
        if obj.last_modified is None:
            kept += 1
            continue
        last_mod_ts = obj.last_modified.timestamp()
        if last_mod_ts < cutoff:
            try:
                client.remove_object(config.MINIO_BUCKET, obj.object_name)
                deleted += 1
            except Exception:
                logger.exception("Failed to delete %s", obj.object_name)
                failed += 1
        else:
            kept += 1

    if deleted or kept or failed:
        logger.info(
            "Blob cleanup tick complete (deleted=%d, kept=%d, failed=%d)",
            deleted, kept, failed,
        )
    return (deleted, kept)
