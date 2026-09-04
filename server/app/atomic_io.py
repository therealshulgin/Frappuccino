"""
Écriture atomique des fichiers de state JSON : tmp → fsync → rename.

Ce helper lève l'OSError au lieu de logger et de continuer, et c'est le point
important du fichier, parce que le réflexe naturel sur une fonction de
sauvegarde est exactement l'inverse (`except OSError: pass`). Avalée pendant un
burst d'auth, une erreur disque laisse la mutation en mémoire sans contrepartie
sur le disque : le nonce que `verify_challenge` vient de consommer reste présent
dans le snapshot, revient frais après un crash, et la signature capturée se
rejoue le temps de son TTL de 60 s (BT-HIGH-13 rouvert à moitié). D'où le
fail-closed : l'appelant propage, la route répond 503, le client retente, et
personne n'opère sur un state que le disque n'a pas pris (audit Red R-M2).

Le fsync avant le rename garantit qu'un crash laisse un fichier complet plutôt
qu'un trou de 0 octet.

Les appelants async doivent passer par `asyncio.to_thread`. Le relais tourne en
`workers=1` — le cache de nonces est process-local —, donc un fsync + rename
synchrone sur l'event loop gèle TOUTES les requêtes le temps de l'I/O : burst
d'auth, drain de l'orphan sweep et chunk workers concurrents s'empilent alors
en stalls cascade (Blue HIGH-7/8).

Ce coût ne justifie pas pour autant de grouper les écritures : un appel = un
fichier écrit et renommé, pas de batching, pas de debounce. Chaque écriture doit
survivre individuellement à un crash, sinon la mutation en mémoire redevient
plus récente que le disque et la fenêtre de rejeu se rouvre — sans qu'aucune
OSError ne le signale, puisqu'il ne s'est rien passé.

Appelants : `auth._save_nonces_unlocked`, `jwt_blacklist._save_unlocked`,
`ratchet_registry._save`.
"""

import json
import logging
import os
import tempfile
from pathlib import Path
from typing import Any

logger = logging.getLogger("stream.atomic_io")


def atomic_json_save(
    path: Path | str,
    data: Any,
    indent: int | None = None,
) -> None:
    """Atomic write : tmp file → fsync → rename onto target.

    On OSError, propagate — do not log and carry on. The caller turns it into
    a 503 so the client retries; operating on state the disk never took is
    what lets a consumed nonce come back alive after a crash.

    Async callers must go through `await asyncio.to_thread(...)`, or the fsync
    and the rename block the event loop of the single worker.

    Holding a threading.Lock across this call is safe, and is not a deadlock:
    the lock is held inside the `to_thread` worker, not on the event loop.
    Releasing it before the save instead opens a window where the state on
    disk and the state in memory disagree.

    The parent directory is created if missing, `indent` is pretty-printing
    only (None = compact), and data that is not JSON-serializable raises
    TypeError.
    """
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    # mkstemp returns an OS file descriptor + a str path. Use the str
    # path for os.replace and the fd for the write loop. The temp file
    # sits next to the target so rename is atomic (same filesystem).
    fd, tmp_str = tempfile.mkstemp(
        dir=p.parent,
        prefix=p.name + ".",
        suffix=".tmp",
    )
    tmp = Path(tmp_str)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=indent)
            # Durability before rename : ensure the bytes are on disk
            # (not just in the page cache) so a crash after the rename
            # leaves a complete file, not a 0-byte hole. fsync is
            # blocking but worth the cost — this helper is meant for
            # state files where atomicity matters more than throughput.
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, p)
    except Exception:
        # Clean up the tmp file on any failure path so /state doesn't
        # accumulate orphan tmp files on repeated failures (e.g. disk
        # full, permission error).
        try:
            tmp.unlink(missing_ok=True)
        except OSError as cleanup_err:
            logger.warning(
                "atomic_json_save: failed to clean up tmp %s : %s",
                tmp, cleanup_err,
            )
        raise
