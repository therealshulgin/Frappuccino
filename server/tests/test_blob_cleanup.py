#!/usr/bin/env python3
"""
Tests unitaires de ``_cleanup_once``, avec le client MinIO stubbé (pas de MinIO
réel). Script autonome : ``python tests/test_blob_cleanup.py``.
"""

import os
import sys
import time
import tempfile
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

# Setup env BEFORE imports — JWT_SECRET requis sinon config.py exit(1)
os.environ["JWT_SECRET"] = "test-secret-do-not-use-in-prod"
_tmpdir = tempfile.mkdtemp()
os.environ["RATCHET_REGISTRY_FILE"] = os.path.join(_tmpdir, "registry.json")

from app import blob_cleanup, config, storage  # noqa: E402

passed = 0
failed = 0


def t(name, condition, detail=""):
    global passed, failed
    if condition:
        print(f"  [PASS] {name}")
        passed += 1
    else:
        print(f"  [FAIL] {name} ({detail})")
        failed += 1


def make_obj(name: str, age_seconds: float):
    """Construit un mock minio.Object avec une last_modified ago."""
    mock = MagicMock()
    mock.object_name = name
    mock.last_modified = datetime.now(timezone.utc) - timedelta(seconds=age_seconds)
    return mock


def run():
    print("[1] Pas de blobs = no-op")
    client_mock = MagicMock()
    client_mock.list_objects.return_value = []
    storage._client = client_mock
    deleted, kept = blob_cleanup._cleanup_once()
    t("0 deleted", deleted == 0)
    t("0 kept", kept == 0)
    t("remove_object pas appele", client_mock.remove_object.call_count == 0)

    print("\n[2] Blobs frais (< 24h) tous gardes")
    client_mock = MagicMock()
    client_mock.list_objects.return_value = [
        make_obj("report1/chunk_1.strm", 60),         # 1 min
        make_obj("report1/chunk_2.strm", 3600),       # 1h
        make_obj("report2/chunk_1.strm", 12 * 3600),  # 12h
    ]
    storage._client = client_mock
    deleted, kept = blob_cleanup._cleanup_once()
    t("3 kept", kept == 3)
    t("0 deleted", deleted == 0)
    t("remove_object pas appele", client_mock.remove_object.call_count == 0)

    print("\n[3] Blobs anciens (> 24h) supprimes")
    client_mock = MagicMock()
    client_mock.list_objects.return_value = [
        make_obj("report1/chunk_1.strm", 25 * 3600),   # 25h
        make_obj("report1/chunk_2.strm", 48 * 3600),   # 48h
        make_obj("report2/chunk_1.strm", 7 * 24 * 3600),  # 7j
    ]
    storage._client = client_mock
    deleted, kept = blob_cleanup._cleanup_once()
    t("3 deleted", deleted == 3)
    t("0 kept", kept == 0)
    t("remove_object appele 3x", client_mock.remove_object.call_count == 3)

    print("\n[4] Mix : seuls les > 24h supprimes")
    client_mock = MagicMock()
    client_mock.list_objects.return_value = [
        make_obj("report1/chunk_1.strm", 1 * 3600),      # 1h - keep
        make_obj("report1/chunk_2.strm", 25 * 3600),     # 25h - delete
        make_obj("report2/chunk_1.strm", 23.5 * 3600),   # 23.5h - keep (just below)
        make_obj("report2/chunk_2.strm", 36 * 3600),     # 36h - delete
    ]
    storage._client = client_mock
    deleted, kept = blob_cleanup._cleanup_once()
    t("2 deleted", deleted == 2)
    t("2 kept", kept == 2)
    # Vérifie qu'on a delete les BONS noms (pas seulement le bon count)
    deleted_names = {call.args[1] for call in client_mock.remove_object.call_args_list}
    t("delete_set contient les > 24h",
      deleted_names == {"report1/chunk_2.strm", "report2/chunk_2.strm"},
      detail=f"got {deleted_names}")

    print("\n[5] last_modified None → garde par defaut (safe)")
    client_mock = MagicMock()
    obj_no_modtime = MagicMock()
    obj_no_modtime.object_name = "weirdblob"
    obj_no_modtime.last_modified = None
    client_mock.list_objects.return_value = [obj_no_modtime]
    storage._client = client_mock
    deleted, kept = blob_cleanup._cleanup_once()
    t("0 deleted (last_modified None safe-guard)", deleted == 0)
    t("1 kept", kept == 1)

    print("\n[6] remove_object lance exception → log + continue")
    client_mock = MagicMock()
    client_mock.list_objects.return_value = [
        make_obj("report1/chunk_1.strm", 25 * 3600),
        make_obj("report1/chunk_2.strm", 48 * 3600),
    ]
    # Premier remove fail, second OK
    client_mock.remove_object.side_effect = [Exception("S3 error"), None]
    storage._client = client_mock
    deleted, kept = blob_cleanup._cleanup_once()
    t("1 deleted (le 2e), 1er fail compte pas", deleted == 1)

    print("\n[7] list_objects fail → no-op safe")
    client_mock = MagicMock()
    client_mock.list_objects.side_effect = Exception("MinIO down")
    storage._client = client_mock
    deleted, kept = blob_cleanup._cleanup_once()
    t("0 deleted sur list fail", deleted == 0)
    t("0 kept sur list fail", kept == 0)
    t("remove_object pas appele", client_mock.remove_object.call_count == 0)

    print(f"\n=== {'ALL GREEN' if failed == 0 else 'FAILED'} ===")
    print(f"    {passed}/{passed + failed} tests reussis")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(run())
