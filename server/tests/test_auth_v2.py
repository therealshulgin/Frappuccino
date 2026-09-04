#!/usr/bin/env python3
"""
test_auth_v2.py — Tests des endpoints V2 (ratchet registry + auth_v2 routes).

Requirements : pip install pynacl pyjwt fastapi httpx pytest
"""

import os
import sys
import time
import tempfile

# Add parent to path
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

# Redirect registry file to a temp location BEFORE importing anything that uses it
os.environ["JWT_SECRET"] = os.environ.get("JWT_SECRET") or "test-secret-do-not-use-in-prod"
os.environ["LEGACY_LOGIN_ENABLED"] = "false"
_tmpdir = tempfile.mkdtemp()
os.environ["RATCHET_REGISTRY_FILE"] = os.path.join(_tmpdir, "test_registry.json")

from app import ratchet_registry, auth  # noqa: E402
from app.routes import auth_v2 as auth_v2_routes  # noqa: E402
import nacl.bindings  # noqa: E402

passed = 0
failed = 0


def test(name, condition, detail=""):
    global passed, failed
    if condition:
        print(f"  [PASS] {name}")
        passed += 1
    else:
        print(f"  [FAIL] {name}  {detail}")
        failed += 1


def new_ed25519():
    seed = os.urandom(32)
    pk, sk = nacl.bindings.crypto_sign_seed_keypair(seed)
    return pk, sk


def generate_batch(batch_size=50):
    """Génère un batch de keypairs Ed25519."""
    return [new_ed25519() for _ in range(batch_size)]


def sign(sk: bytes, message: bytes) -> bytes:
    """Signature détachée Ed25519."""
    signed = nacl.bindings.crypto_sign(message, sk)
    return signed[:64]


def concat_pks(keypairs: list) -> bytes:
    """Concat les pk (32B chacune)."""
    return b"".join(kp[0] for kp in keypairs)


def run():
    global passed, failed

    print("=== V2 auth + ratchet registry — Unit Tests ===\n")

    # --- Test 1 : enroll ---
    print("[1] enroll()")
    ratchet_registry._clear_for_tests()
    identity_pk, identity_sk = new_ed25519()
    identity_pk_hex = identity_pk.hex()
    batch_0 = generate_batch()
    batch_0_pk_hex = [kp[0].hex() for kp in batch_0]

    # Concat batch_0 pks et signe avec identity_sk
    batch_0_concat = concat_pks(batch_0)
    batch_0_sig = sign(identity_sk, batch_0_concat)

    ok = ratchet_registry.enroll(identity_pk_hex, batch_0_pk_hex, batch_0_sig.hex())
    test("enroll retourne True", ok)
    test("identité existe", ratchet_registry.exists(identity_pk_hex))

    # Re-enroll doit échouer
    ok2 = ratchet_registry.enroll(identity_pk_hex, batch_0_pk_hex, batch_0_sig.hex())
    test("re-enroll refusé", not ok2)

    entry = ratchet_registry.get(identity_pk_hex)
    test("batch_number initial = 0", entry["batch_number"] == 0)
    test("50 clés publiques stockées", len(entry["batch_keys"]) == 50)
    test("consumed_indices vide", len(entry["consumed_indices"]) == 0)
    print()

    # --- Test 2 : signature valide du batch_0 ---
    print("[2] verify_ed25519_sig (helper)")
    test("batch_0 signé par identité",
         auth_v2_routes._verify_ed25519_sig(
             identity_pk_hex, batch_0_concat, batch_0_sig.hex()))
    test("mauvaise sig rejetée",
         not auth_v2_routes._verify_ed25519_sig(
             identity_pk_hex, batch_0_concat, "00" * 64))
    # message altéré
    test("message altéré rejeté",
         not auth_v2_routes._verify_ed25519_sig(
             identity_pk_hex, batch_0_concat + b"\x01", batch_0_sig.hex()))
    print()

    # --- Test 3 : is_ephemeral_key_valid ---
    print("[3] is_ephemeral_key_valid")
    ephem_pk_0 = batch_0_pk_hex[0]
    test("slot 0 valide",
         ratchet_registry.is_ephemeral_key_valid(identity_pk_hex, 0, 0, ephem_pk_0))
    test("mauvais batch_number rejeté",
         not ratchet_registry.is_ephemeral_key_valid(identity_pk_hex, 1, 0, ephem_pk_0))
    test("index hors-borne rejeté",
         not ratchet_registry.is_ephemeral_key_valid(identity_pk_hex, 0, 50, ephem_pk_0))
    test("mauvaise ephemeral_pk rejetée",
         not ratchet_registry.is_ephemeral_key_valid(identity_pk_hex, 0, 0, "00" * 32))
    test("identité inconnue rejetée",
         not ratchet_registry.is_ephemeral_key_valid("ff" * 32, 0, 0, ephem_pk_0))
    print()

    # --- Test 4 : consume_ephemeral_key ---
    print("[4] consume_ephemeral_key")
    test("consommation slot 0 OK",
         ratchet_registry.consume_ephemeral_key(identity_pk_hex, 0, 0))
    test("slot 0 maintenant invalide",
         not ratchet_registry.is_ephemeral_key_valid(identity_pk_hex, 0, 0, ephem_pk_0))
    test("double-consommation rejetée",
         not ratchet_registry.consume_ephemeral_key(identity_pk_hex, 0, 0))
    test("slot 1 toujours valide",
         ratchet_registry.is_ephemeral_key_valid(identity_pk_hex, 0, 1, batch_0_pk_hex[1]))

    entry2 = ratchet_registry.get(identity_pk_hex)
    test("consumed_indices contient 0", 0 in entry2["consumed_indices"])
    test("49 slots restants", len(entry2["consumed_indices"]) == 1)
    print()

    # --- Test 5 : rotate_batch ---
    print("[5] rotate_batch")
    # On va rotater en utilisant le slot 49
    batch_1 = generate_batch()
    batch_1_pk_hex = [kp[0].hex() for kp in batch_1]
    batch_1_concat = concat_pks(batch_1)

    # Signe batch_1 avec la clé secrète du slot 49 de batch_0
    signer_sk = batch_0[49][1]
    batch_1_sig = sign(signer_sk, batch_1_concat)

    new_batch_number = ratchet_registry.rotate_batch(
        identity_pk_hex,
        signer_batch_number=0,
        signer_key_index=49,
        new_batch_keys=batch_1_pk_hex,
        new_batch_signature_hex=batch_1_sig.hex(),
    )
    test("rotation retourne 1", new_batch_number == 1)

    entry3 = ratchet_registry.get(identity_pk_hex)
    test("batch_number = 1", entry3["batch_number"] == 1)
    test("batch_keys = batch_1", entry3["batch_keys"] == batch_1_pk_hex)
    test("consumed_indices fresh (vide)", len(entry3["consumed_indices"]) == 0)
    # On peut maintenant consommer slot 0 du batch_1
    test("slot 0 du batch_1 valide",
         ratchet_registry.is_ephemeral_key_valid(identity_pk_hex, 1, 0, batch_1_pk_hex[0]))
    # L'ancien batch ne peut plus être utilisé
    test("slot 1 du batch_0 invalide (mauvais batch_number)",
         not ratchet_registry.is_ephemeral_key_valid(identity_pk_hex, 0, 1, batch_0_pk_hex[1]))
    print()

    # --- Test 6 : rotate avec slot déjà consommé ---
    print("[6] rotate avec slot déjà consommé")
    ratchet_registry.consume_ephemeral_key(identity_pk_hex, 1, 5)
    fake_batch = generate_batch()
    fake_concat = concat_pks(fake_batch)
    fake_sig = sign(batch_1[5][1], fake_concat)  # Slot 5 consommé
    result = ratchet_registry.rotate_batch(
        identity_pk_hex, 1, 5, [kp[0].hex() for kp in fake_batch], fake_sig.hex()
    )
    test("rotation avec slot consommé rejetée", result is None)
    print()

    # --- Test 7 : revoke ---
    print("[7] revoke")
    test("revoke OK", ratchet_registry.revoke(identity_pk_hex))
    test("identité révoquée n'accepte plus de signatures",
         not ratchet_registry.is_ephemeral_key_valid(identity_pk_hex, 1, 10, batch_1_pk_hex[10]))
    print()

    # --- Test 8 : persistance JSON (round-trip load/save) ---
    print("[8] persistence")
    ratchet_registry._clear_for_tests()
    id2_pk, id2_sk = new_ed25519()
    id2_pk_hex = id2_pk.hex()
    b0 = generate_batch()
    b0_hex = [kp[0].hex() for kp in b0]
    sig0 = sign(id2_sk, concat_pks(b0)).hex()
    ratchet_registry.enroll(id2_pk_hex, b0_hex, sig0)
    ratchet_registry.consume_ephemeral_key(id2_pk_hex, 0, 10)

    # Force reload depuis le fichier
    ratchet_registry._registry = {}
    ratchet_registry._load()
    entry_r = ratchet_registry.get(id2_pk_hex)
    test("identité rechargée", entry_r is not None)
    test("batch_keys préservé après reload", entry_r["batch_keys"] == b0_hex)
    test("consumed_indices préservé", 10 in entry_r["consumed_indices"])
    print()

    # --- Test 9 : flow complet via auth_v2._verify_ed25519_sig ---
    print("[9] flow complet signature challenge")
    ratchet_registry._clear_for_tests()
    user_pk, user_sk = new_ed25519()
    user_pk_hex = user_pk.hex()
    bk = generate_batch()
    bk_hex = [kp[0].hex() for kp in bk]
    bk_sig = sign(user_sk, concat_pks(bk)).hex()
    ratchet_registry.enroll(user_pk_hex, bk_hex, bk_sig)

    # Simule un challenge (S9-pre-audit pt2 : le nonce est lié à un timestamp)
    nonce = os.urandom(32)
    nonce_hex = nonce.hex()
    ts = int(time.time())
    auth._nonce_cache[nonce_hex] = {"ts": ts, "expiry": time.time() + 60}
    ts_bytes = ts.to_bytes(8, "big", signed=False)
    message = nonce + ts_bytes

    # Signe `nonce || ts_be_u64` avec la clé éphémère du slot 0
    ephem_sk = bk[0][1]
    ephem_pk_hex = bk[0][0].hex()
    sig = sign(ephem_sk, message).hex()

    # Vérifie la signature éphémère comme le ferait /auth/v2/verify
    valid = auth_v2_routes._verify_ed25519_sig(ephem_pk_hex, message, sig)
    test("signature éphémère du nonce||ts OK", valid)
    test("slot 0 valide avant conso",
         ratchet_registry.is_ephemeral_key_valid(user_pk_hex, 0, 0, ephem_pk_hex))
    ratchet_registry.consume_ephemeral_key(user_pk_hex, 0, 0)
    test("slot 0 invalide après conso",
         not ratchet_registry.is_ephemeral_key_valid(user_pk_hex, 0, 0, ephem_pk_hex))

    # Rejeu même nonce : l'attaquant aurait la signature mais le nonce serait consommé
    # côté auth._nonce_cache dans le flow réel. Ici on teste just que le slot est consommé.
    test("consommation double rejetée",
         not ratchet_registry.consume_ephemeral_key(user_pk_hex, 0, 0))
    print()

    # --- Summary ---
    total = passed + failed
    print(f"=== {'Tous les tests passent' if failed == 0 else f'{failed} ECHEC(S)'} ===")
    print(f"    {passed}/{total} tests réussis")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(run())
