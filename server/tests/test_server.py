#!/usr/bin/env python3
"""
test_server.py — Tests unitaires du serveur STREAM (sans MinIO).

Teste la logique auth, JWT, et les modeles.
Pour les tests d'integration avec MinIO, utiliser docker-compose.

Dependance : pip install pynacl pyjwt
"""

import os
import sys
import time

# Add parent to path
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from app import auth
from app.models import AuthVerifyRequest

import nacl.bindings

passed = 0
failed = 0

def test(name, condition):
    global passed, failed
    if condition:
        print(f"  [PASS] {name}")
        passed += 1
    else:
        print(f"  [FAIL] {name}")
        failed += 1


def run_tests():
    global passed, failed

    print("=== STREAM Server — Unit Tests ===\n")

    # --- Test 1: JWT ---
    print("[1] JWT creation and verification")
    token = auth.create_jwt("test-subject")
    test("JWT created", len(token) > 0)

    payload = auth.verify_jwt(token)
    test("JWT verified", payload is not None)
    test("JWT subject correct", payload["sub"] == "test-subject")

    payload_bearer = auth.verify_jwt("Bearer " + token)
    test("JWT with Bearer prefix", payload_bearer is not None)

    test("Invalid JWT rejected", auth.verify_jwt("invalid-token") is None)
    print()

    # V2 : legacy login tests supprimés (/login/ removed in Phase 5).

    # --- Test 3: Ed25519 challenge-response ---
    print("[3] Ed25519 challenge-response")

    # Generate a keypair
    seed = os.urandom(32)
    ed_pk, ed_sk = nacl.bindings.crypto_sign_seed_keypair(seed)

    # Get challenge (S9-pre-audit pt2: returns nonce + server timestamp)
    nonce_hex, ts = auth.generate_challenge()
    test("Nonce generated", len(nonce_hex) == 64)
    test("Timestamp is recent", abs(int(time.time()) - ts) < 5)

    # Sign `nonce_bytes || ts_be_u64`
    nonce_bytes = bytes.fromhex(nonce_hex)
    ts_bytes = ts.to_bytes(8, "big", signed=False)
    message = nonce_bytes + ts_bytes
    signed = nacl.bindings.crypto_sign(message, ed_sk)
    signature = signed[:64]  # Ed25519 signature is first 64 bytes

    pk_hex = ed_pk.hex()
    sig_hex = signature.hex()

    # Verify
    result = auth.verify_challenge(pk_hex, nonce_hex, sig_hex, ts)
    test("Valid signature accepted", result)

    # Replay should fail (nonce consumed)
    result2 = auth.verify_challenge(pk_hex, nonce_hex, sig_hex, ts)
    test("Replay rejected", not result2)

    # Wrong signature
    nonce_hex2, ts2 = auth.generate_challenge()
    test("Wrong signature rejected",
         not auth.verify_challenge(pk_hex, nonce_hex2, "00" * 64, ts2))

    # Timestamp mismatch (client-provided ts differs from stored)
    nonce_hex4, ts4 = auth.generate_challenge()
    sig4 = nacl.bindings.crypto_sign(
        bytes.fromhex(nonce_hex4) + ts4.to_bytes(8, "big"), ed_sk
    )[:64].hex()
    test("Timestamp mismatch rejected",
         not auth.verify_challenge(pk_hex, nonce_hex4, sig4, ts4 + 1000))

    # Expired nonce
    nonce_hex3, ts3 = auth.generate_challenge()
    auth._nonce_cache[nonce_hex3] = {"ts": ts3, "expiry": time.time() - 1}
    signed3 = nacl.bindings.crypto_sign(
        bytes.fromhex(nonce_hex3) + ts3.to_bytes(8, "big"), ed_sk
    )
    test("Expired nonce rejected",
         not auth.verify_challenge(pk_hex, nonce_hex3, signed3[:64].hex(), ts3))
    print()

    # --- Test 6: Full auth flow ---
    # Audit 2026-06-29 — l'index V1 _authorized_keys (register_key) est retire :
    # la verif d'identite vit dans le ratchet registry, verify_challenge ne
    # consulte aucun index d'enrolement. L'ancien test "[4] Key registration"
    # (set _authorized_keys) est supprime ; ce flux teste challenge + verify +
    # JWT, la vraie surface.
    print("[6] Full Ed25519 auth flow")

    # Generate identity
    seed2 = os.urandom(32)
    pk2, sk2 = nacl.bindings.crypto_sign_seed_keypair(seed2)
    pk2_hex = pk2.hex()

    # Challenge
    nonce, ts = auth.generate_challenge()

    # Sign `nonce_bytes || ts_be_u64`
    signed_msg = nacl.bindings.crypto_sign(
        bytes.fromhex(nonce) + ts.to_bytes(8, "big"), sk2
    )
    sig = signed_msg[:64].hex()

    # Verify
    ok = auth.verify_challenge(pk2_hex, nonce, sig, ts)
    test("Challenge verified", ok)

    # Create JWT
    jwt_token = auth.create_jwt(pk2_hex)
    jwt_payload = auth.verify_jwt(jwt_token)
    test("JWT subject is public key", jwt_payload["sub"] == pk2_hex)
    print()

    # --- Summary ---
    total = passed + failed
    print(f"=== {'Tous les tests passent' if failed == 0 else f'{failed} ECHEC(S)'} ===")
    print(f"    {passed}/{total} tests reussis")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(run_tests())
