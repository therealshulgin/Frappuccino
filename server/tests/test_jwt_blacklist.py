#!/usr/bin/env python3
"""
Tests unitaires de app/jwt_blacklist.py et de son effet sur auth.verify_jwt ;
le endpoint /auth/v2/logout n'est pas exercé ici.

Script `__main__`, pas pytest, comme test_auth_v2.py / test_e2e_v2.py :
    python tests/test_jwt_blacklist.py
"""

import os
import sys
import time
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

# Setup env BEFORE imports
os.environ["JWT_SECRET"] = "test-secret-do-not-use-in-prod"
_tmpdir = tempfile.mkdtemp()
os.environ["JWT_BLACKLIST_FILE"] = os.path.join(_tmpdir, "test_blacklist.json")
os.environ["RATCHET_REGISTRY_FILE"] = os.path.join(_tmpdir, "test_registry.json")

import jwt as pyjwt  # noqa: E402
from app import auth, config, jwt_blacklist  # noqa: E402

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


def make_token(sub="test-user", ttl_seconds=3600):
    payload = {
        "sub": sub,
        "iat": int(time.time()),
        "exp": int(time.time()) + ttl_seconds,
    }
    return pyjwt.encode(payload, config.JWT_SECRET, algorithm=config.JWT_ALGORITHM)


def run():
    print("[1] Token frais non revoque")
    jwt_blacklist._reset_for_test()
    tok = make_token()
    t("is_revoked False sur token frais", not jwt_blacklist.is_revoked(tok))
    t("verify_jwt accepte token frais", auth.verify_jwt(tok) is not None)

    print("\n[2] revoke + is_revoked")
    jwt_blacklist._reset_for_test()
    tok = make_token(ttl_seconds=3600)
    payload = pyjwt.decode(tok, config.JWT_SECRET, algorithms=[config.JWT_ALGORITHM])
    jwt_blacklist.revoke(tok, payload["exp"])
    t("is_revoked True apres revoke", jwt_blacklist.is_revoked(tok))
    t("verify_jwt rejette token revoque", auth.verify_jwt(tok) is None)

    print("\n[3] revoke avec expiry passee = no-op")
    jwt_blacklist._reset_for_test()
    expired_exp = time.time() - 100
    tok = make_token()
    jwt_blacklist.revoke(tok, expired_exp)
    t("token avec expiry passe pas blacklisted",
      not jwt_blacklist.is_revoked(tok))

    print("\n[4] cleanup opportuniste apres expiry")
    jwt_blacklist._reset_for_test()
    tok = make_token()
    payload = pyjwt.decode(tok, config.JWT_SECRET, algorithms=[config.JWT_ALGORITHM])
    # Revoke avec une expiry dans 1s pour pouvoir voir le cleanup
    jwt_blacklist.revoke(tok, time.time() + 1)
    t("blacklisted juste apres revoke", jwt_blacklist.is_revoked(tok))
    time.sleep(1.5)
    t("cleanup apres expiry", not jwt_blacklist.is_revoked(tok))

    print("\n[5] persistance disque")
    jwt_blacklist._reset_for_test()
    tok = make_token(ttl_seconds=3600)
    payload = pyjwt.decode(tok, config.JWT_SECRET, algorithms=[config.JWT_ALGORITHM])
    jwt_blacklist.revoke(tok, payload["exp"])
    # Force reload depuis disque (simule restart serveur)
    jwt_blacklist._blacklist = {}
    jwt_blacklist._load()
    t("blacklist rechargee apres restart", jwt_blacklist.is_revoked(tok))

    print("\n[6] hash bearer prefix transparent")
    jwt_blacklist._reset_for_test()
    tok = make_token(ttl_seconds=3600)
    payload = pyjwt.decode(tok, config.JWT_SECRET, algorithms=[config.JWT_ALGORITHM])
    jwt_blacklist.revoke(tok, payload["exp"])
    # Token avec prefix "Bearer " doit hash pareil
    t("is_revoked accepte Bearer prefix", jwt_blacklist.is_revoked(f"Bearer {tok}"))

    print("\n[7] verify_jwt skip blacklist check si decode fail (token malformes)")
    t("verify_jwt None pour token bidon", auth.verify_jwt("clearly-not-a-jwt") is None)

    print("\n[8] tokens differents = hash differents = isole")
    jwt_blacklist._reset_for_test()
    tok_a = make_token(sub="alice")
    tok_b = make_token(sub="bob")
    payload_a = pyjwt.decode(tok_a, config.JWT_SECRET, algorithms=[config.JWT_ALGORITHM])
    jwt_blacklist.revoke(tok_a, payload_a["exp"])
    t("tok_a revoque", jwt_blacklist.is_revoked(tok_a))
    t("tok_b NON revoque", not jwt_blacklist.is_revoked(tok_b))

    print(f"\n=== {'ALL GREEN' if failed == 0 else 'FAILED'} ===")
    print(f"    {passed}/{passed + failed} tests reussis")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(run())
