#!/usr/bin/env python3
"""
test_e2e_v2.py — End-to-end HTTP test of V2 endpoints via FastAPI TestClient.

Tests /auth/v2/enroll, /auth/challenge, /auth/v2/verify, /auth/v2/rotate-batch.
Pas de MinIO requis (on ne teste pas l'upload ici).
"""

import os
import sys
import tempfile

_tmpdir = tempfile.mkdtemp()
os.environ["JWT_SECRET"] = "test-e2e-secret-do-not-use-in-prod"
os.environ["LEGACY_LOGIN_ENABLED"] = "false"
os.environ["RATCHET_REGISTRY_FILE"] = os.path.join(_tmpdir, "test_reg.json")
os.environ["MINIO_ACCESS_KEY"] = "dummy"
os.environ["MINIO_SECRET_KEY"] = "dummy"

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from fastapi.testclient import TestClient  # noqa: E402
import nacl.bindings  # noqa: E402
from unittest.mock import patch  # noqa: E402

# Mock MinIO out during import (sinon ensure_bucket plante)
with patch("minio.Minio"):
    from app.main import app
    from app import ratchet_registry  # noqa: E402

# R-C-1 signature domain tags (mirror the Rust client / server verify path).
from app.signature_domain import (  # noqa: E402
    SIG_DOMAIN_AUTH_CHALLENGE,
    SIG_DOMAIN_BATCH_ROTATION,
    SIG_DOMAIN_ENROLLMENT,
)


passed = 0
failed = 0


def test(name, cond, detail=""):
    global passed, failed
    if cond:
        print(f"  [PASS] {name}")
        passed += 1
    else:
        print(f"  [FAIL] {name}  {detail}")
        failed += 1


def new_keypair():
    seed = os.urandom(32)
    pk, sk = nacl.bindings.crypto_sign_seed_keypair(seed)
    return pk, sk


def sign(sk, msg):
    return nacl.bindings.crypto_sign(msg, sk)[:64]


def gen_batch(n=50):
    return [new_keypair() for _ in range(n)]


def concat_pks(pairs):
    return b"".join(p[0] for p in pairs)


def run():
    global passed, failed
    print("=== V2 E2E HTTP tests ===\n")
    ratchet_registry._clear_for_tests()
    client = TestClient(app)

    # --- Test 1 : enroll happy path ---
    print("[1] POST /auth/v2/enroll — happy path")
    identity_pk, identity_sk = new_keypair()
    id_hex = identity_pk.hex()
    batch0 = gen_batch()
    batch0_pks = [p[0].hex() for p in batch0]
    batch0_sig = sign(identity_sk, SIG_DOMAIN_ENROLLMENT + concat_pks(batch0)).hex()

    r = client.post("/auth/v2/enroll", json={
        "ed25519_pk": id_hex,
        "batch_0_public_keys": batch0_pks,
        "batch_0_signature": batch0_sig,
    })
    test("status 200", r.status_code == 200, r.text)
    data = r.json()
    test("enrolled=True", data.get("enrolled") is True)
    test("batch_number=0", data.get("batch_number") == 0)
    print()

    # --- Test 2 : enroll double ---
    print("[2] POST /auth/v2/enroll — re-enroll refusé")
    r2 = client.post("/auth/v2/enroll", json={
        "ed25519_pk": id_hex,
        "batch_0_public_keys": batch0_pks,
        "batch_0_signature": batch0_sig,
    })
    test("status 409", r2.status_code == 409, r2.text)
    print()

    # --- Test 3 : enroll bad signature ---
    print("[3] POST /auth/v2/enroll — signature invalide")
    bad_pk, bad_sk = new_keypair()
    r3 = client.post("/auth/v2/enroll", json={
        "ed25519_pk": bad_pk.hex(),
        "batch_0_public_keys": [p[0].hex() for p in gen_batch()],
        "batch_0_signature": "ab" * 64,  # bogus
    })
    test("status 401 signature invalide", r3.status_code == 401, r3.text)
    print()

    # S9-pre-audit pt2 helper: sign `nonce || ts_be_u64` as the client does.
    def sign_challenge(sk, nonce_hex, ts):
        msg = (
            SIG_DOMAIN_AUTH_CHALLENGE
            + bytes.fromhex(nonce_hex)
            + int(ts).to_bytes(8, "big", signed=False)
        )
        return sign(sk, msg).hex()

    # --- Test 4 : flow complet challenge + verify ---
    print("[4] challenge + verify — slot 0 du batch_0")
    # Get nonce + timestamp
    rc = client.post("/auth/challenge")
    test("challenge 200", rc.status_code == 200)
    cj = rc.json()
    nonce_hex = cj["nonce"]
    ts = cj["timestamp"]
    test("challenge retourne un timestamp", isinstance(ts, int) and ts > 0)

    # Signe avec slot 0 du batch_0
    ephem_sk = batch0[0][1]
    ephem_pk_hex = batch0[0][0].hex()
    sig = sign_challenge(ephem_sk, nonce_hex, ts)

    rv = client.post("/auth/v2/verify", json={
        "ed25519_pk": id_hex,
        "ephemeral_pk": ephem_pk_hex,
        "batch_number": 0,
        "key_index": 0,
        "nonce": nonce_hex,
        "timestamp": ts,
        "signature": sig,
    })
    test("verify 200", rv.status_code == 200, rv.text)
    jwt_token = rv.json()["access_token"]
    test("JWT reçu", bool(jwt_token) and len(jwt_token) > 20)
    test("auth_version=2", rv.json()["user"].get("auth_version") == 2)
    print()

    # --- Test 5 : replay du même nonce rejeté ---
    print("[5] replay rejected")
    rv2 = client.post("/auth/v2/verify", json={
        "ed25519_pk": id_hex,
        "ephemeral_pk": ephem_pk_hex,
        "batch_number": 0,
        "key_index": 0,
        "nonce": nonce_hex,
        "timestamp": ts,
        "signature": sig,
    })
    test("replay refusé (401/409)", rv2.status_code in (401, 409), rv2.text)
    print()

    # --- Test 5b : timestamp modifié par le client → rejeté ---
    print("[5b] timestamp tampering rejected")
    rcb = client.post("/auth/challenge")
    cbj = rcb.json()
    nb = cbj["nonce"]; tsb = cbj["timestamp"]
    sigb = sign_challenge(ephem_sk, nb, tsb)
    rvb = client.post("/auth/v2/verify", json={
        "ed25519_pk": id_hex,
        "ephemeral_pk": ephem_pk_hex,
        "batch_number": 0,
        "key_index": 0,
        "nonce": nb,
        "timestamp": tsb + 1000,  # tampered
        "signature": sigb,
    })
    test("timestamp tamperé → 401", rvb.status_code == 401, rvb.text)
    print()

    # --- Test 6 : verify avec slot déjà consommé ---
    print("[6] verify avec slot 0 déjà consommé — rejeté")
    rc2 = client.post("/auth/challenge")
    c2j = rc2.json()
    nonce2 = c2j["nonce"]; ts2 = c2j["timestamp"]
    sig2 = sign_challenge(ephem_sk, nonce2, ts2)
    rv3 = client.post("/auth/v2/verify", json={
        "ed25519_pk": id_hex,
        "ephemeral_pk": ephem_pk_hex,
        "batch_number": 0,
        "key_index": 0,
        "nonce": nonce2,
        "timestamp": ts2,
        "signature": sig2,
    })
    test("slot consommé → 401", rv3.status_code == 401)
    print()

    # --- Test 7 : status endpoint REMOVED (audit R-SRV-1) -> must be 404 ---
    print("[7] GET /auth/v2/status/{ed25519_pk} (removed)")
    rs = client.get(f"/auth/v2/status/{id_hex}")
    test("status route removed (404)", rs.status_code == 404)
    print()

    # --- Test 8 : rotate batch ---
    print("[8] POST /auth/v2/rotate-batch")
    batch1 = gen_batch()
    batch1_pks = [p[0].hex() for p in batch1]
    # Rotation signée par slot 49 de batch_0
    signer_sk = batch0[49][1]
    signer_pk_hex = batch0[49][0].hex()
    batch1_sig = sign(signer_sk, SIG_DOMAIN_BATCH_ROTATION + concat_pks(batch1)).hex()

    rr = client.post("/auth/v2/rotate-batch", json={
        "ed25519_pk": id_hex,
        "signer_batch_number": 0,
        "signer_key_index": 49,
        "signer_public_key": signer_pk_hex,
        "new_batch_public_keys": batch1_pks,
        "new_batch_signature": batch1_sig,
    })
    test("rotation 200", rr.status_code == 200, rr.text)
    test("nouveau batch = 1", rr.json()["new_batch_number"] == 1)
    print()

    # --- Test 9 : après rotation, vieille clé rejetée ---
    print("[9] après rotation : batch_0 inutilisable")
    rc3 = client.post("/auth/challenge")
    c3j = rc3.json()
    n3 = c3j["nonce"]; ts3 = c3j["timestamp"]
    sig3 = sign_challenge(batch0[1][1], n3, ts3)  # slot 1 du batch_0
    rv4 = client.post("/auth/v2/verify", json={
        "ed25519_pk": id_hex,
        "ephemeral_pk": batch0[1][0].hex(),
        "batch_number": 0,
        "key_index": 1,
        "nonce": n3,
        "timestamp": ts3,
        "signature": sig3,
    })
    test("vieille clé → 401", rv4.status_code == 401, rv4.text)
    print()

    # --- Test 10 : nouvelle clé du batch_1 OK ---
    print("[10] batch_1 slot 0 accepté")
    rc4 = client.post("/auth/challenge")
    c4j = rc4.json()
    n4 = c4j["nonce"]; ts4 = c4j["timestamp"]
    sig4 = sign_challenge(batch1[0][1], n4, ts4)
    rv5 = client.post("/auth/v2/verify", json={
        "ed25519_pk": id_hex,
        "ephemeral_pk": batch1[0][0].hex(),
        "batch_number": 1,
        "key_index": 0,
        "nonce": n4,
        "timestamp": ts4,
        "signature": sig4,
    })
    test("batch_1 slot 0 → 200", rv5.status_code == 200, rv5.text)
    print()

    # --- Test 11 : rotate avec mauvais signer → 401 générique (LOT A) ---
    # Depuis le fix anti-oracle (2026-07-02), tout rejet d'état/signature de
    # rotate-batch est fusionné en un unique 401 "Rotation rejected" : plus de
    # 409 distinct, plus de batch_number serveur dans le corps.
    print("[11] rotate avec signer du mauvais batch → 401 générique")
    b2 = gen_batch()
    b2_sig = sign(batch0[2][1], SIG_DOMAIN_BATCH_ROTATION + concat_pks(b2)).hex()  # slot de batch_0, pas batch_1
    rr2 = client.post("/auth/v2/rotate-batch", json={
        "ed25519_pk": id_hex,
        "signer_batch_number": 0,  # ancien batch
        "signer_key_index": 2,
        "signer_public_key": batch0[2][0].hex(),
        "new_batch_public_keys": [p[0].hex() for p in b2],
        "new_batch_signature": b2_sig,
    })
    test("rotate batch_0 après batch_1 → 401", rr2.status_code == 401, rr2.text)
    test("rejet générique (pas de fuite batch_number)",
         rr2.json().get("detail") == "Rotation rejected" and "server=" not in rr2.text,
         rr2.text)
    print()

    # --- Summary ---
    total = passed + failed
    print(f"=== {'ALL GREEN' if failed == 0 else f'{failed} ECHEC(S)'} ===")
    print(f"    {passed}/{total} tests réussis")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(run())
