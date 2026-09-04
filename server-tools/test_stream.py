#!/usr/bin/env python3
"""
test_stream.py — tests end-to-end du format STREAM, cote Python.

Couvre l'encodage V3 et sa relecture par parse_header. NE couvre PAS le parsing
legacy : aucun blob V1 ou V2 n'est fabrique ici, donc ni la branche V1/V2 de
stream_decrypt.parse_header ni le rejet RT-02 du V1 CHUNKED ne sont exerces.

C'est de l'auto-coherence Python (formes de sortie, determinisme d'une execution
a l'autre), pas une parite avec une autre implementation : la derivation de
reference est en Rust (crypto-rs/core) et aucun vecteur produit par elle n'est
epingle ici.

Dependance : pip install pynacl
"""

import hashlib
import hmac
import os
import struct
import sys
import tempfile

try:
    import nacl.bindings
    import nacl.utils
except ImportError:
    print("ERROR: pip install pynacl", file=sys.stderr)
    sys.exit(1)

# Import from stream_decrypt
sys.path.insert(0, os.path.dirname(__file__))
from stream_decrypt import (
    mnemonic_to_seed, hkdf_sha256, derive_identity, fingerprint,
    parse_header, decrypt_blob, inspect_blob,
    HKDF_CONTEXT_IDENTITY, HKDF_CONTEXT_ENCRYPTION,
    MAGIC, VERSION, MODE_SINGLE, MODE_CHUNKED,
    SEALED_BOX_OVERHEAD, SESSION_KEY_BYTES, NONCE_BYTES, AEAD_TAG_BYTES,
    SEALED_ENVELOPE_SIZE,
)

# --- Test encryption (Python re-implementation of SovereignEncryptor) ---

def encrypt_blob(plaintext: bytes, identity: dict, recipients: list = None, force_chunked: bool = False) -> bytes:
    """Encrypt plaintext into a STREAM V3 blob (no author identity at rest)."""
    recipients = recipients or []
    session_key = nacl.utils.random(SESSION_KEY_BYTES)

    # V3 header: MAGIC | VERSION | sealed_self | grant_count | grants.
    # F-C1: NO author_ed25519_pk is written (the witness identity stays off-disk).
    header = bytearray()
    header += MAGIC
    header += bytes([VERSION])

    # Self-envelope
    sealed_self = nacl.bindings.crypto_box_seal(session_key, identity["x25519_pk"])
    header += sealed_self

    # Access grants
    header += struct.pack(">H", len(recipients))
    for rpk in recipients:
        header += rpk
        sealed = nacl.bindings.crypto_box_seal(session_key, rpk)
        header += sealed

    header_aad = bytes(header)
    buf = bytearray(header)

    # Payload
    chunk_threshold = 10 * 1024 * 1024
    if len(plaintext) <= chunk_threshold and not force_chunked:
        # Single mode
        buf += bytes([MODE_SINGLE])
        nonce = nacl.utils.random(NONCE_BYTES)
        # AAD = header bytes (SINGLE)
        ciphertext = nacl.bindings.crypto_aead_xchacha20poly1305_ietf_encrypt(
            plaintext, header_aad, nonce, session_key
        )
        buf += nonce
        buf += ciphertext
    else:
        # Chunked mode
        buf += bytes([MODE_CHUNKED])
        # Random nonce prefix (20 bytes)
        nonce_prefix = nacl.utils.random(NONCE_BYTES - 4)
        buf += nonce_prefix
        chunk_size = 1024 * 1024
        chunk_count = (len(plaintext) + chunk_size - 1) // chunk_size
        # V2/V3 extended AAD = header | MODE_CHUNKED | nonce_prefix | chunk_count.
        aad = header_aad + bytes([MODE_CHUNKED]) + bytes(nonce_prefix) + struct.pack(">I", chunk_count)
        chunks_data = []
        idx = 0
        offset = 0
        while offset < len(plaintext):
            chunk = plaintext[offset:offset + chunk_size]
            # Nonce = prefix (20) + chunk index BE (4)
            nonce = bytes(nonce_prefix) + struct.pack(">I", idx)
            ct = nacl.bindings.crypto_aead_xchacha20poly1305_ietf_encrypt(
                chunk, aad, nonce, session_key
            )
            total_len = NONCE_BYTES + len(ct)
            chunk_data = struct.pack(">I", total_len) + nonce + ct
            chunks_data.append(chunk_data)
            idx += 1
            offset += chunk_size
        buf += struct.pack(">I", chunk_count)
        for cd in chunks_data:
            buf += cd

    return bytes(buf)


# --- Test runner ---

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

    test_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

    print("=== STREAM Format — Tests end-to-end ===\n")

    # --- Test 1: Key determinism ---
    print("[1] Determinisme des cles")
    id1 = derive_identity(test_mnemonic)
    id2 = derive_identity(test_mnemonic)
    test("Meme phrase -> memes cles Ed25519", id1["ed25519_pk"] == id2["ed25519_pk"])
    test("Meme phrase -> memes cles X25519", id1["x25519_pk"] == id2["x25519_pk"])
    test("Ed25519 pk = 32 bytes", len(id1["ed25519_pk"]) == 32)
    test("X25519 pk = 32 bytes", len(id1["x25519_pk"]) == 32)
    test("Fingerprint non vide", len(fingerprint(id1["ed25519_pk"])) > 0)
    print()

    # --- Test 2: Plausible deniability ---
    print("[2] Deni plausible (passphrase)")
    id_no_pass = derive_identity(test_mnemonic, "")
    id_with_pass = derive_identity(test_mnemonic, "secret13")
    test("Passphrase change Ed25519", id_no_pass["ed25519_pk"] != id_with_pass["ed25519_pk"])
    test("Passphrase change X25519", id_no_pass["x25519_pk"] != id_with_pass["x25519_pk"])
    print()

    # --- Test 3: Single mode encrypt/decrypt ---
    print("[3] Chiffrement souverain single")
    identity = derive_identity(test_mnemonic)
    plaintext = b"Hello STREAM! This is a sovereign encryption test."
    blob = encrypt_blob(plaintext, identity)
    test("Blob commence par STRM", blob[:4] == MAGIC)
    test("Version = V3", blob[4] == VERSION)

    info = parse_header(blob)
    test("Mode = single", info["mode"] == MODE_SINGLE)
    test("Grant count = 0", info["grant_count"] == 0)
    test("Pas d'author en V3 (F-C1)", info["author_pk"] is None)
    # Motto (binaire) : l'identite long-terme du temoin n'apparait nulle part
    # dans le blob au repos. C'est la garde qui aurait attrape F-C1.
    test("Motto: identite absente du blob",
         identity["ed25519_pk"] not in blob and identity["x25519_pk"] not in blob)

    # Decrypt
    with tempfile.NamedTemporaryFile(suffix=".strm", delete=False) as f:
        f.write(blob)
        blob_path = f.name
    with tempfile.NamedTemporaryFile(suffix=".dec", delete=False) as f:
        out_path = f.name

    decrypt_blob(blob_path, identity, output=out_path)
    decrypted = open(out_path, "rb").read()
    test("Dechiffrement single correct", decrypted == plaintext)
    test(f"Blob size = {len(blob)} bytes", len(blob) > 0)
    os.unlink(blob_path)
    os.unlink(out_path)
    print()

    # --- Test 4: Chunked mode ---
    print("[4] Chiffrement souverain chunked")
    big_plaintext = os.urandom(3 * 1024 * 1024)  # 3 MB
    blob_chunked = encrypt_blob(big_plaintext, identity, force_chunked=True)
    info_c = parse_header(blob_chunked)
    test("Mode = chunked", info_c["mode"] == MODE_CHUNKED)

    with tempfile.NamedTemporaryFile(suffix=".strm", delete=False) as f:
        f.write(blob_chunked)
        blob_path = f.name
    with tempfile.NamedTemporaryFile(suffix=".dec", delete=False) as f:
        out_path = f.name

    decrypt_blob(blob_path, identity, output=out_path)
    decrypted_chunked = open(out_path, "rb").read()
    test("Dechiffrement chunked correct", decrypted_chunked == big_plaintext)
    test(f"Plaintext = {len(big_plaintext)} bytes, blob = {len(blob_chunked)} bytes",
         len(blob_chunked) > len(big_plaintext))
    os.unlink(blob_path)
    os.unlink(out_path)
    print()

    # --- Test 5: Access grant ---
    print("[5] Access grant — destinataire autorise")
    recipient_mnemonic = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong"
    recipient = derive_identity(recipient_mnemonic)
    blob_grant = encrypt_blob(plaintext, identity, recipients=[recipient["x25519_pk"]])
    info_g = parse_header(blob_grant)
    test("Grant count = 1", info_g["grant_count"] == 1)
    test("Recipient pk dans le grant", info_g["grants"][0][0] == recipient["x25519_pk"])

    with tempfile.NamedTemporaryFile(suffix=".strm", delete=False) as f:
        f.write(blob_grant)
        blob_path = f.name
    with tempfile.NamedTemporaryFile(suffix=".dec", delete=False) as f:
        out_path = f.name

    # Decrypt as recipient
    decrypt_blob(blob_path, recipient, as_recipient=True, output=out_path)
    decrypted_grant = open(out_path, "rb").read()
    test("Destinataire dechiffre correctement", decrypted_grant == plaintext)
    os.unlink(blob_path)
    os.unlink(out_path)
    print()

    # --- Test 6: Unauthorized key rejection ---
    print("[6] Rejet des cles non autorisees")
    unauthorized_mnemonic = "legal winner thank year wave sausage worth useful legal winner thank yellow"
    unauthorized = derive_identity(unauthorized_mnemonic)
    blob_no_grant = encrypt_blob(plaintext, identity)  # No grants

    with tempfile.NamedTemporaryFile(suffix=".strm", delete=False) as f:
        f.write(blob_no_grant)
        blob_path = f.name

    try:
        reject_out = tempfile.mktemp(suffix=".dec")
        decrypt_blob(blob_path, unauthorized, output=reject_out)
        test("Cle non autorisee rejetee", False)
        if os.path.exists(reject_out): os.unlink(reject_out)
    except SystemExit:
        test("Cle non autorisee rejetee", True)
        if os.path.exists(reject_out): os.unlink(reject_out)
    os.unlink(blob_path)
    print()

    # --- Test 7: Multi-recipients ---
    print("[7] Multi-destinataires")
    r1 = derive_identity("zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong")
    r2 = derive_identity("legal winner thank year wave sausage worth useful legal winner thank yellow")
    r3 = derive_identity(test_mnemonic, "decoy")
    blob_multi = encrypt_blob(plaintext, identity, recipients=[
        r1["x25519_pk"], r2["x25519_pk"], r3["x25519_pk"]
    ])
    info_m = parse_header(blob_multi)
    test("3 grants", info_m["grant_count"] == 3)

    # Each recipient can decrypt
    for i, r in enumerate([r1, r2, r3]):
        with tempfile.NamedTemporaryFile(suffix=".strm", delete=False) as f:
            f.write(blob_multi)
            bp = f.name
        with tempfile.NamedTemporaryFile(suffix=".dec", delete=False) as f:
            op = f.name
        decrypt_blob(bp, r, as_recipient=True, output=op)
        dec = open(op, "rb").read()
        test(f"Destinataire {i+1} dechiffre", dec == plaintext)
        os.unlink(bp)
        os.unlink(op)
    print()

    # --- Test 8: Blob inspection ---
    print("[8] Inspection du blob")
    blob_inspect = encrypt_blob(b"test data", identity, recipients=[r1["x25519_pk"]])
    info_i = parse_header(blob_inspect)
    test("Version lisible", info_i["version"] == VERSION)
    test("Author absent en V3 (F-C1)", info_i["author_pk"] is None)
    test("Mode single ou chunked", info_i["mode"] in (MODE_SINGLE, MODE_CHUNKED))
    print()

    # --- Test 9: Known test vectors (cross-platform determinism) ---
    print("[9] Vecteurs de test connus (determinisme cross-platform)")
    # These are shape checks, not pinned vectors: nothing below compares bytes
    # against a value produced by another implementation. The reference derivation
    # lives in crypto-rs/core.
    # Mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    # Passphrase: ""
    tv_identity = derive_identity(test_mnemonic, "")
    tv_ed_pk_hex = tv_identity["ed25519_pk"].hex()
    tv_x_pk_hex = tv_identity["x25519_pk"].hex()
    tv_fingerprint = fingerprint(tv_identity["ed25519_pk"])

    # Shapes only — a real cross-platform pin would compare against vectors
    # produced by crypto-rs/core.
    test("Ed25519 pk deterministe", len(tv_ed_pk_hex) == 64)
    test("X25519 pk deterministe", len(tv_x_pk_hex) == 64)
    test("Fingerprint format 6 groupes", len(tv_fingerprint.split(" ")) == 6)

    # With passphrase "decoy" — must produce DIFFERENT keys
    tv_decoy = derive_identity(test_mnemonic, "decoy")
    test("Passphrase 'decoy' change Ed25519", tv_decoy["ed25519_pk"] != tv_identity["ed25519_pk"])
    test("Passphrase 'decoy' change X25519", tv_decoy["x25519_pk"] != tv_identity["x25519_pk"])

    # Test empty plaintext edge case
    empty_blob = encrypt_blob(b"", tv_identity)
    test("Blob vide commence par STRM", empty_blob[:4] == MAGIC)
    with tempfile.NamedTemporaryFile(suffix=".strm", delete=False) as f:
        f.write(empty_blob)
        ep = f.name
    with tempfile.NamedTemporaryFile(suffix=".dec", delete=False) as f:
        eo = f.name
    decrypt_blob(ep, tv_identity, output=eo)
    test("Dechiffrement plaintext vide", open(eo, "rb").read() == b"")
    os.unlink(ep)
    os.unlink(eo)
    print()

    # --- Summary ---
    total = passed + failed
    print(f"=== {'Tous les tests passent' if failed == 0 else f'{failed} ECHEC(S)'} ===")
    print(f"    {passed}/{total} tests reussis")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(run_tests())
