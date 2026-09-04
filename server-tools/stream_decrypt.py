#!/usr/bin/env python3
"""
stream_decrypt.py — déchiffrement hors-ligne des blobs STREAM.

Cet outil ne parle à aucun relais et ne doit jamais commencer : c'est celui qu'on
utilise sous contrainte, sur une machine qu'on choisit. Même raison pour la
dépendance unique `pip install pynacl` — ni requests, ni cryptography, ni ffmpeg
obligatoire (le réassemblage dégrade en instructions imprimées plutôt que d'exiger
un binaire externe). Chaque ajout élargit la base de confiance d'un outil de
récupération.

Le décodeur accepte V1, V2 et V3 : les archives .strm déjà au repos restent
récupérables.
"""

import argparse
import getpass
import hashlib
import hmac
import struct
import sys
from pathlib import Path

try:
    import nacl.bindings
    import nacl.utils
except ImportError:
    print("ERROR: pip install pynacl", file=sys.stderr)
    sys.exit(1)

# --- BIP-39 seed derivation (PBKDF2-HMAC-SHA512, 2048 iterations) ---

def _strip_accents(s: str) -> str:
    """Strip les accents ('aïeul' → 'aieul') via Unicode NFD + filtre combining marks."""
    import unicodedata
    decomposed = unicodedata.normalize("NFD", s)
    return "".join(c for c in decomposed if unicodedata.category(c) != "Mn")


def _load_french_wordlist() -> dict:
    """Charge la wordlist BIP-39 FR et construit un map stripped→canonical."""
    import os
    here = os.path.dirname(os.path.abspath(__file__))
    # Essaye les emplacements usuels
    for candidate in [
        os.path.join(here, "bip39_fr.txt"),
        os.path.join(here, "..", "stream-crypto", "src", "main", "resources", "bip39_fr.txt"),
    ]:
        if os.path.isfile(candidate):
            with open(candidate, encoding="utf-8") as f:
                words = [w.strip() for w in f if w.strip()]
            return {_strip_accents(w.lower()): w for w in words}
    return {}


_FRENCH_STRIPPED_MAP = _load_french_wordlist()


def _normalize_word(word: str) -> str:
    """Convertit 'aieul' ou 'aïeul' en forme canonique 'aïeul' si la wordlist est chargée."""
    w = word.strip().lower()
    if not w:
        return w
    stripped = _strip_accents(w)
    return _FRENCH_STRIPPED_MAP.get(stripped, w)


def mnemonic_to_seed(mnemonic: str, passphrase: str = "") -> bytes:
    import hashlib
    # V2 : normalise chaque mot vers la forme canonique accentuée
    # (même logique que Bip39.normalizePhrase côté Android)
    words = [_normalize_word(w) for w in mnemonic.strip().split() if w]
    normalized = " ".join(words)
    salt = f"mnemonic{passphrase}".encode("utf-8")
    return hashlib.pbkdf2_hmac("sha512", normalized.encode("utf-8"), salt, 2048, dklen=64)


# --- HKDF-SHA256 ---

def hkdf_sha256(ikm: bytes, info: bytes, length: int, salt: bytes = None) -> bytes:
    if salt is None:
        salt = b"\x00" * 32
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    t = b""
    result = b""
    counter = 1
    while len(result) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        result += t
        counter += 1
    return result[:length]


# --- Identity derivation ---

HKDF_CONTEXT_IDENTITY = b"stream.identity.ed25519.v1"
HKDF_CONTEXT_ENCRYPTION = b"stream.encryption.x25519.v1"

def derive_identity(mnemonic: str, passphrase: str = ""):
    seed = mnemonic_to_seed(mnemonic, passphrase)
    ed_seed = hkdf_sha256(seed, HKDF_CONTEXT_IDENTITY, 32)
    x_seed = hkdf_sha256(seed, HKDF_CONTEXT_ENCRYPTION, 32)

    ed_pk, ed_sk = nacl.bindings.crypto_sign_seed_keypair(ed_seed)
    x_pk, x_sk = nacl.bindings.crypto_box_seed_keypair(x_seed)

    return {
        "ed25519_pk": ed_pk,
        "ed25519_sk": ed_sk,
        "x25519_pk": x_pk,
        "x25519_sk": x_sk,
    }


def fingerprint(ed25519_pk: bytes) -> str:
    h = hashlib.sha256(ed25519_pk).digest()[:12]
    hex_str = h.hex()
    return " ".join(hex_str[i:i+4] for i in range(0, len(hex_str), 4))


# --- STREAM blob parsing ---

MAGIC = b"STRM"
# Legacy formats carry a 32-byte author_ed25519_pk at offset 5; V3 drops it
# (F-C1: no witness identity at rest). The decoder accepts all three; tools that
# imported `VERSION` get the current encoder version (V3) via the alias below.
VERSION_V1 = 0x01
VERSION_V2 = 0x02
VERSION_V3 = 0x03
VERSION_CURRENT = VERSION_V3
VERSION = VERSION_CURRENT  # backward-compat alias (== current encoder)
MODE_SINGLE = 0x01
MODE_CHUNKED = 0x02
SEALED_BOX_OVERHEAD = 48
SESSION_KEY_BYTES = 32
NONCE_BYTES = 24
NONCE_PREFIX_BYTES = NONCE_BYTES - 4
AEAD_TAG_BYTES = 16
SEALED_ENVELOPE_SIZE = SESSION_KEY_BYTES + SEALED_BOX_OVERHEAD


def parse_header(data: bytes, offset: int = 0):
    header_start = offset
    magic = data[offset:offset+4]
    if magic != MAGIC:
        raise ValueError(f"Not a STREAM blob (magic: {magic!r})")
    version = data[offset+4]
    # Version-branched layout: V3 has no author key (sealed at +5); legacy V1/V2
    # carry a 32-byte author key (sealed at +37).
    if version == VERSION_V3:
        author_pk = None
        sealed_off = offset + 5
    elif version in (VERSION_V1, VERSION_V2):
        author_pk = data[offset+5:offset+37]
        sealed_off = offset + 37
    else:
        raise ValueError(f"Unsupported version: {version}")
    self_envelope = data[sealed_off:sealed_off+SEALED_ENVELOPE_SIZE]
    pos = sealed_off + SEALED_ENVELOPE_SIZE
    grant_count = struct.unpack(">H", data[pos:pos+2])[0]
    pos += 2
    grants = []
    for _ in range(grant_count):
        rpk = data[pos:pos+32]
        sealed = data[pos+32:pos+32+SEALED_ENVELOPE_SIZE]
        grants.append((rpk, sealed))
        pos += 32 + SEALED_ENVELOPE_SIZE
    # H-01: Header AAD = everything from magic to end of grants (before mode byte)
    header_aad = data[header_start:pos]
    mode = data[pos]
    pos += 1
    return {
        "version": version,
        "author_pk": author_pk,  # None for V3
        "self_envelope": self_envelope,
        "grant_count": grant_count,
        "grants": grants,
        "mode": mode,
        "payload_offset": pos,
        "header_aad": header_aad,
    }


def inspect_blob(filepath: str):
    data = Path(filepath).read_bytes()
    info = parse_header(data)
    print(f"=== STREAM Blob Inspector ===")
    print(f"File        : {filepath}")
    print(f"Size        : {len(data)} bytes")
    print(f"Version     : {info['version']}")
    if info["author_pk"] is not None:
        print(f"Author (Ed) : {info['author_pk'].hex()}")
        print(f"Fingerprint : {fingerprint(info['author_pk'])}")
    else:
        print(f"Author (Ed) : (none - V3 carries no identity at rest)")
    print(f"Self-envelope: {len(info['self_envelope'])} bytes")
    print(f"Grant count : {info['grant_count']}")
    for i, (rpk, _) in enumerate(info["grants"]):
        print(f"  Grant {i}: recipient X25519 pk = {rpk.hex()}")
    mode_name = {MODE_SINGLE: "single", MODE_CHUNKED: "chunked"}.get(info["mode"], f"unknown({info['mode']})")
    print(f"Mode        : {mode_name}")
    print(f"Payload at  : offset {info['payload_offset']}")
    payload_size = len(data) - info["payload_offset"]
    print(f"Payload size: {payload_size} bytes")


def decrypt_blob(filepath: str, identity: dict, as_recipient: bool = False, output: str = None):
    data = Path(filepath).read_bytes()
    info = parse_header(data)

    x_pk = identity["x25519_pk"]
    x_sk = identity["x25519_sk"]

    session_key = None
    is_self = False

    if not as_recipient:
        try:
            session_key = nacl.bindings.crypto_box_seal_open(info["self_envelope"], x_pk, x_sk)
            is_self = True
        except Exception:
            pass

    if session_key is None:
        for rpk, sealed in info["grants"]:
            if rpk == x_pk:
                try:
                    session_key = nacl.bindings.crypto_box_seal_open(sealed, x_pk, x_sk)
                    break
                except Exception:
                    continue

    if session_key is None:
        print("ERROR: Access denied — cannot decrypt with this identity", file=sys.stderr)
        sys.exit(1)

    pos = info["payload_offset"]
    mode = info["mode"]
    version = info["version"]
    header_aad = info["header_aad"]

    if mode == MODE_SINGLE:
        nonce = data[pos:pos+NONCE_BYTES]
        ciphertext = data[pos+NONCE_BYTES:]
        # H-01: Pass header as AAD for integrity verification
        plaintext = nacl.bindings.crypto_aead_xchacha20poly1305_ietf_decrypt(
            ciphertext, header_aad, nonce, session_key
        )
    elif mode == MODE_CHUNKED:
        # RT-02: V1 CHUNKED bound only the header in its AAD (chunk_count was
        # not authenticated) — a silent-truncation primitive. The Rust decoder
        # rejects it outright; mirror that here for parity.
        if version == VERSION_V1:
            print("ERROR: V1 CHUNKED rejected (silent-truncation primitive, RT-02)", file=sys.stderr)
            sys.exit(1)
        # H-02: Read random nonce prefix (20 bytes, before chunk count)
        nonce_prefix = data[pos:pos + NONCE_PREFIX_BYTES]
        pos += NONCE_PREFIX_BYTES
        chunk_count = struct.unpack(">I", data[pos:pos+4])[0]
        pos += 4
        # V2/V3 extended AAD binds MODE + nonce_prefix + chunk_count, so a
        # truncation (dropping trailing chunks + patching chunk_count) fails.
        aad = header_aad + bytes([MODE_CHUNKED]) + nonce_prefix + struct.pack(">I", chunk_count)
        chunks = []
        for i in range(chunk_count):
            chunk_len = struct.unpack(">I", data[pos:pos+4])[0]
            pos += 4
            nonce = data[pos:pos+NONCE_BYTES]
            ct = data[pos+NONCE_BYTES:pos+chunk_len]
            pos += chunk_len
            pt = nacl.bindings.crypto_aead_xchacha20poly1305_ietf_decrypt(
                ct, aad, nonce, session_key
            )
            chunks.append(pt)
        plaintext = b"".join(chunks)
    else:
        print(f"ERROR: Unknown mode {mode}", file=sys.stderr)
        sys.exit(1)

    decrypt_type = "self-decrypt" if is_self else "grant-decrypt"
    print(f"Decrypted ({decrypt_type}): {len(plaintext)} bytes", file=sys.stderr)

    if output:
        Path(output).write_bytes(plaintext)
        print(f"Written to: {output}", file=sys.stderr)
    else:
        out_name = Path(filepath).stem
        if out_name.endswith(".strm"):
            out_name = out_name[:-5]
        out_path = Path(filepath).parent / f"{out_name}.decrypted"
        Path(out_path).write_bytes(plaintext)
        print(f"Written to: {out_path}", file=sys.stderr)


def show_identity(mnemonic: str, passphrase: str = ""):
    identity = derive_identity(mnemonic, passphrase)
    print(f"=== STREAM Identity ===")
    print(f"Ed25519 public key : {identity['ed25519_pk'].hex()}")
    print(f"X25519 public key  : {identity['x25519_pk'].hex()}")
    print(f"Fingerprint        : {fingerprint(identity['ed25519_pk'])}")
    if passphrase:
        print(f"(derived with 13th word passphrase)")


def reassemble_session(session_dir: str, identity: dict, output: str):
    """Reassemble a streaming session from individual chunk blobs."""
    from pathlib import Path
    import tempfile
    import subprocess

    session_path = Path(session_dir)
    blobs = sorted(session_path.glob("*.strm"))
    if not blobs:
        print(f"ERROR: No .strm files found in {session_dir}", file=sys.stderr)
        sys.exit(1)

    print(f"Found {len(blobs)} chunks in session", file=sys.stderr)

    # Decrypt metadata (sequence 000000)
    meta_blobs = [b for b in blobs if "_000000.strm" in b.name]
    if meta_blobs:
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            meta_out = tmp.name
        decrypt_blob(str(meta_blobs[0]), identity, output=meta_out)
        meta_text = Path(meta_out).read_text(errors="replace")
        print(f"Session metadata: {meta_text}", file=sys.stderr)
        os.unlink(meta_out)

    # Decrypt video chunks (sequence 000001+)
    chunk_blobs = [b for b in blobs if "_000000.strm" not in b.name]
    temp_dir = Path(tempfile.mkdtemp(prefix="stream_reassemble_"))
    chunk_files = []

    for i, blob in enumerate(chunk_blobs):
        out_file = temp_dir / f"chunk_{i:06d}.mp4"
        try:
            decrypt_blob(str(blob), identity, output=str(out_file))
            if out_file.exists() and out_file.stat().st_size > 0:
                chunk_files.append(out_file)
        except Exception as e:
            print(f"WARNING: Failed to decrypt {blob.name}: {e}", file=sys.stderr)

    if not chunk_files:
        print("ERROR: No chunks decrypted successfully", file=sys.stderr)
        sys.exit(1)

    print(f"Decrypted {len(chunk_files)} video chunks", file=sys.stderr)

    # Create concat file for ffmpeg
    concat_file = temp_dir / "concat.txt"
    with open(concat_file, "w") as f:
        for cf in chunk_files:
            f.write(f"file '{cf}'\n")

    # Try ffmpeg concatenation
    try:
        result = subprocess.run([
            "ffmpeg", "-y", "-f", "concat", "-safe", "0",
            "-i", str(concat_file), "-c", "copy", output
        ], capture_output=True, text=True)
        if result.returncode == 0:
            print(f"Reassembled video: {output}", file=sys.stderr)
        else:
            print(f"ffmpeg error: {result.stderr}", file=sys.stderr)
            # Fallback: just list the individual chunk files
            print(f"Individual chunks available in: {temp_dir}", file=sys.stderr)
            return
    except FileNotFoundError:
        print("ffmpeg not found — individual chunks decrypted to:", file=sys.stderr)
        for cf in chunk_files:
            print(f"  {cf}", file=sys.stderr)
        print(f"Install ffmpeg and run: ffmpeg -f concat -safe 0 -i {concat_file} -c copy {output}",
              file=sys.stderr)
        return

    # Cleanup temp files
    for cf in chunk_files:
        cf.unlink()
    concat_file.unlink()
    temp_dir.rmdir()


def main():
    parser = argparse.ArgumentParser(description="STREAM blob decryption CLI")
    parser.add_argument("file", nargs="?", help="Path to .strm blob file or session directory")
    parser.add_argument("--inspect", action="store_true", help="Inspect blob metadata without decrypting")
    parser.add_argument("--mnemonic", type=str, help="BIP-39 mnemonic phrase (or use interactive prompt)")
    parser.add_argument("--passphrase", type=str, default="", help="Optional 13th word for plausible deniability")
    parser.add_argument("--as-recipient", action="store_true", help="Decrypt as grant recipient (skip self-envelope)")
    parser.add_argument("--show-identity", action="store_true", help="Show identity derived from mnemonic")
    parser.add_argument("--reassemble", action="store_true",
                        help="Reassemble a streaming session from a directory of chunk blobs")
    parser.add_argument("-o", "--output", type=str, help="Output file path")

    args = parser.parse_args()

    if args.show_identity:
        mnemonic = args.mnemonic or getpass.getpass("Mnemonic: ")
        show_identity(mnemonic, args.passphrase)
        return

    if not args.file:
        parser.error("file or directory is required")

    if args.inspect:
        inspect_blob(args.file)
        return

    mnemonic = args.mnemonic or getpass.getpass("Mnemonic: ")
    identity = derive_identity(mnemonic, args.passphrase)

    if args.reassemble:
        output = args.output or "reassembled.mp4"
        reassemble_session(args.file, identity, output)
        return

    decrypt_blob(args.file, identity, args.as_recipient, args.output)


if __name__ == "__main__":
    main()
