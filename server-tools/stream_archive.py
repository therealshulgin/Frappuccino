#!/usr/bin/env python3
"""
stream_archive.py — CLI d'archive V2. DÉPRÉCIÉ (2026-06-30).

Ne pas réparer le chemin réseau en redemandant `/auth/v2/status` au relais : la
route a été retirée le 2026-06-27 (R-SRV-1) parce qu'elle était un oracle
d'activité par identité, contraire au motto du relais aveugle. La remettre pour
faire remarcher cet outil rouvrirait la fuite. Ce qui marche à la place :
récupération réseau = rescue in-app (ArchiveModeActivity) ; chemins locaux = CLI
Rust (`crypto-rs/cli`).

Ce qui reste utilisable ici : `--inspect <blob.strm>`, purement local, sans
réseau. Le reste s'arrête en chemin — l'outil dérive l'identité depuis la phrase
BIP-39 (12 mots, wordlist française ; les accents sont optionnels à la saisie,
stream_decrypt._normalize_word recanonicalise chaque mot), s'authentifie en V2
(et seulement si l'identité n'est pas déjà enrôlée, cf. enroll_or_reuse), puis
imprime une recette curl. Le chemin complet n'est pas câblé : `download_chunk`
existe mais personne ne l'appelle, et le listing des blobs, le déchiffrement,
l'assemblage MP4 et `--output` ne sont pas implémentés.

Dépendances : pip install pynacl httpx
"""
import argparse
import getpass
import json
import os
import re
import sys
import tempfile
from pathlib import Path

try:
    import nacl.bindings
    import httpx
except ImportError:
    print("ERREUR : pip install pynacl httpx", file=sys.stderr)
    sys.exit(1)

# Réutilise les helpers de stream_decrypt.py (déchiffrement blob)
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
try:
    import stream_decrypt
except ImportError:
    print("ERREUR : stream_decrypt.py non trouvé — placer dans server-tools/", file=sys.stderr)
    sys.exit(1)


# -----------------------------------------------------------------------------
# V2 ratchet client : génère un batch_0, enroll, auth via signature éphémère
# -----------------------------------------------------------------------------

BATCH_SIZE = 50


def derive_identity(mnemonic: str, passphrase: str = ""):
    """Dérive ed25519_sk (long-terme) + chain_0 (pour ratchet) depuis la phrase."""
    return stream_decrypt.derive_identity(mnemonic, passphrase)


def hkdf_expand_bytes(chain_key: bytes, info: bytes, length: int) -> bytes:
    """HKDF-SHA256 — même algo que Bip39/ratchet côté app."""
    return stream_decrypt.hkdf_sha256(chain_key, info, length)


def derive_batch0_and_chain1(chain0: bytes):
    """Reproduit EphemeralRatchet.initialize(chain0)."""
    seeds = hkdf_expand_bytes(
        chain0, b"frappuccino-v2-ratchet-batch-seeds", BATCH_SIZE * 32
    )
    keypairs = []
    for i in range(BATCH_SIZE):
        seed = seeds[i * 32 : (i + 1) * 32]
        pk, sk = nacl.bindings.crypto_sign_seed_keypair(seed)
        keypairs.append((pk, sk))
    chain1 = hkdf_expand_bytes(chain0, b"frappuccino-v2-ratchet-next-chain", 32)
    return keypairs, chain1


def derive_chain0(seed: bytes) -> bytes:
    """HKDF-SHA256(seed, info='stream.ratchet.chain0.v2', 32)."""
    return hkdf_expand_bytes(seed, b"stream.ratchet.chain0.v2", 32)


class V2Client:
    """Client V2 minimal en Python — mirror de StreamServerClient.kt."""

    def __init__(self, base_url: str, identity: dict):
        self.base = base_url.rstrip("/")
        self.identity = identity
        self.http = httpx.Client(timeout=15)
        self.jwt = None
        self._batch_keypairs = None
        self._batch_number = 0
        self._consumed = set()

    def enroll_or_reuse(self) -> bool:
        """
        Enrôle l'identité sur le serveur en postant un batch_0.

        Règle de fil, invisible depuis ce fichier : une identité déjà enrôlée ne
        peut pas re-poster un batch_0, le serveur refuse — c'est le 409 traité
        plus bas. Et il n'y a plus rien à en faire ici : la re-synchronisation
        passait par `GET /auth/v2/status`, route retirée (R-SRV-1), donc on
        renvoie False et l'outil s'arrête. Prendre le rescue in-app ou la CLI Rust.
        """
        # Dérive chain_0 + batch_0
        seed = stream_decrypt.mnemonic_to_seed(self._raw_mnemonic, self._passphrase)
        chain0 = derive_chain0(seed)
        self._batch_keypairs, chain1 = derive_batch0_and_chain1(chain0)
        self._batch_number = 0

        # Concat pks + signature
        pks = [kp[0] for kp in self._batch_keypairs]
        concat = b"".join(pks)
        sig = nacl.bindings.crypto_sign(concat, self.identity["ed25519_sk"])[:64]

        r = self.http.post(
            f"{self.base}/auth/v2/enroll",
            json={
                "ed25519_pk": self.identity["ed25519_pk"].hex(),
                "batch_0_public_keys": [p.hex() for p in pks],
                "batch_0_signature": sig.hex(),
            },
        )
        if r.status_code == 200:
            print(f"[enroll] nouvelle identité enrôlée", file=sys.stderr)
            return True
        if r.status_code == 409:
            print(f"[enroll] identité déjà enrôlée — utilisation du batch courant", file=sys.stderr)
            return self._sync_with_server_batch()
        print(f"[enroll] ERROR {r.status_code}: {r.text}", file=sys.stderr)
        return False

    def _sync_with_server_batch(self) -> bool:
        """
        DÉPRÉCIÉ : interrogeait `GET /auth/v2/status` pour récupérer le batch
        courant du serveur et reproduire la chaîne HKDF localement. Cette route a
        été retirée (2026-06-27, R-SRV-1 : oracle d'activité par identité,
        contraire au motto relais-aveugle), donc cette re-synchronisation de
        batch pour une identité déjà enrôlée n'est plus disponible via cet outil.
        """
        print(
            "[status] DÉPRÉCIÉ : la route /auth/v2/status a été retirée du relais "
            "(R-SRV-1). La re-synchronisation de batch pour une identité déjà "
            "enrôlée n'est plus possible ici — utilise le rescue in-app "
            "(ArchiveModeActivity) ou la CLI Rust.",
            file=sys.stderr,
        )
        return False

    def authenticate(self) -> bool:
        """Challenge + verify avec la première clé éphémère non consommée."""
        # Tente chaque slot 0..49 jusqu'à ce qu'un fonctionne
        for slot in range(BATCH_SIZE):
            if slot in self._consumed:
                continue
            r = self.http.post(f"{self.base}/auth/challenge")
            if r.status_code != 200:
                return False
            nonce_hex = r.json()["nonce"]

            pk, sk = self._batch_keypairs[slot]
            sig = nacl.bindings.crypto_sign(bytes.fromhex(nonce_hex), sk)[:64]
            r = self.http.post(
                f"{self.base}/auth/v2/verify",
                json={
                    "ed25519_pk": self.identity["ed25519_pk"].hex(),
                    "ephemeral_pk": pk.hex(),
                    "batch_number": self._batch_number,
                    "key_index": slot,
                    "nonce": nonce_hex,
                    "signature": sig.hex(),
                },
            )
            self._consumed.add(slot)
            if r.status_code == 200:
                self.jwt = "Bearer " + r.json()["access_token"]
                print(f"[auth] OK via slot {slot}", file=sys.stderr)
                return True
            if r.status_code == 401:
                # Slot probablement consommé côté serveur, essaie le suivant
                continue
            print(f"[auth] ERROR {r.status_code}: {r.text}", file=sys.stderr)
            return False
        print("[auth] tous les slots consommés, aucun dispo", file=sys.stderr)
        return False

    def download_chunk(self, report_id: str, filename: str, out_path: Path) -> bool:
        """GET /file/{report}/{name} — requires JWT."""
        r = self.http.get(
            f"{self.base}/{report_id}/{filename}",
            headers={"Authorization": self.jwt} if self.jwt else {},
        )
        if r.status_code != 200:
            # Repli MORT : les routes de compat Tella `/p/{slug}` et `/{slug}`
            # ont été retirées du relais le 2026-09-03. Il ne pouvait de toute
            # façon pas fonctionner (ce chemin a trois segments, la route en
            # avait deux). Ne pas le réparer ; ce fichier est déjà déprécié.
            r = self.http.get(
                f"{self.base}/p/{report_id}/{filename}",
                headers={"Authorization": self.jwt} if self.jwt else {},
            )
            if r.status_code != 200:
                print(f"[download] ERROR {r.status_code} pour {filename}", file=sys.stderr)
                return False
        out_path.write_bytes(r.content)
        return True


# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------


def main():
    parser = argparse.ArgumentParser(description="V2 archive tool")
    parser.add_argument("--server", default="http://136.244.101.236:8000",
                        help="URL du serveur V2")
    parser.add_argument("--mnemonic", help="Phrase BIP-39 (sinon prompt)")
    parser.add_argument("--passphrase", default="", help="13e mot optionnel")
    parser.add_argument("--inspect", help="Inspecte un blob local (pas de réseau)")
    parser.add_argument("--session", help="ID de session à télécharger (préfixe hex)")
    parser.add_argument("--output", help="Fichier MP4 de sortie (défaut : reassembled.mp4)")
    parser.add_argument("--show-identity", action="store_true",
                        help="Affiche juste l'identité dérivée")
    args = parser.parse_args()

    if args.inspect:
        stream_decrypt.inspect_blob(args.inspect)
        return

    mnemonic = args.mnemonic or getpass.getpass("Phrase BIP-39 (12 mots) : ")

    identity = derive_identity(mnemonic, args.passphrase)
    fingerprint = stream_decrypt.fingerprint(identity["ed25519_pk"])
    print(f"Fingerprint : {fingerprint}", file=sys.stderr)

    if args.show_identity:
        print(f"ed25519_pk = {identity['ed25519_pk'].hex()}")
        print(f"x25519_pk  = {identity['x25519_pk'].hex()}")
        return

    if not args.session:
        print("ERREUR : --session <id> requis (ou --show-identity / --inspect)",
              file=sys.stderr)
        sys.exit(1)

    # Auth V2
    client = V2Client(args.server, identity)
    client._raw_mnemonic = mnemonic
    client._passphrase = args.passphrase

    if not client.enroll_or_reuse():
        print("ERREUR : enroll/sync échoué", file=sys.stderr)
        sys.exit(1)

    if not client.authenticate():
        print("ERREUR : auth échoué — batch probablement épuisé", file=sys.stderr)
        sys.exit(1)

    # La session est un préfixe — on télécharge les blobs de /file/{report}/*
    # Note : ici on a besoin de connaître le report_id qui a hosté la session.
    # Le serveur n'expose pas de listing → on tente de deviner depuis la prod.
    # Pour le demo : l'user peut passer directement un chemin /file/<report>/<session>
    print(
        "[archive] Le listing serveur n'est pas encore implémenté.\n"
        "Pour l'instant, utilise curl directement :\n"
        f"  curl -H 'Authorization: {client.jwt}' \\\n"
        f"       {args.server}/file/<report_id>/<session>_000001.strm \\\n"
        "       -o chunk_001.strm\n"
        "Puis : python stream_decrypt.py --mnemonic '...' chunk_001.strm",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
