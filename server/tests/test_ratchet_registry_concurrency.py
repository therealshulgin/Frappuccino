#!/usr/bin/env python3
"""
Concurrency tests for `app.ratchet_registry`, whose every mutation is already
wrapped in a `threading.Lock` — a surface the audit scope flagged as untested
(`AUDIT_SCOPE_RUST §6.3 — Batch chain TTL queued`).

What they prove is bounded, and the bound is the point: that Lock holds within
ONE Python process, not across forks, and the tests below spawn threads inside a
single process. They validate exactly what `--workers 1` exposes. Moving the
relay to `uvicorn --workers N` (RT-12) on the strength of a green run here would
reintroduce the double-consume of an ephemeral slot, which is the replay the
ratchet exists to prevent.

The races covered: concurrent consumes of the same slot, concurrent rotations
from the same (batch_number, key_index), and concurrent enrollments of the same
identity — exactly one winner each — plus consumes of disjoint slots, where all
must succeed, because the lock must not serialize what is legitimately parallel.

The requirement is ROADMAP 4.2.2, which also says what to do when a race here
goes red: fix the `threading.Lock` in the registry, not the test.
"""

import concurrent.futures
import os
import sys
import tempfile

# Same pattern as test_auth_v2.py: redirect the registry file before import.
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
os.environ["JWT_SECRET"] = os.environ.get("JWT_SECRET") or "test-secret-do-not-use-in-prod"
_tmpdir = tempfile.mkdtemp()
os.environ["RATCHET_REGISTRY_FILE"] = os.path.join(_tmpdir, "concurrency_registry.json")

import nacl.bindings  # noqa: E402
import pytest  # noqa: E402

from app import ratchet_registry  # noqa: E402


# ----------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------


def fresh_identity() -> tuple[str, list[str], str]:
    """Generate an Ed25519 identity + a 50-key batch_0 + a signature over the
    concatenated batch keys. Returns (pk_hex, batch_keys, sig_hex)."""
    long_pk, long_sk = nacl.bindings.crypto_sign_keypair()

    batch_keys = []
    for _ in range(ratchet_registry.BATCH_SIZE):
        ek_pk, _ek_sk = nacl.bindings.crypto_sign_keypair()
        batch_keys.append(ek_pk.hex())

    concat = b"".join(bytes.fromhex(k) for k in batch_keys)
    sig = nacl.bindings.crypto_sign(concat, long_sk)[: nacl.bindings.crypto_sign_BYTES]
    return long_pk.hex(), batch_keys, sig.hex()


def _enroll_one() -> str:
    pk_hex, batch_keys, sig_hex = fresh_identity()
    ok = ratchet_registry.enroll(pk_hex, batch_keys, sig_hex)
    assert ok, "enroll should succeed for fresh identity"
    return pk_hex


@pytest.fixture(autouse=True)
def _clean_registry():
    """Reset the in-memory registry between tests (test isolation)."""
    ratchet_registry._clear_for_tests()
    yield
    ratchet_registry._clear_for_tests()


# ----------------------------------------------------------------------------
# Tests
# ----------------------------------------------------------------------------


def test_concurrent_consume_same_key_only_one_wins():
    """Race on consume_ephemeral_key with the SAME (batch=0, key_index=0).

    The lock must serialize so that the first thread sees an empty
    consumed_indices set and the others see {0}, returning False.
    """
    pk_hex = _enroll_one()
    n_workers = 8

    def attempt() -> bool:
        return ratchet_registry.consume_ephemeral_key(pk_hex, 0, 0)

    with concurrent.futures.ThreadPoolExecutor(max_workers=n_workers) as ex:
        results = list(ex.map(lambda _i: attempt(), range(n_workers)))

    successes = sum(1 for r in results if r)
    failures = sum(1 for r in results if not r)
    assert successes == 1, (
        f"exactly one consume must win on the same slot, got {successes} "
        f"(results = {results}) — Lock leaked or not held across the read-modify-write"
    )
    assert failures == n_workers - 1, "the rest must be losers, not crashers"

    entry = ratchet_registry.get(pk_hex)
    assert entry is not None
    assert entry["consumed_indices"] == {0}, (
        f"only slot 0 should be consumed, got {entry['consumed_indices']}"
    )


def test_concurrent_consume_different_keys_all_succeed():
    """Sanity check: the lock must NOT bottleneck legitimately disjoint
    consumes. 8 threads consume 8 different slot indices → all must
    succeed.
    """
    pk_hex = _enroll_one()
    n_workers = 8

    def attempt(idx: int) -> bool:
        return ratchet_registry.consume_ephemeral_key(pk_hex, 0, idx)

    with concurrent.futures.ThreadPoolExecutor(max_workers=n_workers) as ex:
        results = list(ex.map(attempt, range(n_workers)))

    assert all(results), (
        f"all {n_workers} disjoint consumes must succeed, got {results}"
    )
    entry = ratchet_registry.get(pk_hex)
    assert entry is not None
    assert entry["consumed_indices"] == set(range(n_workers))


def test_concurrent_rotate_batch_only_one_wins():
    """Race on rotate_batch with the same signer_key_index. Exactly one
    must produce a new batch_number; the others must return None and
    leave the registry coherent.
    """
    pk_hex = _enroll_one()
    n_workers = 8

    # Each rotation needs its own fresh batch_keys + signature (the actual
    # signature isn't verified inside ratchet_registry — that's the route
    # layer's job — but len() == BATCH_SIZE is asserted).
    def make_rotation_args() -> tuple[list[str], str]:
        new_keys = []
        for _ in range(ratchet_registry.BATCH_SIZE):
            pk, _sk = nacl.bindings.crypto_sign_keypair()
            new_keys.append(pk.hex())
        return new_keys, "00" * 64  # opaque sig — registry doesn't verify

    rotation_args = [make_rotation_args() for _ in range(n_workers)]

    def attempt(args: tuple[list[str], str]):
        new_keys, sig_hex = args
        return ratchet_registry.rotate_batch(pk_hex, 0, 0, new_keys, sig_hex)

    with concurrent.futures.ThreadPoolExecutor(max_workers=n_workers) as ex:
        results = list(ex.map(attempt, rotation_args))

    successes = [r for r in results if r is not None]
    failures = [r for r in results if r is None]
    assert len(successes) == 1, (
        f"exactly one rotate_batch must win, got {len(successes)} successes "
        f"(results = {results})"
    )
    assert successes[0] == 1, f"new batch_number must be 1, got {successes[0]}"
    assert len(failures) == n_workers - 1

    # Registry must reflect a single coherent post-rotation state:
    # batch_number=1, consumed_indices={} (fresh).
    entry = ratchet_registry.get(pk_hex)
    assert entry is not None
    assert entry["batch_number"] == 1
    assert entry["consumed_indices"] == set()


def test_concurrent_enroll_same_pk_only_one_wins():
    """Bonus: two threads racing to enroll the same pk_hex. Lock must
    ensure exactly one returns True; the other sees the entry already
    there and returns False.
    """
    pk_hex, batch_keys, sig_hex = fresh_identity()
    n_workers = 4

    def attempt() -> bool:
        return ratchet_registry.enroll(pk_hex, batch_keys, sig_hex)

    with concurrent.futures.ThreadPoolExecutor(max_workers=n_workers) as ex:
        results = list(ex.map(lambda _i: attempt(), range(n_workers)))

    successes = sum(1 for r in results if r)
    assert successes == 1, (
        f"exactly one enroll must win, got {successes} (results = {results})"
    )
