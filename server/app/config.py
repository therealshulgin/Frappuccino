import logging
import os
import sys

logger = logging.getLogger("stream.config")

MINIO_ENDPOINT = os.getenv("MINIO_ENDPOINT", "localhost:9000")
MINIO_ACCESS_KEY = os.getenv("MINIO_ACCESS_KEY", "streamadmin")
MINIO_SECRET_KEY = os.getenv("MINIO_SECRET_KEY", "streamadmin-secret")
MINIO_SECURE = os.getenv("MINIO_SECURE", "false").lower() == "true"
MINIO_BUCKET = os.getenv("MINIO_BUCKET", "stream-blobs")

# C-06: JWT secret MUST be provided via env var — no auto-generation
JWT_SECRET = os.getenv("JWT_SECRET")
if not JWT_SECRET:
    logger.critical("FATAL: JWT_SECRET env var is required. Generate one with: python -c \"import secrets; print(secrets.token_hex(32))\"")
    sys.exit(1)

JWT_ALGORITHM = "HS256"
# Access-token lifetime. There are no refresh tokens in V2 and none should be
# added: a long-lived refresh credential is exactly the persistent bearer the
# ephemeral ratchet exists to eliminate. "Refreshing" here means calling
# /auth/v2/verify again, which consumes a fresh ratchet slot and buys
# forward secrecy per upload — that slot is the real cost of a shorter exp.
#
# A stolen token is bounded by this exp and can also be killed on the spot with
# POST /auth/v2/logout (jwt_blacklist). The default stays 24 h because the theft
# surface is already small: the JWT is RAM-only on the client, never written to
# disk (audit R-01), and the relay is SPKI-pinned, while a shorter exp costs
# extra slots and round-trips on the intermittent connectivity this app targets.
#
# Dialling it down is a legitimate per-deployment call — 4 h suits a high-churn
# deployment where slots are plentiful — but never on its own: the client does
# not read this value. StreamRecordingService.kt hardcodes a 24 h lifetime and a
# refresh at T-1h in two constants, so lowering the exp here without touching
# them leaves the upload workers taking 401s past the real expiry. They do
# recover — clear the token, retry — but each recovery costs a WorkManager
# backoff and one more ratchet slot.
JWT_EXPIRE_HOURS = int(os.getenv("JWT_EXPIRE_HOURS", "24"))

# Phase 4.4 — reports persistence path. JSON file on disk, reloaded at
# startup. Cheap and good enough for the relay's use case (Phase 4.4
# archive retrieval needs the user→reports mapping to survive reboots).
# Override via env to point at a volume mount in container deployments.
REPORTS_DB_PATH = os.getenv("REPORTS_DB_PATH", "data/reports.json")

# Phase C (relay-blind reports) anti-abuse (D1) — soft per-identity,
# per-batch report creation budget. The creating PUT proves enrollment with a
# stream JWT; we bump a *count* per (identity, current batch_number) in the
# ratchet registry (a number, never a report↔identity map) and reject beyond
# this ceiling. Generous on purpose: it stops a runaway sybil minting unbounded
# reports on one enrolled batch, not legitimate field use (a batch is 50 auth
# slots ≈ many sessions). Override per deployment.
MAX_REPORTS_PER_BATCH = int(os.getenv("MAX_REPORTS_PER_BATCH", "256"))

# Archive blob retention TTL: blobs older than this are purged by the periodic
# cleanup (blob_cleanup.py).
#
# Six months looks careless and is not. The TTL was 24 h at first, to shrink the
# exposure window on server seizure, and that turned out to cost testimony: on
# intermittent connectivity a session's upload queue can take far longer than a
# day to drain (observed 2026-05-21, a session on bad train coverage), and any
# blob the cleanup reaches before the device has finished rapatriating it is
# lost for good.
#
# Tightening this back down does not buy what it looks like it buys: STRM blobs
# are end-to-end encrypted and useless without the BIP-39-derived keys, which
# never leave the client, so a longer retention on the relay does not
# meaningfully widen what a seizure yields. Stricter deployments can still
# override via env.
BLOB_TTL_SECONDS = int(os.getenv("ARCHIVE_BLOB_TTL_SECONDS", str(180 * 24 * 3600)))  # 6 months

# Phase C (relay-blind reports) — the empty-report sweep TTL is gone. The lazy
# blob-first invariant (a record is written only AFTER >=1 durable blob) means
# there are no 0-blob "zombie" records at creation anymore, so the reaper
# (report_cleanup.py) deletes records purely on "0 blobs == fully purged", with
# no per-record timestamp to age-guard (we store no createdAt). See
# report_cleanup.reap_blobless_reports.

# V2 : legacy username/password login entirely removed.
# Kept as False constants for any residual import; not read from env anymore.
LEGACY_LOGIN_ENABLED = False
LEGACY_USERNAME = ""
LEGACY_PASSWORD = ""

# Relay-assisted OpenTimestamps (§10.11). The relay takes a 32-byte opaque
# commitment from the witness, submits it to the public OTS calendars in the
# witness's place, and returns the detached `.ots` proof, which the witness
# uploads durably like any other blob. The indirection is the whole point: have
# the device submit its own commitment and the witness's IP is handed to a set
# of third parties nobody chose, which is a de-anonymisation vector.
#
# The feature is dormant — /api/v2/timestamp answers 503 until OTS_ENABLED=true
# and the `opentimestamps` library is actually installed. That library is kept
# out of requirements.txt on purpose (it lives in requirements-ots.txt) so the
# running relay's dependency closure stays as small as it is audited to be.
# Tidying it back into the base requirements would widen that closure and arm
# the endpoint without anyone deciding to. Enabling it for real touches the
# relay in PROD, so it takes a separate operator GO.
OTS_ENABLED = os.getenv("OTS_ENABLED", "false").lower() == "true"

# Public OpenTimestamps calendars (the reference set the `ots` client ships).
# Submitting to several is redundancy, not trust: a calendar can only FAIL to
# anchor a digest, never forge a fake anchor (the Bitcoin proof-of-work is what
# is trusted, not the calendar). Comma-separated; override per deployment.
OTS_CALENDAR_URLS = [
    u.strip()
    for u in os.getenv(
        "OTS_CALENDAR_URLS",
        "https://alice.btc.calendar.opentimestamps.org,"
        "https://bob.btc.calendar.opentimestamps.org,"
        "https://finney.calendar.eternitywall.com",
    ).split(",")
    if u.strip()
]

# Per-calendar submission timeout (seconds). Kept short: a stamp is best-effort
# and the device retries, so we don't want a slow calendar tying up the single
# worker on a thread.
OTS_SUBMIT_TIMEOUT_S = float(os.getenv("OTS_SUBMIT_TIMEOUT_S", "10"))
