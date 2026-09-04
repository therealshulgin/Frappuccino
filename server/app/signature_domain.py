"""Explicit V2 signature domain separation (audit R-C-1) — server mirror.

These one-byte tags MUST stay byte-identical to the Rust source of truth in
``crypto-rs/core/src/signature_domain.rs``. The client prepends the tag to the
signed message before signing; the server prepends the same tag before
verifying. Changing a value invalidates every in-flight signature for that
context, so client and server must be deployed together.

| tag  | domain          | signer key        | message                      | endpoint                |
|------|-----------------|-------------------|------------------------------|-------------------------|
| 0x01 | AuthChallenge   | ephemeral slot    | nonce||ts_be_u64             | /auth/v2/verify         |
| 0x02 | BatchRotation   | ephemeral slot    | concat(50 pk)                | /auth/v2/rotate-batch   |
| 0x03 | Enrollment      | long-term ed25519 | concat(50 pk)                | /auth/v2/enroll         |
| 0x04 | ArchiveAuth     | (RETIRED, Phase C)| --                           | (archive reads id-free) |
| 0x07 | ReportCreate    | per-report R_n    | report_id(16)||report_pk(32) | PUT /file/{rid}/{name}  |
| 0x08 | ReportWrite     | per-report R_n    | report_id(16)||name||sha(32) | PUT /file/{rid}/{name}  |

0x05/0x06 (provenance manifest/attestation) are RETIRED and RESERVED: the signed
manifest design was dropped in the 2026-06-25 metadata walk-back, so nothing emits
or verifies them, on the client or here. They stay absent from this file, and their
byte values stay reserved so they can never be reused
(``crypto-rs/core/src/signature_domain.rs``).

0x07/0x08 are the relay-blind report capability tags: each report is authorized
by a key ``R_n`` derived from the BIP-39 seed (``core::report``), not the
identity, so the relay stores ``report_id -> report_pk`` and never the identity.
The relay is the verifier for both, in ``app/routes/upload.py``: 0x07 gates the
creating PUT, 0x08 covers the body of every PUT.
"""

SIG_DOMAIN_AUTH_CHALLENGE = b"\x01"
SIG_DOMAIN_BATCH_ROTATION = b"\x02"
SIG_DOMAIN_ENROLLMENT = b"\x03"
# RETIRED (Phase C relay-blind reports): archive reads are now identity-free
# (the phrase-derived report_id is the capability), so the relay no longer
# verifies an archive-auth signature. Kept RESERVED for wire-tag stability so
# 0x04 is never reused for a new context (mirrors the Rust enum variant).
SIG_DOMAIN_ARCHIVE_AUTH = b"\x04"
SIG_DOMAIN_REPORT_CREATE = b"\x07"
SIG_DOMAIN_REPORT_WRITE = b"\x08"
