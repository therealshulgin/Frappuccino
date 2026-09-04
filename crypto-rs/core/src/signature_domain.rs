//! Explicit domain separation for V2 Ed25519 signatures (audit R-C-1).
//!
//! Every Ed25519 signature in the V2 protocol commits to a one-byte **domain
//! tag** prepended to the signed message. A signature minted for one context
//! can therefore never be replayed in another, even when the underlying
//! message bytes — or their length — coincide. Before R-C-1, separation was
//! only *emergent* (different verifying keys + the 40-byte `nonce‖ts` vs the
//! 1600-byte `concat(50 pk)` length gap), which the Fable 5 adversarial audit
//! flagged as a forgery surface waiting for the next endpoint/length change
//! (the open Tamarin "rotation safety depends on size separation" finding).
//!
//! The verifier (the relay server) MUST prepend the **same** byte before
//! checking the signature. These byte values are a **wire-protocol constant**:
//! changing one invalidates every in-flight signature for that context, and
//! the server's mirror (`server/app/routes/auth_v2.py`, `server/app/auth.py`,
//! `server/app/signature_domain.py`) must be kept byte-identical. The current
//! contexts:
//!
//! | tag  | domain          | signer key      | message            | endpoint                 |
//! |------|-----------------|-----------------|--------------------|--------------------------|
//! | 0x01 | `AuthChallenge` | ephemeral slot  | `nonce‖ts_be_u64`  | `/auth/v2/verify`        |
//! | 0x02 | `BatchRotation` | ephemeral slot  | `concat(50 pk)`    | `/auth/v2/rotate-batch`  |
//! | 0x03 | `Enrollment`    | long-term ed25519 | `concat(50 pk)`  | `/auth/v2/enroll`        |
//! | 0x04 | `ArchiveAuth`   | (RETIRED, Phase C) | —              | (archive reads now identity-free) |
//! | 0x05 | `ProvenanceManifest` | (RETIRED, lean provenance) | —      | (nothing signs or verifies this) |
//! | 0x06 | `ProvenanceKeyAttestation` | (RETIRED, lean provenance) | — | (nothing signs or verifies this) |
//! | 0x07 | `ReportCreate`  | per-report key `R_n` (seed-derived) | `report_id(16)‖report_pk(32)` | `PUT /file/{rid}/{name}` (1st chunk) |
//! | 0x08 | `ReportWrite`   | per-report key `R_n` (seed-derived) | `report_id(16)‖filename‖sha256(body)(32)` | `PUT /file/{rid}/{name}` (every chunk) |
//!
//! **0x07 and 0x08 — the Phase C relay-blind report capability signatures.**
//! Each report is addressed and authorized by a key `R_n` derived from the
//! BIP-39 seed (a *separate* HKDF context, `core::report`), **not** the
//! identity. The relay stores `report_id → report_pk` and never the identity,
//! so a seizure of the relay disk reveals no `identity → report` link. Like
//! 0x01-0x04 these are **server-mirrored** (the relay is the verifier:
//! `server/app/routes/upload.py`), but the signer is the per-report `R_n`, so
//! the relay authorizes writes against a key it was handed at creation time
//! rather than against a published identity. 0x07 authorizes the *lazy
//! creation* of `report_id` at its first chunk PUT (binds the id to its pk);
//! 0x08 authorizes writing one chunk (binds the id to the filename + body
//! hash) and rides every chunk. Both are permanent wire-protocol constants.
//!
//! **0x05 and 0x06 are RESERVED, and nothing emits them.** They were specified
//! for the signed-manifest provenance design: 0x05 over a sealed manifest, 0x06
//! a one-time "mini-cert" letting a third party tie a manifest key to an
//! identity. The metadata walk-back of 2026-06-25 removed that design in favour
//! of the lean hash-plus-Bitcoin model, which deliberately has **no manifest, no
//! signature, no sealing and no identity attestation** (`core::provenance`,
//! module docs). Non-repudiation baked into a stored artifact is a weapon
//! against the witness, not an asset, so attribution is on-demand instead.
//!
//! No signer, no verifier, no test vector: both tags are in the same state as
//! 0x04, and the values stay reserved for the same reason — a byte that was ever
//! specified must never be reused, or an old signature could be replayed into a
//! new context. What survives of the old machinery is `ProvenanceSigner`, kept
//! only to derive the per-recording `OpenTimestamps` blinding salt; despite its
//! name it signs nothing.
//!
//! Any *new* signing context MUST get its own tag here (and on the server, when
//! the relay is the verifier); never reuse an existing tag for a different
//! message shape or purpose.

/// V2 signature context. The discriminant is the one-byte domain tag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum SignatureDomain {
    /// Ephemeral slot signs `nonce ‖ ts_be_u64` for `/auth/v2/verify`.
    AuthChallenge = 0x01,
    /// Ephemeral slot signs `concat(50 new pk)` for `/auth/v2/rotate-batch`.
    BatchRotation = 0x02,
    /// Long-term key signs `concat(50 batch_0 pk)` for `/auth/v2/enroll`.
    Enrollment = 0x03,
    /// **RETIRED (Phase C relay-blind reports).** Was: long-term key signs
    /// `nonce ‖ ts_be_u64` for `/api/v2/archive/auth`. Archive reads are now
    /// identity-free — the phrase-derived `report_id` is the capability, so no
    /// archive-auth signature exists any more. The tag stays RESERVED (never
    /// reuse 0x04) for wire-protocol stability, like the retired provenance
    /// tags; the `tags_are_distinct_and_stable` test keeps it pinned.
    ArchiveAuth = 0x04,
    /// **RETIRED (metadata walk-back, 2026-06-25).** Was: the seed-derived
    /// provenance key `P` signs a manifest's `magic ‖ version ‖ recording_id ‖
    /// signer_pk ‖ fields_root`. Provenance is now the lean hash-plus-Bitcoin
    /// model, which stores no manifest and no signature at all
    /// (`core::provenance`), so nothing emits or verifies this tag. The value
    /// stays RESERVED (never reuse 0x05) for wire-protocol stability, like 0x04.
    ProvenanceManifest = 0x05,
    /// **RETIRED (metadata walk-back, 2026-06-25).** Was: the long-term identity
    /// key attests that a provenance key `P` belongs to this witness, the
    /// "mini-cert" a third party would check a 0x05 manifest against. It went
    /// with the manifest: there is no attestation to mint and nothing to verify
    /// it against. The value stays RESERVED (never reuse 0x06), like 0x04.
    ProvenanceKeyAttestation = 0x06,
    /// Per-report capability key `R_n` (seed-derived, `core::report`) signs
    /// `report_id(16) ‖ report_pk(32)` to authorize the lazy creation of report
    /// `report_id` at its first chunk PUT (Phase C relay-blind reports). The
    /// relay (verifier) checks this against the presented `report_pk` and
    /// stores `report_id → report_pk` — never the identity. Server-mirrored,
    /// like 0x01-0x04.
    ReportCreate = 0x07,
    /// Per-report capability key `R_n` signs `report_id(16) ‖ filename ‖
    /// sha256(body)(32)` to authorize writing one chunk to report `report_id`.
    /// Rides **every** chunk PUT; the relay verifies it under the stored
    /// `report_pk`. Server-mirrored.
    ReportWrite = 0x08,
}

impl SignatureDomain {
    /// The one-byte wire tag prepended to the signed message.
    #[must_use]
    pub fn tag(self) -> u8 {
        self as u8
    }

    /// Build the to-be-signed (or to-be-verified) buffer `[tag] ‖ message`.
    ///
    /// The message itself is never secret here (a public nonce/timestamp or
    /// public keys), so the returned `Vec` is a plain buffer — no zeroize.
    #[must_use]
    pub fn prefixed(self, message: &[u8]) -> Vec<u8> {
        let mut buf = Vec::with_capacity(1 + message.len());
        buf.push(self.tag());
        buf.extend_from_slice(message);
        buf
    }
}

#[cfg(test)]
mod tests {
    use super::SignatureDomain;

    #[test]
    fn tags_are_distinct_and_stable() {
        let tags = [
            SignatureDomain::AuthChallenge.tag(),
            SignatureDomain::BatchRotation.tag(),
            SignatureDomain::Enrollment.tag(),
            SignatureDomain::ArchiveAuth.tag(),
            SignatureDomain::ProvenanceManifest.tag(),
            SignatureDomain::ProvenanceKeyAttestation.tag(),
            SignatureDomain::ReportCreate.tag(),
            SignatureDomain::ReportWrite.tag(),
        ];
        // Stable wire values. 0x01-0x03 + 0x07-0x08 are verified by the relay,
        // so their Python mirror must stay byte-identical. 0x04-0x06 are
        // reserved bytes of flows that no longer exist and nothing emits them;
        // the two states differ, though: 0x04 still HAS a reserved constant in
        // the server mirror (`SIG_DOMAIN_ARCHIVE_AUTH`, kept so the byte is
        // never reused there either), while 0x05/0x06 never had one, having
        // been offline-only when they were believed live. All three are pinned
        // here so none can be quietly reused.
        assert_eq!(tags, [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
        // Pairwise distinct (the whole point of domain separation).
        for i in 0..tags.len() {
            for j in (i + 1)..tags.len() {
                assert_ne!(tags[i], tags[j]);
            }
        }
    }

    /// Whether the relay is a verifier of a domain (so its Python mirror must
    /// stay byte-identical), or the byte is the reservation of a retired flow.
    /// There is no third state any more: see [`ServerMirror::Retired`].
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum ServerMirror {
        /// Relay-verified — `server/app/signature_domain.py` + `routes/*.py`
        /// must mirror this tag and signed-message layout byte-for-byte.
        Yes,
        /// Reserved byte of a flow that no longer exists — never reused,
        /// never mirrored, emitted by nothing. Covers both a flow that shipped
        /// and was removed (0x04, archive auth) and one that was specified then
        /// walked back before any signer existed (0x05/0x06, signed provenance
        /// manifests).
        ///
        /// There is deliberately no `No` variant for "live but offline-only".
        /// It existed for 0x05/0x06 while they were believed live; nothing in
        /// the tree signs outside the relay's view today. Bring it back with the
        /// flow that needs it, not before, so the enum cannot claim a capability
        /// the code does not have.
        Retired,
    }

    /// The COMPLETE, frozen protocol surface: `(variant, tag, server-mirror)`,
    /// in exactly the set the Tamarin model (`core/proofs/RatchetProtocol.spthy`),
    /// the server mirror, and `ARCHITECTURE_TECHNIQUE_COMPLETE.md` §4.4 describe.
    const FROZEN_SURFACE: [(SignatureDomain, u8, ServerMirror); 8] = [
        (SignatureDomain::AuthChallenge, 0x01, ServerMirror::Yes),
        (SignatureDomain::BatchRotation, 0x02, ServerMirror::Yes),
        (SignatureDomain::Enrollment, 0x03, ServerMirror::Yes),
        (SignatureDomain::ArchiveAuth, 0x04, ServerMirror::Retired),
        (SignatureDomain::ProvenanceManifest, 0x05, ServerMirror::Retired),
        (
            SignatureDomain::ProvenanceKeyAttestation,
            0x06,
            ServerMirror::Retired,
        ),
        (SignatureDomain::ReportCreate, 0x07, ServerMirror::Yes),
        (SignatureDomain::ReportWrite, 0x08, ServerMirror::Yes),
    ];

    /// The descriptor every domain MUST have. The `match` is **exhaustive with
    /// no wildcard on purpose**: adding / removing a `SignatureDomain` variant
    /// makes this fail to compile, which is the model-fidelity gate (see
    /// [`signature_domain_surface_is_frozen`]).
    fn descriptor(d: SignatureDomain) -> (u8, ServerMirror) {
        match d {
            SignatureDomain::AuthChallenge => (0x01, ServerMirror::Yes),
            SignatureDomain::BatchRotation => (0x02, ServerMirror::Yes),
            SignatureDomain::Enrollment => (0x03, ServerMirror::Yes),
            SignatureDomain::ArchiveAuth => (0x04, ServerMirror::Retired),
            SignatureDomain::ProvenanceManifest => (0x05, ServerMirror::Retired),
            SignatureDomain::ProvenanceKeyAttestation => (0x06, ServerMirror::Retired),
            SignatureDomain::ReportCreate => (0x07, ServerMirror::Yes),
            SignatureDomain::ReportWrite => (0x08, ServerMirror::Yes),
            // ── ADDING AN ARM HERE? The protocol surface changed. In lockstep:
            //   1. update the Tamarin model RatchetProtocol.spthy (+ neg controls)
            //      if the domain is in the auth/rotation flow;
            //   2. mirror it byte-identically in server/app/signature_domain.py
            //      + routes/*.py if the relay verifies it;
            //   3. update docs ARCHITECTURE_TECHNIQUE_COMPLETE.md §4.4 + Annexe A,
            //      GUIDE_AUDITEUR.md, and scripts/check-doc-currency.sh;
            //   4. extend FROZEN_SURFACE above so this test re-pins the new set.
        }
    }

    /// MODEL-FIDELITY GATE (Q1 anti-drift). Freezes the full signature-domain
    /// surface so a protocol-surface change can never land with stale proofs,
    /// a stale server mirror, or stale docs: the build stops at [`descriptor`]
    /// (exhaustive `match`) until they are reconciled, and this test re-pins the
    /// tag + mirror status of every existing domain against [`FROZEN_SURFACE`].
    #[test]
    fn signature_domain_surface_is_frozen() {
        assert_eq!(
            FROZEN_SURFACE.len(),
            8,
            "the V2 protocol has exactly 8 signature domains (0x01-0x08)"
        );
        for (domain, tag, mirror) in FROZEN_SURFACE {
            assert_eq!(domain.tag(), tag, "wire tag drift for {domain:?}");
            assert_eq!(
                descriptor(domain),
                (tag, mirror),
                "descriptor (tag/server-mirror) drift for {domain:?}"
            );
        }
    }

    #[test]
    fn prefixed_prepends_exactly_one_tag_byte() {
        let msg = b"hello";
        let out = SignatureDomain::AuthChallenge.prefixed(msg);
        assert_eq!(out.len(), 1 + msg.len());
        assert_eq!(out[0], 0x01);
        assert_eq!(&out[1..], msg);
    }

    #[test]
    fn distinct_domains_yield_distinct_tbs_for_same_message() {
        let msg = b"same-bytes";
        assert_ne!(
            SignatureDomain::AuthChallenge.prefixed(msg),
            SignatureDomain::ArchiveAuth.prefixed(msg),
        );
        assert_ne!(
            SignatureDomain::BatchRotation.prefixed(msg),
            SignatureDomain::Enrollment.prefixed(msg),
        );
        // Phase C report tags: create vs write must never share a TBS buffer.
        assert_ne!(
            SignatureDomain::ReportCreate.prefixed(msg),
            SignatureDomain::ReportWrite.prefixed(msg),
        );
    }
}
