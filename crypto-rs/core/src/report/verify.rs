//! Secret-free verification of report signatures.
//!
//! Every function takes the report public key and recomputes `report_id =
//! H(report_pk)` itself: a `report_id` is never accepted as input, so a caller
//! cannot verify a signature against an id that does not belong to the key.
//! The rescue device passes the key it re-derived from the phrase; the envelope
//! check passes the key carried by the envelope and compares the recomputed id
//! to the one it was given.
//!
//! Verification uses dalek's `verify_strict`, the stricter of its two modes
//! (it refuses small-order keys and non-canonical signatures), which are not
//! what an honest dalek signer produces.

use super::{
    close_message, create_message, report_id_from_pk, sha256, write_message, Manifest, ReportError,
    HASH_BYTES, PK_BYTES, SIG_BYTES,
};
use crate::signature_domain::SignatureDomain;
use ed25519_dalek::{Signature, VerifyingKey};

/// Check a 0x07 `create_sig` under `report_pk`.
///
/// # Errors
/// [`ReportError::InvalidPublicKey`] or [`ReportError::InvalidSignature`].
#[must_use = "a verification result must be checked"]
pub fn verify_create(
    report_pk: &[u8; PK_BYTES],
    create_sig: &[u8; SIG_BYTES],
) -> Result<(), ReportError> {
    let report_id = report_id_from_pk(report_pk);
    verify_domain(
        report_pk,
        SignatureDomain::ReportCreate,
        &create_message(&report_id, report_pk),
        create_sig,
    )
}

/// Check a 0x08 `write_sig` of object `filename` with stored-bytes hash
/// `body_sha256` under `report_pk`.
///
/// # Errors
/// [`ReportError::InvalidPublicKey`] or [`ReportError::InvalidSignature`].
#[must_use = "a verification result must be checked"]
pub fn verify_write(
    report_pk: &[u8; PK_BYTES],
    filename: &[u8],
    body_sha256: &[u8; HASH_BYTES],
    write_sig: &[u8; SIG_BYTES],
) -> Result<(), ReportError> {
    let report_id = report_id_from_pk(report_pk);
    verify_domain(
        report_pk,
        SignatureDomain::ReportWrite,
        &write_message(&report_id, filename, body_sha256),
        write_sig,
    )
}

/// Check a 0x09 closure: parse `manifest` strictly ([`Manifest::parse`]),
/// require `seq_limit` to be the one the manifest implies, then verify
/// `close_sig` over `report_id ‖ u32_be(seq_limit) ‖ sha256(manifest)`.
/// Returns the parsed manifest on success.
///
/// This checks structure and authenticity only. Which shapes a scheme allows
/// (empty for a legacy closure, starting at seq 0 for a chained one) is
/// checked by [`super::RescueReport::verify_close`].
///
/// # Errors
/// [`ReportError::InvalidManifest`], [`ReportError::SeqLimitMismatch`],
/// [`ReportError::InvalidPublicKey`] or [`ReportError::InvalidSignature`].
#[must_use = "a verification result must be checked"]
pub fn verify_close(
    report_pk: &[u8; PK_BYTES],
    seq_limit: u32,
    manifest: &[u8],
    close_sig: &[u8; SIG_BYTES],
) -> Result<Manifest, ReportError> {
    let parsed = Manifest::parse(manifest)?;
    if parsed.seq_limit() != seq_limit {
        return Err(ReportError::SeqLimitMismatch);
    }
    let report_id = report_id_from_pk(report_pk);
    verify_domain(
        report_pk,
        SignatureDomain::ReportClose,
        &close_message(&report_id, seq_limit, &sha256(manifest)),
        close_sig,
    )?;
    Ok(parsed)
}

fn verify_domain(
    report_pk: &[u8; PK_BYTES],
    domain: SignatureDomain,
    message: &[u8],
    signature: &[u8; SIG_BYTES],
) -> Result<(), ReportError> {
    let key = VerifyingKey::from_bytes(report_pk).map_err(|_| ReportError::InvalidPublicKey)?;
    key.verify_strict(&domain.prefixed(message), &Signature::from_bytes(signature))
        .map_err(|_| ReportError::InvalidSignature)
}

#[cfg(test)]
mod tests {
    use super::super::{
        report_id_from_pk, sign_close_under, sign_create_under, sign_write_under, ManifestEntry,
    };
    use super::*;
    use ed25519_dalek::SigningKey;

    fn key(fill: u8) -> SigningKey {
        SigningKey::from_bytes(&[fill; 32])
    }

    fn three_entries() -> Manifest {
        Manifest::from_entries(vec![
            ManifestEntry {
                seq: 0,
                blob_sha256: [1; 32],
            },
            ManifestEntry {
                seq: 1,
                blob_sha256: [2; 32],
            },
            ManifestEntry {
                seq: 4,
                blob_sha256: [3; 32],
            },
        ])
        .unwrap()
    }

    /// A 32-byte string that is not a valid compressed Edwards point.
    fn invalid_point() -> [u8; 32] {
        (0u8..=255)
            .map(|fill| [fill; 32])
            .find(|bytes| VerifyingKey::from_bytes(bytes).is_err())
            .expect("some constant byte string is off the curve")
    }

    #[test]
    fn create_and_write_verify_under_their_key_only() {
        let sk = key(7);
        let pk = sk.verifying_key().to_bytes();
        let other = key(8).verifying_key().to_bytes();
        let create = sign_create_under(&sk);
        verify_create(&pk, &create).unwrap();
        assert_eq!(
            verify_create(&other, &create).unwrap_err(),
            ReportError::InvalidSignature
        );
        let write = sign_write_under(&sk, b"000003.strm", &[9; 32]);
        verify_write(&pk, b"000003.strm", &[9; 32], &write).unwrap();
        for (name, hash) in [
            (&b"000004.strm"[..], [9u8; 32]),
            (&b"000003.strm"[..], [8u8; 32]),
        ] {
            assert_eq!(
                verify_write(&pk, name, &hash, &write).unwrap_err(),
                ReportError::InvalidSignature
            );
        }
        assert_eq!(
            verify_write(&other, b"000003.strm", &[9; 32], &write).unwrap_err(),
            ReportError::InvalidSignature
        );
    }

    #[test]
    fn close_verifies_and_returns_the_parsed_manifest() {
        let sk = key(7);
        let pk = sk.verifying_key().to_bytes();
        let manifest = three_entries();
        let bytes = manifest.to_bytes();
        let sig = sign_close_under(&sk, 5, &sha256(&bytes));
        assert_eq!(verify_close(&pk, 5, &bytes, &sig).unwrap(), manifest);
    }

    #[test]
    fn close_rejects_a_wrong_limit_a_tampered_manifest_and_a_foreign_key() {
        let sk = key(7);
        let pk = sk.verifying_key().to_bytes();
        let bytes = three_entries().to_bytes();
        let sig = sign_close_under(&sk, 5, &sha256(&bytes));
        assert_eq!(
            verify_close(&pk, 4, &bytes, &sig).unwrap_err(),
            ReportError::SeqLimitMismatch
        );
        assert_eq!(
            verify_close(&pk, 6, &bytes, &sig).unwrap_err(),
            ReportError::SeqLimitMismatch
        );
        // Same shape, one hash byte changed: structurally valid, not signed.
        let mut tampered = bytes.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert_eq!(
            verify_close(&pk, 5, &tampered, &sig).unwrap_err(),
            ReportError::InvalidSignature
        );
        assert_eq!(
            verify_close(&pk, 5, &bytes[..bytes.len() - 1], &sig).unwrap_err(),
            ReportError::InvalidManifest("length does not match count")
        );
        let other = key(8).verifying_key().to_bytes();
        assert_eq!(
            verify_close(&other, 5, &bytes, &sig).unwrap_err(),
            ReportError::InvalidSignature
        );
    }

    #[test]
    fn signatures_never_cross_domains() {
        // Build a close message and sign it under the WRITE domain by hand: the
        // close verifier must refuse it, and the reverse.
        let sk = key(7);
        let pk = sk.verifying_key().to_bytes();
        let id = report_id_from_pk(&pk);
        let bytes = three_entries().to_bytes();
        let message = close_message(&id, 5, &sha256(&bytes));
        let as_write = {
            use ed25519_dalek::Signer;
            sk.sign(&SignatureDomain::ReportWrite.prefixed(&message))
                .to_bytes()
        };
        assert_eq!(
            verify_close(&pk, 5, &bytes, &as_write).unwrap_err(),
            ReportError::InvalidSignature
        );
        let close = sign_close_under(&sk, 5, &sha256(&bytes));
        // The write verifier rebuilds `id ‖ filename ‖ hash`. With the close
        // fields as filename and hash, it rebuilds the exact close message;
        // only the domain byte differs, and that alone must make it fail.
        let filename = 5u32.to_be_bytes();
        assert_eq!(
            verify_write(&pk, &filename, &sha256(&bytes), &close).unwrap_err(),
            ReportError::InvalidSignature
        );
    }

    #[test]
    fn an_off_curve_key_is_reported_as_such() {
        let bad = invalid_point();
        assert_eq!(
            verify_create(&bad, &[0; 64]).unwrap_err(),
            ReportError::InvalidPublicKey
        );
        assert_eq!(
            verify_write(&bad, b"x", &[0; 32], &[0; 64]).unwrap_err(),
            ReportError::InvalidPublicKey
        );
        let empty = Manifest::empty().to_bytes();
        assert_eq!(
            verify_close(&bad, 0, &empty, &[0; 64]).unwrap_err(),
            ReportError::InvalidPublicKey
        );
    }
}
