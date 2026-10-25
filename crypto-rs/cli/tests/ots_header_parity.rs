//! The device reads the timestamped digest of an `OpenTimestamps` proof with a
//! small header reader of its own (`uniffi_frappuccino::ots_proof_status`):
//! the `.so` carries no `OpenTimestamps` parser. This test checks that reader
//! against proofs serialized by the real `opentimestamps` crate, the one the
//! CLI verifies Bitcoin anchoring with, so the two cannot disagree on what a
//! proof timestamps.

use std::fs;
use std::path::PathBuf;

use opentimestamps::attestation::Attestation;
use opentimestamps::ser::DigestType;
use opentimestamps::timestamp::{Step, StepData, Timestamp};
use opentimestamps::DetachedTimestampFile;
use uniffi_frappuccino::{ots_proof_status, OtsStatus};

fn write_proof(path: &PathBuf, digest: &[u8], attestation: Attestation) {
    let file = DetachedTimestampFile {
        digest_type: DigestType::Sha256,
        timestamp: Timestamp {
            start_digest: digest.to_vec(),
            first_step: Step {
                data: StepData::Attestation(attestation),
                output: digest.to_vec(),
                next: vec![],
            },
        },
    };
    file.to_writer(fs::File::create(path).unwrap()).unwrap();
}

#[test]
fn the_device_reader_agrees_with_the_opentimestamps_crate() {
    let dir = std::env::temp_dir().join(format!("frap_ots_parity_{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let digest = [0x5Eu8; 32];
    let attestations = [
        Attestation::Pending {
            uri: "https://alice.btc.calendar.opentimestamps.org".to_owned(),
        },
        Attestation::Bitcoin { height: 812_345 },
    ];
    for (i, attestation) in attestations.into_iter().enumerate() {
        let path = dir.join(format!("proof_{i}.ots"));
        write_proof(&path, &digest, attestation);
        let path = Some(path.to_str().unwrap().to_owned());
        assert_eq!(
            ots_proof_status(path.clone(), &digest).unwrap(),
            OtsStatus::Match
        );
        assert_eq!(
            ots_proof_status(path, &[0x5Fu8; 32]).unwrap(),
            OtsStatus::Mismatch
        );
    }
    let _ = fs::remove_dir_all(&dir);
}
