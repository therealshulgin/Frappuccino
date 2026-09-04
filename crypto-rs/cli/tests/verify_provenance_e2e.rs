//! End-to-end test for the LEAN `frappuccino-cli verify-provenance` (§10.11
//! "hash + Bitcoin" model).
//!
//! The disclosure bundle is just the plaintext media chunks + an `.ots` proof
//! (+ a salt) — NO manifest, NO cert, NO signature. The verifier recomputes the
//! media Merkle root from the chunks, confirms the `.ots` commits
//! `SHA-256(salt ‖ root)`, and reports the Bitcoin anchor. This proves integrity
//! and anteriority; attribution is deliberately out of scope (on-demand, never
//! a stored artifact).

use std::fs;
use std::path::PathBuf;
use std::process::Command;

use frappuccino_crypto_core::provenance::{
    chunk_merkle_root, hash_plaintext_chunk, ots_media_commitment,
};

struct Bundle {
    dir: PathBuf,
    chunks: Vec<PathBuf>,
    root: [u8; 32],
}

fn build_bundle(tag: &str, chunks_data: &[&[u8]]) -> Bundle {
    let dir = std::env::temp_dir().join(format!("fppv-{}-{}", std::process::id(), tag));
    fs::create_dir_all(&dir).unwrap();
    let mut chunks = Vec::new();
    let mut hashes = Vec::new();
    for (i, c) in chunks_data.iter().enumerate() {
        let cp = dir.join(format!("chunk_{i:06}.mp4"));
        fs::write(&cp, c).unwrap();
        chunks.push(cp);
        hashes.push(hash_plaintext_chunk(c));
    }
    let root = chunk_merkle_root(&hashes);
    Bundle { dir, chunks, root }
}

/// Build a minimal `.ots` proof (digest → single attestation) and write it.
/// `bitcoin_height = Some(h)` makes it a Bitcoin-anchored proof; `None` a
/// pending-calendar proof. Round-tripping the real crate proves the verifier
/// reads exactly what a real relay submission writes.
fn write_ots(path: &PathBuf, digest: &[u8], bitcoin_height: Option<usize>) {
    use opentimestamps::attestation::Attestation;
    use opentimestamps::ser::DigestType;
    use opentimestamps::timestamp::{Step, StepData, Timestamp};
    use opentimestamps::DetachedTimestampFile;

    let att = match bitcoin_height {
        Some(h) => Attestation::Bitcoin { height: h },
        None => Attestation::Pending {
            uri: "https://alice.btc.calendar.opentimestamps.org".to_string(),
        },
    };
    let step = Step {
        data: StepData::Attestation(att),
        output: digest.to_vec(),
        next: vec![],
    };
    let ts = Timestamp {
        start_digest: digest.to_vec(),
        first_step: step,
    };
    let dtf = DetachedTimestampFile {
        digest_type: DigestType::Sha256,
        timestamp: ts,
    };
    let f = fs::File::create(path).unwrap();
    dtf.to_writer(f).unwrap();
}

fn run_verify(chunks: &[PathBuf], ots: &PathBuf, salt_hex: Option<&str>) -> std::process::Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_frappuccino-cli"));
    cmd.arg("verify-provenance").arg("--ots").arg(ots);
    if let Some(s) = salt_hex {
        cmd.arg("--ots-salt").arg(s);
    }
    for c in chunks {
        cmd.arg("--chunk").arg(c);
    }
    cmd.output().unwrap()
}

#[test]
fn good_bundle_passes() {
    let b = build_bundle("good", &[b"chunk-zero", b"chunk-one", b"chunk-two"]);
    let salt = [0x11u8; 32];
    let commitment = ots_media_commitment(&salt, &b.root);
    let ots = b.dir.join("media.ots");
    write_ots(&ots, &commitment, Some(800_000));

    let out = run_verify(&b.chunks, &ots, Some(&hex::encode(salt)));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "expected exit 0\nstdout:\n{stdout}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(stdout.contains("RESULT: PASS"), "stdout:\n{stdout}");
    assert!(
        stdout.contains("Bitcoin block(s) 800000"),
        "stdout:\n{stdout}"
    );
    let _ = fs::remove_dir_all(&b.dir);
}

#[test]
fn bare_root_no_salt_passes() {
    // A witness who didn't blind the commitment: the `.ots` commits the bare root.
    let b = build_bundle("bare", &[b"a", b"b"]);
    let ots = b.dir.join("media.ots");
    write_ots(&ots, &b.root, Some(810_000));

    let out = run_verify(&b.chunks, &ots, None);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "expected exit 0\nstdout:\n{stdout}");
    assert!(
        stdout.contains("Bitcoin block(s) 810000"),
        "stdout:\n{stdout}"
    );
    let _ = fs::remove_dir_all(&b.dir);
}

#[test]
fn tampered_chunk_fails() {
    let b = build_bundle("tamper", &[b"a", b"b"]);
    let salt = [0x22u8; 32];
    let commitment = ots_media_commitment(&salt, &b.root);
    let ots = b.dir.join("media.ots");
    write_ots(&ots, &commitment, Some(800_000));

    // Tamper a chunk on disk AFTER the .ots was committed → the recomputed root
    // no longer matches what the `.ots` commits.
    fs::write(&b.chunks[1], b"b-TAMPERED").unwrap();

    let out = run_verify(&b.chunks, &ots, Some(&hex::encode(salt)));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !out.status.success(),
        "expected non-zero exit\nstdout:\n{stdout}"
    );
    assert!(stdout.contains("RESULT: FAIL"), "stdout:\n{stdout}");
    let _ = fs::remove_dir_all(&b.dir);
}

#[test]
fn salt_mismatch_fails() {
    // A correct salted `.ots` verified with the WRONG salt: the recomputed leaf
    // differs, so it must be rejected.
    let b = build_bundle("saltbad", &[b"a"]);
    let salt = [0x33u8; 32];
    let commitment = ots_media_commitment(&salt, &b.root);
    let ots = b.dir.join("media.ots");
    write_ots(&ots, &commitment, Some(800_000));

    let wrong_salt = hex::encode([0xAAu8; 32]);
    let out = run_verify(&b.chunks, &ots, Some(&wrong_salt));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !out.status.success(),
        "expected non-zero exit\nstdout:\n{stdout}"
    );
    assert!(stdout.contains("RESULT: FAIL"), "stdout:\n{stdout}");
    let _ = fs::remove_dir_all(&b.dir);
}
