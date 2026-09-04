//! E2E test for the `frappuccino-migrate-v1-ratchet` binary.
//!
//! Closes RT-03 (Phase 4.1.4) — proves that the only audited path that still
//! reads V1 ratchet blobs (the migration tool) actually round-trips through
//! a sealed V1 file → sealed V2 file with the right PIN, and refuses to
//! overwrite an existing output file.

use frappuccino_crypto_core::pin_store;
use frappuccino_crypto_core::ratchet::{
    EphemeralRatchet, SERIALIZED_PAYLOAD_SIZE, VERSION_V1, VERSION_V2,
};
use std::path::PathBuf;
use std::process::Command;

/// Build a PIN-sealed V1 ratchet blob from a fresh ratchet by stripping the
/// MAC + flipping the version byte to V1. Mirrors what a Kotlin pre-S5
/// device wrote to disk before the migration to V2.
fn fake_v1_sealed(pin: &str) -> Vec<u8> {
    let mut chain0 = [42u8; 32];
    let mut r = EphemeralRatchet::new();
    r.initialize(&mut chain0).unwrap();
    let v2 = r.serialize().unwrap();
    let mut v1_plain = v2[..SERIALIZED_PAYLOAD_SIZE].to_vec();
    v1_plain[0] = VERSION_V1;
    // Phase 6.1.4-A : pin_store::seal accepte maintenant &[u8]. Le pin
    // ici est un &str littéral du test, on le convertit en bytes.
    pin_store::seal(pin.as_bytes(), &v1_plain).unwrap()
}

/// Per-test scratch dir under the system temp. Suffixed with PID + a
/// monotonic counter to avoid collisions when tests run in parallel.
fn scratch(label: &str) -> PathBuf {
    use std::sync::atomic::{AtomicU32, Ordering};
    static SEQ: AtomicU32 = AtomicU32::new(0);
    let id = SEQ.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!(
        "frappuccino-migrate-test-{}-{}-{}",
        std::process::id(),
        label,
        id
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch mkdir");
    dir
}

#[test]
fn migrate_v1_ratchet_roundtrip() {
    let pin = "123456";
    let dir = scratch("roundtrip");
    let in_path = dir.join("ratchet.v1.sealed");
    let out_path = dir.join("ratchet.v2.sealed");

    std::fs::write(&in_path, fake_v1_sealed(pin)).unwrap();

    let bin = env!("CARGO_BIN_EXE_frappuccino-migrate-v1-ratchet");
    let status = Command::new(bin)
        .args([
            "--in",
            in_path.to_str().unwrap(),
            "--out",
            out_path.to_str().unwrap(),
            "--pin",
            pin,
        ])
        .status()
        .expect("spawn migrate-v1-ratchet");
    assert!(status.success(), "CLI exit code: {status:?}");

    // Output must be a valid PIN-sealed V2 blob.
    let v2_sealed = std::fs::read(&out_path).unwrap();
    let v2_plain = pin_store::open(pin.as_bytes(), &v2_sealed).expect("V2 unseal");
    assert_eq!(
        v2_plain[0], VERSION_V2,
        "migrated payload must have version byte 0x02"
    );
    // Round-trip via deserialize must succeed (MAC verified).
    let _r = EphemeralRatchet::deserialize(&v2_plain).expect("V2 deserialize");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn migrate_v1_ratchet_refuses_overwrite() {
    let pin = "123456";
    let dir = scratch("overwrite");
    let in_path = dir.join("ratchet.v1.sealed");
    let out_path = dir.join("ratchet.v2.sealed");

    std::fs::write(&in_path, fake_v1_sealed(pin)).unwrap();
    std::fs::write(&out_path, b"existing-content-must-not-be-touched").unwrap();

    let bin = env!("CARGO_BIN_EXE_frappuccino-migrate-v1-ratchet");
    let status = Command::new(bin)
        .args([
            "--in",
            in_path.to_str().unwrap(),
            "--out",
            out_path.to_str().unwrap(),
            "--pin",
            pin,
        ])
        .status()
        .expect("spawn migrate-v1-ratchet");
    assert!(
        !status.success(),
        "must refuse to overwrite an existing output file"
    );
    // Output left untouched.
    let after = std::fs::read(&out_path).unwrap();
    assert_eq!(after, b"existing-content-must-not-be-touched");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn migrate_v1_ratchet_rejects_wrong_pin() {
    let dir = scratch("wrongpin");
    let in_path = dir.join("ratchet.v1.sealed");
    let out_path = dir.join("ratchet.v2.sealed");

    std::fs::write(&in_path, fake_v1_sealed("123456")).unwrap();

    let bin = env!("CARGO_BIN_EXE_frappuccino-migrate-v1-ratchet");
    let status = Command::new(bin)
        .args([
            "--in",
            in_path.to_str().unwrap(),
            "--out",
            out_path.to_str().unwrap(),
            "--pin",
            "999999",
        ])
        .status()
        .expect("spawn migrate-v1-ratchet");
    assert!(!status.success(), "wrong PIN must fail");
    assert!(
        !out_path.exists(),
        "no output file must be written on failure"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
