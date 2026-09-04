//! Error-path coverage for `pin_store::open_extended` and `seal_with_key`.
//!
//! The happy-path tests in `pin_store.rs` already cover `open` and `seal`
//! fully; the fast-reseal API (`open_extended` + `seal_with_key`) had
//! identical guard clauses that weren't exercised.

use frappuccino_crypto_core::pin_store;

#[test]
fn open_extended_rejects_empty_pin() {
    let err = pin_store::open_extended(b"", &[0u8; 100]).unwrap_err();
    assert!(format!("{err:?}").contains("EmptyInput"));
}

#[test]
fn open_extended_rejects_short_blob() {
    let err = pin_store::open_extended(b"123456", &[0u8; 10]).unwrap_err();
    assert!(format!("{err:?}").contains("blob too short"), "got {err:?}");
}

#[test]
fn open_extended_rejects_wrong_version_byte() {
    // Valid shape (header + tag-sized ciphertext), wrong version byte.
    let mut blob = vec![0u8; 1 + 16 + 24 + 16]; // version + salt + nonce + tag
    blob[0] = 0xFE; // not VERSION = 0x01
    let err = pin_store::open_extended(b"123456", &blob).unwrap_err();
    assert!(
        format!("{err:?}").contains("unsupported version byte"),
        "got {err:?}"
    );
}

#[test]
fn open_extended_rejects_wrong_pin() {
    // Seal with one pin, try to open with another.
    let sealed = pin_store::seal(b"111111", b"payload").unwrap();
    let err = pin_store::open_extended(b"999999", &sealed).unwrap_err();
    assert!(format!("{err:?}").contains("WrongPin"));
}

#[test]
fn open_extended_roundtrip_then_seal_with_key() {
    // Happy path so the `Ok` branch (lines around 271) is covered: seal,
    // open_extended, re-seal using the derived key (no new Argon2id).
    let sealed = pin_store::seal(b"424242", b"state").unwrap();
    let (plaintext, derived_key, salt) = pin_store::open_extended(b"424242", &sealed).unwrap();
    assert_eq!(&plaintext[..], b"state");

    // Re-seal with the same key/salt — no PIN re-derivation.
    let resealed = pin_store::seal_with_key(&derived_key, &salt, b"new state").unwrap();
    // The new blob opens with the same PIN because the derived key/salt match.
    let plaintext2 = pin_store::open(b"424242", &resealed).unwrap();
    assert_eq!(&plaintext2[..], b"new state");
}
