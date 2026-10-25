//! Property tests of the queue-envelope codec (`FQE1`), through the public
//! API only.
//!
//! Three things are checked over generated inputs: the trailer parser never
//! panics, whatever the bytes and wherever they sit relative to the AEAD; a
//! trailer built by hand from the documented layout opens, so the code and the
//! layout in `envelope.rs` describe the same bytes; and an envelope produced
//! by the codec opens to exactly its fields, while any change to its trailer,
//! footer or payload length is refused.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use frappuccino_crypto_stream::core::report::{report_id_from_pk, ReportKeyring};
use frappuccino_crypto_stream::envelope::{MAX_TAIL_BYTES, TRAILER_FIXED_BYTES};
use frappuccino_crypto_stream::{
    is_relay_object_name, EnvelopeError, EnvelopeFields, EnvelopeKind, EnvelopeTrailer, QueueKey,
};
use proptest::prelude::*;
use sha2::{Digest, Sha256};
use std::sync::OnceLock;

const KEY: [u8; 32] = [0x6bu8; 32];
const MN_FIXED: &str = "abaisser abandon abdiquer abeille abolir aborder aboutir aboyer \
     abrasif abreuver abriter abroger";

fn key() -> QueueKey {
    QueueKey::from_bytes(&KEY).unwrap()
}

fn keyring() -> &'static ReportKeyring {
    static RING: OnceLock<ReportKeyring> = OnceLock::new();
    RING.get_or_init(|| ReportKeyring::from_mnemonic(MN_FIXED, "").unwrap())
}

/// `EnvelopeTrailer::open` on the last bytes of `file`, as a sender reads it.
fn open(file: &[u8]) -> Result<EnvelopeTrailer, EnvelopeError> {
    let start = file.len().saturating_sub(MAX_TAIL_BYTES);
    EnvelopeTrailer::open(file.len() as u64, &file[start..], &key())
}

/// `payload_len` filler bytes, then `plain` sealed exactly as the documented
/// layout says: `nonce ‖ AEAD(plain, aad = "FQE1" ‖ u64_be(payload_len)) ‖
/// u32_be(sealed_len) ‖ "FQE1"`.
fn seal_by_hand(plain: &[u8], payload_len: u64, payload_byte: u8) -> Vec<u8> {
    let nonce = [0x11u8; 24];
    let mut aad = b"FQE1".to_vec();
    aad.extend_from_slice(&payload_len.to_be_bytes());
    let ct = XChaCha20Poly1305::new((&KEY).into())
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plain,
                aad: &aad,
            },
        )
        .unwrap();
    let mut file = vec![payload_byte; usize::try_from(payload_len).unwrap()];
    file.extend_from_slice(&nonce);
    file.extend_from_slice(&ct);
    file.extend_from_slice(&u32::try_from(24 + ct.len()).unwrap().to_be_bytes());
    file.extend_from_slice(b"FQE1");
    file
}

/// The documented plaintext layout, written out field by field.
#[allow(clippy::too_many_arguments)]
fn plain_by_hand(
    kind: u8,
    report_pk: &[u8; 32],
    signature: &[u8; 64],
    create_sig: &[u8; 64],
    seq_limit: u32,
    filename: &[u8],
    payload_len: u64,
    payload_sha256: &[u8; 32],
) -> Vec<u8> {
    let mut plain = vec![kind];
    plain.extend_from_slice(&report_id_from_pk(report_pk));
    plain.extend_from_slice(report_pk);
    plain.extend_from_slice(signature);
    plain.extend_from_slice(create_sig);
    plain.extend_from_slice(&seq_limit.to_be_bytes());
    plain.push(u8::try_from(filename.len()).unwrap());
    plain.extend_from_slice(filename);
    plain.extend_from_slice(&payload_len.to_be_bytes());
    plain.extend_from_slice(payload_sha256);
    assert_eq!(plain.len(), TRAILER_FIXED_BYTES + filename.len());
    plain
}

/// What a decoded trailer must say, read independently from `plain`.
fn assert_faithful(trailer: &EnvelopeTrailer, plain: &[u8], payload_len: u64) {
    let name_len = usize::from(plain[181]);
    assert_eq!(trailer.kind().to_byte(), plain[0]);
    assert_eq!(&trailer.report_id()[..], &plain[1..17]);
    assert_eq!(&trailer.report_pk()[..], &plain[17..49]);
    assert_eq!(&trailer.signature()[..], &plain[49..113]);
    match trailer.create_sig() {
        Some(sig) => assert_eq!(&sig[..], &plain[113..177]),
        None => assert!(plain[113..177].iter().all(|&b| b == 0)),
    }
    assert_eq!(trailer.seq_limit().to_be_bytes(), plain[177..181]);
    assert_eq!(trailer.filename().as_bytes(), &plain[182..182 + name_len]);
    assert_eq!(trailer.payload_len(), payload_len);
    assert_eq!(&trailer.payload_sha256()[..], &plain[plain.len() - 32..]);
    assert_eq!(trailer.report_id(), &report_id_from_pk(trailer.report_pk()));
    if trailer.kind() == EnvelopeKind::Closure {
        assert!(trailer.filename().is_empty());
    } else {
        assert!(is_relay_object_name(trailer.filename()));
        assert_eq!(trailer.seq_limit(), 0);
        assert!(payload_len > 0);
    }
}

fn object_kind() -> impl Strategy<Value = EnvelopeKind> {
    prop_oneof![
        Just(EnvelopeKind::Chunk),
        Just(EnvelopeKind::DirectoryEntry),
        Just(EnvelopeKind::TimestampProof),
    ]
}

fn relay_name() -> impl Strategy<Value = String> {
    "[A-Za-z0-9_-]{1,40}(\\.[A-Za-z0-9_-]{1,10})?".prop_filter("reserved", |n| n != "manifest")
}

/// A validly signed object envelope, built with the codec.
fn sealed_object(
    kind: EnvelopeKind,
    index: u32,
    filename: &str,
    payload: &[u8],
    with_create: bool,
) -> (EnvelopeFields, Vec<u8>) {
    let ring = keyring();
    let digest: [u8; 32] = Sha256::digest(payload).into();
    let fields = EnvelopeFields::object(
        kind,
        ring.report_pk(index).unwrap(),
        filename,
        ring.sign_write(index, filename.as_bytes(), &digest)
            .unwrap(),
        with_create.then(|| ring.sign_create(index).unwrap()),
    )
    .unwrap();
    let trailer = EnvelopeTrailer::for_payload(fields.clone(), payload).unwrap();
    let mut file = payload.to_vec();
    file.extend_from_slice(&trailer.seal(&key()).unwrap());
    (fields, file)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Arbitrary bytes, with the file possibly longer than the bytes seen.
    #[test]
    fn open_never_panics_on_arbitrary_tails(
        bytes in proptest::collection::vec(any::<u8>(), 0..700),
        hidden_prefix in 0u64..10_000,
    ) {
        let start = bytes.len().saturating_sub(MAX_TAIL_BYTES);
        let file_len = bytes.len() as u64 + hidden_prefix;
        let result = EnvelopeTrailer::open(file_len, &bytes[start..], &key());
        prop_assert!(result.is_err());
    }

    /// A footer that names a plausible trailer in front of random bytes.
    #[test]
    fn a_plausible_footer_over_random_bytes_is_refused(
        body in proptest::collection::vec(any::<u8>(), 0..600),
        sealed_len in 0u32..700,
    ) {
        let mut file = body;
        file.extend_from_slice(&sealed_len.to_be_bytes());
        file.extend_from_slice(b"FQE1");
        let error = open(&file).unwrap_err();
        prop_assert!(error.is_corrupt(), "{error:?}");
    }

    /// Arbitrary plaintext authenticated under the queue key reaches the
    /// decoder: it must not panic, and whatever it accepts must be exactly
    /// what the bytes say.
    #[test]
    fn the_decoder_never_panics_past_the_aead(
        plain in proptest::collection::vec(any::<u8>(), 0..420),
        payload_len in 0u64..200,
    ) {
        let file = seal_by_hand(&plain, payload_len, 0xEE);
        if let Ok(trailer) = open(&file) {
            assert_faithful(&trailer, &plain, payload_len);
        }
    }

    /// A trailer written by hand from the documented layout opens, and every
    /// one-byte change to it either is refused or still decodes faithfully.
    #[test]
    fn the_documented_layout_is_the_codec_layout(
        filename in relay_name(),
        payload_len in 1u64..64,
        position in 0usize..400,
        flip in 1u8..=255,
    ) {
        let pk = keyring().report_pk(7).unwrap();
        let plain = plain_by_hand(
            EnvelopeKind::TimestampProof.to_byte(),
            &pk,
            &[0x5au8; 64],
            &[0u8; 64],
            0,
            filename.as_bytes(),
            payload_len,
            &[0x33u8; 32],
        );
        let trailer = open(&seal_by_hand(&plain, payload_len, 0)).unwrap();
        prop_assert_eq!(trailer.filename(), filename.as_str());
        prop_assert!(trailer.create_sig().is_none());
        assert_faithful(&trailer, &plain, payload_len);

        let mut mutated = plain.clone();
        let at = position % mutated.len();
        mutated[at] ^= flip;
        if let Ok(trailer) = open(&seal_by_hand(&mutated, payload_len, 0)) {
            assert_faithful(&trailer, &mutated, payload_len);
            // The report_id/report_pk binding survives no change to either.
            prop_assert!(!(1..49).contains(&at));
        }
    }

    /// Envelopes produced by the codec open to their own fields; a flipped
    /// bit anywhere in the trailer or footer, or a payload one byte longer or
    /// shorter, is refused.
    #[test]
    fn codec_envelopes_roundtrip_and_resist_change(
        kind in object_kind(),
        index in 0u32..5,
        filename in relay_name(),
        payload in proptest::collection::vec(any::<u8>(), 1..2000),
        with_create in any::<bool>(),
        offset in 0usize..400,
        bit in 0u8..8,
    ) {
        let (fields, file) = sealed_object(kind, index, &filename, &payload, with_create);
        let trailer = open(&file).unwrap();
        prop_assert_eq!(trailer.kind(), kind);
        prop_assert_eq!(trailer.filename(), filename.as_str());
        prop_assert_eq!(trailer.payload_len(), payload.len() as u64);
        prop_assert_eq!(trailer.create_sig().is_some(), with_create);
        let rebuilt = EnvelopeTrailer::for_payload(fields, &payload).unwrap();
        prop_assert_eq!(rebuilt.report_id(), trailer.report_id());
        prop_assert_eq!(rebuilt.report_pk(), trailer.report_pk());

        let trailer_len = file.len() - payload.len();
        let mut flipped = file.clone();
        let at = payload.len() + offset % trailer_len;
        flipped[at] ^= 1 << bit;
        prop_assert!(open(&flipped).is_err());

        let mut longer = vec![0u8];
        longer.extend_from_slice(&file);
        prop_assert_eq!(open(&longer).unwrap_err(), EnvelopeError::Undecryptable);
        prop_assert_eq!(open(&file[1..]).unwrap_err(), EnvelopeError::Undecryptable);
        prop_assert!(open(&file[..file.len() - 1]).is_err());
    }
}
