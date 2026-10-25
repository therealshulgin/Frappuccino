//! Cross-language Known-Answer Test for the chained report scheme and the
//! 0x09 closure, the companion of the 0x07 / 0x08 KAT in `core/src/report.rs`.
//!
//! Rust PRODUCES these bytes from the fixed mnemonic and pins them here; the
//! relay's Python KAT, `server/tests/test_report_close_kat.py`, must VERIFY the
//! same bytes against messages it rebuilds on its own side, and never re-sign
//! them. A change to a chain
//! context, to the 0x09 domain tag, to the close message layout or to the
//! manifest format then breaks one side's test instead of every closure in
//! production.
//!
//! Everything goes through the public API (`ReportDeviceState`, the writer,
//! the verifiers), so the pinned values are the ones the device emits.
//!
//! To regenerate after a DELIBERATE change:
//! `cargo test -p frappuccino-crypto-core --test report_chain_kat -- --nocapture`,
//! then copy the printed values here and into that Python file.

use frappuccino_crypto_core::report::{
    report_id_from_pk, verify_close, verify_create, verify_write, Manifest, ReportDeviceState,
    ReportKeyring, ReportRescue, ReportWriter, STATE_BYTES,
};
use sha2::{Digest, Sha256};

/// The fixed French phrase shared by every KAT of this crate.
const MN_FIXED: &str =
    "abaisser abandon abdiquer abeille abolir aborder aboutir aboyer abrasif abreuver abriter abroger";

/// The stored bytes of object seq 0 in this KAT: bytes `00 01 02 … 1f`
/// (Python: `bytes(range(32))`). Unlike the 0x07/0x08 KAT, which feeds those
/// bytes in directly as the hash, here they are the BODY, so the relay can
/// hash them the way it hashes a PUT.
fn blob_seq0() -> [u8; 32] {
    let mut out = [0u8; 32];
    for (value, byte) in (0u8..).zip(out.iter_mut()) {
        *byte = value;
    }
    out
}

/// `sha256(blob_seq0())`, the hash signed by `write_sig_0` and listed for seq 0.
fn blob_sha256_seq0() -> [u8; 32] {
    Sha256::digest(blob_seq0()).into()
}

/// The three-entry manifest: seq 0 → `sha256(bytes(range(32)))`, seq 1 →
/// `0x11 × 32`, seq 3 → `0x33 × 32` (seq 2 is a gap, as when a chunk is lost at
/// capture). `seq_limit` is therefore 4.
fn kat_entries() -> [(u32, [u8; 32]); 3] {
    [(0, blob_sha256_seq0()), (1, [0x11; 32]), (3, [0x33; 32])]
}

fn to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn open_writer(state: &mut ReportDeviceState) -> ReportWriter {
    state
        .open_report()
        .expect("open report 0")
        .release_after_persist(|_| Ok::<(), ()>(()))
        .expect("persist cannot fail here")
}

// The serialized states are `0x02 ‖ u32_be(i) ‖ C_i ‖ directory seed`: secret
// bytes, pinned here only because they derive from the public test phrase.
const EXP_STATE_0: &str = "0200000000\
     f46046c8222fa3be2c949f63239b2ff7954cc94d89d532a1a988d183a88f7359\
     ae9ad82a9109f96c99a7e15e84394f923ec907a78b4782636cbc3add2ba49f0b";
const EXP_STATE_1: &str = "0200000001\
     5acf74e27c91faa33cd3e8a2567e0f408286638e10084e688eeb9aefa70cdc24\
     ae9ad82a9109f96c99a7e15e84394f923ec907a78b4782636cbc3add2ba49f0b";
const EXP_DIRECTORY_PK: &str = "1f5797f307b7343e06e86a335131f1f62024fe81ea6c57f9639257862a315303";
const EXP_DIRECTORY_ID: &str = "37a3f942934dcbbc39104db7b29f48a3";
const EXP_CHAIN_PK_0: &str = "74650ad013cd6ebdacfd09b27877f468f11974fc0d0c6f6065b673f57655cca4";
const EXP_CHAIN_ID_0: &str = "a918268f24dd26e637aad05e9fd53da3";
const EXP_DIR_ENTRY_0: &str = "a6c2f8e53532333e878cce6644f0a419";
const EXP_OTS_NAME_0: &str = "2c18f6ebeb1c95f30dee935198f5ded9";
const EXP_CREATE_SIG_0: &str = "ed3895f37bfb4d87148c265ce6fb54c7d1f3b129cfcefe853ef73c2f8288d10c\
     becb70ff47e1f8b8e7ee51c33d1bf24f275e7a8f4a719f69168e9e1d8b465a02";
const EXP_BLOB_SHA256_0: &str = "630dcd2966c4336691125448bbb25b4ff412a49c732db2c8abc1b8581bd710dd";
const EXP_WRITE_SIG_0: &str = "78cf356eb3d846a2dd2ca9d562ab6098e9ea84c9a6018b14c551a150f9d3274a\
     e7c36c6f345b803a9ab54b54ea29f9811b6e1bea261a8cc09575fd65c2377c0a";
const EXP_MANIFEST: &str = "46514d3100000003\
     00000000630dcd2966c4336691125448bbb25b4ff412a49c732db2c8abc1b8581bd710dd\
     000000011111111111111111111111111111111111111111111111111111111111111111\
     000000033333333333333333333333333333333333333333333333333333333333333333";
const EXP_MANIFEST_SHA256: &str =
    "646333e15d611c60daf7c15cc2b08ea236ec78b53488b217609113efe698676a";
const EXP_SEQ_LIMIT: u32 = 4;
const EXP_CLOSE_SIG: &str = "e023ed75070c336d0c8bc09a42d948b2b21492315bbcc56314dc7f6a2f09311d\
     9df54f2f49d02b89e2222da8944928b565e0303aa6278fab38113d0a408a700a";
const EXP_LEGACY_CLOSE_SIG_0: &str =
    "c9c7c76ea639150ec8c300b10af15edce3b03c861979ae1f69fb6864d8c02e51\
     7d5008fef4ad7b4afd58cfa35b445c6acdd21d840bab86614f678a944512990e";

/// Every value of the KAT, produced through the public API.
struct KatRun {
    state_0: Vec<u8>,
    state_1: Vec<u8>,
    directory_pk: [u8; 32],
    directory_id: [u8; 16],
    pk: [u8; 32],
    id: [u8; 16],
    dir_entry: String,
    ots_name: String,
    create_sig: [u8; 64],
    write_sig_0: [u8; 64],
    manifest: Vec<u8>,
    manifest_sha256: [u8; 32],
    seq_limit: u32,
    close_sig: [u8; 64],
    legacy_pk_0: [u8; 32],
    legacy_close_sig_0: [u8; 64],
}

/// Open report 0 of a fresh enrollment, record objects 0, 1 and 3 (in that
/// order), close it, and sign legacy report 0's closure. The plaintext hashes
/// are arbitrary: they never reach the relay.
fn run_kat() -> KatRun {
    let mut state = ReportDeviceState::from_mnemonic(MN_FIXED, "").unwrap();
    let state_0 = state.to_bytes().to_vec();
    let mut writer = open_writer(&mut state);
    let state_1 = state.to_bytes().to_vec();

    let mut write_sig_0 = [0u8; 64];
    for (seq, blob_sha256) in kat_entries() {
        let plain = [0xA0 | seq.to_le_bytes()[0]; 32];
        let prepared = if seq == 0 {
            writer.prepare_metadata(&plain, &blob_sha256).unwrap()
        } else {
            writer.prepare_chunk(seq, &plain, &blob_sha256).unwrap()
        };
        if seq == 0 {
            assert_eq!(prepared.filename(), "000000.strm");
            write_sig_0 = *prepared.write_sig();
        }
        writer.commit(prepared).unwrap();
    }
    let close = writer.prepare_close().unwrap();
    let legacy = ReportKeyring::from_mnemonic(MN_FIXED, "").unwrap();

    KatRun {
        state_0,
        state_1,
        directory_pk: state.directory_pk(),
        directory_id: state.directory_id(),
        pk: *writer.report_pk(),
        id: *writer.report_id(),
        dir_entry: writer.directory_entry_name().to_owned(),
        ots_name: writer.ots_name().to_owned(),
        create_sig: *writer.create_sig(),
        write_sig_0,
        manifest: close.manifest().to_vec(),
        manifest_sha256: *close.manifest_sha256(),
        seq_limit: close.seq_limit(),
        close_sig: *close.close_sig(),
        legacy_pk_0: legacy.report_pk(0).unwrap(),
        legacy_close_sig_0: legacy.sign_legacy_close(0).unwrap(),
    }
}

#[test]
fn chained_report_and_closure_kat() {
    let kat = run_kat();
    assert_eq!(kat.state_0.len(), STATE_BYTES);

    println!("KAT mnemonic            = {MN_FIXED}");
    println!("KAT state_0             = {}", to_hex(&kat.state_0));
    println!("KAT state_1             = {}", to_hex(&kat.state_1));
    println!("KAT directory_pk        = {}", to_hex(&kat.directory_pk));
    println!("KAT directory_id        = {}", to_hex(&kat.directory_id));
    println!("KAT chain_pk_0          = {}", to_hex(&kat.pk));
    println!("KAT chain_id_0          = {}", to_hex(&kat.id));
    println!("KAT dir_entry_0         = {}", kat.dir_entry);
    println!("KAT ots_name_0          = {}", kat.ots_name);
    println!("KAT create_sig_0        = {}", to_hex(&kat.create_sig));
    println!("KAT blob_seq0           = {}", to_hex(&blob_seq0()));
    println!("KAT blob_sha256_seq0    = {}", to_hex(&blob_sha256_seq0()));
    println!("KAT write_sig_0         = {}", to_hex(&kat.write_sig_0));
    println!("KAT manifest            = {}", to_hex(&kat.manifest));
    println!("KAT manifest_sha256     = {}", to_hex(&kat.manifest_sha256));
    println!("KAT seq_limit           = {}", kat.seq_limit);
    println!("KAT close_sig           = {}", to_hex(&kat.close_sig));
    println!("KAT legacy_pk_0         = {}", to_hex(&kat.legacy_pk_0));
    println!(
        "KAT legacy_close_sig_0  = {}",
        to_hex(&kat.legacy_close_sig_0)
    );

    assert_eq!(to_hex(&kat.state_0), EXP_STATE_0, "state_0 drift");
    assert_eq!(to_hex(&kat.state_1), EXP_STATE_1, "state_1 drift");
    assert_eq!(to_hex(&kat.directory_pk), EXP_DIRECTORY_PK);
    assert_eq!(to_hex(&kat.directory_id), EXP_DIRECTORY_ID);
    assert_eq!(to_hex(&kat.pk), EXP_CHAIN_PK_0, "chain pk_0 drift");
    assert_eq!(to_hex(&kat.id), EXP_CHAIN_ID_0, "chain report_id_0 drift");
    assert_eq!(kat.dir_entry, EXP_DIR_ENTRY_0);
    assert_eq!(kat.ots_name, EXP_OTS_NAME_0);
    assert_eq!(to_hex(&kat.create_sig), EXP_CREATE_SIG_0);
    assert_eq!(to_hex(&blob_sha256_seq0()), EXP_BLOB_SHA256_0);
    assert_eq!(to_hex(&kat.write_sig_0), EXP_WRITE_SIG_0);
    assert_eq!(to_hex(&kat.manifest), EXP_MANIFEST, "manifest drift");
    assert_eq!(to_hex(&kat.manifest_sha256), EXP_MANIFEST_SHA256);
    assert_eq!(kat.seq_limit, EXP_SEQ_LIMIT);
    assert_eq!(to_hex(&kat.close_sig), EXP_CLOSE_SIG, "close_sig drift");
    assert_eq!(to_hex(&kat.legacy_close_sig_0), EXP_LEGACY_CLOSE_SIG_0);
}

/// Live cross-checks: the pinned bytes verify through the public verifiers,
/// the manifest is the documented layout, and the rescue re-derives the same
/// report from the phrase alone.
#[test]
fn kat_values_verify_and_match_the_rescue() {
    let kat = run_kat();
    assert_eq!(kat.id, report_id_from_pk(&kat.pk));
    verify_create(&kat.pk, &kat.create_sig).unwrap();
    verify_write(
        &kat.pk,
        b"000000.strm",
        &blob_sha256_seq0(),
        &kat.write_sig_0,
    )
    .unwrap();
    let parsed = verify_close(&kat.pk, kat.seq_limit, &kat.manifest, &kat.close_sig).unwrap();
    assert_eq!(parsed.len(), 3);

    let mut expected_manifest = b"FQM1\x00\x00\x00\x03".to_vec();
    for (seq, hash) in kat_entries() {
        expected_manifest.extend_from_slice(&seq.to_be_bytes());
        expected_manifest.extend_from_slice(&hash);
    }
    assert_eq!(kat.manifest, expected_manifest);
    assert_eq!(
        kat.manifest_sha256[..],
        Sha256::digest(&expected_manifest)[..]
    );

    verify_close(
        &kat.legacy_pk_0,
        0,
        &Manifest::empty().to_bytes(),
        &kat.legacy_close_sig_0,
    )
    .unwrap();

    let mut rescue = ReportRescue::from_mnemonic(MN_FIXED, "").unwrap();
    let found = rescue.chain(0).unwrap();
    assert_eq!(*found.report_pk(), kat.pk);
    assert_eq!(found.directory_entry_name(), Some(EXP_DIR_ENTRY_0));
    assert_eq!(found.ots_name(), Some(EXP_OTS_NAME_0));
    assert_eq!(*rescue.directory().report_pk(), kat.directory_pk);
}
