//! Regenerate the seed corpus for each fuzz target in `crypto-rs/fuzz/`.
//!
//! Run from the workspace root:
//!
//! ```sh
//! cargo run -p frappuccino-cli --release --bin generate_fuzz_seeds
//! ```
//!
//! Produces exactly one valid blob per target under
//! `crypto-rs/fuzz/corpus/<target>/0000_seed`. Overwrites existing seeds.
//! The files are committed so fuzz runs start from a known-good input
//! instead of pure random bytes — libfuzzer reaches meaningful coverage
//! orders of magnitude faster that way.
//!
//! This is a plain binary: it does not link `libfuzzer-sys`, so it builds
//! under stable Rust on Windows, macOS, and Linux. Lives here rather than
//! in `crypto-rs/fuzz/` precisely to keep the fuzz crate single-purpose
//! (libfuzzer targets only).

use std::fs;
use std::path::Path;

use frappuccino_crypto_core::identity::{ArchiveIdentity, EnrollmentKit};
use frappuccino_crypto_core::pin_store;
use frappuccino_crypto_core::ratchet::EphemeralRatchet;
use frappuccino_crypto_stream::encrypt::encrypt_single;

const FIXTURE_MN: &str = "abaisser abandon abdiquer abeille abolir aborder aboutir aboyer abrasif abreuver abriter abroger";

fn main() {
    // CARGO_MANIFEST_DIR here is `crypto-rs/cli` — step up one level to
    // reach the fuzz crate.
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let corpus = repo_root.join("fuzz").join("corpus");

    // ---- decrypt_blob: a valid v2 SINGLE blob ------------------------------
    let archive = ArchiveIdentity::from_mnemonic(FIXTURE_MN, "").unwrap();
    let author = archive.identity().clone();
    let blob = encrypt_single(b"fuzz seed: the quick brown fox.", &author).unwrap();
    write_seed(&corpus.join("fuzz_decrypt_blob/0000_seed"), &blob);

    // ---- parse_strm_header: same blob; parse_header only reads the prefix.
    write_seed(&corpus.join("fuzz_parse_strm_header/0000_seed"), &blob);

    // ---- ratchet_deserialize: a freshly initialized V2 ratchet blob -------
    let mut kit = EnrollmentKit::from_mnemonic(FIXTURE_MN, "").unwrap();
    let chain0 = kit.take_chain_zero().unwrap();
    let mut chain_bytes = [0u8; 32];
    chain0.with_bytes(|b| chain_bytes.copy_from_slice(b));
    let mut ratchet = EphemeralRatchet::new();
    ratchet.initialize(&mut chain_bytes).unwrap();
    let ratchet_blob = ratchet.serialize().unwrap();
    write_seed(
        &corpus.join("fuzz_ratchet_deserialize/0000_seed"),
        &ratchet_blob,
    );

    // ---- pin_store_open: a real sealed blob under a throwaway pin ---------
    let sealed = pin_store::seal(b"284193", b"fuzz seed plaintext").unwrap();
    write_seed(&corpus.join("fuzz_pin_store_open/0000_seed"), &sealed);

    println!("seeds regenerated under {}", corpus.display());
}

fn write_seed(path: &Path, data: &[u8]) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(path, data).unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
    println!("  {} ({} bytes)", path.display(), data.len());
}
