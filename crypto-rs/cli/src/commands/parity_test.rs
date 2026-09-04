//! `frappuccino-cli parity-test` — replay every parity vector under a
//! directory.
//!
//! Mirrors `crypto-rs/core/tests/parity_*.rs` and
//! `crypto-rs/stream/tests/parity_strm.rs` but in a runner that works without
//! `cargo test` — useful when shipping the CLI as a standalone binary for
//! auditors or CI pipelines where the workspace source tree isn't available.
//!
//! Expected directory layout (the one produced by the Android dumper):
//!
//! ```text
//! <root>/
//!   bip39/seed.json
//!   identity/derive.json
//!   strm_blobs/vectors.json
//!   strm_blobs/*.strm
//!   strm_blobs/chunked_3mb.plaintext.bin     (optional, skipped if absent)
//! ```
//!
//! Exits 0 on full pass, 1 on the first mismatch.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use clap::Args as ClapArgs;
use frappuccino_crypto_core::bip39::{self, Language};
use frappuccino_crypto_core::identity::{ArchiveIdentity, EnrollmentKit};
use frappuccino_crypto_stream::decrypt::decrypt;
use serde::Deserialize;

#[derive(Debug, ClapArgs)]
pub struct Args {
    /// Path to the parity-vectors root directory.
    pub vectors_dir: PathBuf,

    /// Only run a subset of suites. Defaults to all.
    #[arg(long, value_delimiter = ',')]
    pub only: Vec<Suite>,
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum Suite {
    Bip39,
    Identity,
    Strm,
}

pub fn run(args: &Args) -> Result<()> {
    let root = &args.vectors_dir;
    if !root.is_dir() {
        bail!("vectors directory not found: {}", root.display());
    }

    let suites = if args.only.is_empty() {
        vec![Suite::Bip39, Suite::Identity, Suite::Strm]
    } else {
        args.only.clone()
    };

    let mut total = 0usize;
    let mut passed = 0usize;

    for s in suites {
        match s {
            Suite::Bip39 => {
                let n = run_bip39_seed(&root.join("bip39/seed.json"))?;
                total += n;
                passed += n;
                eprintln!("bip39/seed.json: {n}/{n} OK");
            }
            Suite::Identity => {
                let n = run_identity_derive(&root.join("identity/derive.json"))?;
                total += n;
                passed += n;
                eprintln!("identity/derive.json: {n}/{n} OK");
            }
            Suite::Strm => {
                let (n, p) = run_strm(&root.join("strm_blobs"))?;
                total += n;
                passed += p;
                eprintln!("strm_blobs: {p}/{n} OK");
            }
        }
    }

    println!("TOTAL: {passed}/{total}");
    if passed != total {
        bail!("{} parity case(s) failed", total - passed);
    }
    Ok(())
}

// ----------------------------------------------------------------------------
// bip39/seed.json
// ----------------------------------------------------------------------------

#[derive(Deserialize)]
struct Bip39File {
    cases: Vec<Bip39Case>,
}

#[derive(Deserialize)]
struct Bip39Case {
    mnemonic: String,
    passphrase: String,
    seed_hex: String,
}

fn run_bip39_seed(path: &Path) -> Result<usize> {
    let raw = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let file: Bip39File =
        serde_json::from_str(&raw).with_context(|| format!("parse {}", path.display()))?;
    for (i, c) in file.cases.iter().enumerate() {
        let seed = bip39::mnemonic_to_seed(&c.mnemonic, &c.passphrase, Language::French)
            .with_context(|| format!("seed case {i}"))?;
        let got = hex::encode(seed.as_bytes());
        if got != c.seed_hex {
            bail!(
                "bip39 seed case {i}: mismatch\n  mnemonic   = {}\n  passphrase = {:?}\n  expected   = {}\n  got        = {}",
                c.mnemonic, c.passphrase, c.seed_hex, got
            );
        }
    }
    Ok(file.cases.len())
}

// ----------------------------------------------------------------------------
// identity/derive.json
// ----------------------------------------------------------------------------

#[derive(Deserialize)]
struct IdentityFile {
    cases: Vec<IdentityCase>,
}

#[derive(Deserialize)]
struct IdentityCase {
    mnemonic: String,
    passphrase: String,
    ed25519_pk_hex: String,
    x25519_pk_hex: String,
    fingerprint: String,
}

fn run_identity_derive(path: &Path) -> Result<usize> {
    let raw = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let file: IdentityFile =
        serde_json::from_str(&raw).with_context(|| format!("parse {}", path.display()))?;
    for (i, c) in file.cases.iter().enumerate() {
        let kit = EnrollmentKit::from_mnemonic(&c.mnemonic, &c.passphrase)
            .with_context(|| format!("identity case {i}: enroll from mnemonic"))?;
        let id = kit.identity();
        let got_ed = hex::encode(id.ed25519_pk());
        let got_x = hex::encode(id.x25519_pk());
        let got_fp = id.readable_fingerprint();

        if got_ed != c.ed25519_pk_hex {
            bail!(
                "identity case {i}: ed25519_pk mismatch\n  expected {}\n  got      {}",
                c.ed25519_pk_hex,
                got_ed
            );
        }
        if got_x != c.x25519_pk_hex {
            bail!(
                "identity case {i}: x25519_pk mismatch\n  expected {}\n  got      {}",
                c.x25519_pk_hex,
                got_x
            );
        }
        if got_fp != c.fingerprint {
            bail!(
                "identity case {i}: fingerprint mismatch\n  expected {}\n  got      {}",
                c.fingerprint,
                got_fp
            );
        }
    }
    Ok(file.cases.len())
}

// ----------------------------------------------------------------------------
// strm_blobs/vectors.json
// ----------------------------------------------------------------------------

#[derive(Deserialize)]
struct StrmFile {
    mnemonic: String,
    passphrase: String,
    cases: Vec<StrmCase>,
}

#[derive(Deserialize)]
struct StrmCase {
    filename: String,
    plaintext_size: usize,
    plaintext_sha256: String,
    #[serde(default)]
    plaintext_hex: Option<String>,
    #[serde(default)]
    plaintext_filename: Option<String>,
}

fn run_strm(dir: &Path) -> Result<(usize, usize)> {
    let vec_path = dir.join("vectors.json");
    let raw =
        fs::read_to_string(&vec_path).with_context(|| format!("read {}", vec_path.display()))?;
    let file: StrmFile =
        serde_json::from_str(&raw).with_context(|| format!("parse {}", vec_path.display()))?;

    let archive = ArchiveIdentity::from_mnemonic(&file.mnemonic, &file.passphrase)
        .context("derive archive for strm vectors")?;

    let mut total = 0usize;
    let mut passed = 0usize;

    for (i, c) in file.cases.iter().enumerate() {
        total += 1;
        let blob_path = dir.join(&c.filename);
        if !blob_path.exists() {
            eprintln!("  skip: {} (missing fixture)", c.filename);
            total -= 1; // missing fixtures are skipped, not failed
            continue;
        }
        let blob =
            fs::read(&blob_path).with_context(|| format!("read blob {}", blob_path.display()))?;
        let expected = load_expected_plaintext(c, dir)?;
        if expected.len() != c.plaintext_size {
            bail!(
                "strm case {i} ({}): plaintext_size mismatch fixture-vs-expected",
                c.filename
            );
        }
        let (plaintext, _meta) = match decrypt(&blob, &archive) {
            Ok(r) => r,
            Err(e) => bail!("strm case {i} ({}): decrypt: {e:?}", c.filename),
        };
        if plaintext[..] != expected[..] {
            bail!(
                "strm case {i} ({}): plaintext mismatch (got {} bytes, expected {})",
                c.filename,
                plaintext.len(),
                expected.len()
            );
        }
        // The sha256 fixture is redundant with the byte-exact equality above
        // — if the fixture's sha ever drifts we'll see it in the build that
        // regenerates vectors.json, not here. Not recomputing it keeps the
        // CLI's dep tree off `sha2`.
        let _ = &c.plaintext_sha256;
        passed += 1;
    }
    Ok((total, passed))
}

fn load_expected_plaintext(c: &StrmCase, dir: &Path) -> Result<Vec<u8>> {
    if let Some(hex_str) = &c.plaintext_hex {
        return hex::decode(hex_str).context("decode plaintext_hex");
    }
    if let Some(name) = &c.plaintext_filename {
        let p = dir.join(name);
        return fs::read(&p).with_context(|| format!("read plaintext file {}", p.display()));
    }
    Ok(Vec::new())
}
