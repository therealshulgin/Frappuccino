//! `frappuccino-cli verify-provenance` — offline verification of a disclosed
//! recording (ROADMAP §10.11, lean "hash + Bitcoin" model).
//!
//! A third party (journalist, court, fact-checker) runs this against the
//! artifacts a witness chooses to disclose:
//!   * `--chunk` (repeatable, REQUIRED) — the plaintext media chunk files, IN
//!     RECORDING ORDER. Their ordered SHA-256 hashes are folded into the media
//!     Merkle root (`chunk_merkle_root`) — the integrity commitment.
//!   * `--ots` (REQUIRED) — the `OpenTimestamps` proof. It must commit the media
//!     root (salted), and it carries the trustless Bitcoin anchor = the *when*.
//!   * `--ots-salt` (optional) — the 32-byte blinding salt (hex) from the
//!     bundle's `.otssalt`. The witness's `.ots` commits `SHA-256(salt ‖ root)`;
//!     supply it so the leaf can be recomputed. Omit for a bare-root `.ots`.
//!
//! What it proves: the disclosed media (those exact chunks, in that order)
//! **existed by** the Bitcoin block the `.ots` anchors — i.e. integrity +
//! anteriority (it was not fabricated *after* that time). Exit 0 iff every check
//! passed; exit 1 otherwise.
//!
//! What it does NOT prove — by design (the motto: a seizure exposes nothing):
//! **attribution**. There is no identity, signature, cert, or manifest here. If a
//! witness wants to claim authorship, they sign a disclosure statement with their
//! identity key **on demand**, when and to whom they choose — never baked into a
//! stored, seizable artifact.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use clap::Args as ClapArgs;

use frappuccino_crypto_core::provenance::{
    chunk_merkle_root, hash_plaintext_chunk, ots_media_commitment,
};

#[derive(Debug, ClapArgs)]
pub struct Args {
    /// Plaintext media chunk file(s), IN RECORDING ORDER. Repeat once per chunk.
    /// Their ordered hashes recompute the media Merkle root the `.ots` commits.
    #[arg(long = "chunk", required = true)]
    pub chunks: Vec<PathBuf>,

    /// The `OpenTimestamps` proof (`.ots`) over the media root. Confirms the
    /// proof commits `SHA-256(salt ‖ root)` (or the bare root without `--ots-salt`)
    /// and reports its Bitcoin anchor (or pending calendar state) — the trustless
    /// *when*.
    #[arg(long)]
    pub ots: PathBuf,

    /// Optional 32-byte OTS blinding salt (hex, 64 chars), from the bundle's
    /// `.otssalt`. The witness's `.ots` commits `SHA-256(salt ‖ root)`; supply it
    /// so the leaf can be recomputed. Omit for a bare-root `.ots`.
    #[arg(long = "ots-salt")]
    pub ots_salt: Option<String>,
}

fn hex_array<const N: usize>(s: &str, field: &str) -> Result<[u8; N]> {
    let v = hex::decode(s.trim()).with_context(|| format!("{field}: invalid hex"))?;
    if v.len() != N {
        bail!("{field}: expected {N} bytes, got {}", v.len());
    }
    let mut a = [0u8; N];
    a.copy_from_slice(&v);
    Ok(a)
}

pub fn run(args: &Args) -> Result<()> {
    // ---- recompute the media Merkle root from the disclosed chunks ----
    // clap enforces `required = true`, so `chunks` is non-empty here.
    let mut hashes = Vec::with_capacity(args.chunks.len());
    for p in &args.chunks {
        let bytes = std::fs::read(p).with_context(|| format!("read chunk {}", p.display()))?;
        hashes.push(hash_plaintext_chunk(&bytes));
    }
    let root = chunk_merkle_root(&hashes);

    let salt: Option<[u8; 32]> = match &args.ots_salt {
        Some(s) => Some(hex_array::<32>(s, "ots-salt")?),
        None => None,
    };

    println!("Recording verification (integrity + trustless timestamp)");
    println!("  chunks          : {}", args.chunks.len());
    println!("  media root      : {}", hex::encode(root));
    println!(
        "  salt            : {}",
        if salt.is_some() {
            "present"
        } else {
            "none (bare root)"
        }
    );
    println!("  checks:");

    let mut failed = 0u32;
    report_ots(&root, salt.as_ref(), &args.ots, &mut failed);

    if failed == 0 {
        println!(
            "\nRESULT: PASS — the disclosed media existed by the OpenTimestamps \
             anchor (integrity + anteriority). Attribution is NOT part of this proof."
        );
        Ok(())
    } else {
        println!("\nRESULT: FAIL — {failed} check(s) failed.");
        bail!("verification FAILED ({failed} check(s) failed)");
    }
}

fn report(label: &str, ok: bool, failed: &mut u32) {
    println!("    [{}] {label}", if ok { "OK" } else { "!!" });
    if !ok {
        *failed += 1;
    }
}

/// Run the OTS check against the recomputed media `root` and print the result.
/// A leaf mismatch / parse error is a hard failure (the proof is for different
/// media); a pending-only proof is informational (the Bitcoin anchor matures
/// later); a Bitcoin-anchored proof is the trustless *when*.
fn report_ots(root: &[u8; 32], salt: Option<&[u8; 32]>, ots_path: &Path, failed: &mut u32) {
    match verify_ots(root, salt, ots_path) {
        Ok(c) if !c.digest_ok => {
            report("timestamp    OTS commits the media root", false, failed);
        }
        Ok(c) if !c.bitcoin_heights.is_empty() => {
            let hs = c
                .bitcoin_heights
                .iter()
                .map(usize::to_string)
                .collect::<Vec<_>>()
                .join(", ");
            report(
                &format!("timestamp    OTS anchored in Bitcoin block(s) {hs}"),
                true,
                failed,
            );
        }
        Ok(c) => {
            let where_ = if c.pending_uris.is_empty() {
                "no attestation yet".to_string()
            } else {
                format!("pending at {}", c.pending_uris.join(", "))
            };
            println!(
                "    [ ~~ ] timestamp    OTS root OK but NOT yet Bitcoin-confirmed \
                 ({where_}); run `ots upgrade` later"
            );
        }
        Err(e) => {
            report(
                &format!("timestamp    OTS parse/verify ({e})"),
                false,
                failed,
            );
        }
    }
}

/// Result of checking an `OpenTimestamps` proof against the media root.
struct OtsCheck {
    /// The `.ots` commits the expected leaf (`SHA-256(salt ‖ root)`, or the bare
    /// `root` when no salt was disclosed).
    digest_ok: bool,
    /// Bitcoin block heights this proof is anchored in (trustless *when*).
    bitcoin_heights: Vec<usize>,
    /// Calendar URIs still pending (not yet Bitcoin-confirmed).
    pending_uris: Vec<String>,
}

/// Parse an `.ots`, confirm it commits the expected leaf, and collect its Bitcoin
/// / pending attestations. The lean contract: the timestamped leaf is
/// `SHA-256(salt ‖ root)` (the salted media root), or the bare `root` when the
/// witness didn't blind the commitment.
fn verify_ots(root: &[u8; 32], salt: Option<&[u8; 32]>, ots_path: &Path) -> Result<OtsCheck> {
    let expected = match salt {
        Some(s) => ots_media_commitment(s, root),
        None => *root,
    };

    let f =
        std::fs::File::open(ots_path).with_context(|| format!("open {}", ots_path.display()))?;
    let dtf = opentimestamps::DetachedTimestampFile::from_reader(std::io::BufReader::new(f))
        .map_err(|e| anyhow::anyhow!("parse .ots: {e}"))?;

    let digest_ok = dtf.timestamp.start_digest.as_slice() == expected.as_slice();
    let mut bitcoin_heights = Vec::new();
    let mut pending_uris = Vec::new();
    collect_attestations(
        &dtf.timestamp.first_step,
        &mut bitcoin_heights,
        &mut pending_uris,
    );
    Ok(OtsCheck {
        digest_ok,
        bitcoin_heights,
        pending_uris,
    })
}

/// Walk the timestamp tree, collecting Bitcoin block heights and pending
/// calendar URIs from the attestations.
fn collect_attestations(
    step: &opentimestamps::timestamp::Step,
    btc: &mut Vec<usize>,
    pending: &mut Vec<String>,
) {
    if let opentimestamps::timestamp::StepData::Attestation(att) = &step.data {
        match att {
            opentimestamps::attestation::Attestation::Bitcoin { height } => btc.push(*height),
            opentimestamps::attestation::Attestation::Pending { uri } => pending.push(uri.clone()),
            opentimestamps::attestation::Attestation::Unknown { .. } => {}
        }
    }
    for n in &step.next {
        collect_attestations(n, btc, pending);
    }
}
