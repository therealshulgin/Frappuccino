//! `frappuccino-cli fetch-archive` — Phase 4.4 rescue device flow,
//! Phase C **relay-blind** (identity-free).
//!
//! Use case: a journalist's phone got seized or wiped. They have the
//! BIP-39 paper phrase. They want their already-uploaded streams back.
//!
//! Workflow (one process invocation):
//!
//! 1. Read the mnemonic + optional passphrase (stdin by default).
//! 2. Derive the per-report capability keyring
//!    (`ReportKeyring::from_mnemonic`). The `report_id` is the
//!    phrase-derived capability — there is no identity, no archive-auth, no
//!    bearer. The relay stores `report_id → report_pk` and never the identity.
//! 3. With `--list` (default when no `--report-id`): **enumerate** the
//!    witness's reports by derivation — probe `report_id_0, report_id_1, …`
//!    via `GET /…/{report_id}/blobs` (404 = a hole), stopping after
//!    [`HOLE_TOLERANCE`] consecutive holes or [`MAX_PROBES`] total probes, and
//!    print the per-report blob summary.
//! 4. With `--report-id <id>`: list that report's blobs (id-free) and
//!    download each to `<out>/<report_id>/<filename>`. STRM blobs are written
//!    as-is — decryption is the user's next step (`frappuccino-cli decrypt`),
//!    so the rescue + decrypt phases stay auditable separately.
//!
//! The mnemonic + passphrase live as `String` for the duration of the CLI
//! process, acceptable for a one-shot rescue: the process exits seconds after,
//! the OS reclaims the heap, and the BIP-39 paper is the durable secret anyway.
//! The `ReportKeyring` holds its `report_master` in an `mlock`'d locked secret.

use std::fs;
use std::io::Write;
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use clap::Args as ClapArgs;
use frappuccino_crypto_core::bip39::{validate as bip39_validate, Language};
use frappuccino_crypto_core::report::ReportKeyring;
use frappuccino_crypto_stream::{is_safe_blob_filename, StreamServerClient};

use crate::{resolve_mnemonic, resolve_passphrase};

/// Dense-probe bound used ONLY when the report directory is absent — a rare edge
/// reachable only if index 0's directory entry never uploaded (i.e. ~no reports).
/// With the directory present (the norm) `n_max` is exact and there is no
/// arbitrary cap; the fallback is still truncation-free within `0..=FALLBACK_CAP`.
const FALLBACK_CAP: u32 = 512;

/// Local-only backstop for the M-1 derive-and-match loop: how far to derive
/// opaque entry names when matching the directory's blob list back to indices.
/// The loop normally STOPS as soon as every opaque entry is matched (exact,
/// hole-tolerant), so this only bites if a (semi-trusted, possibly coerced)
/// relay injected a junk name that matches no derived index — then we warn and
/// stop. It bounds local hashing; the resulting `n_max` (which DOES drive the
/// dense network probe) is separately clamped by [`PROBE_SLACK_OVER_ENTRIES`].
const DERIVE_MATCH_CAP: u32 = 100_000;

/// L-3 (WP-C) — clamp the dense network probe (`0..=n_max`) to the number of
/// directory entries the relay actually returned, plus this slack for any
/// allocated-but-unuploaded directory entries (holes). Each real report writes
/// exactly one directory entry, so `n_max` can legitimately exceed the entry
/// count only by the (tiny) number of lost entries. Without this, a coerced
/// relay could return ONE forged decimal entry (e.g. "100000") and inflate the
/// probe to 100k round-trips — a rescue `DoS`. 512 tolerates generous hole
/// counts while bounding a few-entry directory to a few-hundred probes.
const PROBE_SLACK_OVER_ENTRIES: u32 = 512;

#[derive(Debug, ClapArgs)]
pub struct Args {
    /// Relay URL (e.g. `https://136.244.101.236:8443`).
    pub url: String,

    /// BIP-39 phrase. **Avoid:** leaks into shell history. Pipe over
    /// stdin instead unless you're scripting in a sandbox.
    #[arg(long)]
    pub mnemonic: Option<String>,

    /// Optional BIP-39 passphrase. Empty by default.
    #[arg(long)]
    pub passphrase: Option<String>,

    /// Restrict the operation to a single report id; without this flag the
    /// command enumerates the witness's reports and prints a summary (no
    /// downloads).
    #[arg(long)]
    pub report_id: Option<String>,

    /// Output directory. Created if missing. Each blob is written to
    /// `<out>/<report_id>/<filename>`.
    #[arg(long, default_value = ".")]
    pub out: PathBuf,

    /// Emit one-line JSON instead of human-readable lines.
    #[arg(long)]
    pub json: bool,
}

#[allow(clippy::too_many_lines)] // single linear flow, splitting hurts readability more than it helps
pub fn run(args: &Args) -> Result<()> {
    let mnemonic = resolve_mnemonic(args.mnemonic.as_deref())?;
    let passphrase = resolve_passphrase(args.passphrase.as_deref(), false)?;

    // R-CR-2 (audit 2026-06-26) — defense-in-depth: gate the BIP-39 checksum
    // BEFORE deriving. `ReportKeyring::from_mnemonic` goes through
    // `mnemonic_to_seed`, which only rejects unknown words, NOT a wrong 4-bit
    // checksum. A phrase with two words swapped (or one mistyped-but-valid
    // word) would derive a *different* seed silently and the rescue would just
    // find 0 reports — confusing for a witness recovering under stress. The
    // Android archive-restore flow already gates on `bip39_validate`
    // (`ArchiveModeActivity.kt`); mirror it here so the rescue CLI fails loudly
    // on a mistyped phrase instead of pretending nothing was ever uploaded.
    bip39_validate(&mnemonic, Language::French)
        .context("BIP-39 mnemonic invalid (wrong word or checksum mismatch)")?;

    // 1. Derive the per-report capability keyring (report_master mlock'd inside).
    let keyring = ReportKeyring::from_mnemonic(&mnemonic, &passphrase)
        .context("derive report keyring from mnemonic")?;

    // 2. Build pinned client.
    let client = StreamServerClient::new(&args.url)
        .context("build StreamServerClient (TLS pin / reqwest)")?;

    let stdout = std::io::stdout();
    let mut out = stdout.lock();

    match &args.report_id {
        None => {
            // Summary mode — exact enumeration via the report DIRECTORY.
            // Step 1: recover the authoritative n_max from the directory's blob
            // names by derive-and-match (names are opaque since M-1, not indices).
            let dir_id = hex::encode(keyring.directory_id().context("derive directory_id")?);
            let n_max: u32 = match client
                .archive_list_blobs(&dir_id)
                .context("probe report directory")?
            {
                None => {
                    eprintln!("[fetch-archive] report directory absent — dense fallback to {FALLBACK_CAP}");
                    FALLBACK_CAP
                }
                // M-1 — entry names are now opaque (hex of a secret-derived tag),
                // no longer the decimal index. Dual-read so a directory written
                // across an app upgrade (mixed legacy + opaque entries) stays
                // fully recoverable: (a) parse any legacy "%010d" entries directly,
                // AND (b) re-derive each opaque name and match it back to its
                // index. The schemes are disjoint (a 32-hex name never parses as
                // u32), so the union is unambiguous.
                Some(entries) => {
                    let mut n_max: Option<u32> = None;

                    // A legacy "%010d" entry is a decimal index bounded by the
                    // SAME ceiling as the opaque derive-and-match (DERIVE_MATCH_CAP).
                    // Capping it identically (i) stops a coerced relay from
                    // inflating n_max with one big decimal -> billions of dense
                    // network probes (a rescue DoS), and (ii) makes the CLI (u32)
                    // and Android (Int) classify byte-for-byte the same: any value
                    // <= the ceiling fits both, anything above is junk in both.
                    let legacy_index = |name: &str| -> Option<u32> {
                        name.parse::<u32>().ok().filter(|&n| n <= DERIVE_MATCH_CAP)
                    };

                    // (a) Legacy decimal entries (within the ceiling).
                    for b in &entries {
                        if let Some(n) = legacy_index(&b.filename) {
                            n_max = Some(n_max.map_or(n, |m| m.max(n)));
                        }
                    }

                    // (b) Opaque entries = everything that is NOT a valid in-range
                    // legacy index. Derive name(n) and match; terminate as soon as
                    // every opaque entry is accounted for (exact, holes tolerated),
                    // or stop at DERIVE_MATCH_CAP on relay junk (a forged decimal
                    // above the ceiling lands here, never matches a derived name,
                    // and is surfaced in the unmatched warning).
                    let opaque: std::collections::HashSet<&str> = entries
                        .iter()
                        .filter(|b| legacy_index(&b.filename).is_none())
                        .map(|b| b.filename.as_str())
                        .collect();
                    let mut unmatched = opaque.len();
                    let mut n: u32 = 0;
                    while unmatched > 0 && n <= DERIVE_MATCH_CAP {
                        let name = hex::encode(
                            keyring
                                .directory_entry_name(n)
                                .with_context(|| format!("derive directory entry name {n}"))?,
                        );
                        if opaque.contains(name.as_str()) {
                            n_max = Some(n_max.map_or(n, |m| m.max(n)));
                            unmatched -= 1;
                        }
                        n += 1;
                    }
                    if unmatched > 0 {
                        eprintln!(
                            "[fetch-archive] {unmatched} directory entr(ies) unrecognized \
                             (relay junk or index > {DERIVE_MATCH_CAP}) — n_max may be incomplete"
                        );
                    }
                    let n_max_val = n_max.unwrap_or(FALLBACK_CAP);
                    // L-3 (WP-C): clamp the dense probe by the number of entries
                    // the relay returned (+ slack for holes) so a forged decimal
                    // entry can't inflate it to a 100k-probe rescue DoS.
                    let entry_cap = u32::try_from(entries.len())
                        .unwrap_or(u32::MAX)
                        .saturating_add(PROBE_SLACK_OVER_ENTRIES);
                    n_max_val.min(entry_cap)
                }
            };

            // Step 2: probe reports 0..=n_max DENSELY (a 404 is a skipped hole,
            // never an early stop). A real transport error returns Err and aborts.
            // (index, report_id, blob_count, total_bytes)
            let mut found: Vec<(u32, String, usize, u64)> = Vec::new();
            for n in 0..=n_max {
                let rid = hex::encode(
                    keyring
                        .report_id(n)
                        .with_context(|| format!("derive report_id {n}"))?,
                );
                if let Some(blobs) = client
                    .archive_list_blobs(&rid)
                    .with_context(|| format!("probe report {rid} (index {n})"))?
                {
                    let total: u64 = blobs.iter().map(|b| b.size).sum();
                    found.push((n, rid, blobs.len(), total));
                }
            }

            if args.json {
                let json = serde_json::json!({
                    "nMax": n_max,
                    "reports": found.iter().map(|(idx, rid, count, bytes)| serde_json::json!({
                        "index": idx,
                        "id": rid,
                        "blobCount": count,
                        "totalBytes": bytes,
                    })).collect::<Vec<_>>(),
                });
                writeln!(out, "{json}")?;
            } else {
                writeln!(out, "{} report(s) found (n_max={}):", found.len(), n_max)?;
                for (idx, rid, count, bytes) in &found {
                    writeln!(out, "  [{idx}] {rid}  ({count} blobs, {bytes} bytes)")?;
                }
                writeln!(
                    out,
                    "\nRe-run with --report-id <id> --out <dir> to download."
                )?;
            }
        }
        Some(rid) => {
            // Download mode — id-free list + download of a single report.
            let blobs = client
                .archive_list_blobs(rid)
                .with_context(|| format!("GET archive blobs for {rid}"))?
                .ok_or_else(|| anyhow::anyhow!("report {rid} not found (404)"))?;
            if blobs.is_empty() {
                bail!("report {rid} has no blobs to download");
            }

            let target_dir = args.out.join(rid);
            fs::create_dir_all(&target_dir)
                .with_context(|| format!("create output dir {}", target_dir.display()))?;

            let mut downloaded_bytes = 0u64;
            for blob in &blobs {
                if !is_safe_blob_filename(&blob.filename) {
                    bail!(
                        "relay returned an unsafe blob filename {:?} for report {rid} — refusing to write",
                        blob.filename
                    );
                }
                let path = target_dir.join(&blob.filename);
                let mut file = fs::File::create(&path)
                    .with_context(|| format!("create {}", path.display()))?;
                let n = client
                    .archive_download_blob(rid, &blob.filename, &mut file)
                    .with_context(|| format!("download {}/{}", rid, blob.filename))?;
                downloaded_bytes += n;
                if !args.json {
                    writeln!(out, "  -> {} ({} bytes)", path.display(), n)?;
                }
            }

            if args.json {
                let json = serde_json::json!({
                    "report_id": rid,
                    "blobs_downloaded": blobs.len(),
                    "bytes_downloaded": downloaded_bytes,
                    "out_dir": target_dir.display().to_string(),
                });
                writeln!(out, "{json}")?;
            } else {
                writeln!(
                    out,
                    "\n{} blob(s), {} bytes total written to {}",
                    blobs.len(),
                    downloaded_bytes,
                    target_dir.display(),
                )?;
                writeln!(
                    out,
                    "Use `frappuccino-cli decrypt` to extract plaintext from each .strm.",
                )?;
            }
        }
    }

    Ok(())
}
