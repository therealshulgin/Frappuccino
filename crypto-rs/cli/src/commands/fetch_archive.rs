//! `frappuccino-cli fetch-archive` — the rescue on a desktop: from the BIP-39
//! phrase alone, find the witness's reports on the relay, verify every stored
//! object, and write only what verifies.
//!
//! It runs the same code as the Android rescue (`frappuccino_crypto_ffi::rescue`):
//! the same enumeration (directory names matched back to indices in both
//! derivation families, then a probe past the highest one), the same
//! verification (keys re-derived from the phrase, closures and write
//! signatures checked), the same statuses.
//!
//! Output, under `--out`:
//! - `<report_id>/<name>`: the VERIFIED objects, still encrypted (decrypt them
//!   with `frappuccino-cli decrypt`);
//! - `<report_id>/unverifiable/<name>`: legacy objects stored without a
//!   signature. Kept apart because they are the only copy of old recordings,
//!   but they are NOT part of the verified testimony: nothing proves they are
//!   the witness's;
//! - `<report_id>/timestamp.ots` and `timestamp.otssalt`: a chained report's
//!   decrypted timestamp proof and its blinding salt, when the proof verifies
//!   and matches the commitment recomputed from the verified objects (feed
//!   them to `verify-provenance` for the Bitcoin anchoring).
//!
//! Everything else is deleted as soon as it is classified, and counted. A 429
//! from the relay waits (at least 60 s) and resumes.
//!
//! What the relay serves can be malformed on purpose: whoever holds the device
//! state can fill the directory or a report past the listing cap. A directory
//! listing that does not read is shown as an anomaly and the enumeration falls
//! back to the long probe it uses without a directory; a report listing that
//! does not read is shown as an anomaly at its index and the probe goes on.
//! Only a failure to reach the relay stops the enumeration. A report whose
//! check fails part way is reported with its error, after which the others
//! are still checked. The statuses are always printed; the command exits
//! non-zero if the enumeration could not finish (a transport failure, or the
//! probe cap reached before a run of empty indices), or if any report could
//! not be read or checked to the end.
//!
//! The mnemonic and passphrase live as `String` for the duration of the
//! process, acceptable for a one-shot rescue that exits once done (the BIP-39
//! paper is the durable secret anyway); the derived keys are held by the core
//! types, which wipe them on drop.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use crate::{resolve_mnemonic, resolve_passphrase};
use anyhow::{bail, Context, Result};
use clap::Args as ClapArgs;
use frappuccino_crypto_core::identity::ArchiveIdentity;
use frappuccino_crypto_core::provenance::{
    chunk_merkle_root, hash_plaintext_chunk, ots_media_commitment, ProvenanceSigner,
};
use frappuccino_crypto_core::report::parse_chain_object_name;
use uniffi_frappuccino::{
    ClosureState, FfiError, ObjectStatus, ReportCheck, ReportRescue, ReportScheme, ReportStatus,
    ReportVerdict, RescuePlanner, RescueTarget, StreamServerClient,
};

/// Consecutive 429 answers waited out for one request before giving up.
const MAX_RATE_LIMIT_WAITS: u32 = 30;
/// Shortest wait after a 429 (the relay sends no `Retry-After`).
const MIN_RATE_LIMIT_WAIT: u64 = 60;
/// Where fetched objects land before their status decides where they go.
const INCOMING_DIR: &str = ".incoming";
/// Where legacy objects without a signature are kept apart.
const UNVERIFIABLE_DIR: &str = "unverifiable";

#[derive(Debug, ClapArgs)]
pub struct Args {
    /// Relay URL (e.g. `https://relay.example.org:8443`).
    pub url: String,

    /// BIP-39 phrase. **Avoid:** leaks into shell history. Pipe over
    /// stdin instead unless you're scripting in a sandbox.
    #[arg(long)]
    pub mnemonic: Option<String>,

    /// Optional BIP-39 passphrase. Empty by default.
    #[arg(long)]
    pub passphrase: Option<String>,

    /// Only enumerate: print the reports found and their listings, fetch no
    /// object.
    #[arg(long)]
    pub list: bool,

    /// Restrict the verification to the report with this id (32 lowercase
    /// hex, as printed by `--list`).
    #[arg(long)]
    pub report_id: Option<String>,

    /// Output directory. Created if missing.
    #[arg(long, default_value = ".")]
    pub out: PathBuf,

    /// Emit one JSON document instead of human-readable lines.
    #[arg(long)]
    pub json: bool,
}

/// The rescue material the phrase gives, besides the report keys.
struct PhraseKeys {
    archive: ArchiveIdentity,
    provenance: ProvenanceSigner,
}

/// One report's result.
struct Rescued {
    report_id: String,
    scheme: ReportScheme,
    index: Option<u32>,
    /// The verdict and the timestamp check, or why the check could not end.
    outcome: Result<Checked, String>,
}

/// A report checked to the end.
struct Checked {
    verdict: ReportVerdict,
    ots: Option<OtsOutcome>,
}

/// The directory, as listed.
enum Directory {
    /// The relay has none for this phrase.
    Absent,
    /// The relay served something that is not a listing (an anomaly).
    Unreadable(String),
    Listed(Arc<ReportCheck>),
}

impl Directory {
    fn check(&self) -> Option<&Arc<ReportCheck>> {
        match self {
            Self::Listed(check) => Some(check),
            Self::Absent | Self::Unreadable(_) => None,
        }
    }
}

/// The directory's closure, as checked before the reports.
enum DirectoryClosure {
    NoDirectory,
    Unreadable,
    Checked(ClosureState),
    /// The check could not end; the reports are rescued anyway.
    Failed(String),
}

/// What the enumeration found, and why it stopped early, if it did.
struct Enumeration<T> {
    found: Vec<T>,
    /// Targets whose listing the relay served unreadable, with the error.
    unreadable: Vec<(RescueTarget, String)>,
    incomplete: Option<String>,
}

/// What a failed probe means for the enumeration.
#[derive(Debug, PartialEq, Eq)]
enum ProbeFailure {
    /// The relay answered with something that is not a listing: an anomaly
    /// at that index, and the enumeration goes on.
    Unreadable,
    /// The relay could not be reached, or kept refusing: the enumeration
    /// stops, incomplete.
    Stop,
}

/// The timestamp check of a chained report.
#[derive(Clone, Copy)]
enum OtsOutcome {
    Match,
    Mismatch,
    Absent,
}

pub fn run(args: &Args) -> Result<()> {
    let mnemonic = resolve_mnemonic(args.mnemonic.as_deref())?;
    let passphrase = resolve_passphrase(args.passphrase.as_deref(), false)?;
    // Validates the words AND the checksum: a mistyped phrase fails loudly
    // instead of finding no report.
    let rescue = ReportRescue::from_mnemonic(mnemonic.as_bytes(), passphrase.as_bytes())
        .context("BIP-39 mnemonic invalid (wrong word or checksum mismatch)")?;
    let client = Arc::new(
        StreamServerClient::new(&args.url).context("build relay client (TLS pin / reqwest)")?,
    );

    let directory = open_directory(&rescue, &client)?;
    let planner = rescue
        .planner(directory.check().cloned())
        .context("match the directory names")?;
    let mut enumeration = enumerate(&planner, |target| {
        with_backoff(|| rescue.open_report(Arc::clone(&client), target))
    });
    if let Some(wanted) = &args.report_id {
        enumeration
            .found
            .retain(|check| &check.report_id_hex() == wanted);
    }

    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    let mut failed = enumeration.unreadable.len();
    if args.list {
        print_listing(&mut out, args.json, &directory, &planner, &enumeration)?;
    } else {
        let keys = PhraseKeys {
            archive: ArchiveIdentity::from_mnemonic(&mnemonic, &passphrase)
                .context("derive the archive identity")?,
            provenance: ProvenanceSigner::from_mnemonic(&mnemonic, &passphrase)
                .context("derive the provenance seed")?,
        };
        let incoming = args.out.join(INCOMING_DIR);
        fs::create_dir_all(&incoming)
            .with_context(|| format!("create output dir {}", incoming.display()))?;
        let directory_closure = check_directory_closure(&directory, &args.out);
        let rescued = rescue_each(
            &enumeration.found,
            |check| (check.report_id_hex(), check.scheme(), check.index()),
            |check| {
                rescue_report(
                    check,
                    directory.check().map(AsRef::as_ref),
                    &keys,
                    &args.out,
                )
            },
        );
        failed += rescued.iter().filter(|r| r.outcome.is_err()).count();
        let _ = fs::remove_dir(&incoming);
        print_results(
            &mut out,
            args.json,
            &directory_closure,
            &planner,
            &enumeration,
            &rescued,
            &args.out,
        )?;
    }
    if let Some(reason) = &enumeration.incomplete {
        bail!("enumeration incomplete: {reason}");
    }
    if failed > 0 {
        bail!("{failed} report(s) could not be read or checked to the end");
    }
    Ok(())
}

/// List the directory. A listing the relay served unreadable is an anomaly,
/// not a stop: the rescue goes on without a directory.
fn open_directory(rescue: &ReportRescue, client: &Arc<StreamServerClient>) -> Result<Directory> {
    match with_backoff(|| rescue.open_directory(Arc::clone(client))) {
        Ok(Some(check)) => Ok(Directory::Listed(check)),
        Ok(None) => Ok(Directory::Absent),
        Err(error) if probe_failure(&error) == ProbeFailure::Unreadable => {
            Ok(Directory::Unreadable(format!("{error:#}")))
        }
        Err(error) => Err(error.context("list the report directory")),
    }
}

/// Check the directory's closure (any closure of it is an anomaly). A check
/// that cannot end is reported, and the reports are rescued anyway.
fn check_directory_closure(directory: &Directory, out: &Path) -> DirectoryClosure {
    match directory {
        Directory::Absent => DirectoryClosure::NoDirectory,
        Directory::Unreadable(_) => DirectoryClosure::Unreadable,
        Directory::Listed(check) => {
            match with_backoff(|| check.verify_closure(&scratch(out, "directory-manifest")?)) {
                Ok(state) => DirectoryClosure::Checked(state),
                Err(error) => DirectoryClosure::Failed(format!("{error:#}")),
            }
        }
    }
}

/// Rescue every report with `check`, keeping each one's error instead of
/// stopping on it: the reports after a failed one are still checked, and every
/// status is printed. `describe` gives a report's id, scheme and index.
fn rescue_each<T>(
    reports: &[T],
    describe: impl Fn(&T) -> (String, ReportScheme, Option<u32>),
    mut check: impl FnMut(&T) -> Result<Checked>,
) -> Vec<Rescued> {
    reports
        .iter()
        .map(|report| {
            let (report_id, scheme, index) = describe(report);
            Rescued {
                report_id,
                scheme,
                index,
                outcome: check(report).map_err(|error| format!("{error:#}")),
            }
        })
        .collect()
}

// ============================================================================
// Enumeration and network helpers
// ============================================================================

/// Run `call`, waiting out 429 answers (at least a minute each).
fn with_backoff<T>(mut call: impl FnMut() -> Result<T, FfiError>) -> Result<T> {
    let mut waits = 0u32;
    loop {
        match call() {
            Err(FfiError::RateLimited { retry_after_secs }) if waits < MAX_RATE_LIMIT_WAITS => {
                waits += 1;
                let wait = retry_after_secs.max(MIN_RATE_LIMIT_WAIT);
                eprintln!("[fetch-archive] rate limited by the relay, waiting {wait}s");
                std::thread::sleep(Duration::from_secs(wait));
            }
            other => return other.map_err(anyhow::Error::from),
        }
    }
}

/// What a failed probe means: a listing the relay served unreadable
/// (`InvalidBlob`, a shape error) is an anomaly at that index; anything else
/// (transport, I/O, a rate limit that never lifted) stops the enumeration.
fn probe_failure(error: &anyhow::Error) -> ProbeFailure {
    match error.downcast_ref::<FfiError>() {
        Some(FfiError::InvalidBlob { .. }) => ProbeFailure::Unreadable,
        _ => ProbeFailure::Stop,
    }
}

/// Probe every target the planner yields with `probe`. An unreadable listing
/// is recorded as found (something is stored there, so it does not count in
/// the run of empty indices) and kept as an anomaly. A failure that stops the
/// enumeration, or the probe cap, makes it incomplete; the reports found so
/// far are kept either way.
fn enumerate<T>(
    planner: &RescuePlanner,
    mut probe: impl FnMut(RescueTarget) -> Result<Option<T>>,
) -> Enumeration<T> {
    let mut found = Vec::new();
    let mut unreadable = Vec::new();
    while let Some(target) = planner.next() {
        match probe(target) {
            Ok(Some(report)) => {
                planner.record(true);
                found.push(report);
            }
            Ok(None) => planner.record(false),
            Err(error) if probe_failure(&error) == ProbeFailure::Unreadable => {
                planner.record(true);
                unreadable.push((target, format!("{error:#}")));
            }
            Err(error) => {
                return Enumeration {
                    found,
                    unreadable,
                    incomplete: Some(format!("{error:#}")),
                }
            }
        }
    }
    let incomplete = planner
        .hit_probe_cap()
        .then(|| "probe cap reached before a run of empty indices".to_owned());
    Enumeration {
        found,
        unreadable,
        incomplete,
    }
}

/// A scratch file under the output directory, as a string path.
fn scratch(out: &Path, name: &str) -> Result<String, FfiError> {
    path_str(&out.join(INCOMING_DIR).join(name))
}

fn path_str(path: &Path) -> Result<String, FfiError> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| FfiError::Io {
            detail: format!("path is not UTF-8: {}", path.display()),
        })
}

// ============================================================================
// Verification of one report
// ============================================================================

/// Verify every object of one report, keep what verifies, and check its
/// timestamp proof.
fn rescue_report(
    check: &ReportCheck,
    directory: Option<&ReportCheck>,
    keys: &PhraseKeys,
    out: &Path,
) -> Result<Checked> {
    let report_id = check.report_id_hex();
    let report_dir = out.join(&report_id);
    let incoming = report_dir.join(INCOMING_DIR);
    fs::create_dir_all(&incoming).with_context(|| format!("create {}", incoming.display()))?;
    if check.has_closure() {
        let manifest = path_str(&incoming.join("manifest"))?;
        with_backoff(|| check.verify_closure(&manifest))
            .with_context(|| format!("verify the closure of {report_id}"))?;
    }
    for name in check.object_names() {
        let landing = incoming.join(&name);
        let landing_str = path_str(&landing)?;
        let status = with_backoff(|| check.fetch_object(&name, &landing_str))
            .with_context(|| format!("fetch {report_id}/{name}"))?;
        keep(status, &landing, &report_dir, &name)?;
    }
    let verdict = check.verdict()?;
    let ots = match (check.scheme(), check.ots_name(), directory) {
        (ReportScheme::Chain, Some(ots_name), Some(directory)) => Some(check_timestamp(
            directory,
            &ots_name,
            &verdict,
            &report_dir,
            keys,
        )?),
        (ReportScheme::Chain, _, _) => Some(OtsOutcome::Absent),
        _ => None,
    };
    let _ = fs::remove_dir(&incoming);
    Ok(Checked { verdict, ots })
}

/// Move a fetched object to where its status says (the excluded ones are
/// already deleted).
fn keep(status: ObjectStatus, landing: &Path, report_dir: &Path, name: &str) -> Result<()> {
    let target = match status {
        ObjectStatus::Verified => report_dir.join(name),
        ObjectStatus::Unverifiable => {
            let apart = report_dir.join(UNVERIFIABLE_DIR);
            fs::create_dir_all(&apart).with_context(|| format!("create {}", apart.display()))?;
            apart.join(name)
        }
        _ => return Ok(()),
    };
    fs::rename(landing, &target).with_context(|| format!("move to {}", target.display()))
}

/// Fetch and check a chained report's timestamp proof from the directory, and
/// compare it with the commitment recomputed from the report's verified
/// objects. On a match, write the decrypted proof and its salt.
fn check_timestamp(
    directory: &ReportCheck,
    ots_name: &str,
    verdict: &ReportVerdict,
    report_dir: &Path,
    keys: &PhraseKeys,
) -> Result<OtsOutcome> {
    if !directory.object_names().iter().any(|name| name == ots_name) {
        return Ok(OtsOutcome::Absent);
    }
    let landing = report_dir.join(INCOMING_DIR).join("timestamp.ots.strm");
    let landing_str = path_str(&landing)?;
    let status = with_backoff(|| directory.fetch_object(ots_name, &landing_str))
        .context("fetch the timestamp proof")?;
    if status != ObjectStatus::Verified {
        let _ = fs::remove_file(&landing);
        return Ok(OtsOutcome::Mismatch);
    }
    let sealed = fs::read(&landing).context("read the fetched proof")?;
    let _ = fs::remove_file(&landing);
    judge_proof(&sealed, verdict, report_dir, keys)
}

/// Compare a fetched proof, which passed the directory signature, with the
/// commitment recomputed from the report's verified objects. On a match,
/// write the decrypted proof and its salt.
///
/// The directory signature is only a filter (its key is persistent, held by
/// whoever has the device state): a signed proof that does not decrypt is a
/// mismatch to show, not a reason to stop.
fn judge_proof(
    sealed: &[u8],
    verdict: &ReportVerdict,
    report_dir: &Path,
    keys: &PhraseKeys,
) -> Result<OtsOutcome> {
    let Ok((proof, _)) = frappuccino_crypto_stream::decrypt::decrypt(sealed, &keys.archive) else {
        return Ok(OtsOutcome::Mismatch);
    };
    let Some((commitment, salt)) = recompute_commitment(verdict, report_dir, keys)? else {
        return Ok(OtsOutcome::Mismatch);
    };
    let timestamped = opentimestamps::DetachedTimestampFile::from_reader(proof.as_slice())
        .map(|file| file.timestamp.start_digest)
        .ok();
    if timestamped.as_deref() != Some(commitment.as_slice()) {
        return Ok(OtsOutcome::Mismatch);
    }
    fs::write(report_dir.join("timestamp.ots"), proof.as_slice()).context("write timestamp.ots")?;
    fs::write(report_dir.join("timestamp.otssalt"), hex::encode(salt))
        .context("write timestamp.otssalt")?;
    Ok(OtsOutcome::Match)
}

/// The salted commitment over the verified chunks (seq >= 1, in order), with
/// the salt derived from the session id in the verified metadata object.
/// `None` without a verified metadata object or a readable session id, or if
/// a verified object does not decrypt.
fn recompute_commitment(
    verdict: &ReportVerdict,
    report_dir: &Path,
    keys: &PhraseKeys,
) -> Result<Option<([u8; 32], [u8; 32])>> {
    let mut session_id = None;
    let mut chunk_hashes = Vec::new();
    for name in &verdict.verified_names {
        let Some(seq) = parse_chain_object_name(name) else {
            continue;
        };
        let sealed = fs::read(report_dir.join(name)).with_context(|| format!("read {name}"))?;
        let Ok((plain, _)) = frappuccino_crypto_stream::decrypt::decrypt(&sealed, &keys.archive)
        else {
            // Verified, so signed by the report key, yet not encrypted to
            // this phrase: no commitment can be recomputed (a mismatch).
            eprintln!("[fetch-archive] anomaly: {name} verified but does not decrypt");
            return Ok(None);
        };
        if seq == 0 {
            session_id = serde_json::from_slice::<serde_json::Value>(&plain)
                .ok()
                .and_then(|json| json.get("sessionId")?.as_str().map(str::to_owned));
        } else {
            chunk_hashes.push(hash_plaintext_chunk(&plain));
        }
    }
    let Some(session_id) = session_id else {
        return Ok(None);
    };
    let digest = hash_plaintext_chunk(session_id.as_bytes());
    let mut recording_id = [0u8; 16];
    recording_id.copy_from_slice(&digest[..16]);
    let salt = keys
        .provenance
        .ots_salt(&recording_id)
        .context("derive the timestamp salt")?;
    let commitment = ots_media_commitment(&salt, &chunk_merkle_root(&chunk_hashes));
    Ok(Some((commitment, salt)))
}

// ============================================================================
// Output
// ============================================================================

fn report_status_name(status: ReportStatus) -> &'static str {
    match status {
        ReportStatus::Complete => "COMPLETE",
        ReportStatus::Incomplete => "INCOMPLETE",
        ReportStatus::Altered => "ALTERED",
        ReportStatus::Interrupted => "INTERRUPTED",
        ReportStatus::Legacy => "LEGACY",
        ReportStatus::Directory => "DIRECTORY",
    }
}

fn closure_name(state: ClosureState) -> &'static str {
    match state {
        ClosureState::Absent => "ABSENT",
        ClosureState::Unchecked => "UNCHECKED",
        ClosureState::Valid => "VALID",
        ClosureState::Invalid => "INVALID",
    }
}

fn scheme_name(scheme: ReportScheme) -> &'static str {
    match scheme {
        ReportScheme::Legacy => "legacy",
        ReportScheme::Chain => "chain",
        ReportScheme::Directory => "directory",
    }
}

fn ots_name_of(ots: Option<OtsOutcome>) -> Option<&'static str> {
    ots.map(|outcome| match outcome {
        OtsOutcome::Match => "OTS_MATCH",
        OtsOutcome::Mismatch => "OTS_MISMATCH",
        OtsOutcome::Absent => "OTS_ABSENT",
    })
}

fn target_json(target: RescueTarget, error: &str) -> serde_json::Value {
    serde_json::json!({
        "scheme": scheme_name(target.scheme),
        "index": target.index,
        "error": error,
    })
}

/// The anomalies of the enumeration, shared by both outputs: an unreadable
/// directory, unmatched directory names, unreadable report listings.
fn print_enumeration_anomalies<T>(
    out: &mut impl Write,
    planner: &RescuePlanner,
    enumeration: &Enumeration<T>,
) -> Result<()> {
    if planner.unmatched_entries() > 0 {
        writeln!(
            out,
            "  {} directory name(s) matched no index (anomaly)",
            planner.unmatched_entries()
        )?;
    }
    for (target, error) in &enumeration.unreadable {
        writeln!(
            out,
            "[{} {}] listing UNREADABLE (anomaly; the probe went on): {error}",
            scheme_name(target.scheme),
            target.index
        )?;
    }
    if let Some(reason) = &enumeration.incomplete {
        writeln!(out, "enumeration INCOMPLETE: {reason}")?;
    }
    Ok(())
}

fn print_listing(
    out: &mut impl Write,
    json: bool,
    directory: &Directory,
    planner: &RescuePlanner,
    enumeration: &Enumeration<Arc<ReportCheck>>,
) -> Result<()> {
    let reports = &enumeration.found;
    if json {
        let doc = serde_json::json!({
            "directory": directory.check().map(|d| serde_json::json!({
                "entries": d.object_names().len(),
                "closed": d.has_closure(),
            })),
            "directoryUnreadable": matches!(directory, Directory::Unreadable(_)),
            "unmatchedEntries": planner.unmatched_entries(),
            "unreadableReports": enumeration.unreadable.iter()
                .map(|(target, error)| target_json(*target, error)).collect::<Vec<_>>(),
            "incomplete": enumeration.incomplete,
            "reports": reports.iter().map(|r| serde_json::json!({
                "scheme": scheme_name(r.scheme()),
                "index": r.index(),
                "id": r.report_id_hex(),
                "objects": r.object_names().len(),
                "closed": r.has_closure(),
            })).collect::<Vec<_>>(),
        });
        writeln!(out, "{doc}")?;
        return Ok(());
    }
    match directory {
        Directory::Listed(d) if d.has_closure() => writeln!(
            out,
            "directory: {} entries, CLOSED (anomaly: someone holding the device state froze it)",
            d.object_names().len()
        )?,
        Directory::Listed(d) => writeln!(out, "directory: {} entries", d.object_names().len())?,
        Directory::Unreadable(error) => writeln!(
            out,
            "directory: UNREADABLE (anomaly; long probe instead): {error}"
        )?,
        Directory::Absent => writeln!(out, "directory: absent")?,
    }
    print_enumeration_anomalies(out, planner, enumeration)?;
    writeln!(out, "{} report(s) found:", reports.len())?;
    for r in reports {
        writeln!(
            out,
            "  [{} {}] {}  ({} objects{})",
            scheme_name(r.scheme()),
            r.index().map_or_else(String::new, |i| i.to_string()),
            r.report_id_hex(),
            r.object_names().len(),
            if r.has_closure() { ", closed" } else { "" }
        )?;
    }
    writeln!(out, "\nRe-run without --list to verify and download.")?;
    Ok(())
}

fn verdict_json(rescued: &Rescued, out_dir: &Path) -> serde_json::Value {
    let checked = match &rescued.outcome {
        Ok(checked) => checked,
        Err(error) => {
            return serde_json::json!({
                "scheme": scheme_name(rescued.scheme),
                "index": rescued.index,
                "id": rescued.report_id,
                "error": error,
            })
        }
    };
    let v = &checked.verdict;
    serde_json::json!({
        "scheme": scheme_name(v.scheme),
        "index": v.index,
        "id": rescued.report_id,
        "status": report_status_name(v.status),
        "closure": closure_name(v.closure),
        "closureAnomaly": v.closure_anomaly,
        "counts": {
            "verified": v.verified, "foreign": v.foreign, "missing": v.missing,
            "unexpected": v.unexpected, "unexpectedSigned": v.unexpected_signed,
            "unverifiable": v.unverifiable, "invalid": v.invalid, "unchecked": v.unchecked,
        },
        "missingSeqs": v.missing_seqs,
        "firstModified": v.first_modified,
        "lastModified": v.last_modified,
        "ots": ots_name_of(checked.ots),
        "outDir": out_dir.join(&rescued.report_id).display().to_string(),
    })
}

fn directory_closure_json(directory: &DirectoryClosure) -> serde_json::Value {
    match directory {
        DirectoryClosure::NoDirectory => serde_json::Value::Null,
        DirectoryClosure::Unreadable => serde_json::json!({ "unreadable": true, "anomaly": true }),
        DirectoryClosure::Checked(state) => serde_json::json!({
            "closure": closure_name(*state),
            "anomaly": *state != ClosureState::Absent,
        }),
        DirectoryClosure::Failed(error) => serde_json::json!({ "error": error, "anomaly": true }),
    }
}

fn print_results(
    out: &mut impl Write,
    json: bool,
    directory: &DirectoryClosure,
    planner: &RescuePlanner,
    enumeration: &Enumeration<Arc<ReportCheck>>,
    rescued: &[Rescued],
    out_dir: &Path,
) -> Result<()> {
    if json {
        let doc = serde_json::json!({
            "directory": directory_closure_json(directory),
            "unmatchedEntries": planner.unmatched_entries(),
            "unreadableReports": enumeration.unreadable.iter()
                .map(|(target, error)| target_json(*target, error)).collect::<Vec<_>>(),
            "incomplete": enumeration.incomplete,
            "reports": rescued.iter().map(|r| verdict_json(r, out_dir)).collect::<Vec<_>>(),
        });
        writeln!(out, "{doc}")?;
        return Ok(());
    }
    match directory {
        DirectoryClosure::NoDirectory => writeln!(out, "directory: absent (long probe)")?,
        DirectoryClosure::Unreadable => {
            writeln!(out, "directory: UNREADABLE (anomaly; long probe instead)")?;
        }
        DirectoryClosure::Checked(ClosureState::Absent) => writeln!(out, "directory: present")?,
        DirectoryClosure::Checked(_) => writeln!(
            out,
            "directory: CLOSED (anomaly: someone holding the device state froze it); probed beyond"
        )?,
        DirectoryClosure::Failed(error) => {
            writeln!(out, "directory: closure NOT CHECKED (anomaly): {error}")?;
        }
    }
    print_enumeration_anomalies(out, planner, enumeration)?;
    for r in rescued {
        print_verdict(out, r)?;
    }
    writeln!(
        out,
        "\nVerified objects are under {}/<id>/ (still encrypted: `frappuccino-cli decrypt`).",
        out_dir.display()
    )?;
    Ok(())
}

fn print_verdict(out: &mut impl Write, rescued: &Rescued) -> Result<()> {
    let checked = match &rescued.outcome {
        Ok(checked) => checked,
        Err(error) => {
            writeln!(
                out,
                "[{} {}] {}  NOT CHECKED TO THE END: {error}",
                scheme_name(rescued.scheme),
                rescued.index.map_or_else(String::new, |i| i.to_string()),
                rescued.report_id,
            )?;
            return Ok(());
        }
    };
    let v = &checked.verdict;
    writeln!(
        out,
        "[{} {}] {}  {}  closure={}{}",
        scheme_name(v.scheme),
        v.index.map_or_else(String::new, |i| i.to_string()),
        rescued.report_id,
        report_status_name(v.status),
        closure_name(v.closure),
        if v.closure_anomaly { " (ANOMALY)" } else { "" },
    )?;
    writeln!(
        out,
        "    verified={} foreign={} missing={} unexpected={} unexpected_signed={} \
         unverifiable={} invalid={} unchecked={}",
        v.verified,
        v.foreign,
        v.missing,
        v.unexpected,
        v.unexpected_signed,
        v.unverifiable,
        v.invalid,
        v.unchecked
    )?;
    if let (Some(first), Some(last)) = (&v.first_modified, &v.last_modified) {
        writeln!(out, "    stored between {first} and {last} (relay clock)")?;
    }
    if !v.missing_seqs.is_empty() {
        writeln!(out, "    missing seq: {:?}", v.missing_seqs)?;
    }
    if v.unverifiable > 0 {
        writeln!(
            out,
            "    {} object(s) kept apart in {UNVERIFIABLE_DIR}/: stored without a signature, NOT verified",
            v.unverifiable
        )?;
    }
    if let Some(ots) = ots_name_of(checked.ots) {
        writeln!(out, "    timestamp: {ots}")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const MN_FIXED: &str = "abaisser abandon abdiquer abeille abolir aborder aboutir aboyer abrasif abreuver abriter abroger";

    fn keys() -> PhraseKeys {
        PhraseKeys {
            archive: ArchiveIdentity::from_mnemonic(MN_FIXED, "").unwrap(),
            provenance: ProvenanceSigner::from_mnemonic(MN_FIXED, "").unwrap(),
        }
    }

    fn scratch_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("frap_cli_{}_{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn verdict(names: &[&str]) -> ReportVerdict {
        ReportVerdict {
            scheme: ReportScheme::Chain,
            index: Some(0),
            status: ReportStatus::Complete,
            closure: ClosureState::Valid,
            closure_anomaly: false,
            verified: u32::try_from(names.len()).unwrap(),
            foreign: 0,
            missing: 0,
            unexpected: 0,
            unexpected_signed: 0,
            unverifiable: 0,
            invalid: 0,
            unchecked: 0,
            verified_names: names.iter().map(|n| (*n).to_owned()).collect(),
            unverifiable_names: Vec::new(),
            missing_seqs: Vec::new(),
            first_modified: None,
            last_modified: None,
        }
    }

    fn seal(dir: &Path, name: &str, plain: &[u8], keys: &PhraseKeys) {
        let blob =
            frappuccino_crypto_stream::encrypt::encrypt(plain, keys.archive.identity()).unwrap();
        fs::write(dir.join(name), blob).unwrap();
    }

    #[test]
    fn the_commitment_is_recomputed_from_the_verified_objects_only() {
        let dir = scratch_dir("commitment");
        let keys = keys();
        seal(
            &dir,
            "000000.strm",
            br#"{"version":1,"sessionId":"abc123"}"#,
            &keys,
        );
        seal(&dir, "000001.strm", b"first chunk", &keys);
        seal(&dir, "000003.strm", b"third chunk", &keys);
        let (commitment, salt) = recompute_commitment(
            &verdict(&["000000.strm", "000001.strm", "000003.strm"]),
            &dir,
            &keys,
        )
        .unwrap()
        .unwrap();
        // The device's computation: SHA-256(sessionId)[..16] as recording id.
        let digest = hash_plaintext_chunk(b"abc123");
        let recording_id: [u8; 16] = digest[..16].try_into().unwrap();
        let expected_salt = keys.provenance.ots_salt(&recording_id).unwrap();
        let root = chunk_merkle_root(&[
            hash_plaintext_chunk(b"first chunk"),
            hash_plaintext_chunk(b"third chunk"),
        ]);
        assert_eq!(salt, expected_salt);
        assert_eq!(commitment, ots_media_commitment(&expected_salt, &root));
        // Without the verified metadata object there is no session id.
        assert!(
            recompute_commitment(&verdict(&["000001.strm"]), &dir, &keys)
                .unwrap()
                .is_none()
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn only_kept_statuses_leave_the_landing_area() {
        let dir = scratch_dir("keep");
        let landing = dir.join("landing");
        for (status, name, kept) in [
            (
                ObjectStatus::Verified,
                "000001.strm",
                Some(dir.join("000001.strm")),
            ),
            (
                ObjectStatus::Unverifiable,
                "sid_000002.strm",
                Some(dir.join(UNVERIFIABLE_DIR).join("sid_000002.strm")),
            ),
            (ObjectStatus::Foreign, "000003.strm", None),
        ] {
            fs::write(&landing, b"x").unwrap();
            keep(status, &landing, &dir, name).unwrap();
            match kept {
                Some(target) => {
                    assert!(target.exists(), "{name}");
                    assert!(!landing.exists());
                }
                None => assert!(!dir.join(name).exists()),
            }
        }
        let _ = fs::remove_dir_all(&dir);
    }

    fn shape_error() -> anyhow::Error {
        FfiError::InvalidBlob {
            detail: "malformed listing".into(),
        }
        .into()
    }

    fn transport_error() -> anyhow::Error {
        FfiError::Network {
            detail: "down".into(),
        }
        .into()
    }

    /// The plan of a rescue without a directory. The plan does not depend on
    /// the phrase; any valid one will do (the KAT phrase has no checksum).
    fn planner_without_directory() -> Arc<RescuePlanner> {
        let phrase = uniffi_frappuccino::bip39_generate_fr();
        ReportRescue::from_mnemonic(&phrase, b"")
            .unwrap()
            .planner(None)
            .unwrap()
    }

    #[test]
    fn a_shape_error_goes_on_and_a_transport_error_stops() {
        assert_eq!(probe_failure(&shape_error()), ProbeFailure::Unreadable);
        assert_eq!(probe_failure(&transport_error()), ProbeFailure::Stop);
        let io: anyhow::Error = FfiError::Io { detail: "x".into() }.into();
        assert_eq!(probe_failure(&io), ProbeFailure::Stop);
        let limited: anyhow::Error = FfiError::RateLimited {
            retry_after_secs: 60,
        }
        .into();
        assert_eq!(probe_failure(&limited), ProbeFailure::Stop);

        // An unreadable listing at chained index 2: shown, and the probe goes
        // on past it to find the report at index 3, then stops on the network.
        let planner = planner_without_directory();
        let mut probed = Vec::new();
        let enumeration = enumerate(&planner, |target| {
            probed.push(target);
            match (target.scheme, target.index) {
                (ReportScheme::Chain, 2) => Err(shape_error()),
                (ReportScheme::Chain, 3) => Ok(Some(3u32)),
                (_, 5) => Err(transport_error()),
                _ => Ok(None),
            }
        });
        assert_eq!(enumeration.found, [3]);
        assert_eq!(enumeration.unreadable.len(), 1);
        assert_eq!(enumeration.unreadable[0].0.index, 2);
        assert!(enumeration.incomplete.is_some());
        assert_eq!(probed.last().unwrap().index, 5);
    }

    #[test]
    fn an_unreadable_listing_does_not_end_the_tail_early() {
        // Nothing anywhere but an unreadable listing at index 0: it counts as
        // occupied, so the empty run starts after it, and the enumeration
        // completes.
        let planner = planner_without_directory();
        let mut last = 0;
        let enumeration = enumerate(&planner, |target| {
            last = target.index;
            if target.index == 0 && target.scheme == ReportScheme::Legacy {
                Err(shape_error())
            } else {
                Ok(None::<u32>)
            }
        });
        assert!(enumeration.found.is_empty());
        assert_eq!(enumeration.unreadable.len(), 1);
        assert!(enumeration.incomplete.is_none());
        let complete_tail = {
            let planner = planner_without_directory();
            let mut last = 0;
            let _ = enumerate(&planner, |target| {
                last = target.index;
                Ok(None::<u32>)
            });
            last
        };
        assert_eq!(last, complete_tail + 1);
    }

    #[test]
    fn the_probe_cap_makes_the_enumeration_incomplete() {
        // A relay that answers every probe: the cap ends it, and says so.
        let planner = planner_without_directory();
        let enumeration = enumerate(&planner, |_| Ok(Some(())));
        assert!(enumeration.found.len() > 4096);
        assert!(enumeration
            .incomplete
            .as_deref()
            .is_some_and(|reason| reason.contains("probe cap")));
    }

    #[test]
    fn a_failed_report_is_reported_and_the_others_still_print() {
        let failed = Rescued {
            report_id: "ab".repeat(16),
            scheme: ReportScheme::Chain,
            index: Some(4),
            outcome: Err("fetch the timestamp proof: down".into()),
        };
        let fine = Rescued {
            report_id: "cd".repeat(16),
            scheme: ReportScheme::Chain,
            index: Some(5),
            outcome: Ok(Checked {
                verdict: verdict(&["000000.strm"]),
                ots: Some(OtsOutcome::Absent),
            }),
        };
        let mut text = Vec::new();
        for r in [&failed, &fine] {
            print_verdict(&mut text, r).unwrap();
        }
        let text = String::from_utf8(text).unwrap();
        assert!(text.contains("NOT CHECKED TO THE END: fetch the timestamp proof: down"));
        assert!(text.contains("COMPLETE"));
        let json = verdict_json(&failed, Path::new("out"));
        assert_eq!(json["error"], "fetch the timestamp proof: down");
        assert_eq!(json["index"], 4);
    }

    #[test]
    fn a_failed_report_does_not_stop_the_others() {
        let reports = [0u32, 1, 2];
        let mut checked = Vec::new();
        let rescued = rescue_each(
            &reports,
            |&i| (format!("{i:032}"), ReportScheme::Chain, Some(i)),
            |&i| {
                checked.push(i);
                if i == 1 {
                    bail!("network down")
                }
                Ok(Checked {
                    verdict: verdict(&[]),
                    ots: None,
                })
            },
        );
        assert_eq!(checked, [0, 1, 2]);
        assert_eq!(rescued.len(), 3);
        assert!(rescued[0].outcome.is_ok());
        assert_eq!(rescued[1].outcome.as_ref().err().unwrap(), "network down");
        assert!(rescued[2].outcome.is_ok());
    }

    #[test]
    fn a_signed_proof_that_does_not_decrypt_is_a_mismatch_not_a_stop() {
        let dir = scratch_dir("proof");
        let keys = keys();
        let outcome = judge_proof(b"not a STRM blob", &verdict(&[]), &dir, &keys).unwrap();
        assert!(matches!(outcome, OtsOutcome::Mismatch));
        assert!(!dir.join("timestamp.ots").exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_verified_object_that_does_not_decrypt_is_a_mismatch_not_a_stop() {
        let dir = scratch_dir("undecryptable");
        let keys = keys();
        seal(
            &dir,
            "000000.strm",
            br#"{"version":1,"sessionId":"abc123"}"#,
            &keys,
        );
        fs::write(dir.join("000001.strm"), b"not a STRM blob").unwrap();
        assert!(
            recompute_commitment(&verdict(&["000000.strm", "000001.strm"]), &dir, &keys)
                .unwrap()
                .is_none()
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn errors_other_than_a_rate_limit_are_returned_at_once() {
        // A 429 waits at least a minute, too long for a unit test; what is
        // checked here is that nothing else is retried.
        let mut calls = 0;
        let result: Result<()> = with_backoff(|| {
            calls += 1;
            Err(FfiError::Network {
                detail: "down".into(),
            })
        });
        assert!(result.is_err());
        assert_eq!(calls, 1);
        let ok: Result<u32> = with_backoff(|| Ok(7));
        assert_eq!(ok.unwrap(), 7);
    }
}
