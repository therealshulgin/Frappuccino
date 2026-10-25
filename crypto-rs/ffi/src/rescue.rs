//! The rescue: from the phrase alone, find the reports the relay holds and
//! verify every stored object before anything is kept.
//!
//! The Android rescue (through the FFI) and `frappuccino-cli fetch-archive`
//! (as a Rust library) both run this module, so the two cannot drift: same
//! enumeration, same verification, same statuses.
//!
//! ## Enumeration ([`RescuePlanner`])
//!
//! The directory's listing names, by opaque name, the reports that were
//! opened. The names are matched back to indices by re-deriving them, in both
//! families (legacy and chained), together with the names of chained
//! timestamp proofs. Then every index up to the highest matched one is probed,
//! only in the families the directory names for it (both when it names none),
//! and probing goes on past it until a run of empty indices. The run is short
//! normally and long when the directory is absent or carries a closure: a
//! closed directory is an anomaly (someone holding the device state froze it),
//! and the reports opened after it have no entry.
//!
//! ## Verification ([`ReportCheck`])
//!
//! Every key is re-derived from the phrase; nothing the relay sends is taken
//! as a key or an id. For a chained report with a valid closure (signature
//! under the re-derived key, manifest whose hash is the recorded one), each
//! object listed in the manifest is `Verified` when its stored bytes hash to
//! the manifest's value, `Foreign` otherwise, `Missing` when absent; any other
//! object is `Unexpected`, or `UnexpectedSigned` if it carries a valid write
//! signature (a second signer). Without a valid closure, an object is
//! `Verified` only by its stored write signature. A legacy or directory object
//! without a stored signature is `Unverifiable`: it is kept apart, never part
//! of the verified testimony. Whatever does not verify is deleted from disk as
//! soon as it is classified, and counted.

use std::collections::{BTreeMap, HashSet, VecDeque};
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use frappuccino_crypto_core::bip39::{self, Language};
use frappuccino_crypto_core::report::{
    self as core_report, chain_object_name, parse_chain_object_name, Manifest, RescueReport,
};
use frappuccino_crypto_stream::{
    is_relay_object_name, ArchiveObject, StreamServerClient as CoreClient, WriteSigHeader,
};
use sha2::{Digest, Sha256};

use crate::{lock_poisoned, ArchiveBlobInfo, FfiError, StreamServerClient};

/// Name under which the relay stores a closure's manifest.
const MANIFEST_NAME: &str = "manifest";
/// Empty indices probed past the highest one the directory names.
const TAIL_NORMAL: u32 = 16;
/// The same, when the directory is absent or closed.
const TAIL_SUSPECT: u32 = 128;
/// Indices probed at most past the highest one the directory names (or from 0
/// without a directory): a relay answering every probe cannot keep the
/// enumeration going for ever. The highest named index is itself bounded by
/// the number of names listed (see [`match_directory_names`]). Reaching this
/// cap before an empty tail is reported ([`RescuePlanner::hit_probe_cap`]).
const PROBE_SPAN_CAP: u32 = 4096;
/// Indices derived at most to match directory names, beyond the number of
/// names: a junk name matches nothing and would otherwise drive the derivation
/// to its absolute cap.
const DERIVE_SLACK: usize = 512;
/// Absolute cap on the indices derived to match directory names.
const DERIVE_MATCH_CAP: u32 = 100_000;

// ============================================================================
// FFI records and enums
// ============================================================================

/// Which derivation produced a report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportScheme {
    /// Legacy per-index key (devices enrolled before the chained scheme).
    Legacy,
    /// Chained key.
    Chain,
    /// The directory.
    Directory,
}

impl From<core_report::ReportScheme> for ReportScheme {
    fn from(scheme: core_report::ReportScheme) -> Self {
        match scheme {
            core_report::ReportScheme::Legacy => Self::Legacy,
            core_report::ReportScheme::Chain => Self::Chain,
            core_report::ReportScheme::Directory => Self::Directory,
        }
    }
}

/// A report to probe: its scheme and index. The keys and the id are always
/// re-derived from these by Rust. `index` is ignored for the directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RescueTarget {
    pub scheme: ReportScheme,
    pub index: u32,
}

/// A closure as the relay recorded it (unverified).
#[derive(Debug, Clone)]
pub struct ArchiveClosureInfo {
    pub seq_limit: u32,
    pub manifest_sha256: Vec<u8>,
    pub sig: Vec<u8>,
}

/// A report's listing as the relay returned it (unverified).
#[derive(Debug, Clone)]
pub struct ArchiveListing {
    pub blobs: Vec<ArchiveBlobInfo>,
    pub closure: Option<ArchiveClosureInfo>,
}

impl From<frappuccino_crypto_stream::ArchiveListing> for ArchiveListing {
    fn from(listing: frappuccino_crypto_stream::ArchiveListing) -> Self {
        Self {
            blobs: listing
                .blobs
                .into_iter()
                .map(ArchiveBlobInfo::from)
                .collect(),
            closure: listing.closure.map(|c| ArchiveClosureInfo {
                seq_limit: c.seq_limit(),
                manifest_sha256: c.manifest_sha256().to_vec(),
                sig: c.sig().to_vec(),
            }),
        }
    }
}

/// Whether a fetched object was stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveFetchStatus {
    Stored,
    NotFound,
}

/// The write-signature header of a fetched object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteSigState {
    /// No header (an object stored before the relay kept signatures).
    Absent,
    /// One well-formed signature.
    Present,
    /// A header that is not one signature; treated as an invalid signature.
    Malformed,
}

/// Result of `StreamServerClient.archive_fetch_object`.
#[derive(Debug, Clone)]
pub struct ArchiveObjectResult {
    pub status: ArchiveFetchStatus,
    /// Bytes written (0 when not found).
    pub size: u64,
    /// SHA-256 of the bytes written, `None` when not found.
    pub blob_sha256: Option<Vec<u8>>,
    pub write_sig_state: WriteSigState,
    /// The signature when `write_sig_state` is `Present`.
    pub write_sig: Option<Vec<u8>>,
}

impl From<ArchiveObject> for ArchiveObjectResult {
    fn from(object: ArchiveObject) -> Self {
        match object {
            ArchiveObject::NotFound => Self {
                status: ArchiveFetchStatus::NotFound,
                size: 0,
                blob_sha256: None,
                write_sig_state: WriteSigState::Absent,
                write_sig: None,
            },
            ArchiveObject::Stored(stored) => {
                let (write_sig_state, write_sig) = match stored.write_sig() {
                    WriteSigHeader::Absent => (WriteSigState::Absent, None),
                    WriteSigHeader::Present(sig) => (WriteSigState::Present, Some(sig.to_vec())),
                    WriteSigHeader::Malformed => (WriteSigState::Malformed, None),
                };
                Self {
                    status: ArchiveFetchStatus::Stored,
                    size: stored.size(),
                    blob_sha256: Some(stored.blob_sha256().to_vec()),
                    write_sig_state,
                    write_sig,
                }
            }
        }
    }
}

/// The verdict on one stored object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectStatus {
    /// Authentic: kept, part of the verified testimony.
    Verified,
    /// Listed by the valid closure, but with other bytes. Excluded.
    Foreign,
    /// Listed by the valid closure (or by the relay's listing) but not stored.
    Missing,
    /// Outside the valid closure, without a valid signature. Excluded.
    Unexpected,
    /// Outside the valid closure, yet validly signed: a second signer.
    /// Excluded, and the report is ALTERED.
    UnexpectedSigned,
    /// A legacy or directory object stored without a signature: kept apart,
    /// never part of the verified testimony.
    Unverifiable,
    /// No valid signature where one is required, or a malformed one. Excluded.
    Invalid,
}

impl ObjectStatus {
    /// Whether the fetched file is kept on disk.
    #[must_use]
    pub fn is_kept(self) -> bool {
        matches!(self, Self::Verified | Self::Unverifiable)
    }
}

/// What became of the report's recorded closure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClosureState {
    /// The relay recorded none.
    Absent,
    /// Recorded, not checked yet ([`ReportCheck::verify_closure`]).
    Unchecked,
    /// Signed under the re-derived key, over the manifest stored with it, and
    /// of the shape the scheme allows.
    Valid,
    /// Present but not valid.
    Invalid,
}

/// The status of a whole report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportStatus {
    /// Chained, validly closed, every listed object verified, nothing
    /// foreign, missing or signed outside the closure.
    Complete,
    /// Chained, validly closed, with objects missing (or not fetched) and
    /// nothing altered.
    Incomplete,
    /// Chained, validly closed, with at least one foreign object or a validly
    /// signed object outside the closure.
    Altered,
    /// Chained, without a valid closure: the recording never closed (or the
    /// closure was lost). Objects verify one by one; the end is not certified.
    Interrupted,
    /// A legacy report.
    Legacy,
    /// The directory.
    Directory,
}

/// Everything shown for one report.
#[derive(Debug, Clone)]
pub struct ReportVerdict {
    pub scheme: ReportScheme,
    pub index: Option<u32>,
    pub status: ReportStatus,
    pub closure: ClosureState,
    /// An invalid closure, or any closure of the directory.
    pub closure_anomaly: bool,
    pub verified: u32,
    pub foreign: u32,
    pub missing: u32,
    pub unexpected: u32,
    pub unexpected_signed: u32,
    pub unverifiable: u32,
    pub invalid: u32,
    /// Listed objects not fetched yet.
    pub unchecked: u32,
    /// Verified objects, in reading order (increasing seq).
    pub verified_names: Vec<String>,
    /// Kept-apart objects (legacy without a signature), in name order.
    pub unverifiable_names: Vec<String>,
    /// With a valid closure, the sequence numbers it lists that the relay does
    /// not store. Without one, those of listed objects the relay did not
    /// serve.
    pub missing_seqs: Vec<u32>,
    /// Earliest and latest `last_modified` of the listing, as the relay wrote
    /// them: the date range shown to help spot reports posterior to a loss.
    pub first_modified: Option<String>,
    pub last_modified: Option<String>,
}

// ============================================================================
// ReportRescue
// ============================================================================

/// FFI object: everything the rescue derives from the phrase.
pub struct ReportRescue {
    inner: Mutex<core_report::ReportRescue>,
}

impl std::fmt::Debug for ReportRescue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ReportRescue(<redacted>)")
    }
}

impl ReportRescue {
    /// Derive the rescue material. The phrase is checked (words and
    /// checksum) first, so a mistyped phrase fails loudly instead of finding
    /// nothing.
    ///
    /// # Errors
    /// [`FfiError::InvalidMnemonic`] for bytes that are not UTF-8 or a phrase
    /// that does not validate; derivation errors.
    pub fn from_mnemonic(mnemonic: &[u8], passphrase: &[u8]) -> Result<Self, FfiError> {
        let mnemonic = std::str::from_utf8(mnemonic).map_err(|e| FfiError::InvalidMnemonic {
            detail: format!("mnemonic bytes are not valid UTF-8: {e}"),
        })?;
        let passphrase =
            std::str::from_utf8(passphrase).map_err(|e| FfiError::InvalidMnemonic {
                detail: format!("passphrase bytes are not valid UTF-8: {e}"),
            })?;
        bip39::validate(mnemonic, Language::French)?;
        Ok(Self {
            inner: Mutex::new(core_report::ReportRescue::from_mnemonic(
                mnemonic, passphrase,
            )?),
        })
    }

    fn lock(&self) -> Result<MutexGuard<'_, core_report::ReportRescue>, FfiError> {
        self.inner.lock().map_err(|_| lock_poisoned())
    }

    /// The re-derived public description of `target`.
    fn derive(&self, target: RescueTarget) -> Result<RescueReport, FfiError> {
        let mut rescue = self.lock()?;
        Ok(match target.scheme {
            ReportScheme::Directory => rescue.directory().clone(),
            ReportScheme::Legacy => rescue.legacy(target.index)?,
            ReportScheme::Chain => rescue.chain(target.index)?,
        })
    }

    /// List the directory. `None` if the relay has no directory for this
    /// phrase.
    ///
    /// # Errors
    /// As [`StreamServerClient::archive_list`].
    #[allow(clippy::needless_pass_by_value)] // UniFFI hands interface arguments over as owned Arcs.
    pub fn open_directory(
        &self,
        client: Arc<StreamServerClient>,
    ) -> Result<Option<Arc<ReportCheck>>, FfiError> {
        self.open_report(
            client,
            RescueTarget {
                scheme: ReportScheme::Directory,
                index: 0,
            },
        )
    }

    /// List the report `target` re-derives. `None` on 404 (no such report):
    /// for the planner, `found = result != null`.
    ///
    /// # Errors
    /// [`FfiError::RateLimited`] on 429 (wait, then probe the same target
    /// again); [`FfiError::Network`] otherwise; derivation errors.
    #[allow(clippy::needless_pass_by_value)] // UniFFI hands interface arguments over as owned Arcs.
    pub fn open_report(
        &self,
        client: Arc<StreamServerClient>,
        target: RescueTarget,
    ) -> Result<Option<Arc<ReportCheck>>, FfiError> {
        let report = self.derive(target)?;
        // Cloning the stream client shares its connection pool (`Arc`
        // inside); the check keeps one to fetch objects later.
        let core_client = client.inner.clone();
        let Some(listing) = core_client.archive_list(&report.report_id_hex())? else {
            return Ok(None);
        };
        Ok(Some(Arc::new(ReportCheck::new(
            report,
            listing,
            core_client,
        ))))
    }

    /// The enumeration plan, from the directory's check (or `None` if the
    /// directory is absent).
    ///
    /// # Errors
    /// Derivation errors.
    #[allow(clippy::needless_pass_by_value)] // UniFFI hands interface arguments over as owned Arcs.
    pub fn planner(
        &self,
        directory: Option<Arc<ReportCheck>>,
    ) -> Result<Arc<RescuePlanner>, FfiError> {
        let (names, suspect) = match &directory {
            Some(check) => (check.listed_names(), check.has_closure()),
            None => (Vec::new(), true),
        };
        let matched = {
            let mut rescue = self.lock()?;
            match_directory_names(&mut rescue, &names)?
        };
        Ok(Arc::new(RescuePlanner {
            inner: Mutex::new(Plan::new(matched, suspect)),
        }))
    }
}

// ============================================================================
// Directory matching
// ============================================================================

/// Which families the directory names for an index.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Families {
    legacy: bool,
    chain: bool,
}

const BOTH: Families = Families {
    legacy: true,
    chain: true,
};

/// The directory's names, matched back to indices.
#[derive(Debug, Default)]
pub(crate) struct DirectoryMatch {
    named: BTreeMap<u32, Families>,
    unmatched: usize,
}

/// A directory entry written before entry names were opaque: the index in
/// ten decimal digits, if it is within `bound`.
fn decimal_entry_index(name: &str, bound: u32) -> Option<u32> {
    if name.len() != 10 || !name.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    name.parse().ok().filter(|&index| index <= bound)
}

/// Match the directory's object names to the indices that produce them, by
/// re-deriving names until every name is accounted for or the bound is hit.
///
/// A decimal name needs no derivation, so anyone able to list a name (the
/// relay, or whoever holds the directory key) can write one: it adds its
/// index to the plan with BOTH families and takes none away, and only within
/// the same bound as the derivation, so the highest named index stays bounded
/// by the number of names listed. A decimal name beyond the bound matches
/// nothing.
pub(crate) fn match_directory_names(
    rescue: &mut core_report::ReportRescue,
    names: &[String],
) -> Result<DirectoryMatch, FfiError> {
    let bound = u32::try_from(names.len().saturating_add(DERIVE_SLACK))
        .unwrap_or(u32::MAX)
        .min(DERIVE_MATCH_CAP);
    let mut matched = DirectoryMatch::default();
    let mut pending: HashSet<&str> = HashSet::new();
    for name in names {
        match decimal_entry_index(name, bound) {
            Some(index) => {
                matched.named.insert(index, BOTH);
            }
            None => {
                pending.insert(name.as_str());
            }
        }
    }
    let mut index = 0u32;
    while !pending.is_empty() && index <= bound {
        let legacy = rescue.legacy(index)?;
        if legacy
            .directory_entry_name()
            .is_some_and(|name| pending.remove(name))
        {
            matched.named.entry(index).or_default().legacy = true;
        }
        let chain = rescue.chain(index)?;
        for name in [chain.directory_entry_name(), chain.ots_name()]
            .into_iter()
            .flatten()
        {
            if pending.remove(name) {
                matched.named.entry(index).or_default().chain = true;
            }
        }
        index += 1;
    }
    matched.unmatched = pending.len();
    Ok(matched)
}

// ============================================================================
// RescuePlanner
// ============================================================================

/// FFI object: the enumeration, one target at a time. Call `next()`, probe
/// the target (`ReportRescue.open_report`), report the outcome with
/// `record(found)`, repeat until `next()` returns `None`. A 429 is not an
/// outcome: wait and probe the same target again before recording.
pub struct RescuePlanner {
    inner: Mutex<Plan>,
}

impl std::fmt::Debug for RescuePlanner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RescuePlanner(<redacted>)")
    }
}

impl RescuePlanner {
    fn lock(&self) -> MutexGuard<'_, Plan> {
        // Plain bookkeeping, nothing secret: recover from a poisoned lock.
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The next target to probe, or `None` when the enumeration is over.
    pub fn next(&self) -> Option<RescueTarget> {
        self.lock().next_target()
    }

    /// The outcome of probing the target `next()` returned last.
    pub fn record(&self, found: bool) {
        self.lock().record(found);
    }

    /// Directory names that matched no index: relay junk, or a report beyond
    /// the derivation bound. Shown as an anomaly.
    #[must_use]
    pub fn unmatched_entries(&self) -> u32 {
        u32::try_from(self.lock().unmatched).unwrap_or(u32::MAX)
    }

    /// Whether the enumeration probes the long tail (directory absent or
    /// closed).
    #[must_use]
    pub fn probes_long_tail(&self) -> bool {
        self.lock().tail == TAIL_SUSPECT
    }

    /// Whether the enumeration ended on the probe cap rather than on a run of
    /// empty indices: reports past the cap were not looked for, so the result
    /// must be shown as incomplete. Meaningful once `next()` returned `None`.
    #[must_use]
    pub fn hit_probe_cap(&self) -> bool {
        self.lock().capped
    }
}

/// The planner's state.
#[derive(Debug)]
pub(crate) struct Plan {
    named: BTreeMap<u32, Families>,
    max_named: Option<u32>,
    unmatched: usize,
    tail: u32,
    last_index: u32,
    cursor: Option<u32>,
    queue: VecDeque<RescueTarget>,
    /// The index being probed, and whether anything was found at it.
    current: Option<(u32, bool)>,
    empty_run: u32,
    /// The enumeration stopped at `last_index` with the tail not exhausted.
    capped: bool,
}

impl Plan {
    pub(crate) fn new(matched: DirectoryMatch, suspect: bool) -> Self {
        let max_named = matched.named.keys().next_back().copied();
        Self {
            last_index: max_named.unwrap_or(0).saturating_add(PROBE_SPAN_CAP),
            max_named,
            named: matched.named,
            unmatched: matched.unmatched,
            tail: if suspect { TAIL_SUSPECT } else { TAIL_NORMAL },
            cursor: Some(0),
            queue: VecDeque::new(),
            current: None,
            empty_run: 0,
            capped: false,
        }
    }

    fn within_named(&self, index: u32) -> bool {
        self.max_named.is_some_and(|max| index <= max)
    }

    pub(crate) fn next_target(&mut self) -> Option<RescueTarget> {
        if let Some(target) = self.queue.pop_front() {
            return Some(target);
        }
        if let Some((index, found)) = self.current.take() {
            if found || self.within_named(index) {
                self.empty_run = 0;
            } else {
                self.empty_run += 1;
            }
        }
        let index = self.cursor?;
        let tail_left = self.within_named(index) || self.empty_run < self.tail;
        if index > self.last_index || !tail_left {
            self.capped = index > self.last_index && tail_left;
            self.cursor = None;
            return None;
        }
        self.cursor = index.checked_add(1);
        let families = self.named.get(&index).copied().unwrap_or(BOTH);
        if families.legacy {
            self.queue.push_back(RescueTarget {
                scheme: ReportScheme::Legacy,
                index,
            });
        }
        if families.chain {
            self.queue.push_back(RescueTarget {
                scheme: ReportScheme::Chain,
                index,
            });
        }
        self.current = Some((index, false));
        self.queue.pop_front()
    }

    pub(crate) fn record(&mut self, found: bool) {
        if let Some((_, any)) = &mut self.current {
            *any |= found;
        }
    }
}

// ============================================================================
// ReportCheck
// ============================================================================

/// A closure as recorded, in fixed-size form.
#[derive(Debug, Clone)]
pub(crate) struct ClosureRecord {
    seq_limit: u32,
    manifest_sha256: [u8; 32],
    sig: [u8; 64],
}

/// The closure's verification so far.
#[derive(Debug, Clone)]
enum ClosureCheck {
    Absent,
    Unchecked,
    Valid(Manifest),
    Invalid,
}

impl ClosureCheck {
    fn state(&self) -> ClosureState {
        match self {
            Self::Absent => ClosureState::Absent,
            Self::Unchecked => ClosureState::Unchecked,
            Self::Valid(_) => ClosureState::Valid,
            Self::Invalid => ClosureState::Invalid,
        }
    }
}

/// What a fetch measured: the stored bytes' hash and the signature header.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Fetched {
    pub(crate) blob_sha256: [u8; 32],
    pub(crate) write_sig: WriteSigHeader,
}

/// The verification of one report, without the network: what is listed, the
/// closure, and the status of each object fetched so far.
#[derive(Debug)]
pub(crate) struct Evidence {
    report: RescueReport,
    /// Listed objects (`manifest` excluded) that are relay object names, with
    /// their `last_modified`.
    listed: BTreeMap<String, Option<String>>,
    /// Listed names that are not relay object names: junk, never fetched.
    junk: u32,
    first_modified: Option<String>,
    last_modified: Option<String>,
    closure: Option<ClosureRecord>,
    closure_check: ClosureCheck,
    objects: BTreeMap<String, ObjectStatus>,
}

impl Evidence {
    pub(crate) fn new(
        report: RescueReport,
        blobs: &[frappuccino_crypto_stream::ArchiveBlobInfo],
        closure: Option<ClosureRecord>,
    ) -> Self {
        let mut listed = BTreeMap::new();
        let mut junk = 0u32;
        for blob in blobs.iter().filter(|b| b.filename != MANIFEST_NAME) {
            if is_relay_object_name(&blob.filename) {
                listed.insert(blob.filename.clone(), blob.last_modified.clone());
            } else {
                junk = junk.saturating_add(1);
            }
        }
        let dates = blobs.iter().filter_map(|b| b.last_modified.as_deref());
        let first_modified = dates.clone().min().map(str::to_owned);
        let last_modified = dates.max().map(str::to_owned);
        Self {
            report,
            listed,
            junk,
            first_modified,
            last_modified,
            closure_check: if closure.is_some() {
                ClosureCheck::Unchecked
            } else {
                ClosureCheck::Absent
            },
            closure,
            objects: BTreeMap::new(),
        }
    }

    /// Check the recorded closure against `manifest` (the stored manifest's
    /// bytes, `None` when the relay has none).
    ///
    /// The first decision is final: once the closure is `Valid` or `Invalid`,
    /// a later call returns that state and checks nothing, because the objects
    /// classified since then were classified against it, and a second
    /// manifest (another answer of the relay) must not requalify them. Only an
    /// unchecked closure (after a rate limit or an I/O error) is checked
    /// again; an absent one stays absent.
    pub(crate) fn check_closure(&mut self, manifest: Option<&[u8]>) -> ClosureState {
        if let Some(decided) = self.decided_closure() {
            return decided;
        }
        self.closure_check = match (&self.closure, manifest) {
            (None, _) => ClosureCheck::Absent,
            (Some(_), None) => ClosureCheck::Invalid,
            (Some(closure), Some(bytes)) => {
                let digest: [u8; 32] = Sha256::digest(bytes).into();
                if digest == closure.manifest_sha256 {
                    self.report
                        .verify_close(closure.seq_limit, bytes, &closure.sig)
                        .map_or(ClosureCheck::Invalid, ClosureCheck::Valid)
                } else {
                    ClosureCheck::Invalid
                }
            }
        };
        self.closure_check.state()
    }

    /// The closure's state once [`Self::check_closure`] decided it (`Valid`
    /// or `Invalid`), `None` before.
    fn decided_closure(&self) -> Option<ClosureState> {
        matches!(
            self.closure_check,
            ClosureCheck::Valid(_) | ClosureCheck::Invalid
        )
        .then(|| self.closure_check.state())
    }

    /// Refuse a fetch the verdict could not use.
    fn check_fetchable(&self, name: &str) -> Result<(), FfiError> {
        if !self.listed.contains_key(name) {
            return Err(FfiError::ReportRefused {
                detail: "not an object of this report's listing".into(),
            });
        }
        if self.report.scheme() == core_report::ReportScheme::Chain
            && matches!(self.closure_check, ClosureCheck::Unchecked)
        {
            return Err(FfiError::ReportRefused {
                detail: "verify the report's closure before its objects".into(),
            });
        }
        Ok(())
    }

    /// Classify a fetched object (`None` when the relay no longer has it)
    /// and record the status.
    pub(crate) fn check_object(&mut self, name: &str, fetched: Option<&Fetched>) -> ObjectStatus {
        let status = fetched.map_or(ObjectStatus::Missing, |fetched| {
            classify(&self.report, &self.closure_check, name, fetched)
        });
        self.objects.insert(name.to_owned(), status);
        status
    }

    /// The verdict from what has been checked so far.
    pub(crate) fn verdict(&self) -> ReportVerdict {
        let manifest = self.chained_manifest();
        let mut tally = match manifest {
            Some(manifest) => self.tally_closed(manifest),
            None => self.tally_by_listing(),
        };
        tally.unexpected = tally.unexpected.saturating_add(self.junk);
        tally.verified_names.sort();
        tally.unverifiable_names.sort();
        let closure = self.closure_check.state();
        let scheme = self.report.scheme();
        let status = report_status(scheme, manifest.is_some(), &tally);
        let closure_anomaly = closure == ClosureState::Invalid
            || (scheme == core_report::ReportScheme::Directory && self.closure.is_some());
        ReportVerdict {
            scheme: scheme.into(),
            index: self.report.index(),
            status,
            closure,
            closure_anomaly,
            verified: tally.verified,
            foreign: tally.foreign,
            missing: tally.missing,
            unexpected: tally.unexpected,
            unexpected_signed: tally.unexpected_signed,
            unverifiable: tally.unverifiable,
            invalid: tally.invalid,
            unchecked: tally.unchecked,
            verified_names: tally.verified_names,
            unverifiable_names: tally.unverifiable_names,
            missing_seqs: tally.missing_seqs,
            first_modified: self.first_modified.clone(),
            last_modified: self.last_modified.clone(),
        }
    }

    /// The valid closure's manifest, for a chained report only: a legacy
    /// closure is empty by construction and certifies no object set.
    fn chained_manifest(&self) -> Option<&Manifest> {
        match &self.closure_check {
            ClosureCheck::Valid(manifest)
                if self.report.scheme() == core_report::ReportScheme::Chain =>
            {
                Some(manifest)
            }
            _ => None,
        }
    }

    /// Counters against a valid closure: every manifest entry is verified,
    /// foreign, missing or not fetched yet; every other object is unexpected.
    fn tally_closed(&self, manifest: &Manifest) -> Tally {
        let mut tally = Tally::default();
        for entry in manifest.entries() {
            // Every seq of a valid manifest is in range.
            let Ok(name) = chain_object_name(entry.seq) else {
                continue;
            };
            match self.objects.get(&name) {
                Some(status) => tally.add(*status, &name),
                None if self.listed.contains_key(&name) => tally.unchecked += 1,
                None => tally.missing_seq(entry.seq),
            }
        }
        let in_manifest = |name: &str| {
            parse_chain_object_name(name).is_some_and(|seq| manifest.blob_sha256(seq).is_some())
        };
        for name in self.listed.keys().filter(|name| !in_manifest(name)) {
            match self.objects.get(name) {
                // Listed outside the closure, then not served: still an object
                // outside the closure, never one the closure misses.
                Some(ObjectStatus::Missing) => tally.unexpected += 1,
                Some(status) => tally.add(*status, name),
                None => tally.unchecked += 1,
            }
        }
        tally
    }

    /// Counters without a certified object set: each listed object on its own.
    fn tally_by_listing(&self) -> Tally {
        let mut tally = Tally::default();
        for name in self.listed.keys() {
            match self.objects.get(name) {
                Some(status) => tally.add(*status, name),
                None => tally.unchecked += 1,
            }
        }
        tally
    }
}

/// The status of a report from its scheme, whether a valid closure certifies
/// its object set, and its counters.
fn report_status(
    scheme: core_report::ReportScheme,
    certified: bool,
    tally: &Tally,
) -> ReportStatus {
    match scheme {
        core_report::ReportScheme::Legacy => ReportStatus::Legacy,
        core_report::ReportScheme::Directory => ReportStatus::Directory,
        core_report::ReportScheme::Chain if !certified => ReportStatus::Interrupted,
        core_report::ReportScheme::Chain if tally.foreign > 0 || tally.unexpected_signed > 0 => {
            ReportStatus::Altered
        }
        core_report::ReportScheme::Chain if tally.missing > 0 || tally.unchecked > 0 => {
            ReportStatus::Incomplete
        }
        core_report::ReportScheme::Chain => ReportStatus::Complete,
    }
}

/// Counters of a verdict.
#[derive(Debug, Default)]
struct Tally {
    verified: u32,
    foreign: u32,
    missing: u32,
    unexpected: u32,
    unexpected_signed: u32,
    unverifiable: u32,
    invalid: u32,
    unchecked: u32,
    verified_names: Vec<String>,
    unverifiable_names: Vec<String>,
    missing_seqs: Vec<u32>,
}

impl Tally {
    fn add(&mut self, status: ObjectStatus, name: &str) {
        match status {
            ObjectStatus::Verified => {
                self.verified += 1;
                self.verified_names.push(name.to_owned());
            }
            ObjectStatus::Foreign => self.foreign += 1,
            ObjectStatus::Missing => {
                self.missing += 1;
                if let Some(seq) = parse_chain_object_name(name) {
                    self.missing_seqs.push(seq);
                }
            }
            ObjectStatus::Unexpected => self.unexpected += 1,
            ObjectStatus::UnexpectedSigned => self.unexpected_signed += 1,
            ObjectStatus::Unverifiable => {
                self.unverifiable += 1;
                self.unverifiable_names.push(name.to_owned());
            }
            ObjectStatus::Invalid => self.invalid += 1,
        }
    }

    fn missing_seq(&mut self, seq: u32) {
        self.missing += 1;
        self.missing_seqs.push(seq);
    }
}

/// The status of one fetched object. See the module documentation.
fn classify(
    report: &RescueReport,
    closure: &ClosureCheck,
    name: &str,
    fetched: &Fetched,
) -> ObjectStatus {
    let signed = match &fetched.write_sig {
        WriteSigHeader::Present(sig) => report
            .verify_write(name.as_bytes(), &fetched.blob_sha256, sig)
            .is_ok(),
        WriteSigHeader::Absent | WriteSigHeader::Malformed => false,
    };
    match (report.scheme(), closure) {
        (core_report::ReportScheme::Chain, ClosureCheck::Valid(manifest)) => {
            match parse_chain_object_name(name).and_then(|seq| manifest.blob_sha256(seq)) {
                Some(expected) if *expected == fetched.blob_sha256 => ObjectStatus::Verified,
                Some(_) => ObjectStatus::Foreign,
                None if signed => ObjectStatus::UnexpectedSigned,
                None => ObjectStatus::Unexpected,
            }
        }
        (core_report::ReportScheme::Chain, _) if signed => ObjectStatus::Verified,
        (core_report::ReportScheme::Chain, _) => ObjectStatus::Invalid,
        (_, _) => match fetched.write_sig {
            WriteSigHeader::Absent => ObjectStatus::Unverifiable,
            _ if signed => ObjectStatus::Verified,
            _ => ObjectStatus::Invalid,
        },
    }
}

/// FFI object: the verification of one listed report. Usage: if
/// `has_closure()`, call `verify_closure` first; then `fetch_object` for each
/// of `object_names()`; then `verdict()`.
pub struct ReportCheck {
    report_id_hex: String,
    client: CoreClient,
    evidence: Mutex<Evidence>,
}

impl std::fmt::Debug for ReportCheck {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ReportCheck(<redacted>)")
    }
}

impl ReportCheck {
    fn new(
        report: RescueReport,
        listing: frappuccino_crypto_stream::ArchiveListing,
        client: CoreClient,
    ) -> Self {
        let closure = listing.closure.map(|c| ClosureRecord {
            seq_limit: c.seq_limit(),
            manifest_sha256: *c.manifest_sha256(),
            sig: *c.sig(),
        });
        Self {
            report_id_hex: report.report_id_hex(),
            client,
            evidence: Mutex::new(Evidence::new(report, &listing.blobs, closure)),
        }
    }

    fn lock(&self) -> Result<MutexGuard<'_, Evidence>, FfiError> {
        self.evidence.lock().map_err(|_| lock_poisoned())
    }

    fn listed_names(&self) -> Vec<String> {
        self.lock()
            .map(|evidence| evidence.listed.keys().cloned().collect())
            .unwrap_or_default()
    }

    /// The scheme of the report.
    #[must_use]
    pub fn scheme(&self) -> ReportScheme {
        self.lock()
            .map_or(ReportScheme::Directory, |e| e.report.scheme().into())
    }

    /// Its index (`None` for the directory).
    #[must_use]
    pub fn index(&self) -> Option<u32> {
        self.lock().ok().and_then(|e| e.report.index())
    }

    /// Its `report_id`, 32 lowercase hex (re-derived, never read from the
    /// relay). Not a name for local files.
    #[must_use]
    pub fn report_id_hex(&self) -> String {
        self.report_id_hex.clone()
    }

    /// Name of the chained report's timestamp proof in the directory, `None`
    /// for other schemes.
    #[must_use]
    pub fn ots_name(&self) -> Option<String> {
        self.lock()
            .ok()
            .and_then(|e| e.report.ots_name().map(str::to_owned))
    }

    /// Names of the listed objects to fetch, in increasing name order (for a
    /// chained report, increasing seq). Excludes the manifest and any name
    /// the relay could not have stored.
    #[must_use]
    pub fn object_names(&self) -> Vec<String> {
        self.listed_names()
    }

    /// Whether the relay recorded a closure for this report.
    #[must_use]
    pub fn has_closure(&self) -> bool {
        self.lock().is_ok_and(|e| e.closure.is_some())
    }

    /// Fetch the closure's manifest to `scratch_path`, check it, and delete
    /// the file. Without a recorded closure nothing is fetched (`Absent`).
    /// Once the closure is decided (`Valid` or `Invalid`) the decision is
    /// final: a later call returns it without fetching anything.
    ///
    /// # Errors
    /// [`FfiError::RateLimited`] (call again after the wait), network and I/O
    /// errors. A missing or unreadable manifest is an `Invalid` closure, not
    /// an error.
    pub fn verify_closure(&self, scratch_path: &str) -> Result<ClosureState, FfiError> {
        if !self.has_closure() {
            return Ok(self.lock()?.check_closure(None));
        }
        if let Some(decided) = self.lock()?.decided_closure() {
            return Ok(decided);
        }
        let path = Path::new(scratch_path);
        let fetched = self
            .client
            .archive_fetch_object(&self.report_id_hex, MANIFEST_NAME, path)?;
        let manifest = match fetched {
            ArchiveObject::NotFound => None,
            ArchiveObject::Stored(_) => {
                let bytes = std::fs::read(path);
                let _ = std::fs::remove_file(path);
                Some(bytes.map_err(|e| FfiError::Io {
                    detail: format!("read fetched manifest: {e}"),
                })?)
            }
        };
        Ok(self.lock()?.check_closure(manifest.as_deref()))
    }

    /// Fetch object `name` (one of [`Self::object_names`]) to `out_path`,
    /// classify it, and delete the file unless it is kept
    /// ([`ObjectStatus::is_kept`]).
    ///
    /// # Errors
    /// [`FfiError::ReportRefused`] for a name not in the listing, or a chained
    /// report whose closure was not verified yet; [`FfiError::RateLimited`]
    /// (nothing recorded; call again after the wait); network and I/O errors.
    pub fn fetch_object(&self, name: &str, out_path: &str) -> Result<ObjectStatus, FfiError> {
        self.lock()?.check_fetchable(name)?;
        let path = Path::new(out_path);
        let fetched = match self
            .client
            .archive_fetch_object(&self.report_id_hex, name, path)?
        {
            ArchiveObject::NotFound => None,
            ArchiveObject::Stored(stored) => Some(Fetched {
                blob_sha256: *stored.blob_sha256(),
                write_sig: stored.write_sig(),
            }),
        };
        let status = self.lock()?.check_object(name, fetched.as_ref());
        if !status.is_kept() {
            let _ = std::fs::remove_file(path);
        }
        Ok(status)
    }

    /// The report's verdict, from what has been checked so far.
    ///
    /// # Errors
    /// [`FfiError::Internal`] on a poisoned lock.
    pub fn verdict(&self) -> Result<ReportVerdict, FfiError> {
        Ok(self.lock()?.verdict())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::MN_FIXED;
    use frappuccino_crypto_core::report::{ReportDeviceState, ReportKeyring};

    fn rescue() -> core_report::ReportRescue {
        core_report::ReportRescue::from_mnemonic(MN_FIXED, "").unwrap()
    }

    fn blob(name: &str, date: &str) -> frappuccino_crypto_stream::ArchiveBlobInfo {
        frappuccino_crypto_stream::ArchiveBlobInfo {
            filename: name.to_owned(),
            size: 1,
            last_modified: Some(date.to_owned()),
        }
    }

    /// A chained report 0 with objects 0, 1 and 3 sealed: the closure, the
    /// per-object write signatures, and the blob hashes.
    struct Closed {
        report: RescueReport,
        closure: ClosureRecord,
        manifest: Vec<u8>,
        sigs: BTreeMap<u32, [u8; 64]>,
    }

    fn blob_hash(seq: u32) -> [u8; 32] {
        let byte = u8::try_from(seq).unwrap();
        [byte.wrapping_add(0xB0); 32]
    }

    fn closed_report() -> Closed {
        let mut state = ReportDeviceState::from_mnemonic(MN_FIXED, "").unwrap();
        let mut writer = state
            .open_report()
            .unwrap()
            .release_after_persist(|_| Ok::<(), ()>(()))
            .unwrap();
        let mut sigs = BTreeMap::new();
        for seq in [0u32, 1, 3] {
            let prepared = if seq == 0 {
                writer.prepare_metadata(&[0; 32], &blob_hash(seq)).unwrap()
            } else {
                writer
                    .prepare_chunk(seq, &[0; 32], &blob_hash(seq))
                    .unwrap()
            };
            sigs.insert(seq, *prepared.write_sig());
            writer.commit(prepared).unwrap();
        }
        let close = writer.prepare_close().unwrap();
        Closed {
            report: rescue().chain(0).unwrap(),
            closure: ClosureRecord {
                seq_limit: close.seq_limit(),
                manifest_sha256: *close.manifest_sha256(),
                sig: *close.close_sig(),
            },
            manifest: close.manifest().to_vec(),
            sigs,
        }
    }

    fn signed(closed: &Closed, seq: u32) -> Fetched {
        Fetched {
            blob_sha256: blob_hash(seq),
            write_sig: WriteSigHeader::Present(closed.sigs[&seq]),
        }
    }

    fn unsigned(hash: [u8; 32]) -> Fetched {
        Fetched {
            blob_sha256: hash,
            write_sig: WriteSigHeader::Absent,
        }
    }

    #[test]
    fn a_complete_chained_report() {
        let c = closed_report();
        let blobs = [
            blob("manifest", "2026-10-02T00:00:00"),
            blob("000000.strm", "2026-10-01T10:00:00"),
            blob("000001.strm", "2026-10-01T10:00:05"),
            blob("000003.strm", "2026-10-01T10:00:15"),
        ];
        let mut e = Evidence::new(c.report.clone(), &blobs, Some(c.closure.clone()));
        assert!(e.check_fetchable("000001.strm").is_err(), "closure first");
        assert_eq!(e.check_closure(Some(&c.manifest)), ClosureState::Valid);
        // Verified by the manifest even without a stored signature.
        assert_eq!(
            e.check_object("000000.strm", Some(&unsigned(blob_hash(0)))),
            ObjectStatus::Verified
        );
        assert_eq!(
            e.check_object("000001.strm", Some(&signed(&c, 1))),
            ObjectStatus::Verified
        );
        let v = e.verdict();
        assert_eq!(v.status, ReportStatus::Incomplete, "000003 not fetched yet");
        assert_eq!(v.unchecked, 1);
        assert_eq!(
            e.check_object("000003.strm", Some(&signed(&c, 3))),
            ObjectStatus::Verified
        );
        let v = e.verdict();
        assert_eq!(v.status, ReportStatus::Complete);
        assert_eq!(v.closure, ClosureState::Valid);
        assert!(!v.closure_anomaly);
        assert_eq!(v.verified, 3);
        assert_eq!(
            v.verified_names,
            ["000000.strm", "000001.strm", "000003.strm"]
        );
        assert_eq!(v.first_modified.as_deref(), Some("2026-10-01T10:00:00"));
        assert_eq!(v.last_modified.as_deref(), Some("2026-10-02T00:00:00"));
        assert_eq!(v.index, Some(0));
        assert_eq!(v.scheme, ReportScheme::Chain);
    }

    #[test]
    fn foreign_missing_and_second_signers_are_told_apart() {
        let c = closed_report();
        // 000003 is not stored; 000002 is outside the closure.
        let blobs = [
            blob("000000.strm", "a"),
            blob("000001.strm", "b"),
            blob("000002.strm", "c"),
        ];
        let mut e = Evidence::new(c.report.clone(), &blobs, Some(c.closure.clone()));
        e.check_closure(Some(&c.manifest));
        e.check_object("000000.strm", Some(&signed(&c, 0)));
        assert_eq!(
            e.check_object("000001.strm", Some(&unsigned([0xEE; 32]))),
            ObjectStatus::Foreign
        );
        assert_eq!(
            e.check_object("000002.strm", Some(&unsigned([0x01; 32]))),
            ObjectStatus::Unexpected
        );
        let v = e.verdict();
        assert_eq!(v.status, ReportStatus::Altered);
        assert_eq!(
            (v.verified, v.foreign, v.missing, v.unexpected),
            (1, 1, 1, 1)
        );
        assert_eq!(v.missing_seqs, [3]);

        // Without the foreign object, a plain gap is INCOMPLETE.
        let mut e = Evidence::new(c.report.clone(), &blobs[..1], Some(c.closure.clone()));
        e.check_closure(Some(&c.manifest));
        e.check_object("000000.strm", Some(&signed(&c, 0)));
        let v = e.verdict();
        assert_eq!(v.status, ReportStatus::Incomplete);
        assert_eq!(v.missing_seqs, [1, 3]);

        // A validly signed object outside the closure: a second signer.
        let mut state = ReportDeviceState::from_mnemonic(MN_FIXED, "").unwrap();
        let mut writer = state
            .open_report()
            .unwrap()
            .release_after_persist(|_| Ok::<(), ()>(()))
            .unwrap();
        writer
            .commit(writer.prepare_metadata(&[0; 32], &[1; 32]).unwrap())
            .unwrap();
        let extra = writer.prepare_chunk(2, &[0; 32], &[0x22; 32]).unwrap();
        let mut e = Evidence::new(c.report.clone(), &blobs, Some(c.closure.clone()));
        e.check_closure(Some(&c.manifest));
        assert_eq!(
            e.check_object(
                "000002.strm",
                Some(&Fetched {
                    blob_sha256: [0x22; 32],
                    write_sig: WriteSigHeader::Present(*extra.write_sig()),
                })
            ),
            ObjectStatus::UnexpectedSigned
        );
        assert_eq!(e.verdict().status, ReportStatus::Altered);
        // An object the relay listed but no longer serves.
        assert_eq!(e.check_object("000000.strm", None), ObjectStatus::Missing);
    }

    #[test]
    fn without_a_valid_closure_objects_verify_by_signature() {
        let c = closed_report();
        let blobs = [
            blob("000000.strm", "a"),
            blob("000001.strm", "b"),
            blob("000003.strm", "c"),
        ];
        // No closure recorded at all: interrupted.
        let mut e = Evidence::new(c.report.clone(), &blobs, None);
        assert_eq!(e.check_closure(None), ClosureState::Absent);
        assert_eq!(
            e.check_object("000000.strm", Some(&signed(&c, 0))),
            ObjectStatus::Verified
        );
        assert_eq!(
            e.check_object("000001.strm", Some(&unsigned(blob_hash(1)))),
            ObjectStatus::Invalid
        );
        let mut tampered = signed(&c, 3);
        tampered.blob_sha256[0] ^= 1;
        assert_eq!(
            e.check_object("000003.strm", Some(&tampered)),
            ObjectStatus::Invalid
        );
        let v = e.verdict();
        assert_eq!(v.status, ReportStatus::Interrupted);
        assert!(!v.closure_anomaly);
        assert_eq!((v.verified, v.invalid), (1, 2));

        // A closure over another manifest, or a forged one: an anomaly, and
        // the objects fall back to their signatures.
        let mut e = Evidence::new(c.report.clone(), &blobs, Some(c.closure.clone()));
        let mut other = c.manifest.clone();
        other[10] ^= 1;
        assert_eq!(e.check_closure(Some(&other)), ClosureState::Invalid);
        assert_eq!(
            e.check_object("000001.strm", Some(&signed(&c, 1))),
            ObjectStatus::Verified
        );
        let v = e.verdict();
        assert_eq!(v.status, ReportStatus::Interrupted);
        assert!(v.closure_anomaly);
        let mut forged = c.closure.clone();
        forged.sig[0] ^= 1;
        let mut e = Evidence::new(c.report.clone(), &blobs, Some(forged));
        assert_eq!(e.check_closure(Some(&c.manifest)), ClosureState::Invalid);
        // A closure recorded without its manifest.
        let mut e = Evidence::new(c.report, &blobs, Some(c.closure));
        assert_eq!(e.check_closure(None), ClosureState::Invalid);
    }

    #[test]
    fn legacy_reports_keep_unsigned_objects_apart() {
        let keyring = ReportKeyring::from_mnemonic(MN_FIXED, "").unwrap();
        let report = rescue().legacy(2).unwrap();
        let name = "abcd_000001.strm";
        let sig = keyring.sign_write(2, name.as_bytes(), &[5; 32]).unwrap();
        let blobs = [
            blob(name, "a"),
            blob("abcd_000002.strm", "b"),
            blob("abcd_000003.strm", "c"),
            blob("../junk", "d"),
        ];
        let empty = Manifest::empty();
        let closure = ClosureRecord {
            seq_limit: 0,
            manifest_sha256: empty.sha256(),
            sig: keyring.sign_legacy_close(2).unwrap(),
        };
        let mut e = Evidence::new(report, &blobs, Some(closure));
        assert_eq!(
            e.check_closure(Some(&empty.to_bytes())),
            ClosureState::Valid
        );
        assert_eq!(
            e.check_object(
                name,
                Some(&Fetched {
                    blob_sha256: [5; 32],
                    write_sig: WriteSigHeader::Present(sig),
                })
            ),
            ObjectStatus::Verified
        );
        assert_eq!(
            e.check_object("abcd_000002.strm", Some(&unsigned([6; 32]))),
            ObjectStatus::Unverifiable
        );
        assert_eq!(
            e.check_object(
                "abcd_000003.strm",
                Some(&Fetched {
                    blob_sha256: [7; 32],
                    write_sig: WriteSigHeader::Malformed,
                })
            ),
            ObjectStatus::Invalid
        );
        assert!(e.check_fetchable("../junk").is_err());
        let v = e.verdict();
        assert_eq!(v.status, ReportStatus::Legacy);
        assert_eq!(v.closure, ClosureState::Valid, "frozen on the relay");
        assert_eq!(
            (v.verified, v.unverifiable, v.invalid, v.unexpected),
            (1, 1, 1, 1)
        );
        assert_eq!(v.unverifiable_names, ["abcd_000002.strm"]);
        assert!(ObjectStatus::Unverifiable.is_kept());
        assert!(!ObjectStatus::Invalid.is_kept());
    }

    #[test]
    fn any_closure_of_the_directory_is_an_anomaly() {
        let report = rescue().directory().clone();
        let keyring = ReportKeyring::from_mnemonic(MN_FIXED, "").unwrap();
        let state = ReportDeviceState::from_mnemonic(MN_FIXED, "").unwrap();
        let name = "0123456789abcdef0123456789abcdef";
        let blobs = [blob(name, "a")];
        let closure = ClosureRecord {
            seq_limit: 0,
            manifest_sha256: Manifest::empty().sha256(),
            sig: [0; 64],
        };
        let mut e = Evidence::new(report.clone(), &blobs, Some(closure));
        assert_eq!(
            e.check_closure(Some(&Manifest::empty().to_bytes())),
            ClosureState::Invalid
        );
        let sig = state.sign_directory_write(name.as_bytes(), &[1; 32]);
        assert_eq!(
            sig,
            keyring
                .sign_directory_write(name.as_bytes(), &[1; 32])
                .unwrap()
        );
        assert_eq!(
            e.check_object(
                name,
                Some(&Fetched {
                    blob_sha256: [1; 32],
                    write_sig: WriteSigHeader::Present(sig),
                })
            ),
            ObjectStatus::Verified
        );
        let v = e.verdict();
        assert_eq!(v.status, ReportStatus::Directory);
        assert!(v.closure_anomaly);
        assert_eq!(v.index, None);
        let e = Evidence::new(report, &blobs, None);
        assert!(!e.verdict().closure_anomaly);
    }

    fn drain(plan: &mut Plan, found: &dyn Fn(RescueTarget) -> bool) -> Vec<RescueTarget> {
        let mut seen = Vec::new();
        while let Some(target) = plan.next_target() {
            plan.record(found(target));
            seen.push(target);
            assert!(seen.len() < 100_000, "the plan must end");
        }
        seen
    }

    #[test]
    fn directory_names_are_matched_in_both_families() {
        let mut r = rescue();
        let legacy1 = r
            .legacy(1)
            .unwrap()
            .directory_entry_name()
            .unwrap()
            .to_owned();
        let chain4 = r.chain(4).unwrap();
        let names = vec![
            "0000000000".to_owned(),
            legacy1,
            chain4.directory_entry_name().unwrap().to_owned(),
            r.chain(6).unwrap().ots_name().unwrap().to_owned(),
            "ffffffffffffffffffffffffffffffff".to_owned(),
        ];
        let matched = match_directory_names(&mut r, &names).unwrap();
        assert_eq!(matched.unmatched, 1);
        let by_index: Vec<(u32, Families)> = matched.named.iter().map(|(i, f)| (*i, *f)).collect();
        assert_eq!(
            by_index,
            [
                (0, BOTH),
                (
                    1,
                    Families {
                        legacy: true,
                        chain: false
                    }
                ),
                (
                    4,
                    Families {
                        legacy: false,
                        chain: true
                    }
                ),
                (
                    6,
                    Families {
                        legacy: false,
                        chain: true
                    }
                ),
            ]
        );
        assert_eq!(decimal_entry_index("0000000012", 512), Some(12));
        assert_eq!(decimal_entry_index("12", 512), None);
        assert_eq!(decimal_entry_index("0000000513", 512), None);
        assert_eq!(decimal_entry_index("9999999999", DERIVE_MATCH_CAP), None);
    }

    fn plan_for(names: &[String], suspect: bool) -> Plan {
        Plan::new(
            match_directory_names(&mut rescue(), names).unwrap(),
            suspect,
        )
    }

    #[test]
    fn a_decimal_name_neither_hides_the_chain_nor_stretches_the_plan() {
        let mut r = rescue();
        // A closed directory holding the authentic chained entries 0..2, and
        // a decimal name for index 3, which anyone listing names can write.
        let mut names: Vec<String> = (0..3)
            .map(|i| {
                r.chain(i)
                    .unwrap()
                    .directory_entry_name()
                    .unwrap()
                    .to_owned()
            })
            .collect();
        names.push("0000000003".to_owned());
        let seen = drain(&mut plan_for(&names, true), &|_| false);
        assert!(
            seen.contains(&RescueTarget {
                scheme: ReportScheme::Chain,
                index: 3
            }),
            "a decimal name must not take the chained family away"
        );

        // One decimal name far out probes no more than one junk name does.
        let junk = vec!["ffffffffffffffffffffffffffffffff".to_owned()];
        let far = vec!["0000100000".to_owned()];
        let junk_probes = drain(&mut plan_for(&junk, false), &|_| false).len();
        let mut far_plan = plan_for(&far, false);
        let far_probes = drain(&mut far_plan, &|_| false).len();
        assert_eq!(far_probes, junk_probes);
        assert_eq!(far_probes, usize::try_from(TAIL_NORMAL * 2).unwrap());
        assert_eq!(far_plan.unmatched, 1, "out of bound: counted, not planned");
    }

    #[test]
    fn the_plan_probes_named_families_then_a_tail() {
        let mut named = BTreeMap::new();
        named.insert(
            0,
            Families {
                legacy: true,
                chain: false,
            },
        );
        named.insert(
            2,
            Families {
                legacy: false,
                chain: true,
            },
        );
        let mut plan = Plan::new(
            DirectoryMatch {
                named,
                unmatched: 0,
            },
            false,
        );
        // Index 1 is named by nobody: both families. Nothing found past 2.
        let seen = drain(&mut plan, &|t| t.index <= 2);
        assert_eq!(
            seen[0],
            RescueTarget {
                scheme: ReportScheme::Legacy,
                index: 0
            }
        );
        assert_eq!(
            seen[1],
            RescueTarget {
                scheme: ReportScheme::Legacy,
                index: 1
            }
        );
        assert_eq!(
            seen[2],
            RescueTarget {
                scheme: ReportScheme::Chain,
                index: 1
            }
        );
        assert_eq!(
            seen[3],
            RescueTarget {
                scheme: ReportScheme::Chain,
                index: 2
            }
        );
        let last = seen.last().unwrap().index;
        assert_eq!(last, 2 + TAIL_NORMAL);
        // A report found in the tail extends it.
        let mut named = BTreeMap::new();
        named.insert(
            0,
            Families {
                legacy: false,
                chain: true,
            },
        );
        let mut plan = Plan::new(
            DirectoryMatch {
                named,
                unmatched: 0,
            },
            false,
        );
        let seen = drain(&mut plan, &|t| {
            t.index == 10 && t.scheme == ReportScheme::Chain
        });
        assert_eq!(seen.last().unwrap().index, 10 + TAIL_NORMAL);
    }

    #[test]
    fn an_absent_or_closed_directory_probes_a_long_bounded_tail() {
        let mut plan = Plan::new(DirectoryMatch::default(), true);
        let seen = drain(&mut plan, &|_| false);
        assert_eq!(seen.last().unwrap().index, TAIL_SUSPECT - 1);
        assert_eq!(seen.len(), usize::try_from(TAIL_SUSPECT * 2).unwrap());
        assert!(!plan.capped, "an exhausted tail is a complete enumeration");
        // A relay that answers every probe cannot keep it going for ever, and
        // the stop on the cap is told apart from a complete enumeration.
        let mut plan = Plan::new(DirectoryMatch::default(), true);
        let seen = drain(&mut plan, &|_| true);
        assert_eq!(seen.last().unwrap().index, PROBE_SPAN_CAP);
        assert!(plan.capped);
        // Once over, it stays over.
        assert!(plan.next_target().is_none());
        assert!(plan.capped);
        // A tail that runs out exactly at the cap is not a capped one.
        let mut plan = Plan::new(DirectoryMatch::default(), true);
        let last_found = PROBE_SPAN_CAP - TAIL_SUSPECT;
        let seen = drain(&mut plan, &|t| t.index <= last_found);
        assert_eq!(seen.last().unwrap().index, PROBE_SPAN_CAP);
        assert!(!plan.capped);
        let planner = RescuePlanner {
            inner: Mutex::new(Plan::new(DirectoryMatch::default(), true)),
        };
        while planner.next().is_some() {
            planner.record(true);
        }
        assert!(planner.hit_probe_cap());
    }

    #[test]
    fn the_first_closure_decision_is_final() {
        let c = closed_report();
        let blobs = [blob("000000.strm", "a"), blob("000002.strm", "b")];
        // First answer: no manifest, so the closure is invalid and objects go
        // by their signatures; a signed object outside the manifest verifies.
        let mut e = Evidence::new(c.report.clone(), &blobs, Some(c.closure.clone()));
        assert_eq!(e.check_closure(None), ClosureState::Invalid);
        let mut state = ReportDeviceState::from_mnemonic(MN_FIXED, "").unwrap();
        let mut writer = state
            .open_report()
            .unwrap()
            .release_after_persist(|_| Ok::<(), ()>(()))
            .unwrap();
        writer
            .commit(writer.prepare_metadata(&[0; 32], &[1; 32]).unwrap())
            .unwrap();
        let extra = writer.prepare_chunk(2, &[0; 32], &[0x22; 32]).unwrap();
        let outside = Fetched {
            blob_sha256: [0x22; 32],
            write_sig: WriteSigHeader::Present(*extra.write_sig()),
        };
        assert_eq!(
            e.check_object("000002.strm", Some(&outside)),
            ObjectStatus::Verified
        );
        // A second answer with the manifest must not requalify it.
        assert_eq!(e.check_closure(Some(&c.manifest)), ClosureState::Invalid);
        let v = e.verdict();
        assert_eq!(v.status, ReportStatus::Interrupted);
        assert!(v.closure_anomaly);

        // The other way round: valid first, then no manifest.
        let mut e = Evidence::new(c.report.clone(), &blobs, Some(c.closure.clone()));
        assert_eq!(e.check_closure(Some(&c.manifest)), ClosureState::Valid);
        assert_eq!(e.check_closure(None), ClosureState::Valid);
        // An absent closure stays absent; an unchecked one is still checked.
        let mut e = Evidence::new(c.report.clone(), &blobs, None);
        assert_eq!(e.check_closure(None), ClosureState::Absent);
        assert_eq!(e.check_closure(Some(&c.manifest)), ClosureState::Absent);
        let mut e = Evidence::new(c.report, &blobs, Some(c.closure));
        assert_eq!(e.verdict().closure, ClosureState::Unchecked);
        assert_eq!(e.check_closure(Some(&c.manifest)), ClosureState::Valid);
    }

    #[test]
    fn an_object_outside_the_closure_that_vanished_is_not_missing() {
        let c = closed_report();
        let blobs = [
            blob("000000.strm", "a"),
            blob("000001.strm", "b"),
            blob("000003.strm", "c"),
            blob("000007.strm", "d"),
        ];
        let mut e = Evidence::new(c.report.clone(), &blobs, Some(c.closure.clone()));
        e.check_closure(Some(&c.manifest));
        for seq in [0, 1, 3] {
            let name = chain_object_name(seq).unwrap();
            assert_eq!(
                e.check_object(&name, Some(&signed(&c, seq))),
                ObjectStatus::Verified
            );
        }
        // Listed, then not served.
        assert_eq!(e.check_object("000007.strm", None), ObjectStatus::Missing);
        let v = e.verdict();
        assert_eq!(v.status, ReportStatus::Complete);
        assert_eq!((v.missing, v.unexpected), (0, 1));
        assert!(v.missing_seqs.is_empty(), "the closure never listed seq 7");
    }

    #[test]
    fn manifest_entries_drive_the_missing_list() {
        let c = closed_report();
        let parsed = Manifest::parse(&c.manifest).unwrap();
        assert_eq!(
            parsed.entries().iter().map(|e| e.seq).collect::<Vec<_>>(),
            [0, 1, 3]
        );
        let mut e = Evidence::new(c.report, &[], Some(c.closure));
        e.check_closure(Some(&c.manifest));
        let v = e.verdict();
        assert_eq!(v.status, ReportStatus::Incomplete);
        assert_eq!(v.missing_seqs, [0, 1, 3]);
        assert_eq!(v.first_modified, None);
    }
}
