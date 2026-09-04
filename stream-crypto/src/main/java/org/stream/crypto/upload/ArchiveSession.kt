package org.stream.crypto.upload

import org.stream.crypto.ArchiveIdentity
import timber.log.Timber
import uniffi.frappuccino.ArchiveBlobInfo
import uniffi.frappuccino.ArchiveDownloadResult
import uniffi.frappuccino.ReportKeyring as FfiReportKeyring
import uniffi.frappuccino.StreamServerClient as FfiServerClient

/**
 * A report discovered by relay-blind enumeration. The relay stores no identity
 * and no title — a report is just its phrase-derived [reportId] (the capability)
 * plus the [reportIndex] `n` it was derived from and its blob tally.
 */
data class DiscoveredReport(
    val reportId: String,
    val reportIndex: Int,
    val blobCount: Int,
    val totalBytes: Long,
)

/**
 * Relay-blind archive retrieval session — **identity-free by design**.
 *
 * Reads carry no bearer and consume no ratchet slot, and that is not a missing
 * authentication waiting to be fixed: the phrase-derived `report_id` IS the
 * capability (`GET /api/v2/archive/reports/{report_id}/…`). The relay stores
 * `report_id → report_pk` and never the identity, so a seizure of its disk
 * reveals no `identity → report` link (Phase C). Bolting a bearer onto these
 * reads would recreate exactly that link, and would put ratchet slots back into
 * a path that currently spends none.
 *
 * The rescue device therefore discovers its own reports by **derivation** rather
 * than by asking the relay "what do I own": it probes `report_id_0, report_id_1,
 * …` (derived from a [FfiReportKeyring]) via [enumerate]. There is no
 * `archive_auth`, no `archive_list_reports`, no cached mnemonic, no bearer — so
 * nothing here is secret and [close] has nothing to wipe: the X25519 decrypt
 * secret lives in the separate [ArchiveIdentity], the keyring in the caller.
 *
 * Threading: the FFI calls are blocking. Call from a background thread or
 * coroutine (`Dispatchers.IO`).
 */
class ArchiveSession(
    private val serverUrl: String,
) {

    private val client: FfiServerClient = FfiServerClient(serverUrl)

    /**
     * Probe a single `report_id`. Returns its blob list, or **null on 404**
     * (no record at this id — a *hole* in the enumeration). Throws
     * [uniffi.frappuccino.FfiException] on a real transport failure (network /
     * 5xx / TLS) so the caller retries and NEVER mistakes a transient error for
     * a hole.
     */
    fun listBlobs(reportId: String): List<ArchiveBlobInfo>? =
        client.archiveListBlobs(reportId)

    /**
     * Enumerate the witness's reports exactly, using the report **directory** for
     * an authoritative `n_max` instead of guessing where to stop.
     *
     * Two rules keep a transient failure from being read as the end of the
     * list, and neither is optional. A 404 is a hole — an allocated index whose
     * report never uploaded — so it is skipped, never read as an early stop. A
     * transport error, on the directory probe as much as on any report probe,
     * is retried [PROBE_RETRIES] times and then aborts by throwing (see
     * [probeWithRetry]): a relay outage must never be read silently as "the end
     * of your reports". Telling a witness his testimony is gone when it is
     * merely unreachable is the worst non-security failure this product can
     * produce. Only a directory *404* takes the [FALLBACK_CAP] branch below — a
     * directory transport failure must never take it.
     *
     * That is as far as the two rules go: they are not a proof that nothing can
     * be truncated. A hostile relay that 404s the *last* directory entries
     * under-reports `n_max` and drops the tail undetected: that is residual C1,
     * inherent to having a single relay and accepted as such (see
     * `docs/RELAY_BLIND_REPORTS.md`). The L-3 clamp below lowers `n_max`
     * deliberately, and both probe paths are bounded ([FALLBACK_CAP],
     * [DERIVE_MATCH_CAP]).
     *
     * The directory is a singleton, phrase-derived report with one entry per
     * session, appended at index allocation by
     * [rs.readahead.washington.mobile.util.jobs.DirectoryEntryWorker]. Each entry
     * name is the opaque, secret-derived `directoryEntryNameHex(n)` rather than
     * the plain index (M-1), so the directory no longer fingerprints as a
     * session counter and `n` is not readable from the name. It does not hide
     * the entry count or the cadence from a relay that has identified the
     * directory report: that much comes with having a directory at all, and is
     * an explicit non-claim (`docs/RELAY_BLIND_REPORTS.md`, "Non-claim M-1").
     *
     * Step 1 fetches `list_blobs(directory)` and re-derives
     * `directoryEntryNameHex(0..)` to match the returned names back to indices
     * (dual-reading any legacy `%010d` entries too); the max matched index is the
     * authoritative `n_max`. Step 2 probes reports `0..n_max` **densely**. That
     * density is what replaced the previous hole-tolerance guess, which truncated
     * the recovery when ≥K allocated-but-unuploaded indices sat between two real
     * reports, along with the arbitrary probe cap.
     *
     * A directory 404 (absent — only reachable if index 0's directory entry never
     * uploaded, which implies essentially no reports) falls back to a dense
     * bounded probe ([FALLBACK_CAP]); that fallback is still truncation-free
     * within its range.
     *
     * @param keyring the phrase-derived [FfiReportKeyring] (`directory_id_hex()` +
     *   `report_id_hex(n)`). The caller owns it and `destroy()`s it afterward.
     * @param onProgress optional `(probed, found)` callback for UI feedback.
     */
    fun enumerate(
        keyring: FfiReportKeyring,
        onProgress: ((probed: Int, found: Int) -> Unit)? = null,
    ): List<DiscoveredReport> {
        // 1. Authoritative n_max from the directory (a fixed, phrase-derived id).
        val dirBlobs = probeWithRetry(keyring.directoryIdHex())
        val nMax: Int = when {
            dirBlobs == null -> {
                Timber.w("ArchiveSession: report directory absent (404) — dense fallback to %d", FALLBACK_CAP)
                FALLBACK_CAP
            }
            else -> {
                // Both halves have to be read. A directory written across an app
                // upgrade holds a mix of legacy "%010d" names and opaque ones (hex
                // of a secret-derived tag, M-1), and dropping either half
                // truncates a recovery silently: (a) parse the legacy decimal
                // entries, (b) re-derive each opaque name and match it back to its
                // index. The two schemes are disjoint — a 32-hex name never parses
                // as an Int — so the union is unambiguous.
                // The legacy branch is bounded by the SAME ceiling as the opaque
                // derive-and-match (DERIVE_MATCH_CAP), for two reasons. It stops a
                // coerced relay from inflating n_max with one big decimal -> a
                // huge dense probe (rescue DoS). And it keeps this (Int)
                // classification identical to the CLI's (u32) — any value <= the
                // ceiling fits both, anything above is junk in both — so the phone
                // and the CLI never recover different sets of reports from the
                // same directory.
                fun legacyIndex(name: String): Int? =
                    name.toIntOrNull()?.takeIf { it in 0..DERIVE_MATCH_CAP }
                var maxIdx = -1
                // (a) legacy decimal entries (within the ceiling)
                for (b in dirBlobs) {
                    legacyIndex(b.filename)?.let { if (it > maxIdx) maxIdx = it }
                }
                // (b) opaque entries = everything not a valid in-range legacy
                // index. Derive name(n) and match. Stop as soon as every opaque
                // entry is matched (exact, holes tolerated), or at DERIVE_MATCH_CAP
                // on relay junk (bounds only local hashing).
                val opaque = dirBlobs.map { it.filename }
                    .filter { legacyIndex(it) == null }
                    .toHashSet()
                var unmatched = opaque.size
                var n = 0
                while (unmatched > 0 && n <= DERIVE_MATCH_CAP) {
                    if (opaque.contains(keyring.directoryEntryNameHex(n.toUInt()))) {
                        if (n > maxIdx) maxIdx = n
                        unmatched--
                    }
                    n++
                }
                if (unmatched > 0) {
                    Timber.w(
                        "ArchiveSession: %d directory entr(ies) unrecognized (relay junk or index > %d) — n_max may be incomplete",
                        unmatched, DERIVE_MATCH_CAP,
                    )
                }
                if (maxIdx < 0) {
                    Timber.w("ArchiveSession: directory has no recognizable entry — dense fallback to %d", FALLBACK_CAP)
                    FALLBACK_CAP
                } else {
                    // L-3 (WP-C): clamp the dense probe by the number of entries
                    // the relay returned (+ slack for holes), so a coerced relay
                    // can't inflate n_max via one forged decimal entry (e.g.
                    // "100000") into a 100k-probe rescue DoS. Mirrors the CLI.
                    val cap = dirBlobs.size + PROBE_SLACK_OVER_ENTRIES
                    val clamped = minOf(maxIdx, cap)
                    if (clamped < maxIdx) {
                        Timber.w(
                            "ArchiveSession: clamped n_max %d -> %d (entries=%d) [L-3]",
                            maxIdx, clamped, dirBlobs.size,
                        )
                    }
                    Timber.i("ArchiveSession: directory n_max=%d (%d entries)", clamped, dirBlobs.size)
                    clamped
                }
            }
        }

        // 2. DENSE enumeration 0..n_max — probe EVERY index (a 404 is a skipped
        //    hole, never an early stop). This is the whole point of the directory.
        val found = ArrayList<DiscoveredReport>()
        for (n in 0..nMax) {
            val reportId = keyring.reportIdHex(n.toUInt())
            val blobs = probeWithRetry(reportId)
            if (blobs != null) {
                found.add(DiscoveredReport(reportId, n, blobs.size, blobs.sumOf { it.size.toLong() }))
            }
            onProgress?.invoke(n + 1, found.size)
        }
        Timber.i(
            "ArchiveSession: enumerate found %d report(s) over %d index/es (n_max=%d)",
            found.size, nMax + 1, nMax,
        )
        return found
    }

    /**
     * [listBlobs] with a small retry budget on transport errors. Returns null
     * (404 hole) or the blob list. Rethrows the last error if the relay stays
     * unreachable across [PROBE_RETRIES] — the enumeration aborts rather than
     * truncate.
     */
    private fun probeWithRetry(reportId: String): List<ArchiveBlobInfo>? {
        var attempt = 0
        var lastError: Exception? = null
        while (attempt < PROBE_RETRIES) {
            attempt++
            try {
                return listBlobs(reportId)
            } catch (e: Exception) {
                lastError = e
                Timber.w(
                    e, "ArchiveSession: probe %s attempt %d/%d failed",
                    reportId, attempt, PROBE_RETRIES,
                )
                if (attempt < PROBE_RETRIES) {
                    try {
                        Thread.sleep(PROBE_RETRY_BACKOFF_MS * attempt)
                    } catch (ie: InterruptedException) {
                        Thread.currentThread().interrupt()
                        throw lastError
                    }
                }
            }
        }
        throw lastError ?: IllegalStateException("ArchiveSession: probe failed for $reportId")
    }

    /**
     * Download + decrypt a single blob to `outputPath` in one shot (id-free).
     * The encrypted blob never lands on disk — only the plaintext. Caller is
     * responsible for `secureDeleteFile(outputPath)` after consumption.
     *
     * @throws uniffi.frappuccino.FfiException on network / wrong recipient / I/O.
     */
    fun downloadAndDecrypt(
        reportId: String,
        filename: String,
        outputPath: String,
        archive: ArchiveIdentity,
    ): ArchiveDownloadResult =
        client.archiveDownloadAndDecrypt(reportId, filename, outputPath, archive.inner)

    /**
     * §10.11 — download a blob's RAW bytes (no STRM decrypt) to `outputPath`
     * (id-free). Used for the opt-in `.ots` timestamp proof (and any legacy
     * sealed `.fpm`), unsealed / verified offline by the recipient.
     *
     * @return bytes written to `outputPath`.
     * @throws uniffi.frappuccino.FfiException on network / I/O.
     */
    fun downloadRaw(
        reportId: String,
        filename: String,
        outputPath: String,
    ): ULong =
        client.archiveDownloadRaw(reportId, filename, outputPath)

    /**
     * Phase C — nothing secret to wipe (no bearer, no cached mnemonic): reads
     * are identity-free. Kept for API symmetry with the call sites
     * ([rs.readahead.washington.mobile.util.jobs.ArchiveAuthHolder.clear]). The
     * underlying Rust client drops on GC of this object. Idempotent.
     */
    fun close() {
        // No-op: id-free session holds no secret.
    }

    companion object {
        /** Dense-probe bound used ONLY when the report directory is absent — a
         *  rare edge reachable only if index 0's directory entry never uploaded,
         *  which implies ~no reports. With the directory present (the norm),
         *  `n_max` is exact and there is NO arbitrary cap. The fallback is still
         *  truncation-free within `0..FALLBACK_CAP` (it probes every index). */
        const val FALLBACK_CAP = 512

        /** M-1 — local-only backstop for the derive-and-match loop that recovers
         *  `n_max` from opaque directory entry names. The loop normally stops as
         *  soon as every opaque entry is matched (exact, hole-tolerant); this only
         *  bites if a semi-trusted relay injected a junk name matching no derived
         *  index. Bounds local hashing; the resulting `n_max` (which DOES drive
         *  the dense network probe) is separately clamped by
         *  [PROBE_SLACK_OVER_ENTRIES]. */
        private const val DERIVE_MATCH_CAP = 100_000

        /** L-3 (WP-C) — clamp the dense network probe (`0..n_max`) to the number
         *  of directory entries the relay returned, plus this slack for any
         *  allocated-but-unuploaded directory entries (holes). Each real report
         *  writes exactly one directory entry, so n_max can legitimately exceed
         *  the entry count only by the (tiny) number of lost entries. Without it,
         *  a coerced relay could return ONE forged decimal entry and inflate the
         *  probe to 100k round-trips — a rescue DoS. */
        private const val PROBE_SLACK_OVER_ENTRIES = 512

        private const val PROBE_RETRIES = 3
        private const val PROBE_RETRY_BACKOFF_MS = 1000L
    }
}
