package rs.readahead.washington.mobile.archive

import org.stream.crypto.SecureWipe
import uniffi.frappuccino.ClosureState
import uniffi.frappuccino.OtsStatus
import uniffi.frappuccino.ReportCheck
import uniffi.frappuccino.ReportScheme
import uniffi.frappuccino.ReportVerdict
import java.io.File

/**
 * The in-memory state of one rescue: what the enumeration found and what the
 * verification of each report concluded. Written by `ArchiveDownloadService`,
 * read by the archive screens through [snapshot].
 *
 * Process-local and RAM-only, like the secrets in `ArchiveAuthHolder`, whose
 * `clear()` calls [reset]. Nothing here is a secret key, but it is a map of
 * the witness's reports: the native handles it holds are destroyed on reset,
 * and the local files it points to are purged by `ArchiveLocalData`.
 *
 * Every enumeration runs under a generation number, returned by
 * [beginEnumeration] and bumped by [reset]. The enumeration's writes carry it
 * and are dropped when it is stale. The enumeration's probe is a blocking
 * native call that a cancellation does not interrupt, so a probe that was in
 * flight when the session was wiped still returns; without the check, its
 * report (and the native handle holding its listing) would land in the
 * emptied session and outlive the wipe.
 */
object RescueSession {

    enum class EnumerationState { NOT_STARTED, RUNNING, COMPLETE, INCOMPLETE, CANCELLED }

    enum class EntryState { LISTED, VERIFYING, VERIFIED, FAILED }

    enum class ExportState { NONE, RUNNING, DONE, FAILED }

    /** What became of the reading of the report directory. */
    enum class DirectoryState {
        /** Not read yet, or the read failed (network, cancellation): nothing
         *  is known about the directory, and nothing may be said about it. */
        UNKNOWN,

        /** The relay answered that it has no directory for this phrase. */
        ABSENT,

        /** The relay served the directory's listing. */
        LISTED,

        /** The relay served a listing that could not be read: an anomaly,
         *  the enumeration went on without it. */
        UNREADABLE,
    }

    /** What the screens show about the directory and the enumeration. */
    data class EnumerationView(
        val state: EnumerationState,
        val probed: Int,
        val found: Int,
        /** Epoch millis until which a 429 is being waited out, or 0. */
        val rateLimitedUntil: Long,
        val directory: DirectoryState,
        /** The closure the relay recorded on the directory, as checked, or
         *  null when it recorded none. Any closure on the directory is an
         *  anomaly: the probe goes on past it. [ClosureState.UNCHECKED]
         *  means the check could not be made. */
        val directoryClosure: ClosureState?,
        /** Directory names that matched no index. */
        val unmatchedEntries: Int,
        /** Report listings the relay served unreadable: those reports are not
         *  in the list, and the enumeration went on past them. */
        val unreadableListings: Int,
        val probesLongTail: Boolean,
        /** Why an INCOMPLETE enumeration stopped, for the screen. */
        val failure: FailureReason?,
    )

    /** One report as the screens show it. Immutable copy. */
    data class EntryView(
        val ordinal: Int,
        val scheme: ReportScheme,
        val index: Long?,
        val objectCount: Int,
        val state: EntryState,
        val fetched: Int,
        val verdict: ReportVerdict?,
        val ots: OtsStatus?,
        val token: String?,
        val playableChunks: Int,
        val exportState: ExportState,
        val exportDone: Int,
        val exportTotal: Int,
        /** What the last finished export wrote and excluded; null before one. */
        val exportOutcome: ExportOutcome?,
        val failure: FailureReason?,
        /** Objects kept apart as not verifiable (see [ObjectPlacement]). */
        val unverifiableObjects: Int,
        val unverifiableChunks: Int,
        /** Of those, the files an export of the section would write. */
        val unverifiableExportable: Int,
        val unverifiableExportState: ExportState,
        val unverifiableExportDone: Int,
        val unverifiableExportTotal: Int,
        val unverifiableExportOutcome: ExportOutcome?,
    )

    data class Snapshot(val enumeration: EnumerationView, val entries: List<EntryView>)

    /**
     * One report found by the enumeration. Mutated by the service only;
     * every field is volatile so a screen thread reads a coherent value.
     */
    class Entry internal constructor(
        val ordinal: Int,
        val check: ReportCheck,
        val scheme: ReportScheme,
        val index: Long?,
        val objectCount: Int,
    ) {
        @Volatile var state: EntryState = EntryState.LISTED
        @Volatile var fetched: Int = 0
        @Volatile var verdict: ReportVerdict? = null
        @Volatile var ots: OtsStatus? = null
        @Volatile var failure: FailureReason? = null

        /** The report's local directory (`archive_view/<token>/`), null
         *  until a verification starts. */
        @Volatile var dir: ReportDir? = null

        /** Relay object name → the local file holding it, still encrypted.
         *  VERIFIED objects only. */
        @Volatile var verifiedFiles: Map<String, File> = emptyMap()

        /** The same for the legacy objects kept apart as not verifiable.
         *  Never merged into [verifiedFiles]: the two are read, played and
         *  exported separately. */
        @Volatile var unverifiableFiles: Map<String, File> = emptyMap()

        /** The timestamp proof in clear (decrypted for a chained report, as
         *  stored for a legacy one), kept only when it matched. */
        @Volatile var otsProof: File? = null

        /** SHA-256(session id)[..16] when the timestamp matched, to re-derive
         *  its salt at export time. Wiped on reset. */
        @Volatile var recordingId: ByteArray? = null

        @Volatile var exportState: ExportState = ExportState.NONE
        @Volatile var exportDone: Int = 0
        @Volatile var exportTotal: Int = 0
        @Volatile var exportOutcome: ExportOutcome? = null

        @Volatile var unverifiableExportState: ExportState = ExportState.NONE
        @Volatile var unverifiableExportDone: Int = 0
        @Volatile var unverifiableExportTotal: Int = 0
        @Volatile var unverifiableExportOutcome: ExportOutcome? = null

        /** The verified chunks, in reading order, as local files. */
        fun playableFiles(): List<File> {
            val names = verdict?.verifiedNames ?: return emptyList()
            val files = verifiedFiles
            return RescueNames.playbackOrder(names).mapNotNull { files[it] }
        }

        /** The chunks kept apart as not verifiable, in reading order. */
        fun unverifiablePlayableFiles(): List<File> {
            val names = verdict?.unverifiableNames ?: return emptyList()
            val files = unverifiableFiles
            return RescueNames.playbackOrder(names).mapNotNull { files[it] }
        }

        private fun unverifiableExportable(): Int {
            val names = verdict?.unverifiableNames ?: return 0
            val files = unverifiableFiles
            return ExportPlan.planUnverifiable(names).count { it.sourceName in files }
        }

        internal fun view(): EntryView = EntryView(
            ordinal = ordinal,
            scheme = scheme,
            index = index,
            objectCount = objectCount,
            state = state,
            fetched = fetched,
            verdict = verdict,
            ots = ots,
            token = dir?.token,
            playableChunks = if (state == EntryState.VERIFIED) playableFiles().size else 0,
            exportState = exportState,
            exportDone = exportDone,
            exportTotal = exportTotal,
            exportOutcome = exportOutcome,
            failure = failure,
            unverifiableObjects = if (state == EntryState.VERIFIED) unverifiableFiles.size else 0,
            unverifiableChunks = if (state == EntryState.VERIFIED) unverifiablePlayableFiles().size else 0,
            unverifiableExportable = if (state == EntryState.VERIFIED) unverifiableExportable() else 0,
            unverifiableExportState = unverifiableExportState,
            unverifiableExportDone = unverifiableExportDone,
            unverifiableExportTotal = unverifiableExportTotal,
            unverifiableExportOutcome = unverifiableExportOutcome,
        )

        internal fun release() {
            try {
                check.destroy()
            } catch (_: Exception) {
            }
            recordingId?.let { SecureWipe.wipe(it) }
            recordingId = null
        }
    }

    private val lock = Any()
    private val entries = ArrayList<Entry>()

    // Written under [lock]; volatile so [snapshot] reads them without it.
    @Volatile private var generation = 0L
    @Volatile private var directory: ReportCheck? = null
    @Volatile private var directoryState = DirectoryState.UNKNOWN
    @Volatile private var directoryClosure: ClosureState? = null
    @Volatile private var enumerationState = EnumerationState.NOT_STARTED
    @Volatile private var probed = 0
    @Volatile private var rateLimitedUntil = 0L
    @Volatile private var unmatchedEntries = 0
    @Volatile private var unreadableListings = 0
    @Volatile private var probesLongTail = false
    @Volatile private var enumerationFailure: FailureReason? = null

    /** The directory's check (for the timestamp proofs it holds), if any. */
    fun directoryCheck(): ReportCheck? = directory

    /**
     * Start a new enumeration: forget every report found before, and the
     * directory. Returns the enumeration's generation, which every later
     * write of this enumeration passes back.
     */
    fun beginEnumeration(): Long {
        val (oldEntries, oldDirectory, gen) = synchronized(lock) {
            val copy = entries.toList()
            entries.clear()
            val dir = directory
            directory = null
            generation++
            directoryState = DirectoryState.UNKNOWN
            directoryClosure = null
            unmatchedEntries = 0
            unreadableListings = 0
            probesLongTail = false
            probed = 0
            rateLimitedUntil = 0L
            enumerationFailure = null
            enumerationState = EnumerationState.RUNNING
            Triple(copy, dir, generation)
        }
        oldEntries.forEach { it.release() }
        destroyQuietly(oldDirectory)
        return gen
    }

    /**
     * Record what reading the directory gave: [check] (owned by the session
     * from here on, null when there is none), what the read concluded, the
     * checked closure, and the planner's view of it. A stale [gen] destroys
     * [check] and records nothing; returns whether it was recorded.
     */
    fun setDirectory(
        gen: Long,
        check: ReportCheck?,
        state: DirectoryState,
        closure: ClosureState?,
        unmatched: Int,
        longTail: Boolean,
    ): Boolean {
        val recorded = synchronized(lock) {
            if (gen != generation) {
                false
            } else {
                directory = check
                directoryState = state
                directoryClosure = closure
                unmatchedEntries = unmatched
                probesLongTail = longTail
                true
            }
        }
        if (!recorded) destroyQuietly(check)
        return recorded
    }

    /** Mark an enumeration as started before the service runs it. */
    fun markEnumerationStarting() {
        synchronized(lock) {
            enumerationState = EnumerationState.RUNNING
            enumerationFailure = null
            rateLimitedUntil = 0L
        }
    }

    /**
     * Add a report found by the enumeration of generation [gen]. When [gen]
     * is stale (the session was reset or a new enumeration began while the
     * probe was in flight), [check] is destroyed instead and null returned.
     */
    fun addEntry(gen: Long, check: ReportCheck, scheme: ReportScheme, index: Long?, objectCount: Int): Entry? {
        val entry = synchronized(lock) {
            if (gen != generation) {
                null
            } else {
                Entry(entries.size + 1, check, scheme, index, objectCount).also { entries.add(it) }
            }
        }
        if (entry == null) destroyQuietly(check)
        return entry
    }

    /** Count one report listing the relay served unreadable. */
    fun noteUnreadableListing(gen: Long) {
        synchronized(lock) { if (gen == generation) unreadableListings++ }
    }

    fun setProbed(gen: Long, count: Int) {
        synchronized(lock) { if (gen == generation) probed = count }
    }

    fun setRateLimitedUntil(epochMillis: Long) {
        rateLimitedUntil = epochMillis
    }

    /** End the enumeration of generation [gen]; a stale one changes nothing. */
    fun endEnumeration(gen: Long, state: EnumerationState, failure: FailureReason?) {
        synchronized(lock) {
            if (gen != generation) return
            enumerationState = state
            enumerationFailure = failure
            rateLimitedUntil = 0L
        }
    }

    /**
     * An enumeration batch that never ran (the service could not start, or
     * another batch held it): the screen already showed it as running, and
     * would otherwise keep a RUNNING line with its RECOVER button hidden.
     * Leaves any other state alone (see [stateAfterFailedStart]).
     */
    fun failStartedEnumeration(isEnumeration: Boolean) {
        synchronized(lock) {
            val next = stateAfterFailedStart(isEnumeration, enumerationState) ?: return
            enumerationState = next
            enumerationFailure = FailureReason.OTHER
            rateLimitedUntil = 0L
        }
    }

    /**
     * The enumeration state after a batch failed to start, or null to leave
     * [current] as it is. Only an enumeration the screen marked RUNNING is
     * ended, as INCOMPLETE. A verification or an export that fails to start
     * must not turn a COMPLETE enumeration into an INCOMPLETE one.
     */
    fun stateAfterFailedStart(isEnumeration: Boolean, current: EnumerationState): EnumerationState? =
        if (isEnumeration && current == EnumerationState.RUNNING) EnumerationState.INCOMPLETE else null

    private fun destroyQuietly(check: ReportCheck?) {
        try {
            check?.destroy()
        } catch (_: Exception) {
        }
    }

    fun entry(ordinal: Int): Entry? = synchronized(lock) { entries.getOrNull(ordinal - 1) }

    fun entryByToken(token: String): Entry? = synchronized(lock) { entries.firstOrNull { it.dir?.token == token } }

    fun entries(): List<Entry> = synchronized(lock) { entries.toList() }

    fun snapshot(): Snapshot {
        val list = synchronized(lock) { entries.toList() }
        return Snapshot(
            enumeration = EnumerationView(
                state = enumerationState,
                probed = probed,
                found = list.size,
                rateLimitedUntil = rateLimitedUntil,
                directory = directoryState,
                directoryClosure = directoryClosure,
                unmatchedEntries = unmatchedEntries,
                unreadableListings = unreadableListings,
                probesLongTail = probesLongTail,
                failure = enumerationFailure,
            ),
            entries = list.map { it.view() },
        )
    }

    /** Forget everything and destroy the native handles. Called by
     *  `ArchiveAuthHolder.clear()`. The local files are not touched here.
     *  Bumps the generation: a write of an enumeration still in flight is
     *  dropped from now on. */
    fun reset() {
        val (old, dir) = synchronized(lock) {
            val copy = entries.toList()
            entries.clear()
            val d = directory
            directory = null
            generation++
            enumerationState = EnumerationState.NOT_STARTED
            directoryState = DirectoryState.UNKNOWN
            directoryClosure = null
            probed = 0
            rateLimitedUntil = 0L
            unmatchedEntries = 0
            unreadableListings = 0
            probesLongTail = false
            enumerationFailure = null
            copy to d
        }
        old.forEach { it.release() }
        destroyQuietly(dir)
    }
}
