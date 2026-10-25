package org.stream.crypto.upload

import android.content.Context
import org.stream.crypto.SecureWipe
import org.stream.crypto.StreamPreferences
import timber.log.Timber
import uniffi.frappuccino.EnvelopeKind
import uniffi.frappuccino.FfiException
import uniffi.frappuccino.ReportKeyring
import java.io.File

/**
 * One-time move of a device enrolled under the legacy report scheme to the
 * chained one, at the first unlock after the update.
 *
 * Under the legacy scheme the device kept the report master and signed each
 * object when sending it. The chained scheme signs at production and keeps no
 * master. The migration therefore:
 *  1. stops the old upload work (it would send unsigned files the relay no
 *     longer accepts unsigned) and keeps the orphan sweeper off meanwhile;
 *     timestamps requested but not received yet are cancelled there (the
 *     opt-in proof is lost, the video is not), and the witness is told at
 *     once;
 *  2. gives a legacy index to every session with a pending blob that has
 *     none, then sets the chained scheme's first index `k` past every legacy
 *     index;
 *  3. writes the report state at `k` (Rust unseals the master in-crate, it
 *     never crosses into the JVM) and makes sure the queue key exists;
 *  4. turns each pending legacy file (queued blobs, blobs staged for the queue,
 *     directory entries, timestamp proofs already received) into an envelope,
 *     signed now with its legacy key, by appending a trailer and renaming, with
 *     a free-space check before each file. A file that cannot be converted is
 *     securely deleted and counted lost; a received proof whose session has no
 *     index any more is deleted and counted with the cancelled timestamps;
 *  5. writes one legacy closure per index below `k`;
 *  6. only then deletes the master and the legacy bookkeeping.
 *
 * On a lack of space or any error that is not about one file, it stops
 * without deleting anything and a later run resumes it. Every step is
 * idempotent: a file already converted is only renamed, an existing state is
 * kept, an existing closure is not rewritten.
 *
 * An emergency wipe during a run stops it at its next step. The writes that
 * would outlive the wipe (alerts, the legacy index table, the queue key, the
 * upload jobs) are guarded by the wipe generation read when the run started
 * ([StreamUploadManager.unlessWipedSince]) and never land after it. A file
 * operation already under way when the wipe starts can still recreate an
 * empty directory the wipe renamed away; the conversions themselves fail
 * once the queue key is gone. The legacy keyring the conversions sign with
 * does not wait for the run's own cleanup: it is published where the wipe
 * destroys it, before erasing any file ([destroyLiveKeyring]), and a signature
 * that would start after that stops the run instead.
 *
 * Objects signed here are signed at migration, not at production: a residual
 * the documentation states. Needs the PIN session (the master is sealed under
 * it); runs off the main thread.
 */
object LegacyReportMigration {

    /** What only the app module can do (WorkManager lives there). */
    interface Hooks {
        /**
         * Cancel the old upload work (chunks, directory entries, timestamp
         * submissions and proof uploads). Returns how many timestamp
         * submissions were still waiting, which the witness is told about
         * right away (the cancellation cannot be undone, whatever the rest of
         * the migration does).
         */
        fun cancelLegacyWork(): Int

        /**
         * Schedule the upload of the envelopes now in the queue, unless an
         * emergency wipe began since [wipeGeneration] (see
         * [StreamUploadManager.unlessWipedSince]).
         */
        fun scheduleEnvelopes(wipeGeneration: Int)
    }

    enum class Outcome {
        /** No legacy state: nothing to do. */
        NOT_NEEDED,

        /** The PIN session is not open: try again after unlock. */
        LOCKED,

        /** Finished; the legacy master and bookkeeping are gone. */
        DONE,

        /**
         * Stopped part way (space, I/O, an emergency wipe); a later run
         * resumes it (the worker's retry, or the next unlock).
         */
        STOPPED,
    }

    /** Free space kept in reserve before each converted file. */
    private const val MIN_FREE_BYTES = 8L * 1024 * 1024

    private const val STAGING_DIR = "stream_migration"
    private const val LEGACY_STAGED_BLOBS_DIR = "stream_encrypted"
    private const val LEGACY_ENTRIES_DIR = "directory_entries"
    const val PROVENANCE_DIR = "stream_provenance"

    /** True while a migration runs; the orphan sweeper stays off meanwhile. */
    @Volatile
    var inProgress: Boolean = false
        private set

    /** The legacy keyring of the run in steps 4 and 5, where the emergency
     *  wipe destroys it ([destroyLiveKeyring]). Every signature goes through
     *  it, never through the bare handle. */
    private val liveKeyring = LiveKeyringSlot<ReportKeyring> { it.destroy() }

    /**
     * Emergency wipe: destroy the legacy keyring a migration holds open, if
     * any, before the files are erased. Synchronous and non-blocking: the
     * handle is released now, or as soon as the one conversion in flight
     * returns, and nothing more is signed with it either way. Idempotent.
     * Returns whether a keyring was open.
     */
    fun destroyLiveKeyring(): Boolean = liveKeyring.destroyLive()

    fun isNeeded(context: Context): Boolean = StreamPreferences.hasReportMasterBlob(context)

    // Steps 1 to 3 (what a recording needs before it can open a report) run
    // under this lock, shorter-lived than [run]'s: see [ensureState].
    private val stateLock = Any()

    /**
     * Steps 1 to 3 only, the part a recording waits for: once the report
     * state exists, a report can be opened, while the conversions (steps 4 to
     * 6, which can take a while on a large backlog) go on in [run]. Waits for
     * a run that is in those first steps, never for one that is converting.
     * Returns whether the report state exists when it returns. Off the main
     * thread; needs the PIN session.
     */
    fun ensureState(context: Context, hooks: Hooks): Boolean {
        val app = context.applicationContext
        val manager = StreamUploadManager.getInstance(app)
        if (manager.hasReportState()) return true
        if (!isNeeded(app) || !manager.isUnlocked()) return manager.hasReportState()
        val gen = StreamUploadManager.wipeGeneration()
        try {
            synchronized(stateLock) {
                if (!manager.hasReportState()) prepareState(app, manager, hooks, gen)
            }
        } catch (e: Exception) {
            Timber.e(e, "legacy migration: report state not written")
        }
        return manager.hasReportState()
    }

    @Synchronized
    fun run(context: Context, hooks: Hooks): Outcome {
        val app = context.applicationContext
        if (!isNeeded(app)) return Outcome.NOT_NEEDED
        val manager = StreamUploadManager.getInstance(app)
        if (!manager.isUnlocked()) return Outcome.LOCKED
        // Nothing this run writes may outlive an emergency wipe that starts
        // while it runs: every persistent write below is guarded by this
        // generation, and the run stops as soon as it moves.
        val gen = StreamUploadManager.wipeGeneration()
        inProgress = true
        return try {
            val k = synchronized(stateLock) { prepareState(app, manager, hooks, gen) }
            if (k == null) Outcome.STOPPED else convertAll(app, hooks, gen, k)
        } catch (e: LiveKeyringSlot.Closed) {
            Timber.w("legacy migration stopped: the keyring was destroyed by an emergency wipe")
            Outcome.STOPPED
        } catch (e: Exception) {
            Timber.e(e, "legacy migration stopped")
            Outcome.STOPPED
        } finally {
            inProgress = false
        }
    }

    private class Counters {
        var converted = 0
        var lost = 0

        /** Received timestamp proofs dropped: not video, counted apart. */
        var proofsDropped = 0
    }

    /**
     * Steps 1 to 3, under [stateLock]. Idempotent: on a device where they
     * already ran, they cancel nothing more, allocate nothing more, install
     * the existing queue key and keep the existing state. Returns `k`, or
     * null when the run has to stop.
     */
    private fun prepareState(context: Context, manager: StreamUploadManager, hooks: Hooks, gen: Int): Int? {
        val queue = EnvelopeQueue.get(context)
        val legacyQueueDir = ChunkUploadQueue(context).queueDir

        // 1. Old upload work off. The cancellation is final as of this call,
        //    so the witness is told now: a run that stops later and resumes
        //    would find these jobs already cancelled and count none.
        val cancelledTimestamps = hooks.cancelLegacyWork()
        StreamUploadManager.unlessWipedSince(gen) {
            StreamPreferences.addReportAlert(
                context, cancelledTimestamps, 0L, ReportAlerts.Reason.TIMESTAMPS_CANCELLED
            )
        }

        // 2. An index for every session with a pending blob, queued or still
        //    staged in cacheDir (listed here, moved later), then k. A proof
        //    whose session has none is dropped at conversion, never given an
        //    index of its own (LegacyMigrationPlan.sessionsNeedingIndex).
        val blobNames = listOf(legacyQueueDir, File(context.cacheDir, LEGACY_STAGED_BLOBS_DIR))
            .flatMap { dir ->
                dir.listFiles()?.filter { it.isFile && it.name.endsWith(".strm") }?.map { it.name }.orEmpty()
            }
        for (sid in LegacyMigrationPlan.sessionsNeedingIndex(blobNames)) {
            StreamUploadManager.unlessWipedSince(gen) {
                StreamPreferences.ensureLegacyIndexForSession(context, sid)
            } ?: return null
        }
        val k = LegacyMigrationPlan.firstChainIndex(
            StreamPreferences.getNextLegacyReportIndex(context),
            StreamPreferences.getLegacySessionIndices(context).values,
        )

        // 3. Queue key, then the state at k.
        val noEnvelopeYet = queue.pending().isEmpty() && queue.failedCount() == 0
        StreamUploadManager.unlessWipedSince(gen) {
            QueueKeyStore.createOrInstall(context, replaceUnreadable = noEnvelopeYet)
        } ?: return null
        val masterSealed = StreamPreferences.getReportMasterBlob(context) ?: return null
        try {
            uniffi.frappuccino.pinSessionMigrateReportState(
                masterSealed, k.toUInt(), manager.reportStatePath()
            )
        } finally {
            SecureWipe.wipe(masterSealed)
        }
        return k
    }

    /** Steps 4 to 6, once the state exists at [k]. */
    private fun convertAll(context: Context, hooks: Hooks, gen: Int, k: Int): Outcome {
        val queue = EnvelopeQueue.get(context)
        val legacyQueueDir = ChunkUploadQueue(context).queueDir
        val wiped = { StreamUploadManager.wipeGeneration() != gen }

        // Files staged in cacheDir move to filesDir first: the conversion
        // renames a file into the queue, and a rename cannot cross filesystems.
        if (wiped()) return Outcome.STOPPED
        val staging = File(context.filesDir, STAGING_DIR).apply { mkdirs() }
        val mover = LegacyFileMover()
        mover.moveAll(File(context.cacheDir, LEGACY_STAGED_BLOBS_DIR), legacyQueueDir) { it.endsWith(".strm") }
        mover.moveAll(File(context.cacheDir, LEGACY_ENTRIES_DIR), staging) { true }

        val blobs = legacyQueueDir.listFiles()?.filter { it.isFile && it.name.endsWith(".strm") }.orEmpty()
        val entries = staging.listFiles()?.filter { it.isFile }.orEmpty()
        val proofs = File(context.filesDir, PROVENANCE_DIR).listFiles()
            ?.filter { it.isFile && it.name.endsWith(".ots") }.orEmpty()
        val indices = StreamPreferences.getLegacySessionIndices(context)

        val masterSealed = StreamPreferences.getReportMasterBlob(context)
            ?: return Outcome.STOPPED
        val opened: ReportKeyring = try {
            uniffi.frappuccino.pinSessionOpenReportKeyring(masterSealed)
        } finally {
            SecureWipe.wipe(masterSealed)
        }
        // Published before its first use, under the wipe guard: a wipe that
        // began since the run started gets it destroyed here, one that begins
        // later destroys it itself. From here on it is reached through the
        // slot only.
        if (!liveKeyring.publishUnlessWipedSince(opened, gen)) return Outcome.STOPPED

        val counters = Counters()
        try {
            // 4. Pending legacy files.
            for (blob in blobs) {
                if (wiped() || !enoughSpace(queue)) return Outcome.STOPPED
                if (!convertBlob(queue, blob, indices, counters)) return Outcome.STOPPED
            }
            for (entry in entries) {
                if (wiped() || !enoughSpace(queue)) return Outcome.STOPPED
                if (!convertEntry(queue, entry, counters)) return Outcome.STOPPED
            }
            for (proof in proofs) {
                if (wiped() || !enoughSpace(queue)) return Outcome.STOPPED
                if (!convertProof(queue, proof, indices, counters)) return Outcome.STOPPED
            }

            // 5. One closure per legacy index.
            for (i in LegacyMigrationPlan.indicesToClose(k)) {
                val out = queue.pathFor(EnvelopeNames.legacyClosure(i))
                if (out.exists() && out.length() > 0) continue
                if (wiped() || !enoughSpace(queue)) return Outcome.STOPPED
                liveKeyring.withLive { uniffi.frappuccino.legacyWriteClosure(it, i.toUInt(), out.absolutePath) }
            }
        } finally {
            queue.invalidate()
            // A no-op when an emergency wipe already destroyed it.
            liveKeyring.retire(opened)
            // The losses are reported even if the migration stops later on:
            // the files are already gone. Not after an emergency wipe: the
            // identity they belonged to is gone too.
            StreamUploadManager.unlessWipedSince(gen) {
                StreamPreferences.addReportAlert(context, counters.lost, 0L, ReportAlerts.Reason.MIGRATION_LOST)
                StreamPreferences.addReportAlert(
                    context, counters.proofsDropped, 0L, ReportAlerts.Reason.TIMESTAMPS_CANCELLED
                )
            }
            hooks.scheduleEnvelopes(gen)
        }

        // 6. Only now: the master and the legacy bookkeeping go.
        if (!StreamPreferences.clearLegacyReportState(context)) return Outcome.STOPPED
        for (dir in listOf(legacyQueueDir, staging,
            File(context.cacheDir, LEGACY_STAGED_BLOBS_DIR), File(context.cacheDir, LEGACY_ENTRIES_DIR))) {
            if (dir.listFiles().isNullOrEmpty()) dir.delete()
        }
        Timber.tag("StreamMetrics").i(
            "legacyMigration done k=%d converted=%d lost=%d", k, counters.converted, counters.lost
        )
        return Outcome.DONE
    }

    private fun convertBlob(
        queue: EnvelopeQueue,
        src: File,
        indices: Map<String, Int>,
        counters: Counters,
    ): Boolean {
        if (src.length() == 0L) {
            // A torn write: holds nothing to lose.
            EnvelopeQueue.secureDelete(src)
            return true
        }
        val blob = LegacyMigrationPlan.parseBlob(src.name)
        val index = blob?.let { indices[it.sessionId] }
        if (blob == null || index == null) return dropInconvertible(src, counters)
        val dst = queue.pathFor(EnvelopeNames.legacyObject(index, blob.sessionId, blob.seq))
        return convert(src, counters) {
            liveKeyring.withLive {
                uniffi.frappuccino.legacyConvertReportObject(
                    it, index.toUInt(), EnvelopeKind.CHUNK, src.name, src.absolutePath, dst.absolutePath
                )
            }
        }
    }

    private fun convertEntry(
        queue: EnvelopeQueue,
        src: File,
        counters: Counters,
    ): Boolean {
        val index = LegacyMigrationPlan.parseDirectoryEntry(src.name) ?: return dropInconvertible(src, counters)
        val dst = queue.pathFor(EnvelopeNames.legacyDirectoryEntry(index))
        return convert(src, counters) {
            liveKeyring.withLive {
                uniffi.frappuccino.legacyConvertDirectoryEntry(it, index.toUInt(), src.absolutePath, dst.absolutePath)
            }
        }
    }

    /**
     * A received proof goes into the legacy report of its session's video.
     * One whose session has no index any more cannot: it is dropped, and so
     * is one the conversion refuses. Either way that is a lost timestamp, not
     * lost video, and it is counted with the cancelled timestamps.
     */
    private fun convertProof(
        queue: EnvelopeQueue,
        src: File,
        indices: Map<String, Int>,
        counters: Counters,
    ): Boolean {
        val dropProof = {
            Timber.w("legacy migration: timestamp proof without its report, deleted")
            EnvelopeQueue.secureDelete(src)
            counters.proofsDropped++
            true
        }
        val index = LegacyMigrationPlan.parseProof(src.name)?.let { indices[it] }
            ?: return dropProof()
        val dst = queue.pathFor(EnvelopeNames.legacyTimestampProof(index))
        return convert(src, counters, onInconvertible = dropProof) {
            liveKeyring.withLive {
                uniffi.frappuccino.legacyConvertReportObject(
                    it, index.toUInt(), EnvelopeKind.TIMESTAMP_PROOF, src.name,
                    src.absolutePath, dst.absolutePath
                )
            }
        }
    }

    /**
     * Run one conversion. A file the conversion refuses as such (corrupt,
     * refused name, malformed) is securely deleted and counted lost (by
     * [onInconvertible]); anything else (I/O, no key, no session) stops the
     * migration with the file intact.
     */
    private fun convert(
        src: File,
        counters: Counters,
        onInconvertible: () -> Boolean = { dropInconvertible(src, counters) },
        call: () -> Unit,
    ): Boolean =
        try {
            call()
            counters.converted++
            true
        } catch (e: FfiException.EnvelopeCorrupt) {
            onInconvertible()
        } catch (e: FfiException.ReportRefused) {
            onInconvertible()
        } catch (e: FfiException.InvalidBlob) {
            onInconvertible()
        } catch (e: FfiException) {
            Timber.w(e, "legacy conversion stopped on a file")
            false
        }

    private fun dropInconvertible(src: File, counters: Counters): Boolean {
        Timber.w("legacy migration: inconvertible file deleted")
        EnvelopeQueue.secureDelete(src)
        counters.lost++
        return true
    }

    private fun enoughSpace(queue: EnvelopeQueue): Boolean {
        val free = try {
            queue.queueDir.usableSpace
        } catch (e: Exception) {
            0L
        }
        if (free < MIN_FREE_BYTES) {
            Timber.w("legacy migration: not enough free space, stopped (a later run resumes)")
            return false
        }
        return true
    }
}
