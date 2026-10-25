package org.stream.crypto.upload

import android.content.Context
import timber.log.Timber
import java.io.File
import java.util.concurrent.ConcurrentHashMap

/**
 * The on-disk queue of envelopes waiting to leave the device.
 *
 * Three directories under `filesDir`, never one inside another:
 *  - `stream_envelopes/`: the queue. Each `.fqe` file is one envelope (see
 *    [EnvelopeNames]); a `.part` file is one being written, which nothing reads
 *    and which [sweepPartFiles] removes at process start.
 *  - `stream_envelopes_failed/`: envelopes the relay refused for good, or that
 *    do not verify any more. Never sent again and never counted as pending, but
 *    kept, because nothing can re-sign them: they go only with the emergency
 *    wipe. Their number is shown to the witness.
 *  - `stream_envelopes_425/`: one empty marker per queued envelope the relay
 *    answered 425 for ("report not created yet"), so that the decision "this one
 *    needs the bearer to go" survives a process restart.
 *
 * The queue holds only signed, encrypted objects and needs neither the PIN nor
 * the bearer to be added to; it is the unlock state and the network that decide
 * when it drains, never whether an object is kept.
 *
 * File names are local only (see [EnvelopeNames]); what an envelope carries is
 * read by Rust from its trailer.
 *
 * One instance per root directory in the process ([get]), so that the
 * pending-list cache is shared by the recording service, the workers and the
 * UI, and every mutation invalidates it for all of them.
 */
class EnvelopeQueue(
    root: File,
    private val deleter: (File) -> Unit = ::secureDelete,
) {
    val queueDir: File = File(root, QUEUE_DIR)
    val failedDir: File = File(root, FAILED_DIR)
    private val markerDir: File = File(root, MARKER_DIR)

    // `pending()` is read at 1 Hz by the recording notification and the HUD,
    // and by every worker run. A 1 s cache turns that into one directory
    // listing per second at most; every mutation below invalidates it, so a
    // read after a write never sees a stale list.
    private var cachedPending: List<File>? = null
    private var cachedAtMs: Long = 0L
    private val cacheLock = Any()

    // The report id of each envelope, read once from its trailer by the caller
    // (envelope_inspect) and kept: a trailer never changes once written. A
    // report id is what reads a report on the relay, so an entry is only kept
    // while its envelope is in the queue, and the emergency wipe drops them all
    // ([forget]).
    private val reportIdByName = ConcurrentHashMap<String, String>()

    fun ensureDirs() {
        queueDir.mkdirs()
        failedDir.mkdirs()
        markerDir.mkdirs()
    }

    /** Where the envelope called [name] is written. */
    fun pathFor(name: String): File = File(queueDir, name)

    /**
     * Delete [file] with this queue's deleter (the native secure delete in the
     * app, a plain delete in the JVM tests): for the files whose life is tied
     * to the queue's, such as a chunk's MP4 once its envelope is written.
     */
    fun delete(file: File) = deleter(file)

    /**
     * Emergency wipe: drop every report id this instance cached. The strings
     * become unreachable; the JVM gives no way to overwrite them, so their
     * bytes stay in the heap until it reuses the memory.
     */
    fun forget() {
        reportIdByName.clear()
        invalidate()
    }

    /** Whether [file] is a queue envelope (and not, say, a legacy `.strm`). */
    fun isQueued(file: File): Boolean =
        file.parentFile?.absoluteFile == queueDir.absoluteFile &&
            file.name.endsWith(".${EnvelopeNames.EXTENSION}")

    fun invalidate() {
        synchronized(cacheLock) {
            cachedPending = null
            cachedAtMs = 0L
        }
    }

    /** Queued envelopes (failed ones excluded), sorted by name. */
    fun pending(): List<File> {
        synchronized(cacheLock) {
            val now = System.currentTimeMillis()
            val cache = cachedPending
            if (cache != null && now - cachedAtMs < CACHE_TTL_MS) return cache
            val fresh = queueDir.listFiles()
                ?.filter { it.isFile && it.name.endsWith(".${EnvelopeNames.EXTENSION}") && it.length() > 0 }
                ?.sortedBy { it.name }
                ?: emptyList()
            cachedPending = fresh
            cachedAtMs = now
            return fresh
        }
    }

    fun pendingCount(): Int = pending().size

    /** Queued objects (metadata and chunks) of chained session [sid]. */
    fun pendingObjectsOfSession(sid: String): Int =
        pending().count { EnvelopeNames.isObjectOfSession(it.name, sid) }

    /** Queued media chunks (seq >= 1) of chained session [sid]. */
    fun pendingChunksOfSession(sid: String): Int =
        pending().count {
            EnvelopeNames.isObjectOfSession(it.name, sid) && (EnvelopeNames.parse(it.name)?.seq ?: 0) >= 1
        }

    /** Queued envelopes older than [ageMs]. */
    fun pendingOlderThan(ageMs: Long, nowMs: Long = System.currentTimeMillis()): List<File> =
        pending().filter { nowMs - it.lastModified() >= ageMs }

    fun failedCount(): Int =
        failedDir.listFiles()?.count { it.isFile } ?: 0

    /**
     * Media chunks (seq >= 1) of chained session [sid] parked in the failed
     * directory: refused by the relay for good, so never delivered. Counted
     * once per name: a second failure under the same name is parked with a
     * numeric suffix ([moveToFailed]). A leftover `.part` is not an envelope
     * and is not counted.
     */
    fun failedChunksOfSession(sid: String): Int =
        failedDir.listFiles()
            ?.filter { it.isFile }
            ?.mapNotNull { parkedName(it.name) }
            ?.filter { EnvelopeNames.isObjectOfSession(it, sid) && (EnvelopeNames.parse(it)?.seq ?: 0) >= 1 }
            ?.toSet()
            ?.size ?: 0

    /**
     * Whether some queued envelope may need the upload bearer to go: the first
     * object of a report, a directory entry, or one the relay answered 425 for.
     * The lock-timeout controller keeps the bearer (and the unlocked state that
     * can renew it) while this is true.
     */
    fun hasBearerDependent(): Boolean =
        pending().any { EnvelopeNames.mayNeedJwt(it.name) || isMarkedNotCreated(it.name) }

    /**
     * The relay answered 425 for [name]: remember it across restarts. Only
     * while the envelope is in the queue: a marker without its envelope is a
     * file named after the session that nothing will ever read. The marker
     * directory is not recreated here; if it is gone, so is the queue (the
     * emergency wipe renamed both away), and the queue's owner recreates them
     * all on its next [get].
     */
    fun markNotCreated(name: String) {
        try {
            if (!markerDir.isDirectory || !File(queueDir, name).exists()) return
            val marker = File(markerDir, name)
            marker.createNewFile()
            // The envelope may have gone meanwhile (sent, parked, or renamed
            // away by the emergency wipe): no marker outlives it.
            if (!File(queueDir, name).exists()) marker.delete()
        } catch (e: Exception) {
            Timber.w(e, "EnvelopeQueue: cannot record the 425 marker")
        }
    }

    fun isMarkedNotCreated(name: String): Boolean = File(markerDir, name).exists()

    private fun clearMarker(name: String) {
        val marker = File(markerDir, name)
        if (marker.exists() && !marker.delete()) {
            Timber.w("EnvelopeQueue: cannot delete a 425 marker")
        }
    }

    /** Securely delete a queued envelope (the relay holds it, or it is moot). */
    fun remove(file: File) {
        try {
            if (file.exists()) deleter(file)
        } finally {
            clearMarker(file.name)
            reportIdByName.remove(file.name)
            invalidate()
        }
    }

    /**
     * Move a queued envelope to the failed directory. Never deletes it: if the
     * move fails the envelope stays in the queue and the caller retries later.
     */
    fun moveToFailed(file: File): Boolean {
        failedDir.mkdirs()
        var target = File(failedDir, file.name)
        if (target.exists()) target = File(failedDir, "${file.name}.${System.currentTimeMillis()}")
        val moved = try {
            file.renameTo(target)
        } catch (e: Exception) {
            Timber.w(e, "EnvelopeQueue: move to failed threw")
            false
        }
        if (moved) {
            fsyncDir(failedDir)
            fsyncDir(queueDir)
            clearMarker(file.name)
            reportIdByName.remove(file.name)
        }
        invalidate()
        return moved
    }

    /**
     * Remember [reportIdHex] for [name] (read by the caller from the trailer),
     * only while that envelope is in the queue. An envelope that left it in
     * the meantime (sent, parked, or renamed away by the emergency wipe) leaves
     * no entry behind: the check after the insert closes the window in which
     * a [forget] could run between the first check and the insert.
     */
    fun rememberReportId(name: String, reportIdHex: String) {
        val envelope = File(queueDir, name)
        if (!envelope.exists()) return
        reportIdByName[name] = reportIdHex
        if (!envelope.exists()) reportIdByName.remove(name)
    }

    fun knownReportId(name: String): String? = reportIdByName[name]

    /**
     * Whether another queued envelope belongs to report [reportIdHex].
     * [reportIdOf] reads a trailer (envelope_inspect) for a name whose report is
     * not known yet; an envelope it cannot read counts as a peer, so that an
     * unreadable file never lets a closure go before objects it may cover.
     */
    fun hasPeer(selfName: String, reportIdHex: String, reportIdOf: (File) -> String?): Boolean {
        for (file in pending()) {
            if (file.name == selfName) continue
            val rid = reportIdByName[file.name] ?: reportIdOf(file)?.also {
                rememberReportId(file.name, it)
            } ?: return true
            if (rid == reportIdHex) return true
        }
        return false
    }

    /**
     * Delete the `.part` files a write interrupted by a process death left
     * behind. Call at process start only, before anything can be writing one.
     */
    fun sweepPartFiles(): Int {
        var removed = 0
        for (dir in listOf(queueDir, failedDir)) {
            dir.listFiles()?.forEach { f ->
                if (f.name.endsWith(PART_SUFFIX)) {
                    try {
                        deleter(f)
                        removed++
                    } catch (e: Exception) {
                        Timber.w(e, "EnvelopeQueue: cannot delete a leftover .part")
                    }
                }
            }
        }
        // A marker whose envelope is gone (sent, or moved to failed by a
        // process that died before clearing it) is dropped too.
        markerDir.listFiles()?.forEach { m ->
            if (!File(queueDir, m.name).exists()) m.delete()
        }
        if (removed > 0) invalidate()
        return removed
    }

    companion object {
        const val QUEUE_DIR = "stream_envelopes"
        const val FAILED_DIR = "stream_envelopes_failed"
        const val MARKER_DIR = "stream_envelopes_425"
        const val PART_SUFFIX = ".part"

        private const val CACHE_TTL_MS = 1_000L

        private val instances = ConcurrentHashMap<String, EnvelopeQueue>()

        /** The process-wide queue under `filesDir`. Creates its directories. */
        fun get(context: Context): EnvelopeQueue {
            val root = context.applicationContext.filesDir
            return instances.getOrPut(root.absolutePath) { EnvelopeQueue(root) }.also { it.ensureDirs() }
        }

        /**
         * Emergency wipe: [forget] the report ids the process-wide queue holds,
         * without creating anything. Unlike [get] it does not recreate the
         * queue directories the wipe has just renamed away.
         */
        fun forgetForWipe(context: Context) {
            instances[context.applicationContext.filesDir.absolutePath]?.forget()
        }

        /**
         * The name an envelope had before [moveToFailed] parked it: the file
         * name itself, or the name without the numeric suffix a second failure
         * under the same name gets. Null for anything else (a `.part`).
         */
        internal fun parkedName(fileName: String): String? {
            val ext = ".${EnvelopeNames.EXTENSION}"
            if (fileName.endsWith(ext)) return fileName
            val cut = fileName.lastIndexOf("$ext.")
            if (cut < 0) return null
            val suffix = fileName.substring(cut + ext.length + 1)
            if (suffix.isEmpty() || !suffix.all { it in '0'..'9' }) return null
            return fileName.substring(0, cut + ext.length)
        }

        /** The three directory names, for the emergency wipe. */
        val ALL_DIRS = listOf(QUEUE_DIR, FAILED_DIR, MARKER_DIR)

        /**
         * Rust secure delete (overwrite, fsync, truncate, unlink), falling back
         * to a plain delete so that a failed overwrite never leaves the file.
         */
        fun secureDelete(file: File) {
            try {
                uniffi.frappuccino.secureDeleteFile(file.absolutePath)
            } catch (e: Exception) {
                Timber.w(e, "secureDelete failed, plain delete")
                file.delete()
            }
        }

        /**
         * fsync a directory so a rename in it survives a power loss. Without
         * it, ext4 `data=ordered` (the Android default) can reach the disk
         * with the file's blocks but not yet its directory entry: after a
         * forced shutdown the bytes stay on the partition, invisible to
         * `listFiles()`, so neither the emergency wipe nor a secure-delete
         * sweep can reach them. Audit R-06.
         */
        fun fsyncDir(dir: File) {
            try {
                val fd = android.system.Os.open(dir.absolutePath, android.system.OsConstants.O_RDONLY, 0)
                try {
                    android.system.Os.fsync(fd)
                } finally {
                    android.system.Os.close(fd)
                }
            } catch (e: Exception) {
                Timber.w(e, "fsync of %s failed (rename less crash-durable)", dir.name)
            }
        }
    }
}
