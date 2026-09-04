package org.stream.crypto.upload

import android.content.Context
import org.stream.crypto.StreamPreferences
import timber.log.Timber
import java.io.File

/**
 * Filesystem-based queue for encrypted STRM chunks pending upload.
 *
 * Uses filesDir (NOT cacheDir) to survive system cache clearing.
 * Each .strm blob in the queue directory is a pending upload.
 * Files are deleted after successful upload.
 */
class ChunkUploadQueue(context: Context) {

    // Kept so sweepStaleChunks can record a user-visible
    // deletion event (StreamActivity surfaces "N fragments deleted" instead
    // of the 48 h TTL purge being silent).
    private val appContext: Context = context.applicationContext

    val queueDir: File = File(context.filesDir, "stream_chunk_queue").also { it.mkdirs() }

    // `getPending()` is polled from the main thread while a recording is
    // running: StreamRecordingService refreshes its notification at 1 Hz and
    // emits a snapshot metric every 30 s, both reaching `listFiles()` plus one
    // stat per file through `getPendingCountForSession`. Nothing in this file
    // says so — it does not know its callers. With ~200 orphans in the queue
    // that is a ~200-syscall sweep every second, during video capture. This
    // cache amortises away ~95 % of those calls while keeping the count within
    // a second of the truth, already coarser than the UI refresh cadence.
    // Every mutation invalidates it, so a read after a write never sees a
    // stale list. Audit IMP-R1-4.
    private var cachedPending: List<File>? = null
    private var cachedAtMs: Long = 0L
    private val cacheLock = Any()

    private fun invalidateCache() {
        synchronized(cacheLock) {
            cachedPending = null
            cachedAtMs = 0L
        }
    }

    /**
     * Move an encrypted blob into the upload queue.
     *
     * The queue directory is fsynced after `renameTo` so the rename
     * survives a power loss. Without it, ext4 `data=ordered` (the
     * Android default) lets the data blocks reach the disk while the
     * parent directory metadata is still in the journal: a forced
     * shutdown (battery, kill -9) then loses the directory entry while
     * the ciphertext blob bytes stay on the partition as orphans,
     * invisible to `listFiles()` — so neither panic-wipe nor the
     * secure-delete sweep can reach them. Audit R-06.
     */
    fun enqueue(blobFile: File): File {
        val dest = File(queueDir, blobFile.name)
        // `renameTo()` can simply return false here: filesDir and cacheDir
        // may sit on different mount points — rare, but observed on certain
        // custom ROMs and on some Samsung A-series with extended storage
        // emulation. The fallback below is therefore not dead defensive
        // code. It copies, then secure-deletes the source rather than
        // plain-deleting it: the blob is STRM-encrypted so confidentiality
        // is preserved, but a source left in place keeps a nonce_prefix +
        // session_id pattern that is forensically useful for session
        // correlation. The earlier behaviour was a silent return with the
        // source still in place, hence the Timber.w below and the throw
        // when the copy itself fails. (Phase H2-B.15, 2026-05-18 — Red MED-5.)
        val renamed = try {
            blobFile.renameTo(dest)
        } catch (e: Exception) {
            Timber.w(e, "renameTo threw for %s", blobFile.name)
            false
        }
        if (!renamed) {
            Timber.w(
                "renameTo failed for %s → falling back to copy+secureDelete",
                blobFile.name
            )
            try {
                blobFile.copyTo(dest, overwrite = true)
            } catch (e: Exception) {
                Timber.e(e, "enqueue fallback copy failed for %s", blobFile.name)
                throw e
            }
            try {
                uniffi.frappuccino.secureDeleteFile(blobFile.absolutePath)
            } catch (e: Exception) {
                Timber.w(e, "secureDelete fallback failed for %s, plain delete", blobFile.name)
                try {
                    blobFile.delete()
                } catch (e2: Exception) {
                    Timber.w(e2, "plain delete fallback also failed for %s", blobFile.name)
                }
            }
        }
        try {
            // android.system.Os is API 21+. Open the directory, fsync,
            // close. On ext4 (Android default) this forces the rename's
            // directory metadata out of the journal onto stable storage.
            val fd = android.system.Os.open(
                queueDir.absolutePath,
                android.system.OsConstants.O_RDONLY,
                0
            )
            try {
                android.system.Os.fsync(fd)
            } finally {
                android.system.Os.close(fd)
            }
        } catch (e: Exception) {
            Timber.w(e, "fsync of queueDir failed (not fatal, just less crash-durable)")
        }
        invalidateCache()
        Timber.d("Enqueued for upload: %s (%d bytes)", dest.name, dest.length())
        return dest
    }

    /**
     * Get all pending uploads, sorted by filename (chronological order).
     *
     * Cached for [CACHE_TTL_MS] (1 s). Mutations
     * (enqueue/remove/clear/sweepStaleChunks) call [invalidateCache]
     * so a writer is immediately visible.
     */
    fun getPending(): List<File> {
        synchronized(cacheLock) {
            val now = System.currentTimeMillis()
            val cache = cachedPending
            if (cache != null && (now - cachedAtMs) < CACHE_TTL_MS) {
                return cache
            }
            val fresh = queueDir.listFiles()
                ?.filter { it.extension == "strm" && it.length() > 0 }
                ?.sortedBy { it.name }
                ?: emptyList()
            cachedPending = fresh
            cachedAtMs = now
            return fresh
        }
    }

    fun getPendingCount(): Int = getPending().size

    /**
     * Remove a blob from the queue after successful upload.
     */
    fun remove(blobFile: File) {
        if (blobFile.exists()) {
            // Secure-delete : le STRM blob est chiffré, donc
            // moins critique que le MP4 plaintext, mais il contient le
            // ciphertext + nonce. Si la clé éphémère du chunk fuit
            // (improbable), un attacker disk-level peut déchiffrer.
            // Defense-in-depth, coût négligeable (~ms par fichier).
            try {
                uniffi.frappuccino.secureDeleteFile(blobFile.absolutePath)
                Timber.d("Removed from queue: %s", blobFile.name)
            } catch (e: Exception) {
                Timber.w(e, "secureDelete failed on %s, fallback delete()", blobFile.name)
                blobFile.delete()
            }
            invalidateCache()
        }
    }

    /**
     * Like [getPending] but limited to blobs whose filename starts with
     * [sessionId]. Used by scheduleUpload and the HUD pendingCount.
     * Without the filter, a new session would re-enqueue orphan blobs
     * left by earlier sessions against the wrong reportId — fragments of
     * one recording going up attached to another session's report — and
     * would inflate its own progress counter with them.
     *
     * The orphans remain on disk on purpose: they are potentially
     * rescuable, and they only go at the TTL sweep ([sweepStaleChunks],
     * audit R-10). Deleting them at session start to "clean up" destroys
     * recoverable footage.
     */
    fun getPendingForSession(sessionId: String): List<File> =
        getPending().filter { it.name.startsWith(sessionId) }

    /** Count variant. */
    fun getPendingCountForSession(sessionId: String): Int =
        getPendingForSession(sessionId).size

    /**
     * Phase 3.19 — secure-delete chunks older than [maxAgeMs] (based on
     * lastModified). Returns the count of files removed. Called at
     * service start to bound how long ciphertext+nonces can sit on
     * disk if the user never came back to a usable network.
     */
    fun sweepStaleChunks(maxAgeMs: Long): Int {
        val cutoff = System.currentTimeMillis() - maxAgeMs
        var removed = 0
        // Track the oldest blob we actually delete so the
        // user-visible alert can say "fragments from around <date>".
        var oldestMs = Long.MAX_VALUE
        queueDir.listFiles()?.forEach { f ->
            val lm = f.lastModified()
            if (lm < cutoff) {
                try {
                    uniffi.frappuccino.secureDeleteFile(f.absolutePath)
                    removed++
                    if (lm < oldestMs) oldestMs = lm
                } catch (e: Exception) {
                    Timber.w(e, "sweepStaleChunks: secureDelete failed on %s", f.name)
                    if (f.delete()) {
                        removed++
                        if (lm < oldestMs) oldestMs = lm
                    }
                }
            }
        }
        if (removed > 0) {
            invalidateCache()
            Timber.i("sweepStaleChunks: removed %d stale chunks (> %d ms old)",
                removed, maxAgeMs)
            // Surface the loss in-app (no notification, by
            // threat-model choice) so the next StreamActivity resume tells
            // the user instead of the footage vanishing silently.
            StreamPreferences.addOrphanDeletion(
                appContext,
                removed,
                if (oldestMs == Long.MAX_VALUE) 0L else oldestMs,
                "expired",
            )
        }
        return removed
    }

    /**
     * Clear all pending uploads (e.g., on session cancel).
     */
    fun clear() {
        // Secure-delete sur tous les blobs résiduels.
        queueDir.listFiles()?.forEach { f ->
            try {
                uniffi.frappuccino.secureDeleteFile(f.absolutePath)
            } catch (e: Exception) {
                Timber.w(e, "secureDelete failed on %s, fallback delete()", f.name)
                f.delete()
            }
        }
        invalidateCache()
    }

    companion object {
        // Pending-list cache TTL. 1 s is long enough to
        // collapse the 1 Hz UI poll into a single listFiles() while
        // staying short enough that any user perception of "pending
        // count" stays within a second of truth. Mutations bust the
        // cache immediately regardless of TTL.
        private const val CACHE_TTL_MS = 1_000L
    }
}
