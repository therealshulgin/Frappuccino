package org.stream.crypto.capture

import java.util.concurrent.atomic.AtomicReference

/**
 * Process-wide holder for the active [AdaptiveQualityManager]. The
 * recording service installs the manager when capture starts; the upload
 * worker reads it back through [get] and reports each chunk's upload time.
 *
 * The manager calls back inline, on whatever thread called into it, and
 * that thread is not always the same one: a WorkManager thread
 * (ChunkUploadWorker) on the [reportChunkUploadTime] path, but the main
 * looper on the [setBacklog] path, which the service pushes from its 1 Hz
 * notification refresher — and a backlog push can itself force a quality
 * change. So the service's onQualityChange callback goes through
 * `Handler(Looper.getMainLooper()).post` before it touches the camera
 * pipeline (`StreamRecordingService.applyQuality`) : that hop is not
 * ceremony, it is what makes the calling thread stop mattering.
 *
 * A null holder is a normal state, not a bug — either the recording session
 * that enqueued this chunk has ended, or the process died and the worker
 * outlived it, possibly in a different Application instance. Skipping the
 * report is the right thing to do, so the no-ops below must not be
 * "repaired" into an exception or into a lazy re-creation of the manager.
 *
 * Lifetime: set at recording start, cleared at recording stop.
 */
object AdaptiveQualityHolder {
    private val ref = AtomicReference<AdaptiveQualityManager?>(null)

    /** Install [manager] as the process-wide active instance. */
    fun set(manager: AdaptiveQualityManager) {
        ref.set(manager)
    }

    /** Returns the active manager, or null if none. */
    fun get(): AdaptiveQualityManager? = ref.get()

    /** Drop the active manager. Idempotent. */
    fun clear() {
        ref.set(null)
    }

    /**
     * Convenience: report a chunk upload time iff a manager is active.
     * No-op otherwise. Safe to call from any thread.
     */
    fun reportChunkUploadTime(uploadTimeMs: Long) {
        ref.get()?.reportChunkUploadTime(uploadTimeMs)
    }

    /**
     * Convenience: push the upload backlog (chunks pending) to the active
     * manager. No-op otherwise. See [AdaptiveQualityManager.setBacklog]
     * for the semantics.
     */
    fun setBacklog(count: Int) {
        ref.get()?.setBacklog(count)
    }
}
