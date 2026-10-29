package rs.readahead.washington.mobile.diagnostics

import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.locks.ReentrantLock

/**
 * When the upload passes of [Diagnostics.uploadPass] run: one at a time
 * across the one-time and the periodic work, and once more when a recording
 * ends during one.
 *
 * A worker that finds a pass already running returns at once instead of
 * waiting for it: the running pass covers it, and a worker that waits holds a
 * thread of WorkManager's pool, which the chunk uploads use too (two to four
 * threads, by the number of cores).
 *
 * A recording that ends while a pass runs ([requestRerun]) gets one more pass
 * after it. The running pass captured logcat when it started, before the
 * recording's teardown, and the one-time work is unique and KEEP, so the
 * request the recording makes to WorkManager adds nothing while that work runs.
 * Without the extra pass, the lines of a recording that failed to start would
 * wait for the periodic pass, up to an hour, in a logcat ring buffer that the
 * whole system shares and that may wrap meanwhile. A request that arrives in
 * the instant between a pass's last check and the end of its work is still
 * lost to KEEP; the periodic pass picks those lines up.
 *
 * Plain JVM, so that it is tested without Android.
 */
internal class UploadPasses(private val maxPasses: Int = MAX_PASSES) {

    private val lock = ReentrantLock()
    private val rerun = AtomicBoolean(false)

    /** A recording has ended: a pass running now is followed by another. */
    fun requestRerun() = rerun.set(true)

    /**
     * Run [pass], and again while a rerun was requested during the last one,
     * [maxPasses] times at most. Returns at once, true, when a pass is already
     * running. Otherwise true when done, false when the last pass must be
     * retried later (a rerun is not attempted then: the retry is a pass).
     */
    fun run(pass: () -> Boolean): Boolean {
        repeat(maxPasses) {
            if (!lock.tryLock()) return true
            try {
                rerun.set(false)
                if (!pass()) return false
            } finally {
                lock.unlock()
            }
            if (!rerun.get()) return true
        }
        return true
    }

    companion object {
        const val MAX_PASSES = 3
    }
}
