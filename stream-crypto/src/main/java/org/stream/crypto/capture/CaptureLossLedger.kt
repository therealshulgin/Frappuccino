package org.stream.crypto.capture

/**
 * The count of one recording's chunks lost at capture (never sealed), and
 * what of it still has to be written to the witness's alerts.
 *
 * Losses are written in bulk when the report is closed ([close]). A loss can
 * still happen after that: a chunk the recorder delivers past the closure, or
 * one the writer reports late. Those are not in the bulk, so from [close] on
 * each loss is handed back by [onLoss] to be written on its own. Under one
 * lock, so that a loss racing the bulk write is counted exactly once, either
 * in the bulk or on its own.
 *
 * Pure JVM: unit-tested without the native library.
 */
class CaptureLossLedger {
    private val lock = Any()
    private var lost = 0
    private var bulkTaken = false

    /** Every loss of the recording, for the HUD and the notification. */
    val total: Int get() = synchronized(lock) { lost }

    /**
     * Count [n] lost chunks. Returns how many of them to write to the alerts
     * now: 0 while the bulk is still to come (it will include them), [n] once
     * it has been taken.
     */
    fun onLoss(n: Int = 1): Int = synchronized(lock) {
        if (n <= 0) return 0
        lost += n
        if (bulkTaken) n else 0
    }

    /**
     * Take the bulk to write at the closure: every loss counted so far. From
     * now on, [onLoss] hands each new loss back. A second call returns 0.
     */
    fun close(): Int = synchronized(lock) {
        if (bulkTaken) return 0
        bulkTaken = true
        lost
    }
}
