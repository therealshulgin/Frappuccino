package org.stream.crypto.upload

/**
 * The in-app alerts about a witness's reports: things that happened to their
 * footage or to its proof and that they must hear about from the app rather
 * than discover later.
 *
 * In-app only, never a system notification (threat-model choice): a
 * notification would need POST_NOTIFICATIONS app-wide, and that permission
 * also makes the recording service's own notification visible, which would
 * light up the status bar of a witness filming covertly. The alerts are read
 * after unlock, so nothing shows on a locked screen either.
 *
 * Each alert is a count per [reason], merged as they come so that a burst of
 * one kind cannot push another kind out of the bounded store.
 *
 * Pure JVM: unit-tested without the native library.
 */
object ReportAlerts {

    /** Why an alert was raised. Stored as is: never rename a value. */
    object Reason {
        /** Old builds: queued fragments deleted by the 48 h expiry. */
        const val EXPIRED = "expired"

        /** Old builds: queued fragments deleted after repeated rescue failures. */
        const val UNRECOVERABLE = "unrecoverable"

        /** A chunk could not be sealed at capture; its video is lost. */
        const val CAPTURE_LOST = "capture_lost"

        /** An envelope the relay refused for good, or that no longer verifies;
         *  it is kept in the failed directory. */
        const val FAILED = "failed"

        /**
         * The relay refused a directory entry or a timestamp proof because it
         * says the directory is closed. This app never closes its directory;
         * the alert says so without claiming who did. A refusal for any other
         * reason is [FAILED].
         */
        const val DIRECTORY_REFUSED = "directory_refused"

        /** A closure for a report the relay never created, with nothing left
         *  in the queue that could create it. */
        const val CLOSURE_ABANDONED = "closure_abandoned"

        /** A recording whose closure could not be written: its objects stay
         *  verifiable one by one, its end is not certified. */
        const val INTERRUPTED = "interrupted"

        /** A pending object from before the update that could not be
         *  converted, and was deleted. */
        const val MIGRATION_LOST = "migration_lost"

        /** Opt-in timestamps requested before the update and not received yet
         *  were cancelled (the video itself is untouched). */
        const val TIMESTAMPS_CANCELLED = "timestamps_cancelled"

        /** Reasons that mean video was lost (shown first, in red). */
        val LOSSES = setOf(EXPIRED, UNRECOVERABLE, CAPTURE_LOST, MIGRATION_LOST)
    }

    data class Alert(
        val count: Int,
        val oldestMs: Long,
        val reason: String,
        val recordedAtMs: Long,
    )

    /** Upper bound of stored alerts (one per reason in practice). */
    const val MAX_ALERTS = 20

    /**
     * Add [count] of [reason] to [existing]: merged into the alert of the same
     * reason if there is one, appended otherwise. Returns the new list, bounded
     * to [MAX_ALERTS] (oldest dropped). A non-positive count changes nothing.
     */
    fun merge(
        existing: List<Alert>,
        count: Int,
        oldestMs: Long,
        reason: String,
        nowMs: Long,
    ): List<Alert> {
        if (count <= 0) return existing
        val out = existing.toMutableList()
        val i = out.indexOfFirst { it.reason == reason }
        if (i >= 0) {
            val old = out.removeAt(i)
            val oldest = listOf(old.oldestMs, oldestMs).filter { it > 0L }.minOrNull() ?: 0L
            out.add(Alert(old.count + count, oldest, reason, nowMs))
        } else {
            out.add(Alert(count, oldestMs, reason, nowMs))
        }
        return out.takeLast(MAX_ALERTS)
    }

    /** Total count per reason. */
    fun totals(alerts: List<Alert>): Map<String, Int> =
        alerts.groupBy { it.reason }.mapValues { (_, v) -> v.sumOf { it.count } }

    /** Total count of the reasons that mean lost video. */
    fun lostTotal(alerts: List<Alert>): Int =
        alerts.filter { it.reason in Reason.LOSSES }.sumOf { it.count }
}
