package org.stream.crypto.upload

/**
 * The recording HUD's "sent" count, derived at display time rather than
 * counted as uploads happen (a counter bumped at each scheduling pass climbs
 * whenever the queue is walked again).
 *
 * Pure JVM: unit-tested without the native library.
 */
object HudCounters {

    /**
     * Chunks of the session the relay holds: those sealed, minus those still
     * in the queue, minus those the relay refused for good (parked in the
     * failed directory, never sent again). Without the last term a refused
     * chunk leaves the queue and would show as delivered.
     */
    fun delivered(sealed: Int, pending: Int, failed: Int): Int =
        (sealed - pending - failed).coerceAtLeast(0)
}
