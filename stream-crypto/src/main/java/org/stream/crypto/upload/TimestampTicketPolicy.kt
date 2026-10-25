package org.stream.crypto.upload

import uniffi.frappuccino.FfiException

/**
 * What the timestamp worker does in the two cases where it could lose the
 * witness's opt-in timestamp for good. A ticket is written once, at the
 * report's closure, and nothing writes it again: deleting it is final.
 *
 * Pure JVM: unit-tested without the native library.
 */
object TimestampTicketPolicy {

    enum class Outcome {
        /** Keep the ticket (or the job) and try again later. */
        RETRY,

        /** The ticket can never be read: delete it, end the job. */
        DROP_TICKET,

        /** End the job; there is no ticket to keep. */
        FAIL,
    }

    /**
     * A job queued by a build from before the tickets (it carries no ticket
     * path). While the legacy migration is still to run, it stays pending so
     * that the migration counts it and tells the witness the timestamp was
     * cancelled; ending it here would make it finished, and the migration only
     * counts unfinished ones. Once the migration is done, nothing will count
     * it any more.
     */
    fun forLegacyJob(migrationNeeded: Boolean): Outcome =
        if (migrationNeeded) Outcome.RETRY else Outcome.FAIL

    /**
     * Reading the ticket failed. Only a ticket that cannot open under the
     * installed queue key ([FfiException.WrongPin]) or is malformed
     * ([FfiException.InvalidBlob]) is dropped. Anything else, an I/O error
     * above all, may pass, and keeps the ticket.
     */
    fun forReadFailure(e: Throwable): Outcome = when (e) {
        is FfiException.WrongPin, is FfiException.InvalidBlob -> Outcome.DROP_TICKET
        else -> Outcome.RETRY
    }
}
