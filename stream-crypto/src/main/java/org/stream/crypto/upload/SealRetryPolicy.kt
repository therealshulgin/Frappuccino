package org.stream.crypto.upload

/**
 * How many times the writer thread tries again when sealing a chunk or the
 * closure fails, and how long it waits in between.
 *
 * The attempts run on the writer's single thread, so every wait here delays
 * the chunks queued behind. The bounds are kept small for chunks for that
 * reason; the closure, which nothing waits behind, gets more room.
 *
 * Pure JVM: unit-tested without the native library.
 */
object SealRetryPolicy {

    /** Why an attempt failed, from the writer's error. */
    enum class Failure {
        /** The writer was closed or aborted: nothing can be sealed any more. */
        WRITER_CLOSED,

        /** The writer refused the request (seq out of range or already sealed,
         *  no metadata yet): the same request will be refused again. */
        REFUSED,

        /** No queue key installed in the process. */
        NO_QUEUE_KEY,

        /** File I/O (the MP4 or the envelope). */
        IO,

        /** Anything else. */
        OTHER,
    }

    sealed class Decision {
        /** Try again after [delayMs]; reinstall the queue key first if asked. */
        data class Retry(val delayMs: Long, val reinstallQueueKey: Boolean) : Decision()

        /** Stop: the object is lost (a chunk) or the report stays unclosed. */
        object Abandon : Decision()
    }

    /** Attempts at sealing one chunk, the first one included. */
    const val CHUNK_ATTEMPTS = 3

    /** Attempts at writing the closure, the first one included. */
    const val CLOSE_ATTEMPTS = 5

    private const val BASE_DELAY_MS = 250L

    /**
     * @param attemptsMade attempts already made, the failed one included (>= 1).
     * @param maxAttempts [CHUNK_ATTEMPTS] or [CLOSE_ATTEMPTS].
     */
    fun decide(failure: Failure, attemptsMade: Int, maxAttempts: Int): Decision {
        require(attemptsMade >= 1) { "attemptsMade starts at 1" }
        if (failure == Failure.WRITER_CLOSED || failure == Failure.REFUSED) return Decision.Abandon
        if (attemptsMade >= maxAttempts) return Decision.Abandon
        // 250 ms, 1 s, 4 s, 16 s: grows fast, so a full disk or a wedged
        // keystore stops costing time quickly.
        val delay = BASE_DELAY_MS shl (2 * (attemptsMade - 1)).coerceAtMost(12)
        return Decision.Retry(delay, reinstallQueueKey = failure == Failure.NO_QUEUE_KEY)
    }
}
