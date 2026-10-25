package rs.readahead.washington.mobile.archive

/**
 * How a failed relay call is treated during the rescue. Kept free of the
 * generated bindings so the retry rules are testable on a plain JVM; the
 * service maps the FFI errors onto [Failure] (see [RescueFailures]).
 */
sealed class Failure {
    /** HTTP 429. The relay sends no `Retry-After`, so [retryAfterSecs] is
     *  usually 0 and the policy's floor applies. */
    data class RateLimited(val retryAfterSecs: Long) : Failure()

    /** Network, TLS or 5xx: worth a few quick retries. */
    object Transient : Failure()

    /** Anything else (refused call, destroyed handle): retrying fails the
     *  same way. */
    object Permanent : Failure()

    /**
     * What the relay served could not be read (a malformed listing, or one
     * larger than the rescue accepts). Never retried, like [Permanent]: the
     * same bytes would come back. The enumeration does not stop on it,
     * though: an unreadable listing is an anomaly at its index and the
     * probe goes on past it, as in the desktop CLI ([RescueEnumeration]).
     * Anyone who extracted the device's state can write to the directory
     * (accepted residual R1b), so stopping here would let them block the
     * rescue of every report.
     */
    object Unreadable : Failure()
}

/**
 * The retry rules of the rescue.
 *
 * A 429 is never an outcome: the same request is repeated after at least
 * [minRateLimitWaitMillis], up to [maxRateLimitWaits] times in a row. Reading a
 * rate limit as "no report here" would silently truncate the enumeration, the
 * worst failure a rescue can have. A transient failure gets
 * [maxTransientAttempts] attempts in all, with a growing pause; past that the
 * caller stops and says the work is incomplete rather than guessing.
 */
class RescueRetryPolicy(
    val minRateLimitWaitMillis: Long = 60_000L,
    val maxRateLimitWaits: Int = 30,
    val maxTransientAttempts: Int = 3,
    val transientBackoffMillis: Long = 1_000L,
) {
    /**
     * The pause before the next attempt, or null to give up.
     *
     * @param rateLimitWaits 429 answers already waited out for this request.
     * @param transientFailures transient failures already seen for this
     *   request, the current one included.
     */
    fun nextWaitMillis(failure: Failure, rateLimitWaits: Int, transientFailures: Int): Long? =
        when (failure) {
            is Failure.RateLimited ->
                if (rateLimitWaits >= maxRateLimitWaits) {
                    null
                } else {
                    maxOf(minRateLimitWaitMillis, failure.retryAfterSecs.coerceAtLeast(0L) * 1_000L)
                }
            Failure.Transient ->
                if (transientFailures >= maxTransientAttempts) null else transientBackoffMillis * transientFailures
            Failure.Permanent, Failure.Unreadable -> null
        }
}

/**
 * Runs one relay call under a [RescueRetryPolicy].
 *
 * [sleep] is the pause (a coroutine `delay` in the service, so a cancelled
 * batch stops waiting at once). [onRateLimited] is told how long the wait is
 * before it starts, so the screen can say why nothing moves for a minute.
 */
class RescueCallRunner(
    private val policy: RescueRetryPolicy,
    private val classify: (Throwable) -> Failure,
    private val sleep: suspend (Long) -> Unit,
    private val onRateLimited: (waitMillis: Long) -> Unit = {},
) {
    /** The result of [call], or its last error once the policy gives up. */
    suspend fun <T> run(call: () -> T): T {
        var rateLimitWaits = 0
        var transientFailures = 0
        while (true) {
            try {
                return call()
            } catch (e: Exception) {
                val failure = classify(e)
                if (failure == Failure.Transient) transientFailures++
                val wait = policy.nextWaitMillis(failure, rateLimitWaits, transientFailures) ?: throw e
                if (failure is Failure.RateLimited) {
                    rateLimitWaits++
                    onRateLimited(wait)
                }
                sleep(wait)
            }
        }
    }
}
