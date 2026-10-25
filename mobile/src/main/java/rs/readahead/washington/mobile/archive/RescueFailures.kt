package rs.readahead.washington.mobile.archive

import uniffi.frappuccino.FfiException
import kotlin.coroutines.cancellation.CancellationException

/** Why a rescue step stopped, as the screen tells it. */
enum class FailureReason {
    RATE_LIMITED,
    NETWORK,
    STORAGE,
    REFUSED,

    /** The enumeration reached the planner's probe cap before a run of empty
     *  addresses: reports past the cap were not looked for. Searching again
     *  stops at the same cap. */
    PROBE_CAP,
    OTHER,
}

/** Maps the errors of the rescue's FFI calls onto the retry rules. */
object RescueFailures {

    /**
     * - 429 → [Failure.RateLimited]: wait, then the same call again.
     * - network, TLS, 5xx, and I/O (a body cut off mid-stream surfaces as
     *   I/O) → [Failure.Transient].
     * - a listing or object the relay served unreadable (`InvalidBlob`) →
     *   [Failure.Unreadable]: not retried; the enumeration keeps it as an
     *   anomaly and goes on.
     * - anything else (a call Rust refuses, a destroyed handle after a wipe)
     *   → [Failure.Permanent]: the same call would fail the same way.
     *
     * `InvalidBlob` also comes out of some derivation errors; the desktop CLI
     * treats them the same way, and the two stay aligned.
     */
    fun classify(error: Throwable): Failure = when (error) {
        is FfiException.RateLimited -> Failure.RateLimited(
            error.retryAfterSecs.coerceAtMost(Long.MAX_VALUE.toULong()).toLong(),
        )
        is FfiException.Network, is FfiException.Io -> Failure.Transient
        is FfiException.InvalidBlob -> Failure.Unreadable
        else -> Failure.Permanent
    }

    /** Whether [error] is a listing the relay served unreadable: an anomaly
     *  at that index, not the end of the enumeration. */
    fun isUnreadable(error: Throwable): Boolean = classify(error) == Failure.Unreadable

    /**
     * Whether [error], raised while decrypting an object for the timestamp
     * check, means the object does not decrypt. A verified signature says who
     * stored an object, not that it decrypts; such an object makes the check
     * conclude MISMATCH, as in the desktop CLI, and never fails the report.
     * A failure that may pass (local I/O, the relay, a rate limit), a
     * cancellation and anything that is not an FFI error are not that: the
     * caller rethrows them.
     */
    fun isUndecryptable(error: Throwable): Boolean = when (error) {
        is CancellationException -> false
        is FfiException.Io, is FfiException.Network, is FfiException.RateLimited -> false
        is FfiException -> true
        else -> false
    }

    /** The reason shown for [error]. Never a text chosen by the relay. */
    fun reason(error: Throwable): FailureReason = when (error) {
        is FfiException.RateLimited -> FailureReason.RATE_LIMITED
        is FfiException.Network -> FailureReason.NETWORK
        is FfiException.Io, is java.io.IOException -> FailureReason.STORAGE
        is FfiException.ReportRefused -> FailureReason.REFUSED
        else -> FailureReason.OTHER
    }
}
