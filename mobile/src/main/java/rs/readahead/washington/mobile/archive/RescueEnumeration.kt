package rs.readahead.washington.mobile.archive

/**
 * The planner side of the enumeration, as the loop sees it. The production
 * implementation wraps the Rust `RescuePlanner`, which decides which index and
 * derivation family comes next; a test passes a plain list.
 */
interface ProbePlan<T> {
    /** The next target, or null when the enumeration is over. */
    fun next(): T?

    /** Whether the target [next] returned last holds a report. */
    fun record(found: Boolean)

    /**
     * Read once [next] returned null: whether the plan stopped on its probe
     * cap with the tail not exhausted. Reports past the cap were not looked
     * for, so the enumeration is not complete.
     */
    fun hitCap(): Boolean
}

/** How an enumeration ended. */
sealed class EnumerationEnd {
    /** The plan ran out: every target was probed. */
    object Complete : EnumerationEnd()

    /** The plan stopped on its probe cap before the tail was exhausted:
     *  every target it handed out was probed, but reports past the cap were
     *  never looked for. Shown as incomplete, never as complete. */
    object Capped : EnumerationEnd()

    /** A probe failed for good; what was found before it is kept, the rest
     *  of the plan was never probed. */
    data class Incomplete(val cause: Throwable) : EnumerationEnd()

    /** Stopped on request (explicit close, emergency wipe). */
    object Cancelled : EnumerationEnd()
}

/**
 * The enumeration loop: `next`, probe, `record`, until the plan is over.
 *
 * Four rules, and none is optional.
 *
 * A probe that fails is replayed on the SAME target, and `record` is called
 * only once a probe has answered: a 429 or a network error is not "nothing
 * here", and recording it as such would move the plan on and could end it
 * early.
 *
 * An enumeration that cannot go on ends as [EnumerationEnd.Incomplete], and
 * one the plan cut at its probe cap as [EnumerationEnd.Capped], never as a
 * short complete list: a witness told his testimony is gone when it is merely
 * unreachable is the worst non-security failure this screen can produce.
 *
 * A listing the relay served unreadable ([isUnreadable]) is an anomaly at its
 * index, not a stop: it is recorded as found (something is stored there, so
 * it does not count in the run of empty indices), reported to [run]'s
 * `onUnreadable`, and the probe goes on. The desktop CLI does the same. A
 * stop there would let anyone who can write to that index (R1b: whoever
 * extracted the device's state) hide every report after it.
 *
 * Whether the enumeration is still wanted is asked again once a probe has
 * answered, before its result is used: the probe is a blocking call that a
 * cancellation does not interrupt, and a wipe that ran meanwhile has already
 * emptied the session. A late result goes to `onDiscard`, never to `onFound`.
 */
class RescueEnumeration<T, R : Any>(
    private val plan: ProbePlan<T>,
    private val runner: RescueCallRunner,
    private val isUnreadable: (Throwable) -> Boolean = { false },
    private val probe: (T) -> R?,
) {
    /**
     * @param isActive polled between probes and after each answer; false
     *   ends with [EnumerationEnd.Cancelled].
     * @param onFound called with every target that holds a report.
     * @param onUnreadable called with every target whose listing could not
     *   be read.
     * @param onDiscard called with a result that came back after the
     *   enumeration stopped being wanted, so its native handle can be
     *   released; it is never passed to [onFound].
     * @param onProbed called with the number of targets probed so far.
     */
    suspend fun run(
        isActive: () -> Boolean,
        onFound: (T, R) -> Unit,
        onUnreadable: (T) -> Unit = {},
        onDiscard: (R) -> Unit = {},
        onProbed: (Int) -> Unit = {},
    ): EnumerationEnd {
        var probed = 0
        while (true) {
            if (!isActive()) return EnumerationEnd.Cancelled
            val target = plan.next()
                ?: return if (plan.hitCap()) EnumerationEnd.Capped else EnumerationEnd.Complete
            val result = try {
                runner.run { probe(target) }
            } catch (e: Exception) {
                if (!isActive()) return EnumerationEnd.Cancelled
                if (!isUnreadable(e)) return EnumerationEnd.Incomplete(e)
                plan.record(true)
                onUnreadable(target)
                probed++
                onProbed(probed)
                continue
            }
            if (!isActive()) {
                if (result != null) onDiscard(result)
                return EnumerationEnd.Cancelled
            }
            plan.record(result != null)
            if (result != null) onFound(target, result)
            probed++
            onProbed(probed)
        }
    }
}

/** What reading the report directory gave. */
sealed class DirectoryRead<out D : Any> {
    /** The relay answered: [directory] is its listing, or null when it has
     *  no directory for this phrase (a 404). Only this case may be shown as
     *  "no directory on the relay". */
    data class Listed<D : Any>(val directory: D?) : DirectoryRead<D>()

    /** The relay served a listing that could not be read: an anomaly. The
     *  enumeration goes on without the directory, probing the long tail. */
    object Unreadable : DirectoryRead<Nothing>()

    /** The directory could not be read for a reason that may pass (network,
     *  a rate limit that never lifted), or the batch was cancelled while it
     *  waited: the enumeration stops, incomplete or cancelled. */
    data class Failed(val cause: Throwable) : DirectoryRead<Nothing>()
}

/**
 * Read the report directory under [runner]'s retry rules. An unreadable
 * listing ([isUnreadable]) is not a stop, as in the desktop CLI: the rescue
 * goes on without a directory. Every other failure, a cancelled wait
 * included, comes back as [DirectoryRead.Failed]; the caller tells a
 * cancellation from a failure by asking whether the batch is still wanted,
 * as the enumeration loop does.
 */
suspend fun <D : Any> readDirectory(
    runner: RescueCallRunner,
    isUnreadable: (Throwable) -> Boolean,
    open: () -> D?,
): DirectoryRead<D> = try {
    DirectoryRead.Listed(runner.run(open))
} catch (e: Exception) {
    if (isUnreadable(e)) DirectoryRead.Unreadable else DirectoryRead.Failed(e)
}
