package rs.readahead.washington.mobile.archive

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The enumeration loop: a failed probe is replayed on the same target and
 * never recorded as "nothing here"; an enumeration that cannot go on says it
 * is incomplete.
 */
class RescueEnumerationTest {

    private class RateLimited : Exception()
    private class Down : Exception()

    /** A plan over a fixed list that remembers what was recorded. [capped]
     *  is what it says about its probe cap once the list is over. */
    private class ListPlan(private val targets: List<Int>, private val capped: Boolean = false) : ProbePlan<Int> {
        private var next = 0
        val handedOut = ArrayList<Int>()
        val recorded = ArrayList<Pair<Int, Boolean>>()

        override fun next(): Int? {
            val t = targets.getOrNull(next) ?: return null
            next++
            handedOut.add(t)
            return t
        }

        override fun record(found: Boolean) {
            recorded.add(handedOut.last() to found)
        }

        override fun hitCap(): Boolean = capped
    }

    /** A listing the relay served unreadable, as the classifier sees it. */
    private class Unreadable : Exception()

    private val sleeps = ArrayList<Long>()

    private fun runner(policy: RescueRetryPolicy = RescueRetryPolicy()) = RescueCallRunner(
        policy = policy,
        classify = { e ->
            when (e) {
                is RateLimited -> Failure.RateLimited(0)
                is Down -> Failure.Transient
                is Unreadable -> Failure.Unreadable
                else -> Failure.Permanent
            }
        },
        sleep = { sleeps.add(it) },
    )

    @Test
    fun `every target is probed and recorded once`() = runBlocking {
        val plan = ListPlan(listOf(0, 1, 2, 3))
        val found = ArrayList<Pair<Int, String>>()
        val end = RescueEnumeration(plan, runner()) { t -> if (t % 2 == 0) "report-$t" else null }
            .run(isActive = { true }, onFound = { t, r -> found.add(t to r) })
        assertSame(EnumerationEnd.Complete, end)
        assertEquals(listOf(0 to true, 1 to false, 2 to true, 3 to false), plan.recorded)
        assertEquals(listOf(0 to "report-0", 2 to "report-2"), found)
    }

    @Test
    fun `a 429 replays the same target and is not recorded`() = runBlocking {
        val plan = ListPlan(listOf(7, 8))
        val attempts = HashMap<Int, Int>()
        val end = RescueEnumeration(plan, runner()) { t ->
            val n = (attempts[t] ?: 0) + 1
            attempts[t] = n
            if (t == 7 && n == 1) throw RateLimited()
            "r$t"
        }.run(isActive = { true }, onFound = { _, _ -> })
        assertSame(EnumerationEnd.Complete, end)
        assertEquals(2, attempts[7])
        assertEquals(listOf(7, 8), plan.handedOut)
        assertEquals(listOf(7 to true, 8 to true), plan.recorded)
        assertEquals(listOf(60_000L), sleeps)
    }

    @Test
    fun `a relay that stays down ends the enumeration as incomplete, keeping what was found`() = runBlocking {
        val plan = ListPlan(listOf(0, 1, 2))
        val found = ArrayList<Int>()
        val end = RescueEnumeration(plan, runner()) { t -> if (t == 1) throw Down() else "r$t" }
            .run(isActive = { true }, onFound = { t, _ -> found.add(t) })
        assertTrue(end is EnumerationEnd.Incomplete)
        assertTrue((end as EnumerationEnd.Incomplete).cause is Down)
        assertEquals(listOf(0), found)
        // The failed target was never recorded, and nothing after it was probed.
        assertEquals(listOf(0 to true), plan.recorded)
        assertEquals(listOf(0, 1), plan.handedOut)
    }

    @Test
    fun `a cancelled enumeration stops between probes`() = runBlocking {
        val plan = ListPlan(listOf(0, 1, 2))
        var active = true
        val end = RescueEnumeration(plan, runner()) { t ->
            if (t == 0) active = false
            "r$t"
        }.run(isActive = { active }, onFound = { _, _ -> })
        assertSame(EnumerationEnd.Cancelled, end)
        assertEquals(listOf(0), plan.handedOut)
    }

    @Test
    fun `a report probed while the session was wiped is discarded, never added`() = runBlocking {
        // The probe is a blocking call a cancellation does not interrupt: the
        // wipe runs while it is in flight, and it still returns a report.
        val plan = ListPlan(listOf(0, 1, 2))
        var active = true
        val found = ArrayList<String>()
        val discarded = ArrayList<String>()
        val end = RescueEnumeration(plan, runner()) { t ->
            if (t == 0) active = false
            "r$t"
        }.run(
            isActive = { active },
            onFound = { _, r -> found.add(r) },
            onDiscard = { discarded.add(it) },
        )
        assertSame(EnumerationEnd.Cancelled, end)
        assertEquals(emptyList<String>(), found)
        assertEquals(listOf("r0"), discarded)
        // Nothing was recorded for an answer nobody wants any more.
        assertEquals(emptyList<Pair<Int, Boolean>>(), plan.recorded)
    }

    @Test
    fun `a plan cut at its probe cap ends as capped, never as complete`() = runBlocking {
        val capped = ListPlan(listOf(0, 1), capped = true)
        val end = RescueEnumeration(capped, runner()) { t -> "r$t" }
            .run(isActive = { true }, onFound = { _, _ -> })
        assertSame(EnumerationEnd.Capped, end)
        assertEquals(listOf(0 to true, 1 to true), capped.recorded)

        val exhausted = ListPlan(listOf(0, 1), capped = false)
        val end2 = RescueEnumeration(exhausted, runner()) { t -> "r$t" }
            .run(isActive = { true }, onFound = { _, _ -> })
        assertSame(EnumerationEnd.Complete, end2)
    }

    @Test
    fun `an unreadable listing is an anomaly, not a stop`() = runBlocking {
        val plan = ListPlan(listOf(0, 1, 2, 3))
        val found = ArrayList<Int>()
        val unreadable = ArrayList<Int>()
        val progress = ArrayList<Int>()
        val end = RescueEnumeration(plan, runner(), isUnreadable = { it is Unreadable }) { t ->
            when (t) {
                1 -> throw Unreadable()
                0, 2 -> "r$t"
                else -> null
            }
        }.run(
            isActive = { true },
            onFound = { t, _ -> found.add(t) },
            onUnreadable = { unreadable.add(it) },
            onProbed = { progress.add(it) },
        )
        assertSame(EnumerationEnd.Complete, end)
        // Something is stored at 1: it counts as found for the plan, so it
        // does not shorten the run of empty indices.
        assertEquals(listOf(0 to true, 1 to true, 2 to true, 3 to false), plan.recorded)
        assertEquals(listOf(0, 2), found)
        assertEquals(listOf(1), unreadable)
        assertEquals(listOf(1, 2, 3, 4), progress)
        // Never retried: the same bytes would come back.
        assertEquals(emptyList<Long>(), sleeps)
    }

    @Test
    fun `an unreadable directory is an anomaly, a failing one stops, a missing one is said so`() = runBlocking {
        val isUnreadable: (Throwable) -> Boolean = { it is Unreadable }
        assertSame(
            DirectoryRead.Unreadable,
            readDirectory<String>(runner(), isUnreadable) { throw Unreadable() },
        )
        assertEquals(DirectoryRead.Listed<String>(null), readDirectory<String>(runner(), isUnreadable) { null })
        assertEquals(DirectoryRead.Listed("dir"), readDirectory(runner(), isUnreadable) { "dir" })
        val failed = readDirectory<String>(runner(), isUnreadable) { throw Down() }
        assertTrue(failed is DirectoryRead.Failed && failed.cause is Down)
    }

    @Test
    fun `progress counts answered probes only`() = runBlocking {
        val plan = ListPlan(listOf(0, 1))
        val progress = ArrayList<Int>()
        var first = true
        RescueEnumeration(plan, runner()) { _ ->
            if (first) {
                first = false
                throw RateLimited()
            }
            null
        }.run(isActive = { true }, onFound = { _, _ -> }, onProbed = { progress.add(it) })
        assertEquals(listOf(1, 2), progress)
    }
}
