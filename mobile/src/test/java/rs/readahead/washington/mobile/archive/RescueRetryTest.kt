package rs.readahead.washington.mobile.archive

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.fail
import org.junit.Test

/**
 * The retry rules of the rescue, on a plain JVM: the pauses are recorded, not
 * slept, so the one-minute floor after a 429 costs nothing here.
 */
class RescueRetryTest {

    private class RateLimited(val secs: Long = 0) : Exception()
    private class Down : Exception()
    private class Refused : Exception()

    private fun classify(e: Throwable): Failure = when (e) {
        is RateLimited -> Failure.RateLimited(e.secs)
        is Down -> Failure.Transient
        else -> Failure.Permanent
    }

    private val sleeps = ArrayList<Long>()
    private val announced = ArrayList<Long>()

    private fun runner(policy: RescueRetryPolicy = RescueRetryPolicy()) = RescueCallRunner(
        policy = policy,
        classify = ::classify,
        sleep = { sleeps.add(it) },
        onRateLimited = { announced.add(it) },
    )

    @Test
    fun `a 429 waits at least a minute even when the relay asks for less`() {
        val policy = RescueRetryPolicy()
        assertEquals(60_000L, policy.nextWaitMillis(Failure.RateLimited(0), 0, 0))
        assertEquals(60_000L, policy.nextWaitMillis(Failure.RateLimited(5), 0, 0))
        assertEquals(120_000L, policy.nextWaitMillis(Failure.RateLimited(120), 0, 0))
    }

    @Test
    fun `a negative retry-after does not shorten the floor`() {
        assertEquals(60_000L, RescueRetryPolicy().nextWaitMillis(Failure.RateLimited(-30), 0, 0))
    }

    @Test
    fun `a 429 replays the same call after the wait`() = runBlocking {
        var calls = 0
        val result = runner().run {
            calls++
            if (calls < 3) throw RateLimited()
            "listing"
        }
        assertEquals("listing", result)
        assertEquals(3, calls)
        assertEquals(listOf(60_000L, 60_000L), sleeps)
        assertEquals(listOf(60_000L, 60_000L), announced)
    }

    @Test
    fun `rate limits are waited out a bounded number of times`() = runBlocking {
        val policy = RescueRetryPolicy(maxRateLimitWaits = 2)
        val error = RateLimited()
        try {
            runner(policy).run<Unit> { throw error }
            fail("expected the 429 to surface after the bounded waits")
        } catch (e: RateLimited) {
            assertSame(error, e)
        }
        assertEquals(2, sleeps.size)
    }

    @Test
    fun `transient failures get a few attempts then surface`() = runBlocking {
        var calls = 0
        try {
            runner().run<Unit> {
                calls++
                throw Down()
            }
            fail("expected the failure to surface")
        } catch (_: Down) {
        }
        assertEquals(3, calls)
        assertEquals(listOf(1_000L, 2_000L), sleeps)
        assertEquals(emptyList<Long>(), announced)
    }

    @Test
    fun `a permanent failure is not retried`() = runBlocking {
        var calls = 0
        try {
            runner().run<Unit> {
                calls++
                throw Refused()
            }
            fail("expected the failure to surface")
        } catch (_: Refused) {
        }
        assertEquals(1, calls)
        assertEquals(emptyList<Long>(), sleeps)
        assertNull(RescueRetryPolicy().nextWaitMillis(Failure.Permanent, 0, 0))
    }

    @Test
    fun `a transient failure after rate limits keeps both budgets apart`() = runBlocking {
        var calls = 0
        val result = runner().run {
            calls++
            when (calls) {
                1 -> throw RateLimited()
                2 -> throw Down()
                3 -> throw RateLimited()
                else -> 42
            }
        }
        assertEquals(42, result)
        assertEquals(listOf(60_000L, 1_000L, 60_000L), sleeps)
    }
}
