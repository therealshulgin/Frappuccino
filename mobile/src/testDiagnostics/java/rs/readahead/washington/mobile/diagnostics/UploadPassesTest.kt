package rs.readahead.washington.mobile.diagnostics

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

class UploadPassesTest {

    @Test
    fun `a recording that ends during a pass gets one more pass`() {
        val passes = UploadPasses()
        var count = 0
        assertTrue(passes.run {
            count++
            if (count == 1) passes.requestRerun()
            true
        })
        assertEquals(2, count)
    }

    @Test
    fun `a recording that ended before the pass started adds no pass`() {
        val passes = UploadPasses()
        passes.requestRerun()
        var count = 0
        assertTrue(passes.run { count++; true })
        assertEquals(1, count)
    }

    @Test
    fun `a failed pass is left to the retry, not run again now`() {
        val passes = UploadPasses()
        var count = 0
        assertFalse(passes.run { count++; passes.requestRerun(); false })
        assertEquals(1, count)
    }

    @Test
    fun `passes in a row are bounded`() {
        val passes = UploadPasses(maxPasses = 3)
        var count = 0
        assertTrue(passes.run { count++; passes.requestRerun(); true })
        assertEquals(3, count)
    }

    @Test
    fun `a worker that finds a pass running returns at once without a pass of its own`() {
        val passes = UploadPasses()
        val running = CountDownLatch(1)
        val release = CountDownLatch(1)
        val pool = Executors.newFixedThreadPool(2)
        try {
            val first = pool.submit<Boolean> {
                passes.run { running.countDown(); release.await(10, TimeUnit.SECONDS); true }
            }
            assertTrue(running.await(5, TimeUnit.SECONDS))
            val secondPasses = AtomicInteger()
            // Waiting for the first pass would hold this thread until the
            // release below, past the timeout.
            val second = pool.submit<Boolean> { passes.run { secondPasses.incrementAndGet(); true } }
            assertTrue(second.get(2, TimeUnit.SECONDS))
            assertEquals(0, secondPasses.get())
            release.countDown()
            assertTrue(first.get(5, TimeUnit.SECONDS))
        } finally {
            release.countDown()
            pool.shutdownNow()
        }
    }
}
