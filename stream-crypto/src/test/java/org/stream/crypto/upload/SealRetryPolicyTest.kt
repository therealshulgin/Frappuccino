package org.stream.crypto.upload

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.stream.crypto.upload.SealRetryPolicy.Decision
import org.stream.crypto.upload.SealRetryPolicy.Failure

class SealRetryPolicyTest {

    @Test
    fun a_closed_writer_or_a_refusal_is_never_retried() {
        for (attempt in 1..3) {
            assertEquals(Decision.Abandon, SealRetryPolicy.decide(Failure.WRITER_CLOSED, attempt, 3))
            assertEquals(Decision.Abandon, SealRetryPolicy.decide(Failure.REFUSED, attempt, 3))
        }
    }

    @Test
    fun transient_failures_are_retried_a_bounded_number_of_times() {
        val max = SealRetryPolicy.CHUNK_ATTEMPTS
        for (failure in listOf(Failure.IO, Failure.OTHER, Failure.NO_QUEUE_KEY)) {
            for (attempt in 1 until max) {
                assertTrue(SealRetryPolicy.decide(failure, attempt, max) is Decision.Retry)
            }
            assertEquals(Decision.Abandon, SealRetryPolicy.decide(failure, max, max))
        }
    }

    @Test
    fun delays_grow_and_a_missing_key_is_reinstalled() {
        val first = SealRetryPolicy.decide(Failure.IO, 1, 5) as Decision.Retry
        val second = SealRetryPolicy.decide(Failure.IO, 2, 5) as Decision.Retry
        assertTrue(second.delayMs > first.delayMs)
        assertEquals(false, first.reinstallQueueKey)
        val key = SealRetryPolicy.decide(Failure.NO_QUEUE_KEY, 1, 5) as Decision.Retry
        assertEquals(true, key.reinstallQueueKey)
    }

    @Test
    fun the_chunk_bound_keeps_the_writer_thread_moving() {
        // Every wait runs on the writer's only thread, ahead of the chunks
        // queued behind: a chunk's total wait stays under a few seconds.
        var total = 0L
        var attempt = 1
        while (true) {
            val d = SealRetryPolicy.decide(Failure.IO, attempt, SealRetryPolicy.CHUNK_ATTEMPTS)
            if (d !is Decision.Retry) break
            total += d.delayMs
            attempt++
        }
        assertTrue("total wait $total ms", total <= 5_000L)
    }

    @Test(expected = IllegalArgumentException::class)
    fun attempts_count_from_one() {
        SealRetryPolicy.decide(Failure.IO, 0, 3)
    }
}
