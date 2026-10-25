package org.stream.crypto.upload

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.concurrent.CyclicBarrier
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

/**
 * One need for a bearer spends at most one ratchet slot, whichever components
 * meet on it: they must share the gate's lock, not each guard their own.
 */
class SingleFlightAuthTest {

    private class Relay {
        val bearer = AtomicBoolean(false)
        val attempts = AtomicInteger(0)
        fun authenticate(): Boolean {
            attempts.incrementAndGet()
            Thread.sleep(50)
            bearer.set(true)
            return true
        }
    }

    private fun race(gateA: SingleFlightAuth, gateB: SingleFlightAuth, relay: Relay) {
        val barrier = CyclicBarrier(2)
        val threads = listOf(gateA, gateB).map { gate ->
            Thread {
                barrier.await()
                assertTrue(gate.ensure({ relay.bearer.get() }) { relay.authenticate() })
            }.apply { start() }
        }
        threads.forEach { it.join() }
    }

    @Test
    fun two_callers_on_the_shared_gate_spend_one_slot() {
        val lock = Any()
        repeat(20) {
            val relay = Relay()
            race(SingleFlightAuth(lock), SingleFlightAuth(lock), relay)
            assertEquals(1, relay.attempts.get())
        }
    }

    @Test
    fun two_gates_with_locks_of_their_own_spend_two() {
        // The shape the sweep and the upload worker had: each serialised its
        // own attempts, and the two still authenticated side by side.
        val relay = Relay()
        race(SingleFlightAuth(Any()), SingleFlightAuth(Any()), relay)
        assertEquals(2, relay.attempts.get())
    }

    @Test
    fun a_held_bearer_spends_nothing_and_a_refused_attempt_reports_it() {
        val gate = SingleFlightAuth(Any())
        val attempts = AtomicInteger(0)
        assertTrue(gate.ensure({ true }) { attempts.incrementAndGet(); true })
        assertEquals(0, attempts.get())
        assertFalse(gate.ensure({ false }) { attempts.incrementAndGet(); false })
        // Authenticated, but no bearer published: not a bearer.
        assertFalse(gate.ensure({ false }) { attempts.incrementAndGet(); true })
        assertEquals(2, attempts.get())
    }
}
