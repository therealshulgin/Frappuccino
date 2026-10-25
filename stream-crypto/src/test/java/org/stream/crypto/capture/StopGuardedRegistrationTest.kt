package org.stream.crypto.capture

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class StopGuardedRegistrationTest {

    /** Counts the callbacks the "system" still holds. */
    private class Registrar {
        val live = HashSet<Int>()
        private var next = 0
        fun register(): Int = (next++).also { live.add(it) }
        fun unregister(id: Int) {
            live.remove(id)
        }
    }

    @Test
    fun a_registration_after_the_stop_never_happens() {
        // The stop arrives while the session is still authenticating, before
        // it registered its network callback.
        val sys = Registrar()
        val slot = StopGuardedRegistration<Int>()
        slot.stop(sys::unregister)
        assertFalse(slot.registerUnlessStopped(sys::register))
        assertEquals(0, sys.live.size)
    }

    @Test
    fun a_registration_before_the_stop_is_undone_by_it() {
        val sys = Registrar()
        val slot = StopGuardedRegistration<Int>()
        assertTrue(slot.registerUnlessStopped(sys::register))
        assertEquals(1, sys.live.size)
        slot.stop(sys::unregister)
        slot.stop(sys::unregister)
        assertEquals(0, sys.live.size)
    }
}
